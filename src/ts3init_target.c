/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                 This is the "target" code
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teamspeak com>, 2016-10-03
 *    Maximilian Muenchow <maximilian muenchow [at] teamspeak.com>, 2016-10-03
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#    include <linux/netfilter_bridge.h>
#endif
#include <linux/random.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include "compat_xtables.h"
#include "ts3init_random_seed.h"
#include "ts3init_cookie.h"
#include "ts3init_target.h"
#include "ts3init_header.h"
#include "ts3init_cache.h"

/*
 * Send a reply back to the client
 */
static bool
ts3init_send_ipv6_reply(struct sk_buff *oldskb, const struct xt_action_param *par, 
                        const struct ipv6hdr *oldip, const struct udphdr *oldudp,
                        const void* payload, const size_t payload_size)
{
    struct sk_buff *skb;
    struct ipv6hdr *ip;
    struct udphdr *udp;
    struct flowi6 fl;
    struct dst_entry *dst = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
    struct net *net = dev_net((xt_in(par) != NULL) ? xt_in(par) : xt_out(par));
#else
    struct net *net = dev_net((par->in != NULL) ? par->in : par->out);
#endif
    
	if(unlikely(!oldskb->dev)){
		pr_warn("Unable to identify device\n");
		return false;
	}

    skb = alloc_skb(LL_MAX_HEADER + sizeof(*ip) +
             sizeof(*udp) + payload_size, GFP_ATOMIC);
    if (skb == NULL)
        return false;

    skb_reserve(skb, LL_MAX_HEADER);
    skb->protocol = oldskb->protocol;

    skb_reset_network_header(skb);
    ip = (void *)skb_put(skb, sizeof(*ip));
    ip->version  = oldip->version;
    ip->priority = oldip->priority;
    memcpy(ip->flow_lbl, oldip->flow_lbl, sizeof(ip->flow_lbl));
    ip->nexthdr  = par->target->proto;
    ip->saddr    = oldip->daddr;
    ip->daddr    = oldip->saddr;

    skb_reset_transport_header(skb);
    udp = (void *)skb_put(skb, sizeof(*udp));
    udp->source = oldudp->dest;
    udp->dest   = oldudp->source;
    udp->len    = htons(sizeof(*udp) + payload_size);

    memcpy(skb_put(skb, payload_size), payload, payload_size);

    udp->check = 0;
    udp->check = csum_ipv6_magic(&ip->saddr, &ip->daddr,
                    ntohs(udp->len), IPPROTO_UDP,
                    csum_partial(udp, ntohs(udp->len), 0));

    memset(&fl, 0, sizeof(fl));
    fl.flowi6_proto = ip->nexthdr;
    memcpy(&fl.saddr, &ip->saddr, sizeof(fl.saddr));
    memcpy(&fl.daddr, &ip->daddr, sizeof(fl.daddr));
    fl.fl6_sport = udp->source;
    fl.fl6_dport = udp->dest;
    security_skb_classify_flow((struct sk_buff *)oldskb, flowi6_to_flowi(&fl));
    dst = ip6_route_output(net, NULL, &fl);
    if (unlikely(dst == NULL || dst->error != 0)) {
        dst_release(dst);
        goto free_nskb;
    }

    skb_dst_set(skb, dst);
    ip->hop_limit = ip6_dst_hoplimit(skb_dst(skb));
    skb->ip_summed = CHECKSUM_NONE;

    /* "Never happens" (?) */
    if (unlikely(skb->len > dst_mtu(skb_dst(skb)))) {
        goto free_nskb;
    }

	nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
    //nf_ct_attach(skb, oldskb);
    ip6_local_out(par_net(par), skb->sk, skb);
    return true;

 free_nskb:
    kfree_skb(skb);
    return false;
}

static void dst_init2(struct dst_entry *dst, struct net_device *dev)
{
       dst->dev = dev;
       dst->flags = DST_NOCOUNT;
       dst->__use = 1;
}

/*
 * Send a reply back to the client
 */
static bool
ts3init_send_ipv4_reply(struct sk_buff *oldskb, const struct xt_action_param *par, 
                        const struct iphdr *oldip, const struct udphdr *oldudp,
                        const void* payload, size_t payload_size)
{
    struct sk_buff *skb;
    struct iphdr *ip;
    struct udphdr *udp;
	struct dst_entry dste;

	if(unlikely(!oldskb->dev)){
		pr_warn("Unable to identify device\n");
		return false;
	}

    skb = alloc_skb(LL_MAX_HEADER + sizeof(*ip) +
         sizeof(*udp) + payload_size, GFP_ATOMIC);
    if (skb == NULL)
        return false;

    skb_reserve(skb, LL_MAX_HEADER);
    skb->protocol = oldskb->protocol;

    skb_reset_network_header(skb);
    ip = (void *)skb_put(skb, sizeof(*ip));
    ip->version  = oldip->version;
    ip->ihl      = sizeof(*ip) / 4;
    ip->tos      = oldip->tos;
    ip->id       = 0;
    ip->frag_off = htons(IP_DF);
    ip->protocol = oldip->protocol;
    ip->check    = 0;
    ip->saddr    = oldip->daddr;
    ip->daddr    = oldip->saddr;

    skb_reset_transport_header(skb);
    udp = (void *)skb_put(skb, sizeof(*udp));
    udp->source = oldudp->dest;
    udp->dest   = oldudp->source;

    memcpy(skb_put(skb, payload_size), payload, payload_size);
    payload_size += sizeof(*udp);
    udp->len    = htons(payload_size);

    udp->check = 0;
    udp->check = csum_tcpudp_magic(ip->saddr, ip->daddr,
                    payload_size, IPPROTO_UDP,
                    csum_partial(udp, payload_size, 0));

    /* ip_route_me_harder expects the skb's dst to be set */
    dst_init2(&dste, oldskb->dev);
    skb_dst_set_noref(skb, &dste);

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 78)
    if (unlikely(ip_route_me_harder(par_net(par), skb->sk, skb, RTN_UNSPEC) != 0)){
    #else
    if (ip_route_me_harder(par_net(par), skb, RTN_UNSPEC) != 0){
    #endif
        goto free_nskb;
    }

    ip->ttl = ip4_dst_hoplimit(skb_dst(skb));
    skb->ip_summed = CHECKSUM_NONE;

    /* "Never happens" (?) */
    if (unlikely(skb->len > dst_mtu(skb_dst(skb)))){
        goto free_nskb;
    }

	nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
    ip_local_out(par_net(par), skb->sk, skb);
    return true;

 free_nskb:
    kfree_skb(skb);
    return false;
}

/* The payload replied by TS3INIT_RESET. */
static const char ts3init_reset_packet[] = {'T', 'S', '3', 'I', 'N', 'I', 'T', '1', 0, 0x65, 0x88, COMMAND_RESET, 0 };

/* 
 * The 'TS3INIT_RESET' target handler.
 * Always replies with COMMAND_RESET and drops the packet
 */
static unsigned int
ts3init_reset_ipv4_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct udphdr *udp, udp_buf;
    ip  = ip_hdr(skb);
    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &udp_buf);
    if (udp == NULL || ntohs(udp->len) <= sizeof(*udp))
        return NF_DROP;

    ts3init_send_ipv4_reply(skb, par, ip, udp, ts3init_reset_packet, sizeof(ts3init_reset_packet));
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    nf_reset_ct(skb);
    #else
    nf_reset(skb);
    #endif
    consume_skb(skb);
    return NF_STOLEN;
}

/* 
 * The 'TS3INIT_RESET' target handler.
 * Always replies with COMMAND_RESET and drops the packet.
 */
static unsigned int
ts3init_reset_ipv6_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct ipv6hdr *ip;
    struct udphdr *udp, udp_buf;
    ip  = ipv6_hdr(skb);
    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &udp_buf);
    if (udp == NULL || ntohs(udp->len) <= sizeof(*udp))
        return NF_DROP;

    ts3init_send_ipv6_reply(skb, par, ip, udp, ts3init_reset_packet, sizeof(ts3init_reset_packet));
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    nf_reset_ct(skb);
    #else
    nf_reset(skb);
    #endif
    consume_skb(skb);
    return NF_STOLEN;
}

/* The header replied by TS3INIT_SET_COOKIE. */
static const char ts3init_set_cookie_packet_header[TS3INIT_HEADER_SERVER_LENGTH] = {'T', 'S', '3', 'I', 'N', 'I', 'T', '1', 0, 0x65, 0x88, COMMAND_SET_COOKIE };

/*
 * Returns the current cookie.
 */
static bool
ts3init_generate_cookie_ipv4(const struct xt_action_param *par,
                             const struct iphdr *ip, const struct udphdr *udp,
                             u64 *cookie, u8 *packet_index)
{
    const struct xt_ts3init_set_cookie_tginfo *info = par->targinfo;
    __u64 cookie_seed[2];

    if (ts3init_get_current_cookie_seed(info->random_seed, &cookie_seed, packet_index) == false)
        return false;
    if (ts3init_calculate_cookie_ipv4(ip, udp, cookie_seed[0], cookie_seed[1], cookie))
        return false;
    return true;
}

/*
 * Returns the current cookie.
 */
static bool
ts3init_generate_cookie_ipv6(const struct xt_action_param *par, 
                             const struct ipv6hdr *ip, const struct udphdr *udp,
                             u64 *cookie, u8 *packet_index)
{
    const struct xt_ts3init_set_cookie_tginfo *info = par->targinfo;
    __u64 cookie_seed[2];

    if (ts3init_get_current_cookie_seed(info->random_seed, &cookie_seed, packet_index) == false)
        return false;
    if (ts3init_calculate_cookie_ipv6(ip, udp, cookie_seed[0], cookie_seed[1], cookie))
        return false;
    return true;
}

/*
 * Fills 'newpayload' with a TS3INIT_SET_COOKIE packet.
 */
static bool
ts3init_fill_set_cookie_payload(const struct sk_buff *skb,
                                const struct xt_action_param *par, 
                                const u64 cookie, const u8 packet_index,
                                u8 *newpayload)
{
    const struct xt_ts3init_set_cookie_tginfo *info = par->targinfo;
    u8 *payload, payload_buf[34];

    memcpy(newpayload, ts3init_set_cookie_packet_header, sizeof(ts3init_set_cookie_packet_header));
    newpayload[12] = (u8)cookie;
    newpayload[13] = (u8)(cookie >> 8);
    newpayload[14] = (u8)(cookie >> 16);
    newpayload[15] = (u8)(cookie >> 24);
    newpayload[16] = (u8)(cookie >> 32);
    newpayload[17] = (u8)(cookie >> 40);
    newpayload[18] = (u8)(cookie >> 48);
    newpayload[19] = (u8)(cookie >> 56);
    newpayload[20] = packet_index;
    if (info->specific_options & TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE)
    {
        memset(&newpayload[21], 0, 11);
    }
    else
    {
        memset(&newpayload[21], 0, 7);
        payload = skb_header_pointer(skb, par->thoff + sizeof(struct udphdr), 
                                      sizeof(payload_buf), payload_buf);
        if (payload == NULL)
        {
            printk(KERN_WARNING KBUILD_MODNAME ": was expecting a ts3init_get_cookie packet. Use -m ts3init_get_cookie!\n");
            return false;
        }
        newpayload[28] = payload[25];
        newpayload[29] = payload[24];
        newpayload[30] = payload[23];
        newpayload[31] = payload[22];
    }
    return true;
}

/* 
 * The 'TS3INIT_SET_COOKIE' target handler.
 * Always replies with TS3INIT_SET_COOKIE and drops the packet.
 */
static unsigned int
ts3init_set_cookie_ipv4_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct udphdr *udp, udp_buf;
    u64 cookie;
    u8 packet_index;
    u8 payload[sizeof(ts3init_set_cookie_packet_header) + 20];

    ip  = ip_hdr(skb);
    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &udp_buf);
    if (udp == NULL || ntohs(udp->len) <= sizeof(*udp))
        return NF_DROP;

    if (ts3init_generate_cookie_ipv4(par, ip, udp, &cookie, &packet_index) &&
        ts3init_fill_set_cookie_payload(skb, par, cookie, packet_index, payload))
    {
        ts3init_send_ipv4_reply(skb, par, ip, udp, payload, sizeof(payload));
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
        nf_reset_ct(skb);
	#else
        nf_reset(skb);
	#endif
        consume_skb(skb);
        return NF_STOLEN;
    }
    return NF_DROP;
}

/* 
 * The 'TS3INIT_SET_COOKIE' target handler.
 * Always replies with TS3INIT_SET_COOKIE and drops the packet.
 */
static unsigned int
ts3init_set_cookie_ipv6_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct ipv6hdr *ip;
    struct udphdr *udp, udp_buf;
    u64 cookie;
    u8 packet_index;
    u8 payload[sizeof(ts3init_set_cookie_packet_header) + 20];

    ip  = ipv6_hdr(skb);
    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &udp_buf);
    if (udp == NULL || ntohs(udp->len) <= sizeof(*udp))
        return NF_DROP;

    if (ts3init_generate_cookie_ipv6(par, ip, udp, &cookie, &packet_index) &&
        ts3init_fill_set_cookie_payload(skb, par, cookie, packet_index, payload))
    {
        ts3init_send_ipv6_reply(skb, par, ip, udp, payload, sizeof(payload));
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
        nf_reset_ct(skb);
	#else
	nf_reset(skb);
	#endif
        consume_skb(skb);
        return NF_STOLEN;
    }
    return NF_DROP;
}

/*
 * Validates targinfo recieved from userspace.
 */
static int ts3init_set_cookie_tg_check(const struct xt_tgchk_param *par)
{
    struct xt_ts3init_set_cookie_tginfo *info = par->targinfo;
    
    if (! (par->family == NFPROTO_IPV4 || par->family == NFPROTO_IPV6))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid protocol (only ipv4 and ipv6) for TS3INIT_SET_COOKIE\n");
        return -EINVAL;
    }

    if (info->common_options & ~(TARGET_COMMON_VALID_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid (common) options for TS3INIT_SET_COOKIE\n");
        return -EINVAL;
    }

    if (info->specific_options & ~(TARGET_SET_COOKIE_VALID_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid (specific) options for TS3INIT_SET_COOKIE\n");
        return -EINVAL;
    }
    
    return 0;
}

static inline void
ts3init_fill_get_cookie_payload(u8 *payload)
{
    time_t current_unix_time = ts3init_get_cached_unix_time();
    payload[TS3INIT_HEADER_CLIENT_LENGTH - 1] = COMMAND_GET_COOKIE;
    payload[TS3INIT_HEADER_CLIENT_LENGTH + 0] = current_unix_time >> 24;
    payload[TS3INIT_HEADER_CLIENT_LENGTH + 1] = current_unix_time >> 16;
    payload[TS3INIT_HEADER_CLIENT_LENGTH + 2] = current_unix_time >> 8;
    payload[TS3INIT_HEADER_CLIENT_LENGTH + 3] = current_unix_time;
    get_random_bytes(&payload[TS3INIT_HEADER_CLIENT_LENGTH + 4], 4);
    memset(&payload[TS3INIT_HEADER_CLIENT_LENGTH + 8], 0, 8);
}

/*
 * The 'TS3INIT_GET_COOKIE' target handler.
 * Morphes the incomming packet into a TS3INIT_GET_COOKIE
 */
static unsigned int
ts3init_get_cookie_ipv4_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct udphdr *udp, udp_buf;
    u8 *payload, payload_buf[TS3INIT_HEADER_CLIENT_LENGTH + 16];
    int new_len;

    ip  = ip_hdr(skb);
    udp = skb_header_pointer(skb, par->thoff, sizeof(udp_buf), &udp_buf);
    if (unlikely(udp == NULL || ip->frag_off & htons(IP_OFFSET)))
        return NF_DROP;

    new_len = par->thoff + sizeof(*udp) + sizeof(payload_buf);
    if (!skb_ensure_writable(skb, new_len))
        return NF_DROP;
    if (likely(new_len < skb->len))
    {
        skb_trim(skb, new_len);
    }
    else if(unlikely(new_len > skb->len))
    {
        if (skb_put_padto(skb, new_len))
            return NF_STOLEN;
    }

    payload = skb_header_pointer(skb, par->thoff + sizeof(*udp), sizeof(payload_buf), payload_buf);
    ts3init_fill_get_cookie_payload(payload);

    udp->len = htons(sizeof(*udp) + sizeof(payload_buf));
    udp->check = 0;
    udp->check = csum_tcpudp_magic(ip->saddr, ip->daddr,
                                    sizeof(*udp) + sizeof(payload_buf), IPPROTO_UDP, 
                                   csum_partial(udp, sizeof(*udp) + sizeof(payload_buf), 0));
    ip->tot_len = htons( new_len );
    ip_send_check(ip);

    //if (skb->len > dst_mtu(skb_dst(skb)))
    //    return NF_DROP;

    return XT_CONTINUE;
}

/*
 * The 'TS3INIT_GET_COOKIE' target handler.
 * Morphes the incomming packet into a TS3INIT_GET_COOKIE
 */
static unsigned int
ts3init_get_cookie_ipv6_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct ipv6hdr *ip;
    struct udphdr *udp, udp_buf;
    u8 *payload, payload_buf[TS3INIT_HEADER_CLIENT_LENGTH + 16];
    int new_len;

    ip  = ipv6_hdr(skb);
    udp = skb_header_pointer(skb, par->thoff, sizeof(udp_buf), &udp_buf);
    if (unlikely(udp == NULL))
        return NF_DROP;

    new_len = par->thoff + sizeof(*udp) + sizeof(payload_buf);
    if (!skb_ensure_writable(skb, new_len))
        return NF_DROP;
    if (likely(new_len < skb->len))
    {
        skb_trim(skb, new_len);
    }
    else if(unlikely(skb->len > new_len))
    {
        if (skb_put_padto(skb, new_len))
            return NF_STOLEN;
    }

    payload = skb_header_pointer(skb, par->thoff + sizeof(*udp), sizeof(payload_buf), payload_buf);
    ts3init_fill_get_cookie_payload(payload);

    udp->len = htons(sizeof(*udp) + sizeof(payload_buf));
    udp->check = 0;
    udp->check = csum_ipv6_magic(&ip->saddr, &ip->daddr,
                                 sizeof(*udp) + sizeof(payload_buf), IPPROTO_UDP, 
                                 csum_partial(udp, sizeof(*udp) + sizeof(payload_buf), 0));
    ip->payload_len = htons( new_len );

    //if (skb->len > dst_mtu(skb_dst(skb)))
    //    return NF_DROP;

    return XT_CONTINUE;
}

static struct xt_target ts3init_tg_reg[] __read_mostly = {
    {
        .name       = "TS3INIT_RESET",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .target     = ts3init_reset_ipv4_tg,
        .me         = THIS_MODULE,
    },
    {
        .name       = "TS3INIT_RESET",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .target     = ts3init_reset_ipv6_tg,
        .me         = THIS_MODULE,
    },
    {
        .name       = "TS3INIT_SET_COOKIE",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .targetsize  = sizeof(struct xt_ts3init_set_cookie_tginfo),
        .target     = ts3init_set_cookie_ipv4_tg,
        .checkentry = ts3init_set_cookie_tg_check,
        .me         = THIS_MODULE,
    },
    {
        .name       = "TS3INIT_SET_COOKIE",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .targetsize  = sizeof(struct xt_ts3init_set_cookie_tginfo),
        .target     = ts3init_set_cookie_ipv6_tg,
        .checkentry = ts3init_set_cookie_tg_check,
        .me         = THIS_MODULE,
    },
    {
        .name       = "TS3INIT_GET_COOKIE",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .target     = ts3init_get_cookie_ipv4_tg,
        .me         = THIS_MODULE,
    },
    {
        .name       = "TS3INIT_GET_COOKIE",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .target     = ts3init_get_cookie_ipv6_tg,
        .me         = THIS_MODULE,
    },
};

int __init ts3init_target_init(void)
{
    return xt_register_targets(ts3init_tg_reg, ARRAY_SIZE(ts3init_tg_reg));
}

void ts3init_target_exit(void)
{
    xt_unregister_targets(ts3init_tg_reg, ARRAY_SIZE(ts3init_tg_reg));
}
