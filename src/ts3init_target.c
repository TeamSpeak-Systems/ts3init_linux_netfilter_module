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
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#    include <linux/netfilter_bridge.h>
#endif
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include "compat_xtables.h"
#include "ts3init_target.h"
#include "ts3init_header.h"


bool
send_ipv6(const struct sk_buff *oldskb, const struct xt_action_param *par, u8 command, const void *payload, const size_t payload_size)
{
    const struct udphdr *oldudp;
    const struct ipv6hdr *oldip;
    struct udphdr *newudp, oldudp_buf;
    struct ipv6hdr *newip;
    struct sk_buff *newskb;
    struct flowi6 fl;
    struct dst_entry *dst = NULL;
    struct net *net = dev_net((par->in != NULL) ? par->in : par->out);

    oldip  = ipv6_hdr(oldskb);
    oldudp = skb_header_pointer(oldskb, par->thoff,
             sizeof(*oldudp), &oldudp_buf);
    if (oldudp == NULL)
        return false;
    if (ntohs(oldudp->len) <= sizeof(*oldudp))
        return false;

    newskb = alloc_skb(LL_MAX_HEADER + sizeof(*newip) +
             sizeof(*newudp) + payload_size, GFP_ATOMIC);
    if (newskb == NULL)
        return false;

    skb_reserve(newskb, LL_MAX_HEADER);
    newskb->protocol = oldskb->protocol;

    skb_reset_network_header(newskb);
    newip = (void *)skb_put(newskb, sizeof(*newip));
    newip->version  = oldip->version;
    newip->priority = oldip->priority;
    memcpy(newip->flow_lbl, oldip->flow_lbl, sizeof(newip->flow_lbl));
    newip->nexthdr  = par->target->proto;
    newip->saddr    = oldip->daddr;
    newip->daddr    = oldip->saddr;

    skb_reset_transport_header(newskb);
    newudp = (void *)skb_put(newskb, sizeof(*newudp));
    newudp->source = oldudp->dest;
    newudp->dest   = oldudp->source;
    newudp->len    = htons(sizeof(*newudp) + payload_size);

    memcpy(skb_put(newskb, payload_size), payload, payload_size);
    newip->payload_len = htons(newskb->len);

    newudp->check = 0;
    newudp->check = csum_ipv6_magic(&newip->saddr, &newip->daddr,
                    ntohs(newudp->len), IPPROTO_UDP,
                    csum_partial(newudp, ntohs(newudp->len), 0));

    memset(&fl, 0, sizeof(fl));
    fl.flowi6_proto = newip->nexthdr;
    memcpy(&fl.saddr, &newip->saddr, sizeof(fl.saddr));
    memcpy(&fl.daddr, &newip->daddr, sizeof(fl.daddr));
    fl.fl6_sport = newudp->source;
    fl.fl6_dport = newudp->dest;
    security_skb_classify_flow((struct sk_buff *)oldskb, flowi6_to_flowi(&fl));
    dst = ip6_route_output(net, NULL, &fl);
    if (dst == NULL || dst->error != 0)
    {
        dst_release(dst);
        goto free_nskb;
    }

    skb_dst_set(newskb, dst);
    newip->hop_limit = ip6_dst_hoplimit(skb_dst(newskb));
    newskb->ip_summed = CHECKSUM_NONE;

    /* "Never happens" (?) */
    if (newskb->len > dst_mtu(skb_dst(newskb)))
        goto free_nskb;

    nf_ct_attach(newskb, oldskb);
    ip6_local_out(par_net(par), newskb->sk, newskb);
    return true;

 free_nskb:
    kfree_skb(newskb);
    return false;
}

bool
send_ipv4(const struct sk_buff *oldskb, const struct xt_action_param *par, u8 command, const void *payload, const size_t payload_size)
{
    const struct udphdr *oldudp;
    const struct iphdr *oldip;
    struct udphdr *newudp, oldudp_buf;
    struct iphdr *newip;
    struct sk_buff *newskb;

    oldip  = ip_hdr(oldskb);
    oldudp = skb_header_pointer(oldskb, par->thoff,
             sizeof(*oldudp), &oldudp_buf);
    if (oldudp == NULL)
        return false;
    if (ntohs(oldudp->len) <= sizeof(*oldudp))
        return false;

    newskb = alloc_skb(LL_MAX_HEADER + sizeof(*newip) +
             sizeof(*newudp) + payload_size, GFP_ATOMIC);
    if (newskb == NULL)
        return false;

    skb_reserve(newskb, LL_MAX_HEADER);
    newskb->protocol = oldskb->protocol;

    skb_reset_network_header(newskb);
    newip = (void *)skb_put(newskb, sizeof(*newip));
    newip->version  = oldip->version;
    newip->ihl      = sizeof(*newip) / 4;
    newip->tos      = oldip->tos;
    newip->id       = oldip->id;
    newip->frag_off = 0;
    newip->protocol = oldip->protocol;
    newip->check    = 0;
    newip->saddr    = oldip->daddr;
    newip->daddr    = oldip->saddr;

    skb_reset_transport_header(newskb);
    newudp = (void *)skb_put(newskb, sizeof(*newudp));
    newudp->source = oldudp->dest;
    newudp->dest   = oldudp->source;
    newudp->len    = htons(sizeof(*newudp) + payload_size);

    memcpy(skb_put(newskb, payload_size), payload, payload_size);
    newip->tot_len = htons(newskb->len);

    newudp->check = 0;
    newudp->check = csum_tcpudp_magic(newip->saddr, newip->daddr,
                    ntohs(newudp->len), IPPROTO_UDP,
                    csum_partial(newudp, ntohs(newudp->len), 0));

    /* ip_route_me_harder expects the skb's dst to be set */
    skb_dst_set(newskb, dst_clone(skb_dst(oldskb)));

    if (ip_route_me_harder(par_net(par), newskb, RTN_UNSPEC) != 0)
        goto free_nskb;

    newip->ttl = ip4_dst_hoplimit(skb_dst(newskb));
    newskb->ip_summed = CHECKSUM_NONE;

    /* "Never happens" (?) */
    if (newskb->len > dst_mtu(skb_dst(newskb)))
        goto free_nskb;

    nf_ct_attach(newskb, oldskb);
    ip_local_out(par_net(par), newskb->sk, newskb);
    return true;

 free_nskb:
    kfree_skb(newskb);
    return false;
}

static const char reset_package[] = {'T', 'S', '3', 'I', 'N', 'I', 'T', '1', 0x65, 0, 0x88, COMMAND_RESET_PUZZLE, 0 };

static unsigned int
ts3init_reset_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    switch (par->family)
    {
        case NFPROTO_IPV4:
            send_ipv4(skb, par, COMMAND_RESET_PUZZLE, reset_package, sizeof(reset_package));
            break;

        case NFPROTO_IPV6:
            send_ipv6(skb, par, COMMAND_RESET_PUZZLE, reset_package, sizeof(reset_package));
            break;
    }
    return NF_DROP;
}

static struct xt_target ts3init_tg_reg[] __read_mostly =
{
    {
        .name       = "ts3init_reset",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .target     = ts3init_reset_tg,
        .me         = THIS_MODULE,
    },
    {
        .name       = "ts3init_reset",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .target     = ts3init_reset_tg,
        .me         = THIS_MODULE,
    },
};

int __init ts3init_target_init(void)
{
    return xt_register_targets(ts3init_tg_reg, ARRAY_SIZE(ts3init_tg_reg));
}

void __exit ts3init_target_exit(void)
{
    xt_unregister_targets(ts3init_tg_reg, ARRAY_SIZE(ts3init_tg_reg));
}
