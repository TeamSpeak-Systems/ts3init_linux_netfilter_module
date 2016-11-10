/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                 This is the "match" code
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teamspeak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/percpu.h>
#include "ts3init_random_seed.h"
#include "ts3init_cookie.h"
#include "ts3init_match.h"
#include "ts3init_header.h"
#include "ts3init_cache.h"

/* Magic number of a TS3INIT packet. */
static const struct ts3_init_header_tag ts3init_header_tag_signature =
    {{ .tag8 = {'T', 'S', '3', 'I', 'N', 'I', 'T', '1'} }};


struct ts3_init_checked_client_header_data
{
    struct udphdr *udp, udp_buf;
    struct ts3_init_client_header* ts3_header, ts3_header_buf;
};

struct ts3_init_checked_server_header_data
{
    struct udphdr *udp, udp_buf;
    struct ts3_init_server_header* ts3_header, ts3_header_buf;
};

static const int ts3init_payload_sizes[] = { 16, 20, 20, 244, -1, 1 };

/* 
 * Check that skb contains a valid TS3INIT client header.
 * Also initializes header_data, and checks client version.
 */
static bool check_client_header(const struct sk_buff *skb, const struct xt_action_param *par,
    struct ts3_init_checked_client_header_data* header_data, __u32 min_client_version)
{
    unsigned int data_len;
    struct udphdr *udp;
    struct ts3_init_client_header* ts3_header;

    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &header_data->udp_buf);
    data_len = be16_to_cpu(udp->len) - sizeof(*udp);

    if (data_len < TS3INIT_HEADER_CLIENT_LENGTH)
        return false;

    ts3_header = (struct ts3_init_client_header*) skb_header_pointer(skb, 
        par->thoff + sizeof(*udp), TS3INIT_HEADER_CLIENT_LENGTH,
        &header_data->ts3_header_buf);

    if (!ts3_header) return false;

    if (ts3_header->tag.tag64 != ts3init_header_tag_signature.tag64) return false;
    if (ts3_header->packet_id != cpu_to_be16(101)) return false;
    if (ts3_header->client_id != 0) return false;
    if (ts3_header->flags != 0x88) return false;

    /* check min_client_version if needed */
    if (min_client_version)
    {
        /* the client version is unaligned in the packet.
         * load it byte for byte. big endian*/
        __u8* v = ts3_header->client_version;
        __u32 packet_min_client_version =
            ((__u32)v[0]) << 24 | ((__u32)v[1]) << 16 |
            ((__u32)v[1]) <<  8 | ((__u32)v[3]);

        if (packet_min_client_version < min_client_version)
            return false;
    }

    header_data->udp = udp;
    header_data->ts3_header = ts3_header;
    return true;
}

/*
 * Check that skb contains a valid TS3INIT server header.
 */
static bool check_server_header(const struct sk_buff *skb, const struct xt_action_param *par,
    struct ts3_init_checked_server_header_data* header_data)
{
    unsigned int data_len;
    struct udphdr *udp;
    struct ts3_init_server_header* ts3_header;

    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &header_data->udp_buf);
    data_len = be16_to_cpu(udp->len) - sizeof(*udp);

    if (data_len < TS3INIT_HEADER_SERVER_LENGTH) return false;

    ts3_header = (struct ts3_init_server_header*) skb_header_pointer(skb, 
        par->thoff + sizeof(*udp), TS3INIT_HEADER_SERVER_LENGTH,
        &header_data->ts3_header_buf);

    if (!ts3_header) return false;

    if (ts3_header->tag.tag64 != ts3init_header_tag_signature.tag64) return false;
    if (ts3_header->packet_id != cpu_to_be16(101)) return false;
    if (ts3_header->flags != 0x88) return false;

    header_data->udp = udp;
    header_data->ts3_header = ts3_header;
    return true;
}

static inline __u8* get_payload(const struct sk_buff *skb, const struct xt_action_param *par,
                         const struct ts3_init_checked_client_header_data* header_data,
                         __u8 *buf, size_t buf_size)
{
    const int header_len = sizeof(*header_data->udp) + TS3INIT_HEADER_CLIENT_LENGTH;
    unsigned int data_len = be16_to_cpu(header_data->udp->len) - header_len;
    if (data_len < buf_size)
        return NULL;
    return skb_header_pointer(skb, par->thoff + header_len, buf_size, buf);
}

/*
 * Hashes the cookie with source/destination address/port.
 */
static int calculate_cookie(const struct sk_buff *skb, const struct xt_action_param *par, 
                       struct udphdr *udp, __u64 k0, __u64 k1, __u64* out)
{
    switch (par->family)
    {
    case NFPROTO_IPV4:
        {
            const struct iphdr *ip;

            ip  = ip_hdr(skb);
            if (ip == NULL)
            {
                printk(KERN_ERR KBUILD_MODNAME ": could not load ipv4 addresses\n");
                return -EINVAL;
            }

            return ts3init_calculate_cookie_ipv4(ip, udp, k0, k1, out);
        }

    case NFPROTO_IPV6:
        {
            const struct ipv6hdr *ip;

            ip  = ipv6_hdr(skb);
            if (ip == NULL)
            {
                printk(KERN_ERR KBUILD_MODNAME ": could not load ipv6 addresses\n");
                return -EINVAL;
            }

            return ts3init_calculate_cookie_ipv6(ip, udp, k0, k1, out);
        }
    default:
        printk(KERN_ERR KBUILD_MODNAME ": invalid family\n");
        return -EINVAL;
    }
}

/*
 * The 'ts3init_get_cookie' match handler.
 * Checks that the packet is a valid COMMAND_GET_COOKIE.
 */
static bool
ts3init_get_cookie_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct xt_ts3init_get_cookie_mtinfo *info = par->matchinfo;
    struct ts3_init_checked_client_header_data header_data;

    if (!check_client_header(skb, par, &header_data, info->min_client_version))
        return false;

    if (header_data.ts3_header->command != COMMAND_GET_COOKIE) return false;

    if (info->specific_options & CHK_GET_COOKIE_CHECK_TIMESTAMP)
    {
        __u8 *payload, payload_buf[ts3init_payload_sizes[COMMAND_GET_COOKIE]];
        time_t current_unix_time, packet_unix_time;

        payload = get_payload(skb, par, &header_data, payload_buf, sizeof(payload_buf));
        if (!payload)
            return false;

        current_unix_time = ts3init_get_cached_unix_time();

        packet_unix_time =
            payload[0] << 24 |
            payload[1] << 16 |
            payload[2] << 8  |
            payload[3];

        if (abs(current_unix_time - packet_unix_time) > info->max_utc_offset)
            return false;
    }
    return true;
}

/*
 * Validates matchinfo recieved from userspace.
 */
static int ts3init_get_cookie_mt_check(const struct xt_mtchk_param *par)
{
    struct xt_ts3init_get_cookie_mtinfo *info = par->matchinfo;

    if (! (par->family == NFPROTO_IPV4 || par->family == NFPROTO_IPV6))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid protocol (only ipv4 and ipv6) for get_cookie\n");
        return -EINVAL;
    }

    if (info->common_options & ~(CHK_COMMON_VALID_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid (common) options for get_cookie\n");
        return -EINVAL;
    }

    if (info->specific_options & ~(CHK_GET_COOKIE_VALID_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid (specific) options for get_cookie\n");
        return -EINVAL;
    }

    return 0;
}

/*
 * The 'ts3init_get_cookie' match handler.
 * Checks that the packet is a valid COMMAND_GET_PUZZLE, and if the client
 * replied with the correct cookie.
 */
static bool ts3init_get_puzzle_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct xt_ts3init_get_puzzle_mtinfo *info = par->matchinfo;
    struct ts3_init_checked_client_header_data header_data;

    if (!check_client_header(skb, par, &header_data, info->min_client_version))
        return false;

    if (header_data.ts3_header->command != COMMAND_GET_PUZZLE) return false;

    if (info->specific_options & CHK_GET_PUZZLE_CHECK_COOKIE)
    {
        __u8 *payload, payload_buf[ts3init_payload_sizes[COMMAND_GET_PUZZLE]];
        __u64 cookie_seed[2];
        __u64 cookie, packet_cookie;

        payload = get_payload(skb, par, &header_data, payload_buf, sizeof(payload_buf));
        if (!payload)
            return false;

        if (ts3init_get_cookie_seed_for_packet_index(payload[8], info->random_seed, &cookie_seed) == false)
            return false;

        /* use cookie_seed and ipaddress and port to create a hash
         * (cookie) for this connection */
        if (calculate_cookie(skb, par, header_data.udp, cookie_seed[0], cookie_seed[1], &cookie))
            return false; /*something went wrong*/

        /* compare cookie with payload bytes 0-7. if equal, cookie
         * is valid */

        packet_cookie = (((u64)((payload)[0])) | ((u64)((payload)[1]) << 8) |
           ((u64)((payload)[2]) << 16) | ((u64)((payload)[3]) << 24) |
           ((u64)((payload)[4]) << 32) | ((u64)((payload)[5]) << 40) |
           ((u64)((payload)[6]) << 48) | ((u64)((payload)[7]) << 56));

        if (packet_cookie != cookie) return false;
    }
    return true;
}

/*
 * Validates matchinfo recieved from userspace.
 */
static int ts3init_get_puzzle_mt_check(const struct xt_mtchk_param *par)
{
    struct xt_ts3init_get_puzzle_mtinfo *info = par->matchinfo;

        if (! (par->family == NFPROTO_IPV4 || par->family == NFPROTO_IPV6))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid protocol (only ipv4 and ipv6) for get_puzzle\n");
        return -EINVAL;
    }

    if (info->common_options & ~(CHK_COMMON_VALID_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid (common) options for get_puzzle\n");
        return -EINVAL;
    }

    if (info->specific_options & ~(CHK_GET_PUZZLE_VALID_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid (specific) options for get_puzzle\n");
        return -EINVAL;
    }

    return 0;
}

/*
 * The 'ts3init' match handler.
 * Checks that the packet is a valid ts3init packet
 */
static bool ts3init_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct xt_ts3init_mtinfo *info = par->matchinfo;

    if (info->specific_options & CHK_TS3INIT_CLIENT)
    {
        struct ts3_init_checked_client_header_data header_data;

        if (!check_client_header(skb, par, &header_data, 0))
            return false;
        if (info->specific_options & CHK_TS3INIT_COMMAND)
        {
            if (header_data.ts3_header->command != info->command)
                return false;
        }
    }
    else if (info->specific_options & CHK_TS3INIT_SERVER)
    {
        struct ts3_init_checked_server_header_data header_data;

        if (!check_server_header(skb, par, &header_data))
            return false;
        if (info->specific_options & CHK_TS3INIT_COMMAND)
        {
            if (header_data.ts3_header->command != info->command)
                return false;
        }
    }
    else
    {
        struct udphdr *udp, udp_buf;
        u64 *signature, signature_buf;

        udp = skb_header_pointer(skb, par->thoff, sizeof(udp_buf), &udp_buf);
        if (!udp)
            return false;
        signature = skb_header_pointer(skb, par->thoff + sizeof(*udp),
                        sizeof(signature_buf), &signature_buf);

        if (!signature || *signature != ts3init_header_tag_signature.tag64)
            return false;
    }
    return true;
}

/*
 * Validates matchinfo recieved from userspace.
 */
static int ts3init_check(const struct xt_mtchk_param *par)
{
    struct xt_ts3init_get_puzzle_mtinfo *info = par->matchinfo;

    if (info->common_options & ~(CHK_COMMON_VALID_MASK))
    {
        printk(KERN_ERR KBUILD_MODNAME ": invalid (common) options for ts3init\n");
        return -EINVAL;
    }

    if (info->specific_options & ~(CHK_TS3INIT_VALID_MASK))
    {
        printk(KERN_ERR KBUILD_MODNAME ": invalid (specific) options for ts3init\n");
        return -EINVAL;
    }

    return 0;
}

static struct xt_match ts3init_mt_reg[] __read_mostly =
{
    {
        .name       = "ts3init_get_cookie",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_get_cookie_mtinfo),
        .match      = ts3init_get_cookie_mt,
        .checkentry = ts3init_get_cookie_mt_check,
        .me         = THIS_MODULE,
    },
    {
        .name       = "ts3init_get_cookie",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_get_cookie_mtinfo),
        .match      = ts3init_get_cookie_mt,
        .checkentry = ts3init_get_cookie_mt_check,
        .me         = THIS_MODULE,
    },
    {
        .name       = "ts3init_get_puzzle",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_get_puzzle_mtinfo),
        .match      = ts3init_get_puzzle_mt,
        .checkentry = ts3init_get_puzzle_mt_check,
        .me         = THIS_MODULE,
    },
    {
        .name       = "ts3init_get_puzzle",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_get_puzzle_mtinfo),
        .match      = ts3init_get_puzzle_mt,
        .checkentry = ts3init_get_puzzle_mt_check,
        .me         = THIS_MODULE,
    },
    {
        .name       = "ts3init",
        .revision   = 0,
        .family     = NFPROTO_UNSPEC,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_mtinfo),
        .match      = ts3init_mt,
        .checkentry = ts3init_check,
        .me         = THIS_MODULE,
    },
};

int __init ts3init_match_init(void)
{
    return xt_register_matches(ts3init_mt_reg, ARRAY_SIZE(ts3init_mt_reg));
}

void ts3init_match_exit(void)
{
    xt_unregister_matches(ts3init_mt_reg, ARRAY_SIZE(ts3init_mt_reg));
}
