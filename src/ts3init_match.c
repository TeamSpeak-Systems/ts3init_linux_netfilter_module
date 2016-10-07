/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                 This is the "match" code
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teampseak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/percpu.h>
#include "ts3init_match.h"
#include "ts3init_cookie.h"

struct ts3init_cache_t
{
    unsigned long                  saved_jiffies;
    time_t                         unix_time;
    struct xt_ts3init_cookie_cache cookie_cache;
};        

struct ts3_init_header_tag
{
    union {
        char          tag8[8];
        __aligned_u64 tag64;
    };
};

struct ts3_init_header
{
    struct ts3_init_header_tag tag;
    __be16 packet_id;
    __be16 client_id;
    __u8   flags;
    __u8   client_version_0;
    __u8   client_version_1;
    __u8   client_version_2;
    __u8   client_version_3;
    __u8   command;
    __u8   payload[20];
};

static const __u16 packet_payload_size[2] = { 34, 38 };

static const struct ts3_init_header_tag header_tag_signature =
    { .tag8 = {'T', 'S', '3', 'I', 'N', 'I', 'T', '1'} };

DEFINE_PER_CPU(struct ts3init_cache_t, ts3init_cache);

static inline void update_cache_time(unsigned long jifs,
    struct ts3init_cache_t* cache)
{
    if (((long)jifs - (long)cache->saved_jiffies) >= HZ)
    {
        /* it's been 1 second sinds last time update.
         * Get the new unix time and cache it*/
       struct timeval tv;
       cache->saved_jiffies = jifs;
       do_gettimeofday(&tv);
       cache->unix_time = tv.tv_sec;
   }
}

static bool
ts3init_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    struct udphdr *udp, udp_buf;
    struct ts3init_cache_t* cache;
    unsigned int data_len;
    unsigned long jifs;
    time_t current_unix_time, packet_unix_time;
    struct ts3_init_header* ts3_header, ts3_header_buf;
    const struct xt_ts3init_mtinfo *info = par->matchinfo;
    __u8* cookie_seed;
    __u8  cookie[8];

    __u8 command = info->command_check_and_options & COMMAND_MASK;

    udp = skb_header_pointer(skb, par->thoff, sizeof(*udp), &udp_buf);
    data_len = be16_to_cpu(udp->len) - sizeof(*udp);

    if (data_len != packet_payload_size[command-1]) return false;

    ts3_header = (struct ts3_init_header*) skb_header_pointer(skb, 
        par->thoff + sizeof(*udp), data_len, &ts3_header_buf);

    if (!ts3_header) return false;

    if (ts3_header->tag.tag64 != header_tag_signature.tag64) return false;
    if (ts3_header->packet_id != cpu_to_be16(101)) return false;
    if (ts3_header->client_id != 0) return false;
    if (ts3_header->flags != 0x88) return false;

    /* TODO: check min_client_version if needed */
    
    switch (command)
    {
        case COMMAND_CHECK_GET_COOKIE:
        {
            if (ts3_header->command != 0) return false;

            if (info->command_check_and_options & CHK_GET_COOKIE_CHECK_TIMESTAMP)
            {
                jifs = jiffies;
                
                cache = &get_cpu_var(ts3init_cache);
                
                update_cache_time(jifs, cache);
                
                current_unix_time = cache->unix_time;
                
                put_cpu_var(ts3init_cache);

                packet_unix_time =
                    ts3_header->payload[0] << 24 |
                    ts3_header->payload[1] << 16 |
                    ts3_header->payload[2] << 8  |
                    ts3_header->payload[3];

                if (abs(current_unix_time - packet_unix_time) > 
                    info->get_cookie_opts.max_utc_offset) return false;
            }
            return true;
        }
        
        case COMMAND_CHECK_GET_PUZZLE:
        {
            if (ts3_header->command != 2) return false;

            if (info->command_check_and_options & CHK_GET_PUZZLE_CHECK_COOKIE)
            {
                jifs = jiffies;
                cache = &get_cpu_var(ts3init_cache);

                update_cache_time(jifs, cache);

                current_unix_time = cache->unix_time;
                
                cookie_seed = get_cookie_seed(current_unix_time,
                    ts3_header->payload[8], &cache->cookie_cache,
                    info->get_puzzle_opts.cookie_seed);
                    
                if (!cookie_seed)
                {
                    put_cpu_var(ts3init_cache);
                    return false;
                }
                
                /* use cookie_seed and ipaddress and port to create a hash
                 * (cookie) for this connection */
                /* TODO: implement using sipHash */ 
                put_cpu_var(ts3init_cache);

                /* compare cookie with payload bytes 0-7. if equal, cookie
                 * is valid */
                /*if (memcmp(cookie, ts3_header->payload, 8) != 0) return false;*/
                
            }
            return true;
        }
        
        default:
            return false;
    };
}

static int ts3init_mt_check(const struct xt_mtchk_param *par)
{
    struct xt_ts3init_mtinfo *info = par->matchinfo;
    __u8 command;

    if (info->command_check_and_options &
        ~(COMMAND_AND_CHK_COMMON_MASK | COMMAND_SPECIFIC_OPTIONS_MASK))
    {
        printk(KERN_INFO KBUILD_MODNAME ": invalid command or common options\n");
        return -EINVAL;
    }

    command = info->command_check_and_options & COMMAND_MASK;
    switch (command)
    {
        case COMMAND_CHECK_GET_COOKIE:
        {
            if (info->command_check_and_options & 
                ~(COMMAND_AND_CHK_COMMON_MASK | CHK_GET_COOKIE_MASK))
            {
                printk(KERN_INFO KBUILD_MODNAME ": invalid get_cookie options\n");
                return -EINVAL;
            }
            return 0;
        }
        case COMMAND_CHECK_GET_PUZZLE:
        {
            if (info->command_check_and_options & 
                ~(COMMAND_AND_CHK_COMMON_MASK | CHK_GET_PUZZLE_MASK))
            {
                printk(KERN_INFO KBUILD_MODNAME ": invalid get_puzzle options\n");
                return -EINVAL;
            }
            return 0;
        }
        default:
        {
            printk(KERN_INFO KBUILD_MODNAME ": invalid command value\n");
            return -EINVAL;
        }
    }
}    

static void ts3init_mt_destroy(const struct xt_mtdtor_param *par)
{
}

static struct xt_match ts3init_mt_reg[] __read_mostly = {
    {
        .name       = "ts3init",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_mtinfo),
        .match      = ts3init_mt,
        .checkentry = ts3init_mt_check,
        .destroy    = ts3init_mt_destroy,
        .me         = THIS_MODULE,
    },
    {
        .name       = "ts3init",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .proto      = IPPROTO_UDP,
        .matchsize  = sizeof(struct xt_ts3init_mtinfo),
        .match      = ts3init_mt,
        .checkentry = ts3init_mt_check,
        .destroy    = ts3init_mt_destroy,
        .me         = THIS_MODULE,
    },
};

