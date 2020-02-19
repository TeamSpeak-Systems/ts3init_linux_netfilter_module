/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                   This is the "caching of cookies" related code
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teampseak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/percpu.h>
#include "ts3init_cookie.h"
#include "ts3init_cache.h"

struct ts3init_cache_t
{
    unsigned long                  saved_jiffies;
    time_t                         unix_time;
    struct xt_ts3init_cookie_cache cookie_cache;
};        

DEFINE_PER_CPU(struct ts3init_cache_t, ts3init_cache);

static inline void update_cache_time(unsigned long jifs,
    struct ts3init_cache_t* cache)
{
    struct timespec64 now;
    if (unlikely(((long)jifs - (long)cache->saved_jiffies) >= HZ)){
        /* it's been 1 second sinds last time update.
         * Get the new unix time and cache it*/
       cache->saved_jiffies = jifs;
       ktime_get_real_ts64(&now);
       cache->unix_time = now.tv_sec;
   }
}

time_t ts3init_get_cached_unix_time(void)
{
    struct ts3init_cache_t* cache;
    unsigned long jifs;
    time_t current_unix_time;

    jifs = jiffies;
            
    cache = &get_cpu_var(ts3init_cache);
            
    update_cache_time(jifs, cache);
            
    current_unix_time = cache->unix_time;
            
    put_cpu_var(ts3init_cache);
    
    return current_unix_time;
}

bool ts3init_get_cookie_seed_for_packet_index(u8 packet_index, const u8* random_seed, u64 (*cookie)[2])
{
    struct ts3init_cache_t* cache;
    u64* result;
    unsigned long jifs;
    time_t current_unix_time;

    jifs = jiffies;
    cache = &get_cpu_var(ts3init_cache);

    update_cache_time(jifs, cache);

    current_unix_time = cache->unix_time;

    result = ts3init_get_cookie_seed(current_unix_time,
             packet_index, &cache->cookie_cache, random_seed);

    if (result)
    {
        (*cookie)[0] = result[0];
        (*cookie)[1] = result[1];
    }
    put_cpu_var(ts3init_cache);
    return result != NULL;
}

bool ts3init_get_current_cookie_seed(const u8* random_seed, u64 (*cookie)[2], u8 *packet_index)
{
    struct ts3init_cache_t* cache;
    u64* result;
    unsigned long jifs;
    time_t current_unix_time;

    jifs = jiffies;
    cache = &get_cpu_var(ts3init_cache);

    update_cache_time(jifs, cache);

    current_unix_time = cache->unix_time;
    
    *packet_index = current_unix_time % 8;
    
    result = ts3init_get_cookie_seed(current_unix_time,
             *packet_index, &cache->cookie_cache, random_seed);

    if (result)
    {
        (*cookie)[0] = result[0];
        (*cookie)[1] = result[1];
    }
    put_cpu_var(ts3init_cache);
    return result != NULL;
}
