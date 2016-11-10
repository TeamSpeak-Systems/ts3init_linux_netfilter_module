/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                   This is the "cookie" related code
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teampseak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include "siphash24.h"
#include "ts3init_random_seed.h"
#include "ts3init_cookie.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define TS3_SHA_512_NAME "sha512"
#else
#include <crypto/hash_info.h>
#define TS3_SHA_512_NAME hash_algo_name[HASH_ALGO_SHA512]
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
#define SHASH_DESC_ON_STACK(shash, ctx)                           \
        char __##shash##_desc[sizeof(struct shash_desc) +         \
                crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
        struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

static struct crypto_shash *sha512_tfm;


static void check_update_seed_cache(time_t time, __u8 index, 
                struct xt_ts3init_cookie_cache* cache,
                const __u8* random_seed)
{
    int ret;
    __le32 seed_hash_time;

    if (time == cache->time[index]) return;

    /* We need to update the cache. */
    /* seed = sha512(random_seed[RANDOM_SEED_LEN] + __le32 time) */
    seed_hash_time = cpu_to_le32( (__u32)time);
    {
        SHASH_DESC_ON_STACK(shash, sha512_tfm);
        shash->tfm = sha512_tfm;
        shash->flags = 0;

        ret = crypto_shash_init(shash);
        if (ret != 0)
        {
            printk(KERN_ERR KBUILD_MODNAME ": could not initalize sha512\n");
            return;
        }

        ret = crypto_shash_update(shash, random_seed, RANDOM_SEED_LEN);
        if (ret != 0)
        {
            printk(KERN_ERR KBUILD_MODNAME ": could not update sha512\n");
            return;
        }

        ret = crypto_shash_finup(shash, (u8*)&seed_hash_time, 4,
            cache->seed8 + index * SHA512_SIZE);            
        if (ret != 0)
        {
            printk(KERN_ERR KBUILD_MODNAME ": could not finup sha512\n");
            return;
        }

        cache->time[index] = time;
    }
}

__u64* ts3init_get_cookie_seed(time_t current_time, __u8 packet_index, 
                struct xt_ts3init_cookie_cache* cache,
                const __u8* random_seed)
{

    __u8 current_cache_index;
    __u8 packet_cache_index;
    time_t current_cache_time;
    time_t packet_cache_time;

    if (packet_index >= 8) return NULL;

    current_cache_index = (current_time % 8) / 4;
    packet_cache_index = packet_index / 4;

    /* get cache time of packet */
    current_cache_time = current_time & ~((time_t)3);
    packet_cache_time = current_cache_time 
        - ((current_cache_index ^ packet_cache_index)*4);

    /* make sure the cache is up-to-date */
    check_update_seed_cache(packet_cache_time, packet_cache_index, cache,
        random_seed);

    /* return the proper seed */
    return cache->seed64 + ((SIP_KEY_SIZE/sizeof(__u64)) * packet_index );
}

int ts3init_calculate_cookie_ipv6(const struct ipv6hdr *ip, const struct udphdr *udp, 
                                  __u64 k0, __u64 k1, __u64* out)
{
    struct ts3init_siphash_state hash_state;

    ts3init_siphash_setup(&hash_state, k0, k1);
    ts3init_siphash_update(&hash_state, (u8 *)&ip->saddr, sizeof(ip->saddr) * 2);
    ts3init_siphash_update(&hash_state, (u8 *)&udp->source, 4);
    *out = ts3init_siphash_finalize(&hash_state);

    return 0;
}

int ts3init_calculate_cookie_ipv4(const struct iphdr *ip, const struct udphdr *udp, 
                                  __u64 k0, __u64 k1, __u64* out)
{
    struct ts3init_siphash_state hash_state;

    ts3init_siphash_setup(&hash_state, k0, k1);
    ts3init_siphash_update(&hash_state, (u8 *)&ip->saddr, sizeof(ip->saddr) * 2);
    ts3init_siphash_update(&hash_state, (u8 *)&udp->source, 4);
    *out = ts3init_siphash_finalize(&hash_state);

    return 0;
}

int __init ts3init_cookie_init(void)
{
    sha512_tfm = crypto_alloc_shash(TS3_SHA_512_NAME, 0, 0);
    if (IS_ERR(sha512_tfm))
    {
        printk(KERN_ERR KBUILD_MODNAME ": could not alloc sha512\n");
        return (int) PTR_ERR(sha512_tfm);
    }
    return 0;
}

void ts3init_cookie_exit(void)
{
    crypto_free_shash(sha512_tfm);
}

