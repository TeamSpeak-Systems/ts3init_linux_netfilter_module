#ifndef _TS3INIT_CACHE_H
#define _TS3INIT_CACHE_H

/*
 * Returns the current unix_time from cache, updated once every second.
 */
time_t ts3init_get_cached_unix_time(void);


/*
 * Returns the cookie seed for a packet_index. 
 * If the cookie seed is not in the cache, it will be generated using the random seed.
 */
bool ts3init_get_cookie_seed_for_packet_index(u8 packet_index, const u8* random_seed, u64 (*cookie)[2]);

/*
 * Returns the current cookie seed and packet_index.
 * If the cookie seed is not in the cache, it will be generated using the random seed.
 */
bool ts3init_get_current_cookie_seed(const u8* random_seed, u64 (*cookie)[2], u8 *packet_index);
                
#endif /* _TS3INIT_CACHE_H */
