#ifndef _TS3INIT_CACHE_H
#define _TS3INIT_CACHE_H

/*
 * Returns the current unix_time from cache, updated once every second.
 */
time_t ts3init_get_cached_unix_time(void);


/*
 * Returns the cookie for a packet_index. 
 * If the cookie is not in the cache, it will be generated using the seed.
 */
bool ts3init_get_cookie_for_packet_index(u8 packet_index, const u8* seed, u64 (*cookie)[2]);

/*
 * Returns the current cookie and packet_index.
 * If the cookie is not in the cache, it will be generated using the seed.
 */
bool ts3init_get_current_cookie(const u8* seed, u64 (*cookie)[2], u8 *packet_index);
                
#endif /* _TS3INIT_CACHE_H */
