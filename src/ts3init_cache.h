#ifndef _TS3INIT_CACHE_H
#define _TS3INIT_CACHE_H

time_t ts3init_get_cached_unix_time(void);

bool ts3init_get_cookie_for_packet_index(u8 packet_index, const u8* seed, u64 (*cookie)[2]);

bool ts3init_get_current_cookie(const u8* seed, u64 (*cookie)[2], u8 *packet_index);
                
#endif /* _TS3INIT_CACHE_H */
