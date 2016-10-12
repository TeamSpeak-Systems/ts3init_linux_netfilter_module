#ifndef _TS3INIT_CACHE_H
#define _TS3INIT_CACHE_H

time_t get_cached_unix_time(void);

bool get_cookie_for_package_index(u8 packet_index, const u8* seed, u64 (*cookie)[2]);

bool get_current_cookie(const u8* seed, u64 (*cookie)[2], u8 *packet_index);
                
#endif /* _TS3INIT_CACHE_H */
