#ifndef _TS3INIT_COOKIE_H
#define _TS3INIT_COOKIE_H

enum
{
    SHA512_SIZE = 64,
    SIP_KEY_SIZE = 16
};

struct xt_ts3init_cookie_cache
{
    time_t time[2];
    union
    {
        __u8 seed8[SHA512_SIZE*2];
        __u64 seed64[(SHA512_SIZE/sizeof(__u64))*2];
    };
};

/*
 * Returns the cookie seed that fits current_time and packet_index.
 * If the cookie seed is missing in cache it will be generated using 
 * random_seed and current_time
 */
__u64* ts3init_get_cookie_seed(time_t current_time, __u8 packet_index, 
                struct xt_ts3init_cookie_cache* cache,
                const __u8* random_seed);

/* 
 * Returns a valid cookie. 
 * The cookie is generated from a cookie seed and ip and port from the source 
 * and destination. Ip and udp are the recieved headers from the client, 
 * k0 and k1 are the cookie seed, and out is the resulting hash.
 */
int ts3init_calculate_cookie_ipv6(const struct ipv6hdr *ip, const struct udphdr *udp, 
                                  __u64 k0, __u64 k1, __u64* out);
int ts3init_calculate_cookie_ipv4(const struct iphdr *ip, const struct udphdr *udp, 
                                  __u64 k0, __u64 k1, __u64* out);

#endif /* _TS3INIT_COOKIE_H */
