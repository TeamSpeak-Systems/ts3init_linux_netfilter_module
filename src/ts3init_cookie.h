#ifndef _TS3INIT_COOKIE_H
#define _TS3INIT_COOKIE_H

enum {
    SHA512_SIZE = 64,
    SIP_KEY_SIZE = 16
};

struct xt_ts3init_cookie_cache
{
    time_t time[2];
    __u8 __attribute__((aligned(8))) seed[SHA512_SIZE*2];
};

#endif /* _TS3INIT_COOKIE_H */
