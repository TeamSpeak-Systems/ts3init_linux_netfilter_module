#ifndef _TS3INIT_TARGET_H
#define _TS3INIT_TARGET_H

/* Common Enums for targets */
enum
{
    TARGET_COMMON_VALID_MASK = (1 << 0) -1
};

/* Enums and structs for set_cookie */
enum
{
    TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE = 1 << 0,
    TARGET_SET_COOKIE_SEED                 = 1 << 1,
    TARGET_SET_COOKIE_VALID_MASK          = (1 << 2) - 1
};


struct xt_ts3init_set_cookie_tginfo
{
    __u8 common_options;
    __u8 specific_options;
    __u16 reserved1;
    __u8 cookie_seed[COOKIE_SEED_LEN];
};

#endif /* _TS3INIT_TARGET_H */
