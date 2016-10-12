#ifndef _TS3INIT_MATCH_H
#define _TS3INIT_MATCH_H

/* Enums for get_cookie and get_puzzle matches */
enum
{
    CHK_COMMON_CLIENT_VERSION = 1 << 0,
    CHK_COMMON_VALID_MASK     = (1 << 1) -1,

    CLIENT_VERSION_OFFSET     = 1356998400
};

/* Enums and structs for get_cookie */
enum
{ 
    CHK_GET_COOKIE_CHECK_TIMESTAMP = 1 << 0,
    CHK_GET_COOKIE_VALID_MASK      = (1 << 1) -1
};

struct xt_ts3init_get_cookie_mtinfo
{
    __u8 common_options;
    __u8 specific_options;
    __u16 reserved1;
    __u32 min_client_version;
    __u32 max_utc_offset;
};


/* Enums and structs for get_puzzle */
enum
{
    CHK_GET_PUZZLE_CHECK_COOKIE = 1 << 0,
    CHK_GET_PUZZLE_VALID_MASK   = (1 << 1) - 1,
};

struct xt_ts3init_get_puzzle_mtinfo
{
    __u8 common_options;
    __u8 specific_options;
    __u16 reserved1;
    __u32 min_client_version;
    __u8 cookie_seed[COOKIE_SEED_LEN];
};

#endif /* _TS3INIT_MATCH_H */
