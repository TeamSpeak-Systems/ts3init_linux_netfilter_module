#ifndef _TS3INIT_MATCH_H
#define _TS3INIT_MATCH_H

enum {
    SEED_SHA512_LEN = 512 / 8
};

enum {
    COMMAND_CHECK_GET_COOKIE = 1,
    COMMAND_CHECK_GET_PUZZLE = 2,
    COMMAND_MASK = 3,

    CHK_COMMON_CLIENT_VERSION = 1 << 2,
    CHK_COMMON_MASK = 1 << 2,

    COMMAND_AND_CHK_COMMON_MASK = COMMAND_MASK | CHK_COMMON_MASK,
    COMMAND_SPECIFIC_OPTIONS_MASK = 0xf0
};

enum { 
    CHK_GET_COOKIE_CHECK_TIMESTAMP = 1 << 4,
    CHK_GET_COOKIE_MASK = 1 << 4
};

enum{
    CHK_GET_PUZZLE_CHECK_COOKIE = 1 << 4,
    CHK_GET_PUZZLE_MASK = 1 << 4
};

struct xt_ts3init_mtinfo {
    __u8 command_check_and_options;
    __u32 min_client_version;
    union{
        struct {
            __u32 max_utc_offset;
        } get_cookie_opts;
        struct {
            __u8 cookie_seed[SEED_SHA512_LEN];
        } get_puzzle_opts;
    };
};

#endif /* _TS3INIT_MATCH_H */
