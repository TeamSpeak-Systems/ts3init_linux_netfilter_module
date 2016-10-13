#ifndef _TS3INIT_HEADER_H
#define _TS3INIT_HEADER_H

struct ts3_init_header_tag
{
    union
    {
        char          tag8[8];
        __aligned_u64 tag64;
    };
};

struct ts3_init_header
{
    struct ts3_init_header_tag tag;
    __be16 packet_id;
    __be16 client_id;
    __u8   flags;
    __u8   client_version[4];
    __u8   command;
    __u8   payload[20];
};

enum
{
    COMMAND_GET_COOKIE = 0,
    COMMAND_SET_COOKIE,
    COMMAND_GET_PUZZLE,
    COMMAND_SET_PUZZLE,
    COMMAND_SOLVE_PUZZLE,
    COMMAND_RESET_PUZZLE,
    COMMAND_MAX,
    COMMAND_RESET = 127
};

#endif /* _TS3INIT_HEADER_H */
