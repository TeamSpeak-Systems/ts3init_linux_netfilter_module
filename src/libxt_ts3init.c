/*
 *    "ts3init" match extension for iptables
 *    Niels Werensteijn <niels werensteijn [at] teamspeak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>
#include "ts3init_match.h"
/*
#include "compat_user.h"
*/
#define param_act(t, s, f) xtables_param_act((t), "ts3init", (s), (f))

static void ts3init_help(void)
{
    printf(
"ts3init match options:\n"
"  --get-cookie Check if packet is 'get-cookie' request.\n"
"  --get-puzzle Check if packet is 'get-puzzle' request.\n"
"  --min-client n The sending client needs to be at least version n.\n"
"\n"
"get-cookie options:\n"
"  --check-time sec Check packet send time request. May be off by sec seconds.\n"
"\n"
"get-puzzle options:\n"
"  --check-cookie seed Check the cookie. Assume it was generated with seed.\n"
"                      seed is a 64 byte random number in lowecase hex. Could be\n"
"                      generated with sha512 of something.\n"
);
}

static const struct option ts3init_opts[] = {
    {.name = "get-cookie",   .has_arg = false, .val = '1'},
    {.name = "get-puzzle",   .has_arg = false, .val = '2'},
    {.name = "min-client",   .has_arg = true,  .val = '3'},
    {.name = "check-time",   .has_arg = true,  .val = '4'},
    {.name = "check-cookie", .has_arg = true,  .val = '5'},
    {NULL},
};

static bool hex2int_seed(const char *src, __u8* dst)
{
    for (int i = 0; i < 64; ++i)
    {
        int v = 0;
        for (int j = 0; j < 2; ++j)
        {
            uint8_t byte = *src++; 
                if (byte >= '0' && byte <= '9') byte = byte - '0';
                else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
                else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;
            else return false;
                v = (v << 4) | byte;
        }
        *dst++ = v;
    }
    return true;
}

static int ts3init_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
    struct xt_ts3init_mtinfo *info = (void *)(*match)->data;
    int client_version;
    int time_offset;

    switch (c) {
    case '1':
        param_act(XTF_ONLY_ONCE, "--get-cookie", (*flags & COMMAND_MASK) == COMMAND_CHECK_GET_COOKIE);
        param_act(XTF_NO_INVERT, "--get-cookie", invert);
        if ((*flags & COMMAND_MASK) == COMMAND_CHECK_GET_PUZZLE)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: use `--get-cookie' OR `--get-puzzle' but not both of them!");
        *flags |= COMMAND_CHECK_GET_COOKIE;
        info->command_check_and_options |= COMMAND_CHECK_GET_COOKIE;
        return true;

    case '2':
        param_act(XTF_ONLY_ONCE, "--get-puzzle", (*flags & COMMAND_MASK) == COMMAND_CHECK_GET_PUZZLE);
        param_act(XTF_NO_INVERT, "--get-puzzle", invert);
        if ((*flags & COMMAND_MASK) == COMMAND_CHECK_GET_COOKIE)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: use `--get-cookie' OR `--get-puzzle' but not both of them!");
        *flags |= COMMAND_CHECK_GET_PUZZLE;
        info->command_check_and_options |= COMMAND_CHECK_GET_PUZZLE;
        return true;

    case '3':
        param_act(XTF_ONLY_ONCE, "--min-client", *flags & CHK_COMMON_CLIENT_VERSION);
        param_act(XTF_NO_INVERT, "--min-client", invert);
        client_version = atoi(optarg);
        if (client_version <= 0)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: invalid min-client version");
        *flags |= CHK_COMMON_CLIENT_VERSION;
        info->command_check_and_options |= CHK_COMMON_CLIENT_VERSION;
        info->min_client_version = client_version;
        return true;

    case '4':
        param_act(XTF_ONLY_ONCE, "--check-time", *flags & CHK_GET_COOKIE_CHECK_TIMESTAMP);
        param_act(XTF_NO_INVERT, "--check-time", invert);
        if ((*flags & COMMAND_MASK) != COMMAND_CHECK_GET_COOKIE)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: --check-time can only work together with --get-cookie");
        time_offset = atoi(optarg);
        if (time_offset <= 0)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: invalid time offset");
        *flags |= CHK_GET_COOKIE_CHECK_TIMESTAMP;
        info->command_check_and_options |= CHK_GET_COOKIE_CHECK_TIMESTAMP;
        info->get_cookie_opts.max_utc_offset = time_offset;
        return true;

    case '5':
        param_act(XTF_ONLY_ONCE, "--check-cookie", *flags & CHK_GET_PUZZLE_CHECK_COOKIE);
        param_act(XTF_NO_INVERT, "--check-cookie", invert);
        if ((*flags & COMMAND_MASK) != COMMAND_CHECK_GET_PUZZLE)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: --check-cookie can only work together with --get-puzzle");
        if (strlen(optarg) != 128)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: invalid cookie-seed length");
        if (!hex2int_seed(optarg, info->get_puzzle_opts.cookie_seed))
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: invalid cookie-seed. (not lowercase hex)");
        *flags |= CHK_GET_PUZZLE_CHECK_COOKIE;
        info->command_check_and_options |= CHK_GET_PUZZLE_CHECK_COOKIE;
        return true;

    default:
        return false;
    }
}

static void ts3init_check(unsigned int flags)
{
    if ((flags & COMMAND_MASK) == 0)
        xtables_error(PARAMETER_PROBLEM,
               "TS3init match: must specify --get-cookie or --get-puzzle");
}

static void ts3init_save(const void *ip, const struct xt_entry_match *match)
{
    const struct xt_ts3init_mtinfo *info = (const void *)match->data;
    if ((info->command_check_and_options & COMMAND_MASK) == COMMAND_CHECK_GET_COOKIE)
    {
        printf("--get-cookie ");
    }
    else 
    {
        printf("--get-puzzle ");
    }
    if (info->command_check_and_options & CHK_COMMON_CLIENT_VERSION)
    {
        printf("--min-client %u ", info->min_client_version);
    }
    if ((info->command_check_and_options & COMMAND_MASK) == COMMAND_CHECK_GET_COOKIE)
    {
        if (info->command_check_and_options & CHK_GET_COOKIE_CHECK_TIMESTAMP)
        {
            printf("--check-time %u ", info->get_cookie_opts.max_utc_offset);
        }
    }
    else 
    {
        if (info->command_check_and_options & CHK_GET_PUZZLE_CHECK_COOKIE)
        {
            printf("--check-cookie ");
            for (int i = 0; i < 64; i++)
            {
                    printf("%02X", info->get_puzzle_opts.cookie_seed[i]);
            }
            printf(" ");
        }
    }

}

static void ts3init_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
    printf(" -m ts3init ");
    ts3init_save(ip, match);
}

static struct xtables_match ts3init_mt_reg = {
    .name         = "ts3init",
    .revision    = 0,
    .family        = NFPROTO_UNSPEC,
    .version     = XTABLES_VERSION,
    .size         = XT_ALIGN(sizeof(struct xt_ts3init_mtinfo)),
    .userspacesize     = XT_ALIGN(sizeof(struct xt_ts3init_mtinfo)),
    .help         = ts3init_help,
    .parse         = ts3init_parse,
    .final_check    = ts3init_check,
    .print         = ts3init_print,
    .save         = ts3init_save,
    .extra_opts     = ts3init_opts,
};

static __attribute__((constructor)) void ts3init_mt_ldr(void)
{
    xtables_register_match(&ts3init_mt_reg);
}

