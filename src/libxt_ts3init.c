/*
 *    "ts3init_get_cookie and ts3init_get_puzzle" match extension for iptables
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

#define param_act(t, s, f) xtables_param_act((t), "ts3init_get_cookie", (s), (f))

static void ts3init_get_cookie_help(void)
{
    printf(
        "ts3init_get_cookie match options:\n"
        "  --min-client n The sending client needs to be at least version n.\n"
        "  --check-time sec Check packet send time request. May be off by sec seconds.\n"
    );
}

static const struct option ts3init_get_cookie_opts[] = {
    {.name = "min-client",   .has_arg = true,  .val = '1'},
    {.name = "check-time",   .has_arg = true,  .val = '2'},
    {NULL},
};

static int ts3init_get_cookie_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
    struct xt_ts3init_get_cookie_mtinfo *info = (void *)(*match)->data;
    int client_version;
    int time_offset;

    switch (c) {
    case '1':
        param_act(XTF_ONLY_ONCE, "--min-client", info->common_options & CHK_COMMON_CLIENT_VERSION);
        param_act(XTF_NO_INVERT, "--min-client", invert);
        client_version = atoi(optarg);
        if (client_version <= 0)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init_get_cookie: invalid min-client version");
        info->common_options |= CHK_COMMON_CLIENT_VERSION;
        info->min_client_version = client_version;
        return true;

    case '2':
        param_act(XTF_ONLY_ONCE, "--check-time", info->specific_options & CHK_GET_COOKIE_CHECK_TIMESTAMP);
        param_act(XTF_NO_INVERT, "--check-time", invert);
        time_offset = atoi(optarg);
        if (time_offset <= 0)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init_get_cookie: invalid time offset");
        info->specific_options |= CHK_GET_COOKIE_CHECK_TIMESTAMP;
        info->max_utc_offset = time_offset;
        return true;

    default:
        return false;
    }
}

static void ts3init_get_cookie_save(const void *ip, const struct xt_entry_match *match)
{
    const struct xt_ts3init_get_cookie_mtinfo *info = (const void *)match->data;
    if (info->common_options & CHK_COMMON_CLIENT_VERSION)
    {
        printf("--min-client %u ", info->min_client_version);
    }
    if (info->specific_options & CHK_GET_COOKIE_CHECK_TIMESTAMP)
    {
        printf("--check-time %u ", info->max_utc_offset);
    }
}

static void ts3init_get_cookie_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
    printf(" -m ts3init_get_cookie ");
    ts3init_get_cookie_save(ip, match);
}


#undef  param_act
#define param_act(t, s, f) xtables_param_act((t), "ts3init_get_puzzle", (s), (f))

static bool hex2int_seed(const char *src, __u8* dst)
{
    for (int i = 0; i < 60; ++i)
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

static void ts3init_get_puzzle_help(void)
{
    printf(
        "ts3init_get_puzzle match options:\n"
        "  --min-client n The sending client needs to be at least version n.\n"
        "  --check-cookie seed Check the cookie. Assume it was generated with seed.\n"
        "                      seed is a 60 byte random number in lowecase hex. A source\n"
        "                      could be /dev/random.\n"
);
}

static const struct option ts3init_get_puzzle_opts[] = {
    {.name = "min-client",   .has_arg = true,  .val = '1'},
    {.name = "check-cookie", .has_arg = true,  .val = '2'},
    {NULL},
};

static int ts3init_get_puzzle_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
    struct xt_ts3init_get_puzzle_mtinfo *info = (void *)(*match)->data;
    int client_version;

    switch (c) {
    case '1':
        param_act(XTF_ONLY_ONCE, "--min-client", info->common_options & CHK_COMMON_CLIENT_VERSION);
        param_act(XTF_NO_INVERT, "--min-client", invert);
        client_version = atoi(optarg);
        if (client_version <= 0)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init_get_cookie: invalid min-client version");
        info->common_options |= CHK_COMMON_CLIENT_VERSION;
        info->min_client_version = client_version;
        return true;

    case '2':
        param_act(XTF_ONLY_ONCE, "--check-cookie", info->specific_options & CHK_GET_PUZZLE_CHECK_COOKIE);
        param_act(XTF_NO_INVERT, "--check-cookie", invert);
        if (strlen(optarg) != 120)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init_get_puzzle: invalid cookie-seed length");
        if (!hex2int_seed(optarg, info->cookie_seed))
            xtables_error(PARAMETER_PROBLEM,
                "ts3init_get_puzzle: invalid cookie-seed. (not lowercase hex)");
        info->specific_options |= CHK_GET_PUZZLE_CHECK_COOKIE;
        return true;

    default:
        return false;
    }
}

static void ts3init_get_puzzle_save(const void *ip, const struct xt_entry_match *match)
{
    const struct xt_ts3init_get_puzzle_mtinfo *info = (const void *)match->data;
    if (info->common_options & CHK_COMMON_CLIENT_VERSION)
    {
        printf("--min-client %u ", info->min_client_version);
    }
    if (info->specific_options & CHK_GET_PUZZLE_CHECK_COOKIE)
    {
        printf("--check-cookie ");
        for (int i = 0; i < 60; i++)
        {
                printf("%02X", info->cookie_seed[i]);
        }
        printf(" ");
    }
}

static void ts3init_get_puzzle_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
    printf(" -m ts3init_get_puzzle ");
    ts3init_get_puzzle_save(ip, match);
}

/* register and init */
static struct xtables_match ts3init_get_cookie_mt_reg = {
    .name          = "ts3init_get_cookie",
    .revision      = 0,
    .family        = NFPROTO_UNSPEC,
    .version       = XTABLES_VERSION,
    .size          = XT_ALIGN(sizeof(struct xt_ts3init_get_cookie_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_ts3init_get_cookie_mtinfo)),
    .help          = ts3init_get_cookie_help,
    .parse         = ts3init_get_cookie_parse,
    .print         = ts3init_get_cookie_print,
    .save          = ts3init_get_cookie_save,
    .extra_opts    = ts3init_get_cookie_opts,
};

static struct xtables_match ts3init_get_puzzle_mt_reg = {
    .name          = "ts3init_get_puzzle",
    .revision      = 0,
    .family        = NFPROTO_UNSPEC,
    .version       = XTABLES_VERSION,
    .size          = XT_ALIGN(sizeof(struct xt_ts3init_get_puzzle_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_ts3init_get_puzzle_mtinfo)),
    .help          = ts3init_get_puzzle_help,
    .parse         = ts3init_get_puzzle_parse,
    .print         = ts3init_get_puzzle_print,
    .save          = ts3init_get_puzzle_save,
    .extra_opts    = ts3init_get_puzzle_opts,
};

static __attribute__((constructor)) void ts3init_mt_ldr(void)
{
    xtables_register_match(&ts3init_get_cookie_mt_reg);
    xtables_register_match(&ts3init_get_puzzle_mt_reg);
}

