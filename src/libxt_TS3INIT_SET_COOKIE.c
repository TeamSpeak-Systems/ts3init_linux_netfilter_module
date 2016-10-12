/*
 *    "ts3init_set_cookie" target extension for iptables
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
#include "ts3init_cookie_seed.h"
#include "ts3init_target.h"

#define param_act(t, s, f) xtables_param_act((t), "ts3init_set_cookie", (s), (f))

static void ts3init_set_cookie_tg_help(void)
{
    printf(
        "TS3INIT_SET_COOKIE match options:\n"
        "  --zero-random-sequence        Always return 0 as random sequence.\n"
        "  --cookie-seed seed            Seed is a 60 byte random number in\n"
        "                                hex. A source could be /dev/random.\n");
}

static const struct option ts3init_set_cookie_tg_opts[] = {
    {.name = "zero-random-sequence", .has_arg = false, .val = '1'},
    {.name = "cookie-seed",          .has_arg = true,  .val = '2'},
    {NULL},
};

static int ts3init_set_cookie_tg_parse(int c, char **argv, 
                                       int invert, unsigned int *flags, const void *entry,
                                       struct xt_entry_target **target)
{
    struct xt_ts3init_set_cookie_tginfo *info = (void *)(*target)->data;
    switch (c) {
    case '1':
        param_act(XTF_ONLY_ONCE, "--zero-random-sequence", info->specific_options & TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE);
        param_act(XTF_NO_INVERT, "--check-time", invert);
        info->specific_options |= TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE;
        return true;
    case '2':
        param_act(XTF_ONLY_ONCE, "--cookie-seed", info->specific_options & TARGET_SET_COOKIE_SEED);
        param_act(XTF_NO_INVERT, "--cookie-seed", invert);
        if (strlen(optarg) != (COOKIE_SEED_LEN * 2))
            xtables_error(PARAMETER_PROBLEM,
                "TS3INIT_SET_COOKIE: invalid cookie-seed length");
        if (!hex2int_seed(optarg, info->cookie_seed))
            xtables_error(PARAMETER_PROBLEM,
                "TS3INIT_SET_COOKIE: invalid cookie-seed. (not lowercase hex)");
        info->specific_options |= TARGET_SET_COOKIE_SEED;
        *flags |= TARGET_SET_COOKIE_SEED;
        return true;

    default:
        return false;
    }
}

static void ts3init_set_cookie_tg_save(const void *ip, const struct xt_entry_target *target)
{
    const struct xt_ts3init_set_cookie_tginfo *info = (const void *)target->data;
    if (info->specific_options & TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE)
    {
        printf("--zero-random-sequence ");
    }
    if (info->specific_options & TARGET_SET_COOKIE_SEED)
    {
        printf("--cookie-seed ");
        for (int i = 0; i < COOKIE_SEED_LEN; i++)
        {
            printf("%02X", info->cookie_seed[i]);
        }
        printf(" ");
    }
}

static void ts3init_set_cookie_tg_print(const void *ip, const struct xt_entry_target *target,
                                     int numeric)
{
    printf(" -j TS3INIT_SET_COOKIE ");
    ts3init_set_cookie_tg_save(ip, target);
}

static void ts3init_set_cookie_tg_check(unsigned int flags)
{
    if ((flags & TARGET_SET_COOKIE_SEED) == 0)
    {
            xtables_error(PARAMETER_PROBLEM, 
                "TS3INIT_SET_COOKIE: --cookie-seed must be specified");
    }
}

/* register and init */
static struct xtables_target ts3init_set_cookie_tg_reg =
{
    .name          = "TS3INIT_SET_COOKIE",
    .revision      = 0,
    .family        = NFPROTO_UNSPEC,
    .version       = XTABLES_VERSION,
    .size          = XT_ALIGN(sizeof(struct xt_ts3init_set_cookie_tginfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_ts3init_set_cookie_tginfo)),
    .help          = ts3init_set_cookie_tg_help,
    .parse         = ts3init_set_cookie_tg_parse,
    .print         = ts3init_set_cookie_tg_print,
    .save          = ts3init_set_cookie_tg_save,
    .final_check   = ts3init_set_cookie_tg_check,
    .extra_opts    = ts3init_set_cookie_tg_opts,
};

static __attribute__((constructor)) void ts3init_set_cookie_tg_ldr(void)
{
    xtables_register_target(&ts3init_set_cookie_tg_reg);
}
