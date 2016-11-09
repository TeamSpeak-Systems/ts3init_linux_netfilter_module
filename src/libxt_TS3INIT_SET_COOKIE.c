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
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "ts3init_random_seed.h"
#include "ts3init_target.h"

#define param_act(t, s, f) xtables_param_act((t), "TS3INIT_SET_COOKIE", (s), (f))

static void ts3init_set_cookie_tg_help(void)
{
    printf(
        "TS3INIT_SET_COOKIE target options:\n"
        "  --zero-random-sequence       Always return 0 as random sequence.\n"
        "  --random-seed <seed>         Seed is a %i byte hex number in.\n"
        "                               A source could be /dev/random.\n"
        "  --random-seed-file <file>    Read the seed from a file.\n",
        RANDOM_SEED_LEN);
}

static const struct option ts3init_set_cookie_tg_opts[] = {
    {.name = "zero-random-sequence", .has_arg = false, .val = '1'},
    {.name = "random-seed",          .has_arg = true,  .val = '2'},
    {.name = "random-seed-file",     .has_arg = true,  .val = '3'},
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
        param_act(XTF_NO_INVERT, "--zero-random-sequence", invert);
        info->specific_options |= TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE;
        return true;
    case '2':
        param_act(XTF_ONLY_ONCE, "--random-seed", *flags & TARGET_SET_COOKIE_RANDOM_SEED_FROM_ARGUMENT);
        param_act(XTF_NO_INVERT, "--random-seed", invert);
        if (strlen(optarg) != (RANDOM_SEED_LEN * 2))
            xtables_error(PARAMETER_PROBLEM,
                "TS3INIT_SET_COOKIE: invalid random seed length");
        if (!parse_random_seed(optarg, info->random_seed))
            xtables_error(PARAMETER_PROBLEM,
                "TS3INIT_SET_COOKIE: invalid random seed. (not lowercase hex)");
        info->specific_options |= TARGET_SET_COOKIE_RANDOM_SEED_FROM_ARGUMENT;
        *flags |= TARGET_SET_COOKIE_RANDOM_SEED_FROM_ARGUMENT;
        return true;

    case '3':
        param_act(XTF_ONLY_ONCE, "--random-seed-file", *flags & TARGET_SET_COOKIE_RANDOM_SEED_FROM_FILE);
        param_act(XTF_NO_INVERT, "--random-seed-file", invert);

        if (read_random_seed_from_file("TS3INIT_SET_COOKIE", optarg, info->random_seed))
            memcpy(info->random_seed_path, optarg, strlen(optarg) + 1);
        info->specific_options |= TARGET_SET_COOKIE_RANDOM_SEED_FROM_FILE;
        *flags |= TARGET_SET_COOKIE_RANDOM_SEED_FROM_FILE;
        return true;

    default:
        return false;
    }
}

static void ts3init_set_cookie_tg_save(const void *ip, const struct xt_entry_target *target)
{
    int i;
    const struct xt_ts3init_set_cookie_tginfo *info = (const void *)target->data;
    if (info->specific_options & TARGET_SET_COOKIE_ZERO_RANDOM_SEQUENCE)
    {
        printf(" --zero-random-sequence");
    }
    if (info->specific_options & TARGET_SET_COOKIE_RANDOM_SEED_FROM_ARGUMENT)
    {
        printf(" --random-seed");
        for (i = 0; i < RANDOM_SEED_LEN; i++)
        {
            printf("%02X", info->random_seed[i]);
        }
    }
    if (info->specific_options & TARGET_SET_COOKIE_RANDOM_SEED_FROM_FILE)
    {
        printf(" --random-seed-file \"%s\"", info->random_seed_path);
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
    bool random_seed_from_argument = flags & TARGET_SET_COOKIE_RANDOM_SEED_FROM_ARGUMENT;
    bool random_seed_from_file = flags & TARGET_SET_COOKIE_RANDOM_SEED_FROM_FILE;
    if (random_seed_from_argument && random_seed_from_file)
    {
        xtables_error(PARAMETER_PROBLEM,
            "TS3INIT_SET_COOKIE: --random-seed and --random-seed-file "
            "can not be specified at the same time");
    }
    if (!random_seed_from_argument && !random_seed_from_file)
    {
        xtables_error(PARAMETER_PROBLEM,
            "TS3INIT_SET_COOKIE: either --random-seed or --random-seed-file "
            "must be specified");
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
