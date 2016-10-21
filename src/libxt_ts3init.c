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
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "ts3init_random_seed.h"
#include "ts3init_match.h"

#define param_act(t, s, f) xtables_param_act((t), "ts3init", (s), (f))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static void ts3init_help(void)
{
    printf(
        "ts3init match options:\n"
        "  --client                     Match ts3init client packets.\n"
        "  --server                     Match ts3init server packets.\n"
        "  --command <command>          Match packets with the specified command.\n"
    );
}

static const struct option ts3init_opts[] = {
    {.name = "client",            .has_arg = false, .val = '1'},
    {.name = "server",            .has_arg = false, .val = '2'},
    {.name = "command",           .has_arg = true,  .val = '3'},
    {NULL},
};

static int ts3init_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
    struct xt_ts3init_mtinfo *info = (void *)(*match)->data;
    int command;

    switch (c) {
    case '1':
        param_act(XTF_ONLY_ONCE, "--client", info->specific_options & CHK_TS3INIT_CLIENT);
        param_act(XTF_NO_INVERT, "--client", invert);
        info->specific_options |= CHK_TS3INIT_CLIENT;
        *flags |= CHK_TS3INIT_CLIENT;
        return true;

    case '2':
        param_act(XTF_ONLY_ONCE, "--server", info->specific_options & CHK_TS3INIT_SERVER);
        param_act(XTF_NO_INVERT, "--server", invert);
        info->specific_options |= CHK_TS3INIT_SERVER;
        *flags |= CHK_TS3INIT_SERVER;
        return true;

    case '3':
        param_act(XTF_ONLY_ONCE, "--random-seed", info->specific_options & CHK_TS3INIT_COMMAND);
        param_act(XTF_NO_INVERT, "--random-seed", invert);
        command = atoi(optarg);
        if (command < 0 || command > 255)
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: invalid command number");
        info->specific_options |= CHK_TS3INIT_COMMAND;
        info->command = (__u8)command;
        *flags |= CHK_TS3INIT_COMMAND;
        return true;

    default:
        return false;
    }
}

static void ts3init_save(const void *ip, const struct xt_entry_match *match)
{
    const struct xt_ts3init_mtinfo *info = (const void *)match->data;
    if (info->specific_options & CHK_TS3INIT_CLIENT)
    {
        printf("--client ");
    }
    if (info->specific_options & CHK_TS3INIT_SERVER)
    {
        printf("--server ");
    }
    if (info->specific_options & CHK_TS3INIT_COMMAND)
    {
        printf("--command %i ", (int)info->command);
    }
}

static void ts3init_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
    printf(" -m ts3init ");
    ts3init_save(ip, match);
}

static void ts3init_check(unsigned int flags)
{
    bool client = flags & CHK_TS3INIT_CLIENT;
    bool server = flags & CHK_TS3INIT_SERVER;
    if (client && server)
    {
        xtables_error(PARAMETER_PROBLEM,
            "ts3init_: --client and --server can not be specified at the same time");
    }
    if (flags & CHK_TS3INIT_COMMAND)
    {
        if (!client && !server)
        {
            xtables_error(PARAMETER_PROBLEM,
                "ts3init: --command requires either --client or --server");
        }
    }
}

/* register and init */
static struct xtables_match ts3init_mt_reg[] =
{
    {
        .name          = "ts3init",
        .revision      = 0,
        .family        = NFPROTO_UNSPEC,
        .version       = XTABLES_VERSION,
        .size          = XT_ALIGN(sizeof(struct xt_ts3init_mtinfo)),
        .userspacesize = XT_ALIGN(sizeof(struct xt_ts3init_mtinfo)),
        .help          = ts3init_help,
        .parse         = ts3init_parse,
        .print         = ts3init_print,
        .save          = ts3init_save,
        .extra_opts    = ts3init_opts,
        .final_check   = ts3init_check,
    },
};

static __attribute__((constructor)) void ts3init_mt_ldr(void)
{
    xtables_register_matches(ts3init_mt_reg, ARRAY_SIZE(ts3init_mt_reg));
}
