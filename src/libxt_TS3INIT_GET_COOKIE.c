/*
 *    "libxt_ts3init_reset" target extension for iptables
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

static void ts3init_get_cookie_help(void)
{
    printf("TS3INIT_GET_COOKIE takes no options\n\n");
}

static int ts3init_get_cookie_parse(int c, char **argv, int invert, unsigned int *flags,
                               const void *entry, struct xt_entry_target **target)
{
    return false;
}

static void ts3init_get_cookie_check(unsigned int flags)
{
}

/* register and init */
static struct xtables_target ts3init_get_cookie_tg_reg =
{
    .name          = "TS3INIT_GET_COOKIE",
    .revision      = 0,
    .family        = NFPROTO_UNSPEC,
    .version       = XTABLES_VERSION,
    .help          = ts3init_get_cookie_help,
    .parse         = ts3init_get_cookie_parse,
    .final_check   = ts3init_get_cookie_check,
};

static __attribute__((constructor)) void ts3init_get_cookie_tg_ldr(void)
{
    xtables_register_target(&ts3init_get_cookie_tg_reg);
}