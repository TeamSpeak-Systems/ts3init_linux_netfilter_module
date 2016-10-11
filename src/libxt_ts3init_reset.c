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
#include "ts3init_target.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static void ts3init_reset_help(void)
{
    printf("ts3init_reset takes no options\n\n");
}

static int ts3init_reset_parse(int c, char **argv, int invert, unsigned int *flags,
                               const void *entry, struct xt_entry_target **target)
{
	return false;
}

static void ts3init_reset_check(unsigned int flags)
{
}

/* register and init */
static struct xtables_target ts3init_reset_tg_reg =
{
	.name          = "ts3init_reset",
	.revision      = 0,
	.family        = NFPROTO_UNSPEC,
	.version       = XTABLES_VERSION,
	.help          = ts3init_reset_help,
	.parse         = ts3init_reset_parse,
	.final_check   = ts3init_reset_check,
};

static __attribute__((constructor)) void ts3init_reset_tg_ldr(void)
{
    xtables_register_target(&ts3init_reset_tg_reg);
}