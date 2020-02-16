/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                 This file sets up the module load and remove functions
 *                 and module meta data.
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teampseak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>

/* defined in ts3init_match.c */
int ts3init_match_init(void) __init;
void ts3init_match_exit(void);

/* defined in ts3init_target.c */
int ts3init_target_init(void) __init;
void ts3init_target_exit(void);

/* defined in ts3init_cookie.c */
int ts3init_cookie_init(void) __init;
void ts3init_cookie_exit(void);

MODULE_AUTHOR("Niels Werensteijn <niels.werensteijn@teamspeak.com>");
MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_DESCRIPTION("A module to aid in ts3 spoof protection");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ts3init");
MODULE_ALIAS("ip6t_ts3init");
MODULE_ALIAS("ipt_ts3init_get_cookie");
MODULE_ALIAS("ip6t_ts3init_get_cookie");
MODULE_ALIAS("ipt_ts3init_get_puzzle");
MODULE_ALIAS("ip6t_ts3init_get_puzzle");
MODULE_ALIAS("ipt_TS3INIT_SET_COOKIE");
MODULE_ALIAS("ip6t_TS3INIT_SET_COOKIE");
MODULE_ALIAS("ipt_TS3INIT_GET_COOKIE");
MODULE_ALIAS("ip6t_TS3INIT_GET_COOKIE");
MODULE_ALIAS("ipt_TS3INIT_RESET");
MODULE_ALIAS("ip6t_TS3INIT_RESET");

static int __init ts3init_init(void)
{
    int error;

    error = ts3init_cookie_init();
    if (error)
        goto out1;

    error = ts3init_match_init();
    if (error)
        goto out2;

    error = ts3init_target_init();
    if (error)
        goto out3;

    return error;

out3:
    ts3init_match_exit();
out2:
    ts3init_cookie_exit();
out1:
    return error;
}

static void __exit ts3init_exit(void)
{
    ts3init_target_exit();
    ts3init_match_exit();
    ts3init_cookie_exit();
}

module_init(ts3init_init);
module_exit(ts3init_exit);
