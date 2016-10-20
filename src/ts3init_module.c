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
#include <linux/netfilter/x_tables.h>

/* defined in ts3init_match.c */
int __init ts3init_match_init(void);
void __exit ts3init_match_exit(void);

/* defined in ts3init_target.c */
int __init ts3init_target_init(void);
void __exit ts3init_target_exit(void);


MODULE_AUTHOR("Niels Werensteijn <niels.werensteijn@teamspeak.com>");
MODULE_DESCRIPTION("A module to aid in ts3 spoof protection");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ts3init");
MODULE_ALIAS("ip6t_ts3init");

static int __init ts3init_init(void)
{
    int error;
    error = ts3init_match_init();
    if (error)
        return error;

    error = ts3init_target_init();
    if (error)
        ts3init_match_exit();

    return error;
}

static void __exit ts3init_exit(void)
{
    ts3init_match_exit();
    ts3init_target_exit();
}

module_init(ts3init_init);
module_exit(ts3init_exit);
