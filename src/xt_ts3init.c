/*
 *    "ts3init" extension for Xtables
 *
 *    Description: A module to aid in ts3 spoof protection
 *                 This file just includes the actual code files so that
 *                 we do not have to export unneed symbols to the kernel
 *                 while stil organizing code into logical files.
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teampseak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */

#include "ts3init_cookie.c"
#include "ts3init_match.c"

MODULE_AUTHOR("Niels Werensteijn <niels.werensteijn@teamspeak.com>");
MODULE_DESCRIPTION("A module to aid in ts3 spoof protection");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ts3init");
MODULE_ALIAS("ip6t_ts3init");

static int __init ts3init_mt_init(void)
{
    return xt_register_matches(ts3init_mt_reg, ARRAY_SIZE(ts3init_mt_reg));
}

static void __exit ts3init_mt_exit(void)
{
    xt_unregister_matches(ts3init_mt_reg, ARRAY_SIZE(ts3init_mt_reg));
}

module_init(ts3init_mt_init);
module_exit(ts3init_mt_exit);
