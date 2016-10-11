#ifndef _TS3INIT_SIPHASH_H
#define _TS3INIT_SIPHASH_H

/*
   SipHash reference C implementation
   Copyright (c) 2012-2014 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
   Copyright (c) 2016 Maximilian Muenchow <maximilian.muenchow@teamspeak.com>
   Copyright (c) 2016 Niels Werensteijn <niels.werensteijn@teamspeak.com>
   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <linux/kernel.h>
#include <linux/udp.h>

struct ts3init_siphash_state
{
  u64 v0;
  u64 v1;
  u64 v2;
  u64 v3;
  u64 m;
  size_t len;	
};

void ts3init_siphash_setup(struct ts3init_siphash_state* state, u64 k0, u64 k1);
void ts3init_siphash_update(struct ts3init_siphash_state* state, const u8 *in, size_t inlen);
u64 ts3init_siphash_finalize(struct ts3init_siphash_state* state);

#endif /*_TS3INIT_SIPHASH_H*/

