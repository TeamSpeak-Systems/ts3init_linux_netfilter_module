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

#include "siphash24.h"


/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x, b) (u64)(((x) << (b)) | ((x) >> (64 - (b))))

#define U8TO64_LE(p)                                                           \
  (((u64)((p)[0])) | ((u64)((p)[1]) << 8) |                                    \
   ((u64)((p)[2]) << 16) | ((u64)((p)[3]) << 24) |                             \
   ((u64)((p)[4]) << 32) | ((u64)((p)[5]) << 40) |                             \
   ((u64)((p)[6]) << 48) | ((u64)((p)[7]) << 56))

#define SIPROUND                                                               \
  do {                                                                         \
    v0 += v1;                                                                  \
    v1 = ROTL(v1, 13);                                                         \
    v1 ^= v0;                                                                  \
    v0 = ROTL(v0, 32);                                                         \
    v2 += v3;                                                                  \
    v3 = ROTL(v3, 16);                                                         \
    v3 ^= v2;                                                                  \
    v0 += v3;                                                                  \
    v3 = ROTL(v3, 21);                                                         \
    v3 ^= v0;                                                                  \
    v2 += v1;                                                                  \
    v1 = ROTL(v1, 17);                                                         \
    v1 ^= v2;                                                                  \
    v2 = ROTL(v2, 32);                                                         \
  } while (0)

#ifdef DEBUG
#define TRACE                                                                  \
  do {                                                                         \
    printk("(%d) v0 %x %x\n", (int)inlen, (u32)(v0 >> 32), (u32)v0);           \
    printk("(%d) v1 %x %x\n", (int)inlen, (u32)(v1 >> 32), (u32)v1);           \
    printk("(%d) v2 %x %x\n", (int)inlen, (u32)(v2 >> 32), (u32)v2);           \
    printk("(%d) v3 %x %x\n", (int)inlen, (u32)(v3 >> 32), (u32)v3);           \
  } while (0)
#else
#define TRACE
#endif

void ts3init_siphash_setup(struct ts3init_siphash_state* state, u64 k0, u64 k1)
{
  /* "somepseudorandomlygeneratedbytes" */
  state->v0 = 0x736f6d6570736575ULL;
  state->v1 = 0x646f72616e646f6dULL;
  state->v2 = 0x6c7967656e657261ULL;
  state->v3 = 0x7465646279746573ULL;
  state->len= 0;
  k0 = le64_to_cpu(k0);
  k1 = le64_to_cpu(k1);
  state->v3 ^= k1;
  state->v2 ^= k0;
  state->v1 ^= k1;
  state->v0 ^= k0;
}

void ts3init_siphash_update(struct ts3init_siphash_state* state, const u8 *in, size_t inlen)
{
    size_t next_byte = state->len % 8;
    size_t left;
    const u8* end = in + inlen;
    int i;
    u64 m, v0, v1, v2, v3;

    state->len += inlen;
    m = state->m;
    v0 = state->v0;
    v1 = state->v1;
    v2 = state->v2;
    v3 = state->v3;
        
    switch (next_byte)
    {
    case 1:
        m |= ((u64)(*in++)) << 8;
        if (in==end) goto __exit_update;
    case 2:
        m |= ((u64)(*in++)) << 16;
        if (in==end) goto __exit_update;
    case 3:
        m |= ((u64)(*in++)) << 24;
        if (in==end) goto __exit_update;
    case 4:
        m |= ((u64)(*in++)) << 32;
        if (in==end) goto __exit_update;
    case 5:
        m |= ((u64)(*in++)) << 40;
        if (in==end) goto __exit_update;
    case 6:
        m |= ((u64)(*in++)) << 48;
        if (in==end) goto __exit_update;
    case 7:
        m |= ((u64)(*in++)) << 56;
       
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
          SIPROUND;

        v0 ^= m;
    case 0:
        break;
    }
    
    left = (end-in) % 8;
    end -= left;
    
    for (; in != end; in += 8)
    {
        m = U8TO64_LE(in);
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= m;
    }
    
    m=0;
    switch(left)
    {
        case 7:
            m |= ((u64)(in[6])) << 48;
        case 6:
            m |= ((u64)(in[5])) << 40;
        case 5:
            m |= ((u64)(in[4])) << 32;
        case 4:
            m |= ((u64)(in[3])) << 24;
        case 3:
            m |= ((u64)(in[2])) << 16;
        case 2:
            m |= ((u64)(in[1])) << 8;
        case 1:
            m |= ((u64)(in[0]));
        case 0:
            break;
    }
    
__exit_update:    
    state->m = m;
    state->v0 = v0;
    state->v1 = v1;
    state->v2 = v2;
    state->v3 = v3;
}

u64 ts3init_siphash_finalize(struct ts3init_siphash_state* state)
{
  u64 b = state->len << 56;
  u64 v0, v1, v2, v3;
  int i;

  b |= state->m;


  v0 = state->v0;
  v1 = state->v1;
  v2 = state->v2;
  v3 = state->v3;
  
  v3 ^= b;

  TRACE;
  for (i = 0; i < cROUNDS; ++i)
    SIPROUND;

  v0 ^= b;
  v2 ^= 0xff;

  TRACE;
  for (i = 0; i < dROUNDS; ++i)
    SIPROUND;

  b = v0 ^ v1 ^ v2 ^ v3;
  return cpu_to_le64(b);
}

