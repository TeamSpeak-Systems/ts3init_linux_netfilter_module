/*
   SipHash reference C implementation
   Copyright (c) 2012-2014 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
   Copyright (c) 2016 Maximilian Muenchow <maximilian.muenchow@teamspeak.com>
   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <linux/kernel.h>


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

// it is assumed that every parameter is in LE
int ts3init_siphash(u64 *out, const u8 *in, u64 inlen, u64 k0, u64 k1) {
  /* "somepseudorandomlygeneratedbytes" */
  u64 v0 = 0x736f6d6570736575ULL;
  u64 v1 = 0x646f72616e646f6dULL;
  u64 v2 = 0x6c7967656e657261ULL;
  u64 v3 = 0x7465646279746573ULL;
  u64 b;
  u64 m;
  int i;
  const u8 *end = in + inlen - (inlen % sizeof(u64));
  const int left = inlen & 7;
  k0 = le64_to_cpu(k0);
  k1 = le64_to_cpu(k1);
  b = ((u64)inlen) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  for (; in != end; in += 8) {
    m = U8TO64_LE(in);
    v3 ^= m;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
      SIPROUND;

    v0 ^= m;
  }

  switch (left) {
  case 7:
    b |= ((u64)in[6]) << 48;
  case 6:
    b |= ((u64)in[5]) << 40;
  case 5:
    b |= ((u64)in[4]) << 32;
  case 4:
    b |= ((u64)in[3]) << 24;
  case 3:
    b |= ((u64)in[2]) << 16;
  case 2:
    b |= ((u64)in[1]) << 8;
  case 1:
    b |= ((u64)in[0]);
    break;
  case 0:
    break;
  }

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
  *out = cpu_to_le64(b);


  return 0;
}

