/*
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License; either
 *      version 2 of the License, or any later version, as published by the
 *      Free Software Foundation.
 */
 
#ifndef COMPAT_SKBUFF_H
#define COMPAT_SKBUFF_H 1

struct tcphdr;
struct udphdr;

#define skb_ifindex(skb) (skb)->skb_iif
#define skb_nfmark(skb) (((struct sk_buff *)(skb))->mark)

#ifdef CONFIG_NETWORK_SECMARK
#   define skb_secmark(skb) ((skb)->secmark)
#else
#   define skb_secmark(skb) 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static inline int skb_put_padto(struct sk_buff *skb, unsigned int len)
{
    unsigned int size = skb->len;
 
    if (unlikely(size < len)) {
        len -= size;
        if (skb_pad(skb, len)) return -ENOMEM;
        __skb_put(skb, len);
    }

    return 0;
}
#endif

#endif /* COMPAT_SKBUFF_H */
