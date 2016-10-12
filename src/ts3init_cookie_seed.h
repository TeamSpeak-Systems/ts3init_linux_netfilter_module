#ifndef _TS3INIT_COOKIE_SEED_H
#define _TS3INIT_COOKIE_SEED_H

enum {
    COOKIE_SEED_LEN = 60
};

static inline bool hex2int_seed(const char *src, __u8* dst)
{
    int i, j;
    for (i = 0; i < 60; ++i)
    {
        int v = 0;
        for ( j = 0; j < 2; ++j)
        {
            uint8_t byte = *src++; 
                if (byte >= '0' && byte <= '9') byte = byte - '0';
                else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
                else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;
            else return false;
                v = (v << 4) | byte;
        }
        *dst++ = v;
    }
    return true;
}

#endif /* _TS3INIT_COOKIE_SEED_H */
