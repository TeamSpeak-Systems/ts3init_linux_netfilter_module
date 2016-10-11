/*
 *    test to see if ts3init_siphash24 behaves like it should
 *
 *    Authors:
 *    Niels Werensteijn <niels werensteijn [at] teampseak com>, 2016-10-03
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License; either version 2
 *    or 3 of the License, as published by the Free Software Foundation.
 */
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "../src/siphash24.h"

int siphash(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k);

int main()
{
    uint64_t keys[8][2];
    uint8_t data[40];
    int i, j, k, l;
    
    union
    {
        uint8_t out1[8];
        uint64_t out2;
    } o;
    
    uint64_t out64;
    
    struct ts3init_siphash_state state;
    
    /* initialize */
    
    for (i=0; i<8; ++i)
    {
        keys[i][0] = 1 + i;
        keys[i][1] = 9 + i;
    }
    
    for (i=0; i < 40; ++i)
        data[i] = 100 + i;
            
    for (i=0; i < 8; ++i)
    {
        for (j = 0; j < 40; ++j)
        {
            siphash(o.out1, data, j, (uint8_t*)keys[i] );
                    
            ts3init_siphash_setup(&state, keys[i][0], keys[i][1]);
            ts3init_siphash_update(&state, data, j);
            out64 = ts3init_siphash_finalize(&state);

            if (out64 != o.out2)
                printf("failed i:%d j:%d 0x%" PRIx64 " 0x%" PRIx64 " \n", i, j, out64, o.out2);
                
            for(k=0; k < j; ++k)
            {
                for (l=k; l < j; ++l)
                {
                    ts3init_siphash_setup(&state, keys[i][0], keys[i][1]);
                    ts3init_siphash_update(&state, data, k);
                    ts3init_siphash_update(&state, data+k, l-k);
                    ts3init_siphash_update(&state, data+l, j-l);
                    out64 = ts3init_siphash_finalize(&state);
                    if (out64 != o.out2)
                        printf("failed i:%d j:%d k:%d l:%d 0x%" PRIx64 " 0x%" PRIx64 " \n", i, j, k, l, out64, o.out2);
                }
            }
        }
    }   
    
    printf("test complete\n");
}
