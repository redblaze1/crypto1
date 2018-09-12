#include <stdio.h>
#include "crapto1.h"
#include <string.h>
#include <stdbool.h>
#include "crypto1.c"


int main(){
    int i,count=0;
    uint32_t nt = 0;
    struct Crypto1State* state;
    uint32_t nack_ks=0;
    uint64_t key = 0x000023a396ce;
    // uint64_t key = 0x123456789abc;
    state = crypto1_create(key);
    uint32_t ks2,ks3_1b;

    for(i= 0;i<10000000;i++,nt++){
        crypto1_word(state,nt,0);
        ks2 = crypto1_word(state,0,1);
    
        if( parity(ks2 & 0xff000000) ^ 1 ^ ( (ks2 >> 23) & 1 ) ^ 1){
            if( parity(ks2 & 0x00ff0000) ^ 1 ^ ( (ks2 >> 15) & 1 ) ^1){
                if ( parity(ks2 & 0x0000ff00) ^ 1 ^ ( (ks2 >> 7) & 1 ) ^ 1)
                    ks3_1b = crypto1_word(state,0,1) >> 31;
                    if ( parity(ks2 & 0x000000ff) ^ 1 ^ ks3_1b ^ 1){
                        nack_ks = (nack_ks << 1) | crypto1_bit(state,0,1);
                        nack_ks = (nack_ks << 1) | crypto1_bit(state,1,1);
                        nack_ks = (nack_ks << 1) | crypto1_bit(state,0,1);
                        nack_ks = (nack_ks << 1) | crypto1_bit(state,1,1);
                        if ( nack_ks == 0x5 )
                            count++;
                }
            }
        }
    }

    printf("count: %d\n",count);
    return 0;
}