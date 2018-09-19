#include <stdio.h>
#include "crapto1.h"
#include <string.h>
#include <stdbool.h>
#include "crypto1.c"
#include <stdlib.h>
#include <time.h>



bool check_0(struct Crypto1State* state,const uint32_t ks){
    uint8_t nextks=0;
    if( parity(ks & 0xff000000) ^ 1 ^ ( (ks >> 23) & 1 ) ^ 1){
        if( parity(ks & 0x00ff0000) ^ 1 ^ ( (ks >> 15) & 1 ) ^1){
            if ( parity(ks & 0x0000ff00) ^ 1 ^ ( (ks >> 7) & 1 ) ^ 1){
                nextks = filter(state->odd);
                if ( parity(ks & 0x000000ff) ^ 1 ^ nextks ^ 1){
                    return true;
                }
            }
        }
    }
    else
    return false;
}

int main(){
    srand(time(NULL));
    int k,j,i,count=0;
    uint32_t nt = 0;
    struct Crypto1State* state;
    uint32_t nack_ks=0;
    // uint64_t key = 0x000023a396ce;
    uint64_t key = 0x123456789abc;
    uint32_t ks1,ks2,ks3_1b,lfsro;
    uint64_t lfsr;

    for(i= 0;i<1000000;i++){
        state = crypto1_create(key);
        nt = (rand() % 65536) << 16 | (rand() % 65536);
        crypto1_word(state,nt,0);
        for(k=0;k<32;k++){
        ks1 = (ks1 << 1) | crypto1_bit(state,0,1);
        }
        if (check_0(state,ks1)){
            for(k=0;k<32;k++){
            ks2 = (ks2 << 1) | crypto1_bit(state,0,0);
            }
            
            if(check_0(state,ks2)){
                nack_ks = 0;
                nack_ks = (nack_ks << 1) | crypto1_bit(state,0,1);
                nack_ks = (nack_ks << 1) | crypto1_bit(state,1,1);
                nack_ks = (nack_ks << 1) | crypto1_bit(state,0,1);
                nack_ks = (nack_ks << 1) | crypto1_bit(state,1,1);
                if ( nack_ks == 0 )
                    count++;
            }
        }
        crypto1_destroy(state);
    }

    printf("count: %d\n",count);
    return 0;
}