#include <stdio.h>
#include <stdbool.h>
#include "crapto1.h"
#include "crypto1.c"

// void swap(uint64_t states[],int graph){
//     if(graph > 4 || graph < 0){
//         printf("Error\n");
//         return;
//     }
//     int i=0,t=0;
//     i += graph * 8 + 1;
//     for(;i < 8 + graph * 8;i++){
//         uint32_t temp = (states[i] >> (graph *8)) & 0xff;
//         for(t = 0;t < 4;t++){
//             temp |= (temp & (1 << t) ^ ((temp >> 7-t) & 1)) << 7-t; //xor result save... 
//             temp = (temp & (((0xfe << t ) % 0x100 ) &1 )) | ((temp >> 7-t) & 1 ) ^ (temp & (1 << t)); //xor back
//             temp ^= (temp & (1 << t)) << 7-t;
//         }
//         states[i] 
//     }
// }

void fp(uint8_t *bs) {
    uint8_t t = *bs, i = 7;
    for (*bs = 0;t; t >>= 1)
        *bs |= ((t & 1) << i--);
}


void tr_64(uint64_t *n) {
    uint8_t *t = (uint8_t*) n;
    int i;
    for (i = 0; i < 6; i++)
        fp(&t[i]);
}

void tr_all(uint64_t arr[], int size) {
    int i;
    for (i = 1; i < size; i++)
        tr_64(&arr[i]);
}




int main(){
    uint64_t states[41] = {0};
    uint64_t key = 0x0l;
    uint8_t sameks[3] = {0};
    int i;
    struct Crypto1State *state;
    state = crypto1_create(key);    //This is nr29 stste;
    for(i=0;i<3;i++){
        crypto1_get_lfsr(state,&states[i]);
        crypto1_bit(state,1,0);
    }
    // crypto1_get_lfsr(state,&states[2]);
    // crypto1_bit(state,0,0);
    for(i=0;i<32;i++){
        crypto1_get_lfsr(state,&states[i+3]);
        crypto1_bit(state,0,0);
    }
    for(i=0;i<6;i++){
        crypto1_get_lfsr(state,&states[i+35]);
        if (i<4)
            printf("nack_ks[%d]: %d\n",i,crypto1_bit(state,0,0));
    }

    tr_all(states,40);
    for(i=0;i<13;i++){
        printf("state[%d]: %012lx\tstate[%d]: %012lx\tstate[%d]: %012lx\n",i*3,states[i*3],i*3+1,states[i*3+1],i*3+2,states[i*3+2]);
    }
}