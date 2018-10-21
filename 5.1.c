#include <stdio.h>
#include "crapto1.h"
#include "crypto1.c"

void swapen(uint64_t states[],int graph){
    if(graph > 4 || graph < 0){
        printf("Error\n");
        return;
    }
    int i=0;
    if (graph!=0)
        i += graph * 8 + 1;
    for(;i < 8 + graph * 8;i++){
        
    }
}

int main(){
    uint64_t states[41] = {0};
    uint64_t key = 0x0l;
    int i;
    struct Crypto1State *state;
    state = crypto1_create(key);    //This is nr29 stste;
    for(i=0;i<2;i++){
        crypto1_get_lfsr(state,&states[i]);
        crypto1_bit(state,1,0);
    }
    crypto1_get_lfsr(state,&states[2]);
    crypto1_bit(state,0,0);
    for(i=0;i<32;i++){
        crypto1_get_lfsr(state,&states[i+3]);
        crypto1_bit(state,0,0);
    }
    for(i=0;i<6;i++){
        crypto1_get_lfsr(state,&states[i+35]);
        if (i<4)
            printf("nack_ks[%d]: %d\n",i,crypto1_bit(state,0,0));
    }


    for(i=0;i<13;i++){
        printf("state[%d]: %012lx\tstate[%d]: %012lx\tstate[%d]: %012lx\n",i*3,states[i*3],i*3+1,states[i*3+1],i*3+2,states[i*3+2]);
    }
}