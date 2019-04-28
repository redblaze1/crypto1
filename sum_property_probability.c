#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "crapto1.h"
#include "crypto1.c"

int main(){
    // srand( time(NULL) );
    // struct Crypto1State *state;
    // uint64_t key = 0x0ll;
    // state = crypto1_create(key);
    int i,j,tmp[4],count[17]={0},total=0;
    for(i = 0; i < 1 << 20; ++i) {  //i=0;i<=0xfffff;i++
        for(j = 0; j < 16; ++j){
            tmp[0] = filter( (i << 1) | ( j & 1) );
            tmp[1] = filter( (i << 2) | ( j  & 3) );
            tmp[2] = filter( (i << 3) | ( j  & 7) );
            tmp[3] = filter( (i << 4) |   j       );
            total += tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
        }
        count[total]++;
        total = 0;
	}
    double tmpd = 1 << 20;
    for(i=0;i<17;++i){
        // total+=count[i];
        printf("為%d時的數字:%d 機率: %.3f\n",i,count[i],count[i]/tmpd);
    }
    // printf("全加起來和2^20比較%d: %d\n",1<<20,total);
}