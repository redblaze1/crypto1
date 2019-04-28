#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "crapto1.h"
#include "crypto1.c"


void s(int p,int q,double p_proba,double q_proba,int * result,double * result_proba){
    *result = p * (16-q) + ( q * (16-p) );
    *result_proba = p_proba * q_proba;
}

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
        // total+=count[i]; //同下
        printf("為%d時的數字:%d 機率: %.4f\n",i,count[i],count[i]/tmpd);
    }
    // printf("全加起來和2^20比較%d: %d\n",1<<20,total); //測試總數
    double proba[7];
    proba[0] = count[0]/tmpd;   proba[1] = count[4]/tmpd;   proba[2] = count[6]/tmpd;   proba[3] = count[8]/tmpd;   proba[4] = count[10]/tmpd; proba[5] = count[12]/tmpd; proba[6] = count[16]/tmpd;
    // printf("%.40f\n",proba[0] * proba[0]); //測試overflow
    int result=0,result_i=0,secret[7]={0,4,6,8,10,12,16};
    double result_proba=0,total_result[2][49]={0};
    for(i = 0 ;i < 7 ;++i){
        for(j = 0; j < 7; ++j,++result_i){
            s(secret[i],secret[j],proba[i],proba[j],&result,&result_proba);
            total_result[0][result_i] = result;
            total_result[1][result_i] = result_proba;
        }
    }
    
}