#include <stdio.h>
#include <stdbool.h>
#include <time.h>
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
    srand( time(NULL) );
    uint64_t states[8][41] = {0};
    uint64_t key = 0x0l;
    int i,j,num=0,all_is;
    struct Crypto1State *state[8]; //struct Crypto1State *state2; struct Crypto1State *state3; struct Crypto1State *state4; struct Crypto1State *state5; struct Crypto1State *state6; struct Crypto1State *state7; struct Crypto1State *state8;
    while(1){
        num++;
        key = rand();
        key = (key<<17) ^ rand();
        for(i=0;i<8;i++)
            state[i] = crypto1_create(key);    //This is nr29 stste;
        int same[2]={0};
        int goodcount=0,count=0;
        bool is_first=true;
        for(i=0;i<4;i++){
            for(count=0,j=2;j>=0;j--,count++){
                crypto1_get_lfsr(state[i],&states[i][count]);
                crypto1_get_lfsr(state[7-i],&states[7-i][count]);
                same[0]= (same[0] <<1) | crypto1_bit(state[i],(i>>j)&1,0);
                same[1]= (same[1] <<1) | crypto1_bit(state[7-i],((i^7)>>j)&1,0);
            }
            if(is_first){
                if(same[0] == 7){
                    all_is = 7;
                } else if( same[0] == 0){
                    all_is = 0;
                } else break;
                is_first=false;
            }
            if( same[0] == all_is && same[1] == all_is)
                goodcount++;
                else break;
        }
        if(goodcount == 4)
            break;
        else{
            for(i=0;i<8;i++)
                crypto1_destroy(state[i]);
        }
    }
    // crypto1_get_lfsr(state,&states[2]);
    // crypto1_bit(state,0,0);
    for(j=0;j<8;j++){
        for(i=0;i<32;i++){
            crypto1_get_lfsr(state[j],&states[j][i+3]);
            crypto1_bit(state[j],0,0);
        }
    }
    // for(i=0;i<6;i++){
    //     crypto1_get_lfsr(state,&states[i+35]);
    //     if (i<4)
    //         printf("nack_ks[%d]: %d\n",i,crypto1_bit(state,0,0));
    // }
    for(i=0;i<8;i++){
        crypto1_get_lfsr(state[i],&states[i][35]);
        // tr_all(states[i],36);
    }
    // for(j=0;j<8;j++){
    //     for(i=0;i<12;i++){
    //         printf("state[%d][%d]: %012lx\tstate[%d][%d]: %012lx\tstate[%d][%d]: %012lx\n",j,i*3,states[j][i*3],j,i*3+1,states[j][i*3+1],j,i*3+2,states[j][i*3+2]);
    //     }
    // }
    for(i=0;i<8;i++)
        printf("state[%d][%d]: %012lx\t\n",i,35,states[i][35]);
    printf("次數: %d次找到\n",num);
    for(i=-1;i<7;i++)
    printf("%x\t",state[0]->odd^state[i+1]->odd);
    // printf("%012lx\t",states[0][35]^states[i+1][35]);
    printf("\n");
    for(i=-1;i<7;i++)
    printf("%x\t",state[0]->even^state[i+1]->even);
    // printf("%012lx\t",states[1][34]^states[i+1][34]);
    printf("\n");
    printf("crapto1.c裡面的表是:\n0\t4BC53\tECB1\t450E2\t25E29\t6E27A\t2B298\t60ECB\n0\t1D962\t4BC53\t56531\tECB1\t135D3\t450E2\t58980\n");
}