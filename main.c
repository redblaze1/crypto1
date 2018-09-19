#include <stdio.h>
#include "crapto1.c"
#include <string.h>
#include <stdbool.h>
#include "crypto1.c"



void printhelp(){
    printf(" ex:./crapto1 -(UID) -(NT) -(NRcipher) -(ARcipher) -(ATcipher)\n");
    printf(" If need NR number please -i\n");
}


int main(int argc, char** argv) {
    uint32_t UID = 0; //before completed this program, its value are f1c0ac11 2f3e2f87 4dea9290 5cd31eec e60457a5
    uint32_t NT = 0;
    uint32_t NRcipher = 0;
    uint32_t ARcipher = 0;
    uint32_t ATcipher = 0;
    bool information = false;
    int arg;
    for (arg = 1; arg < argc; arg++){
        unsigned int c;
        char tmp[3]={0x00,0x00,0x00};
        int i;
        static int count=1;

        if (strlen(argv[arg])==8){
            for (i=0;i<4;i++){         
                memcpy(tmp, argv[arg] + i * 2, 2);
                sscanf(tmp, "%02x", &c);
                if(count==1)
                UID = (UID << 8) | (uint32_t) c;
                else if(count==2)
                NT = (NT << 8) | (uint32_t) c;
                else if(count==3)
                NRcipher = (NRcipher << 8) | (uint32_t) c;
                else if(count==4)
                ARcipher = (ARcipher << 8) | (uint32_t) c;
                else if(count==5)
                ATcipher = (ATcipher << 8) | (uint32_t) c;
            }
            count++;
        } else if ((0 == strcmp(argv[arg], "-h")) || (0 == strcmp(argv[arg], "-help"))){
            printhelp();
            return 0;
        } else if ((0 == strcmp(argv[arg], "-i"))){
            information = true;
        }
    }

    if (argc == 1){
    printf("You don't input anything. Please type ./crapto1 -h or -help\n");
    return 0;
    }

    // printf("NT: %08x\nNRcipher: %08x\n", NT,NRcipher);  //test output.
    struct Crypto1State * state;
    uint64_t key = 0x0ll;
    uint32_t suc64 = prng_successor(NT,64);
    uint32_t suc96 = prng_successor(NT,96);
    uint32_t ks2 = suc64^ARcipher;
    uint32_t ks3 = suc96^ATcipher;
    printf("ks2: %8x\n",ks2);
    state=lfsr_recovery64(ks2,ks3); //After recovery fun,the flsr state is ba738f3b9cab
    lfsr_rollback_word(state,0,0);
    lfsr_rollback_word(state,0,0);
    uint32_t ks2ch = 0;
    int i;
    for(i=0;i<32;i++){
        ks2ch = (ks2ch << 1) | crypto1_bit(state,0,0);
    }
    printf("check ks2: %8x\n",ks2ch);
    lfsr_rollback_word(state,0,0);
    uint32_t ks1=lfsr_rollback_word(state,NRcipher,1); //After rollback fun,the flsr state is 2d45da96064f
    uint32_t UxorNT=UID^NT;
    uint32_t ks0=lfsr_rollback_word(state,UxorNT,0); //After rollback fun,the flsr state is 7988256e2d45
    uint32_t NR=ks1^NRcipher;
    crypto1_get_lfsr(state, &key);
    printf("Key found: %012lx\n" , key);

    if (information){
    printf("nr: %08x\n",NR);
    }
    return 0;
}
