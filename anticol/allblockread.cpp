#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <string>
#include <unistd.h>
using namespace std;

void print_help(){
    printf("\t-k\tset key,and need all block key.\n");
    printf("\t-ka\tset all key,it will auth all block with it.\n");
}

int main(int argc,char* argv[]){
    stringstream ss;
    bool kall = false;
    int arg,i,n;
    unsigned int c = 0;
    long long int key[16] = {0x0ll};
    char tmp[3] = {0x00,0x00,0x00};
    char ctranstring[255];
    // Get commandline options
    if(argc == 1 ){
        printf("You must to use parameter,here is the help\n");
        print_help();
        return 0;
    }
    for (arg = 1; arg < argc; arg++) {
        if (0 == strcmp(argv[arg], "-k")) {
            if(argc <18){
            printf("You don't input all block key\n");
            print_help();
            return 0;
            }
            arg++;
            for(n=0;n<16;n++){
                if(strlen(argv[arg]) == 12){
                    for (i=0;i<6;i++){
                        memcpy(tmp, argv[arg] + i * 2, 2);
                        sscanf(tmp, "%02x", &c);
                        key[n] = (key[n] << 8) | (int) c;
        }
                    arg++;
                }
            }
        } else if( 0 == strcmp(argv[arg], "-ka")){
            kall = true;
            for (i=0;i<6;i++){
                memcpy(tmp, argv[arg+1] + i * 2, 2);
                sscanf(tmp, "%02x", &c);
                key[0] = (key[0] << 8) | (int) c;
            }
            arg++;
        } else if( 0 == strcmp(argv[arg], "-h") || 0 == strcmp(argv[arg], "--help" )){
            print_help();
        } else {
            printf("unknow commnad %s\n",argv[arg]);
            print_help();
            return 0;
        }
    }
    string st;
    const char *transt;
    sprintf(tmp,"%c",0x22); //add """ char
    if (kall == false){
        for(int i = 0;i < 16;i++){
            for(int b=0;b<4;b++){
                usleep(30000);
                printf("block[%x]: ",b+(i*4));
                ss << "./anticol -k ";
                sprintf(ctranstring,"%012llx",key[i]);
                for(int tr = 0; tr<strlen(ctranstring) ;tr++){
                    ss << ctranstring[tr];
                }
                ss << " -b ";
                if (b+(i*4) < 0x10){
                ss << "0";
                }
                sprintf(ctranstring,"%x",b+(i*4));
                for(int tr = 0; tr<strlen(ctranstring) ;tr++){
                    ss << ctranstring[tr];
                }
                ss << " | grep -E ";
                ss << tmp[0] << "block data:|ERROR" << tmp[0]; 
                st = ss.str();
                transt = st.c_str();
                system(transt);
                printf("\n");
                ss.clear();
                ss.str("");
            }
        }
    } else {
        for(int i = 0;i<16 ;i++){
            for(int b=0;b<4;b++){
                usleep(30000);
                printf("block[%x]: ",b+(i*4));
                ss << "./anticol -k ";
                sprintf(ctranstring,"%012llx",key[0]);
                for(int tr = 0; tr<strlen(ctranstring) ;tr++){
                    ss << ctranstring[tr];
                }
                ss << " -b ";
                if (b+(i*4) < 0x10){
                ss << "0";
                }
                sprintf(ctranstring,"%x",b+(i*4));
                for(int tr = 0; tr<strlen(ctranstring) ;tr++){
                    ss << ctranstring[tr];
                }
                ss << " | grep -E ";
                ss << tmp[0] << "block data:|ERROR" << tmp[0]; 
                st = ss.str();
                transt = st.c_str();
                system(transt);
                printf("\n");
                ss.clear();
                ss.str("");
            }
        }
    }
}
// 4a4b4b05f73f
// 2e65d2907d15

// b38972aba092
// a736c4d7cef4

// ebbe1e9f21b8
// 1a85c4d2743f

// baa8c81f4269
// 516712b72f88

// b1135288dedb
// 576e461c4d46

// cf3a6076e5cc
// 043af230e2d1

// 184e97e54a98
// dd22ae216e2c

// dc03d41bed03
// ef9d0e4eeb3e

// e54f34e813ed
// c081615b4315

// 169c4262e03b
// d7e22f99b51d

// 8b5c629cc982
// 9f2e9c05979e

// b8cbddfd5192
// 047c0c685f2d

// 46f2d98c7c2e
// 024c506ac203

// dc171371e9eb
// 2c307a3bbfbb

// b1215c8938f5
// ffffffffffff

// 86bc98fe23ec
// da22b2b6edcb