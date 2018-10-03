#include<stdio.h>
#include<stdbool.h>


bool funa(int y){
    bool y0,y1,y2,y3;
    y3 = y & 1;
    y2 = (y>>1) &1;
    y1 = (y>>2) &1;
    y0 = (y>>3) &1;
    bool result = ((y0 | y1) ^ (y0 & y3)) ^ (y2 &((y0 ^ y1)| y3));
    return result;
}
bool funb(int y){
    bool y0,y1,y2,y3;
    y3 = y & 1;
    y2 = (y>>1) &1;
    y1 = (y>>2) &1;
    y0 = (y>>3) &1;
    bool result = ((y0&y1)|y2)^((y0^y1)&(y2|y3));
    return result;
}
bool func(int y){
    bool y0,y1,y2,y3,y4;
    y4 = y &1;
    y3 = (y>>1) & 1;
    y2 = (y>>2) &1;
    y1 = (y>>3) &1;
    y0 = (y>>4) &1;
    bool result = (y0 | ((y1 | y4) & (y3 ^ y4))) ^ ((y0 ^ (y1 & y3)) & ((y2 ^ y3) | (y1 & y4)));
    return result;
}
int main(){
    double abtotal=0,total=0;
    int count=0;
    bool temp;
    for(int i=0;i<8;i++){
        if(funa(i) == funa(i ^ 7))
        abtotal++;
    }
    printf("fun:a 第一bit為0 輸出不變的機率為:%.f/8= %.03f\n",abtotal,abtotal/8.0);
    abtotal = 0; //init
    for(int i=8;i<=0xf;i++){
        if(funa(i) == funa(i ^ 7))
        abtotal++;
    }
    printf("fun:a 第一bit為1 輸出不變的機率為:%.f/8= %.03f\n",abtotal,abtotal/8.0);
    abtotal = 0; //init

    for(int i=0;i<8;i++){
        if(funb(i) == funb(i ^ 7))
        abtotal++;
    }
    printf("\nfun:b 第一bit為0 輸出不變的機率為:%.f/8= %.03f\n",abtotal,abtotal/8.0);
    abtotal = 0; //init
    for(int i=8;i<=0xf;i++){
        if(funb(i) == funb(i ^ 7))
        abtotal++;
    }
    printf("fun:b 第一bit為1 輸出不變的機率為:%.f/8= %.03f\n",abtotal,abtotal/8.0);
    abtotal = 0; //init
    printf("所以依照abbab規則,fun:b 輸出不變的機率平均為0.5,變的機率也為0.5\n");

    for(int i=0;i<=0x1f;i++,count++){
        if (count %2 ==0){
            temp = func(i);
        }
        else if( func(i) == temp)
            total++;
    }
    printf("\nfun:c 最後1bit翻轉後,輸出的數字一樣的機率為: %.f/16 = %.03f\n",total,total/16.0);
    printf("所以如果上面funb數字改了,而結果一樣不改,機率為: 0.5*0.625 = %.03f\n",0.5*0.625);
    printf("總和輸出不改的機率為: 0.5+0.312 = %.03f\n",0.5+0.312);
}
