#include <stdio.h>
#include <iostream>
#include <cmath>
using namespace std;
int main(){
    cout <<"水仙花數: ";
    for(int i=1;i<10;i++){
        for(int j=0;j<10;j++){
            for(int k=0;k<10;k++){
                int num = pow(i,3) + pow(j,3) + pow(k,3);
                if(i*100+j*10+k==num)
                    cout << num << " ";
            }
        }
    }
    cout << endl;
}