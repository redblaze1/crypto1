Table[][];
While(True){
	NT = Send_AUTH(); //get NT
	{NR},{AR},{P4~11} = 0;
	Send {NR}{AR};
	if(get{NACK}){
		if({NACK} == 0x5){
			TempNT = NT;
			Break;
		}
	}
}
	for(key=0;key<=0xffffffffffff;key++){
		create(key);
		p4~P7,NR = word(state,{NR},1);   //get ks,NR
		p8~p11(ks),AR = crapto_word(state,0,0);    //get ks,AR
		if(b40 ^ p4 == 0){
			if(b48 ^ p5 == 0){
				......
				......
				for(int k=0;k<4;k++){
					b96,b97,b98,b99 = crapto_bit(state,0,0);
				}
				if(b96 == 0){
					......
					if(b99 == 0){
						create(key);
						{NR},{AR} = 0xffffffff;
						word(state,{NR},1);
						word(state,0,0);    //save {p4~p11}
						for(int k=0;k<4;k++){
							b96,b97,b98,b99 = crapto_bit(state,0,0); //save b96~99 
						}
						Table[p4~p11 b96~b99][Quantity] = i;
					}
				}
			}
		}
	}
While(TRUE){
	NT = Send_AUTH()  //get NT
	if(NT== TempNT){
		{NR},{AR} = 0xffffffff;
		for(i=0;i<256;i++){
			p4~p11 = i;
			send_NRAR();
			if(get{NACK}){
				decrypt{NACK}; //get b96~99
				Break;
			}		
		}
		print(Table[p4~p11 b96~b99][all]); //The Table has pow(2,24);
	}
}
	


