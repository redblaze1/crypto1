#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "nfc.h"
#include "nfc-utils.h"
#include "crapto1.h"

#define SAK_FLAG_ATS_SUPPORTED 0x20

#define MAX_FRAME_LEN 264
FILE *pFile; //file read
nfc_context *context;
char buffer[1024];
char d[256];

struct Crypto1State * state; //LFSR state
uint64_t keys[80] = {0x00};
uint64_t key = 0xffffffffffff;
unsigned int c;
char tmp[3]={0x00,0x00,0x00};
int i,k,count,st=0,en=0;

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static size_t szRx = sizeof(abtRx);
static uint8_t abtRawUid[12];
static uint8_t abtAtqa[2];
static uint8_t abtSak;
static uint8_t abtAts[MAX_FRAME_LEN];
static uint8_t szAts = 0;
static size_t szCL = 1;//Always start with Cascade Level 1 (CL1)
static nfc_device *pnd;

bool    quiet_output = false;
bool    force_rats = false;
bool    timed = false;
bool    iso_ats_supported = false;
bool    auth_block = false;
bool    write_tag = false;
bool    nospace = false;
bool    sucread[16] = {false};
bool    readse = false;

uint8_t  abtReqa[1] = { 0x26 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

//Auth communication area
uint8_t  sectorkey[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t  abtAuthBlock[4] = { 0x60, 0x00, 0x00, 0x00 };
uint8_t  abtdata[4] = { 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtdata2[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtNT[4] = { 0x00, 0x00, 0x00, 0x00 };
uint8_t  pbtRxpar[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  pbtTxpar[18] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtblock[1] = {0x00};
uint8_t  abtblockdata[18] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtwriteblock[18] = { 0x01,  0x23,  0x45,  0x67,  0x00,  0x08,  0x04,  0x00,  0x46,  0x59,  0x25,  0x58,  0x49,  0x10,  0x23,  0x02,  0x23,  0xeb };

#define CASCADE_BIT 0x04



bool readselse(int,uint8_t);

static  bool
transmit_bits(const uint8_t *pbtTx, const size_t szTxBits,const uint8_t *pbtTxpar)
{

  uint32_t cycles = 0;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex_bits(pbtTx, szTxBits);
  }

  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if (timed) {
    if ((szRxBits = nfc_initiator_transceive_bits_timed(pnd, pbtTx, szTxBits, pbtTxpar, abtRx, sizeof(abtRx), pbtRxpar, &cycles)) < 0){
      return false;
    }
    if ((!quiet_output) && (szRxBits > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, pbtTxpar, abtRx, sizeof(abtRx), pbtRxpar)) < 0){
      return false;
    }
  }
  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex_bits(abtRx, szRxBits);
  }
  // Succesful transfer
  return true;
}


static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  uint32_t cycles = 0;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex(pbtTx, szTx);
  }
  int res;
  // Transmit the command bytes
  if (timed) {
    if ((res = nfc_initiator_transceive_bytes_timed(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), &cycles)) < 0){
      return false;
    }
    if ((!quiet_output) && (res > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0){
      return false;
    }
  }
  szRx = res;
  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex(abtRx, szRx);
  }
  // Succesful transfer
  return true;
}

bool msgcheck(){
  uint8_t ks_bit[1] = {0x00};
  for(i=0;i<4;i++){
      ks_bit[0] |= (crypto1_bit(state,0,0) << (i));
    }
    // printf("ack: %x\n",ks_bit[0] ^ abtRx[0]);
    if((ks_bit[0] ^ abtRx[0]) == 0xa)
    return true;
    else if ((ks_bit[0] ^ abtRx[0]) == 0x4)
    ERR("The Action is not allow");
    else if((ks_bit[0] ^ abtRx[0]) == 0x5)
    ERR("The Tag sent nack, parity right, but answer is wrong");
    else 
    ERR("unknow ERROR");
    return false;
}

uint8_t sent_bits(int word_num, uint8_t *sentdata,bool is_encry){
  for(i=0;i<word_num/8;i++){
    if(word_num == 64){
      if(i<4){
        pbtTxpar[i] = oddparity(sentdata[i]); //generate parity
        if(is_encry){
          sentdata[i] ^= crypto1_byte(state,sentdata[i],0); //encrypt data(have input)
          pbtTxpar[i] ^= filter(state->odd); //encrypt parity
          continue;
        }
      }
    }
        pbtTxpar[i] = oddparity(sentdata[i]); //generate parity
        if(is_encry){
          sentdata[i] ^= crypto1_byte(state,0,0); //encrypt data
          pbtTxpar[i] ^= filter(state->odd); //encrypt parity
        }
    }
    if(!transmit_bits(sentdata, word_num, pbtTxpar)){
      printf("ERROR\n");
    }
    return szRxBits/8;
}

static void
print_usage(char *argv[])
{
  printf("Usage: %s [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("\t-h\t--help\tHelp. Print this message.\n");
  printf("\t-q\tQuiet mode. Suppress output of READER and EMULATOR data (improves timing).\n");
  printf("\t-f\tForce RATS.\n");
  printf("\t-t\tMeasure response time (in cycles).\n");
  printf("\t-k\tSet LFSR key. ex:-k 123456789abc\n (If no set key,then default key is ffffffffffff)\n");
  printf("\t-b\tset block. ex:-b 3a\n");
  printf("\t-w\tset write block data. ex:-w ffffffffffffFF078069ffffffffffff\n");
  printf("\t-kb\tuse key b.\n");
  printf("\t-file\tselect a file to read key. extype:-file (filename) (start sector) (end sector) ex:-file key.txt 0 15\n");
}

int main(int argc, char *argv[]){
  int     arg;

  // Get commandline options
  for (arg = 1; arg < argc; arg++) {
    if (0 == strcmp(argv[arg], "-h") || 0 == strcmp(argv[arg], "--help")) {
      print_usage(argv);
      exit(EXIT_SUCCESS);
    } else if (0 == strcmp(argv[arg], "-q")) {
      quiet_output = true;
    } else if (0 == strcmp(argv[arg], "-f")) {
      force_rats = true;
    } else if (0 == strcmp(argv[arg], "-t")) {
      timed = true;
    } else if (0 == strcmp(argv[arg], "-ns")) {
      nospace = true;
    } else if (0 == strcmp(argv[arg], "-kb")) {
      abtAuthBlock[0] = 0x61;
    } else if (0 == strcmp(argv[arg], "-w")){
      write_tag = true;
      if (strlen(argv[++arg]) == 32){
        for (i = 0 ; i < 16 ; ++i) {
        memcpy(tmp, argv[arg] + i * 2, 2);
        sscanf(tmp, "%02x", &c);
        abtwriteblock[i] = (char) c;
          if (i==15){
            printf("\n");
          }
        }
        iso14443a_crc_append(abtwriteblock, 16);
      } else {
        printf("Your want to write block data is %zd bit, please let it become 32 bit\n",strlen(argv[arg]));
        print_usage(argv);
        exit(EXIT_FAILURE);
      }

    } else if (0 == strcmp(argv[arg], "-b")) {
      auth_block = true;
      if (strlen(argv[++arg]) == 2){
        for (i = 0 ; i < 1 ; ++i) {
          memcpy(tmp, argv[arg] + i * 2, 2);  //-b data copy
          sscanf(tmp, "%02x", &c);
          abtblock[0] = (char) c;
        }
      }
      //check data correct or wrong

      if (strlen(argv[arg]) > 2 || ((int) c ) < 0x00  || ((int) c ) >0x3f){
        ERR("%s not 1 byte Block data or Block data must be smaller than 40", argv[arg]);
        print_usage(argv);
        exit(EXIT_FAILURE);
      }
      // printf("Block: %c\n" , abtBlock[0] ); //test
    } else if (0 == strcmp(argv[arg], "-k")) {
      key=0x0ll;                               //init key
      if (strlen(argv[++arg]) == 12 ){         //copy -k data
        for (i=0;i<6;i++){
        memcpy(tmp, argv[arg] + i * 2, 2);
        sscanf(tmp, "%02x", &c);
        key = (key << 8) | (uint64_t) c;
        }
      
      //-k data wrong message
      } else{
      ERR("%s not 12 bytes data. Please input correct data again", argv[arg]);
      print_usage(argv);
      exit(EXIT_FAILURE);
      }
    } else if (0 == strcmp(argv[arg], "-file")){
      readse = true;
      auth_block = true;
      arg++;
      if(arg==argc){
        printf("no filename\n");
        print_usage(argv);
        exit(EXIT_FAILURE);
      }
      strncpy(d, argv[arg],256);
      pFile = fopen( d, "r" );
      if ( NULL == pFile ){
        printf( "Open failure\n" );
        exit(EXIT_FAILURE);
      }else {
        fread( buffer, 1024, 1, pFile );
      }

      if(++arg == argc){
        printf("no start sector and end sector\n");
        exit(EXIT_FAILURE);
      }
      if (strlen(argv[arg]) == 2 ){
        if(argv[arg][0] < 0x30 || argv[arg][0] > 0x39){
          printf("%s is not a number\n",argv[arg]);
          exit(EXIT_FAILURE);
        }
        if(argv[arg][1] < 0x30 || argv[arg][1] > 0x39){
          printf("%s is not a number\n",argv[arg]);
          exit(EXIT_FAILURE);
        }


        for (i=0;i<1;i++){
          memcpy(tmp, argv[arg] + i * 2, 2);
          sscanf(tmp, "%02d", &c);
          st |= (int) c;
        }
        if(st<0 || st>15){
          ERR("Please input 0~15 start sector");
          exit(EXIT_FAILURE);
        }
      } else {
        printf("Please input only 2 char\n");
        exit(EXIT_FAILURE);
      }
      if(++arg == argc){
        printf("no end sector\n");
        exit(EXIT_FAILURE);
      }
      if (strlen(argv[arg]) == 2 ){
        if(argv[arg][0] < 0x30 || argv[arg][0] > 0x39){
          printf("%s is not a number\n",argv[arg]);
          exit(EXIT_FAILURE);
        }
        if(argv[arg][1] < 0x30 || argv[arg][1] > 0x39){
          printf("%s is not a number\n",argv[arg]);
          exit(EXIT_FAILURE);
        }

        for (i=0;i<1;i++){
          memcpy(tmp, argv[arg] + i * 2, 2);
          sscanf(tmp, "%02d", &c);
          en |= (int) c;
        }
        if(en<0 || en>15){
          ERR("Please input 0~15 end sector");
          exit(EXIT_FAILURE);
        }
      } else {
        printf("Please input only 2 char\n");
        exit(EXIT_FAILURE);
      }
        if(st>en){
          printf("start sector can't bigger than end sector\n");
          exit(EXIT_FAILURE);
        }
    } else {
      ERR("%s is not supported option.", argv[arg]);
      print_usage(argv);
      exit(EXIT_FAILURE);
    }
  }
  printf("before file st: %x en: %x\n",st,en);
  //start get file's key
  if(readse){
    char * pEnd = buffer;
    for(count=0,i=0;i<70;i++,count++){
      keys[count] = strtol (pEnd,&pEnd,16);
    }
  }
  //end get file's key

  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }
  printf("after file st: %x en: %x\n",st,en);
  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  

  printf("NFC reader: %s opened\n\n", nfc_device_get_name(pnd));

  //only read 1 block area
  if(readse == false){
    if(readselse(0,abtblock[0]) == false)
      exit(EXIT_FAILURE);
  }
  //only read 1 block area

  //read sector area
  printf("st: %x en: %x\n",st,en);
    if(readse){
      for(st;st<=en;st++){
        if(readselse(st,st*4)){
          sucread[st] = true;
          readselse(st,st*4+1);
          readselse(st,st*4+2);
          readselse(st,st*4+3);
        }

        for(k=0;k<70 && (sucread[st] == false);k++){
          if(readselse(k,st*4)){
            sucread[st] = true;
            readselse(k,st*4+1);
            readselse(k,st*4+2);
            readselse(k,st*4+3);
          }
        }
      }
    }
  //read sector area

  printf("\nFound tag with\n UID: ");
  switch (szCL) {
    case 1:
      printf("%02x%02x%02x%02x", abtRawUid[0], abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      break;
    case 2:
      printf("%02x%02x%02x", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      printf("%02x%02x%02x%02x", abtRawUid[4], abtRawUid[5], abtRawUid[6], abtRawUid[7]);
      break;
    case 3:
      printf("%02x%02x%02x", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      printf("%02x%02x%02x", abtRawUid[5], abtRawUid[6], abtRawUid[7]);
      printf("%02x%02x%02x%02x", abtRawUid[8], abtRawUid[9], abtRawUid[10], abtRawUid[11]);
      break;
  }
  printf("\n");
  printf("ATQA: %02x%02x\n SAK: %02x\n", abtAtqa[1], abtAtqa[0], abtSak);
  if (szAts > 1) { // if = 1, it's not actual ATS but error code
    if (force_rats && ! iso_ats_supported) {
      printf(" RATS forced\n");
    }
    printf(" ATS: ");
    print_hex(abtAts, szAts);
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}

bool readselse(int k,uint8_t block){
  // Initialise NFC device as "initiator"
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Disable 14443-4 autoswitching
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_device_set_property_bool(pnd, NP_HANDLE_PARITY, true) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    return false;
  }
  abtAuthBlock[1] = block;
  // Send the 7 bits request command specified in ISO 14443A (0x26)
  if (!transmit_bits(abtReqa, 7,NULL)) {
    printf("Error: No tag available\n");
    nfc_close(pnd);
    nfc_exit(context);
    return false;
  }
  memcpy(abtAtqa, abtRx, 2);

  // Anti-collision
  transmit_bytes(abtSelectAll, 2);

  // Check answer
  if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
    printf("WARNING: BCC check failed!\n");
  }

  // Save the UID CL1
  memcpy(abtRawUid, abtRx, 4);

  //Prepare and send CL1 Select-Command
  memcpy(abtSelectTag + 2, abtRx, 5);
  iso14443a_crc_append(abtSelectTag, 7);
  transmit_bytes(abtSelectTag, 9);
  abtSak = abtRx[0];

  if (abtRx[0] & SAK_FLAG_ATS_SUPPORTED) {
    iso_ats_supported = true;
  }
  // if ((abtRx[0] & SAK_FLAG_ATS_SUPPORTED) || force_rats) {
  //   iso14443a_crc_append(abtRats, 2);
  //   if (transmit_bytes(abtRats, 4)) {
  //     memcpy(abtAts, abtRx, szRx);
  //     szAts = szRx;
  //   }
  // }
  if(auth_block || readse){
    if(readse){
      state = crypto1_create(keys[k]);
      printf("use key[%d]: %lx\n",k,keys[k]);
    } else {
      state=crypto1_create(key);
    }

  iso14443a_crc_append(abtAuthBlock, 2);
  transmit_bytes(abtAuthBlock, 4);
  memcpy(abtNT, abtRx, 4);
  uint32_t nt;
  uint32_t uid_xor_nt;

  //uint8_t UID XOR NT convert uint32_t data
  // uid_xor_nt = *(uint32_t*)abtdata ^ *(uint32_t*)abtNT;
  for(i=0;i<=3;i++){
    uid_xor_nt = (uid_xor_nt << 8) | (uint32_t)(abtRawUid[i]^abtNT[i]);
    nt = (nt << 8) | (uint32_t)(abtNT[i]);
  }
  
  uint32_t ks0 = crypto1_word(state,uid_xor_nt,0);
  for(i=0;i<4;i++)
  abtdata2[i] = rand()%0x100; //generate rand nr
  
  //uint32_t convert uint8_t and transfer
  //method

  // uint8_t *byte = (uint8_t*)&ks1;
  // for(i=0;i<4;i++){
  //   abtdata2[i]=byte[3-i];
  // }

  for(i=0;i<4;i++){
    abtdata2[4+i] = ((prng_successor(nt, 64) >> 8 *(3-i)) & 0xff);
  }

  // Configure the Parity
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_PARITY, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    return false;
  }

  uint8_t ks_bit[1] = {0x00};
  int respByte = 0;
  respByte = sent_bits(64,abtdata2,true);
  if(respByte == 254){
    int count2 =0;
    for(i = 0; i < 4;i++){
      if(abtNT[i] == abtRx[i])
      count2++;
    }

    if (count2 == 4){
      if(!readse)
      ERR("Key is wrong,please change key and try again");
        // finish, halt the tag now
      iso14443a_crc_append(abtHalt, 2);
      transmit_bytes(abtHalt, 4);
      return false;
    }
    ERR("Warning, the key maybe wrong");
  } else if (respByte == 1 || respByte == 0){
    msgcheck();
    return false;
  }

  //at check
  uint32_t at = prng_successor(nt,96);
  uint8_t ks3[4] = {0x00,0x00,0x00,0x00};
  for(i=0;i<4;i++){
    ks3[i] = crypto1_byte(state,0,0);
    if( (ks3[i] ^ abtRx[i]) != (at >> (3-i)*8 & 0xff))
    ERR("Warning, AT is wrong");
  }
  //read tag
  if ( write_tag == false){
    abtdata[0] = 0x30;  abtdata[1] = abtAuthBlock[1];
    iso14443a_crc_append(abtdata, 2);
    respByte = sent_bits(32,abtdata,true);
    if(respByte == 0){
      msgcheck();
      return false;
    }

    printf("\nblock %02x data:\n",abtAuthBlock[1]);
    if(abtAuthBlock[1]%4 == 0)
    printf("+Sector: %d\n", abtAuthBlock[1]/4);
    printf("\t       ");

  for(i=0;i<16;i++){
    printf("%02X",abtRx[i] ^ crypto1_byte(state,0,0));
    if(!nospace)
    printf("  ");
  }
  crypto1_byte(state,0,0); crypto1_byte(state,0,0);
  printf("\n");

  } else {
    abtdata[0] = 0xa0;  abtdata[1] = abtAuthBlock[1];
    iso14443a_crc_append(abtdata, 2);
    sent_bits(32,abtdata,true);
    //write tag message send

    if ( msgcheck() ){
      sent_bits(144,abtwriteblock,true);
      if( msgcheck() ){
        printf("成功更改!!\n");
      } else {
        printf("失敗\n");
      }
    } else {
      return false;
    }
  }
  crypto1_destroy(state);
  return true;
  }
  return true;
}

