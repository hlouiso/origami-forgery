#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "origami.h"
#include "origami_gf.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
static int unhex(uint8_t*o,size_t n,const char*h){ if(strlen(h)!=2*n) return -1; for(size_t i=0;i<n;i++){unsigned v;if(sscanf(h+2*i,"%2x",&v)!=1)return -1;o[i]=(uint8_t)v;} return 0; }
/* argv: <pk_hex> <sig_hex> <msg_hex> [msg2_hex] */
int main(int argc,char**argv){
    init_gf_tables();
    if(argc<4){ fprintf(stderr,"usage: %s <pk_hex> <sig_hex> <msg_hex> [msg2_hex]\n",argv[0]); return 1; }
    static uint8_t pk[BYTES_PK], sig[BYTES_SIGNATURE];
    if(unhex(pk,BYTES_PK,argv[1])){ fprintf(stderr,"bad pk hex (len!=%d)\n",BYTES_PK); return 1; }
    if(unhex(sig,BYTES_SIGNATURE,argv[2])){ fprintf(stderr,"bad sig hex (len!=%d)\n",BYTES_SIGNATURE); return 1; }
    size_t mlen=strlen(argv[3])/2; uint8_t*msg=malloc(mlen?mlen:1);
    if(unhex(msg,mlen,argv[3])){ fprintf(stderr,"bad msg hex\n"); return 1; }
    int r=sig_verify(pk,BYTES_PK,sig,BYTES_SIGNATURE,msg,(unsigned long long)mlen);
    printf("MAIN  sig_verify(pk, forged_sig, msg) = %d  -> %s\n", r, r==0?"ACCEPTED (forgery valid)":"rejected");
    /* control A: flip one signature byte */
    { uint8_t s[BYTES_SIGNATURE]; memcpy(s,sig,sizeof s); s[0]^=0x01;
      int a=sig_verify(pk,BYTES_PK,s,BYTES_SIGNATURE,msg,(unsigned long long)mlen);
      printf("CTRL-A flip sig byte           = %d  -> %s\n", a, a!=0?"rejected (good)":"ACCEPTED (BAD)"); }
    /* control B: flip one salt byte (last byte of the signature) */
    { uint8_t s[BYTES_SIGNATURE]; memcpy(s,sig,sizeof s); s[BYTES_SIGNATURE-1]^=0x01;
      int b=sig_verify(pk,BYTES_PK,s,BYTES_SIGNATURE,msg,(unsigned long long)mlen);
      printf("CTRL-B flip salt byte          = %d  -> %s\n", b, b!=0?"rejected (good)":"ACCEPTED (BAD)"); }
    /* control C: same signature, different message */
    if(argc>=5){ size_t m2=strlen(argv[4])/2; uint8_t*msg2=malloc(m2?m2:1);
      if(unhex(msg2,m2,argv[4])==0){ int c=sig_verify(pk,BYTES_PK,sig,BYTES_SIGNATURE,msg2,(unsigned long long)m2);
        printf("CTRL-C other message           = %d  -> %s\n", c, c!=0?"rejected (good)":"ACCEPTED (BAD)"); } }
    return r==0?0:2;
}
