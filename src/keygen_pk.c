#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "origami.h"
#include "origami_gf.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;                 /* referenced by SIG_AlgorithmInstance.o */
static int rd(void*p,size_t n){FILE*f=fopen("/dev/urandom","rb");if(!f)return -1;size_t g=fread(p,1,n,f);fclose(f);return g==n?0:-1;}
static void wr_hex(FILE*f,const char*tag,const uint8_t*b,size_t n){fprintf(f,"%s",tag);for(size_t i=0;i<n;i++)fprintf(f,"%02X",b[i]);fprintf(f,"\n");}
/* argv[1] = path to a PRIVATE file for the secret seed (challenger keeps it; the forger never sees it).
   argv[2] (optional) = message length in bytes (default 56). */
int main(int argc,char**argv){
    init_gf_tables();
    if(argc<2){ fprintf(stderr,"usage: %s <private_seed_file> [msg_len]\n",argv[0]); return 1; }
    size_t mlen=argc>2?(size_t)atol(argv[2]):56; if(mlen<1||mlen>4096) mlen=56;
    static uint8_t seed[SEED_LENGTH_PRIVATE], pk[BYTES_PK], sk[BYTES_SK];
    uint8_t *msg=malloc(mlen);
    if(rd(seed,sizeof seed)||rd(msg,mlen)){ fprintf(stderr,"urandom failed\n"); return 1; }
    if(ORIGAMI_NAMESPACE(genkeys)(pk,sk,seed)!=0){ fprintf(stderr,"genkeys failed\n"); return 1; }
    FILE*pf=fopen(argv[1],"w"); if(!pf){ fprintf(stderr,"cannot open private file\n"); return 1; }
    wr_hex(pf,"SEED=",seed,sizeof seed); wr_hex(pf,"SK=",sk,sizeof sk); wr_hex(pf,"PK=",pk,sizeof pk);
    fclose(pf);
    /* stdout carries ONLY the public key and the message -- never the seed */
    wr_hex(stdout,"PK=",pk,sizeof pk);
    wr_hex(stdout,"MSG=",msg,mlen);
    fprintf(stderr,"keygen_pk: fresh random seed (kept private in %s); published pk=%d B, msg=%zu B\n",argv[1],BYTES_PK,mlen);
    return 0;
}
