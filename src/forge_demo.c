// Universal forgery against Origami, from the PUBLIC KEY ALONE.
//
// It reconstructs the expanded public MQ map exactly as any verifier does
// (from param_id, pk_seed, Rpk), observes that every output equation is a
// bilinear form (non-oil vars of its zone) x (oil vars of its zone), and
// solves the layered system zone-by-zone by linearisation -- the same
// sequential linear solve the legitimate signer uses, but without the secret
// key, the hidden algebras, the rho split or any private data.
//
// The forged (sigma,salt) is then handed to the UNMODIFIED verify() from
// origami_ref.o.  If verify returns 0 the forgery is accepted.
//
// Build (per instance dir), e.g. Origami-128:
//   gcc -std=c11 -O3 -I<dir> -DORIGAMI_OPT=REF forge.c <dir>/origami_ref.o \
//       <dir>/symmetric_iccs.o <dir>/auxfunc.o <dir>/aes.o <dir>/drng.o -o forge128

#ifdef ORIGAMI_MEASURE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef ORIGAMI_MEASURE
#include <time.h>
#endif

#include "origami.h"
#include "origami_gf.h"     // gf ops, expand_gf, compress_gf, init_gf_tables (static)
#include "symmetric.h"      // shake_*
#include "auxfunc.h"          // pseudohash (H_msg)
#include "SIG_AlgorithmInstance.h"  // sig_verify: the public verifier API
#include "drng.h"                    // DRNG_ctx type only

#ifndef ALGSTR
#define ALGSTR "Origami"
#endif

#ifdef ORIGAMI_MEASURE
static unsigned long long metric_calls, metric_outer_passes;
static unsigned long long metric_tail_restarts, metric_main_restarts, metric_verify_calls;
static unsigned long long metric_verify_accepted_calls;
static double metric_forge_seconds, metric_verify_seconds, metric_verify_accepted_seconds;
static double metric_now(void){
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts)!=0){perror("clock_gettime");exit(1);}
    return (double)ts.tv_sec+(double)ts.tv_nsec*1e-9;
}
static void metric_print(void){
    printf("METRICS calls=%llu outer_passes=%llu tail_restarts=%llu main_restarts=%llu forge_s=%.9f verify_calls=%llu verify_s=%.9f verify_accepted_calls=%llu verify_accepted_s=%.9f\n",
           metric_calls,metric_outer_passes,metric_tail_restarts,metric_main_restarts,
           metric_forge_seconds,metric_verify_calls,metric_verify_seconds,
           metric_verify_accepted_calls,metric_verify_accepted_seconds);
}
#endif

#define GF_STREAM_BUF_BYTES 4096
#define GF_STREAM_MAX_EXTRA (BYTES_DIGEST + BYTES_SALT + 8)

/* ---- helpers copied from the reference public-map reconstruction path ---- */
/* (these are what the verifier itself runs; none of them is secret)          */

typedef struct {
    uint8_t seed[SEED_LENGTH_PRIVATE];
    size_t seed_len; char label[32];
    uint32_t a, b, c, block;
    uint8_t extra[GF_STREAM_MAX_EXTRA]; size_t extra_len;
    uint8_t buf[GF_STREAM_BUF_BYTES]; size_t pos, len;
    uint8_t byte; int have_high;
} gf_stream_t;

static void put_u32_le(uint8_t o[4], uint32_t v){o[0]=v;o[1]=v>>8;o[2]=v>>16;o[3]=v>>24;}
static void shake_absorb_u32(shake_t*st,uint32_t v){uint8_t t[4];put_u32_le(t,v);shake_absorb(st,t,4);}

static void derive_bytes(uint8_t*out,size_t outlen,const uint8_t*seed,size_t seed_len,
                         const char*label,uint32_t a,uint32_t b,uint32_t c,
                         const uint8_t*extra,size_t extra_len){
    shake_t st; shake256_init(&st);
    shake_absorb(&st,seed,seed_len);
    shake_absorb(&st,(const uint8_t*)label,strlen(label));
    shake_absorb_u32(&st,a); shake_absorb_u32(&st,b); shake_absorb_u32(&st,c);
    if(extra&&extra_len) shake_absorb(&st,extra,extra_len);
    shake_finalize(&st); shake_squeeze(out,outlen,&st);
}
static void gf_stream_init(gf_stream_t*gs,const uint8_t*seed,size_t seed_len,const char*label,
                           uint32_t a,uint32_t b,uint32_t c,const uint8_t*extra,size_t extra_len){
    memset(gs,0,sizeof(*gs));
    if(seed_len>sizeof(gs->seed)) seed_len=sizeof(gs->seed);
    memcpy(gs->seed,seed,seed_len); gs->seed_len=seed_len;
    strncpy(gs->label,label,sizeof(gs->label)-1);
    gs->a=a; gs->b=b; gs->c=c;
    if(extra&&extra_len){ if(extra_len>sizeof(gs->extra)) extra_len=sizeof(gs->extra);
        memcpy(gs->extra,extra,extra_len); gs->extra_len=extra_len; }
}
static void gf_stream_refill(gf_stream_t*gs){
    uint8_t se[GF_STREAM_MAX_EXTRA+4]; put_u32_le(se,gs->block++);
    if(gs->extra_len) memcpy(se+4,gs->extra,gs->extra_len);
    derive_bytes(gs->buf,sizeof(gs->buf),gs->seed,gs->seed_len,gs->label,
                 gs->a,gs->b,gs->c,se,gs->extra_len+4);
    gs->pos=0; gs->len=sizeof(gs->buf); gs->byte=0; gs->have_high=0;
}
static gf_t gf_stream_next(gf_stream_t*gs){
    gf_t out;
    if(gs->have_high){ out=(gf_t)(gs->byte>>4); gs->have_high=0; return out; }
    if(gs->pos>=gs->len) gf_stream_refill(gs);
    gs->byte=gs->buf[gs->pos++]; out=(gf_t)(gs->byte&0x0f); gs->have_high=1; return out;
}

static int64_t gcd_i64(int64_t a,int64_t b){while(b){int64_t t=a%b;a=b;b=t;}return a<0?-a:a;}

static void zones_init(zone_info_t z[ORIGAMI_TOTAL_ZONES]){ origami_init_zones(z); }

static int64_t elig_total(const zone_info_t*z){
    int64_t t=0; for(int i=0;i<ORIGAMI_TOTAL_ZONES;i++){
        int64_t non=(int64_t)z[i].n_offset+z[i].flat_v;
        t+=(int64_t)z[i].flat_m*non*z[i].flat_o; } return t; }
static int64_t elig_before(const zone_info_t*z,int zone){
    int64_t t=0; for(int i=0;i<zone;i++){
        int64_t non=(int64_t)z[i].n_offset+z[i].flat_v;
        t+=(int64_t)z[i].flat_m*non*z[i].flat_o; } return t; }

typedef struct{int64_t total,stride,offset;}rsched_t;
static int64_t rstride(int64_t total){
    int64_t s=((int64_t)ORIGAMI_PARAM_ID<<1)|1; if(total<=1)return 1; s%=total;
    if((s&1)==0)s++; if(s<=0)s=1;
    while(gcd_i64(s,total)!=1){s+=2; if(s>=total)s=1;} return s; }
static int64_t roffset(const uint8_t pk[SEED_LENGTH_PUBLIC],int64_t total){
    uint64_t acc=0x9e3779b97f4a7c15ULL^(uint64_t)ORIGAMI_PARAM_ID; if(total<=0)return 0;
    for(size_t i=0;i<SEED_LENGTH_PUBLIC;i++) acc^=(uint64_t)pk[i]+0x9e3779b97f4a7c15ULL+(acc<<6)+(acc>>2);
    return (int64_t)(acc%(uint64_t)total); }
static void rsched_init(rsched_t*rs,const zone_info_t*z,const uint8_t pk[SEED_LENGTH_PUBLIC]){
    rs->total=elig_total(z); rs->stride=rstride(rs->total); rs->offset=roffset(pk,rs->total); }
static long rrank(const rsched_t*rs,int64_t idx){
    int64_t r=(idx*rs->stride+rs->offset)%rs->total; return r<(int64_t)NUMGF_RPK?(long)r:-1L; }

/* target vector, exactly as the signer/verifier compute it */
static void hash_to_field(gf_t target[ORIGAMI_M],const uint8_t*digest,size_t len,
                          const uint8_t salt[BYTES_SALT]){
    uint8_t bytes[BYTES_HASH]; shake_t st; shake256_init(&st);
    shake_absorb(&st,(const uint8_t*)"target",6);
    shake_absorb(&st,digest,len); shake_absorb(&st,salt,BYTES_SALT);
    shake_finalize(&st); shake_squeeze(bytes,sizeof(bytes),&st);
    (void)expand_gf(target,bytes,ORIGAMI_M);
}

/* GF(16) Gaussian elimination: solve rows x cols system, free vars = 0.
   returns 0 on full row rank, -1 otherwise */
static int solve_free0(gf_t*x,const gf_t*Ain,const gf_t*rhs,int rows,int cols){
    static gf_t aug[ORIGAMI_MAX_FLAT_M*(ORIGAMI_MAX_FLAT_O+1)];
    int pcol[ORIGAMI_MAX_FLAT_M]; int rank=0;
    for(int r=0;r<rows;r++){ for(int c=0;c<cols;c++) aug[r*(cols+1)+c]=Ain[r*cols+c];
        aug[r*(cols+1)+cols]=rhs[r]; }
    for(int col=0;col<cols&&rank<rows;col++){
        int piv=-1; for(int r=rank;r<rows;r++) if(aug[r*(cols+1)+col]){piv=r;break;}
        if(piv<0) continue;
        if(piv!=rank) for(int c=col;c<=cols;c++){gf_t t=aug[rank*(cols+1)+c];
            aug[rank*(cols+1)+c]=aug[piv*(cols+1)+c];aug[piv*(cols+1)+c]=t;}
        gf_t inv=gf_inv(aug[rank*(cols+1)+col]);
        for(int c=col;c<=cols;c++) aug[rank*(cols+1)+c]=gf_mult(aug[rank*(cols+1)+c],inv);
        for(int r=0;r<rows;r++){ if(r==rank)continue; gf_t f=aug[r*(cols+1)+col]; if(!f)continue;
            for(int c=col;c<=cols;c++) aug[r*(cols+1)+c]=gf_sub(aug[r*(cols+1)+c],gf_mult(f,aug[rank*(cols+1)+c])); }
        pcol[rank]=col; rank++;
    }
    if(rank!=rows) return -1;
    memset(x,0,(size_t)cols*sizeof(gf_t));
    for(int r=rows-1;r>=0;r--){ int pc=pcol[r]; gf_t s=0;
        for(int c=pc+1;c<cols;c++) gf_set_add(&s,gf_mult(aug[r*(cols+1)+c],x[c]));
        x[pc]=gf_sub(aug[r*(cols+1)+cols],s); }
    return 0;
}

/* the forgery: build sigma from pk only */
static int forge(const ph_expanded_PK*pkx,uint8_t*sig,const uint8_t*digest,size_t len,
                 const uint8_t salt[BYTES_SALT]){
#ifdef ORIGAMI_MEASURE
    metric_calls++;
#endif
    zone_info_t z[ORIGAMI_TOTAL_ZONES]; zones_init(z);
    rsched_t rs; rsched_init(&rs,z,pkx->pk_seed);
    gf_t target[ORIGAMI_M]; hash_to_field(target,digest,len,salt);

    static gf_t secret_y[ORIGAMI_N];
    static gf_t A[ORIGAMI_MAX_FLAT_M*ORIGAMI_MAX_FLAT_O];
    gf_t rhs[ORIGAMI_MAX_FLAT_M], W[ORIGAMI_MAX_FLAT_O];

    for(int outer=0; outer<4096; outer++){
#ifdef ORIGAMI_MEASURE
        metric_outer_passes++;
#endif
        memset(secret_y,0,sizeof(secret_y));
        int ok=1;
        for(int zone=0; zone<ORIGAMI_TOTAL_ZONES && ok; zone++){
            const zone_info_t*zn=&z[zone];
            const int non_cnt=zn->n_offset+zn->flat_v;
            const int oil_start=zn->n_offset+zn->flat_v;
            const int64_t zbase=elig_before(z,zone);
            /* Without vinegar, local retries repeat the same system. */
            const int max_local_attempts=zn->flat_v>0?256:1;
            int solved=0;
            for(int att=0; att<max_local_attempts && !solved; att++){
                /* choose this zone's vinegar freely (any values) */
                gf_stream_t vs; gf_stream_init(&vs,pkx->pk_seed,SEED_LENGTH_PUBLIC,"forge-vin",
                                               (uint32_t)zone,(uint32_t)att,(uint32_t)outer,NULL,0);
                for(int i=0;i<zn->flat_v;i++) secret_y[zn->n_offset+i]=gf_stream_next(&vs);
                /* build A[eq][oil] = sum_non coeff(eq,non,oil)*secret_y[non], rhs=target */
                memset(A,0,(size_t)zn->flat_m*zn->flat_o*sizeof(gf_t));
                for(int eq=0; eq<zn->flat_m; eq++){
                    gf_stream_t gs; const int eqg=zn->m_offset+eq;
                    const int64_t ebase=zbase+(int64_t)eq*non_cnt*zn->flat_o;
                    gf_stream_init(&gs,pkx->pk_seed,SEED_LENGTH_PUBLIC,"P_affine",
                                   (uint32_t)eqg,(uint32_t)ORIGAMI_N,(uint32_t)ORIGAMI_PARAM_ID,NULL,0);
                    for(int non=0;non<non_cnt;non++){ gf_t yn=secret_y[non];
                        for(int oil=0;oil<zn->flat_o;oil++){
                            gf_t coeff=gf_stream_next(&gs);
                            long rk=rrank(&rs,ebase+(int64_t)non*zn->flat_o+oil);
                            if(rk>=0) coeff=pkx->R_coeffs[rk];
                            if(coeff==0||yn==0) continue;
                            gf_set_add(&A[eq*zn->flat_o+oil],gf_mult(coeff,yn));
                        }
                    }
                    rhs[eq]=target[zn->m_offset+eq];
                }
                if(solve_free0(W,A,rhs,zn->flat_m,zn->flat_o)==0){
                    for(int oil=0;oil<zn->flat_o;oil++) secret_y[oil_start+oil]=W[oil];
                    solved=1;
                }
            }
            if(!solved){
#ifdef ORIGAMI_MEASURE
                if(zn->flat_v==0) metric_tail_restarts++;
                else metric_main_restarts++;
#endif
                ok=0;
            }
        }
        if(!ok) continue;
        /* internal -> public coordinates via the PUBLIC permutation, then serialise */
        static gf_t public_y[ORIGAMI_N];
        for(int i=0;i<ORIGAMI_N;i++) public_y[pkx->secret_to_public[i]]=secret_y[i];
        compress_gf(sig,public_y,ORIGAMI_N);
        memcpy(sig+BYTES_GF(ORIGAMI_N),salt,BYTES_SALT);
        return 0;
    }
    return -1;
}


/* ---- Demonstration: universal forgery from the public key ----
   Oracle is the PUBLIC verifier API sig_verify(pk, sn, m): it recomputes H_msg(m)
   itself and reads the salt from the signature, exactly as any verifier would.
   Per forgery, three negative controls must all reject (0 false-accepts):
     (A) flip a signature byte, (B) flip a salt byte, (C) verify against another message.
   Modes:
     ./forge_demo [K] [MSGS]                 random keys/messages (defaults 100, 3)
     ./forge_demo --one <seedhex> <msghex>   one fixed keypair+message, print forged Sn */
static int rd(void*p,size_t n){FILE*f=fopen("/dev/urandom","rb");if(!f)return -1;size_t g=fread(p,1,n,f);fclose(f);return g==n?0:-1;}
static int unhex(uint8_t*o,size_t n,const char*h){for(size_t i=0;i<n;i++){unsigned v;if(sscanf(h+2*i,"%2x",&v)!=1)return -1;o[i]=(uint8_t)v;}return 0;}
static void puthex(const char*tag,const uint8_t*b,size_t n){printf("%s",tag);for(size_t i=0;i<n;i++)printf("%02X",b[i]);printf("\n");}

static int forge_one(const uint8_t*pk,const uint8_t*digest,const uint8_t*salt,uint8_t*sig){
    ph_expanded_PK pkx;
#ifdef ORIGAMI_MEASURE
    double start=metric_now();
#endif
    if(ORIGAMI_NAMESPACE(pk_expand)(&pkx,pk)!=0) return -1;
    int rc=forge(&pkx,sig,digest,BYTES_DIGEST,salt);
    ORIGAMI_NAMESPACE(pk_free)(&pkx);
#ifdef ORIGAMI_MEASURE
    metric_forge_seconds+=metric_now()-start;
#endif
    return rc;
}

#ifdef ORIGAMI_MEASURE
static int measured_sig_verify(uint8_t*pk, unsigned long long pklen,
                               uint8_t*sig, unsigned long long siglen,
                               uint8_t*msg, unsigned long long msglen){
    double start=metric_now();
    int rc=sig_verify(pk,pklen,sig,siglen,msg,msglen);
    double elapsed=metric_now()-start;
    metric_verify_seconds+=elapsed;
    metric_verify_calls++;
    if(rc==0){metric_verify_accepted_seconds+=elapsed;metric_verify_accepted_calls++;}
    return rc;
}
#define sig_verify measured_sig_verify
#endif

DRNG_ctx drng_algorithm;  /* referenced by SIG_AlgorithmInstance.o; sig_verify never reads it */
int main(int argc,char**argv){
    init_gf_tables();
    if(argc>=4 && strcmp(argv[1],"--one")==0){
        uint8_t seed[SEED_LENGTH_PRIVATE],pk[BYTES_PK],sk[BYTES_SK],salt[BYTES_SALT],digest[BYTES_DIGEST],sig[BYTES_SIGNATURE];
        size_t mlen=strlen(argv[3])/2; uint8_t*msg=malloc(mlen?mlen:1);
        if(unhex(seed,sizeof seed,argv[2])||unhex(msg,mlen,argv[3])){printf("bad hex\n");return 1;}
        if(ORIGAMI_NAMESPACE(genkeys)(pk,sk,seed)!=0){printf("genkeys failed\n");return 1;}
        if(pseudohash(BYTES_DIGEST*8,msg,(unsigned long long)mlen*8ULL,digest)!=0){printf("pseudohash failed\n");return 1;}
        memset(salt,0x5A,sizeof salt);          /* any salt; a verifier reads it from the signature */
        if(forge_one(pk,digest,salt,sig)!=0){printf("forge failed\n");return 1;}
        int rc=sig_verify(pk,BYTES_PK,sig,BYTES_SIGNATURE,msg,(unsigned long long)mlen);
        printf("%s --one  sig_verify(pk,forged_sn,m) = %d  (%s)\n",ALGSTR,rc,rc==0?"ACCEPTED":"rejected");
        if(argc>=5){ uint8_t kat[BYTES_SIGNATURE]; if(unhex(kat,BYTES_SIGNATURE,argv[4])==0){
            int kr=sig_verify(pk,BYTES_PK,kat,BYTES_SIGNATURE,msg,(unsigned long long)mlen);
            printf("  KAT Sn under regenerated pk = %d (%s -> pk is the KAT keypair); forged==KAT ? %s\n",
                   kr,kr==0?"verifies":"FAILS",memcmp(kat,sig,BYTES_SIGNATURE)==0?"YES (replay!)":"NO (a new signature)"); } }
        if(argc>=6){
            uint8_t kat_pk[BYTES_PK];
            if(strlen(argv[5])!=2*BYTES_PK || unhex(kat_pk,BYTES_PK,argv[5])){
                fprintf(stderr,"bad KAT pk hex\n");return 1;
            }
            int same=memcmp(kat_pk,pk,BYTES_PK)==0;
            printf("  KAT pk matches regenerated pk = %s\n",same?"YES":"NO");
            if(!same) return 2;
        }
        puthex("forged Sn = ",sig,BYTES_SIGNATURE);
#ifdef ORIGAMI_MEASURE
        metric_print();
#endif
        return rc==0?0:2;
    }
    long K=argc>1?atol(argv[1]):100, MSGS=argc>2?atol(argv[2]):3;
    long ok=0,tot=0,ncA=0,ncB=0,ncC=0,badA=0,badB=0,badC=0,keyfail=0;
    uint8_t pk[BYTES_PK],sk[BYTES_SK],seed[SEED_LENGTH_PRIVATE];
    for(long k=0;k<K;k++){
        if(rd(seed,sizeof seed)){printf("urandom failed\n");return 1;}
        if(ORIGAMI_NAMESPACE(genkeys)(pk,sk,seed)!=0){keyfail++;continue;}
        for(long j=0;j<MSGS;j++){
            uint8_t msg[56],msg2[56],digest[BYTES_DIGEST],salt[BYTES_SALT],sig[BYTES_SIGNATURE];
            if(rd(msg,sizeof msg)||rd(msg2,sizeof msg2)||rd(salt,sizeof salt)){printf("urandom failed\n");return 1;}
            if(pseudohash(BYTES_DIGEST*8,msg,(unsigned long long)sizeof(msg)*8ULL,digest)!=0){printf("pseudohash failed\n");return 1;}
            tot++;
            if(forge_one(pk,digest,salt,sig)!=0) continue;                 /* forge from pk only */
            if(sig_verify(pk,BYTES_PK,sig,BYTES_SIGNATURE,msg,sizeof msg)==0) ok++; else continue;
            { uint8_t s2[BYTES_SIGNATURE]; memcpy(s2,sig,sizeof s2); s2[0]^=0x01;
              if(sig_verify(pk,BYTES_PK,s2,BYTES_SIGNATURE,msg,sizeof msg)!=0) ncA++; else badA++; }
            { uint8_t s2[BYTES_SIGNATURE]; memcpy(s2,sig,sizeof s2); s2[BYTES_GF(ORIGAMI_N)]^=0x01;
              if(sig_verify(pk,BYTES_PK,s2,BYTES_SIGNATURE,msg,sizeof msg)!=0) ncB++; else badB++; }
            { if(sig_verify(pk,BYTES_PK,sig,BYTES_SIGNATURE,msg2,sizeof msg2)!=0) ncC++; else badC++; }
        }
    }
    printf("%s  keys=%ld msgs/key=%ld  forged_accepted=%ld/%ld  keyfail=%ld\n",ALGSTR,K,MSGS,ok,tot,keyfail);
    printf("  negative controls (must all reject): A_sig=%ld/%ld B_salt=%ld/%ld C_othermsg=%ld/%ld  [FALSE-ACCEPTS A=%ld B=%ld C=%ld]\n",
           ncA,ok,ncB,ok,ncC,ok,badA,badB,badC);
#ifdef ORIGAMI_MEASURE
    metric_print();
#endif
    return (ok==tot && badA==0 && badB==0 && badC==0)?0:2;
}
