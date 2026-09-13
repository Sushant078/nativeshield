#include "shieldcrypto.h"
#include <string.h>

/* ---- SHA-256 (public-domain style implementation) ---- */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

typedef struct { uint32_t h[8]; uint64_t bits; uint8_t buf[64]; size_t n; } sha256_ctx;

static void sha256_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->bits=0; c->n=0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i=0;i<16;i++)
        w[i]=(uint32_t)p[i*4]<<24|(uint32_t)p[i*4+1]<<16|(uint32_t)p[i*4+2]<<8|(uint32_t)p[i*4+3];
    for (int i=16;i<64;i++){
        uint32_t s0=ROTR(w[i-15],7)^ROTR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROTR(w[i-2],17)^ROTR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i=0;i<64;i++){
        uint32_t S1=ROTR(e,6)^ROTR(e,11)^ROTR(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+S1+ch+K[i]+w[i];
        uint32_t S0=ROTR(a,2)^ROTR(a,13)^ROTR(a,22);
        uint32_t maj=(a&b)^(a&cc)^(b&cc);
        uint32_t t2=S0+maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t len) {
    c->bits += (uint64_t)len*8;
    while (len) {
        size_t take = 64 - c->n; if (take>len) take=len;
        memcpy(c->buf+c->n, p, take); c->n+=take; p+=take; len-=take;
        if (c->n==64){ sha256_block(c,c->buf); c->n=0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint8_t pad=0x80; uint64_t bits=c->bits;
    sha256_update(c,&pad,1);
    uint8_t z=0; while (c->n!=56) sha256_update(c,&z,1);
    uint8_t lb[8]; for(int i=0;i<8;i++) lb[i]=(uint8_t)(bits>>(56-8*i));
    sha256_update(c,lb,8);
    for(int i=0;i<8;i++){ out[i*4]=c->h[i]>>24; out[i*4+1]=c->h[i]>>16; out[i*4+2]=c->h[i]>>8; out[i*4+3]=c->h[i]; }
}

void shield_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c,data,len); sha256_final(&c,out);
}

void shield_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    uint8_t k[64]; memset(k,0,64);
    if (key_len>64) shield_sha256(key,key_len,k); else memcpy(k,key,key_len);
    uint8_t ipad[64], opad[64];
    for (int i=0;i<64;i++){ ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }
    sha256_ctx c; uint8_t inner[32];
    sha256_init(&c); sha256_update(&c,ipad,64); sha256_update(&c,msg,msg_len); sha256_final(&c,inner);
    sha256_init(&c); sha256_update(&c,opad,64); sha256_update(&c,inner,32); sha256_final(&c,out);
    memset(k,0,64); memset(ipad,0,64); memset(opad,0,64); memset(inner,0,32);
}

int shield_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    if (out_len > 255*32 || info_len > 512) return -1;
    uint8_t zero[32]; uint8_t prk[32];
    if (!salt || salt_len==0){ memset(zero,0,32); salt=zero; salt_len=32; }
    shield_hmac_sha256(salt,salt_len,ikm,ikm_len,prk);       /* extract */
    uint8_t t[32]; size_t tlen=0, pos=0; uint8_t counter=1;
    while (pos<out_len){
        sha256_ctx unused; (void)unused;
        /* T(i) = HMAC(prk, T(i-1) | info | counter) */
        uint8_t buf[32+512+1]; size_t bl=0;   /* info kept small in this project */
        if (tlen){ memcpy(buf,t,tlen); bl+=tlen; }
        memcpy(buf+bl,info,info_len); bl+=info_len;
        buf[bl++]=counter;
        shield_hmac_sha256(prk,32,buf,bl,t); tlen=32;
        size_t take=32; if (take>out_len-pos) take=out_len-pos;
        memcpy(out+pos,t,take); pos+=take; counter++;
        memset(buf,0,sizeof(buf));
    }
    memset(prk,0,32); memset(t,0,32);
    return 0;
}

int shield_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t d=0; for (size_t i=0;i<len;i++) d |= (uint8_t)(a[i]^b[i]);
    return d==0;
}
