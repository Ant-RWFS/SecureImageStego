#include "AES.h"
#include <wmmintrin.h>
#include <emmintrin.h>
#include <intrin.h>

static inline __m128i key_expand(__m128i k,__m128i a){
    a= _mm_shuffle_epi32(a,0xff);
    __m128i t= _mm_slli_si128(k,4);
    k= _mm_xor_si128(k,t);
    t= _mm_slli_si128(t,4);
    k= _mm_xor_si128(k,t);
    t= _mm_slli_si128(t,4);
    k= _mm_xor_si128(k,t);
    return _mm_xor_si128(k,a);
}

static void aes128_init(const uint8_t key[16],__m128i rk[11]){
    rk[0]=_mm_loadu_si128((const __m128i *) key);
    rk[1]= key_expand(rk[0],_mm_aeskeygenassist_si128(rk[0],0x01));
    rk[2]= key_expand(rk[1],_mm_aeskeygenassist_si128(rk[1],0x02));
    rk[3]= key_expand(rk[2],_mm_aeskeygenassist_si128(rk[2],0x04));
    rk[4]= key_expand(rk[3],_mm_aeskeygenassist_si128(rk[3],0x08));
    rk[5]= key_expand(rk[4],_mm_aeskeygenassist_si128(rk[4],0x10));
    rk[6]= key_expand(rk[5],_mm_aeskeygenassist_si128(rk[5],0x20));
    rk[7]= key_expand(rk[6],_mm_aeskeygenassist_si128(rk[6],0x40));
    rk[8]= key_expand(rk[7],_mm_aeskeygenassist_si128(rk[7],0x80));
    rk[9]= key_expand(rk[8],_mm_aeskeygenassist_si128(rk[8],0x1b));
    rk[10]= key_expand(rk[9],_mm_aeskeygenassist_si128(rk[9],0x36));
}

static inline __m128i aes128_enc(__m128i m,const __m128i rk[11]){
    m= _mm_xor_si128(m,rk[0]);
    for (int i = 1; i < 10; i++)
        m= _mm_aesenc_si128(m,rk[i]);
    return _mm_aesenclast_si128(m,rk[10]);
}

static void aes128_dec_init(const uint8_t key[16],__m128i rk[11]){
    __m128i enc_rk[11];
    aes128_init(key,enc_rk);

    rk[0]=enc_rk[0];
    rk[10]=enc_rk[10];
    for (int i = 1; i < 10; i++) {
        rk[i]= _mm_aesimc_si128(enc_rk[i]);
    }
}

static inline __m128i aes128_dec(__m128i m,const __m128i rk[11]){
    m= _mm_xor_si128(m,rk[10]);
    for (int i = 9; i > 0; i--) {
        m= _mm_aesdec_si128(m,rk[i]);
    }
    return _mm_aesdeclast_si128(m,rk[0]);
}

static void rk_to_bytes(const __m128i rk[11], uint8_t out[176]){
    for (int i = 0; i < 11; i++) {
        _mm_storeu_si128((__m128i*)(out+i*16),rk[i]);
    }
}

static void bytes_to_rk(const uint8_t in[176],__m128i rk[11]){
    for (int i = 0; i < 11; i++) {
        rk[i]= _mm_loadu_si128((const __m128i*)(in+i*16));
    }
}

AES_API int cpu_has_aes_ni(void){
#if defined(_MSC_VER)
    int i[4];
    __cpuid(i,1);
    return (i[2]&(1<<25))!=0;
#else
    return __builtin_cpu_supports("aes")!=0;
#endif
}

AES_API void aes128_expand_key_enc(const uint8_t key[16],uint8_t rk_enc[176]){
    __m128i rk[11];
    aes128_init(key,rk);
    rk_to_bytes(rk,rk_enc);
}

AES_API void aes128_expand_key_dec(const uint8_t key[16],uint8_t rk_dec[176]){
    __m128i rk[11];
    aes128_dec_init(key,rk);
    rk_to_bytes(rk,rk_dec);
}

AES_API void aes128_encrypt_block(const uint8_t rk_enc[176],const uint8_t in[16],uint8_t out[16]){
    __m128i rk[11];
    bytes_to_rk(rk_enc,rk);
    __m128i m= _mm_loadu_si128((const __m128i*)in);
    __m128i c= aes128_enc(m,rk);
    _mm_storeu_si128((__m128i*)out,c);
}

AES_API void aes128_decrypt_block(const uint8_t rk_dec[176],const uint8_t in[16],uint8_t out[16]){
    __m128i rk[11];
    bytes_to_rk(rk_dec,rk);
    __m128i m= _mm_loadu_si128((const __m128i*)in);
    __m128i p= aes128_dec(m,rk);
    _mm_storeu_si128((__m128i*)out,p);
}