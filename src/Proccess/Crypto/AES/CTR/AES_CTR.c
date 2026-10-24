#define AES_CTR_BUILD_DLL
#include "AES_CTR.h"
#include "../AES.h"
#include <string.h>

static inline void inc128(uint8_t c[16]){
    for (int i=15; i>=0;i--){
        if (++c[i])
            break;
    }
}

AES_CTR_API int ctr_crypt(const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *in,
                            size_t in_len,
                            uint8_t *out,
                            size_t *out_len){
    uint8_t rk_enc[176];
    aes128_expand_key_enc(key,rk_enc);

    uint8_t counter[16];
    memcpy(counter,iv,16);

    for(size_t i=0;i<in_len;i+=16){
        uint8_t ks[16];
        aes128_encrypt_block(rk_enc,counter,ks);

        size_t n=in_len-i<16?in_len-i:16;
        for (size_t j=0;j<n;j++) {
            out[i+j]=in[i+j]^ks[j];
        }

        inc128(counter);
    }
    *out_len=in_len;
    return 0;
}