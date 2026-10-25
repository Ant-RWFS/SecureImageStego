#define AES_CBC_BUILD_DLL
#include "AES_CBC.h"
#include "../AES.h"
#include <string.h>

static int pkcs7_unpad(const uint8_t *in,size_t in_len){
    if (in_len==0||in_len%16!=0)
        return -1;

    uint8_t pad_len=in[in_len-1];
    if(pad_len<1||pad_len>16)
        return -1;
    uint8_t diff=0;
    for(size_t i=in_len-pad_len;i<in_len;i++)
        diff|=(uint8_t)(in[i]^pad_len);
    if(diff!=0)
        return -1;

    return (int)(in_len-pad_len);
}

AES_CBC_API int cbc_encrypt(const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *pt,
                            size_t pt_len,
                            uint8_t *ct,
                            size_t *ct_len){
    uint8_t rk_enc[176];
    aes128_expand_key_enc(key,rk_enc);

    size_t pad_len=16-(pt_len%16);
    size_t padded_len=pt_len+pad_len;
    memcpy(ct,pt,pt_len);
    memset(ct+pt_len,(uint8_t)pad_len,pad_len);

    uint8_t prev[16];
    memcpy(prev,iv,16);

    for (size_t i=0;i<padded_len;i+=16) {
        uint8_t encrypted[16];
        for(int j=0;j<16;j++)
            encrypted[j]=ct[i+j]^prev[j];
        aes128_encrypt_block(rk_enc,encrypted,ct+i);
        memcpy(prev,ct+i,16);
    }

    *ct_len=padded_len;
    return 0;
}

AES_CBC_API int cbc_decrypt(const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *ct,
                            size_t ct_len,
                            uint8_t *pt,
                            size_t *pt_len){
    if (ct_len==0||ct_len%16!=0)
        return -1;

    uint8_t rk_dec[176];
    aes128_expand_key_dec(key,rk_dec);

    uint8_t prev[16];
    memcpy(prev,iv,16);

    for(size_t i=0;i<ct_len;i+=16){
        uint8_t decrypted[16];
        aes128_decrypt_block(rk_dec,ct+i,decrypted);
        for(int j=0;j<16;j++)
            pt[i+j]=decrypted[j]^prev[j];
        memcpy(prev,ct+i,16);
    }

    int unpadded_len= pkcs7_unpad(pt,ct_len);
    if(unpadded_len<0)
        return -1;
    *pt_len=(size_t)unpadded_len;
    return 0;
}