#ifndef AES_H
#define AES_H

#include <stdint.h>

#if defined(_WIN32)
#define AES_API __declspec(dllexport)
#else
#define AES_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
    AES_API int cpu_has_aes_ni(void);
    AES_API void aes128_expand_key_enc(const uint8_t key[16],uint8_t rk_enc[176]);
    AES_API void aes128_expand_key_dec(const uint8_t key[16],uint8_t rk_dec[176]);
    AES_API void aes128_encrypt_block(const uint8_t rk_enc[176], const uint8_t in[16],uint8_t out[16]);
    AES_API void aes128_decrypt_block(const uint8_t rk_dec[176], const uint8_t in[16],uint8_t out[16]);
#ifdef __cplusplus
}
#endif
#endif