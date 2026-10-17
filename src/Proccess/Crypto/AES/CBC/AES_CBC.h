#ifndef AES_CBC_H
#define AES_CBC_H

#include <stdint.h>

#if defined(_WIN32)
#   if defined(AES_CBC_BUILD_DLL)
#       define AES_CBC_API __declspec(dllexport)
#   else
#       define AES_CBC_API __declspec(dllimport)
#   endif
#else
#   define AES_CBC_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

AES_CBC_API int cbc_encrypt(const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *pt,
                            size_t pt_len,
                            uint8_t *ct,
                            size_t *ct_len);
AES_CBC_API int cbc_decrypt(const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *ct,
                            size_t ct_len,
                            uint8_t *pt,
                            size_t *pt_len);
#ifdef __cplusplus
}
#endif
#endif