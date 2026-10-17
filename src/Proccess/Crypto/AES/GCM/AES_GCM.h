#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>

#if defined(_WIN32)
#   if defined(AES_GCM_BUILD_DLL)
#       define AES_GCM_API __declspec(dllexport)
#   else
#       define AES_GCM_API __declspec(dllimport)
#   endif
#else
#   define AES_GCM_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
    AES_GCM_API int gcm_encrypt(const uint8_t *key,
                            const uint8_t *nonce,
                            const uint8_t *aad,
                            size_t alen,
                            const uint8_t *pt,
                            size_t plen,
                            uint8_t *ct,
                            uint8_t *tag);
    AES_GCM_API int gcm_decrypt(const uint8_t *key,
                            const uint8_t *nonce,
                            const uint8_t *aad,
                            size_t alen,
                            const uint8_t *ct,
                            size_t clen,
                            const uint8_t *tag,
                            uint8_t *pt);
#ifdef __cplusplus
}
#endif
#endif