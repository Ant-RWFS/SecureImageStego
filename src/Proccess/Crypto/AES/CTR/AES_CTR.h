#ifndef AES_CTR_H
#define AES_CTR_H

#include <stdint.h>

#if defined(_WIN32)
#   if defined(AES_CTR_BUILD_DLL)
#       define AES_CTR_API __declspec(dllexport)
#   else
#       define AES_CTR_API __declspec(dllimport)
#   endif
#else
#   define AES_CTR_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
AES_CTR_API int ctr_crypt(const uint8_t *key,
                          const uint8_t *iv,
                          const uint8_t *in,
                          size_t in_len,
                          uint8_t *out,
                          size_t *out_len);
#ifdef __cplusplus
}
#endif
#endif