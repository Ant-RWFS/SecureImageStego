#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#   if defined(SHA3_BUILD_DLL)
#       define SHA3_API __declspec(dllexport)
#   else
#       define SHA3_API __declspec(dllimport)
#   endif
#else
#   define SHA3_API __attribute__((visibility("default")))
#endif

#define SHA3_256_DIGEST_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

	SHA3_API int sha3_256(const uint8_t* data, size_t len, uint8_t* out);

#ifdef __cplusplus
}
#endif
#endif