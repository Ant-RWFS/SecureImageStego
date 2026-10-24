cmake_minimum_required(VERSION 3.28)
project(Steganography C)

set(CMAKE_C_STANDARD 11)

add_library(aesgcm SHARED
        src/Proccess/Crypto/AES/AES.h
        src/Proccess/Crypto/AES/AES.c
        src/Proccess/Crypto/AES/CTR/AES_CTR.h
        src/Proccess/Crypto/AES/CTR/AES_CTR.c
        src/Proccess/Crypto/AES/GCM/AES_GCM.h
        src/Proccess/Crypto/AES/GCM/AES_GCM.c
        src/Proccess/Crypto/AES/CBC/AES_CBC.h
        src/Proccess/Crypto/AES/CBC/AES_CBC.c
        src/Proccess/Crypto/SHA3/SHA3.h
        src/Proccess/Crypto/SHA3/SHA3.c
)

if(MSVC)
    target_compile_options(aesgcm PRIVATE /arch:AVX2)
elseif(CYGWIN OR MINGW)
    target_compile_options(aesgcm PRIVATE
            -m64 -msse2 -maes -mpclmul -msse4.1)
else()
    target_compile_options(aesgcm PRIVATE
            -msse2 -maes -mpclmul -msse4.1)
endif()

set_target_properties(aesgcm PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

set_target_properties(aesgcm PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)