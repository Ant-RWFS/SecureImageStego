@echo off
setlocal

for %%I in ("%~dp0..") do set "ROOT_DIR=%%~fI"
set "SRC=%ROOT_DIR%\src\Proccess\Crypto"

set "AES_DLL=%ROOT_DIR%\build\crypto\aes\dll"
set "AES_LIB=%ROOT_DIR%\build\crypto\aes\lib"
set "AES_OBJ=%ROOT_DIR%\build\crypto\aes\obj"

set "SHA3_DLL=%ROOT_DIR%\build\crypto\sha3\dll"
set "SHA3_LIB=%ROOT_DIR%\build\crypto\sha3\lib"
set "SHA3_OBJ=%ROOT_DIR%\build\crypto\sha3\obj"

set "LOG=%ROOT_DIR%\build\gcc_build.log"

if not defined CC set "CC=gcc"
for %%P in ("%CC%") do set "GCC_BIN=%%~dpP"
if defined GCC_BIN set "PATH=%GCC_BIN%;%PATH%"
if defined GCC_BIN echo [INFO] prepend to PATH: %GCC_BIN%

"%CC%" --version >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Cannot run GCC: %CC%
    echo         Add bin of MinGW-w64 to PATH
    exit /b 1
)

set "TARGET="
set "TMP_TARGET=%TEMP%\stego_gcc_target.txt"
"%CC%" -dumpmachine >"%TMP_TARGET%" 2>nul
if exist "%TMP_TARGET%" set /p TARGET=<"%TMP_TARGET%"
if exist "%TMP_TARGET%" del "%TMP_TARGET%" >nul 2>nul
if not defined TARGET set "TARGET=unknown"
echo [INFO] GCC: %CC%
echo [INFO] target: %TARGET%

echo %TARGET% | findstr /i "w64-mingw32" >nul
if errorlevel 1 (
    echo [ERROR] gcc is not MinGW-w64: %CC%
    echo         target = %TARGET%
    echo         Cygwin gcc builds DLLs that depend on cygwin1.dll, which
    echo         ctypes cannot load, and its include search fails on
    echo         Windows backslash paths.
    echo         Install MinGW-w64 and retry, e.g.:
    echo           winget install --id MSYS2.MSYS2 -e
    echo           C:\msys64\usr\bin\bash -lc "pacman -S --needed --noconfirm mingw-w64-ucrt-x86_64-gcc"
    echo           set "CC=C:\msys64\ucrt64\bin\gcc.exe"
    echo         Or build with MSVC: tools\build_msvc_cl.bat
    exit /b 1
)

set "AES_CFLAGS=-O2 -maes -mpclmul -msse4.1 -Wall"
set "SHA3_CFLAGS=-O2 -Wall"
set "LDFLAGS=-shared -static-libgcc"

for %%D in ("%AES_DLL%" "%AES_LIB%" "%AES_OBJ%" "%SHA3_DLL%" "%SHA3_LIB%" "%SHA3_OBJ%") do (
    if not exist "%%~D" mkdir "%%~D"
)

> "%LOG%" echo === build_gcc.bat ===
>>"%LOG%" echo CC     = %CC%
>>"%LOG%" echo TARGET = %TARGET%
>>"%LOG%" echo ROOT   = %ROOT_DIR%
>>"%LOG%" echo.

echo [1/5] aes.dll
>>"%LOG%" echo [1/5] aes.dll
"%CC%" %AES_CFLAGS% -DAES_BUILD_DLL -c "%SRC%\AES\AES.c" -o "%AES_OBJ%\aes.o" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail
"%CC%" %LDFLAGS% -o "%AES_DLL%\aes.dll" "%AES_OBJ%\aes.o" -Wl,--out-implib,"%AES_LIB%\libaes.dll.a" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [2/5] ctr.dll
>>"%LOG%" echo [2/5] ctr.dll
"%CC%" %AES_CFLAGS% -c "%SRC%\AES\CTR\AES_CTR.c" -o "%AES_OBJ%\aes_ctr.o" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail
"%CC%" %LDFLAGS% -o "%AES_DLL%\ctr.dll" "%AES_OBJ%\aes_ctr.o" -L"%AES_LIB%" -laes -Wl,--out-implib,"%AES_LIB%\libctr.dll.a" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [3/5] cbc.dll
>>"%LOG%" echo [3/5] cbc.dll
"%CC%" %AES_CFLAGS% -c "%SRC%\AES\CBC\AES_CBC.c" -o "%AES_OBJ%\aes_cbc.o" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail
"%CC%" %LDFLAGS% -o "%AES_DLL%\cbc.dll" "%AES_OBJ%\aes_cbc.o" -L"%AES_LIB%" -laes -Wl,--out-implib,"%AES_LIB%\libcbc.dll.a" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [4/5] gcm.dll
>>"%LOG%" echo [4/5] gcm.dll
"%CC%" %AES_CFLAGS% -c "%SRC%\AES\GCM\AES_GCM.c" -o "%AES_OBJ%\aes_gcm.o" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail
"%CC%" %LDFLAGS% -o "%AES_DLL%\gcm.dll" "%AES_OBJ%\aes_gcm.o" -L"%AES_LIB%" -laes -Wl,--out-implib,"%AES_LIB%\libgcm.dll.a" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [5/5] sha3.dll
>>"%LOG%" echo [5/5] sha3.dll
"%CC%" %SHA3_CFLAGS% -DSHA3_BUILD_DLL -c "%SRC%\SHA3\SHA3.c" -o "%SHA3_OBJ%\sha3.o" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail
"%CC%" %LDFLAGS% -o "%SHA3_DLL%\sha3.dll" "%SHA3_OBJ%\sha3.o" -Wl,--out-implib,"%SHA3_LIB%\libsha3.dll.a" >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo Done.
echo DLL : %AES_DLL%
echo       %SHA3_DLL%
echo LIB : %AES_LIB%
echo       %SHA3_LIB%
echo OBJ : %AES_OBJ%
echo       %SHA3_OBJ%
echo Log : %LOG%
exit /b 0

:fail
echo Build failed. Full log: %LOG%
type "%LOG%"
exit /b 1
