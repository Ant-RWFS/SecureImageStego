@echo off
setlocal

for %%I in ("%~dp0..") do set "ROOT_DIR=%%~fI"
set "SRC=%ROOT_DIR%\src\Proccess\Crypto\AES"
set "SRC_SHA3=%ROOT_DIR%\src\Proccess\Crypto\SHA3"

set "AES_DLL=%ROOT_DIR%\build\crypto\aes\dll"
set "AES_LIB=%ROOT_DIR%\build\crypto\aes\lib"
set "AES_OBJ=%ROOT_DIR%\build\crypto\aes\obj"

set "SHA3_DLL=%ROOT_DIR%\build\crypto\sha3\dll"
set "SHA3_LIB=%ROOT_DIR%\build\crypto\sha3\lib"
set "SHA3_OBJ=%ROOT_DIR%\build\crypto\sha3\obj"

where cl >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Cannot find cl.exe
    echo         Try to run in "x64 Native Tools Command Prompt for VS 2022"
    echo         Or run vcvars64.bat to initialize
    exit /b 1
)

for %%D in ("%AES_DLL%" "%AES_LIB%" "%AES_OBJ%" "%SHA3_DLL%" "%SHA3_LIB%" "%SHA3_OBJ%") do (
    if not exist "%%~D" mkdir "%%~D"
)

echo [1/5] aes.dll
cl /nologo /O2 /arch:AVX /MD /LD /DAES_BUILD_DLL ^
   "%SRC%\AES.c" ^
   /Fo"%AES_OBJ%\aes.obj" ^
   /Fe"%AES_DLL%\aes.dll" ^
   /link ^
   /IMPLIB:"%AES_LIB%\aes.lib" ^
   /PDB:"%AES_DLL%\aes.pdb"
if errorlevel 1 goto :fail

echo [2/5] ctr.dll
cl /nologo /O2 /arch:AVX /MD /LD /DAES_CTR_BUILD_DLL ^
   "%SRC%\CTR\AES_CTR.c" ^
   /Fo"%AES_OBJ%\aes_ctr.obj" ^
   /Fe"%AES_DLL%\ctr.dll" ^
   /link ^
   /LIBPATH:"%AES_LIB%" ^
   aes.lib ^
   /IMPLIB:"%AES_LIB%\ctr.lib" ^
   /PDB:"%AES_DLL%\ctr.pdb"
if errorlevel 1 goto :fail

echo [3/5] cbc.dll
cl /nologo /O2 /arch:AVX /MD /LD /DCBC_BUILD_DLL ^
   "%SRC%\CBC\AES_CBC.c" ^
   /Fo"%AES_OBJ%\aes_cbc.obj" ^
   /Fe"%AES_DLL%\cbc.dll" ^
   /link ^
   /LIBPATH:"%AES_LIB%" ^
   aes.lib ^
   /IMPLIB:"%AES_LIB%\cbc.lib" ^
   /PDB:"%AES_DLL%\cbc.pdb"
if errorlevel 1 goto :fail

echo [4/5] gcm.dll
cl /nologo /O2 /arch:AVX /MD /LD /DAES_GCM_BUILD_DLL ^
   "%SRC%\GCM\AES_GCM.c" ^
   /Fo"%AES_OBJ%\aes_gcm.obj" ^
   /Fe"%AES_DLL%\gcm.dll" ^
   /link ^
   /LIBPATH:"%AES_LIB%" ^
   aes.lib ^
   /IMPLIB:"%AES_LIB%\gcm.lib" ^
   /PDB:"%AES_DLL%\gcm.pdb"
if errorlevel 1 goto :fail

echo [5/5] sha3.dll
cl /nologo /O2 /MD /LD /DSHA3_BUILD_DLL ^
   "%SRC_SHA3%\SHA3.c" ^
   /Fo"%SHA3_OBJ%\sha3.obj" ^
   /Fe"%SHA3_DLL%\sha3.dll" ^
   /link ^
   /IMPLIB:"%SHA3_LIB%\sha3.lib" ^
   /PDB:"%SHA3_DLL%\sha3.pdb"
if errorlevel 1 goto :fail

echo.
echo Done.
echo DLL : %AES_DLL%
echo       %SHA3_DLL%
echo LIB : %AES_LIB%
echo       %SHA3_LIB%
echo OBJ : %AES_OBJ%
echo       %SHA3_OBJ%
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
