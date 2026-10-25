@echo off
setlocal

set SRC=D:\Agent Workspace\Steganography\src\Proccess\Crypto\AES
set ROOT=D:\Agent Workspace\Steganography\build\crypto\aes

set DLLDIR=%ROOT%\dll
set LIBDIR=%ROOT%\lib
set OBJDIR=%ROOT%\obj

if not exist "%DLLDIR%" mkdir "%DLLDIR%"
if not exist "%LIBDIR%" mkdir "%LIBDIR%"
if not exist "%OBJDIR%" mkdir "%OBJDIR%"

echo ============================================
echo [1/3] Building aes.dll
echo ============================================
cl /nologo /O2 /arch:AVX /MD /LD /DAES_BUILD_DLL ^
   "%SRC%\AES.c" ^
   /Fo"%OBJDIR%\aes.obj" ^
   /Fe"%DLLDIR%\aes.dll" ^
   /link ^
   /IMPLIB:"%LIBDIR%\aes.lib" ^
   /PDB:"%DLLDIR%\aes.pdb"
if errorlevel 1 goto :fail

echo ============================================
echo [2/3] Building gcm.dll
echo ============================================
cl /nologo /O2 /arch:AVX /MD /LD /DAES_GCM_BUILD_DLL ^
   "%SRC%\GCM\AES_GCM.c" ^
   /Fo"%OBJDIR%\aes_gcm.obj" ^
   /Fe"%DLLDIR%\gcm.dll" ^
   /link ^
   /LIBPATH:"%LIBDIR%" ^
   aes.lib ^
   /IMPLIB:"%LIBDIR%\gcm.lib" ^
   /PDB:"%DLLDIR%\gcm.pdb"
if errorlevel 1 goto :fail

echo ============================================
echo [3/3] Building cbc.dll
echo ============================================
cl /nologo /O2 /arch:AVX /MD /LD /DCBC_BUILD_DLL ^
   "%SRC%\CBC\AES_CBC.c" ^
   /Fo"%OBJDIR%\aes_cbc.obj" ^
   /Fe"%DLLDIR%\cbc.dll" ^
   /link ^
   /LIBPATH:"%LIBDIR%" ^
   aes.lib ^
   /IMPLIB:"%LIBDIR%\cbc.lib" ^
   /PDB:"%DLLDIR%\cbc.pdb"
if errorlevel 1 goto :fail

echo.
echo ============================================
echo Done.
echo ============================================
echo DLL : %DLLDIR%
echo LIB : %LIBDIR%
echo OBJ : %OBJDIR%
exit /b 0

:fail
echo.
echo ============================================
echo Build failed.
echo ============================================
exit /b 1