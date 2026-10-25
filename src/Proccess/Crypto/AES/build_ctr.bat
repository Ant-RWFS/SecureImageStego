@echo off
setlocal

set SRC=D:\Agent Workspace\SecureImageStego\src\Proccess\Crypto\AES
set ROOT=D:\Agent Workspace\SecureImageStego\build\crypto\aes

set DLLDIR=%ROOT%\dll
set LIBDIR=%ROOT%\lib
set OBJDIR=%ROOT%\obj

if not exist "%DLLDIR%" mkdir "%DLLDIR%"
if not exist "%LIBDIR%" mkdir "%LIBDIR%"
if not exist "%OBJDIR%" mkdir "%OBJDIR%"

echo ============================================
echo Building ctr.dll
echo ============================================
cl /nologo /O2 /arch:AVX /MD /LD /DAES_CTR_BUILD_DLL ^
   "%SRC%\CTR\AES_CTR.c" ^
   /Fo"%OBJDIR%\aes_ctr.obj" ^
   /Fe"%DLLDIR%\ctr.dll" ^
   /link ^
   /LIBPATH:"%LIBDIR%" ^
   aes.lib ^
   /IMPLIB:"%LIBDIR%\ctr.lib" ^
   /PDB:"%DLLDIR%\ctr.pdb"
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