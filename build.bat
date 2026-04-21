@echo off
setlocal

set SRC_C=src\ghost.c
set SRC_ASM=src\asm_stubs.asm
set OBJ_ASM=asm_stubs.obj
set OUT=ghost.exe
set INC=/I include

if /i "%1"=="clean" (
    for %%f in (%OUT% ghost.obj ghost.pdb %OBJ_ASM%) do (
        if exist %%f del /q %%f
    )
    echo [*] Cleaned.
    goto :eof
)

set COMPILER=none

where cl.exe >nul 2>&1
if %errorlevel%==0 (
    set COMPILER=msvc
    goto :found
)

where gcc.exe >nul 2>&1
if %errorlevel%==0 (
    set COMPILER=gcc
    goto :found
)

echo [-] No compiler found.  Run from a Visual Studio x64 Developer Prompt.
exit /b 1

:found
echo [*] Compiler : %COMPILER%

if "%COMPILER%"=="msvc" (

    echo [*] Assembling %SRC_ASM% ...
    where ml64.exe >nul 2>&1
    if %errorlevel% neq 0 (
        echo [-] ml64.exe not found. Make sure you are in a VS x64 Developer Prompt.
        exit /b 1
    )
    ml64.exe /nologo /c /Fo %OBJ_ASM% %SRC_ASM%
    if %errorlevel% neq 0 (
        echo [-] ASM assembly failed.
        exit /b 1
    )
    echo [+] ASM assembled : %OBJ_ASM%

    if /i "%1"=="debug" (
        echo [*] Mode     : Debug
        cl /nologo /W3 /Zi /Od %INC% %SRC_C% %OBJ_ASM% /Fe%OUT% /link /subsystem:console Advapi32.lib Gdi32.lib User32.lib Shell32.lib
    ) else (
        echo [*] Mode     : Release
        cl /nologo /W3 /O2 %INC% %SRC_C% %OBJ_ASM% /Fe%OUT% /link /subsystem:console Advapi32.lib Gdi32.lib User32.lib Shell32.lib
    )

    for %%f in (ghost.obj %OBJ_ASM%) do (
        if exist %%f del /q %%f
    )
    goto :done
)

if "%COMPILER%"=="gcc" (
    echo [!] MinGW: asm_stubs.asm requires MASM (ml64.exe).
    echo [!] Building C-only fallback (no direct syscall, ntdll call used).
    if /i "%1"=="debug" (
        gcc -Wall -g -O0 -I include -o %OUT% %SRC_C%
    ) else (
        gcc -Wall -O2 -I include -o %OUT% %SRC_C% -s
    )
    goto :done
)

:done
if exist %OUT% (
    echo.
    echo [+] Built ^> %OUT%
    echo [*] Run:  ghost.exe payload.exe [masquerade_name]
) else (
    echo [-] Build failed.
    exit /b 1
)
endlocal
