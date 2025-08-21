@echo off
REM build.bat - Build script for ARM64 Stack Spoofing
REM Requires: ARM64 Native Tools Command Prompt for VS

echo ==================================================================
echo  ARM64 Stack Spoofing Build Script
echo ==================================================================
echo.

REM Check if we're in ARM64 environment
where armasm64 >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] armasm64.exe not found!
    echo Please run this from "ARM64 Native Tools Command Prompt"
    exit /b 1
)

echo [*] Cleaning previous build...
del *.obj *.exe *.pdb 2>nul

echo [*] Assembling ARM64 assembly code...
armasm64 -o stack_spoof_arm64_asm.obj stack_spoof_arm64.asm
if %errorlevel% neq 0 (
    echo [ERROR] Assembly failed!
    exit /b 1
)

echo [*] Compiling C++ code...
cl.exe /O2 /MT /Zi /EHsc /std:c++17 /W3 /c stack_spoof_arm64.c
if %errorlevel% neq 0 (
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo [*] Linking executable...
link.exe /OUT:stack_spoof.exe /MACHINE:ARM64 /DEBUG /PDB:stack_spoof.pdb ^
    stack_spoof_arm64.obj stack_spoof_arm64_asm.obj dbghelp.lib kernel32.lib ntdll.lib
if %errorlevel% neq 0 (
    echo [ERROR] Linking failed!
    exit /b 1
)

echo.
echo ==================================================================
echo  BUILD SUCCESSFUL!
echo ==================================================================
echo.
echo Executable: stack_spoof.exe
echo.
