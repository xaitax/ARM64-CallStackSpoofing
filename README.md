# 🛡️ ARM64 Call Stack Spoofing Framework

**Advanced call stack manipulation techniques for evading EDR/XDR on Windows ARM64 systems**

## 🎯 Overview

This framework demonstrates call stack spoofing techniques specifically designed for ARM64 architecture on Windows 11. It implements multiple evasion methods that can bypass modern EDR (Endpoint Detection and Response) systems by manipulating the call stack to hide malicious activity behind legitimate Windows API calls.

### Key Features

- 🔄 **Dynamic Call-Site Gadget Discovery** - Automatically locates legitimate return addresses in `ntdll.dll`
- 🎭 **Multi-Frame Stack Spoofing** - Creates believable call chains with multiple spoofed frames
- 🏝️ **Stack Pivoting** - Executes code on isolated stacks, completely breaking stack analysis
- 🎲 **Gadget Randomization** - Non-deterministic selection prevents signature-based detection

## 📊 Demonstration Output

```
================================================================================
                      ARM64 Call Stack Spoofing Framework
                          Alexander Hagenah (@xaitax)
================================================================================

System Information:
  * Process ID:        18544
  * Thread ID:         24376
  * Architecture:      ARM64
  * Processor Count:   12
  * Page Size:         0x1000 bytes

[INFO] Initializing symbol handler...
[SUCCESS] Symbol handler initialized
[INFO] Building gadget cache from system modules...
[INFO] Scanning module: ntdll.dll (Base: 0x00007FFC0ACB0000)
[INFO] Scanning .text section (Size: 3081653 bytes)
[SUCCESS] Discovered 512 call-site gadgets in ntdll.dll
[INFO] First gadget: 0x00007FFC0ACB2EF0 | Last gadget: 0x00007FFC0ACBB670

================================================================================
  SCENARIO 1: BASELINE - DIRECT FUNCTION INVOCATION
================================================================================

[INFO] Establishing baseline with direct function call
[INFO] Expected: Full call stack visible to security tools

  [>] Executing concealed function
      Parameter: 0x11111111

  [STACK TRACE] From inside concealed function:
      [00] SecretFunction                   + 0x0078 <-- TARGET
      [01] mainCRTStartup                   + 0x0014
      [02] BaseThreadInitThunk              + 0x0040
      [03] RtlUserThreadStart               + 0x0044

  [>] Operation complete (Result: 0xCFBCAFFE)

[SUCCESS] Direct execution completed in 1 ms
[INFO] Result: 0xCFBCAFFE

================================================================================
  SCENARIO 2: SINGLE-FRAME CALL STACK SPOOFING
================================================================================
[DEBUG] Selected gadget[496/512]: 0x00007FFC0ACBB4C8

[INFO] Executing with spoofed return address
[INFO] Gadget source: ntdll.dll
[INFO] Spoofed return: 0x00007FFC0ACBB4C8

  [>] Executing concealed function
      Parameter: 0x22222222

  [STACK TRACE] From inside concealed function:
      [00] SecretFunction                   + 0x0078 <-- TARGET
      [01] RtlRemoveVectoredExceptionHandler + 0x0048
      [02] main                             + 0x03B8
      [03] mainCRTStartup                   + 0x0014
      [04] BaseThreadInitThunk              + 0x0040
      [05] RtlUserThreadStart               + 0x0044

  [>] Operation complete (Result: 0xFC8F9CCD)

[SUCCESS] Spoofed execution completed in 0 ms
[INFO] Result: 0xFC8F9CCD
[DEBUG] Real return address was: 0x00007FF70153D008

================================================================================
  SCENARIO 3: TRUE MULTI-FRAME CALL CHAIN SPOOFING
================================================================================

[INFO] Building TRUE 3-frame deep call chain using recursive spoofing
[INFO] This technique creates real frames with spoofed return addresses

  Multi-frame chain composition:
[DEBUG] Selected gadget[226/512]: 0x00007FFC0ACB703C
    Frame[0]: 0x00007FFC0ACB703C (RtlWnfDllUnloadCallback+0x60C)
[DEBUG] Selected gadget[90/512]: 0x00007FFC0ACB4CE0
    Frame[1]: 0x00007FFC0ACB4CE0 (LdrControlFlowGuardEnforced+0x990)
[DEBUG] Selected gadget[249/512]: 0x00007FFC0ACB7570
    Frame[2]: 0x00007FFC0ACB7570 (RtlWnfDllUnloadCallback+0xB40)

[INFO] Executing with 3 levels of recursion, each with spoofed return

  [>] Executing concealed function
      Parameter: 0x33333333

  [STACK TRACE] From inside concealed function:
      [00] SecretFunction                   + 0x0078 <-- TARGET
      [01] RtlWnfDllUnloadCallback          + 0x0B40
      [02] RecursiveSpoofHelper             + 0x0064
      [03] LdrControlFlowGuardEnforced      + 0x0990
      [04] RecursiveSpoofHelper             + 0x0064
      [05] RtlWnfDllUnloadCallback          + 0x060C
      [06] RecursiveSpoofHelper             + 0x0064
      [07] mainCRTStartup                   + 0x0014
      [08] BaseThreadInitThunk              + 0x0040
      [09] RtlUserThreadStart               + 0x0044

  [>] Operation complete (Result: 0xED9E8DDC)

[SUCCESS] TRUE multi-frame execution completed in 0 ms
[INFO] Result: 0xED9E8DDC
[INFO] Expected: 3 spoofed frames should appear in the call stack

================================================================================
  SCENARIO 4: STACK PIVOTING & EXECUTION ISOLATION
================================================================================

[INFO] Preparing isolated execution environment
[SUCCESS] Allocated 64 KB isolated stack at 0x000001E1A7A50000
[DEBUG] Selected gadget[57/512]: 0x00007FFC0ACB4338
[INFO] Fake frame configuration:
      FP: 0x000001E1A7A5FF00
      LR: 0x00007FFC0ACB4338
      SP: 0x000001E1A7A60000

  [>] Executing concealed function
      Parameter: 0x44444444

  [>] Operation complete (Result: 0x9AE9FAAB)

[SUCCESS] Isolated execution completed in 0 ms
[INFO] Result: 0x9AE9FAAB
[INFO] Stack isolation prevented normal stack walking
[DEBUG] Released isolated stack memory

================================================================================
  SCENARIO 5: SPOOFED PROCESS LAUNCH VIA STACK PIVOTING
================================================================================

[INFO] Preparing isolated execution environment for process launch
[INFO] Goal: Launch notepad.exe from a concealed call stack
[SUCCESS] Allocated 64 KB isolated stack at 0x000001E1A7A50000
[DEBUG] Selected gadget[149/512]: 0x00007FFC0ACB5E28
[INFO] Fake frame configuration:
      FP: 0x000001E1A7A5FF00
      LR: 0x00007FFC0ACB5E28
      SP: 0x000001E1A7A60000

  [>] Executing concealed function: LaunchNotepad
  [>] Successfully launched notepad.exe (PID: 3704)

  [>] Operation complete

[SUCCESS] Isolated process launch completed in 43 ms
[DEBUG] Released isolated stack memory

================================================================================
  EXECUTION STATISTICS
================================================================================

  Performance Metrics:
    * Total Executions:     5
    * Baseline Tests:       1
    * Spoofing Attempts:    4
    * Successful Spoofs:    4
    * Gadgets Discovered:   512
    * Average Exec Time:    8 ms
    * Spoofing Success:     100.0%

  Security Analysis:
    * EDR Evasion Level:    MAXIMUM (All spoofing techniques successful)
    * Detection Surface:    MINIMAL (Maximum gadget entropy: 512 gadgets)
    * Technique Coverage:   Single-Frame | Multi-Frame | Stack Pivot | Process Launch

[SUCCESS] All scenarios completed successfully
[INFO] Final concealed value: 0x9AE9FAAB
```

## 🔬 Technical Details

### How It Works

1.  **Gadget Discovery**: Scans `ntdll.dll` for legitimate call sites (instructions following `BL` opcodes)
2.  **Stack Manipulation**: Replaces return addresses with discovered gadgets
3.  **Frame Construction**: Builds fake call chains that appear legitimate to unwinders
4.  **Execution**: Target function executes with manipulated stack context

### Evasion Techniques

| Technique                 | Description                                                                                                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Single-Frame Spoofing** | Replaces the immediate return address with a gadget, making the current function appear to be called by a legitimate system function.    |
| **Multi-Frame Recursion** | Creates a deep, convincing call chain of multiple legitimate-looking stack frames, burying the true origin of execution.                 |
| **Stack Pivoting**        | Executes the target function on an entirely separate, isolated stack, which completely breaks standard stack walking and analysis tools. |

### Architecture Support

This framework is specifically designed for ARM64 and leverages:
- ARM64 calling convention (x29/x30 frame chain)
- Windows ARM64 ABI specifics
- Exception handling data (.pdata) alignment

## 🔬 Verifying Evasion with a Debugger

The most effective technique, **Stack Pivoting**, completely breaks the call stack. While this is invisible to live monitoring tools (which is the goal), its success can be definitively proven using a debugger like WinDbg. By pausing the program at the exact moment of execution, we can witness the broken stack firsthand.

### Step-by-Step Verification

1.  **Launch the application in WinDbg:**

2.  **Set a breakpoint on the target function.**
    ```
    0:000> bp stack_spoof!LaunchNotepad
    ```

3.  **Run the program.** The debugger will execute Scenarios 1-4 and then break when it enters `LaunchNotepad` in Scenario 5.
    ```
    0:000> g
    ```

4.  **Inspect the call stack.** Once the breakpoint is hit, we use the `k` command to display the call stack.
    ```
    Breakpoint 1 hit
    stack_spoof!LaunchNotepad:
    00007ff7`0153b1e8 d10043ff sub         sp,sp,#0x10
    0:000> k
    ```

### Analyzing the Debugger Output

The resulting call stack provides three key pieces of evidence that the evasion was successful.

```
WARNING: Stack pointer is outside the normal stack bounds. Stack unwinding can be inaccurate.
 # Child-SP          RetAddr               Call Site
00 000002c1`8e6dffe0 00007ff7`01531634     stack_spoof!LaunchNotepad [...] 
01 000002c1`8e6dffe0 00000000`00000000     stack_spoof!ExecuteWithFakeFrame+0x54
```

1.  **The WinDbg Warning**
    - **`WARNING: Stack pointer is outside the normal stack bounds.`**
    - This is the most important piece of evidence. The debugger itself recognizes that the stack pointer is in an unexpected memory region (our isolated stack allocated with `VirtualAlloc`), not where a normal thread's stack should be. This is definitive proof that **Stack Pivoting** was successful.

2.  **The Stack Pointer (`Child-SP`) Address**
    - **`00 000002c1`8e6dffe0 ...`**
    - The address of the stack frame is a high memory address corresponding to our newly allocated fake stack. This confirms the warning and proves the thread is no longer operating on its original stack.

3.  **The Broken Call Chain**
    - **`01 ... 00000000`00000000 stack_spoof!ExecuteWithFakeFrame+0x54`**
    - The debugger attempts to unwind the stack from `LaunchNotepad`. It correctly identifies that the call originated from our assembly routine `ExecuteWithFakeFrame`. However, it cannot unwind any further. The return address for `ExecuteWithFakeFrame` is `NULL`, and the stack trace terminates abruptly.
    - This is the proof that **stack walking is broken**. An EDR agent would see the same thing: a call to `CreateProcessW` that appears to originate from `LaunchNotepad`, which itself has no legitimate caller. The true origin is completely concealed.

## ⚠️ Disclaimer

This framework is intended for **authorized security research and educational purposes only**. Users are responsible for complying with all applicable laws and regulations. Misuse of this code for malicious purposes is strictly prohibited and may result in severe legal consequences.

## 📚 References

- [Windows ARM64 ABI Documentation](https://docs.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions)
- [ARM64 Instruction Set Reference](https://developer.arm.com/documentation/ddi0602/latest/)
- [Stack Walking in Windows](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/xperf/stack-walking)

## 👤 Author

**Alexander Hagenah**
- [@xaitax](https://x.com/xaitax)
- [LinkedIn](https://www.linkedin.com/in/alexhagenah/)
