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
  * Process ID:        24052
  * Thread ID:         24904
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
[DEBUG] Selected gadget[184/512]: 0x00007FFC0ACB6610

[INFO] Executing with spoofed return address
[INFO] Gadget source: ntdll.dll
[INFO] Spoofed return: 0x00007FFC0ACB6610

  [>] Executing concealed function
      Parameter: 0x22222222

  [STACK TRACE] From inside concealed function:
      [00] SecretFunction                   + 0x0078 <-- TARGET
      [01] RtlTestAndPublishWnfStateData    + 0x0070
      [02] main                             + 0x03AC
      [03] mainCRTStartup                   + 0x0014
      [04] BaseThreadInitThunk              + 0x0040
      [05] RtlUserThreadStart               + 0x0044

  [>] Operation complete (Result: 0xFC8F9CCD)

[SUCCESS] Spoofed execution completed in 0 ms
[INFO] Result: 0xFC8F9CCD
[DEBUG] Real return address was: 0x00007FF759E2CA24

================================================================================
  SCENARIO 3: TRUE MULTI-FRAME CALL CHAIN SPOOFING
================================================================================

[INFO] Building TRUE 3-frame deep call chain using recursive spoofing
[INFO] This technique creates real frames with spoofed return addresses

  Multi-frame chain composition:
[DEBUG] Selected gadget[5/512]: 0x00007FFC0ACB3318
    Frame[0]: 0x00007FFC0ACB3318 (LdrAppxHandleIntegrityFailure+0x68)
[DEBUG] Selected gadget[269/512]: 0x00007FFC0ACB7A68
    Frame[1]: 0x00007FFC0ACB7A68 (RtlWnfDllUnloadCallback+0x1038)
[DEBUG] Selected gadget[218/512]: 0x00007FFC0ACB6F08
    Frame[2]: 0x00007FFC0ACB6F08 (RtlWnfDllUnloadCallback+0x4D8)

[INFO] Executing with 3 levels of recursion, each with spoofed return

  [>] Executing concealed function
      Parameter: 0x33333333

  [STACK TRACE] From inside concealed function:
      [00] SecretFunction                   + 0x0078 <-- TARGET
      [01] RtlWnfDllUnloadCallback          + 0x04D8
      [02] RecursiveSpoofHelper             + 0x0064
      [03] RtlWnfDllUnloadCallback          + 0x1038
      [04] RecursiveSpoofHelper             + 0x0064
      [05] LdrAppxHandleIntegrityFailure    + 0x0068
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
[SUCCESS] Allocated 64 KB isolated stack at 0x000002AFDA9C0000
[DEBUG] Selected gadget[435/512]: 0x00007FFC0ACBA45C
[INFO] Fake frame configuration:
      FP: 0x000002AFDA9CFF00
      LR: 0x00007FFC0ACBA45C
      SP: 0x000002AFDA9D0000

  [>] Executing concealed function
      Parameter: 0x44444444

  [STACK TRACE] From inside concealed function:

  [>] Operation complete (Result: 0x9AE9FAAB)

[SUCCESS] Isolated execution completed in 0 ms
[INFO] Result: 0x9AE9FAAB
[INFO] Stack isolation prevented normal stack walking
[DEBUG] Released isolated stack memory

================================================================================
  EXECUTION STATISTICS
================================================================================

  Performance Metrics:
    * Total Executions:     4
    * Baseline Tests:       1
    * Spoofing Attempts:    3
    * Successful Spoofs:    3
    * Gadgets Discovered:   512
    * Average Exec Time:    0 ms
    * Spoofing Success:     100.0%

  Security Analysis:
    * EDR Evasion Level:    MAXIMUM (All spoofing techniques successful)
    * Detection Surface:    MINIMAL (Maximum gadget entropy: 512 gadgets)
    * Technique Coverage:   Single-Frame | Multi-Frame | Stack Pivot

[SUCCESS] All scenarios completed successfully
[INFO] Final concealed value: 0x9AE9FAAB
```

## 🔬 Technical Details

### How It Works

1. **Gadget Discovery**: Scans `ntdll.dll` for legitimate call sites (instructions following `BL` opcodes)
2. **Stack Manipulation**: Replaces return addresses with discovered gadgets
3. **Frame Construction**: Builds fake call chains that appear legitimate to unwinders
4. **Execution**: Target function executes with manipulated stack context

### Evasion Techniques

| Technique | Description |
|-----------|-------------|
| **Single-Frame Spoofing** | Replaces immediate return address |
| **Multi-Frame Recursion** | Creates deep fake call chains |
| **Stack Pivoting** | Executes on isolated stack |

### Architecture Support

This framework is specifically designed for ARM64 and leverages:
- ARM64 calling convention (x29/x30 frame chain)
- Windows ARM64 ABI specifics
- Exception handling data (.pdata) alignment

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
