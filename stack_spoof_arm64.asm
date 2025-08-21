; stack_spoof_arm64_enhanced.asm
;
; Call-Stack Spoofing ARM64 assembly
; Author: Alexander Hagenah (@xaitax)
;
; Platform: Windows on ARM64

    AREA |.text|, CODE, READONLY, ALIGN=4
    
    EXPORT SpoofCallStack
    EXPORT SpoofCallStackAdvanced
    EXPORT GetCurrentStackPointer
    EXPORT GetCurrentFramePointer
    EXPORT ExecuteWithFakeFrame
    
; --- Symbolic Constants ---
FRAME_SAVE_SIZE         EQU     0x10
NV_REG_PAIRS_SPOOF      EQU     3
NV_REG_SAVE_SPOOF       EQU     NV_REG_PAIRS_SPOOF * 0x10
PROLOGUE_SIZE_SPOOF     EQU     FRAME_SAVE_SIZE + NV_REG_SAVE_SPOOF

NV_REG_PAIRS_ADV        EQU     6       ; Need more registers for advanced
NV_REG_SAVE_ADV         EQU     NV_REG_PAIRS_ADV * 0x10
PROLOGUE_SIZE_ADV       EQU     FRAME_SAVE_SIZE + NV_REG_SAVE_ADV

NV_REG_PAIRS_EXEC       EQU     5
NV_REG_SAVE_EXEC        EQU     NV_REG_PAIRS_EXEC * 0x10
PROLOGUE_SIZE_EXEC      EQU     FRAME_SAVE_SIZE + NV_REG_SAVE_EXEC

; =================================================================
; SpoofCallStack: Single frame spoofing
; =================================================================
SpoofCallStack PROC
    stp     x29, x30, [sp, #-PROLOGUE_SIZE_SPOOF]!
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x30
    cbz     x22, SkipStore
    str     x23, [x22]
SkipStore
    sub     sp, sp, #0x30
    str     x29, [sp, #0x20]
    str     x20, [sp, #0x28]
    add     x9, sp, #0x20
    mov     x29, x9
    mov     x0, x21
    mov     x30, x20
    blr     x19
    mov     x19, x0
    sub     x29, x29, #0x20
    add     sp, sp, #0x30
    mov     x30, x23
    mov     x0, x19
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #PROLOGUE_SIZE_SPOOF
    ret
    ENDP

; =================================================================
; SpoofCallStackAdvanced: Multi-frame spoofing
; This version properly chains frames for Windows stack walking
; =================================================================
SpoofCallStackAdvanced PROC
    ; Save more registers for complex frame manipulation
    stp     x29, x30, [sp, #-PROLOGUE_SIZE_ADV]!
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    stp     x25, x26, [sp, #0x40]
    stp     x27, x28, [sp, #0x50]
    
    mov     x29, sp           ; Establish our frame
    
    ; Save parameters
    mov     x19, x0           ; Target function
    mov     x20, x1           ; Spoof chain array
    mov     x21, x2           ; Parameter
    mov     x22, x3           ; Chain depth
    mov     x23, x30          ; Save real return
    
    ; Calculate space needed for fake frames (32 bytes per frame)
    lsl     x24, x22, #5      ; depth * 32
    sub     sp, sp, x24       ; Allocate space
    
    ; Build the fake frame chain from bottom to top
    mov     x25, sp           ; Current frame position
    mov     x26, #0           ; Frame counter
    
BuildChain
    cmp     x26, x22
    b.ge    ChainComplete
    
    ; Calculate positions
    lsl     x9, x26, #5       ; index * 32
    add     x10, x25, x9      ; Current frame address
    
    ; Get the spoofed return address for this frame
    lsl     x11, x26, #3      ; index * 8
    ldr     x12, [x20, x11]   ; Load spoof address
    
    ; Build frame based on position
    cmp     x26, #0
    b.ne    NotFirstFrame
    
    ; First frame (innermost) - points to our real frame
    str     x29, [x10, #0x00]  ; FP points to our real frame
    str     x12, [x10, #0x08]  ; LR = first spoofed address
    b       FrameDone
    
NotFirstFrame
    ; Calculate previous frame address
    sub     x13, x10, #0x20    ; Previous frame
    str     x13, [x10, #0x00]  ; Chain FP to previous
    str     x12, [x10, #0x08]  ; LR = spoofed address
    
    ; For Windows compatibility, store additional context
    str     x21, [x10, #0x10]  ; Preserve parameter
    str     xzr, [x10, #0x18]  ; Clear padding
    
FrameDone
    add     x26, x26, #1
    b       BuildChain
    
ChainComplete
    ; Point FP to the first fake frame
    mov     x29, x25
    
    ; Load the first spoofed return into LR
    ldr     x30, [x20]
    
    ; For better spoofing, manipulate additional frames
    cmp     x22, #2
    b.lt    SingleFrame
    
    ; If we have multiple frames, set up secondary spoofing
    ldr     x9, [x20, #8]     ; Second spoof address
    str     x9, [x25, #0x28]  ; Store in predictable location
    
SingleFrame
    ; Call target with spoofed context
    mov     x0, x21
    blr     x19
    
    ; Save result
    mov     x26, x0
    
    ; Restore stack
    lsl     x24, x22, #5
    add     sp, sp, x24
    
    ; Restore context
    mov     x30, x23          ; Restore real return
    mov     x0, x26           ; Result in x0
    
    ; Restore saved registers
    ldp     x27, x28, [sp, #0x50]
    ldp     x25, x26, [sp, #0x40]
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #PROLOGUE_SIZE_ADV
    ret
    ENDP

; =================================================================
; Utility functions
; =================================================================
GetCurrentStackPointer PROC
    mov     x0, sp
    ret
    ENDP

GetCurrentFramePointer PROC
    mov     x0, x29
    ret
    ENDP

; =================================================================
; ExecuteWithFakeFrame: Enhanced with better frame chain setup
; =================================================================
ExecuteWithFakeFrame PROC
    stp     x29, x30, [sp, #-PROLOGUE_SIZE_EXEC]!
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    stp     x25, x26, [sp, #0x40]
    stp     x27, x28, [sp, #0x50]
    
    mov     x19, sp
    mov     x20, x29
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    mov     x24, x30
    
    ; Load fake frame data
    ldr     x25, [x22, #0x00]
    ldr     x26, [x22, #0x08]
    ldr     x27, [x22, #0x10]
    
    ; Switch to fake stack
    mov     sp, x27
    
    ; Build a proper frame on the fake stack
    sub     sp, sp, #0x20
    stp     x25, x26, [sp]    ; Store fake FP and LR
    mov     x29, sp           ; Set FP to this frame
    
    ; Call target
    mov     x0, x23
    blr     x21
    
    mov     x28, x0           ; Save result
    
    ; Restore real stack
    mov     sp, x19
    mov     x29, x20
    mov     x30, x24
    mov     x0, x28
    
    ldp     x27, x28, [sp, #0x50]
    ldp     x25, x26, [sp, #0x40]
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #PROLOGUE_SIZE_EXEC
    ret
    ENDP

    END
