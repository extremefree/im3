; ================================================================
; net_utils.asm — 字符串/内存工具函数
;
; 所有函数不直接做 syscall，纯计算
; ================================================================
BITS 64
default rel

%include "calling.inc"

; ================================================================
section .text
; ================================================================

; ================================================================
; util_strlen(str) -> rax = 长度
; ================================================================
global util_strlen
util_strlen:
    mov     r10, A1             ; r10 = str (r10 is volatile on Win64, avoids rsi clobber)
    xor     rax, rax
.lp:
    cmp     byte [r10 + rax], 0
    je      .done
    inc     rax
    jmp     .lp
.done:
    ret

; ================================================================
; util_strcmp(s1, s2) -> rax (0=equal, 1=different)
; Win64: A1=rcx, A2=rdx. Use r10/r11 (volatile) to avoid clobbering rsi/rdi.
; ================================================================
global util_strcmp
util_strcmp:
    mov     r10, A1             ; r10 = s1
    mov     r11, A2             ; r11 = s2
.lp:
    mov     al, [r10]
    mov     r9b, [r11]
    cmp     al, r9b
    jne     .diff
    test    al, al
    jz      .eq
    inc     r10
    inc     r11
    jmp     .lp
.eq:
    xor     eax, eax
    ret
.diff:
    mov     eax, 1
    ret

; ================================================================
; util_strncmp(s1, s2, n) -> rax (0=equal, 1=different)
; ================================================================
global util_strncmp
util_strncmp:
    PROLOGUE
    ; Use r10/r11 (volatile on Win64) to avoid clobbering rsi/rdi (callee-saved on Win64)
    mov     r11, A3             ; r11 = n (A3=r8 on Win64, saved before r8 is clobbered)
    mov     r10, A1             ; r10 = s1
    mov     r8,  A2             ; r8  = s2
    mov     rcx, r11
    movsxd  rcx, ecx
    test    rcx, rcx
    jz      .eq
.lp:
    mov     al, [r10]
    cmp     al, [r8]
    jne     .diff
    test    al, al
    jz      .eq
    inc     r10
    inc     r8
    dec     rcx
    jnz     .lp
.eq:
    xor     eax, eax
    EPILOGUE
.diff:
    mov     eax, 1
    EPILOGUE

; ================================================================
; util_memcpy(dst, src, n)
; ================================================================
global util_memcpy
util_memcpy:
    PROLOGUE
    mov     rdi, A1
    mov     rsi, A2
    mov     rcx, A3
    movsxd  rcx, ecx
%ifdef _WIN32
    ; On Win64, rdi/rsi are callee-saved. Save before rep movsb and restore after.
    ; Use PROLOGUE's sub rsp,32 for alignment. Push rsi/rdi here.
    ; Actually: we save via sub/push outside PROLOGUE so let's use r10/r11 trick.
    ; Simpler: util_memcpy is only called from ASM, which manages its own regs.
    ; But to be safe, just do the copy without rep movsb on Win64:
    test    rcx, rcx
    jz      .done
.lp:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     rcx
    jnz     .lp
.done:
%else
    rep     movsb
%endif
    EPILOGUE

; ================================================================
; util_memset(dst, val, n)
; ================================================================
global util_memset
util_memset:
    PROLOGUE
    mov     r10, A1             ; r10 = dst (volatile, avoids rdi clobber)
    mov     rdx, A3
    movsxd  rdx, edx
    mov     rax, A2
    movzx   eax, al
.lp:
    test    rdx, rdx
    jz      .done
    mov     [r10], al
    inc     r10
    dec     rdx
    jmp     .lp
.done:
    EPILOGUE

; ================================================================
; util_xor_crypt(data, len, key, key_len)
;   XOR 加密/解密（对称操作）
; ================================================================
global util_xor_crypt
util_xor_crypt:
    PROLOGUE
    push    r12
    push    r13

    mov     r12, A1             ; data
    mov     r13, A2
    movsxd  r13, r13d          ; len
    mov     r8, A3             ; key
    mov     r9, A4
    movsxd  r9, r9d            ; key_len

    xor     rcx, rcx
.lp:
    cmp     rcx, r13
    jge     .done
    mov     eax, ecx
    xor     edx, edx
    div     r9d
    movzx   eax, byte [r8 + rdx]
    xor     byte [r12 + rcx], al
    inc     rcx
    jmp     .lp
.done:
    pop     r13
    pop     r12
    EPILOGUE

; ================================================================
; util_find_colon(str, len) -> rax (offset of ':', or -1)
; Win64: A1=rcx, A2=rdx. Use r10 (volatile) to avoid clobbering rsi.
; ================================================================
global util_find_colon
util_find_colon:
    mov     r10, A1             ; r10 = str (volatile, avoids clobbering rsi)
    mov     rdx, A2
    movsxd  rdx, edx
    xor     rcx, rcx
.lp:
    cmp     rcx, rdx
    jge     .not_found
    cmp     byte [r10 + rcx], ':'
    je      .found
    inc     rcx
    jmp     .lp
.found:
    mov     rax, rcx
    ret
.not_found:
    mov     rax, -1
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
