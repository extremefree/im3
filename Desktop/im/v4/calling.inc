; ================================================================
; calling.inc — 跨平台调用约定宏
;
; 使用方式：在 .asm 文件顶部 %include "calling.inc"
; 编译时通过 -d_WIN32 切换到 Windows 约定
; ================================================================

%ifdef _WIN32
    ; Microsoft x64 ABI
    %define A1 rcx
    %define A2 rdx
    %define A3 r8
    %define A4 r9
    %define A1d ecx
    %define A2d edx
    %define A3d r8d
    %define A4d r9d

    %macro PROLOGUE 0
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32            ; 32 bytes: PREP_CALL adds 32 more → total 64 = 16-aligned
    %endmacro

    %macro EPILOGUE 0
        lea     rsp, [rbp]
        pop     rbp
        ret
    %endmacro

    ; 调用 C 函数前准备（预留 shadow space）
    %macro PREP_CALL 0
        sub     rsp, 32
    %endmacro
    %macro POST_CALL 0
        add     rsp, 32
    %endmacro

%else
    ; System V AMD64 ABI (Linux)
    %define A1 rdi
    %define A2 rsi
    %define A3 rdx
    %define A4 rcx
    %define A1d edi
    %define A2d esi
    %define A3d edx
    %define A4d ecx

    %macro PROLOGUE 0
        push    rbp
        mov     rbp, rsp
    %endmacro

    %macro EPILOGUE 0
        lea     rsp, [rbp]
        pop     rbp
        ret
    %endmacro

    %macro PREP_CALL 0
    %endmacro
    %macro POST_CALL 0
    %endmacro

%endif
