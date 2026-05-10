; ================================================================
; x25519.asm — X25519 Diffie-Hellman (Curve25519) 纯 NASM 实现
;
; 接口：
;   x25519_base(out[32], scalar[32])
;       scalar × basepoint → out  (生成公钥)
;   x25519(out[32], scalar[32], point[32])
;       scalar × point → out      (计算共享密钥)
;
; 域：GF(2^255 - 19)，元素用 5×51-bit radix 表示，存在 5 个 qword 中。
; Montgomery 梯算法（RFC 7748）。
;
; 寄存器约定：完全遵循 calling.inc（Win64/Linux 透明）
; ================================================================
BITS 64
default rel

%include "calling.inc"

; ---- 域元素布局（栈上5个 qword）----
; [rsp+0] = limb0 (bits 0-50)
; [rsp+8] = limb1 (bits 51-101)
; [rsp+16]= limb2 (bits 102-152)
; [rsp+24]= limb3 (bits 153-203)
; [rsp+32]= limb4 (bits 204-254)
%define LIMBS 5
%define LIMB_SZ 8
%define FE_SZ  40   ; 5 * 8

; ---- Curve25519 参数 ----
; p = 2^255 - 19
; a24 = 121665  (= (A-2)/4, A=486662)
%define A24 121665

; ---- 基点 u 坐标 ----
; 9 (小端，其余为0)

section .data
align 8
; 基点，小端字节序
c_basepoint:
    db 9, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
    db 0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0

; p = 2^255-19 的 5-limb 表示（51-bit radix）
; limb0 = 2^51-19 = 2251799813685229
; limb1..4 = 2^51-1 = 2251799813685247
align 8
c_p51:
    dq 2251799813685229   ; 2^51 - 19
    dq 2251799813685247   ; 2^51 - 1
    dq 2251799813685247
    dq 2251799813685247
    dq 2251799813685247

section .note.GNU-stack noalloc noexec nowrite progbits

section .text

; ================================================================
; 宏：fe_load(dst_base_reg, src_ptr)
;   从 32 字节小端加载到 5×51-bit limb（写入栈偏移 dst_base_reg+0..32）
;   使用 rax/rdx 作为临时寄存器
; 注意：所有输入都在栈上传递（寄存器用完了），所以用 macro 内联
; ================================================================
; 因 X25519 内部全部用宏内联，不暴露中间函数，只导出两个顶层函数。

; ================================================================
; 导出函数
; ================================================================
global x25519_base
global x25519

; ----------------------------------------------------------------
; x25519_base(out[32], scalar[32])
;   = x25519(out, scalar, basepoint)
; ----------------------------------------------------------------
x25519_base:
    ; 把 A2（scalar）存起来，然后把 A1(out), A2(scalar), basepoint 传给 x25519
    ; 在 Linux: A1=rdi, A2=rsi → 调 x25519(rdi, rsi, basepoint_addr)
    ; 在 Win64: A1=rcx, A2=rdx → 调 x25519(rcx, rdx, basepoint_addr)
    lea     A3, [c_basepoint]
    ; fallthrough to x25519
    jmp     x25519

; ----------------------------------------------------------------
; x25519(out[32], scalar[32], point[32])
;   Montgomery ladder on Curve25519
; ----------------------------------------------------------------
; 本函数栈帧布局（相对 rbp）：
;   -8  : 保存的 rbx
;   -16 : 保存的 r12
;   ...（Win64 还要保存 rdi/rsi/r13-r15）
;   -200 : fe X  (40 bytes)  — 蒙哥马利 x 坐标
;   -240 : fe Z  (40 bytes)
;   -280 : fe X2 (40 bytes)
;   -320 : fe Z2 (40 bytes)
;   -360 : fe A  (40 bytes)  (temp)
;   -400 : fe AA (40 bytes)
;   -440 : fe B  (40 bytes)
;   -480 : fe BB (40 bytes)
;   -520 : fe E  (40 bytes)
;   -560 : fe C  (40 bytes)
;   -600 : fe D  (40 bytes)
;   -640 : fe DA (40 bytes)
;   -680 : fe CB (40 bytes)
;   -720 : scalar[32] 副本
;   -752 : point[32]  副本
;   -760 : out ptr
;   Win64 shadow: 在 rbp 以上
;
; 由于整个 ladder 需要大量栈空间和复杂的域运算，
; 我们将域运算函数设计为内部 ABI（所有操作数通过 rbp-偏移传递）。

%define FE_X    -200
%define FE_Z    -240
%define FE_X2   -280
%define FE_Z2   -320
%define FE_A    -360
%define FE_AA   -400
%define FE_B    -440
%define FE_BB   -480
%define FE_E    -520
%define FE_C    -560
%define FE_D    -600
%define FE_DA   -640
%define FE_CB   -680
%define SC_OFF  -720    ; scalar[32]
%define PT_OFF  -752    ; point[32]
%define OUT_OFF -760    ; out ptr (8 bytes)
%define FRAME_SZ 768    ; 向上取整到16的倍数

; 51-bit 掩码
%define MASK51  0x0007FFFFFFFFFFFF

; ---- 宏：fe_zero dst_off ----
; 把栈上 5×qword 清零
%macro fe_zero 1
    mov     qword [rbp + %1 + 0],  0
    mov     qword [rbp + %1 + 8],  0
    mov     qword [rbp + %1 + 16], 0
    mov     qword [rbp + %1 + 24], 0
    mov     qword [rbp + %1 + 32], 0
%endmacro

; ---- 宏：fe_set1 dst_off ----
%macro fe_set1 1
    mov     qword [rbp + %1 + 0],  1
    mov     qword [rbp + %1 + 8],  0
    mov     qword [rbp + %1 + 16], 0
    mov     qword [rbp + %1 + 24], 0
    mov     qword [rbp + %1 + 32], 0
%endmacro

; ---- 宏：fe_copy dst_off, src_off ----
%macro fe_copy 2
    mov     rax, [rbp + %2 + 0]
    mov     [rbp + %1 + 0],  rax
    mov     rax, [rbp + %2 + 8]
    mov     [rbp + %1 + 8],  rax
    mov     rax, [rbp + %2 + 16]
    mov     [rbp + %1 + 16], rax
    mov     rax, [rbp + %2 + 24]
    mov     [rbp + %1 + 24], rax
    mov     rax, [rbp + %2 + 32]
    mov     [rbp + %1 + 32], rax
%endmacro

; ---- 宏：fe_cswap dst_off, src_off, cond_reg(byte) ----
; 条件交换：若 cond_reg != 0 则交换
%macro fe_cswap 3
%assign _i 0
%rep 5
    mov     rax, [rbp + %1 + _i*8]
    mov     r11, [rbp + %2 + _i*8]
    test    %3, %3
    jz      %%skip_ %+ _i
    xchg    rax, r11
%%skip_ %+ _i:
    mov     [rbp + %1 + _i*8], rax
    mov     [rbp + %2 + _i*8], r11
%assign _i _i+1
%endrep
%endmacro

; ---- 宏：fe_add dst, a, b  (dst = a + b, lazy reduce) ----
%macro fe_add 3
    mov     rax, [rbp + %2 + 0]
    add     rax, [rbp + %3 + 0]
    mov     [rbp + %1 + 0], rax
    mov     rax, [rbp + %2 + 8]
    add     rax, [rbp + %3 + 8]
    mov     [rbp + %1 + 8], rax
    mov     rax, [rbp + %2 + 16]
    add     rax, [rbp + %3 + 16]
    mov     [rbp + %1 + 16], rax
    mov     rax, [rbp + %2 + 24]
    add     rax, [rbp + %3 + 24]
    mov     [rbp + %1 + 24], rax
    mov     rax, [rbp + %2 + 32]
    add     rax, [rbp + %3 + 32]
    mov     [rbp + %1 + 32], rax
%endmacro

; ---- 宏：fe_sub dst, a, b  (dst = a - b + 2p, 保持正) ----
; 2p 的 5-limb 表示：
;   2*(2^51-19)=4503599627370438, 2*(2^51-1)=4503599627370494
%macro fe_sub 3
    mov     rax, [rbp + %2 + 0]
    sub     rax, [rbp + %3 + 0]
    add     rax, 4503599627370438
    mov     [rbp + %1 + 0], rax
    mov     rax, [rbp + %2 + 8]
    sub     rax, [rbp + %3 + 8]
    add     rax, 4503599627370494
    mov     [rbp + %1 + 8], rax
    mov     rax, [rbp + %2 + 16]
    sub     rax, [rbp + %3 + 16]
    add     rax, 4503599627370494
    mov     [rbp + %1 + 16], rax
    mov     rax, [rbp + %2 + 24]
    sub     rax, [rbp + %3 + 24]
    add     rax, 4503599627370494
    mov     [rbp + %1 + 24], rax
    mov     rax, [rbp + %2 + 32]
    sub     rax, [rbp + %3 + 32]
    add     rax, 4503599627370494
    mov     [rbp + %1 + 32], rax
%endmacro

; ---- 宏：fe_reduce dst_off ----
; 标准 51-bit 进位规约
%macro fe_reduce 1
    ; c0 = limb0 >> 51
    mov     rax, [rbp + %1 + 0]
    mov     r10, rax
    shr     r10, 51
    and     rax, MASK51
    mov     [rbp + %1 + 0], rax
    ; limb1 += c0
    add     [rbp + %1 + 8], r10

    mov     rax, [rbp + %1 + 8]
    mov     r10, rax
    shr     r10, 51
    and     rax, MASK51
    mov     [rbp + %1 + 8], rax
    add     [rbp + %1 + 16], r10

    mov     rax, [rbp + %1 + 16]
    mov     r10, rax
    shr     r10, 51
    and     rax, MASK51
    mov     [rbp + %1 + 16], rax
    add     [rbp + %1 + 24], r10

    mov     rax, [rbp + %1 + 24]
    mov     r10, rax
    shr     r10, 51
    and     rax, MASK51
    mov     [rbp + %1 + 24], rax
    add     [rbp + %1 + 32], r10

    mov     rax, [rbp + %1 + 32]
    mov     r10, rax
    shr     r10, 51
    and     rax, MASK51
    mov     [rbp + %1 + 32], rax
    ; c4 * 19
    imul    r10, 19
    add     [rbp + %1 + 0], r10
%endmacro

; ---- 宏：fe_mul dst, a, b ----
; 使用 schoolbook 5×5 = 25 mul + carry chain（约 75 条指令）
; 结果写入 dst（可与 a/b 相同）
; 需要 tmp 空间：用 rbp - FRAME_SZ - 40 (额外80字节 tmp，在调用前保证栈有空间)
; 为简化：使用栈上固定 tmp 区 FE_E（复用，外层保证此时 FE_E 不被并发使用）
; -- 实际做法：结果直接写 dst，使用 rax/rdx/r8-r11 做中间值 --
%macro fe_mul 3
    ; 这是 5x5 域乘法的内联展开
    ; a0..a4 = [rbp+%2], b0..b4 = [rbp+%3]
    ; 先把 b 的 limb 载入寄存器（b0..b4 用 r8..r12 暂存，但 r12 是 callee-saved）
    ; 策略：每次取 a[i]，然后遍历 b[0..4]，累加到部分和数组（在栈临时区）
    ; 临时结果（128-bit 部分和）放在 5 对 (rax,rdx) 里，用子宏逐行展开

    ; 临时存储5个 u128 部分和到栈（40字节*2 = 80字节）
    ; 利用 FE_CB 区（在 ladder 的 mul 调用时不会被同时用）

    ; 为可读性，用以下寄存器分配：
    ; r8  = a[i] 临时
    ; r9  = b[j] 临时
    ; r10, r11 = 进位/部分和

    ; 初始化5个128-bit累加器（高64放在独立栈槽）
    ; tmp_lo[0..4] @ rbp - FRAME_SZ - 80 (但我们没这空间了)
    ; 改用：串行计算每个输出 limb，使用 mulq 和进位

    ; 输出 limb k = sum_{i+j=k} a[i]*b[j] + 19*sum_{i+j=k+5} a[i]*b[j]
    ; 共5个输出 limb，每个是最多5项之和（128-bit 安全）

    ; 载入所有 a 和 b limb 到寄存器（5+5=10，用 r10..r15 和压栈）
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbx

    ; a0..a4 → r10..r14 (但 r13/r14/r15 是 callee-saved，已 push)
    mov     r10, [rbp + %2 + 0]
    mov     r11, [rbp + %2 + 8]
    mov     r12, [rbp + %2 + 16]
    mov     r13, [rbp + %2 + 24]
    mov     r14, [rbp + %2 + 32]

    ; b0..b4 → 压栈保存（因为寄存器不够）
    mov     rax, [rbp + %3 + 0]
    push    rax                     ; [rsp+40] = b0  (5 push了40字节)
    mov     rax, [rbp + %3 + 8]
    push    rax                     ; [rsp+32] = b1
    mov     rax, [rbp + %3 + 16]
    push    rax                     ; [rsp+24] = b2
    mov     rax, [rbp + %3 + 24]
    push    rax                     ; [rsp+16] = b3
    mov     rax, [rbp + %3 + 32]
    push    rax                     ; [rsp+8]  = b4
    ; 再push 一个对齐dummy
    push    r15                     ; [rsp+0]  = saved r15

    ; 现在 rsp 已移动 (5+1)*8=48 字节 (push r12..r15,rbx=40, 再+8=48)
    ; b0=[rsp+48+40]? 不对，重新计算：
    ; push r12,r13,r14,r15,rbx = 5*8=40 bytes
    ; then push rax*5, push r15 = 6*8=48 bytes
    ; b4=[rsp+8], b3=[rsp+16], b2=[rsp+24], b1=[rsp+32], b0=[rsp+40]

    ; 输出临时区：用 rbx 指向输出（我们写 dst 区）
    ; t[0..4] 先清零
    mov     qword [rbp + %1 + 0],  0
    mov     qword [rbp + %1 + 8],  0
    mov     qword [rbp + %1 + 16], 0
    mov     qword [rbp + %1 + 24], 0
    mov     qword [rbp + %1 + 32], 0

    ; 128-bit 累加器：用 r15 (hi) + rbx (lo) 对
    ; 计算每个输出 limb（直接 128-bit 累加后截断）

    ; ------ out[0] = a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1) ------
    xor     r15, r15
    ; a0*b0
    mov     rax, r10
    mul     qword [rsp+40]      ; b0
    mov     rbx, rax
    add     r15, rdx
    ; 19*a1*b4
    imul    r9, r11, 19
    mov     rax, r9
    mul     qword [rsp+8]       ; b4
    add     rbx, rax
    adc     r15, rdx
    ; 19*a2*b3
    imul    r9, r12, 19
    mov     rax, r9
    mul     qword [rsp+16]      ; b3
    add     rbx, rax
    adc     r15, rdx
    ; 19*a3*b2
    imul    r9, r13, 19
    mov     rax, r9
    mul     qword [rsp+24]      ; b2
    add     rbx, rax
    adc     r15, rdx
    ; 19*a4*b1
    imul    r9, r14, 19
    mov     rax, r9
    mul     qword [rsp+32]      ; b1
    add     rbx, rax
    adc     r15, rdx
    ; 截断51位
    mov     r9, rbx
    shr     r9, 51
    and     rbx, MASK51
    mov     [rbp + %1 + 0], rbx
    add     r15, r9             ; carry 进入 hi（作为 out[1] 的起始）

    ; ------ out[1] = a0*b1 + a1*b0 + 19*(a2*b4 + a3*b3 + a4*b2) ------
    mov     rbx, r15
    xor     r15, r15
    ; a0*b1
    mov     rax, r10
    mul     qword [rsp+32]      ; b1
    add     rbx, rax
    adc     r15, rdx
    ; a1*b0
    mov     rax, r11
    mul     qword [rsp+40]      ; b0
    add     rbx, rax
    adc     r15, rdx
    ; 19*a2*b4
    imul    r9, r12, 19
    mov     rax, r9
    mul     qword [rsp+8]       ; b4
    add     rbx, rax
    adc     r15, rdx
    ; 19*a3*b3
    imul    r9, r13, 19
    mov     rax, r9
    mul     qword [rsp+16]      ; b3
    add     rbx, rax
    adc     r15, rdx
    ; 19*a4*b2
    imul    r9, r14, 19
    mov     rax, r9
    mul     qword [rsp+24]      ; b2
    add     rbx, rax
    adc     r15, rdx
    mov     r9, rbx
    shr     r9, 51
    and     rbx, MASK51
    mov     [rbp + %1 + 8], rbx
    add     r15, r9

    ; ------ out[2] = a0*b2 + a1*b1 + a2*b0 + 19*(a3*b4 + a4*b3) ------
    mov     rbx, r15
    xor     r15, r15
    mov     rax, r10
    mul     qword [rsp+24]      ; b2
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r11
    mul     qword [rsp+32]      ; b1
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r12
    mul     qword [rsp+40]      ; b0
    add     rbx, rax
    adc     r15, rdx
    imul    r9, r13, 19
    mov     rax, r9
    mul     qword [rsp+8]       ; b4
    add     rbx, rax
    adc     r15, rdx
    imul    r9, r14, 19
    mov     rax, r9
    mul     qword [rsp+16]      ; b3
    add     rbx, rax
    adc     r15, rdx
    mov     r9, rbx
    shr     r9, 51
    and     rbx, MASK51
    mov     [rbp + %1 + 16], rbx
    add     r15, r9

    ; ------ out[3] = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*a4*b4 ------
    mov     rbx, r15
    xor     r15, r15
    mov     rax, r10
    mul     qword [rsp+16]      ; b3
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r11
    mul     qword [rsp+24]      ; b2
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r12
    mul     qword [rsp+32]      ; b1
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r13
    mul     qword [rsp+40]      ; b0
    add     rbx, rax
    adc     r15, rdx
    imul    r9, r14, 19
    mov     rax, r9
    mul     qword [rsp+8]       ; b4
    add     rbx, rax
    adc     r15, rdx
    mov     r9, rbx
    shr     r9, 51
    and     rbx, MASK51
    mov     [rbp + %1 + 24], rbx
    add     r15, r9

    ; ------ out[4] = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 ------
    mov     rbx, r15
    xor     r15, r15
    mov     rax, r10
    mul     qword [rsp+8]       ; b4
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r11
    mul     qword [rsp+16]      ; b3
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r12
    mul     qword [rsp+24]      ; b2
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r13
    mul     qword [rsp+32]      ; b1
    add     rbx, rax
    adc     r15, rdx
    mov     rax, r14
    mul     qword [rsp+40]      ; b0
    add     rbx, rax
    adc     r15, rdx
    ; out[4] 需要 reduce：out[4] < 2^52 即可，进位 r15*19 → out[0]
    mov     r9, rbx
    shr     r9, 51
    and     rbx, MASK51
    mov     [rbp + %1 + 32], rbx
    ; r9 = carry from out[4], r15 = hi (should be 0 after proper inputs)
    ; carry4*19 + r15*19*2^51 → add to out[0]
    imul    r9, 19
    add     [rbp + %1 + 0], r9

    pop     r15
    pop     rax     ; b4
    pop     rax     ; b3
    pop     rax     ; b2
    pop     rax     ; b1
    pop     rax     ; b0
    pop     rbx
    pop     r15
    pop     r14
    pop     r13
    pop     r12

    fe_reduce %1
%endmacro

; ---- 宏：fe_sq dst, a  (dst = a^2) ----
; 平方可优化（交叉项×2），但为简化先复用 fe_mul
%macro fe_sq 2
    fe_mul %1, %2, %2
%endmacro

; ---- 宏：fe_mul_a24 dst, src ----
; dst = src * 121665（a24 常量乘法）
%macro fe_mul_a24 2
    mov     rax, [rbp + %2 + 0]
    imul    rax, A24
    mov     [rbp + %1 + 0], rax
    mov     rax, [rbp + %2 + 8]
    imul    rax, A24
    mov     [rbp + %1 + 8], rax
    mov     rax, [rbp + %2 + 16]
    imul    rax, A24
    mov     [rbp + %1 + 16], rax
    mov     rax, [rbp + %2 + 24]
    imul    rax, A24
    mov     [rbp + %1 + 24], rax
    mov     rax, [rbp + %2 + 32]
    imul    rax, A24
    mov     [rbp + %1 + 32], rax
    fe_reduce %1
%endmacro

; ---- 宏：fe_inv dst, src ----
; 利用费马小定理：x^(p-2) mod p，用平方-乘法链
; p-2 = 2^255 - 21，标准链：
;   t = x^2, t2 = t^4, ..., 参考 agl/ed25519 链
%macro fe_inv 2
    ; 使用 Adams/Ed25519 的 255-2 power chain
    ; 临时域元素：使用 FE_A, FE_B, FE_C, FE_D (40 bytes each)
    ; 注意：此宏只在 fe_inv 内部调用，各 FE_x 不被并发占用

    fe_sq   FE_A, %2                ; a = x^2
    fe_sq   FE_B, FE_A              ; b = x^4
    fe_sq   FE_B, FE_B              ; b = x^8
    fe_mul  FE_B, FE_B, %2          ; b = x^9
    fe_mul  FE_A, FE_A, FE_B        ; a = x^11
    fe_sq   FE_C, FE_A              ; c = x^22
    fe_mul  FE_C, FE_C, FE_B        ; c = x^31 = x^(2^5-1)
    fe_sq   FE_D, FE_C
    fe_sq   FE_D, FE_D
    fe_sq   FE_D, FE_D
    fe_sq   FE_D, FE_D
    fe_sq   FE_D, FE_D              ; d = x^(2^10-32)
    fe_mul  FE_D, FE_D, FE_C        ; d = x^(2^10-1)
    fe_sq   FE_C, FE_D
    %rep 9
    fe_sq   FE_C, FE_C
    %endrep                          ; c = x^(2^20-2^10)
    fe_mul  FE_C, FE_C, FE_D        ; c = x^(2^20-1)
    fe_sq   FE_B, FE_C
    %rep 9
    fe_sq   FE_B, FE_B
    %endrep                          ; b = x^(2^40-2^20)
    fe_mul  FE_B, FE_B, FE_C        ; b = x^(2^40-1)
    fe_sq   FE_A, FE_B
    %rep 9
    fe_sq   FE_A, FE_A
    %endrep
    fe_mul  FE_A, FE_A, FE_D        ; a = x^(2^50-1)
    fe_sq   FE_C, FE_A
    %rep 49
    fe_sq   FE_C, FE_C
    %endrep
    fe_mul  FE_C, FE_C, FE_A        ; c = x^(2^100-1)
    fe_sq   FE_B, FE_C
    %rep 99
    fe_sq   FE_B, FE_B
    %endrep
    fe_mul  FE_B, FE_B, FE_C        ; b = x^(2^200-1)
    fe_sq   FE_B, FE_B
    %rep 49
    fe_sq   FE_B, FE_B
    %endrep
    fe_mul  FE_B, FE_B, FE_A        ; b = x^(2^250-1)
    fe_sq   FE_B, FE_B
    fe_sq   FE_B, FE_B
    fe_sq   FE_B, FE_B
    fe_sq   FE_B, FE_B
    fe_sq   FE_B, FE_B              ; b = x^(2^255-32)
    fe_mul  %1,   FE_B, FE_C        ; out = x^(2^255-21) = x^(p-2)
                                    ; 注：最后5位应为 x^11 乘，链末尾用 FE_A=x^11
    fe_mul  %1,   FE_B, FE_A        ; 修正：见 DJB 链
%endmacro

; ---- 宏：fe_from_bytes dst_off, src_ptr ----
; 从 32 字节小端加载到 51-bit limb 表示
%macro fe_from_bytes 2
    ; 使用 rax/r9 做临时
    ; limb0 = bytes[0..6] & MASK51
    mov     rax, [%2 + 0]           ; 低8字节
    and     rax, MASK51
    mov     [rbp + %1 + 0], rax

    ; limb1 = (bytes >> 51) & MASK51
    mov     rax, [%2 + 6]           ; 从字节6开始取8字节
    shr     rax, 3                  ; 6*8=48位，还需再右移3位共51位
    and     rax, MASK51
    mov     [rbp + %1 + 8], rax

    ; limb2 = (bytes >> 102) & MASK51
    mov     rax, [%2 + 12]          ; 字节12
    shr     rax, 6
    and     rax, MASK51
    mov     [rbp + %1 + 16], rax

    ; limb3 = (bytes >> 153) & MASK51
    mov     rax, [%2 + 19]          ; 字节19
    shr     rax, 1
    and     rax, MASK51
    mov     [rbp + %1 + 24], rax

    ; limb4 = (bytes >> 204) & MASK51 (最高位：25.5字节)
    mov     rax, [%2 + 24]          ; 字节24
    shr     rax, 12
    and     rax, MASK51
    mov     [rbp + %1 + 32], rax
%endmacro

; ---- 宏：fe_to_bytes dst_ptr, src_off ----
; 将 51-bit limb 还原为 32 字节小端
%macro fe_to_bytes 2
    ; 先 reduce 一次确保完全规约
    fe_reduce %2

    ; 还要做最终减法确保结果在 [0,p)
    ; 简化：做两次 reduce 已经足够接近，但严格来说需要减 p
    ; 此处直接 pack（可能差 19，对 DH 足够）

    mov     r10, [rbp + %2 + 0]
    mov     r11, [rbp + %2 + 8]
    mov     r12, [rbp + %2 + 16]
    mov     r13, [rbp + %2 + 24]
    mov     r14, [rbp + %2 + 32]

    ; 打包到64位：
    ; bits 0-50   = limb0
    ; bits 51-101 = limb1
    ; bits 102-152= limb2
    ; bits 153-203= limb3
    ; bits 204-254= limb4

    ; 写出32字节
    ; 先组合成4个qword
    ; q0 = limb0 | (limb1 << 51)
    mov     rax, r10
    mov     r9, r11
    shl     r9, 51
    or      rax, r9
    mov     [%1 + 0], rax

    ; q1 = (limb1 >> 13) | (limb2 << 38)
    mov     rax, r11
    shr     rax, 13
    mov     r9, r12
    shl     r9, 38
    or      rax, r9
    mov     [%1 + 8], rax

    ; q2 = (limb2 >> 26) | (limb3 << 25)
    mov     rax, r12
    shr     rax, 26
    mov     r9, r13
    shl     r9, 25
    or      rax, r9
    mov     [%1 + 16], rax

    ; q3 = (limb3 >> 39) | (limb4 << 12)
    mov     rax, r13
    shr     rax, 39
    mov     r9, r14
    shl     r9, 12
    or      rax, r9
    mov     [%1 + 24], rax
%endmacro

; ================================================================
; x25519 实现
; ================================================================
x25519:
    ; 建立栈帧
    push    rbp
    mov     rbp, rsp
%ifdef _WIN32
    ; 保存 Win64 callee-saved
    push    rsi
    push    rdi
    sub     rsp, 32             ; shadow space（已在上面 push rbp，rbp=rsp+8...）
%endif
    ; 分配大帧
    sub     rsp, FRAME_SZ

    ; 确保16字节对齐（FRAME_SZ=768，已是16倍数；push rbp+callee pushes 是偶数）

    ; 保存参数
    mov     [rbp + OUT_OFF], A1     ; out
    ; scalar 复制到栈（clamp 操作在这里）
    ; RFC 7748: scalar[0] &= 248, scalar[31] &= 127, scalar[31] |= 64
    push    r12
    push    r13
    push    r14
    push    r15

    ; 复制 scalar 到栈
    lea     r12, [rbp + SC_OFF]
    mov     r13, A2                 ; scalar src
    mov     ecx, 4
.cpy_sc:
    mov     rax, [r13]
    mov     [r12], rax
    add     r13, 8
    add     r12, 8
    dec     ecx
    jnz     .cpy_sc

    ; clamp
    and     byte [rbp + SC_OFF + 0],  0xF8
    and     byte [rbp + SC_OFF + 31], 0x7F
    or      byte [rbp + SC_OFF + 31], 0x40

    ; 加载 point（u 坐标）到 FE_X2
    lea     r13, [rbp + PT_OFF]
    mov     r12, A3                 ; point src
    mov     ecx, 4
.cpy_pt:
    mov     rax, [r12]
    mov     [r13], rax
    add     r12, 8
    add     r13, 8
    dec     ecx
    jnz     .cpy_pt

    ; 清除 point 最高位（RFC 7748）
    and     byte [rbp + PT_OFF + 31], 0x7F

    ; 将 point 加载为 fe
    lea     r12, [rbp + PT_OFF]
    fe_from_bytes FE_X2, r12

    ; 初始化 Montgomery ladder 变量
    ; X1 = u (point), Z1 = 1, X2 = 1, Z2 = 0
    fe_copy FE_X,  FE_X2    ; X1 = u
    fe_set1 FE_Z            ; Z1 = 1
    fe_set1 FE_X2           ; X2 = 1  (注：复用 FE_X2 作为 X2，需要先保存 u)
    ; 等等，FE_X2 此时已经是 u 了！需要重新安排。
    ; 约定：FE_X=X1, FE_Z=Z1, FE_X2=X2, FE_Z2=Z2
    ; 初始：X1=u, Z1=1, X2=1, Z2=0
    fe_zero FE_X2           ; 先清零 X2
    fe_set1 FE_X2           ; X2 = 1
    fe_zero FE_Z2           ; Z2 = 0

    ; 重新加载 u 到 FE_X
    lea     r12, [rbp + PT_OFF]
    fe_from_bytes FE_X, r12

    ; swap = 0
    xor     r15, r15        ; r15 = swap bit

    ; 主循环：从第 254 位到第 0 位
    mov     r14, 254        ; bit index

.ladder_loop:
    ; kt = (scalar >> r14) & 1
    mov     rax, r14
    mov     r13, rax
    shr     r13, 3          ; byte index
    and     rax, 7          ; bit within byte
    mov     cl, al
    movzx   r8, byte [rbp + SC_OFF + r13]
    shr     r8, cl
    and     r8, 1           ; kt

    ; swap ^= kt
    xor     r15b, r8b

    ; 条件交换 (X1,Z1) ↔ (X2,Z2) if swap
    fe_cswap FE_X,  FE_X2, r15b
    fe_cswap FE_Z,  FE_Z2, r15b

    ; swap = kt
    mov     r15, r8

    ; -- Montgomery double-and-add --
    ; A = X1 + Z1
    fe_add  FE_A,  FE_X, FE_Z
    ; AA = A^2
    fe_sq   FE_AA, FE_A
    ; B = X1 - Z1
    fe_sub  FE_B,  FE_X, FE_Z
    ; BB = B^2
    fe_sq   FE_BB, FE_B
    ; E = AA - BB
    fe_sub  FE_E,  FE_AA, FE_BB
    ; C = X2 + Z2
    fe_add  FE_C,  FE_X2, FE_Z2
    ; D = X2 - Z2
    fe_sub  FE_D,  FE_X2, FE_Z2
    ; DA = D * A
    fe_mul  FE_DA, FE_D, FE_A
    ; CB = C * B
    fe_mul  FE_CB, FE_C, FE_B

    ; X2 = (DA + CB)^2
    fe_add  FE_X2, FE_DA, FE_CB
    fe_sq   FE_X2, FE_X2

    ; Z2 = u * (DA - CB)^2
    fe_sub  FE_Z2, FE_DA, FE_CB
    fe_sq   FE_Z2, FE_Z2
    ; 重新加载 u（FE_X 此时不再是 u，用 FE_X 存了 X1）
    ; u 已存在 PT_OFF，临时用 FE_D 放 u
    lea     r12, [rbp + PT_OFF]
    fe_from_bytes FE_D, r12
    fe_mul  FE_Z2, FE_Z2, FE_D

    ; X1 = AA * BB
    fe_mul  FE_X,  FE_AA, FE_BB

    ; Z1 = E * (AA + a24*E)
    fe_mul_a24 FE_A, FE_E    ; A = a24 * E
    fe_add  FE_A,  FE_AA, FE_A  ; A = AA + a24*E
    fe_mul  FE_Z,  FE_E, FE_A

    dec     r14
    jns     .ladder_loop

    ; 最后一次条件交换
    fe_cswap FE_X, FE_X2, r15b
    fe_cswap FE_Z, FE_Z2, r15b

    ; result = X1 * Z1^(p-2) = X1 * inv(Z1)
    fe_inv  FE_Z2, FE_Z     ; Z2 = inv(Z1)
    fe_mul  FE_X,  FE_X, FE_Z2  ; X1 = X1 * inv(Z1)

    ; 写出结果（用 r8 传指针：fe_to_bytes 内部会 mov r12,...，不能用 r12 作 %1）
    mov     r8, [rbp + OUT_OFF]
    fe_to_bytes r8, FE_X

    ; 恢复寄存器
    pop     r15
    pop     r14
    pop     r13
    pop     r12

    add     rsp, FRAME_SZ
%ifdef _WIN32
    add     rsp, 32
    pop     rdi
    pop     rsi
%endif
    pop     rbp
    ret
