; ================================================================
; crypto.asm — ChaCha20 流加密（RFC 8439）纯 NASM 实现
;
; 接口：
;   chacha20_block(out[64], key[32], nonce[12], counter:u32)
;       生成64字节密钥流块
;
;   chacha20_encrypt(out, in, len, key[32], nonce[8], ctr_hi:u32)
;       用 ChaCha20 加/解密 len 字节
;       nonce[8] 为 64-bit 计数器格式（前4字节=0，后8字节=nonce）
;       ctr_hi 通常为0
; ================================================================
BITS 64
default rel

%include "calling.inc"

section .note.GNU-stack noalloc noexec nowrite progbits

section .text

global chacha20_block
global chacha20_encrypt

; ---- QUARTERROUND 宏 ----
; 操作4个32-bit寄存器（都在 xmm 或通用寄存器上）
; 用通用寄存器版本（state 在栈上）
; QR a, b, c, d  （栈偏移）
%macro QR 4
    mov     eax, [rsp + %1*4]
    add     eax, [rsp + %2*4]
    mov     [rsp + %1*4], eax
    xor     dword [rsp + %4*4], eax
    rol     dword [rsp + %4*4], 16

    mov     eax, [rsp + %3*4]
    add     eax, [rsp + %4*4]
    mov     [rsp + %3*4], eax
    xor     dword [rsp + %2*4], eax
    rol     dword [rsp + %2*4], 12

    mov     eax, [rsp + %1*4]
    add     eax, [rsp + %2*4]
    mov     [rsp + %1*4], eax
    xor     dword [rsp + %4*4], eax
    rol     dword [rsp + %4*4], 8

    mov     eax, [rsp + %3*4]
    add     eax, [rsp + %4*4]
    mov     [rsp + %3*4], eax
    xor     dword [rsp + %2*4], eax
    rol     dword [rsp + %2*4], 7
%endmacro

; ================================================================
; chacha20_block(out[64], key[32], nonce[12], counter:u32)
; A1=out, A2=key, A3=nonce, A4=counter
; ================================================================
chacha20_block:
    PROLOGUE
    ; 栈上分配：state[16] (64字节) + init[16] (64字节) = 128字节
    sub     rsp, 128
%ifdef _WIN32
    ; 保存 Win64 callee-saved 寄存器（rsi, rdi 已在 PROLOGUE 处理）
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbx
    ; 保存参数（shadow 已在 PROLOGUE 分配的 32 字节里）
    mov     [rbp - 8],   A1     ; out
    mov     [rbp - 16],  A2     ; key
    mov     [rbp - 24],  A3     ; nonce
    mov     [rbp - 32],  A4d    ; counter
%else
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbx
    sub     rsp, 40             ; 对齐 + 保存参数
    mov     [rsp + 0],  A1      ; out
    mov     [rsp + 8],  A2      ; key
    mov     [rsp + 16], A3      ; nonce
    mov     [rsp + 24], A4d     ; counter (32-bit)
%endif

    ; 初始化状态：
    ; state[0..3]  = "expa" "nd 3" "2-by" "te k"
    ; state[4..11] = key[0..31]
    ; state[12]    = counter
    ; state[13..15]= nonce[0..11]

    ; state 存在 rsp+0..63 (当前 rsp 之上128字节中的前64)
    ; 注：rsp 已经减了 128 字节

%ifdef _WIN32
    lea     r12, [rbp - 8]      ; 从 rbp-8 取 out
    mov     r12, [r12]
    mov     r13, [rbp - 16]     ; key
    mov     r14, [rbp - 24]     ; nonce
    mov     r15d, [rbp - 32]    ; counter
%else
    mov     r12, [rsp + 40 + 0]   ; out (注：上面有5个 push = 40字节，rsp又减了40)
    mov     r13, [rsp + 40 + 8]   ; key
    mov     r14, [rsp + 40 + 16]  ; nonce
    mov     r15d, [rsp + 40 + 24] ; counter
%endif

    ; 常量
    mov     dword [rsp + 0],   0x61707865  ; "expa"
    mov     dword [rsp + 4],   0x3320646E  ; "nd 3"
    mov     dword [rsp + 8],   0x79622D32  ; "2-by"
    mov     dword [rsp + 12],  0x6B206574  ; "te k"

    ; key[0..31]
    mov     eax, [r13 + 0]
    mov     [rsp + 16], eax
    mov     eax, [r13 + 4]
    mov     [rsp + 20], eax
    mov     eax, [r13 + 8]
    mov     [rsp + 24], eax
    mov     eax, [r13 + 12]
    mov     [rsp + 28], eax
    mov     eax, [r13 + 16]
    mov     [rsp + 32], eax
    mov     eax, [r13 + 20]
    mov     [rsp + 36], eax
    mov     eax, [r13 + 24]
    mov     [rsp + 40], eax
    mov     eax, [r13 + 28]
    mov     [rsp + 44], eax

    ; counter
    mov     [rsp + 48], r15d

    ; nonce[0..11]
    mov     eax, [r14 + 0]
    mov     [rsp + 52], eax
    mov     eax, [r14 + 4]
    mov     [rsp + 56], eax
    mov     eax, [r14 + 8]
    mov     [rsp + 60], eax

    ; 保存初始状态副本（state 在 rsp+0，副本在 rsp+64）
    mov     ecx, 16
    lea     rsi, [rsp + 0]
    lea     rdi, [rsp + 64]
.copy_init:
    mov     eax, [rsi]
    mov     [rdi], eax
    add     rsi, 4
    add     rdi, 4
    dec     ecx
    jnz     .copy_init

    ; 20 轮（10 双轮）
    mov     ebx, 10
.double_round:
    ; 列轮
    QR 0, 4, 8,  12
    QR 1, 5, 9,  13
    QR 2, 6, 10, 14
    QR 3, 7, 11, 15
    ; 对角轮
    QR 0, 5, 10, 15
    QR 1, 6, 11, 12
    QR 2, 7,  8, 13
    QR 3, 4,  9, 14
    dec     ebx
    jnz     .double_round

    ; state += initial_state，然后写出
    mov     ecx, 16
    lea     rsi, [rsp + 64]     ; 初始状态
    lea     rdi, [rsp + 0]      ; 当前状态
.add_init:
    mov     eax, [rdi]
    add     eax, [rsi]
    mov     [rdi], eax
    add     rsi, 4
    add     rdi, 4
    dec     ecx
    jnz     .add_init

    ; 把 state 写到 out（小端序，x86 本身就是小端，直接复制）
    mov     ecx, 16
    lea     rsi, [rsp + 0]
    mov     rdi, r12            ; out
.write_out:
    mov     eax, [rsi]
    mov     [rdi], eax
    add     rsi, 4
    add     rdi, 4
    dec     ecx
    jnz     .write_out

%ifdef _WIN32
    pop     rbx
    pop     r15
    pop     r14
    pop     r13
    pop     r12
%else
    add     rsp, 40
    pop     rbx
    pop     r15
    pop     r14
    pop     r13
    pop     r12
%endif
    add     rsp, 128
    ; EPILOGUE
%ifdef _WIN32
    mov     rsp, rbp
    pop     rbp
%else
    pop     rbp
%endif
    ret

; ================================================================
; chacha20_encrypt(out, in, len, key[32], nonce[8], ctr_start:u64)
; A1=out, A2=in, A3=len(qword), A4=key, A5=nonce, A6=ctr_start
;
; 注意 A5/A6 在 Win64 下：
;   Win64: A5 = [rbp+48+8]（第5参数在栈上，shadow=32, ret=8, rbp=8）
;          A6 = [rbp+48+16]
;   Linux: A5 = r8, A6 = r9 → 但 calling.inc 只定义了 A1..A4
;          Linux: A1=rdi, A2=rsi, A3=rdx, A4=rcx, A5=r8, A6=r9
; ================================================================
chacha20_encrypt:
    push    rbp
    mov     rbp, rsp
%ifdef _WIN32
    push    rsi
    push    rdi
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 32 + 64 + 16   ; shadow + keystream 块 + 对齐
    ; 保存参数
    mov     [rbp - 64], rcx     ; out
    mov     [rbp - 72], rdx     ; in
    mov     [rbp - 80], r8      ; len
    mov     [rbp - 88], r9      ; key
    mov     rax, [rbp + 48]     ; nonce（Win64 第5参数，rbp+40+8=rbp+48）
    mov     [rbp - 96], rax
    mov     rax, [rbp + 56]     ; ctr
    mov     [rbp - 104], rax
%else
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 64 + 8         ; keystream + 对齐
    mov     [rbp - 48], rdi     ; out
    mov     [rbp - 56], rsi     ; in
    mov     [rbp - 64], rdx     ; len
    mov     [rbp - 72], rcx     ; key
    mov     [rbp - 80], r8      ; nonce
    mov     [rbp - 88], r9      ; ctr
%endif

    ; 构造 12 字节 nonce（RFC 8439 格式）：[0x00000000][nonce_lo32][nonce_hi32]
    ; 传入的 nonce 是 8 字节计数器，按如下布局：
    ;   chacha_nonce[0..3] = 0
    ;   chacha_nonce[4..11] = nonce[0..7]

    ; keystream 缓冲区在栈上（64字节）
%ifdef _WIN32
    lea     r12, [rbp - 64]     ; 指向 out slot
    mov     r12, [r12]
    mov     r13, [rbp - 72]     ; in
    mov     r14, [rbp - 80]     ; len
    mov     r15, [rbp - 88]     ; key
    mov     rbx, [rbp - 96]     ; nonce (8字节)
    ; ctr: [rbp - 104]
    ; keystream 放在 rbp - 64 - 64 = rbp - 128 处（不行，跟参数区重叠）
    ; 用 rsp 底部（已经 sub rsp, 32+64+16=112）
    ; keystream @ rsp + 32 (32字节shadow以上)
    lea     rbp, [rbp]          ; 重新用 r11 指向 ks
    lea     r11, [rsp + 32]     ; keystream
%else
    mov     r12, [rbp - 48]
    mov     r13, [rbp - 56]
    mov     r14, [rbp - 64]
    mov     r15, [rbp - 72]
    mov     rbx, [rbp - 80]
    ; ctr: [rbp - 88]
    lea     r11, [rsp]          ; keystream（rsp已减去64+8=72，keystream@rsp）
%endif

    xor     r9, r9              ; block_ctr（附加在 ctr_start 上的偏移）

.enc_loop:
    test    r14, r14
    jz      .enc_done

    ; 构造 nonce12（栈上临时，用 r10 指向）
%ifdef _WIN32
    lea     r10, [rsp + 32 + 64]   ; nonce12 临时区（16字节，在 keystream 后面）
%else
    lea     r10, [rsp + 64]         ; nonce12 临时区
%endif
    mov     dword [r10], 0
    mov     rax, rbx                ; nonce[0..7]
    mov     [r10 + 4], rax

    ; counter = ctr_start + r9
%ifdef _WIN32
    mov     rax, [rbp - 104]
%else
    mov     rax, [rbp - 88]
%endif
    add     rax, r9
    ; 只用低32位作为 chacha block counter（ctr_start 高32位进入 nonce 不在此处理）

    ; 调用 chacha20_block(keystream, key, nonce12, counter)
    PREP_CALL
    mov     A1, r11             ; keystream
    mov     A2, r15             ; key
    mov     A3, r10             ; nonce12
    mov     A4d, eax            ; counter
    call    chacha20_block
    POST_CALL

    ; XOR 最多64字节
    mov     rcx, r14
    cmp     rcx, 64
    jle     .partial
    mov     rcx, 64
.partial:
    xor     rdx, rdx            ; offset
.xor_loop:
    cmp     rdx, rcx
    jge     .xor_done
    movzx   eax, byte [r13 + rdx]   ; in[i]
    xor     al, [r11 + rdx]         ; ^ keystream[i]
    mov     [r12 + rdx], al         ; out[i]
    inc     rdx
    jmp     .xor_loop
.xor_done:
    add     r12, rcx
    add     r13, rcx
    sub     r14, rcx
    inc     r9
    jmp     .enc_loop

.enc_done:
%ifdef _WIN32
    add     rsp, 32 + 64 + 16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rdi
    pop     rsi
%else
    add     rsp, 64 + 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
%endif
    pop     rbp
    ret
