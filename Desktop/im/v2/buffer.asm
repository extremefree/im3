; ================================================================
; buffer.asm — 每客户端接收缓冲区 + 按行提取
;
; 解决 TCP 粘包/拆包问题：
;   数据追加到缓冲区尾部，按 \n 提取完整行
;
; client_state 布局：
;   offset 0:   fd       (dword, -1 = 空)
;   offset 4:   buf_len  (dword)
;   offset 8:   buf[BUF_SIZE]  (bytes)
;
; 使用方式：见 calling.inc
; ================================================================
BITS 64
default rel

%include "calling.inc"

%define BUF_SIZE      2048
%define CS_FD         0
%define CS_BUF_LEN    4
%define CS_BUF        8
%define CS_SIZE       (8 + BUF_SIZE)

; ================================================================
section .text
; ================================================================

; ================================================================
; buf_append(state_ptr, data_ptr, data_len) -> rax
;   返回 0=成功, -1=溢出
;
; 把 data 追加到 state 的 buf 尾部。如果放不下则返回 -1
; ================================================================
global buf_append
buf_append:
    PROLOGUE

    mov     r10, A3             ; save data_len FIRST (A3=r8 on Win64, save before clobbering r8)
    mov     r8, A1              ; r8 = state_ptr
    mov     r9, A2              ; r9 = data_ptr
    movsxd  r10, r10d

    ; 当前 buf_len
    mov     eax, [r8 + CS_BUF_LEN]
    movsxd  r11, eax            ; r11 = buf_len

    ; 检查溢出: buf_len + data_len > BUF_SIZE
    lea     rax, [r11 + r10]
    cmp     rax, BUF_SIZE
    jg      .overflow

    ; memcpy(data_ptr → buf + buf_len, data_len)
    lea     rdi, [r8 + CS_BUF + r11]   ; dst
    mov     rsi, r9                      ; src
    mov     rcx, r10                     ; count
    rep     movsb

    ; 更新 buf_len
    mov     [r8 + CS_BUF_LEN], eax      ; eax = new buf_len

    xor     eax, eax                    ; return 0
    EPILOGUE

.overflow:
    mov     eax, -1
    EPILOGUE


; ================================================================
; buf_extract_line(state_ptr, out_ptr, out_max) -> rax
;   返回行长度(不含 \n)，或 0 表示没有完整行
;
; 在 state 的 buf 中找第一个 \n，把 \n 之前的内容复制到 out
; 然后把剩余数据前移（消除已提取的行 + \n）
; ================================================================
global buf_extract_line
buf_extract_line:
    PROLOGUE
    push    r12
    push    r13
    push    r14

    mov     r12, A1             ; r12 = state_ptr
    mov     r13, A2             ; r13 = out_ptr
    mov     r14, A3             ; r14 = out_max
    movsxd  r14, r14d          ; sign-extend 32→64

    ; buf_len
    mov     eax, [r12 + CS_BUF_LEN]
    movsxd  rsi, eax            ; rsi = buf_len
    test    rsi, rsi
    jz      .no_line

    ; 扫描 buf 找 \n
    lea     rdi, [r12 + CS_BUF] ; rdi = buf start
    mov     rcx, rsi            ; max scan count
    mov     al, 10              ; '\n'
    repne   scasb
    jne     .no_line

    ; 找到了！scasb 停在 \n 的下一个字节
    ; 行长度 = (rdi - 1) - buf_start = rdi - buf_start - 1
    lea     rax, [rdi - 1]
    sub     rax, r12
    sub     rax, CS_BUF         ; rax = line_len (不含 \n)

    ; 检查 out 缓冲区大小
    cmp     rax, r14
    jg      .line_too_long      ; 超长截断

    mov     rdx, rax            ; rdx = line_len

    ; 复制行到 out（不含 \n）
    lea     rsi, [r12 + CS_BUF]
    mov     rdi, r13            ; dst = out
    mov     rcx, rdx
    rep     movsb

    ; 计算剩余长度 = buf_len - line_len - 1(\n)
    mov     eax, [r12 + CS_BUF_LEN]
    movsxd  r8, eax
    lea     r9, [r8 - 1]        ; r9 = buf_len - 1
    sub     r9, rdx             ; r9 = remain (去掉 line+\n)

    ; 前移剩余数据: memmove(buf, buf+line_len+1, remain)
    lea     rsi, [r12 + CS_BUF + rdx + 1]  ; src = buf + line_len + 1
    lea     rdi, [r12 + CS_BUF]             ; dst = buf
    mov     rcx, r9
    test    rcx, rcx
    jle     .shift_done
    rep     movsb

.shift_done:
    ; 更新 buf_len = remain
    mov     [r12 + CS_BUF_LEN], r9d

    ; 返回 line_len
    mov     rax, rdx
    pop     r14
    pop     r13
    pop     r12
    EPILOGUE

.no_line:
    xor     eax, eax
    pop     r14
    pop     r13
    pop     r12
    EPILOGUE

.line_too_long:
    ; 行太长，当作无完整行处理（让调用者跳过）
    ; 但要消耗掉到 \n 为止的数据，防止无限循环
    ; 先复制截断的行
    mov     rdx, r14            ; 截断到 out_max
    dec     rdx                 ; 留一个字节给 null
    lea     rsi, [r12 + CS_BUF]
    mov     rdi, r13
    mov     rcx, rdx
    rep     movsb

    ; 前移: 跳过整行(到\n) + \n本身
    mov     eax, [r12 + CS_BUF_LEN]
    movsxd  r8, eax
    lea     r9, [r8 - 1]
    sub     r9, rdx             ; remain
    lea     rsi, [r12 + CS_BUF + rdx + 1]
    lea     rdi, [r12 + CS_BUF]
    mov     rcx, r9
    test    rcx, rcx
    jle     .shift_done2
    rep     movsb
.shift_done2:
    mov     [r12 + CS_BUF_LEN], r9d
    mov     rax, rdx
    pop     r14
    pop     r13
    pop     r12
    EPILOGUE

section .note.GNU-stack noalloc noexec nowrite progbits
