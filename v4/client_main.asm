; ================================================================
; client_main.asm — v4 客户端（二进制帧 + ChaCha20 + X25519 握手）
;
; 命令格式（交互模式）：
;   LOGIN user:pass
;   REGISTER user:pass
;   mail -o <to> -m "<text>"    → PKT_MAIL
;   <其他文本>                  → PKT_MSG
;
; 连接后自动发送 PKT_HELLO（携带客户端公钥）
; ================================================================
BITS 64
default rel

%include "calling.inc"
%include "proto.inc"

%define SOCKADDR6_LEN   28
%define PLAT_FD_SIZE    520
%define LINE_BUF_SIZE   2048
%define KEYGEN_KEY_SIZE 32

extern plat_init
extern plat_cleanup
extern plat_socket6
extern plat_connect
extern plat_close
extern plat_read
extern plat_write
extern plat_print
extern plat_select
extern plat_fd_zero
extern plat_fd_set
extern plat_fd_isset
extern plat_resolve6
extern plat_random
extern plat_client_add_stdin
extern plat_stdin_ready
extern plat_read_stdin

extern util_strlen
extern util_strncmp

extern x25519_base
extern x25519
extern chacha20_encrypt

section .note.GNU-stack noalloc noexec nowrite progbits

; ================================================================
section .data
; ================================================================
str_usage       db "Usage: client <host> [port]", 10, 0
str_connecting  db "[client] connecting...", 10
str_connecting_len equ $ - str_connecting
str_connected   db "[client] connected. Performing handshake...", 10
str_connected_len equ $ - str_connected
str_ready       db "[client] handshake done. You can now LOGIN.", 10
str_ready_len   equ $ - str_ready
str_prompt      db "> ", 0

str_mail_cmd    db "mail", 0    ; "mail" 关键字
str_opt_o       db "-o", 0
str_opt_m       db "-m", 0

; ================================================================
section .bss
; ================================================================
align 8
g_sock          resd 1
g_fds           resb PLAT_FD_SIZE

; 本端 X25519 密钥对
g_my_priv       resb PUBKEY_LEN
g_my_pub        resb PUBKEY_LEN
g_shared        resb SHARED_LEN

; 加密计数器
g_tx_nonce      resq 1
g_rx_nonce      resq 1

; 握手完成标志
g_handshaked    resd 1

; 接收缓冲
g_recv_buf      resb (FRAME_HDR + NONCE_LEN + MAX_PAYLOAD + 64)

; 发送缓冲（line_buf → frame）
g_line_buf      resb LINE_BUF_SIZE
g_frame_buf     resb (FRAME_HDR + NONCE_LEN + MAX_PAYLOAD + 64)

; ================================================================
section .text
; ================================================================
global main

main:
    PROLOGUE
    push    r12
    push    r13
    push    r14
    push    r15

    ; 获取命令行参数（argc, argv）
    ; Linux: main(argc=A1, argv=A2)
    ; Win64: main(argc=A1, argv=A2)
    mov     r12d, A1d    ; argc
    mov     r13,  A2     ; argv

    cmp     r12d, 2
    jl      .usage

    ; plat_init()
    PREP_CALL
    call    plat_init
    POST_CALL
    test    eax, eax
    jnz     .exit_fail

    ; 生成客户端 X25519 密钥对
    PREP_CALL
    lea     A1, [g_my_priv]
    mov     A2d, PUBKEY_LEN
    call    plat_random
    POST_CALL

    and     byte [g_my_priv + 0],  0xF8
    and     byte [g_my_priv + 31], 0x7F
    or      byte [g_my_priv + 31], 0x40

    PREP_CALL
    lea     A1, [g_my_pub]
    lea     A2, [g_my_priv]
    call    x25519_base
    POST_CALL

    ; 初始化计数器和标志
    mov     qword [g_tx_nonce], 0
    mov     qword [g_rx_nonce], 0
    mov     dword [g_handshaked], 0

    ; 创建 socket
    PREP_CALL
    call    plat_socket6
    POST_CALL
    test    eax, eax
    js      .exit_fail
    mov     [g_sock], eax

    ; 解析 host（argv[1]）
    mov     rsi, [r13 + 8]      ; argv[1]

    ; 端口：argv[2] 或默认 9000
    mov     r15d, 9000
    cmp     r12d, 3
    jl      .use_default_port
    ; atoi(argv[2])
    mov     rdi, [r13 + 16]
    xor     r15d, r15d
.atoi:
    movzx   eax, byte [rdi]
    test    al, al
    jz      .atoi_done
    sub     al, '0'
    imul    r15d, r15d, 10
    add     r15d, eax
    inc     rdi
    jmp     .atoi
.atoi_done:
.use_default_port:

    ; resolve host
    lea     rdi, [g_recv_buf]   ; 临时 sockaddr 缓冲
    PREP_CALL
    mov     A1, rsi             ; host string
    mov     A2d, r15d           ; port
    lea     A3, [g_recv_buf]
    call    plat_resolve6
    POST_CALL
    test    eax, eax
    jnz     .exit_fail

    ; connect
    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_recv_buf]
    mov     A3d, SOCKADDR6_LEN
    call    plat_connect
    POST_CALL
    test    eax, eax
    jnz     .exit_fail

    PREP_CALL
    lea     A1, [str_connecting]
    mov     A2d, str_connecting_len
    call    plat_print
    POST_CALL

    ; 发送 PKT_HELLO（携带我方公钥）
    mov     byte [g_frame_buf + F_TYPE],  PKT_HELLO
    mov     byte [g_frame_buf + F_FLAGS], 0
    mov     word [g_frame_buf + F_LEN],   PUBKEY_LEN
    lea     rsi, [g_my_pub]
    lea     rdi, [g_frame_buf + FRAME_HDR]
    mov     ecx, PUBKEY_LEN / 8
    rep     movsq

    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_frame_buf]
    mov     A3d, FRAME_HDR + PUBKEY_LEN
    call    plat_write
    POST_CALL

    ; ---- 主循环 ----
.main_loop:
    ; 构建 fd_set
    PREP_CALL
    lea     A1, [g_fds]
    call    plat_fd_zero
    POST_CALL

    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_fds]
    call    plat_fd_set
    POST_CALL

    PREP_CALL
    lea     A1, [g_fds]
    call    plat_client_add_stdin
    POST_CALL

    PREP_CALL
    mov     A1d, 1024
    lea     A2,  [g_fds]
    call    plat_select
    POST_CALL
    test    eax, eax
    jle     .main_loop

    ; stdin 就绪？
    PREP_CALL
    lea     A1, [g_fds]
    call    plat_stdin_ready
    POST_CALL
    test    eax, eax
    jz      .check_server

    ; 读一行输入
    PREP_CALL
    lea     A1, [g_line_buf]
    mov     A2d, LINE_BUF_SIZE - 1
    call    plat_read_stdin
    POST_CALL
    test    eax, eax
    jle     .exit_ok
    mov     r14d, eax          ; 输入长度

    ; 去掉末尾 \n
    cmp     byte [g_line_buf + r14 - 1], 10
    jne     .no_strip
    dec     r14d
    mov     byte [g_line_buf + r14], 0
.no_strip:

    test    r14d, r14d
    jz      .main_loop

    ; 判断命令类型
    ; 是否以 "mail" 开头？
    lea     rsi, [g_line_buf]
    lea     rdi, [str_mail_cmd]
    PREP_CALL
    mov     A1, rsi
    mov     A2, rdi
    mov     A3d, 4
    call    util_strncmp
    POST_CALL
    test    eax, eax
    jnz     .not_mail

    ; 解析 mail -o <to> -m "<text>"
    ; 简单解析：找 "-o" 后的词，找 "-m" 后的词
    lea     r8, [g_line_buf + 5]    ; 跳过 "mail "
    ; 找 -o
    call    .parse_mail_opt_o       ; 返回 r9=to_ptr, r10=to_len
    test    r9, r9
    jz      .not_mail

    ; 找 -m
    call    .parse_mail_opt_m       ; 返回 r11=text_ptr, ecx=text_len
    test    r11, r11
    jz      .not_mail

    ; 构造 PKT_MAIL payload = "to\0text"
    lea     rdi, [g_frame_buf + FRAME_HDR + NONCE_LEN]
    ; 复制 to
    mov     rsi, r9
    mov     ecx, r10d
    rep     movsb
    mov     byte [rdi], 0
    inc     rdi
    ; 复制 text
    mov     rsi, r11
    ; ecx 已是 text_len（从 parse_mail_opt_m 返回）
    push    rcx
    pop     rcx
    rep     movsb
    ; payload_len = to_len + 1 + text_len
    lea     rax, [rdi - (g_frame_buf + FRAME_HDR + NONCE_LEN)]

    mov     r15d, PKT_MAIL
    jmp     .send_encrypted

.not_mail:
    ; 检查是否 LOGIN/REGISTER（发明文帧，还未加密）
    lea     rsi, [g_line_buf]
    PREP_CALL
    mov     A1, rsi
    lea     A2, [.str_login]
    mov     A3d, 5
    call    util_strncmp
    POST_CALL
    test    eax, eax
    jnz     .check_register

    ; LOGIN user:pass → 找 ':' 分隔，构造 PKT_LOGIN payload = "user\0pass\0"
    ; 简化：直接把 "user:pass" 转换为 "user\0pass\0"
    lea     rsi, [g_line_buf + 6]   ; 跳过 "LOGIN "
    call    .build_login_payload    ; 把 g_frame_buf+FRAME_HDR 填好，返回 rax=len
    mov     r15d, PKT_LOGIN
    jmp     .send_plain_login       ; LOGIN/REGISTER 可在握手后发（加密）

.check_register:
    PREP_CALL
    lea     A1, [g_line_buf]
    lea     A2, [.str_register]
    mov     A3d, 8
    call    util_strncmp
    POST_CALL
    test    eax, eax
    jnz     .send_as_msg

    lea     rsi, [g_line_buf + 9]
    call    .build_login_payload
    mov     r15d, PKT_REGISTER
    jmp     .send_plain_login

.send_as_msg:
    ; 普通文本 → PKT_MSG（加密）
    lea     rdi, [g_frame_buf + FRAME_HDR + NONCE_LEN]
    lea     rsi, [g_line_buf]
    mov     ecx, r14d
    rep     movsb
    mov     eax, r14d
    mov     r15d, PKT_MSG

.send_encrypted:
    ; 若未握手，降级为明文
    cmp     dword [g_handshaked], 0
    je      .send_plain_now

    ; 加密：chacha20_encrypt(dst, src, len, shared, nonce_ptr, 0)
    ; nonce = g_tx_nonce（8字节，存在 g_frame_buf+FRAME_HDR）
    mov     r8, [g_tx_nonce]
    mov     [g_frame_buf + FRAME_HDR], r8
    inc     qword [g_tx_nonce]

    PREP_CALL
    lea     A1, [g_frame_buf + FRAME_HDR + NONCE_LEN]
    lea     A2, [g_frame_buf + FRAME_HDR + NONCE_LEN]
    mov     A3d, eax                ; payload content len
    lea     A4, [g_shared]
%ifdef _WIN32
    lea     r8, [g_frame_buf + FRAME_HDR]
    mov     [rsp + 32], r8
    mov     qword [rsp + 40], 0
%else
    lea     r8, [g_frame_buf + FRAME_HDR]
    xor     r9, r9
%endif
    call    chacha20_encrypt
    POST_CALL

    ; frame len = NONCE_LEN + payload_content_len
    add     eax, NONCE_LEN

.send_plain_now:
    ; 写帧头
    mov     byte [g_frame_buf + F_TYPE], r15b
    mov     byte [g_frame_buf + F_FLAGS], 0
    mov     [g_frame_buf + F_LEN], ax

    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_frame_buf]
    mov     A3d, FRAME_HDR
    add     A3d, eax
    call    plat_write
    POST_CALL
    jmp     .main_loop

.send_plain_login:
    ; LOGIN/REGISTER 加密发送（若握手完成）
    cmp     dword [g_handshaked], 0
    jne     .send_encrypted

    ; 握手未完成，不发登录（应先等 PKT_HELLO 响应）
    jmp     .main_loop

.check_server:
    ; 检查服务端数据
    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_fds]
    call    plat_fd_isset
    POST_CALL
    test    eax, eax
    jz      .main_loop

    ; 读帧头
    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_recv_buf]
    mov     A3d, FRAME_HDR
    call    plat_read
    POST_CALL
    cmp     eax, FRAME_HDR
    jne     .exit_ok

    movzx   r12d, byte [g_recv_buf + F_TYPE]
    movzx   r13d, byte [g_recv_buf + F_FLAGS]
    movzx   r14d, word [g_recv_buf + F_LEN]

    test    r14d, r14d
    jz      .dispatch_recv

    cmp     r14d, NONCE_LEN + MAX_PAYLOAD
    jg      .exit_ok

    PREP_CALL
    mov     A1d, [g_sock]
    lea     A2,  [g_recv_buf + FRAME_HDR]
    mov     A3d, r14d
    call    plat_read
    POST_CALL
    cmp     eax, r14d
    jne     .exit_ok

.dispatch_recv:
    cmp     r12d, PKT_HELLO
    je      .recv_hello
    cmp     r12d, PKT_ACK
    je      .recv_ack
    cmp     r12d, PKT_MSG
    je      .recv_msg
    cmp     r12d, PKT_MAIL
    je      .recv_mail
    cmp     r12d, PKT_ANNOUNCE
    je      .recv_announce
    cmp     r12d, PKT_PONG
    je      .main_loop
    jmp     .main_loop

.recv_hello:
    ; payload = server_pubkey[32]
    cmp     r14d, PUBKEY_LEN
    jne     .main_loop

    ; X25519(shared, my_priv, server_pub)
    PREP_CALL
    lea     A1, [g_shared]
    lea     A2, [g_my_priv]
    lea     A3, [g_recv_buf + FRAME_HDR]
    call    x25519
    POST_CALL

    mov     dword [g_handshaked], 1

    PREP_CALL
    lea     A1, [str_ready]
    mov     A2d, str_ready_len
    call    plat_print
    POST_CALL
    jmp     .main_loop

.recv_ack:
    ; 打印结果
    cmp     r13d, ACK_OK
    je      .ack_ok_print
    ; 打印失败
    PREP_CALL
    lea     A1, [.str_ack_fail]
    call    util_strlen
    POST_CALL
    PREP_CALL
    lea     A1, [.str_ack_fail]
    mov     A2d, eax
    call    plat_print
    POST_CALL
    jmp     .main_loop
.ack_ok_print:
    PREP_CALL
    lea     A1, [.str_ack_ok]
    call    util_strlen
    POST_CALL
    PREP_CALL
    lea     A1, [.str_ack_ok]
    mov     A2d, eax
    call    plat_print
    POST_CALL
    jmp     .main_loop

.recv_msg:
.recv_mail:
.recv_announce:
    ; 若已握手，解密
    cmp     dword [g_handshaked], 0
    je      .print_payload

    mov     eax, r14d
    sub     eax, NONCE_LEN
    js      .main_loop

    PREP_CALL
    lea     A1, [g_recv_buf + FRAME_HDR + NONCE_LEN]
    lea     A2, [g_recv_buf + FRAME_HDR + NONCE_LEN]
    mov     A3d, eax
    lea     A4, [g_shared]
%ifdef _WIN32
    lea     r9, [g_recv_buf + FRAME_HDR]
    mov     [rsp + 32], r9
    mov     qword [rsp + 40], 0
%else
    lea     r8, [g_recv_buf + FRAME_HDR]
    xor     r9, r9
%endif
    call    chacha20_encrypt
    POST_CALL
    mov     r14d, eax

.print_payload:
    ; 打印消息
    PREP_CALL
    lea     A1, [g_recv_buf + FRAME_HDR + NONCE_LEN]
    mov     A2d, r14d
    call    plat_print
    POST_CALL
    ; 打印换行
    PREP_CALL
    lea     A1, [.str_newline]
    mov     A2d, 1
    call    plat_print
    POST_CALL
    jmp     .main_loop

; ================================================================
; 内部辅助（近调用）
; ================================================================

; .build_login_payload(rsi = "user:pass") → 填 g_frame_buf+FRAME_HDR, rax=len
.build_login_payload:
    push    rbx
    mov     rbx, rsi
    ; 找 ':'
    xor     ecx, ecx
.blp_scan:
    cmp     byte [rbx + rcx], 0
    je      .blp_no_colon
    cmp     byte [rbx + rcx], ':'
    je      .blp_found
    inc     ecx
    jmp     .blp_scan
.blp_found:
    ; user = rbx, user_len = ecx
    ; pass = rbx + ecx + 1
    push    rcx
    lea     rdi, [g_frame_buf + FRAME_HDR + NONCE_LEN]
    lea     rsi, [rbx]
    rep     movsb           ; copy user
    mov     byte [rdi], 0
    inc     rdi
    pop     rcx

    ; 计算 pass_len（到行尾或\0）
    lea     rsi, [rbx + rcx + 1]
    xor     ecx, ecx
.blp_passlen:
    cmp     byte [rsi + rcx], 0
    je      .blp_passend
    inc     ecx
    jmp     .blp_passlen
.blp_passend:
    rep     movsb           ; copy pass
    mov     byte [rdi], 0
    inc     rdi

    ; len = rdi - (g_frame_buf + FRAME_HDR + NONCE_LEN)
    lea     rax, [rdi]
    lea     r8,  [g_frame_buf + FRAME_HDR + NONCE_LEN]
    sub     rax, r8
    pop     rbx
    ret
.blp_no_colon:
    xor     eax, eax
    pop     rbx
    ret

; .parse_mail_opt_o → r9=to_ptr, r10d=to_len (uses r8 as scan ptr)
.parse_mail_opt_o:
    ; 在 r8 后面扫描 "-o "
    push    rbx
    mov     rbx, r8
.poo_scan:
    cmp     byte [rbx], 0
    je      .poo_fail
    cmp     byte [rbx], '-'
    jne     .poo_next
    cmp     byte [rbx + 1], 'o'
    jne     .poo_next
    cmp     byte [rbx + 2], ' '
    jne     .poo_next
    ; found "-o "
    lea     r9, [rbx + 3]     ; to_ptr
    xor     r10d, r10d
.poo_len:
    cmp     byte [r9 + r10], 0
    je      .poo_end
    cmp     byte [r9 + r10], ' '
    je      .poo_end
    inc     r10d
    jmp     .poo_len
.poo_end:
    ; 更新 r8 扫描位置到下一个单词后
    lea     r8, [r9 + r10 + 1]
    pop     rbx
    ret
.poo_next:
    inc     rbx
    jmp     .poo_scan
.poo_fail:
    xor     r9, r9
    pop     rbx
    ret

; .parse_mail_opt_m → r11=text_ptr, ecx=text_len
.parse_mail_opt_m:
    push    rbx
    mov     rbx, r8
.pom_scan:
    cmp     byte [rbx], 0
    je      .pom_fail
    cmp     byte [rbx], '-'
    jne     .pom_next
    cmp     byte [rbx + 1], 'm'
    jne     .pom_next
    cmp     byte [rbx + 2], ' '
    jne     .pom_next
    lea     r11, [rbx + 3]
    ; 跳过引号
    cmp     byte [r11], '"'
    jne     .pom_noquote
    inc     r11
.pom_noquote:
    xor     ecx, ecx
.pom_len:
    cmp     byte [r11 + rcx], 0
    je      .pom_end
    cmp     byte [r11 + rcx], '"'
    je      .pom_end
    inc     ecx
    jmp     .pom_len
.pom_end:
    pop     rbx
    ret
.pom_next:
    inc     rbx
    jmp     .pom_scan
.pom_fail:
    xor     r11, r11
    pop     rbx
    ret

; ================================================================
section .data
; （data 段中的字符串常量）
; ================================================================
.str_login      db "LOGIN ", 0
.str_register   db "REGISTER", 0
.str_ack_ok     db "[OK]", 10, 0
.str_ack_fail   db "[FAIL]", 10, 0
.str_newline    db 10

; ================================================================
.exit_ok:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    xor     eax, eax
    jmp     .epilogue

.exit_fail:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    mov     eax, 1
    jmp     .epilogue

.usage:
    ; TODO: 打印 usage
    mov     eax, 1

.epilogue:
    PREP_CALL
    call    plat_cleanup
    POST_CALL
%ifdef _WIN32
    mov     rsp, rbp
    pop     rbp
%else
    pop     rbp
%endif
    ret
