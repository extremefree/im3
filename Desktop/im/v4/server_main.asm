; ================================================================
; server_main.asm — v4 服务器核心（二进制帧 + ChaCha20 加密）
;
; 协议：4字节帧头 [type:1][flags:1][len:2 LE] + payload
; 握手：PKT_HELLO（交换 X25519 公钥），之后用 ChaCha20 加密
; ================================================================
BITS 64
default rel

%include "calling.inc"
%include "proto.inc"

%define MAX_CLIENTS     32
%define SOCKADDR6_LEN   28
%define PLAT_FD_SIZE    520
%define NAME_LEN        32

; ---- 外部 C 函数 ----
extern plat_init
extern plat_cleanup
extern plat_socket6
extern plat_set_reuse
extern plat_bind
extern plat_listen
extern plat_accept
extern plat_close
extern plat_read
extern plat_write
extern plat_print
extern plat_select
extern plat_fd_zero
extern plat_fd_set
extern plat_fd_clr
extern plat_fd_isset
extern plat_fd_copy
extern plat_resolve6
extern plat_random

extern auth_init
extern auth_new_session
extern auth_remove_session
extern auth_login
extern auth_register
extern auth_logout
extern auth_get_name
extern auth_is_logged_in
extern auth_get_user_idx
extern auth_ratelimit
extern auth_load_pubkey
extern auth_save_keypair

extern util_strlen
extern util_strcmp
extern util_strncmp
extern util_xor_crypt

extern chacha20_encrypt
extern x25519_base
extern x25519

section .note.GNU-stack noalloc noexec nowrite progbits

; ================================================================
section .data
; ================================================================
align 8
msg_listen      db "[v4-server] listening on [::]:9000", 10
msg_listen_len  equ $ - msg_listen

msg_new_conn    db "[v4-server] new connection", 10
msg_new_conn_len equ $ - msg_new_conn

msg_disconn     db "[v4-server] client disconnected", 10
msg_disconn_len equ $ - msg_disconn

str_server_hello db "[server] connected. Use: LOGIN user:pass  or  REGISTER user:pass", 0
str_announced   db "[system] ", 0
str_joined      db " joined", 0
str_left        db " left", 0
str_mail_pfx    db "[mail] ", 0
str_login_ok    db "Login OK", 0
str_login_ok_len equ $ - str_login_ok
str_login_fail  db "Login failed", 0
str_reg_ok      db "Register OK", 0
str_reg_fail    db "Register failed", 0

; ================================================================
section .bss
; ================================================================
align 8
g_clients       resb (CS_SIZE * MAX_CLIENTS)
g_listen_fd     resd 1
g_server_priv   resb PUBKEY_LEN          ; 服务器 X25519 私钥
g_server_pub    resb PUBKEY_LEN          ; 服务器 X25519 公钥
g_fds           resb PLAT_FD_SIZE
g_tmp_fds       resb PLAT_FD_SIZE
g_addr          resb SOCKADDR6_LEN
g_payload_buf   resb (NONCE_LEN + MAX_PAYLOAD + 64)  ; 收发 payload 临时缓冲
g_tmp_len       resd 1                               ; 临时保存 payload 长度（穿过 C 函数调用）

; ================================================================
section .text
; ================================================================
global main

; ----------------------------------------------------------------
; 工具宏：send_frame(fd, type, flags, payload_ptr, payload_len)
; 不加密，用于 PKT_HELLO 和建立前的帧
; ----------------------------------------------------------------
%macro send_frame_plain 5
    ; 组装帧头到 g_payload_buf 前4字节
    mov     byte [g_payload_buf + F_TYPE],  %2
    mov     byte [g_payload_buf + F_FLAGS], %3
    mov     word [g_payload_buf + F_LEN],   %5    ; len 是立即数或寄存器

    ; 若 payload_len > 0，复制 payload
    %if %5 > 0
    ; 只处理立即数情形（宏内联）
    %endif

    ; plat_write(fd, hdr, 4)
    PREP_CALL
    mov     A1d, %1
    lea     A2,  [g_payload_buf]
    mov     A3d, FRAME_HDR
    call    plat_write
    POST_CALL

    ; 若有 payload，再写
    %if %5 > 0
    PREP_CALL
    mov     A1d, %1
    mov     A2,  %4
    mov     A3d, %5
    call    plat_write
    POST_CALL
    %endif
%endmacro

; ----------------------------------------------------------------
; send_ack(fd, result_code) — 发送 PKT_ACK（加密或明文）
; 此处简化：未完成握手时发明文，已完成时加密
; 用寄存器：r12=fd, r13=code（由调用者保证）
; ----------------------------------------------------------------
; （实际在各 handler 内部内联处理，见下文）

; ================================================================
; main
; ================================================================
main:
    PROLOGUE
    push    r12
    push    r13
    push    r14
    push    r15

    ; plat_init()
    PREP_CALL
    call    plat_init
    POST_CALL
    test    eax, eax
    jnz     .exit_fail

    ; auth_init()
    PREP_CALL
    call    auth_init
    POST_CALL

    ; 生成服务器 X25519 密钥对
    PREP_CALL
    lea     A1, [g_server_priv]
    mov     A2d, PUBKEY_LEN
    call    plat_random
    POST_CALL

    ; 钳制私钥（RFC 7748）
    and     byte [g_server_priv + 0],  0xF8
    and     byte [g_server_priv + 31], 0x7F
    or      byte [g_server_priv + 31], 0x40

    PREP_CALL
    lea     A1, [g_server_pub]
    lea     A2, [g_server_priv]
    call    x25519_base
    POST_CALL

    ; 初始化客户端状态表
    lea     r12, [g_clients]
    mov     r13d, MAX_CLIENTS
.init_clients:
    mov     dword [r12 + CS_FD], -1
    add     r12, CS_SIZE
    dec     r13d
    jnz     .init_clients

    ; 创建监听 socket
    PREP_CALL
    call    plat_socket6
    POST_CALL
    test    eax, eax
    js      .exit_fail
    mov     [g_listen_fd], eax

    PREP_CALL
    mov     A1d, [g_listen_fd]
    call    plat_set_reuse
    POST_CALL

    ; resolve [::]:9000
    PREP_CALL
    xor     A1, A1
    mov     A2d, 9000
    lea     A3, [g_addr]
    call    plat_resolve6
    POST_CALL

    PREP_CALL
    mov     A1d, [g_listen_fd]
    lea     A2,  [g_addr]
    mov     A3d, SOCKADDR6_LEN
    call    plat_bind
    POST_CALL

    PREP_CALL
    mov     A1d, [g_listen_fd]
    mov     A2d, MAX_CLIENTS
    call    plat_listen
    POST_CALL

    PREP_CALL
    lea     A1, [msg_listen]
    mov     A2d, msg_listen_len
    call    plat_print
    POST_CALL

    ; ---- 主循环 ----
.main_loop:
    ; 构建 fd_set
    PREP_CALL
    lea     A1, [g_fds]
    call    plat_fd_zero
    POST_CALL

    PREP_CALL
    mov     A1d, [g_listen_fd]
    lea     A2,  [g_fds]
    call    plat_fd_set
    POST_CALL

    ; 加入所有活跃客户端
    lea     r12, [g_clients]
    mov     r13d, MAX_CLIENTS
.add_clients:
    mov     eax, [r12 + CS_FD]
    cmp     eax, -1
    je      .skip_add
    PREP_CALL
    mov     A1d, eax
    lea     A2,  [g_fds]
    call    plat_fd_set
    POST_CALL
.skip_add:
    add     r12, CS_SIZE
    dec     r13d
    jnz     .add_clients

    ; select()
    PREP_CALL
    mov     A1d, 1024
    lea     A2,  [g_fds]
    call    plat_select
    POST_CALL
    test    eax, eax
    jle     .main_loop

    ; 新连接？
    PREP_CALL
    mov     A1d, [g_listen_fd]
    lea     A2,  [g_fds]
    call    plat_fd_isset
    POST_CALL
    test    eax, eax
    jz      .check_clients

    ; accept
    PREP_CALL
    mov     A1d, [g_listen_fd]
    xor     A2, A2
    xor     A3, A3
    call    plat_accept
    POST_CALL
    test    eax, eax
    js      .check_clients

    mov     r15d, eax   ; new fd

    ; 找空槽
    lea     r12, [g_clients]
    mov     r13d, MAX_CLIENTS
.find_slot:
    mov     eax, [r12 + CS_FD]
    cmp     eax, -1
    je      .got_slot
    add     r12, CS_SIZE
    dec     r13d
    jnz     .find_slot
    ; 无空槽
    PREP_CALL
    mov     A1d, r15d
    call    plat_close
    POST_CALL
    jmp     .check_clients

.got_slot:
    mov     [r12 + CS_FD],      r15d
    mov     dword [r12 + CS_FLAGS],    0
    mov     dword [r12 + CS_USER_IDX], -1
    mov     qword [r12 + CS_TX_NONCE], 0
    mov     qword [r12 + CS_RX_NONCE], 0
    mov     dword [r12 + CS_BUF_LEN],  0

    ; auth_new_session(fd)
    PREP_CALL
    mov     A1d, r15d
    call    auth_new_session
    POST_CALL

    ; 发送服务器 PKT_HELLO（明文，包含 server_pub）
    ; 帧头 4 字节 + 32 字节公钥
    mov     byte  [g_payload_buf + 0], PKT_HELLO
    mov     byte  [g_payload_buf + 1], 0
    mov     word  [g_payload_buf + 2], PUBKEY_LEN
    ; 把 server_pub 复制到 buf+4
    lea     rsi, [g_server_pub]
    lea     rdi, [g_payload_buf + FRAME_HDR]
    mov     ecx, PUBKEY_LEN / 8
    rep     movsq
    PREP_CALL
    mov     A1d, r15d
    lea     A2,  [g_payload_buf]
    mov     A3d, FRAME_HDR + PUBKEY_LEN
    call    plat_write
    POST_CALL

    PREP_CALL
    lea     A1, [msg_new_conn]
    mov     A2d, msg_new_conn_len
    call    plat_print
    POST_CALL

.check_clients:
    ; 遍历客户端
    lea     r12, [g_clients]
    mov     r13d, MAX_CLIENTS

.client_loop:
    dec     r13d
    js      .main_loop

    mov     r14d, [r12 + CS_FD]
    cmp     r14d, -1
    je      .next_client

    ; fd_isset?
    PREP_CALL
    mov     A1d, r14d
    lea     A2,  [g_fds]
    call    plat_fd_isset
    POST_CALL
    test    eax, eax
    jz      .next_client

    ; 读帧头（4字节）
    lea     rdi, [g_payload_buf]
    PREP_CALL
    mov     A1d, r14d
    lea     A2,  [g_payload_buf]
    mov     A3d, FRAME_HDR
    call    plat_read
    POST_CALL
    cmp     eax, FRAME_HDR
    jne     .disconnect

    ; 解析帧头
    movzx   r9d,  byte [g_payload_buf + F_TYPE]   ; type
    movzx   r10d, byte [g_payload_buf + F_FLAGS]   ; flags
    movzx   r11d, word [g_payload_buf + F_LEN]     ; payload len

    ; 读 payload
    test    r11d, r11d
    jz      .dispatch

    cmp     r11d, NONCE_LEN + MAX_PAYLOAD
    jg      .disconnect

    ; r11d 会被 plat_read 内部的 syscall 破坏（r11 是 caller-saved）
    ; 用 r15（callee-saved）暂存期望长度
    mov     r15d, r11d
    PREP_CALL
    mov     A1d,  r14d
    lea     A2,   [g_payload_buf + FRAME_HDR]
    mov     A3d,  r15d
    call    plat_read
    POST_CALL
    cmp     eax, r15d               ; r15 由 plat_read（C 函数）保留
    jne     .disconnect
    mov     r11d, r15d              ; 恢复 r11d 供后续 dispatch 使用

.dispatch:
    ; 若已完成握手，解密 payload（跳过 nonce 前8字节）
    mov     eax, [r12 + CS_FLAGS]
    and     eax, CSF_HANDSHAKED
    jz      .no_decrypt

    ; 解密：chacha20_encrypt(plain, cipher+8, len-8, shared, nonce, ctr=0)
    ; nonce = payload 前8字节
    lea     rsi, [g_payload_buf + FRAME_HDR]      ; payload 起始
    ; chacha20_encrypt(out, in, len, key, nonce, ctr)
    ; out = 原地（同一指针偏移8开始）
    ; 保存 r9d（PKT_TYPE）：xor r9, r9 和 call 都会破坏它（r9 是 caller-saved）
    mov     r15d, r9d
    sub     r11d, NONCE_LEN
    js      .disconnect

    ; 保存解密后 payload 长度：call chacha20_encrypt 会破坏 r11
    mov     [g_tmp_len], r11d

    ; 用 RX nonce 验证（此处简化：直接解密，不校验计数器）
    ; chacha20_encrypt(dst, src, len, shared, nonce_ptr, 0)
    PREP_CALL
    lea     A1, [g_payload_buf + FRAME_HDR + NONCE_LEN]    ; dst（原地）
    lea     A2, [g_payload_buf + FRAME_HDR + NONCE_LEN]    ; src
    mov     A3d, r11d                                       ; len
    lea     A4, [r12 + CS_SHARED]                          ; key
%ifdef _WIN32
    ; A5, A6 在栈上（shadow+8, shadow+16）
    lea     rax, [g_payload_buf + FRAME_HDR]
    mov     [rsp + 32], rax             ; nonce（payload 前8字节）
    mov     qword [rsp + 40], 0         ; ctr = 0
%else
    lea     r8,  [g_payload_buf + FRAME_HDR]   ; nonce
    xor     r9,  r9                             ; ctr = 0
%endif
    call    chacha20_encrypt
    POST_CALL

    ; 恢复 r9d（PKT_TYPE）和 r11d（解密 payload 长度）
    mov     r9d,  r15d
    mov     r11d, [g_tmp_len]

    ; 增加 RX nonce 计数器
    inc     qword [r12 + CS_RX_NONCE]

.no_decrypt:
    ; 跳转到各类型处理器
    cmp     r9d, PKT_HELLO
    je      .handle_hello
    cmp     r9d, PKT_LOGIN
    je      .handle_login
    cmp     r9d, PKT_REGISTER
    je      .handle_register
    cmp     r9d, PKT_MSG
    je      .handle_msg
    cmp     r9d, PKT_MAIL
    je      .handle_mail
    cmp     r9d, PKT_PING
    je      .handle_ping
    cmp     r9d, PKT_LOGOUT
    je      .handle_logout
    jmp     .next_client

; ---- PKT_HELLO ----
.handle_hello:
    ; payload = client_pubkey[32]
    cmp     r11d, PUBKEY_LEN
    jne     .next_client

    ; X25519(shared, server_priv, client_pub)
    PREP_CALL
    lea     A1, [r12 + CS_SHARED]
    lea     A2, [g_server_priv]
    lea     A3, [g_payload_buf + FRAME_HDR]
    call    x25519
    POST_CALL

    ; 标记握手完成
    or      dword [r12 + CS_FLAGS], CSF_HANDSHAKED
    jmp     .next_client

; ---- PKT_LOGIN ----
.handle_login:
    ; payload = "user\0pass\0"（已解密，从 FRAME_HDR+NONCE_LEN 开始）
    ; 解析 user 和 pass（以 \0 分隔）
    lea     rsi, [g_payload_buf + FRAME_HDR + NONCE_LEN]
    mov     eax, r11d
    ; 找第一个 \0
    xor     ecx, ecx
.login_scan_user:
    cmp     ecx, eax
    jge     .send_ack_fail_login
    cmp     byte [rsi + rcx], 0
    je      .login_got_user
    inc     ecx
    jmp     .login_scan_user
.login_got_user:
    ; user = rsi, user_len = ecx
    push    rcx                 ; user_len
    lea     rdi, [rsi + rcx + 1]   ; pass ptr
    push    rdi
    ; pass_len = r11d - ecx - 1 - 1 (尾部\0)
    mov     edx, r11d
    sub     edx, ecx
    sub     edx, 2
    push    rdx                 ; pass_len

    ; auth_login(fd, user, user_len, pass, pass_len)
    PREP_CALL
    mov     A1d, r14d
    mov     A2,  rsi
    mov     A3d, [rsp + 16]    ; user_len
    mov     A4,  [rsp + 8]     ; pass ptr
%ifdef _WIN32
    mov     rax, [rsp + 0]
    mov     [rsp + 32 + 0], rax ; pass_len（第5参数）
%else
    mov     r8d, [rsp + 0]
%endif
    call    auth_login
    POST_CALL

    add     rsp, 24
    test    eax, eax
    jnz     .send_ack_fail_login

    ; 设置已登录标志
    or      dword [r12 + CS_FLAGS], CSF_LOGGED_IN
    ; 发送 ACK_OK
    call    .send_ack_ok
    jmp     .next_client

.send_ack_fail_login:
    call    .send_ack_fail
    jmp     .next_client

; ---- PKT_REGISTER ----
.handle_register:
    lea     rsi, [g_payload_buf + FRAME_HDR + NONCE_LEN]
    mov     eax, r11d
    xor     ecx, ecx
.reg_scan_user:
    cmp     ecx, eax
    jge     .send_ack_fail_reg
    cmp     byte [rsi + rcx], 0
    je      .reg_got_user
    inc     ecx
    jmp     .reg_scan_user
.reg_got_user:
    push    rcx
    lea     rdi, [rsi + rcx + 1]
    push    rdi
    mov     edx, r11d
    sub     edx, ecx
    sub     edx, 2
    push    rdx

    PREP_CALL
    mov     A1d, r14d
    mov     A2,  rsi
    mov     A3d, [rsp + 16]
    mov     A4,  [rsp + 8]
%ifdef _WIN32
    mov     rax, [rsp + 0]
    mov     [rsp + 32], rax
%else
    mov     r8d, [rsp + 0]
%endif
    call    auth_register
    POST_CALL
    add     rsp, 24
    test    eax, eax
    jnz     .send_ack_fail_reg

    or      dword [r12 + CS_FLAGS], CSF_LOGGED_IN
    call    .send_ack_ok
    jmp     .next_client

.send_ack_fail_reg:
    call    .send_ack_fail
    jmp     .next_client

; ---- PKT_MSG（广播）----
.handle_msg:
    ; 检查登录
    mov     eax, [r12 + CS_FLAGS]
    and     eax, CSF_LOGGED_IN
    jz      .next_client

    ; 获取用户名
    ; (为简化，省略速率限制)
    ; 广播给所有其他已登录客户端
    ; 构造消息：类型 PKT_ANNOUNCE，payload = "[user] text"
    ; 此处先实现明文广播（加密版留 TODO）
    ; 组装 announce payload 到 g_payload_buf+512 以上区域
    ; ... 简化实现：直接原样转发 PKT_MSG 给其他客户端

    lea     rsi, [g_clients]
    mov     ecx, MAX_CLIENTS
.broadcast_loop:
    dec     ecx
    js      .next_client
    mov     eax, [rsi + CS_FD]
    cmp     eax, -1
    je      .broadcast_skip
    cmp     eax, r14d
    je      .broadcast_skip

    ; 发送帧头
    mov     byte  [g_payload_buf + 0], PKT_MSG
    mov     byte  [g_payload_buf + 1], 0
    mov     word  [g_payload_buf + 2], r11w

    PREP_CALL
    mov     A1d,  eax
    lea     A2,   [g_payload_buf]
    mov     A3d,  FRAME_HDR
    call    plat_write
    POST_CALL

    ; 发送 payload（原始，若对方也握手则需加密，此处简化）
    test    r11d, r11d
    jz      .broadcast_skip
    PREP_CALL
    mov     A1d,  [rsi + CS_FD]    ; 重新取（rax 可能被破坏）
    lea     A2,   [g_payload_buf + FRAME_HDR]
    mov     A3d,  r11d
    call    plat_write
    POST_CALL

.broadcast_skip:
    add     rsi, CS_SIZE
    jmp     .broadcast_loop

; ---- PKT_MAIL（私信）----
.handle_mail:
    ; 检查登录
    mov     eax, [r12 + CS_FLAGS]
    and     eax, CSF_LOGGED_IN
    jz      .next_client

    ; payload = "to\0text"（已解密，从 FRAME_HDR+NONCE_LEN 开始）
    lea     rsi, [g_payload_buf + FRAME_HDR + NONCE_LEN]
    mov     eax, r11d
    xor     ecx, ecx
.mail_scan_to:
    cmp     ecx, eax
    jge     .next_client
    cmp     byte [rsi + rcx], 0
    je      .mail_got_to
    inc     ecx
    jmp     .mail_scan_to
.mail_got_to:
    ; to = rsi, to_len = ecx, text = rsi+ecx+1
    ; 找目标客户端
    lea     r8, [rsi + rcx + 1]   ; text ptr
    mov     r9d, r11d
    sub     r9d, ecx
    dec     r9d                   ; text len

    ; 遍历客户端找 to
    lea     rdi, [g_clients]
    mov     edx, MAX_CLIENTS
.mail_find:
    dec     edx
    js      .next_client
    mov     eax, [rdi + CS_FD]
    cmp     eax, -1
    je      .mail_next

    ; 获取该客户端用户名，比较
    ; （简化：跳过，实际需要 auth_get_name per fd）
    ; TODO: 实现精确用户名匹配

.mail_next:
    add     rdi, CS_SIZE
    jmp     .mail_find

; ---- PKT_PING ----
.handle_ping:
    mov     byte  [g_payload_buf + 0], PKT_PONG
    mov     byte  [g_payload_buf + 1], 0
    mov     word  [g_payload_buf + 2], 0
    PREP_CALL
    mov     A1d, r14d
    lea     A2,  [g_payload_buf]
    mov     A3d, FRAME_HDR
    call    plat_write
    POST_CALL
    jmp     .next_client

; ---- PKT_LOGOUT ----
.handle_logout:
    PREP_CALL
    mov     A1d, r14d
    call    auth_logout
    POST_CALL
    call    .send_ack_ok
    jmp     .next_client

; ================================================================
; 发送 ACK 辅助（近调用，用 call + ret）
; 不加密（握手后应加密，此处简化）
; ================================================================
.send_ack_ok:
    mov     byte  [g_payload_buf + 0], PKT_ACK
    mov     byte  [g_payload_buf + 1], ACK_OK
    mov     word  [g_payload_buf + 2], 0
    PREP_CALL
    mov     A1d, r14d
    lea     A2,  [g_payload_buf]
    mov     A3d, FRAME_HDR
    call    plat_write
    POST_CALL
    ret

.send_ack_fail:
    mov     byte  [g_payload_buf + 0], PKT_ACK
    mov     byte  [g_payload_buf + 1], ACK_ERR_CRED
    mov     word  [g_payload_buf + 2], 0
    PREP_CALL
    mov     A1d, r14d
    lea     A2,  [g_payload_buf]
    mov     A3d, FRAME_HDR
    call    plat_write
    POST_CALL
    ret

; ================================================================
; 断开连接
; ================================================================
.disconnect:
    mov     r14d, [r12 + CS_FD]
    PREP_CALL
    mov     A1d, r14d
    lea     A2,  [g_fds]
    call    plat_fd_clr
    POST_CALL

    PREP_CALL
    mov     A1d, r14d
    call    auth_remove_session
    POST_CALL

    PREP_CALL
    mov     A1d, r14d
    call    plat_close
    POST_CALL

    mov     dword [r12 + CS_FD], -1

    PREP_CALL
    lea     A1, [msg_disconn]
    mov     A2d, msg_disconn_len
    call    plat_print
    POST_CALL

.next_client:
    add     r12, CS_SIZE
    jmp     .client_loop

.exit_fail:
    PREP_CALL
    call    plat_cleanup
    POST_CALL

    pop     r15
    pop     r14
    pop     r13
    pop     r12

    mov     eax, 1
    ; EPILOGUE
%ifdef _WIN32
    mov     rsp, rbp
    pop     rbp
%else
    pop     rbp
%endif
    ret
