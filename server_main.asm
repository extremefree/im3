; ================================================================
; server_main.asm — v3 服务器核心
;
; 跨平台：所有 I/O 通过 platform.c 的 C 函数
; 特性：
;   - 每客户端接收缓冲区（解决 TCP 粘包）
;   - 加密用户文件
;   - /register 命令
;   - select() 多路复用
;
; 编译：见 Makefile
; ================================================================
BITS 64
default rel

%include "calling.inc"

%define MAX_CLIENTS     32
%define BUF_SIZE        2048
%define LINE_BUF        2048
%define SOCKADDR6_LEN   28
%define PLAT_FD_SIZE    520

; client_state 布局（与 buffer.asm 一致）
%define CS_FD           0
%define CS_BUF_LEN      4
%define CS_BUF          8
%define CS_SIZE         (8 + BUF_SIZE)

; ---- C 函数声明 ----
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

extern auth_init
extern auth_add_session
extern auth_remove_session
extern auth_login
extern auth_register
extern auth_logout
extern auth_get_name
extern auth_is_logged_in
extern auth_ratelimit

extern buf_append
extern buf_extract_line
extern util_strlen
extern util_strcmp
extern util_strncmp
extern util_find_colon

section .note.GNU-stack noalloc noexec nowrite progbits

; ================================================================
section .data
; ================================================================
msg_listen       db  "[server] listening on [::]:9000", 10
msg_listen_len   equ $ - msg_listen

msg_joined       db  "[server] new connection", 10
msg_joined_len   equ $ - msg_joined

msg_left         db  "[server] client disconnected", 10
msg_left_len     equ $ - msg_left

msg_full         db  "[server] refused: too many clients", 10
msg_full_len     equ $ - msg_full

msg_need_login   db  "Welcome! LOGIN name:pass  or  /REGISTER name:pass", 10
msg_need_login_len equ $ - msg_need_login

msg_login_ok     db  "OK logged in", 10
msg_login_ok_len equ $ - msg_login_ok

msg_login_fail   db  "ERR invalid credentials", 10
msg_login_fail_len equ $ - msg_login_fail

msg_already_in   db  "ERR already logged in", 10
msg_already_in_len equ $ - msg_already_in

msg_reg_ok       db  "OK registered (now LOGIN name:pass)", 10
msg_reg_ok_len   equ $ - msg_reg_ok

msg_reg_exist    db  "ERR user already exists", 10
msg_reg_exist_len equ $ - msg_reg_exist

msg_reg_full     db  "ERR user database full", 10
msg_reg_full_len equ $ - msg_reg_full

msg_rate         db  "ERR rate limit exceeded", 10
msg_rate_len     equ $ - msg_rate

msg_bracket_open  db "["
msg_bracket_close db "] "

; LOGIN 和 /REGISTER 前缀
prefix_login     db "LOGIN "
prefix_login_len equ 6

prefix_reg       db "/REGISTER "
prefix_reg_len   equ 10

str_any_addr     db "::", 0             ; bind to any IPv6 address

; ================================================================
; BSS 变量已合并到 .data section（win64 兼容）
; ================================================================

server_fd       dq 0
max_fd          dq 0
master_set      times PLAT_FD_SIZE db 0
work_set        times PLAT_FD_SIZE db 0
clients         times CS_SIZE * MAX_CLIENTS db 0
recv_buf        times BUF_SIZE db 0
line_buf        times LINE_BUF db 0
cli_addr        times SOCKADDR6_LEN db 0
cli_addr_len    dd 0
broadcast_buf   times (BUF_SIZE + 64) db 0
bind_addr       times 28 db 0
bind_addr_len   dd 0

; ================================================================
section .text
global main
; ================================================================

main:
    PROLOGUE

    ; plat_init()
    mov     A1, 0
    PREP_CALL
    call    plat_init
    POST_CALL

    mov     A1, msg_listen
    mov     A2, msg_listen_len
    PREP_CALL
    call    plat_print
    POST_CALL

    ; 初始化 clients 数组（fd = -1）
    call    _init_clients

    ; auth_init()
    PREP_CALL
    call    auth_init
    POST_CALL

    mov     A1, msg_joined
    mov     A2, msg_joined_len
    PREP_CALL
    call    plat_print
    POST_CALL

    ; 解析绑定地址 "::" → bind_addr
    lea     A1, [str_any_addr]
    mov     A2, 9000
    lea     A3, [bind_addr]
    PREP_CALL
    call    plat_resolve6
    POST_CALL

    ; socket = plat_socket6()
    PREP_CALL
    call    plat_socket6
    POST_CALL
    mov     [server_fd], rax

    ; plat_set_reuse(server_fd)
    mov     A1, rax
    PREP_CALL
    call    plat_set_reuse
    POST_CALL

    ; plat_bind(server_fd, &bind_addr, 28)
    mov     A1, [server_fd]
    lea     A2, [bind_addr]
    mov     A3, SOCKADDR6_LEN
    PREP_CALL
    call    plat_bind
    POST_CALL
    test    eax, eax
    js      .fatal

    ; plat_listen(server_fd, 16)
    mov     A1, [server_fd]
    mov     A2, 16
    PREP_CALL
    call    plat_listen
    POST_CALL
    test    eax, eax
    js      .fatal

    ; plat_fd_zero(&master_set)
    lea     A1, [master_set]
    PREP_CALL
    call    plat_fd_zero
    POST_CALL

    ; plat_fd_set(server_fd, &master_set)
    mov     A1, [server_fd]
    lea     A2, [master_set]
    PREP_CALL
    call    plat_fd_set
    POST_CALL

    mov     rax, [server_fd]
    mov     [max_fd], rax

    ; 打印监听提示
    mov     A1, msg_listen
    mov     A2, msg_listen_len
    PREP_CALL
    call    plat_print
    POST_CALL

; ================================================================
; 主循环
; ================================================================
.main_loop:
    ; work_set = master_set
    lea     A1, [work_set]
    lea     A2, [master_set]
    PREP_CALL
    call    plat_fd_copy
    POST_CALL

    ; plat_select(max_fd+1, &work_set)
    mov     A1, [max_fd]
    inc     A1
    lea     A2, [work_set]
    PREP_CALL
    call    plat_select
    POST_CALL
    test    eax, eax
    jle     .main_loop

    ; ---- 检查新连接 ----
    mov     A1, [server_fd]
    lea     A2, [work_set]
    PREP_CALL
    call    plat_fd_isset
    POST_CALL
    test    eax, eax
    jz      .scan_clients

    ; accept
    mov     dword [cli_addr_len], SOCKADDR6_LEN
    mov     A1, [server_fd]
    lea     A2, [cli_addr]
    lea     A3, [cli_addr_len]
    PREP_CALL
    call    plat_accept
    POST_CALL
    test    eax, eax
    js      .scan_clients

    mov     r15, rax            ; r15 = new fd

    ; 找空闲槽位
    lea     rsi, [clients]
    xor     rcx, rcx
.find_slot:
    cmp     rcx, MAX_CLIENTS
    jge     .refuse_full
    cmp     dword [rsi + CS_FD], -1
    jne     .next_slot_find
    ; 找到了
    mov     [rsi + CS_FD], r15d
    mov     dword [rsi + CS_BUF_LEN], 0
    jmp     .slot_found
.next_slot_find:
    add     rsi, CS_SIZE
    inc     rcx
    jmp     .find_slot

.refuse_full:
    ; 关闭 fd
    mov     A1, r15
    PREP_CALL
    call    plat_close
    POST_CALL
    mov     A1, msg_full
    mov     A2, msg_full_len
    PREP_CALL
    call    plat_print
    POST_CALL
    jmp     .scan_clients

.slot_found:
    ; 加入 master_set
    mov     A1, r15
    lea     A2, [master_set]
    PREP_CALL
    call    plat_fd_set
    POST_CALL

    ; 更新 max_fd
    cmp     r15, [max_fd]
    jle     .skip_maxfd
    mov     [max_fd], r15
.skip_maxfd:

    ; auth_add_session(fd)
    mov     A1, r15
    PREP_CALL
    call    auth_add_session
    POST_CALL

    ; 发送登录提示
    mov     A1, r15
    lea     A2, [msg_need_login]
    mov     A3, msg_need_login_len
    PREP_CALL
    call    plat_write
    POST_CALL

    ; 打印日志
    mov     A1, msg_joined
    mov     A2, msg_joined_len
    PREP_CALL
    call    plat_print
    POST_CALL

    ; ---- 遍历已连接客户端 ----
.scan_clients:
    xor     r12, r12            ; slot index
.client_loop:
    cmp     r12, MAX_CLIENTS
    jge     .main_loop

    ; 计算客户端状态地址
    imul    rax, r12, CS_SIZE
    lea     r13, [clients + rax]  ; r13 = &clients[slot]

    ; 跳过空槽
    mov     eax, [r13 + CS_FD]
    cmp     eax, -1
    je      .next_client

    ; FD_ISSET?
    mov     A1, rax
    lea     A2, [work_set]
    PREP_CALL
    call    plat_fd_isset
    POST_CALL
    test    eax, eax
    jz      .next_client

    ; 读取数据到临时缓冲区
    mov     A1, [r13 + CS_FD]
    lea     A2, [recv_buf]
    mov     A3, BUF_SIZE
    PREP_CALL
    call    plat_read
    POST_CALL

    test    eax, eax
    jle     .do_disconnect

    mov     r14d, eax           ; r14 = read bytes

    ; 追加到客户端缓冲区
    mov     A1, r13
    lea     A2, [recv_buf]
    mov     A3, r14
    PREP_CALL
    call    buf_append
    POST_CALL

    ; 循环提取完整行
.process_lines:
    ; buf_extract_line(state, line_buf, LINE_BUF)
    mov     A1, r13
    lea     A2, [line_buf]
    mov     A3, LINE_BUF
    PREP_CALL
    call    buf_extract_line
    POST_CALL

    test    eax, eax
    jz      .next_client        ; 没有完整行了

    mov     r14d, eax           ; r14 = line length

    ; null-terminate line
    mov     byte [line_buf + r14], 0

    ; 判断是否已登录
    mov     A1, [r13 + CS_FD]
    PREP_CALL
    call    auth_is_logged_in
    POST_CALL
    test    eax, eax
    jnz     .handle_msg

    ; ---- 未登录：解析 LOGIN 或 /REGISTER ----
    ; 检查 /REGISTER 前缀
    lea     A1, [line_buf]
    lea     A2, [prefix_reg]
    mov     A3, prefix_reg_len
    PREP_CALL
    call    util_strncmp
    POST_CALL
    test    eax, eax
    jz      .do_register

    ; 检查 LOGIN 前缀
    lea     A1, [line_buf]
    lea     A2, [prefix_login]
    mov     A3, prefix_login_len
    PREP_CALL
    call    util_strncmp
    POST_CALL
    test    eax, eax
    jnz     .bad_login_format

    ; 解析 LOGIN name:pass
    ; line_buf+6 开始是 "name:pass"
    lea     rdi, [line_buf + prefix_login_len]
    mov     esi, r14d
    sub     esi, prefix_login_len
    jle     .bad_login_format
    mov     r15d, esi           ; 保存剩余长度（caller-saved 可能被踩）

    ; 找冒号
    mov     A1, rdi
    mov     A2, rsi
    PREP_CALL
    call    util_find_colon
    POST_CALL
    cmp     eax, 0
    jle     .bad_login_format

    mov     r8d, eax            ; name_len
    lea     r9, [rdi + r8 + 1]  ; pass_ptr
    mov     r10d, r15d          ; 从 r15 恢复剩余长度
    sub     r10d, r8d
    dec     r10d                ; pass_len

    ; auth_login(fd, name_ptr, name_len, pass_ptr, pass_len)
    ; rdi=name_ptr, r8=name_len, r9=pass_ptr, r10=pass_len, [r13+CS_FD]=fd
%ifdef _WIN32
    ; Win64: A1=rcx, A2=rdx, A3=r8, A4=r9; arg5 on stack at [rsp+32] after PREP_CALL
    mov     rcx, [r13 + CS_FD]  ; A1 = fd
    mov     rdx, rdi             ; A2 = name_ptr (rdi → rdx before rdi is clobbered)
    ; A3 = r8 = name_len  (already in r8 = Win64 A3, no-op)
    ; A4 = r9 = pass_ptr  (already in r9 = Win64 A4, no-op)
    sub     rsp, 8               ; alignment pad: rsp%16 → 0 after push below
    push    r10                  ; arg5 = pass_len → [rsp+32] after PREP_CALL
    PREP_CALL                    ; sub rsp, 32
    call    auth_login
    POST_CALL                    ; add rsp, 32
    add     rsp, 16              ; remove push r10 + alignment pad
%else
    ; Linux: A1=rdi, A2=rsi, A3=rdx, A4=rcx; arg5=r8
    mov     rsi, rdi             ; A2 = name_ptr (save before overwriting A1=rdi)
    mov     rdi, [r13 + CS_FD]  ; A1 = fd
    mov     rdx, r8              ; A3 = name_len
    mov     rcx, r9              ; A4 = pass_ptr
    mov     r8, r10              ; arg5 = pass_len (5th Linux arg reg)
    PREP_CALL
    call    auth_login
    POST_CALL
%endif

    test    eax, eax
    jz      .login_success

    cmp     eax, -2
    je      .login_already

    ; 登录失败
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_login_fail]
    mov     A3, msg_login_fail_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.login_success:
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_login_ok]
    mov     A3, msg_login_ok_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.login_already:
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_already_in]
    mov     A3, msg_already_in_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.bad_login_format:
    ; 格式错误也当登录失败
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_login_fail]
    mov     A3, msg_login_fail_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.do_register:
    ; 解析 /REGISTER name:pass
    ; line_buf+10 开始是 "name:pass"
    lea     rdi, [line_buf + prefix_reg_len]
    mov     esi, r14d
    sub     esi, prefix_reg_len
    jle     .bad_login_format
    mov     r15d, esi           ; 保存剩余长度

    mov     A1, rdi
    mov     A2, rsi
    PREP_CALL
    call    util_find_colon
    POST_CALL
    cmp     eax, 0
    jle     .bad_login_format

    mov     r8d, eax            ; name_len
    lea     r9, [rdi + r8 + 1]  ; pass_ptr
    mov     r10d, r15d
    sub     r10d, r8d
    dec     r10d                ; pass_len

    ; auth_register(name, name_len, pass, pass_len)
    ; ABI args: A1=name, A2=nlen, A3=pass, A4=plen
    push    rdi                 ; name
    push    r8                  ; nlen
    push    r9                  ; pass ptr
    push    r10                 ; plen

    mov     A1, [rsp + 24]      ; name
    mov     A2, [rsp + 16]      ; nlen
    mov     A3, [rsp + 8]       ; pass ptr
    mov     A4, [rsp]           ; plen
    PREP_CALL
    call    auth_register
    POST_CALL

    add     rsp, 32             ; 清理 4 个 push

    test    eax, eax
    jz      .reg_success
    cmp     eax, -1
    je      .reg_exists

    ; full
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_reg_full]
    mov     A3, msg_reg_full_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.reg_success:
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_reg_ok]
    mov     A3, msg_reg_ok_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.reg_exists:
    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_reg_exist]
    mov     A3, msg_reg_exist_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

    ; ---- 已登录：广播消息 ----
.handle_msg:
    ; 限速检查
    mov     A1, [r13 + CS_FD]
    PREP_CALL
    call    auth_ratelimit
    POST_CALL
    test    eax, eax
    jz      .do_broadcast

    mov     A1, [r13 + CS_FD]
    lea     A2, [msg_rate]
    mov     A3, msg_rate_len
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .process_lines

.do_broadcast:
    ; 获取用户名
    mov     A1, [r13 + CS_FD]
    PREP_CALL
    call    auth_get_name
    POST_CALL
    test    rax, rax
    jz      .process_lines
    mov     r15, rax            ; r15 = name ptr

    ; 计算 name 长度
    mov     A1, r15
    PREP_CALL
    call    util_strlen
    POST_CALL
    mov     r8d, eax            ; r8 = name_len

    ; 拼装 broadcast_buf = "[name] line_buf\n"
    ; 1) "["
    lea     rdi, [broadcast_buf]
    mov     byte [rdi], '['
    inc     rdi

    ; 2) name
    mov     rsi, r15
    mov     ecx, r8d
    rep     movsb

    ; 3) "] "
    mov     byte [rdi], ']'
    inc     rdi
    mov     byte [rdi], ' '
    inc     rdi

    ; 4) message body (line_buf, r14 bytes)
    lea     rsi, [line_buf]
    mov     ecx, r14d
    rep     movsb

    ; 5) "\n"
    mov     byte [rdi], 10
    inc     rdi

    ; 总长度
    lea     rax, [broadcast_buf]
    sub     rdi, rax
    mov     r9d, edi            ; r9 = total broadcast msg len

    ; 遍历所有客户端，发送给其他已登录者
    ; r14 (line_len) no longer needed after string is built — reuse for broadcast len
    mov     r14d, r9d           ; r14 = total broadcast msg len (callee-saved)
    push    r12
    push    r13
    push    r14                  ; 4 pushes = 32 bytes → rsp%16=0 on Win64 ✓
    push    r15

    xor     r12, r12
.bc_loop:
    cmp     r12, MAX_CLIENTS
    jge     .bc_done

    imul    rax, r12, CS_SIZE
    lea     rbx, [clients + rax]
    mov     ebx, [rbx + CS_FD]
    cmp     ebx, -1
    je      .bc_next

    ; 跳过发送者
    mov     ecx, [r13 + CS_FD]
    cmp     ebx, ecx
    je      .bc_next

    ; 只发给已登录者
    mov     A1, rbx
    PREP_CALL
    call    auth_is_logged_in
    POST_CALL
    test    eax, eax
    jz      .bc_next

    ; 发送
    mov     A1, rbx
    lea     A2, [broadcast_buf]
    mov     A3, r14             ; broadcast msg len (callee-saved r14)
    PREP_CALL
    call    plat_write
    POST_CALL

.bc_next:
    inc     r12
    jmp     .bc_loop

.bc_done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    jmp     .process_lines

    ; ---- 断开连接 ----
.do_disconnect:
    mov     r14d, [r13 + CS_FD]

    ; 从 master_set 移除
    mov     A1, r14
    lea     A2, [master_set]
    PREP_CALL
    call    plat_fd_clr
    POST_CALL

    ; auth_remove_session
    mov     A1, r14
    PREP_CALL
    call    auth_remove_session
    POST_CALL

    ; 关闭 fd
    mov     A1, r14
    PREP_CALL
    call    plat_close
    POST_CALL

    ; 清空客户端槽位
    mov     dword [r13 + CS_FD], -1
    mov     dword [r13 + CS_BUF_LEN], 0

    ; 日志
    mov     A1, msg_left
    mov     A2, msg_left_len
    PREP_CALL
    call    plat_print
    POST_CALL

.next_client:
    inc     r12
    jmp     .client_loop

.fatal:
    mov     A1, msg_full
    mov     A2, msg_full_len
    PREP_CALL
    call    plat_print
    POST_CALL

    PREP_CALL
    call    plat_cleanup
    POST_CALL
    mov     eax, 1
    EPILOGUE

; ================================================================
; 初始化 clients 数组（fd = -1）
; ================================================================
section .text
global _init_clients
_init_clients:
    PROLOGUE
    lea     rdi, [clients]
    mov     ecx, MAX_CLIENTS
    mov     eax, -1
.init_lp:
    mov     [rdi + CS_FD], eax
    mov     dword [rdi + CS_BUF_LEN], 0
    add     rdi, CS_SIZE
    dec     ecx
    jnz     .init_lp
    EPILOGUE
