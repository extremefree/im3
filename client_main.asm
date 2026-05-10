; ================================================================
; client_main.asm — v3 客户端
;
; 用法：
;   ./client                              → 连默认地址，交互式登录
;   ./client <addr>                       → 连指定地址，交互式登录
;   ./client <addr> <user> <pass>         → 连接并自动登录
;
; 默认地址: 2408:8207:4821:1311:c038:c41e:3f76:8cea
; ================================================================
BITS 64
default rel

%include "calling.inc"

%define BUF_SIZE        2048
%define SOCKADDR6_LEN   28
%define PLAT_FD_SIZE    520

; ---- C 函数 ----
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
extern plat_fd_copy
extern plat_client_add_stdin
extern plat_stdin_ready
extern plat_read_stdin
extern plat_resolve6

extern util_strlen

section .note.GNU-stack noalloc noexec nowrite progbits

; ================================================================
section .data
; ================================================================
default_addr     db  "2408:8207:4821:1311:c038:c41e:3f76:8cea", 0
default_addr_len equ $ - default_addr - 1

str_connecting   db  "[cli] connecting...", 10
str_conn_len     equ $ - str_connecting

str_ok           db  "[cli] connected", 10
str_ok_len       equ $ - str_ok

str_fail         db  "[cli] connection failed", 10
str_fail_len     equ $ - str_fail

str_resolve_err  db  "[cli] failed to resolve address", 10
str_resolve_len  equ $ - str_resolve_err

str_srv_close    db  10, "[cli] server closed connection", 10
str_srv_close_len equ $ - str_srv_close

str_usage        db  "Usage: ./client [addr] [user pass]", 10
str_usage_len    equ $ - str_usage

str_prompt_login db  "login> "
str_prompt_login_len equ $ - str_prompt_login

str_prompt       db  "> "
str_prompt_len   equ $ - str_prompt

str_login_pfx    db  "LOGIN "
str_colon        db  ":"
str_newline      db  10

PORT             equ 9000

; BSS 变量已合并到 .data（win64 兼容）
sock_fd         dq 0
work_set        times PLAT_FD_SIZE db 0
recv_buf        times BUF_SIZE db 0
send_buf        times BUF_SIZE db 0
line_buf        times BUF_SIZE db 0
login_buf       times 256 db 0
srv_addr        times SOCKADDR6_LEN db 0
logged_in       dd 0           ; 0=未登录, 1=已登录

; ================================================================
section .text
global main
; ================================================================

main:
    PROLOGUE
    sub     rsp, 48            ; extra local space
    ; rbp-8:  argc
    ; rbp-16: argv
    ; rbp-24: addr_str
    ; rbp-32: user_str (or 0)
    ; rbp-40: pass_str (or 0)

    ; Save argc/argv FIRST before any call clobbers rcx/rdx (volatile on Win64)
    ; Win64: A1=rcx=argc, A2=rdx=argv  / Linux: A1=rdi=argc, A2=rsi=argv
    mov     [rbp - 8], A1      ; argc
    mov     [rbp - 16], A2     ; argv

    ; plat_init()
    PREP_CALL
    call    plat_init
    POST_CALL

    ; 确定地址
    cmp     qword [rbp - 8], 2
    jl      .use_default_addr
    ; argv[1] = addr
    mov     rax, [rbp - 16]    ; argv
    mov     rax, [rax + 8]     ; argv[1]
    mov     [rbp - 24], rax
    jmp     .resolve_addr

.use_default_addr:
    lea     rax, [default_addr]
    mov     [rbp - 24], rax

.resolve_addr:
    ; plat_resolve6(addr, 9000, &srv_addr)
    mov     A1, [rbp - 24]
    mov     A2, PORT
    lea     A3, [srv_addr]
    PREP_CALL
    call    plat_resolve6
    POST_CALL
    test    eax, eax
    jnz     .resolve_fail

    ; 创建 socket
    PREP_CALL
    call    plat_socket6
    POST_CALL
    test    eax, eax
    js      .conn_fail
    mov     [sock_fd], eax

    ; 连接
    mov     A1, str_connecting
    mov     A2, str_conn_len
    PREP_CALL
    call    plat_print
    POST_CALL

    mov     A1, [sock_fd]
    lea     A2, [srv_addr]
    mov     A3, SOCKADDR6_LEN
    PREP_CALL
    call    plat_connect
    POST_CALL
    test    eax, eax
    jnz     .conn_fail

    mov     A1, str_ok
    mov     A2, str_ok_len
    PREP_CALL
    call    plat_print
    POST_CALL

    ; 判断模式
    mov     dword [logged_in], 0
    mov     rax, [rbp - 8]      ; argc
    cmp     rax, 4
    jl      .interactive_login

    ; 自动登录模式: argv[2]=user, argv[3]=pass
    mov     rax, [rbp - 16]     ; argv
    mov     rax, [rax + 16]     ; argv[2]
    mov     [rbp - 32], rax
    mov     rax, [rbp - 16]
    mov     rax, [rax + 24]     ; argv[3]
    mov     [rbp - 40], rax

    PREP_CALL
    call    .build_and_send_login
    POST_CALL
    jmp     .main_loop

.interactive_login:
    mov     qword [rbp - 32], 0
    mov     qword [rbp - 40], 0

; ================================================================
; 主事件循环
; ================================================================
.main_loop:
    ; 重置 work_set
    lea     A1, [work_set]
    PREP_CALL
    call    plat_fd_zero
    POST_CALL

    ; FD_SET(sock_fd)
    mov     A1, [sock_fd]
    lea     A2, [work_set]
    PREP_CALL
    call    plat_fd_set
    POST_CALL

    ; 添加 stdin（Linux 有效，Windows no-op）
    lea     A1, [work_set]
    PREP_CALL
    call    plat_client_add_stdin
    POST_CALL

    ; select
    mov     A1, [sock_fd]
    inc     A1
    lea     A2, [work_set]
    PREP_CALL
    call    plat_select
    POST_CALL
    test    eax, eax
    jle     .check_stdin        ; timeout or error, check stdin anyway

    ; ---- socket 可读 ----
    mov     A1, [sock_fd]
    lea     A2, [work_set]
    PREP_CALL
    call    plat_fd_isset
    POST_CALL
    test    eax, eax
    jz      .check_stdin

    ; 读 socket
    mov     A1, [sock_fd]
    lea     A2, [recv_buf]
    mov     A3, BUF_SIZE - 1
    PREP_CALL
    call    plat_read
    POST_CALL
    test    eax, eax
    jle     .srv_closed

    ; 打印到 stdout
    mov     A1, recv_buf
    mov     A2, rax
    PREP_CALL
    call    plat_print
    POST_CALL

    ; 检查是否收到 "OK logged in" → 标记已登录
    cmp     byte [recv_buf], 'O'
    jne     .check_stdin
    cmp     byte [recv_buf + 1], 'K'
    jne     .check_stdin
    mov     dword [logged_in], 1

.check_stdin:
    ; 检查 stdin
    lea     A1, [work_set]
    PREP_CALL
    call    plat_stdin_ready
    POST_CALL
    test    eax, eax
    jz      .main_loop

    ; 读 stdin
    lea     A1, [send_buf]
    mov     A2, BUF_SIZE - 1
    PREP_CALL
    call    plat_read_stdin
    POST_CALL
    test    eax, eax
    jle     .quit               ; EOF

    mov     r14d, eax           ; stdin bytes read

    ; 未登录或已登录，均直接发送原始输入
    cmp     dword [logged_in], 0
    jne     .send_raw

.send_raw:
    ; 直接发送 stdin 内容
    mov     A1, [sock_fd]
    lea     A2, [send_buf]
    mov     eax, r14d
    mov     A3, rax
    PREP_CALL
    call    plat_write
    POST_CALL
    jmp     .main_loop

.srv_closed:
    mov     A1, str_srv_close
    mov     A2, str_srv_close_len
    PREP_CALL
    call    plat_print
    POST_CALL

.quit:
    mov     A1, [sock_fd]
    PREP_CALL
    call    plat_close
    POST_CALL

    PREP_CALL
    call    plat_cleanup
    POST_CALL

    xor     eax, eax
    EPILOGUE

.resolve_fail:
    mov     A1, str_resolve_err
    mov     A2, str_resolve_len
    PREP_CALL
    call    plat_print
    POST_CALL
    mov     eax, 1
    EPILOGUE

.conn_fail:
    mov     A1, str_fail
    mov     A2, str_fail_len
    PREP_CALL
    call    plat_print
    POST_CALL
    mov     eax, 1
    EPILOGUE

; ================================================================
; .build_and_send_login — 自动登录模式，从 [rbp-32]/[rbp-40] 构建 LOGIN 包
; ================================================================
.build_and_send_login:
    ; 拼装 "LOGIN user:pass\n" 到 login_buf
    lea     rdi, [login_buf]
    lea     rsi, [str_login_pfx]
    mov     ecx, 6
    rep     movsb

    ; name
    mov     rsi, [rbp - 32]
.bl_name:
    mov     al, [rsi]
    test    al, al
    jz      .bl_name_done
    mov     [rdi], al
    inc     rdi
    inc     rsi
    jmp     .bl_name
.bl_name_done:
    mov     byte [rdi], ':'
    inc     rdi

    ; pass
    mov     rsi, [rbp - 40]
.bl_pass:
    mov     al, [rsi]
    test    al, al
    jz      .bl_pass_done
    mov     [rdi], al
    inc     rdi
    inc     rsi
    jmp     .bl_pass
.bl_pass_done:
    mov     byte [rdi], 10
    inc     rdi

    ; 计算长度
    lea     rax, [login_buf]
    sub     rdi, rax
    mov     r14d, edi

    ; 发送
    mov     A1, [sock_fd]
    lea     A2, [login_buf]
    mov     eax, r14d
    mov     A3, rax
    ; .build_and_send_login is called via PREP_CALL+call, so on entry rsp%16=8.
    ; Need one extra 8-byte adjust before PREP_CALL so rsp%16=0 before call plat_write.
    sub     rsp, 8
    PREP_CALL
    call    plat_write
    POST_CALL
    add     rsp, 8

    mov     dword [logged_in], 1
    ret
