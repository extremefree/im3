; ================================================================
; proto.inc — v4 二进制帧协议定义
;
; 帧格式（所有多字节字段小端序）：
;   [type:1][flags:1][len:2][payload:len]
;
; 连接建立流程：
;   C→S  PKT_HELLO   payload = client_pubkey[32]
;   S→C  PKT_HELLO   payload = server_pubkey[32]
;   双方用 X25519 得到共享密钥，之后所有帧 payload 用 ChaCha20 加密
;
; 加密帧额外头（在 payload 最前面）：
;   [nonce:8]  (递增计数器，每帧独立)
;
; 消息命令（type字段）：
; ================================================================

; ---- 帧类型 ----
%define PKT_HELLO       0x01    ; 密钥交换：payload = pubkey[32]
%define PKT_LOGIN       0x02    ; 登录：    payload = "user\0pass\0"
%define PKT_REGISTER    0x03    ; 注册：    payload = "user\0pass\0"
%define PKT_MSG         0x04    ; 广播消息：payload = text
%define PKT_MAIL        0x05    ; 私信：    payload = "to\0" + text
%define PKT_ACK         0x06    ; 服务端回应：flags=结果码，payload=可选文本
%define PKT_ANNOUNCE    0x07    ; 服务端广播系统消息（如上下线通知）
%define PKT_PING        0x08    ; 心跳
%define PKT_PONG        0x09    ; 心跳回应

; ---- flags / ACK 结果码 ----
%define ACK_OK          0x00
%define ACK_ERR_CRED    0x01    ; 认证失败
%define ACK_ERR_EXIST   0x02    ; 用户已存在
%define ACK_ERR_NOUSER  0x03    ; 目标用户不存在
%define ACK_ERR_RATE    0x04    ; 限速
%define ACK_ERR_FULL    0x05    ; 服务器满

; ---- 帧尺寸常量 ----
%define FRAME_HDR       4       ; type(1)+flags(1)+len(2)
%define NONCE_LEN       8       ; 每帧 nonce 大小
%define MAX_PAYLOAD     4096    ; 最大 payload（不含 nonce）
%define PUBKEY_LEN      32      ; X25519 公钥长度
%define SHARED_LEN      32      ; X25519 共享密钥长度

; ---- 帧头偏移 ----
%define F_TYPE          0
%define F_FLAGS         1
%define F_LEN           2       ; 16-bit LE，包含 nonce（若加密帧）

; ---- client_state 布局（扩展自 v3）----
%define CS_FD           0       ; dword
%define CS_FLAGS        4       ; dword: bit0=已登录, bit1=已完成握手
%define CS_USER_IDX     8       ; dword: -1=未登录
%define CS_TX_NONCE     16      ; qword: 发送计数器
%define CS_RX_NONCE     24      ; qword: 接收计数器
%define CS_SHARED       32      ; 32 bytes: X25519 共享密钥（session key）
%define CS_BUF_LEN      64      ; dword: 接收缓冲区已用字节数
%define CS_BUF          68      ; byte[]: 接收缓冲区
%define CS_BUF_SIZE     4096
%define CS_SIZE         (68 + CS_BUF_SIZE)

; ---- CS_FLAGS 位定义 ----
%define CSF_LOGGED_IN   0x01
%define CSF_HANDSHAKED  0x02
