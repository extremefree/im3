#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

/* ---- 帧类型 ---- */
#define PKT_HELLO       0x01
#define PKT_LOGIN       0x02
#define PKT_REGISTER    0x03
#define PKT_MSG         0x04
#define PKT_MAIL        0x05
#define PKT_ACK         0x06
#define PKT_ANNOUNCE    0x07
#define PKT_PING        0x08
#define PKT_PONG        0x09

/* ---- ACK 结果码（存在 flags 字段）---- */
#define ACK_OK          0x00
#define ACK_ERR_CRED    0x01
#define ACK_ERR_EXIST   0x02
#define ACK_ERR_NOUSER  0x03
#define ACK_ERR_RATE    0x04
#define ACK_ERR_FULL    0x05

/* ---- 尺寸常量 ---- */
#define FRAME_HDR       4
#define NONCE_LEN       8
#define MAX_PAYLOAD     4096
#define PUBKEY_LEN      32
#define SHARED_LEN      32

/* ---- 帧头结构 ---- */
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  flags;
    uint16_t len;       /* payload 长度（小端序），加密帧包含 nonce */
} frame_hdr_t;
#pragma pack(pop)

/* ---- 客户端状态标志 ---- */
#define CSF_LOGGED_IN   0x01
#define CSF_HANDSHAKED  0x02

/* ---- 客户端状态（C 版）---- */
typedef struct {
    int      fd;
    uint32_t flags;
    int      user_idx;
    uint8_t  _pad[4];
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    uint8_t  shared[SHARED_LEN];    /* X25519 共享密钥 */
    uint32_t buf_len;
    uint8_t  buf[4096];
} client_state_t;

#endif /* PROTO_H */
