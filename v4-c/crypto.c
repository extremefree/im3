/*
 * crypto.c — ChaCha20 流加密（RFC 8439）C 实现
 */
#include <stdint.h>
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void quarter_round(uint32_t s[16], int a, int b, int c, int d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d],  8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b],  7);
}

/* chacha20_block(out[64], key[32], nonce[12], counter) */
void chacha20_block(uint8_t *out, const uint8_t *key,
                    const uint8_t *nonce, uint32_t counter) {
    static const uint8_t sigma[16] = "expand 32-byte k";
    uint32_t state[16], init[16];

    /* 常量 */
    memcpy(&state[0], sigma, 16);
    /* key */
    memcpy(&state[4], key, 32);
    /* counter */
    state[12] = counter;
    /* nonce */
    memcpy(&state[13], nonce, 12);

    memcpy(init, state, 64);

    for (int i = 0; i < 10; i++) {
        /* 列 */
        quarter_round(state, 0, 4, 8,  12);
        quarter_round(state, 1, 5, 9,  13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        /* 对角 */
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7,  8, 13);
        quarter_round(state, 3, 4,  9, 14);
    }

    for (int i = 0; i < 16; i++)
        state[i] += init[i];

    /* 小端输出 */
    for (int i = 0; i < 16; i++) {
        out[i*4 + 0] = (uint8_t)(state[i]);
        out[i*4 + 1] = (uint8_t)(state[i] >> 8);
        out[i*4 + 2] = (uint8_t)(state[i] >> 16);
        out[i*4 + 3] = (uint8_t)(state[i] >> 24);
    }
}

/*
 * chacha20_encrypt(out, in, len, key[32], nonce[8], ctr_start)
 * nonce[8]：8字节，布局为 chacha_nonce = [0x00000000 || nonce[0..7]]
 */
void chacha20_encrypt(uint8_t *out, const uint8_t *in, int len,
                      const uint8_t *key, const uint8_t *nonce8,
                      uint64_t ctr_start) {
    uint8_t keystream[64];
    uint8_t nonce12[12];
    nonce12[0] = nonce12[1] = nonce12[2] = nonce12[3] = 0;
    memcpy(nonce12 + 4, nonce8, 8);

    uint32_t block_ctr = (uint32_t)ctr_start;
    int offset = 0;
    while (offset < len) {
        chacha20_block(keystream, key, nonce12, block_ctr);
        int n = len - offset;
        if (n > 64) n = 64;
        for (int i = 0; i < n; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];
        offset += n;
        block_ctr++;
    }
}
