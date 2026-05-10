/*
 * x25519.c — X25519 Diffie-Hellman (Curve25519) C 实现
 *
 * 使用 5×51-bit 有限域表示（GF(2^255-19)）
 * Montgomery ladder（RFC 7748）
 */
#include <stdint.h>
#include <string.h>

typedef uint64_t fe[5];     /* 5 个 51-bit limb */

#define MASK51   ((uint64_t)0x7FFFFFFFFFFFF)
#define A24      121665ULL

/* ---- 域操作 ---- */

static void fe_copy(fe out, const fe in) {
    for (int i = 0; i < 5; i++) out[i] = in[i];
}

static void fe_add(fe out, const fe a, const fe b) {
    for (int i = 0; i < 5; i++) out[i] = a[i] + b[i];
}

static void fe_sub(fe out, const fe a, const fe b) {
    /* a - b + 2p，保持正数 */
    out[0] = a[0] - b[0] + 4503599627370438ULL;
    out[1] = a[1] - b[1] + 4503599627370494ULL;
    out[2] = a[2] - b[2] + 4503599627370494ULL;
    out[3] = a[3] - b[3] + 4503599627370494ULL;
    out[4] = a[4] - b[4] + 4503599627370494ULL;
}

static void fe_reduce(fe out) {
    uint64_t c;
    c = out[0] >> 51; out[0] &= MASK51; out[1] += c;
    c = out[1] >> 51; out[1] &= MASK51; out[2] += c;
    c = out[2] >> 51; out[2] &= MASK51; out[3] += c;
    c = out[3] >> 51; out[3] &= MASK51; out[4] += c;
    c = out[4] >> 51; out[4] &= MASK51; out[0] += c * 19;
}

static void fe_mul(fe out, const fe a, const fe b) {
    /* 5×5 schoolbook，折叠 x19 */
    __uint128_t t[5];

    t[0] = (__uint128_t)a[0]*b[0]
         + (__uint128_t)(a[1]*19)*b[4]
         + (__uint128_t)(a[2]*19)*b[3]
         + (__uint128_t)(a[3]*19)*b[2]
         + (__uint128_t)(a[4]*19)*b[1];

    t[1] = (__uint128_t)a[0]*b[1] + (__uint128_t)a[1]*b[0]
         + (__uint128_t)(a[2]*19)*b[4]
         + (__uint128_t)(a[3]*19)*b[3]
         + (__uint128_t)(a[4]*19)*b[2];

    t[2] = (__uint128_t)a[0]*b[2] + (__uint128_t)a[1]*b[1] + (__uint128_t)a[2]*b[0]
         + (__uint128_t)(a[3]*19)*b[4]
         + (__uint128_t)(a[4]*19)*b[3];

    t[3] = (__uint128_t)a[0]*b[3] + (__uint128_t)a[1]*b[2]
         + (__uint128_t)a[2]*b[1] + (__uint128_t)a[3]*b[0]
         + (__uint128_t)(a[4]*19)*b[4];

    t[4] = (__uint128_t)a[0]*b[4] + (__uint128_t)a[1]*b[3]
         + (__uint128_t)a[2]*b[2] + (__uint128_t)a[3]*b[1]
         + (__uint128_t)a[4]*b[0];

    /* 规约 */
    uint64_t c;
    out[0] = (uint64_t)t[0] & MASK51;
    c = (uint64_t)(t[0] >> 51);
    out[1] = ((uint64_t)t[1] + c) & MASK51;
    c = (uint64_t)((t[1] + c) >> 51);
    out[2] = ((uint64_t)t[2] + c) & MASK51;
    c = (uint64_t)((t[2] + c) >> 51);
    out[3] = ((uint64_t)t[3] + c) & MASK51;
    c = (uint64_t)((t[3] + c) >> 51);
    out[4] = ((uint64_t)t[4] + c) & MASK51;
    c = (uint64_t)((t[4] + c) >> 51);
    out[0] += c * 19;
}

static void fe_sq(fe out, const fe a) {
    fe_mul(out, a, a);
}

static void fe_mul_a24(fe out, const fe a) {
    for (int i = 0; i < 5; i++) out[i] = a[i] * A24;
    fe_reduce(out);
}

static void fe_cswap(fe a, fe b, int cond) {
    if (!cond) return;
    for (int i = 0; i < 5; i++) {
        uint64_t t = a[i]; a[i] = b[i]; b[i] = t;
    }
}

/* ---- 逆元（费马小定理）---- */
static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    /* 参考 agl/ed25519 的 255-2 power chain */
    fe_sq(t0, z);            /* t0 = z^2 */
    fe_sq(t1, t0);           /* t1 = z^4 */
    fe_sq(t1, t1);           /* z^8 */
    fe_mul(t1, t1, z);       /* z^9 */
    fe_mul(t0, t0, t1);      /* z^11 */
    fe_sq(t2, t0);           /* z^22 */
    fe_mul(t2, t2, t1);      /* z^31 = z^(2^5-1) */

    fe_sq(t1, t2);
    for (int i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t2);      /* z^(2^10-1) */

    fe_sq(t3, t1);
    for (int i = 1; i < 10; i++) fe_sq(t3, t3);
    fe_mul(t3, t3, t1);      /* z^(2^20-1) */

    fe_sq(t2, t3);
    for (int i = 1; i < 20; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t3);      /* z^(2^40-1) */

    fe_sq(t2, t2);
    for (int i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);      /* z^(2^50-1) */

    fe_sq(t2, t1);
    for (int i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);      /* z^(2^100-1) */

    fe_sq(t3, t2);
    for (int i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t3, t3, t2);      /* z^(2^200-1) */

    fe_sq(t3, t3);
    for (int i = 1; i < 50; i++) fe_sq(t3, t3);
    fe_mul(t3, t3, t1);      /* z^(2^250-1) */

    fe_sq(t3, t3);
    fe_sq(t3, t3);
    fe_sq(t3, t3);
    fe_sq(t3, t3);
    fe_sq(t3, t3);           /* z^(2^255-32) */
    fe_mul(out, t3, t0);     /* z^(2^255-21) = z^(p-2) */
}

/* ---- 从字节加载（51-bit radix）---- */
static void fe_from_bytes(fe out, const uint8_t *in) {
    out[0] =  ((uint64_t)in[0])
            | ((uint64_t)in[1] << 8)
            | ((uint64_t)in[2] << 16)
            | ((uint64_t)in[3] << 24)
            | ((uint64_t)in[4] << 32)
            | ((uint64_t)in[5] << 40)
            | ((uint64_t)(in[6] & 0x07) << 48);

    out[1] =  ((uint64_t)in[6] >> 3)
            | ((uint64_t)in[7] << 5)
            | ((uint64_t)in[8] << 13)
            | ((uint64_t)in[9] << 21)
            | ((uint64_t)in[10] << 29)
            | ((uint64_t)in[11] << 37)
            | ((uint64_t)(in[12] & 0x3F) << 45);

    out[2] =  ((uint64_t)in[12] >> 6)
            | ((uint64_t)in[13] << 2)
            | ((uint64_t)in[14] << 10)
            | ((uint64_t)in[15] << 18)
            | ((uint64_t)in[16] << 26)
            | ((uint64_t)in[17] << 34)
            | ((uint64_t)in[18] << 42)
            | ((uint64_t)(in[19] & 0x01) << 50);

    out[3] =  ((uint64_t)in[19] >> 1)
            | ((uint64_t)in[20] << 7)
            | ((uint64_t)in[21] << 15)
            | ((uint64_t)in[22] << 23)
            | ((uint64_t)in[23] << 31)
            | ((uint64_t)in[24] << 39)
            | ((uint64_t)(in[25] & 0x0F) << 47);

    out[4] =  ((uint64_t)in[25] >> 4)
            | ((uint64_t)in[26] << 4)
            | ((uint64_t)in[27] << 12)
            | ((uint64_t)in[28] << 20)
            | ((uint64_t)in[29] << 28)
            | ((uint64_t)in[30] << 36)
            | ((uint64_t)(in[31] & 0x7F) << 44);
}

/* ---- 输出到字节 ---- */
static void fe_to_bytes(uint8_t *out, fe h) {
    /* 完全规约 */
    fe_reduce(h);
    /* 再规约一次 */
    fe_reduce(h);

    /* 最终减 p（若 >= p）*/
    uint64_t q = (h[0] + 19) >> 51;
    for (int i = 1; i < 4; i++) q = (h[i] + q) >> 51;
    q = (h[4] + q) >> 51;

    h[0] += 19 * q;
    for (int i = 0; i < 4; i++) {
        uint64_t c = h[i] >> 51;
        h[i] &= MASK51;
        h[i + 1] += c;
    }
    h[4] &= MASK51;

    /* Pack */
    out[0]  = (uint8_t)(h[0]);
    out[1]  = (uint8_t)(h[0] >> 8);
    out[2]  = (uint8_t)(h[0] >> 16);
    out[3]  = (uint8_t)(h[0] >> 24);
    out[4]  = (uint8_t)(h[0] >> 32);
    out[5]  = (uint8_t)(h[0] >> 40);
    out[6]  = (uint8_t)((h[0] >> 48) | (h[1] << 3));
    out[7]  = (uint8_t)(h[1] >> 5);
    out[8]  = (uint8_t)(h[1] >> 13);
    out[9]  = (uint8_t)(h[1] >> 21);
    out[10] = (uint8_t)(h[1] >> 29);
    out[11] = (uint8_t)(h[1] >> 37);
    out[12] = (uint8_t)((h[1] >> 45) | (h[2] << 6));
    out[13] = (uint8_t)(h[2] >> 2);
    out[14] = (uint8_t)(h[2] >> 10);
    out[15] = (uint8_t)(h[2] >> 18);
    out[16] = (uint8_t)(h[2] >> 26);
    out[17] = (uint8_t)(h[2] >> 34);
    out[18] = (uint8_t)(h[2] >> 42);
    out[19] = (uint8_t)((h[2] >> 50) | (h[3] << 1));
    out[20] = (uint8_t)(h[3] >> 7);
    out[21] = (uint8_t)(h[3] >> 15);
    out[22] = (uint8_t)(h[3] >> 23);
    out[23] = (uint8_t)(h[3] >> 31);
    out[24] = (uint8_t)(h[3] >> 39);
    out[25] = (uint8_t)((h[3] >> 47) | (h[4] << 4));
    out[26] = (uint8_t)(h[4] >> 4);
    out[27] = (uint8_t)(h[4] >> 12);
    out[28] = (uint8_t)(h[4] >> 20);
    out[29] = (uint8_t)(h[4] >> 28);
    out[30] = (uint8_t)(h[4] >> 36);
    out[31] = (uint8_t)(h[4] >> 44);
}

/* ================================================================
 * x25519(out[32], scalar[32], point[32])
 * ================================================================ */
void x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe X1, X2, Z2, X3, Z3, A, AA, B, BB, E, C, D, DA, CB;

    fe u;
    uint8_t pt[32];
    memcpy(pt, point, 32);
    pt[31] &= 127;
    fe_from_bytes(u, pt);

    fe_copy(X1, u);
    /* X2=1, Z2=0, X3=u, Z3=1 */
    memset(X2, 0, sizeof(X2)); X2[0] = 1;
    memset(Z2, 0, sizeof(Z2));
    fe_copy(X3, u);
    memset(Z3, 0, sizeof(Z3)); Z3[0] = 1;

    int swap = 0;
    for (int t = 254; t >= 0; t--) {
        int kt = (e[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        fe_cswap(X2, X3, swap);
        fe_cswap(Z2, Z3, swap);
        swap = kt;

        fe_add(A, X2, Z2);
        fe_sq(AA, A);
        fe_sub(B, X2, Z2);
        fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, X3, Z3);
        fe_sub(D, X3, Z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);

        fe_add(X3, DA, CB);
        fe_sq(X3, X3);

        fe_sub(Z3, DA, CB);
        fe_sq(Z3, Z3);
        fe_mul(Z3, Z3, X1);

        fe_mul(X2, AA, BB);

        fe_mul_a24(E, E);
        fe_add(A, AA, E);
        fe_mul(Z2, E, A);
    }
    fe_cswap(X2, X3, swap);
    fe_cswap(Z2, Z3, swap);

    fe_invert(Z2, Z2);
    fe_mul(X2, X2, Z2);
    fe_to_bytes(out, X2);
}

/* ================================================================
 * x25519_base(out[32], scalar[32])  =  x25519(out, scalar, basepoint)
 * ================================================================ */
void x25519_base(uint8_t *out, const uint8_t *scalar) {
    static const uint8_t basepoint[32] = {9};
    x25519(out, scalar, basepoint);
}
