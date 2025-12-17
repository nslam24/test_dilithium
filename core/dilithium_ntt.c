/*
 * dilithium_ntt.c - Optimized NTT implementation for Dilithium
 * 
 * Based on the official CRYSTALS-Dilithium reference implementation
 * This library provides C implementations of NTT operations
 * for use with the Python Dilithium implementation via ctypes.
 */

#include <stdint.h>
#include <string.h>
#include "fips202.h"

#define DILITHIUM_N 256
#define DILITHIUM_Q 8380417
#define MONT -4186625  // 2^32 % Q
#define QINV 58728449  // q^(-1) mod 2^32

// Polynomial structure matching Python expectations
typedef struct {
    int32_t coeffs[DILITHIUM_N];
} poly;

// Precomputed twiddle factors (from official Dilithium implementation)
static const int32_t zetas[DILITHIUM_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
*              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
static inline int32_t montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int64_t)(int32_t)a * QINV;
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;
    return t;
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
static inline int32_t reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q;
    return t;
}

/*************************************************
* Name:        caddq
*
* Description: Add Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
static inline int32_t caddq(int32_t a) {
    a += (a >> 31) & DILITHIUM_Q;
    return a;
}

/*************************************************
* Name:        poly_reduce
*
* Description: Reduce all coefficients modulo Q to canonical range [0, Q)
*
* Arguments:   - poly *a: input/output polynomial
**************************************************/
void poly_reduce(poly *a) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_N; ++i) {
        a->coeffs[i] = reduce32(a->coeffs[i]);
        a->coeffs[i] = caddq(a->coeffs[i]);
    }
}

/*************************************************
* Name:        poly_ntt
*
* Description: Forward NTT, in-place. No modular reduction is performed after
*              additions or subtractions. Output vector is in bitreversed order.
*
* Arguments:   - poly *a: input/output coefficient array
**************************************************/
void poly_ntt(poly *a) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for(len = 128; len > 0; len >>= 1) {
        for(start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = zetas[++k];
            for(j = start; j < start + len; ++j) {
                t = montgomery_reduce((int64_t)zeta * a->coeffs[j + len]);
                a->coeffs[j + len] = a->coeffs[j] - t;
                a->coeffs[j] = a->coeffs[j] + t;
            }
        }
    }
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
*              In-place. No modular reductions after additions or
*              subtractions; input coefficients need to be smaller than
*              Q in absolute value. Output coefficient are smaller than Q in
*              absolute value.
*
* Arguments:   - poly *a: input/output coefficient array
**************************************************/
void poly_invntt_tomont(poly *a) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978; // mont^2/256

    k = 256;
    for(len = 1; len < DILITHIUM_N; len <<= 1) {
        for(start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = -zetas[--k];
            for(j = start; j < start + len; ++j) {
                t = a->coeffs[j];
                a->coeffs[j] = t + a->coeffs[j + len];
                a->coeffs[j + len] = t - a->coeffs[j + len];
                a->coeffs[j + len] = montgomery_reduce((int64_t)zeta * a->coeffs[j + len]);
            }
        }
    }

    for(j = 0; j < DILITHIUM_N; ++j) {
        a->coeffs[j] = montgomery_reduce((int64_t)f * a->coeffs[j]);
    }
}

/*************************************************
* Name:        poly_pointwise_montgomery
*
* Description: Pointwise multiplication in NTT domain
*
* Arguments:   - poly *c: output polynomial
*              - const poly *a: first input polynomial
*              - const poly *b: second input polynomial
**************************************************/
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
    unsigned int i;
    for(i = 0; i < DILITHIUM_N; ++i) {
        c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, Q-1] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while(ctr < len && pos + 3 <= buflen) {
        t  = buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF;

        if(t < DILITHIUM_Q)
            a[ctr++] = t;
    }

    return ctr;
}

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling on the
*              output stream of SHAKE128(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length 32
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#define POLY_UNIFORM_NBLOCKS ((768 + SHAKE128_RATE - 1)/SHAKE128_RATE)
void poly_uniform(poly *a,
                  const uint8_t seed[32],
                  uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS*SHAKE128_RATE;
    uint8_t buf[POLY_UNIFORM_NBLOCKS*SHAKE128_RATE + 2];
    keccak_state state;

    shake128_init(&state);
    shake128_absorb(&state, seed, 32);
    shake128_absorb(&state, (uint8_t *)&nonce, 2);
    shake128_finalize(&state);
    shake128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

    ctr = rej_uniform(a->coeffs, DILITHIUM_N, buf, buflen);

    while(ctr < DILITHIUM_N) {
        off = buflen % 3;
        for(i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        shake128_squeezeblocks(buf + off, 1, &state);
        buflen = SHAKE128_RATE + off;
        ctr += rej_uniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
    }
}

/*************************************************
* Name:        expand_a_row
*
* Description: Expand one row of the matrix A from seed rho
*
* Arguments:   - poly *row: pointer to output polynomial array (L elements)
*              - const uint8_t rho[32]: seed
*              - uint8_t i: row index
*              - unsigned int L: number of columns
**************************************************/
void expand_a_row(poly *row, const uint8_t rho[32], uint8_t i, unsigned int L) {
    unsigned int j;
    for(j = 0; j < L; ++j) {
        uint16_t nonce = (i << 8) | j;
        poly_uniform(&row[j], rho, nonce);
    }
}

/*************************************************
* Name:        expand_a
*
* Description: Expand matrix A from seed rho according to FIPS 204.
*              Generates a K×L matrix of polynomials using SHAKE-128.
*
* Arguments:   - poly *A: pointer to output matrix (K*L elements, row-major)
*              - const uint8_t rho[32]: 32-byte seed
*              - unsigned int K: number of rows
*              - unsigned int L: number of columns
**************************************************/
void expand_a(poly *A, const uint8_t rho[32], unsigned int K, unsigned int L) {
    unsigned int i;
    for(i = 0; i < K; ++i) {
        expand_a_row(&A[i * L], rho, i, L);
    }
}
