/*
 * Dimensional Encryption — C Reference Implementation
 *
 * Optimized for performance benchmarking.
 * Implements DE-256-Fast (k=8, dimensions 1,2,3,4,6 — no EC).
 *
 * Dependencies: OpenSSL (libcrypto) for HMAC-SHA256/HKDF, BLAKE3 for Dim 4.
 *
 * Authors: Ali Vonk, M
 * License: Proprietary — SilentBot
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <blake3.h>

#define BLOCK_SIZE 32
#define NONCE_SIZE 16
#define HEADER_SIZE 25
#define TAG_SIZE 32
#define MAX_LAYERS 8

/* ===================================================================
 * Deterministic PRNG (SHAKE-256 based, matches Python implementation)
 * We use HMAC-SHA256 in counter mode as a simpler portable alternative.
 * =================================================================== */

typedef struct {
    uint8_t seed[32];
    uint8_t buffer[4096];
    int buf_len;
    int buf_pos;
    uint32_t counter;
} DPRNG;

static void dprng_init(DPRNG *rng, const uint8_t *seed, int seed_len) {
    /* Hash the seed to get a 32-byte internal state */
    unsigned int len = 32;
    HMAC(EVP_sha256(), "DPRNG", 5, seed, seed_len, rng->seed, &len);
    rng->counter = 0;
    rng->buf_len = 0;
    rng->buf_pos = 0;
}

static void dprng_fill_buffer(DPRNG *rng) {
    /* Generate a block of pseudorandom bytes using HMAC in counter mode */
    int pos = 0;
    while (pos < 4096) {
        uint8_t input[36];
        memcpy(input, rng->seed, 32);
        input[32] = (rng->counter >> 24) & 0xFF;
        input[33] = (rng->counter >> 16) & 0xFF;
        input[34] = (rng->counter >> 8) & 0xFF;
        input[35] = rng->counter & 0xFF;

        unsigned int len = 32;
        HMAC(EVP_sha256(), "DPRNG-expand", 12, input, 36,
             rng->buffer + pos, &len);
        pos += 32;
        rng->counter++;
    }
    rng->buf_len = 4096;
    rng->buf_pos = 0;
}

static void dprng_read(DPRNG *rng, uint8_t *out, int n) {
    int remaining = n;
    while (remaining > 0) {
        if (rng->buf_pos >= rng->buf_len) {
            dprng_fill_buffer(rng);
        }
        int avail = rng->buf_len - rng->buf_pos;
        int chunk = remaining < avail ? remaining : avail;
        memcpy(out + (n - remaining), rng->buffer + rng->buf_pos, chunk);
        rng->buf_pos += chunk;
        remaining -= chunk;
    }
}

static int dprng_read_int(DPRNG *rng, int modulus) {
    if (modulus <= 1) return 0;
    int byte_count = 4; /* Use 4 bytes for rejection sampling */
    uint8_t raw[4];
    uint32_t limit = (0xFFFFFFFF / modulus) * modulus;
    uint32_t val;
    do {
        dprng_read(rng, raw, 4);
        val = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) |
              ((uint32_t)raw[2] << 8) | raw[3];
    } while (val >= limit);
    return val % modulus;
}

/* ===================================================================
 * Dimension 1: SPN (Substitution-Permutation Network)
 * =================================================================== */

typedef struct {
    uint8_t sbox[256];
    uint8_t inv_sbox[256];
    uint8_t perm[BLOCK_SIZE];
    uint8_t inv_perm[BLOCK_SIZE];
    uint8_t round_keys[14][BLOCK_SIZE]; /* max 14 rounds */
    int num_rounds;
} SPN_State;

static void spn_init(SPN_State *s, const uint8_t *key) {
    DPRNG rng;
    dprng_init(&rng, key, BLOCK_SIZE);

    /* Generate S-box via Fisher-Yates */
    for (int i = 0; i < 256; i++) s->sbox[i] = i;
    for (int i = 255; i > 0; i--) {
        int j = dprng_read_int(&rng, i + 1);
        uint8_t tmp = s->sbox[i];
        s->sbox[i] = s->sbox[j];
        s->sbox[j] = tmp;
    }
    for (int i = 0; i < 256; i++) s->inv_sbox[s->sbox[i]] = i;

    /* Generate byte permutation */
    for (int i = 0; i < BLOCK_SIZE; i++) s->perm[i] = i;
    for (int i = BLOCK_SIZE - 1; i > 0; i--) {
        int j = dprng_read_int(&rng, i + 1);
        uint8_t tmp = s->perm[i];
        s->perm[i] = s->perm[j];
        s->perm[j] = tmp;
    }
    for (int i = 0; i < BLOCK_SIZE; i++) s->inv_perm[s->perm[i]] = i;

    /* Generate round keys */
    s->num_rounds = 10;
    for (int r = 0; r < s->num_rounds; r++) {
        dprng_read(&rng, s->round_keys[r], BLOCK_SIZE);
    }
}

static void spn_mix(uint8_t *state) {
    uint8_t tmp[BLOCK_SIZE];
    int half = BLOCK_SIZE / 2;
    memcpy(tmp, state, BLOCK_SIZE);
    /* Feistel-style mix */
    for (int i = 0; i < half; i++)
        tmp[i] = state[i] ^ state[half + ((i + 1) % half)];
    for (int i = 0; i < half; i++)
        tmp[half + i] = state[half + i] ^ tmp[(i + 3) % half];
    memcpy(state, tmp, BLOCK_SIZE);
}

static void spn_inv_mix(uint8_t *state) {
    uint8_t tmp[BLOCK_SIZE];
    int half = BLOCK_SIZE / 2;
    memcpy(tmp, state, BLOCK_SIZE);
    /* Undo round 2 */
    for (int i = 0; i < half; i++)
        tmp[half + i] = state[half + i] ^ state[(i + 3) % half];
    /* Undo round 1 */
    for (int i = 0; i < half; i++)
        tmp[i] = state[i] ^ tmp[half + ((i + 1) % half)];
    memcpy(state, tmp, BLOCK_SIZE);
}

static void spn_transform(const SPN_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE], tmp[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);

    for (int r = 0; r < s->num_rounds; r++) {
        /* Substitute */
        for (int i = 0; i < BLOCK_SIZE; i++) state[i] = s->sbox[state[i]];
        /* Permute */
        for (int i = 0; i < BLOCK_SIZE; i++) tmp[i] = state[s->perm[i]];
        memcpy(state, tmp, BLOCK_SIZE);
        /* Mix */
        spn_mix(state);
        /* Add round key */
        for (int i = 0; i < BLOCK_SIZE; i++) state[i] ^= s->round_keys[r][i];
    }
    memcpy(out, state, BLOCK_SIZE);
}

static void spn_inverse(const SPN_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE], tmp[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);

    for (int r = s->num_rounds - 1; r >= 0; r--) {
        for (int i = 0; i < BLOCK_SIZE; i++) state[i] ^= s->round_keys[r][i];
        spn_inv_mix(state);
        for (int i = 0; i < BLOCK_SIZE; i++) tmp[i] = state[s->inv_perm[i]];
        memcpy(state, tmp, BLOCK_SIZE);
        for (int i = 0; i < BLOCK_SIZE; i++) state[i] = s->inv_sbox[state[i]];
    }
    memcpy(out, state, BLOCK_SIZE);
}

/* ===================================================================
 * Dimension 2: Lattice (invertible matrix multiply mod 256)
 * =================================================================== */

typedef struct {
    uint8_t matrix[BLOCK_SIZE][BLOCK_SIZE];
    uint8_t inv_matrix[BLOCK_SIZE][BLOCK_SIZE];
    uint8_t offset[BLOCK_SIZE];
} Lattice_State;

static int mod_inverse_256(int a) {
    /* Extended Euclidean for inverse mod 256 (a must be odd) */
    int t = 0, newt = 1, r = 256, newr = a % 256;
    while (newr != 0) {
        int q = r / newr;
        int tmp = t - q * newt; t = newt; newt = tmp;
        tmp = r - q * newr; r = newr; newr = tmp;
    }
    return ((t % 256) + 256) % 256;
}

static void lattice_init(Lattice_State *s, const uint8_t *key) {
    DPRNG rng;
    dprng_init(&rng, key, BLOCK_SIZE);
    int n = BLOCK_SIZE;

    /* Generate invertible matrix via row operations on identity */
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            s->matrix[i][j] = (i == j) ? 1 : 0;

    int num_ops = n * 4;
    for (int op = 0; op < num_ops; op++) {
        int type = dprng_read_int(&rng, 3);
        int r1 = dprng_read_int(&rng, n);
        int r2 = dprng_read_int(&rng, n - 1);
        if (r2 >= r1) r2++;
        int scale = dprng_read_int(&rng, 128) * 2 + 1; /* odd */

        if (type == 0) {
            for (int j = 0; j < n; j++)
                s->matrix[r1][j] = (s->matrix[r1][j] + scale * s->matrix[r2][j]) & 0xFF;
        } else if (type == 1) {
            uint8_t tmp[BLOCK_SIZE];
            memcpy(tmp, s->matrix[r1], n);
            memcpy(s->matrix[r1], s->matrix[r2], n);
            memcpy(s->matrix[r2], tmp, n);
        } else {
            for (int j = 0; j < n; j++)
                s->matrix[r1][j] = (s->matrix[r1][j] * scale) & 0xFF;
        }
    }

    /* Compute inverse via Gaussian elimination mod 256 */
    uint8_t aug[BLOCK_SIZE][BLOCK_SIZE * 2];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) aug[i][j] = s->matrix[i][j];
        for (int j = 0; j < n; j++) aug[i][n + j] = (i == j) ? 1 : 0;
    }

    for (int col = 0; col < n; col++) {
        /* Find odd pivot */
        int pivot = -1;
        for (int row = col; row < n; row++) {
            if (aug[row][col] & 1) { pivot = row; break; }
        }
        if (pivot != col) {
            for (int j = 0; j < 2 * n; j++) {
                uint8_t tmp = aug[col][j];
                aug[col][j] = aug[pivot][j];
                aug[pivot][j] = tmp;
            }
        }

        int inv = mod_inverse_256(aug[col][col]);
        for (int j = 0; j < 2 * n; j++)
            aug[col][j] = (aug[col][j] * inv) & 0xFF;

        for (int row = 0; row < n; row++) {
            if (row == col) continue;
            int factor = aug[row][col];
            for (int j = 0; j < 2 * n; j++)
                aug[row][j] = (aug[row][j] - factor * aug[col][j]) & 0xFF;
        }
    }

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            s->inv_matrix[i][j] = aug[i][n + j];

    dprng_read(&rng, s->offset, BLOCK_SIZE);
}

static void lattice_mat_vec(const uint8_t mat[BLOCK_SIZE][BLOCK_SIZE],
                            const uint8_t *vec, uint8_t *out) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint32_t sum = 0;
        for (int j = 0; j < BLOCK_SIZE; j++)
            sum += (uint32_t)mat[i][j] * vec[j];
        out[i] = sum & 0xFF;
    }
}

static void lattice_transform(const Lattice_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t tmp[BLOCK_SIZE];
    lattice_mat_vec(s->matrix, in, tmp);
    for (int i = 0; i < BLOCK_SIZE; i++)
        out[i] = (tmp[i] + s->offset[i]) & 0xFF;
}

static void lattice_inverse(const Lattice_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t tmp[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++)
        tmp[i] = (in[i] - s->offset[i]) & 0xFF;
    lattice_mat_vec(s->inv_matrix, tmp, out);
}

/* ===================================================================
 * Dimension 3: Permutation Group
 * =================================================================== */

typedef struct {
    uint8_t perms[8][BLOCK_SIZE];
    uint8_t inv_perms[8][BLOCK_SIZE];
    uint8_t xor_keys[8][BLOCK_SIZE];
    int num_cycles;
} Perm_State;

static void perm_init(Perm_State *s, const uint8_t *key) {
    DPRNG rng;
    dprng_init(&rng, key, BLOCK_SIZE);
    s->num_cycles = 8;

    for (int c = 0; c < s->num_cycles; c++) {
        for (int i = 0; i < BLOCK_SIZE; i++) s->perms[c][i] = i;
        for (int i = BLOCK_SIZE - 1; i > 0; i--) {
            int j = dprng_read_int(&rng, i + 1);
            uint8_t tmp = s->perms[c][i];
            s->perms[c][i] = s->perms[c][j];
            s->perms[c][j] = tmp;
        }
        for (int i = 0; i < BLOCK_SIZE; i++)
            s->inv_perms[c][s->perms[c][i]] = i;
        dprng_read(&rng, s->xor_keys[c], BLOCK_SIZE);
    }
}

static void perm_transform(const Perm_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE], tmp[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);

    for (int c = 0; c < s->num_cycles; c++) {
        for (int i = 0; i < BLOCK_SIZE; i++) tmp[i] = state[s->perms[c][i]];
        for (int i = 0; i < BLOCK_SIZE; i++) state[i] = tmp[i] ^ s->xor_keys[c][i];
    }
    memcpy(out, state, BLOCK_SIZE);
}

static void perm_inverse(const Perm_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE], tmp[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);

    for (int c = s->num_cycles - 1; c >= 0; c--) {
        for (int i = 0; i < BLOCK_SIZE; i++) state[i] ^= s->xor_keys[c][i];
        for (int i = 0; i < BLOCK_SIZE; i++) tmp[i] = state[s->inv_perms[c][i]];
        memcpy(state, tmp, BLOCK_SIZE);
    }
    memcpy(out, state, BLOCK_SIZE);
}

/* ===================================================================
 * Dimension 4: Hash-Feistel (4-round Feistel with HMAC-SHA256)
 * =================================================================== */

static void hash_feistel_round(const uint8_t *key, const uint8_t *right,
                                int round_num, uint8_t *h_out) {
    /* BLAKE3 keyed hash — native PRF mode, much faster than HMAC-SHA256 */
    uint8_t input[BLOCK_SIZE / 2 + 4];
    memcpy(input, right, BLOCK_SIZE / 2);
    input[BLOCK_SIZE / 2]     = (round_num >> 24) & 0xFF;
    input[BLOCK_SIZE / 2 + 1] = (round_num >> 16) & 0xFF;
    input[BLOCK_SIZE / 2 + 2] = (round_num >> 8) & 0xFF;
    input[BLOCK_SIZE / 2 + 3] = round_num & 0xFF;

    /* BLAKE3 keyed mode requires exactly 32-byte key */
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key);
    blake3_hasher_update(&hasher, input, BLOCK_SIZE / 2 + 4);
    uint8_t full_hash[32];
    blake3_hasher_finalize(&hasher, full_hash, 32);
    memcpy(h_out, full_hash, BLOCK_SIZE / 2);
}

static void hash_transform(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);
    int half = BLOCK_SIZE / 2;

    for (int r = 0; r < 4; r++) {
        uint8_t h[BLOCK_SIZE / 2];
        hash_feistel_round(key, state + half, r, h);  /* h = H(right) */
        uint8_t new_left[BLOCK_SIZE / 2];
        for (int i = 0; i < half; i++)
            new_left[i] = state[i] ^ h[i];            /* new_left = left ^ H(right) */
        /* state = right || new_left */
        memmove(state, state + half, half);
        memcpy(state + half, new_left, half);
    }
    memcpy(out, state, BLOCK_SIZE);
}

static void hash_inverse(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);
    int half = BLOCK_SIZE / 2;

    for (int r = 3; r >= 0; r--) {
        uint8_t right[BLOCK_SIZE / 2], new_left[BLOCK_SIZE / 2];
        memcpy(right, state, half);
        memcpy(new_left, state + half, half);

        uint8_t h[BLOCK_SIZE / 2];
        hash_feistel_round(key, right, r, h);

        uint8_t left[BLOCK_SIZE / 2];
        for (int i = 0; i < half; i++)
            left[i] = new_left[i] ^ h[i];

        memcpy(state, left, half);
        memcpy(state + half, right, half);
    }
    memcpy(out, state, BLOCK_SIZE);
}

/* ===================================================================
 * Dimension 6: Multivariate Polynomial (affine + nonlinear + affine)
 * =================================================================== */

typedef struct {
    uint8_t S_mat[BLOCK_SIZE][BLOCK_SIZE];
    uint8_t S_inv[BLOCK_SIZE][BLOCK_SIZE];
    uint8_t S_off[BLOCK_SIZE];
    uint8_t T_mat[BLOCK_SIZE][BLOCK_SIZE];
    uint8_t T_inv[BLOCK_SIZE][BLOCK_SIZE];
    uint8_t T_off[BLOCK_SIZE];
} MV_State;

static void mv_generate_invertible_matrix(DPRNG *rng, uint8_t mat[BLOCK_SIZE][BLOCK_SIZE],
                                           uint8_t inv[BLOCK_SIZE][BLOCK_SIZE]) {
    int n = BLOCK_SIZE;
    /* Same approach as lattice: identity + row operations */
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            mat[i][j] = (i == j) ? 1 : 0;

    int num_ops = n * 4;
    for (int op = 0; op < num_ops; op++) {
        int type = dprng_read_int(rng, 3);
        int r1 = dprng_read_int(rng, n);
        int r2 = dprng_read_int(rng, n - 1);
        if (r2 >= r1) r2++;
        int scale = dprng_read_int(rng, 128) * 2 + 1;

        if (type == 0) {
            for (int j = 0; j < n; j++)
                mat[r1][j] = (mat[r1][j] + scale * mat[r2][j]) & 0xFF;
        } else if (type == 1) {
            uint8_t tmp[BLOCK_SIZE];
            memcpy(tmp, mat[r1], n);
            memcpy(mat[r1], mat[r2], n);
            memcpy(mat[r2], tmp, n);
        } else {
            for (int j = 0; j < n; j++)
                mat[r1][j] = (mat[r1][j] * scale) & 0xFF;
        }
    }

    /* Compute inverse */
    uint8_t aug[BLOCK_SIZE][BLOCK_SIZE * 2];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) aug[i][j] = mat[i][j];
        for (int j = 0; j < n; j++) aug[i][n + j] = (i == j) ? 1 : 0;
    }
    for (int col = 0; col < n; col++) {
        int pivot = -1;
        for (int row = col; row < n; row++)
            if (aug[row][col] & 1) { pivot = row; break; }
        if (pivot != col)
            for (int j = 0; j < 2*n; j++) {
                uint8_t tmp = aug[col][j]; aug[col][j] = aug[pivot][j]; aug[pivot][j] = tmp;
            }
        int iv = mod_inverse_256(aug[col][col]);
        for (int j = 0; j < 2*n; j++) aug[col][j] = (aug[col][j] * iv) & 0xFF;
        for (int row = 0; row < n; row++) {
            if (row == col) continue;
            int f = aug[row][col];
            for (int j = 0; j < 2*n; j++) aug[row][j] = (aug[row][j] - f * aug[col][j]) & 0xFF;
        }
    }
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            inv[i][j] = aug[i][n + j];
}

static void mv_init(MV_State *s, const uint8_t *key) {
    DPRNG rng;
    dprng_init(&rng, key, BLOCK_SIZE);
    mv_generate_invertible_matrix(&rng, s->T_mat, s->T_inv);
    dprng_read(&rng, s->T_off, BLOCK_SIZE);
    mv_generate_invertible_matrix(&rng, s->S_mat, s->S_inv);
    dprng_read(&rng, s->S_off, BLOCK_SIZE);
}

static void mv_nonlinear(uint8_t *vec) {
    int half = BLOCK_SIZE / 2;
    for (int i = 0; i < half; i++) {
        uint8_t s = (vec[half + i] * vec[half + i] + vec[half + i]) & 0xFF;
        vec[i] ^= s;
    }
    for (int i = 0; i < half; i++) {
        uint8_t s = (vec[i] * vec[i] + vec[i]) & 0xFF;
        vec[half + i] ^= s;
    }
}

static void mv_nonlinear_inv(uint8_t *vec) {
    int half = BLOCK_SIZE / 2;
    for (int i = 0; i < half; i++) {
        uint8_t s = (vec[i] * vec[i] + vec[i]) & 0xFF;
        vec[half + i] ^= s;
    }
    for (int i = 0; i < half; i++) {
        uint8_t s = (vec[half + i] * vec[half + i] + vec[half + i]) & 0xFF;
        vec[i] ^= s;
    }
}

static void mv_affine_apply(const uint8_t mat[BLOCK_SIZE][BLOCK_SIZE],
                             const uint8_t *off, const uint8_t *in, uint8_t *out) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint32_t sum = off[i];
        for (int j = 0; j < BLOCK_SIZE; j++)
            sum += (uint32_t)mat[i][j] * in[j];
        out[i] = sum & 0xFF;
    }
}

static void mv_transform(const MV_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t tmp[BLOCK_SIZE];
    mv_affine_apply(s->T_mat, s->T_off, in, tmp);
    mv_nonlinear(tmp);
    mv_affine_apply(s->S_mat, s->S_off, tmp, out);
}

static void mv_inverse(const MV_State *s, const uint8_t *in, uint8_t *out) {
    uint8_t tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE];
    /* Undo S */
    for (int i = 0; i < BLOCK_SIZE; i++) tmp[i] = (in[i] - s->S_off[i]) & 0xFF;
    uint8_t zero[BLOCK_SIZE] = {0};
    mv_affine_apply(s->S_inv, zero, tmp, tmp2);
    /* Undo nonlinear */
    mv_nonlinear_inv(tmp2);
    /* Undo T */
    for (int i = 0; i < BLOCK_SIZE; i++) tmp[i] = (tmp2[i] - s->T_off[i]) & 0xFF;
    mv_affine_apply(s->T_inv, zero, tmp, out);
}

/* ===================================================================
 * Layer management
 * =================================================================== */

typedef struct {
    int dim_id;
    uint8_t key[BLOCK_SIZE];
    /* Pre-initialized states for each dimension */
    SPN_State spn;
    Lattice_State lattice;
    Perm_State perm;
    MV_State mv;
    /* dim 4 (hash) uses key directly, no pre-init needed */
} Layer;

typedef struct {
    int num_layers;
    Layer layers[MAX_LAYERS];
} DE_Context;

static const int ALGEBRAIC_DIMS[] = {1, 2, 3, 5, 6};
static const int NUM_ALGEBRAIC = 5;
/* For DE-256-Fast, exclude dim 5 (EC) */
static const int FAST_DIMS[] = {1, 2, 3, 6};
static const int NUM_FAST = 4;

static void hkdf_expand(const uint8_t *prk, int prk_len,
                         const uint8_t *info, int info_len,
                         uint8_t *out, int out_len) {
    int n = (out_len + 31) / 32;
    uint8_t t[32] = {0};
    int t_len = 0;
    int pos = 0;

    for (int i = 1; i <= n; i++) {
        /* T(i) = HMAC(PRK, T(i-1) || info || i) */
        int input_len = t_len + info_len + 1;
        uint8_t *input = malloc(input_len);
        memcpy(input, t, t_len);
        memcpy(input + t_len, info, info_len);
        input[t_len + info_len] = (uint8_t)i;

        unsigned int len = 32;
        HMAC(EVP_sha256(), prk, prk_len, input, input_len, t, &len);
        t_len = 32;
        free(input);

        int chunk = (out_len - pos) < 32 ? (out_len - pos) : 32;
        memcpy(out + pos, t, chunk);
        pos += chunk;
    }
}

static void de_init(DE_Context *ctx, const uint8_t *master_key,
                     const uint8_t *nonce, int num_layers, int fast_mode) {
    ctx->num_layers = num_layers;

    /* HKDF-Extract */
    const char *salt = "DimensionalEncryption-v1";
    unsigned int prk_len = 32;
    uint8_t prk[32];
    HMAC(EVP_sha256(), salt, strlen(salt), master_key, BLOCK_SIZE, prk, &prk_len);

    /* Derive dimension types */
    uint8_t type_bytes[MAX_LAYERS];
    hkdf_expand(prk, 32, (const uint8_t*)"DE-v1-types", 11, type_bytes, num_layers);

    const int *dim_pool = fast_mode ? FAST_DIMS : ALGEBRAIC_DIMS;
    int pool_size = fast_mode ? NUM_FAST : NUM_ALGEBRAIC;

    for (int i = 0; i < num_layers; i++) {
        Layer *l = &ctx->layers[i];

        /* Firewall rule: even positions = hash, odd = algebraic */
        if (i % 2 == 0) {
            l->dim_id = 4;
        } else {
            l->dim_id = dim_pool[type_bytes[i] % pool_size];
        }

        /* Derive layer key */
        char info[64];
        if (i == 0) {
            uint8_t info_buf[64];
            int base_len = snprintf((char*)info_buf, 64, "DE-v1-layer-0");
            memcpy(info_buf + base_len, nonce, NONCE_SIZE);
            hkdf_expand(prk, 32, info_buf, base_len + NONCE_SIZE, l->key, BLOCK_SIZE);
        } else {
            int info_len = snprintf(info, 64, "DE-v1-layer-%d", i);
            hkdf_expand(prk, 32, (const uint8_t*)info, info_len, l->key, BLOCK_SIZE);
        }

        /* Pre-initialize dimension state */
        switch (l->dim_id) {
            case 1: spn_init(&l->spn, l->key); break;
            case 2: lattice_init(&l->lattice, l->key); break;
            case 3: perm_init(&l->perm, l->key); break;
            case 4: break; /* hash uses key directly */
            case 6: mv_init(&l->mv, l->key); break;
        }
    }
}

static void de_encrypt_block(const DE_Context *ctx, const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE], tmp[BLOCK_SIZE];
    memcpy(state, in, BLOCK_SIZE);

    for (int i = 0; i < ctx->num_layers; i++) {
        const Layer *l = &ctx->layers[i];
        switch (l->dim_id) {
            case 1: spn_transform(&l->spn, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
            case 2: lattice_transform(&l->lattice, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
            case 3: perm_transform(&l->perm, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
            case 4: hash_transform(l->key, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
            case 6: mv_transform(&l->mv, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
        }
    }
    memcpy(out, state, BLOCK_SIZE);
}

/* ===================================================================
 * CTR Mode
 * =================================================================== */

static void de_ctr_encrypt(const DE_Context *ctx, const uint8_t *nonce,
                            const uint8_t *plaintext, int pt_len,
                            uint8_t *ciphertext) {
    int num_blocks = (pt_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (int i = 0; i < num_blocks; i++) {
        /* Build counter block: nonce || counter */
        uint8_t counter_block[BLOCK_SIZE];
        memcpy(counter_block, nonce, NONCE_SIZE);
        uint32_t ctr = i + 1;
        memset(counter_block + NONCE_SIZE, 0, NONCE_SIZE - 4);
        counter_block[BLOCK_SIZE - 4] = (ctr >> 24) & 0xFF;
        counter_block[BLOCK_SIZE - 3] = (ctr >> 16) & 0xFF;
        counter_block[BLOCK_SIZE - 2] = (ctr >> 8) & 0xFF;
        counter_block[BLOCK_SIZE - 1] = ctr & 0xFF;

        uint8_t keystream[BLOCK_SIZE];
        de_encrypt_block(ctx, counter_block, keystream);

        int block_start = i * BLOCK_SIZE;
        int block_len = (pt_len - block_start) < BLOCK_SIZE ? (pt_len - block_start) : BLOCK_SIZE;

        for (int j = 0; j < block_len; j++)
            ciphertext[block_start + j] = plaintext[block_start + j] ^ keystream[j];
    }
}

/* ===================================================================
 * Benchmark
 * =================================================================== */

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static void benchmark_block_cipher(int num_layers, int fast_mode) {
    uint8_t master_key[BLOCK_SIZE], nonce[NONCE_SIZE];
    RAND_bytes(master_key, BLOCK_SIZE);
    RAND_bytes(nonce, NONCE_SIZE);

    DE_Context ctx;
    de_init(&ctx, master_key, nonce, num_layers, fast_mode);

    /* Print layer config */
    printf("  Layers: ");
    for (int i = 0; i < ctx.num_layers; i++) {
        const char *names[] = {"", "SPN", "Lat", "Prm", "Hsh", "EC", "MV"};
        printf("%s", names[ctx.layers[i].dim_id]);
        if (i < ctx.num_layers - 1) printf("->");
    }
    printf("\n");

    /* Warm up */
    uint8_t block[BLOCK_SIZE], out[BLOCK_SIZE];
    RAND_bytes(block, BLOCK_SIZE);
    for (int i = 0; i < 100; i++)
        de_encrypt_block(&ctx, block, out);

    /* Benchmark single blocks */
    int iterations = 10000;
    double start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        de_encrypt_block(&ctx, block, out);
        memcpy(block, out, BLOCK_SIZE); /* prevent optimization */
    }
    double elapsed = get_time_ms() - start;
    double blocks_per_sec = iterations / (elapsed / 1000.0);
    double mb_per_sec = blocks_per_sec * BLOCK_SIZE / (1024.0 * 1024.0);
    double us_per_block = elapsed * 1000.0 / iterations;

    printf("  Block cipher:  %8.1f blocks/s  |  %6.2f MB/s  |  %.2f us/block\n",
           blocks_per_sec, mb_per_sec, us_per_block);

    /* Benchmark CTR mode (1 KB message) */
    uint8_t pt[1024], ct[1024];
    RAND_bytes(pt, 1024);

    iterations = 5000;
    start = get_time_ms();
    for (int i = 0; i < iterations; i++)
        de_ctr_encrypt(&ctx, nonce, pt, 1024, ct);
    elapsed = get_time_ms() - start;
    double throughput = (iterations * 1024.0) / (elapsed / 1000.0) / (1024.0 * 1024.0);

    printf("  CTR 1KB:       %8.1f ops/s    |  %6.2f MB/s\n",
           iterations / (elapsed / 1000.0), throughput);

    /* Benchmark CTR mode (64 KB message) */
    int big_size = 65536;
    uint8_t *big_pt = malloc(big_size);
    uint8_t *big_ct = malloc(big_size);
    RAND_bytes(big_pt, big_size);

    iterations = 100;
    start = get_time_ms();
    for (int i = 0; i < iterations; i++)
        de_ctr_encrypt(&ctx, nonce, big_pt, big_size, big_ct);
    elapsed = get_time_ms() - start;
    throughput = (iterations * (double)big_size) / (elapsed / 1000.0) / (1024.0 * 1024.0);

    printf("  CTR 64KB:      %8.1f ops/s    |  %6.2f MB/s\n",
           iterations / (elapsed / 1000.0), throughput);

    free(big_pt);
    free(big_ct);
}

static void correctness_test(void) {
    printf("\n--- Correctness Test ---\n");
    uint8_t master_key[BLOCK_SIZE], nonce[NONCE_SIZE];
    RAND_bytes(master_key, BLOCK_SIZE);
    RAND_bytes(nonce, NONCE_SIZE);

    DE_Context ctx;
    de_init(&ctx, master_key, nonce, 8, 1);

    /* Test block encrypt/decrypt roundtrip */
    /* Note: C implementation uses different PRNG than Python, so test vectors
       won't match. But roundtrip correctness is verified. */
    int passed = 0, total = 20;
    for (int t = 0; t < total; t++) {
        uint8_t block[BLOCK_SIZE], encrypted[BLOCK_SIZE], decrypted[BLOCK_SIZE];
        RAND_bytes(block, BLOCK_SIZE);

        /* Encrypt */
        de_encrypt_block(&ctx, block, encrypted);

        /* Decrypt (apply inverses in reverse) */
        uint8_t state[BLOCK_SIZE], tmp[BLOCK_SIZE];
        memcpy(state, encrypted, BLOCK_SIZE);
        for (int i = ctx.num_layers - 1; i >= 0; i--) {
            const Layer *l = &ctx.layers[i];
            switch (l->dim_id) {
                case 1: spn_inverse(&l->spn, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
                case 2: lattice_inverse(&l->lattice, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
                case 3: perm_inverse(&l->perm, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
                case 4: hash_inverse(l->key, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
                case 6: mv_inverse(&l->mv, state, tmp); memcpy(state, tmp, BLOCK_SIZE); break;
            }
        }

        if (memcmp(block, state, BLOCK_SIZE) == 0) passed++;
    }
    printf("  Roundtrip: %d/%d passed\n", passed, total);
}

int main(int argc, char **argv) {
    printf("================================================================\n");
    printf("DIMENSIONAL ENCRYPTION — C PERFORMANCE BENCHMARK\n");
    printf("================================================================\n");
    printf("Block size: %d bytes (%d bits)\n", BLOCK_SIZE, BLOCK_SIZE * 8);
    printf("Platform: ");
    #ifdef __aarch64__
    printf("ARM64 (Apple Silicon)\n");
    #elif defined(__x86_64__)
    printf("x86-64\n");
    #else
    printf("Unknown\n");
    #endif

    correctness_test();

    printf("\n--- DE-256-Fast (k=8, no EC) ---\n");
    benchmark_block_cipher(8, 1);

    printf("\n--- DE-128-Fast (k=6, no EC) ---\n");
    benchmark_block_cipher(6, 1);

    printf("\n--- DE-256-Fast (k=4, no EC) ---\n");
    benchmark_block_cipher(4, 1);

    printf("\n--- Minimal (k=2) ---\n");
    benchmark_block_cipher(2, 1);

    /* Comparison reference: how fast is raw HMAC-SHA256? */
    printf("\n--- Reference: Raw HMAC-SHA256 speed ---\n");
    uint8_t key[32], data[32], mac[32];
    RAND_bytes(key, 32);
    RAND_bytes(data, 32);
    unsigned int mac_len;

    int iterations = 100000;
    double start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        HMAC(EVP_sha256(), key, 32, data, 32, mac, &mac_len);
        data[0] = mac[0]; /* prevent optimization */
    }
    double elapsed = get_time_ms() - start;
    printf("  HMAC-SHA256:   %8.0f ops/s | %.2f us/op\n",
           iterations / (elapsed / 1000.0), elapsed * 1000.0 / iterations);

    printf("\n================================================================\n");
    printf("BENCHMARK COMPLETE\n");
    printf("================================================================\n");

    return 0;
}
