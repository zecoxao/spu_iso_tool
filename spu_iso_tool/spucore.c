#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "spucore.h"

/* XOR two 16-byte blocks: dst = src1 ^ src2 */
static void xor_block16(unsigned char *dst, const unsigned char *src1, const unsigned char *src2)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = src1[i] ^ src2[i];
    }
}

/*
 * Custom AES-128-CTR + CBC-MAC encryption (CCM-style for PS3 containers).
 * The header's first 3 blocks (0x00..0x2F) are authenticated; the resulting
 * tag is written to header[0x30].
 */
int custom_ccm_encrypt(const unsigned char *key,
                       unsigned char *header,
                       const unsigned char *plaintext,
                       unsigned char *ciphertext,
                       size_t body_len)
{
    aes_context ctx;
    unsigned char chain[16];
    unsigned char temp_block[16];
    unsigned char ctr[16];
    unsigned char keystream[16];
    unsigned char s0[16];
    unsigned char tag[16];

    if (body_len % 16 != 0) {
        return POLARSSL_ERR_AES_INVALID_INPUT_LENGTH;
    }

    size_t N = body_len / 16;
    const unsigned char *iv12 = &header[0x04];

    int ret = aes_setkey_enc(&ctx, key, 128);
    if (ret != 0) return ret;

    /* STAGE 1: CBC-MAC over the first 3 header blocks */
    memset(chain, 0, 16);
    for (int j = 0; j < 3; j++) {
        xor_block16(temp_block, &header[16 * j], chain);
        aes_crypt_ecb(&ctx, AES_ENCRYPT, temp_block, chain);
    }

    /* STAGE 2: CBC-MAC over plaintext + AES-CTR encryption */
    memcpy(ctr + 4, iv12, 12);

    for (size_t i = 0; i < N; i++) {
        const unsigned char *pt_ptr = &plaintext[16 * i];
        unsigned char *ct_ptr = &ciphertext[16 * i];

        xor_block16(temp_block, pt_ptr, chain);
        aes_crypt_ecb(&ctx, AES_ENCRYPT, temp_block, chain);

        unsigned int c = (unsigned int)(N - i);
        ctr[0] = (unsigned char)((c >> 24) & 0xFF);
        ctr[1] = (unsigned char)((c >> 16) & 0xFF);
        ctr[2] = (unsigned char)((c >> 8) & 0xFF);
        ctr[3] = (unsigned char)(c & 0xFF);

        aes_crypt_ecb(&ctx, AES_ENCRYPT, ctr, keystream);
        xor_block16(ct_ptr, pt_ptr, keystream);
    }

    /* STAGE 3: final tag masking (S0) and header update */
    memset(ctr, 0, 4);
    memcpy(ctr + 4, iv12, 12);
    aes_crypt_ecb(&ctx, AES_ENCRYPT, ctr, s0);

    xor_block16(tag, chain, s0);
    memcpy(&header[0x30], tag, 16);

    return 0;
}

/*
 * Custom AES-128-CTR + CBC-MAC decryption (CCM-style for PS3 containers).
 * Returns 0 if the recomputed tag matches header[0x30], -1 otherwise.
 */
int custom_ccm_decrypt(const unsigned char *key,
                       const unsigned char *header,
                       const unsigned char *ciphertext,
                       unsigned char *plaintext,
                       size_t body_len)
{
    aes_context ctx;
    unsigned char chain[16];
    unsigned char temp_block[16];
    unsigned char ctr[16];
    unsigned char keystream[16];
    unsigned char s0[16];
    unsigned char computed_tag[16];

    if (body_len % 16 != 0) {
        return POLARSSL_ERR_AES_INVALID_INPUT_LENGTH;
    }

    size_t N = body_len / 16;
    const unsigned char *iv12 = &header[0x04];

    int ret = aes_setkey_enc(&ctx, key, 128);
    if (ret != 0) return ret;

    /* STAGE 1: CBC-MAC over the first 3 header blocks */
    memset(chain, 0, 16);
    for (int j = 0; j < 3; j++) {
        xor_block16(temp_block, &header[16 * j], chain);
        aes_crypt_ecb(&ctx, AES_ENCRYPT, temp_block, chain);
    }

    /* STAGE 2: AES-CTR decryption + CBC-MAC update over recovered plaintext */
    memcpy(ctr + 4, iv12, 12);

    for (size_t i = 0; i < N; i++) {
        unsigned char *pt_ptr = &plaintext[16 * i];
        const unsigned char *ct_ptr = &ciphertext[16 * i];

        unsigned int c = (unsigned int)(N - i);
        ctr[0] = (unsigned char)((c >> 24) & 0xFF);
        ctr[1] = (unsigned char)((c >> 16) & 0xFF);
        ctr[2] = (unsigned char)((c >> 8) & 0xFF);
        ctr[3] = (unsigned char)(c & 0xFF);

        aes_crypt_ecb(&ctx, AES_ENCRYPT, ctr, keystream);
        xor_block16(pt_ptr, ct_ptr, keystream);

        xor_block16(temp_block, pt_ptr, chain);
        aes_crypt_ecb(&ctx, AES_ENCRYPT, temp_block, chain);
    }

    /* STAGE 3: compute final tag mask (S0) and validate */
    memset(ctr, 0, 4);
    memcpy(ctr + 4, iv12, 12);
    aes_crypt_ecb(&ctx, AES_ENCRYPT, ctr, s0);

    xor_block16(computed_tag, chain, s0);

    if (memcmp(computed_tag, &header[0x30], 16) != 0) {
        return -1; /* MAC FAIL */
    }

    return 0; /* MAC PASS */
}

int spu_encrypt_buffer(const unsigned char key[16],
                       const unsigned char iv[12],
                       const unsigned char nonce[12],
                       const unsigned char ekey[16],
                       const unsigned char *plaintext,
                       size_t plaintext_len,
                       unsigned char **out,
                       size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;

    size_t padded_len = (plaintext_len + 15) & ~(size_t)15;
    size_t N = padded_len / 16;
    size_t total = 64 + padded_len;

    unsigned char *padded = (unsigned char *)calloc(1, padded_len ? padded_len : 16);
    unsigned char *container = (unsigned char *)calloc(1, total);
    if (!padded || !container) {
        free(padded);
        free(container);
        return SPU_ERR_ALLOC;
    }
    if (plaintext_len) {
        memcpy(padded, plaintext, plaintext_len);
    }

    unsigned char *header = container; /* header is the first 64 bytes */

    header[0x00] = (unsigned char)((N >> 24) & 0xFF);
    header[0x01] = (unsigned char)((N >> 16) & 0xFF);
    header[0x02] = (unsigned char)((N >> 8) & 0xFF);
    header[0x03] = (unsigned char)(N & 0xFF);

    memcpy(&header[0x04], iv, 12);

    header[0x10] = header[0x00];
    header[0x11] = header[0x01];
    header[0x12] = header[0x02];
    header[0x13] = header[0x03];

    memcpy(&header[0x14], nonce, 12);
    memcpy(&header[0x20], ekey, 16);

    int rc = custom_ccm_encrypt(key, header, padded, container + 64, padded_len);
    free(padded);
    if (rc != 0) {
        free(container);
        return SPU_ERR_CRYPTO;
    }

    if (out) *out = container; else free(container);
    if (out_len) *out_len = total;
    return SPU_OK;
}

int spu_decrypt_buffer(const unsigned char key[16],
                       const unsigned char *container,
                       size_t container_len,
                       unsigned char **out,
                       size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;

    if (container_len < 64) {
        return SPU_ERR_TOO_SMALL;
    }

    const unsigned char *header = container;
    unsigned int N = ((unsigned int)header[0x10] << 24) |
                     ((unsigned int)header[0x11] << 16) |
                     ((unsigned int)header[0x12] << 8) |
                     ((unsigned int)header[0x13]);
    size_t body_len = (size_t)N * 16;

    if (container_len < 64 + body_len) {
        body_len = (container_len - 64) & ~(size_t)15;
    }

    if (body_len == 0) {
        return SPU_ERR_TOO_SMALL;
    }

    unsigned char *plaintext = (unsigned char *)malloc(body_len);
    if (!plaintext) {
        return SPU_ERR_ALLOC;
    }

    int rc = custom_ccm_decrypt(key, header, container + 64, plaintext, body_len);
    if (rc != 0) {
        free(plaintext);
        return SPU_ERR_MAC;
    }

    if (out) *out = plaintext; else free(plaintext);
    if (out_len) *out_len = body_len;
    return SPU_OK;
}
