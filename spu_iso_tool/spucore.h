#ifndef SPUCORE_H
#define SPUCORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Shared crypto core for spu_iso_tool.
 *
 * Implements the custom AES-128 CCM-style scheme used by lv0ldr / metldr
 * style PS3 SPU isolation containers: AES-CTR body encryption plus a
 * CBC-MAC authentication tag, with a 64-byte header.
 *
 * Container layout (big-endian fields):
 *   0x00  4   body block count N
 *   0x04  12  CTR IV / CBC-MAC nonce
 *   0x10  4   body block count N (mirror)
 *   0x14  12  console nonce
 *   0x20  16  scramble / encrypted key
 *   0x30  16  CBC-MAC tag
 *   0x40  ..  AES-CTR encrypted body (N * 16 bytes)
 */

/* Return codes for the buffer helpers below. */
#define SPU_OK             0
#define SPU_ERR_MAC       -1   /* decryption: authentication tag mismatch */
#define SPU_ERR_ALLOC     -2   /* out of memory */
#define SPU_ERR_TOO_SMALL -3   /* container smaller than the 64-byte header */
#define SPU_ERR_CRYPTO    -4   /* underlying AES/engine failure */

/*
 * Low-level primitives (operate on a caller-provided 64-byte header and a
 * body whose length is a multiple of 16).
 */
int custom_ccm_encrypt(const unsigned char *key,
                       unsigned char *header,
                       const unsigned char *plaintext,
                       unsigned char *ciphertext,
                       size_t body_len);

int custom_ccm_decrypt(const unsigned char *key,
                       const unsigned char *header,
                       const unsigned char *ciphertext,
                       unsigned char *plaintext,
                       size_t body_len);

/*
 * High-level buffer helpers (build / parse the header for you).
 *
 * spu_encrypt_buffer: encrypts an arbitrary-length plaintext (zero padded to
 *   a 16-byte multiple) and produces a complete container (header + body).
 *   On success *out is a malloc'd buffer of *out_len bytes; the caller frees it.
 *
 * spu_decrypt_buffer: verifies the MAC and, on success, returns the decrypted
 *   body in a malloc'd *out of *out_len bytes; the caller frees it. Returns
 *   SPU_ERR_MAC (and writes nothing) if authentication fails.
 *
 * Both return SPU_OK (0) on success or one of the SPU_ERR_* codes above.
 */
int spu_encrypt_buffer(const unsigned char key[16],
                       const unsigned char iv[12],
                       const unsigned char nonce[12],
                       const unsigned char ekey[16],
                       const unsigned char *plaintext,
                       size_t plaintext_len,
                       unsigned char **out,
                       size_t *out_len);

int spu_decrypt_buffer(const unsigned char key[16],
                       const unsigned char *container,
                       size_t container_len,
                       unsigned char **out,
                       size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SPUCORE_H */
