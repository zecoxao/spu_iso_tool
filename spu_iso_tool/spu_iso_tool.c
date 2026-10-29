#define _CRT_SECURE_NO_WARNINGS /* Disable MSVC safe functions warnings */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

/*
 * Helper function to XOR two 16-byte blocks
 */
static void xor_block16(unsigned char* dst, const unsigned char* src1, const unsigned char* src2) {
    for (int i = 0; i < 16; i++) {
        dst[i] = src1[i] ^ src2[i];
    }
}

/**
 * Custom AES-128-CTR + CBC-MAC encryption (CCM-style for PS3 containers).
 */
int custom_ccm_encrypt(const unsigned char* key,
    unsigned char* header,
    const unsigned char* plaintext,
    unsigned char* ciphertext,
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
    const unsigned char* iv12 = &header[0x04];

    int ret = aes_setkey_enc(&ctx, key, 128);
    if (ret != 0) return ret;

    /* STAGE 1: Compute CBC-MAC over the first 3 blocks of the header */
    memset(chain, 0, 16);
    for (int j = 0; j < 3; j++) {
        xor_block16(temp_block, &header[16 * j], chain);
        aes_crypt_ecb(&ctx, AES_ENCRYPT, temp_block, chain);
    }

    /* STAGE 2: CBC-MAC over plaintext + AES-CTR encryption */
    memcpy(ctr + 4, iv12, 12);

    for (size_t i = 0; i < N; i++) {
        const unsigned char* pt_ptr = &plaintext[16 * i];
        unsigned char* ct_ptr = &ciphertext[16 * i];

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

    /* STAGE 3: Final tag masking (S0) and header update */
    memset(ctr, 0, 4);
    memcpy(ctr + 4, iv12, 12);
    aes_crypt_ecb(&ctx, AES_ENCRYPT, ctr, s0);

    xor_block16(tag, chain, s0);
    memcpy(&header[0x30], tag, 16);

    return 0;
}

/**
 * Custom AES-128-CTR + CBC-MAC decryption (CCM-style for PS3 containers).
 */
int custom_ccm_decrypt(const unsigned char* key,
    const unsigned char* header,
    const unsigned char* ciphertext,
    unsigned char* plaintext,
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
    const unsigned char* iv12 = &header[0x04];

    int ret = aes_setkey_enc(&ctx, key, 128);
    if (ret != 0) return ret;

    /* STAGE 1: Compute CBC-MAC over the first 3 blocks of the header */
    memset(chain, 0, 16);
    for (int j = 0; j < 3; j++) {
        xor_block16(temp_block, &header[16 * j], chain);
        aes_crypt_ecb(&ctx, AES_ENCRYPT, temp_block, chain);
    }

    /* STAGE 2: AES-CTR decryption + CBC-MAC update over recovered plaintext */
    memcpy(ctr + 4, iv12, 12);

    for (size_t i = 0; i < N; i++) {
        unsigned char* pt_ptr = &plaintext[16 * i];
        const unsigned char* ct_ptr = &ciphertext[16 * i];

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

    /* STAGE 3: Compute final tag mask (S0) and validate the tag */
    memset(ctr, 0, 4);
    memcpy(ctr + 4, iv12, 12);
    aes_crypt_ecb(&ctx, AES_ENCRYPT, ctr, s0);

    xor_block16(computed_tag, chain, s0);

    if (memcmp(computed_tag, &header[0x30], 16) != 0) {
        return -1; /* MAC FAIL */
    }

    return 0; /* MAC PASS */
}

/*
 * Helper function to parse hex string into byte array
 */
static int hex_to_bytes(const char* hex_str, unsigned char* byte_arr, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0 || len / 2 > max_len) return -1;

    for (size_t i = 0; i < len / 2; i++) {
        unsigned int val;
        if (sscanf(&hex_str[i * 2], "%2x", &val) != 1) return -1;
        byte_arr[i] = (unsigned char)val;
    }
    return (int)(len / 2);
}

/*
 * Helper to print hex arrays for debug/logging
 */
static void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Mode missing!\n");
        fprintf(stderr, "  Encrypt: %s enc --key <hex> --iv <hex> --nonce <hex> --ekey <hex> <infile> <outfile>\n", argv[0]);
        fprintf(stderr, "  Decrypt: %s dec --key <hex> <infile> <outfile>\n", argv[0]);
        return 1;
    }

    char* mode = argv[1];

    // Сразу жестко валидируем режим, чтобы программа не вела себя непредсказуемо
    if (strcmp(mode, "enc") != 0 && strcmp(mode, "dec") != 0) {
        fprintf(stderr, "Error: Invalid mode '%s'. Must be either 'enc' or 'dec'.\n", mode);
        return 1;
    }

    unsigned char key[16] = { 0 };
    unsigned char iv[12] = { 0 };
    unsigned char console_nonce[12] = { 0 };
    unsigned char ekey[16] = { 0 };

    int has_key = 0, has_iv = 0, has_nonce = 0, has_ekey = 0;
    char* infile_path = NULL;
    char* outfile_path = NULL;

    int arg_idx = 2;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "--key") == 0 && arg_idx + 1 < argc) {
            if (hex_to_bytes(argv[arg_idx + 1], key, 16) == 16) has_key = 1;
            arg_idx += 2;
        }
        else if (strcmp(argv[arg_idx], "--iv") == 0 && arg_idx + 1 < argc) {
            if (hex_to_bytes(argv[arg_idx + 1], iv, 12) == 12) has_iv = 1;
            arg_idx += 2;
        }
        else if (strcmp(argv[arg_idx], "--nonce") == 0 && arg_idx + 1 < argc) {
            if (hex_to_bytes(argv[arg_idx + 1], console_nonce, 12) == 12) has_nonce = 1;
            arg_idx += 2;
        }
        else if (strcmp(argv[arg_idx], "--ekey") == 0 && arg_idx + 1 < argc) {
            if (hex_to_bytes(argv[arg_idx + 1], ekey, 16) == 16) has_ekey = 1;
            arg_idx += 2;
        }
        else {
            if (!infile_path) infile_path = argv[arg_idx];
            else if (!outfile_path) outfile_path = argv[arg_idx];
            arg_idx++;
        }
    }

    if (!has_key) {
        fprintf(stderr, "Error: Master key (--key) is required and must be 16 bytes.\n");
        return 1;
    }
    if (!infile_path || !outfile_path) {
        fprintf(stderr, "Error: Missing input or output file paths.\n");
        return 1;
    }

    FILE* fin = fopen(infile_path, "rb");
    if (!fin) {
        fprintf(stderr, "Error: Cannot open input file %s\n", infile_path);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (strcmp(mode, "enc") == 0) {
        if (!has_iv || !has_nonce || !has_ekey) {
            fprintf(stderr, "Error: Encryption requires --iv, --nonce, and --ekey.\n");
            fclose(fin);
            return 1;
        }

        size_t plaintext_len = (size_t)file_size;
        size_t padded_len = (plaintext_len + 15) & ~15;
        size_t N = padded_len / 16;

        unsigned char* plaintext = (unsigned char*)calloc(1, padded_len);
        unsigned char* ciphertext = (unsigned char*)malloc(padded_len);
        unsigned char header[64] = { 0 };

        if (!plaintext || !ciphertext) {
            fprintf(stderr, "Error: Memory allocation failed.\n");
            fclose(fin);
            free(plaintext); free(ciphertext);
            return 1;
        }

        size_t read_bytes = fread(plaintext, 1, plaintext_len, fin);
        (void)read_bytes;
        fclose(fin);

        header[0x00] = (unsigned char)((N >> 24) & 0xFF);
        header[0x01] = (unsigned char)((N >> 16) & 0xFF);
        header[0x02] = (unsigned char)((N >> 8) & 0xFF);
        header[0x03] = (unsigned char)(N & 0xFF);

        memcpy(&header[0x04], iv, 12);

        header[0x10] = header[0x00];
        header[0x11] = header[0x01];
        header[0x12] = header[0x02];
        header[0x13] = header[0x03];

        memcpy(&header[0x14], console_nonce, 12);
        memcpy(&header[0x20], ekey, 16);

        printf("--- Executing Custom CCM Encryption ---\n");
        print_hex("Master Key   ", key, 16);
        print_hex("CTR IV       ", iv, 12);
        print_hex("Console Nonce", console_nonce, 12);
        print_hex("Scramble EKey", ekey, 16);
        printf("Body Blocks  : %zu (%zu bytes)\n", N, padded_len);

        int enc_res = custom_ccm_encrypt(key, header, plaintext, ciphertext, padded_len);
        if (enc_res != 0) {
            fprintf(stderr, "Crypto engine error during encryption.\n");
            free(plaintext); free(ciphertext);
            return 1;
        }

        FILE* fout = fopen(outfile_path, "wb");
        if (!fout) {
            fprintf(stderr, "Error: Cannot open output file %s\n", outfile_path);
            free(plaintext); free(ciphertext);
            return 1;
        }
        fwrite(header, 1, 64, fout);
        fwrite(ciphertext, 1, padded_len, fout);
        fclose(fout);

        printf("Encryption Successful! Container saved to %s\n", outfile_path);
        print_hex("Generated MAC", &header[0x30], 16);

        free(plaintext);
        free(ciphertext);
    }
    else if (strcmp(mode, "dec") == 0) {
        if (file_size < 64) {
            fprintf(stderr, "Error: File too small to contain a valid header.\n");
            fclose(fin);
            return 1;
        }
        unsigned char header[64];
        size_t read_bytes = fread(header, 1, 64, fin);
        (void)read_bytes;
        unsigned int N = ((unsigned int)header[0x10] << 24) |
            ((unsigned int)header[0x11] << 16) |
            ((unsigned int)header[0x12] << 8) |
            ((unsigned int)header[0x13]);
        size_t body_len = N * 16;
        if (file_size < (long)(64 + body_len)) {
            fprintf(stderr, "Warning: File size mismatch. Clamping body length.\n");
            body_len = ((size_t)file_size - 64) & ~15;
        }
        unsigned char* ciphertext = (unsigned char*)malloc(body_len);
        unsigned char* plaintext = (unsigned char*)malloc(body_len);
        if (!ciphertext || !plaintext) {
            fprintf(stderr, "Error: Memory allocation failed.\n");
            fclose(fin);
            free(ciphertext); free(plaintext);
            return 1;
        }
        read_bytes = fread(ciphertext, 1, body_len, fin);
        (void)read_bytes;
        fclose(fin);
        printf("--- Executing Custom CCM Decryption ---\n");
        print_hex("Master Key   ", key, 16);
        print_hex("Extracted IV ", &header[0x04], 12);
        print_hex("Extracted Nonce", &header[0x14], 12);
        print_hex("Extracted EKey", &header[0x20], 16);
        print_hex("Expected MAC ", &header[0x30], 16);
        int dec_res = custom_ccm_decrypt(key, header, ciphertext, plaintext, body_len);
        if (dec_res == 0) {
            printf("\n[+] MAC PASS: Authentic data container verified!\n");
            FILE* fout = fopen(outfile_path, "wb");
            if (!fout) {
                fprintf(stderr, "Error: Cannot open output file %s\n", outfile_path);
                free(ciphertext); free(plaintext);
                return 1;
            }
            fwrite(plaintext, 1, body_len, fout);
            fclose(fout);
            printf("Decrypted payload saved safely to %s\n", outfile_path);
        }
        else {
            fprintf(stderr, "\n[-] MAC FAIL: Verification failed. Wrong key or container corrupted.\n");
            free(ciphertext); free(plaintext);
            return 3;
        }
        free(ciphertext);
        free(plaintext);
    }
    else {
        fprintf(stderr, "Error: Unknown execution mode '%s'. Use 'enc' or 'dec'.\n", mode);
        fclose(fin);
        return 1;
    }
    return 0;
}