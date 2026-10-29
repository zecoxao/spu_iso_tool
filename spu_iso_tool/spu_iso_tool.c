#define _CRT_SECURE_NO_WARNINGS /* Disable MSVC safe functions warnings */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spucore.h"

/*
 * Parse a hex string into a byte array. Returns the number of bytes on
 * success, or -1 on malformed input / overflow.
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

/* Print a labelled hex dump for debug/logging. */
static void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Read an entire file into a malloc'd buffer. Returns 0 on success. */
static int read_file(const char* path, unsigned char** out, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    unsigned char* buf = (unsigned char*)malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *out = buf;
    *out_len = rd;
    return 0;
}

static int write_file(const char* path, const unsigned char* data, size_t len) {
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Mode missing!\n");
        fprintf(stderr, "  Encrypt: %s enc --key <hex> --iv <hex> --nonce <hex> --ekey <hex> <infile> <outfile>\n", argv[0]);
        fprintf(stderr, "  Decrypt: %s dec --key <hex> <infile> <outfile>\n", argv[0]);
        return 1;
    }

    char* mode = argv[1];

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

    unsigned char* indata = NULL;
    size_t inlen = 0;
    if (read_file(infile_path, &indata, &inlen) != 0) {
        fprintf(stderr, "Error: Cannot open input file %s\n", infile_path);
        return 1;
    }

    if (strcmp(mode, "enc") == 0) {
        if (!has_iv || !has_nonce || !has_ekey) {
            fprintf(stderr, "Error: Encryption requires --iv, --nonce, and --ekey.\n");
            free(indata);
            return 1;
        }

        unsigned char* container = NULL;
        size_t container_len = 0;

        printf("--- Executing Custom CCM Encryption ---\n");
        print_hex("Master Key   ", key, 16);
        print_hex("CTR IV       ", iv, 12);
        print_hex("Console Nonce", console_nonce, 12);
        print_hex("Scramble EKey", ekey, 16);
        printf("Input bytes  : %zu\n", inlen);

        int rc = spu_encrypt_buffer(key, iv, console_nonce, ekey, indata, inlen,
                                    &container, &container_len);
        free(indata);
        if (rc != SPU_OK) {
            fprintf(stderr, "Crypto engine error during encryption (%d).\n", rc);
            return 1;
        }

        if (write_file(outfile_path, container, container_len) != 0) {
            fprintf(stderr, "Error: Cannot open output file %s\n", outfile_path);
            free(container);
            return 1;
        }

        printf("Encryption Successful! Container saved to %s\n", outfile_path);
        print_hex("Generated MAC", &container[0x30], 16);
        free(container);
    }
    else { /* dec */
        unsigned char* header = indata;
        if (inlen >= 64) {
            printf("--- Executing Custom CCM Decryption ---\n");
            print_hex("Master Key   ", key, 16);
            print_hex("Extracted IV ", &header[0x04], 12);
            print_hex("Extracted Nonce", &header[0x14], 12);
            print_hex("Extracted EKey", &header[0x20], 16);
            print_hex("Expected MAC ", &header[0x30], 16);
        }

        unsigned char* plain = NULL;
        size_t plain_len = 0;
        int rc = spu_decrypt_buffer(key, indata, inlen, &plain, &plain_len);
        free(indata);

        if (rc == SPU_OK) {
            printf("\n[+] MAC PASS: Authentic data container verified!\n");
            if (write_file(outfile_path, plain, plain_len) != 0) {
                fprintf(stderr, "Error: Cannot open output file %s\n", outfile_path);
                free(plain);
                return 1;
            }
            printf("Decrypted payload saved safely to %s\n", outfile_path);
            free(plain);
        }
        else if (rc == SPU_ERR_TOO_SMALL) {
            fprintf(stderr, "Error: File too small to contain a valid header.\n");
            return 1;
        }
        else {
            fprintf(stderr, "\n[-] MAC FAIL: Verification failed. Wrong key or container corrupted.\n");
            return 3;
        }
    }

    return 0;
}
