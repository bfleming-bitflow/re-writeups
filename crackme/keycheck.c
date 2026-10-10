/*
 * keycheck — benign name/serial crackme for reverse-engineering practice.
 *
 * The expected serial is the FNV-1a 32-bit hash of the name, printed as eight
 * lowercase hexadecimal digits. The success banner is stored XOR-encoded so
 * that a strings pass does not reveal it immediately.
 *
 * Build (ELF):  gcc -O0 -fno-stack-protector -o keycheck keycheck.c
 * This program performs no network I/O and writes nothing to disk.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define FNV_OFFSET 2166136261u
#define FNV_PRIME  16777619u

static uint32_t fnv1a32(const char *data, size_t length) {
    uint32_t hash = FNV_OFFSET;
    for (size_t i = 0; i < length; i++) {
        hash ^= (uint8_t)data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

/* "Access granted." XOR 0x37 */
static const unsigned char SUCCESS_ENC[] = {
    0x76, 0x54, 0x54, 0x52, 0x44, 0x44, 0x17, 0x50, 0x45, 0x56, 0x59, 0x43, 0x52, 0x53, 0x19, 0x00
};
static const unsigned char FAIL_MSG[] = "Access denied.";

static void decode_success(char *out, size_t out_len) {
    size_t i;
    for (i = 0; SUCCESS_ENC[i] != 0 && i + 1 < out_len; i++) {
        out[i] = (char)(SUCCESS_ENC[i] ^ 0x37);
    }
    out[i] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_serial(const char *text, uint32_t *out) {
    if (strlen(text) != 8) return 0;
    uint32_t value = 0;
    for (int i = 0; i < 8; i++) {
        int nibble = hex_nibble(text[i]);
        if (nibble < 0) return 0;
        value = (value << 4) | (uint32_t)nibble;
    }
    *out = value;
    return 1;
}

int main(int argc, char **argv) {
    char success[32];
    uint32_t expected;
    uint32_t provided;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <name> <serial>\n", argv[0]);
        return 2;
    }

    expected = fnv1a32(argv[1], strlen(argv[1]));
    if (!parse_serial(argv[2], &provided) || provided != expected) {
        puts((const char *)FAIL_MSG);
        return 1;
    }

    decode_success(success, sizeof success);
    puts(success);
    return 0;
}
