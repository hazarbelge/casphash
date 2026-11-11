#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_PASSWORD 63
#define MAX_EAPOL 256
#define BATCH_SIZE 128
#define MAX_WORKERS 32

typedef struct {
    unsigned char mic[16];
    unsigned char message[20];
    unsigned char ssid[32];
    size_t ssid_len;
    unsigned int type, keyver, message_pair;
    unsigned char eapol[MAX_EAPOL];
    size_t eapol_len;
    unsigned char expansion[102];
    size_t expansion_len;
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

static unsigned int read_be16(const unsigned char *p) {
    return ((unsigned int)p[0] << 8) | p[1];
}

static bool all_zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return false;
    return true;
}

/* Return a diagnostic rather than treating unsupported data as a mismatch. */
static const char *parse_network(char *line, Network *network) {
    char *fields[9] = {0};
    char *cursor = line;
    memset(network, 0, sizeof(*network));
    for (size_t i = 0; i < 6; ++i) {
        fields[i] = cursor;
        char *end = strchr(cursor, '*');
        if (!end) return "Expected WPA*01 PMKID or WPA*02 EAPOL text record.";
        *end = '\0';
        cursor = end + 1;
    }
    if (strcmp(fields[0], "WPA") || (strcmp(fields[1], "01") && strcmp(fields[1], "02")))
        return "Only WPA*01 PMKID and WPA*02 EAPOL records are supported.";
    network->type = strcmp(fields[1], "01") == 0 ? 1 : 2;
    size_t hex_len = strlen(fields[5]);
    if (hex_len % 2 || hex_len > 64) return "Invalid SSID hex (maximum 32 bytes).";
    network->ssid_len = hex_len / 2;
    memcpy(network->message, "PMK Name", 8);
    if (!decode_hex(fields[2], network->mic, 16)
        || !decode_hex(fields[3], network->message + 8, 6)
        || !decode_hex(fields[4], network->message + 14, 6)
        || !decode_hex(fields[5], network->ssid, network->ssid_len))
        return "Invalid MIC/PMKID, MAC address, or SSID hex.";
    if (network->type == 1) return NULL;
    for (size_t i = 6; i < 8; ++i) {
        fields[i] = cursor;
        char *end = strchr(cursor, '*');
        if (!end) return "EAPOL record requires nonce, EAPOL payload, and message-pair fields.";
        *end = '\0';
        cursor = end + 1;
    }
    fields[8] = cursor;
    unsigned char nonce[32], pair;
    if (!decode_hex(fields[6], nonce, sizeof(nonce)) || !decode_hex(fields[8], &pair, 1))
        return "Invalid nonce or message-pair hex.";
    network->message_pair = pair;
    if ((pair & 7) > 5 || (pair & 8)) return "Unsupported EAPOL message pair.";
    hex_len = strlen(fields[7]);
    if (hex_len % 2 || hex_len < 198 || hex_len > MAX_EAPOL * 2)
        return "EAPOL payload must contain 99-256 bytes.";
    network->eapol_len = hex_len / 2;
    unsigned char *eapol = network->eapol;
    if (!decode_hex(fields[7], eapol, network->eapol_len)) return "Invalid EAPOL payload hex.";
    if (eapol[0] < 1 || eapol[0] > 3 || eapol[1] != 3
        || (eapol[4] != 2 && eapol[4] != 254)
        || read_be16(eapol + 2) != network->eapol_len - 4
        || read_be16(eapol + 97) != network->eapol_len - 99)
        return "Invalid EAPOL-Key header or payload length.";
    unsigned int info = read_be16(eapol + 5);
    network->keyver = info & 7;
    if (network->keyver < 1 || network->keyver > 3)
        return "Unsupported key descriptor version (supported: 1 MD5, 2 SHA1, 3 AES-CMAC).";
    if (!(info & 8) || !(info & 0x100) || (info & 0xc00))
        return "Expected a pairwise EAPOL-Key message with a MIC, not a group/error/request message.";
    bool ap_message = (pair & 7) == 3 || (pair & 7) == 4;
    if (!!(info & 0x80) != ap_message)
        return "Message-pair field disagrees with EAPOL direction.";
    if (all_zero(nonce, 32) || all_zero(eapol + 17, 32))
        return "Missing nonce: this exchange cannot be verified from the supplied record.";
    /* MIC is supplied separately in hc22000; authenticate a zeroed MIC field. */
    memset(eapol + 81, 0, 16);
    unsigned char *p = network->expansion;
    if (network->keyver == 3) {
        p[0] = 1; /* SHA256 KDF counter, little endian. */
        memcpy(p + 2, "Pairwise key expansion", 22);
        p += 24;
        network->expansion[100] = 0x80; /* 384-bit PTK length, little endian. */
        network->expansion[101] = 1;
        network->expansion_len = 102;
    } else {
        memcpy(p, "Pairwise key expansion", 22);
        p += 23; /* NUL separator; trailing PRF counter remains zero. */
        network->expansion_len = 100;
    }
    const unsigned char *ap = network->message + 8, *sta = network->message + 14;
    bool ap_first = memcmp(ap, sta, 6) < 0;
    memcpy(p, ap_first ? ap : sta, 6);
    memcpy(p + 6, ap_first ? sta : ap, 6);
    bool nonce_first = memcmp(nonce, eapol + 17, 32) < 0;
    memcpy(p + 12, nonce_first ? nonce : eapol + 17, 32);
    memcpy(p + 44, nonce_first ? eapol + 17 : nonce, 32);
    return NULL;
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
                case '?': mask->literals[p][0] = '?'; chars = mask->literals[p]; break;
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
static int check_pmk(const Network *network, const unsigned char pmk[32]) {
    unsigned char digest[EVP_MAX_MD_SIZE], kck[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (network->type == 1) {
        if (!HMAC(EVP_sha1(), pmk, 32, network->message,
                sizeof(network->message), digest, &digest_len) || digest_len < 16)
            return -1;
    } else {
        if (!HMAC(network->keyver == 3 ? EVP_sha256() : EVP_sha1(), pmk, 32,
                network->expansion, network->expansion_len, kck, &digest_len) || digest_len < 16)
            return -1;
        if (network->keyver == 3) {
            size_t length = 0;
            if (!EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL, kck, 16,
                    network->eapol, network->eapol_len, digest, sizeof(digest), &length)
                    || length != 16) return -1;
        } else if (!HMAC(network->keyver == 1 ? EVP_md5() : EVP_sha1(), kck, 16,
                network->eapol, network->eapol_len, digest, &digest_len) || digest_len < 16) {
            return -1;
        }
    }
    return memcmp(digest, network->mic, 16) == 0;
}

static double seconds_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

typedef struct {
    Network network;
    bool matched;
    size_t line, next;
} Record;

typedef struct {
    char password[MAX_PASSWORD + 1];
    size_t length;
    uint64_t skipped; /* Invalid lines preceding this candidate. */
} Candidate;

typedef struct {
    Record *records;
    size_t record_count, *groups, group_count;
    Candidate candidates[BATCH_SIZE];
    unsigned char *results, errors[BATCH_SIZE];
    size_t count, next, remaining, generation, worker_count;
    bool shutdown;
    pthread_t workers[MAX_WORKERS];
    pthread_mutex_t mutex;
    pthread_cond_t ready, done;
} Pool;

/* A batch owns an immutable matched-record snapshot. Workers write disjoint rows;
 * only the coordinator commits matches and emits output, in candidate order. */
static void verify_candidate(Pool *pool, size_t index) {
    const Candidate *candidate = &pool->candidates[index];
    for (size_t g = 0; g < pool->group_count; ++g) {
        size_t first = pool->groups[g];
        while (first != SIZE_MAX && pool->records[first].matched)
            first = pool->records[first].next;
        if (first == SIZE_MAX) continue;
        const Network *network = &pool->records[first].network;
        unsigned char pmk[32];
        if (!PKCS5_PBKDF2_HMAC_SHA1(candidate->password, (int)candidate->length,
                network->ssid, (int)network->ssid_len, 4096, 32, pmk)) {
            pool->errors[index] = 1;
            return;
        }
        for (size_t r = first; r != SIZE_MAX; r = pool->records[r].next) {
            if (pool->records[r].matched) continue;
            int result = check_pmk(&pool->records[r].network, pmk);
            if (result < 0) {
                pool->errors[index] = 1;
                return;
            }
            pool->results[index * pool->record_count + r] = (unsigned char)result;
        }
    }
}

static void *worker_main(void *argument) {
    Pool *pool = argument;
    size_t generation = 0;
    pthread_mutex_lock(&pool->mutex);
    for (;;) {
        while (!pool->shutdown && generation == pool->generation)
            pthread_cond_wait(&pool->ready, &pool->mutex);
        if (pool->shutdown) break;
        generation = pool->generation;
        while (pool->next < pool->count) {
            size_t index = pool->next++;
            pthread_mutex_unlock(&pool->mutex);
            verify_candidate(pool, index);
            pthread_mutex_lock(&pool->mutex);
        }
        if (--pool->remaining == 0) pthread_cond_signal(&pool->done);
    }
    pthread_mutex_unlock(&pool->mutex);
    return NULL;
}

static void pool_destroy(Pool *pool) {
    pthread_mutex_lock(&pool->mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->ready);
    pthread_mutex_unlock(&pool->mutex);
    for (size_t w = 0; w < pool->worker_count; ++w)
        pthread_join(pool->workers[w], NULL);
    pthread_cond_destroy(&pool->done);
    pthread_cond_destroy(&pool->ready);
    pthread_mutex_destroy(&pool->mutex);
    free(pool->groups);
    free(pool->results);
}

static bool pool_init(Pool *pool, Record *records, size_t count, size_t workers) {
    memset(pool, 0, sizeof(*pool));
    pool->records = records;
    pool->record_count = count;
    if (count > SIZE_MAX / BATCH_SIZE || count > SIZE_MAX / sizeof(*pool->groups))
        return false;
    pool->groups = malloc(count * sizeof(*pool->groups));
    pool->results = calloc(count, BATCH_SIZE);
    if (!pool->groups || !pool->results) goto allocation_failed;
    /* Link records by exact SSID bytes (including embedded NULs) and length. */
    for (size_t r = 0; r < count; ++r) {
        size_t g = 0;
        for (; g < pool->group_count; ++g) {
            const Network *a = &records[r].network;
            const Network *b = &records[pool->groups[g]].network;
            if (a->ssid_len == b->ssid_len && !memcmp(a->ssid, b->ssid, a->ssid_len)) break;
        }
        records[r].next = g == pool->group_count ? SIZE_MAX : pool->groups[g];
        pool->groups[g] = r;
        if (g == pool->group_count) ++pool->group_count;
    }
    int error = pthread_mutex_init(&pool->mutex, NULL);
    if (error) goto allocation_failed;
    error = pthread_cond_init(&pool->ready, NULL);
    if (error) { pthread_mutex_destroy(&pool->mutex); goto allocation_failed; }
    error = pthread_cond_init(&pool->done, NULL);
    if (error) {
        pthread_cond_destroy(&pool->ready);
        pthread_mutex_destroy(&pool->mutex);
        goto allocation_failed;
    }
    /* A one-worker run uses the coordinator, avoiding thread startup overhead. */
    if (workers > 1) {
        for (size_t w = 0; w < workers; ++w) {
            error = pthread_create(&pool->workers[w], NULL, worker_main, pool);
            if (error) {
                fprintf(stderr, "Creating CPU worker: %s\n", strerror(error));
                pool_destroy(pool);
                return false;
            }
            ++pool->worker_count;
        }
    }
    return true;
allocation_failed:
    free(pool->groups);
    free(pool->results);
    return false;
}

static void pool_run(Pool *pool) {
    memset(pool->results, 0, pool->count * pool->record_count);
    memset(pool->errors, 0, pool->count);
    if (!pool->worker_count) {
        for (size_t i = 0; i < pool->count; ++i) verify_candidate(pool, i);
        return;
    }
    pthread_mutex_lock(&pool->mutex);
    pool->next = 0;
    pool->remaining = pool->worker_count;
    ++pool->generation;
    pthread_cond_broadcast(&pool->ready);
    while (pool->remaining) pthread_cond_wait(&pool->done, &pool->mutex);
    pthread_mutex_unlock(&pool->mutex);
}

static Record *read_records(FILE *hashes, size_t *count) {
    Record *records = NULL;
    size_t allocated = 0, number = 0, capacity = 0;
    char *line = NULL;
    ssize_t length;
    bool failed = false;
    while ((length = getline(&line, &capacity, hashes)) != -1) {
        ++number;
        if (memchr(line, '\0', (size_t)length)) {
            fprintf(stderr, "Line %zu: binary data is not an hc22000 text record.\n", number);
            failed = true;
            break;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) continue;
        Network network;
        const char *error = parse_network(line, &network);
        if (error) {
            fprintf(stderr, "Line %zu: %s\n", number, error);
            failed = true;
            break;
        }
        if (*count == allocated) {
            size_t next = allocated ? allocated * 2 : 16;
            if (next < allocated || next > SIZE_MAX / sizeof(*records)) {
                failed = true;
                break;
            }
            Record *grown = realloc(records, next * sizeof(*records));
            if (!grown) { perror("Allocating hash records"); failed = true; break; }
            records = grown;
            allocated = next;
        }
        records[(*count)++] = (Record){.network = network, .line = number};
        if (network.type == 2 && (network.message_pair & 0xe0))
            fprintf(stderr, "Line %zu: exact recorded nonces only; nonce correction is not implemented.\n", number);
    }
    free(line);
    if (ferror(hashes)) { perror("Reading hash records"); failed = true; }
    if (!*count) { fprintf(stderr, "No usable PMKID/EAPOL records found.\n"); failed = true; }
    if (failed) { free(records); return NULL; }
    return records;
}

static void progress(bool wordlist, bool finished, uint64_t tested, uint64_t skipped,
                     size_t matched, size_t records, double space, double seconds) {
    if (wordlist) {
        printf("%s tested=%" PRIu64 " matched=%zu total=%zu skipped=%" PRIu64 " seconds=%.3f\n",
               finished ? "SUMMARY" : "PROGRESS", tested, matched, records, skipped, seconds);
    } else {
        /* aggregate=1 distinguishes a shared mask search from the legacy per-record protocol. */
        printf("PROGRESS aggregate=1 tested=%" PRIu64 " matched=%zu total=%zu space=%.0f seconds=%.3f finished=%u\n",
               tested, matched, records, space, seconds, (unsigned int)finished);
    }
}

static int search(Record *records, size_t record_count, const char *wordlist_path,
                  Mask *mask, size_t workers) {
    bool wordlist = wordlist_path != NULL;
    FILE *words = NULL;
    if (wordlist) {
        words = !strcmp(wordlist_path, "-") ? stdin : fopen(wordlist_path, "rb");
        if (!words) { perror("Opening wordlist"); return EXIT_FAILURE; }
        /* No hidden stdio read-ahead on a pipe: poll can flush partial batches
         * without waiting for a producer to send more candidates or close stdin. */
        if (words == stdin) setvbuf(words, NULL, _IONBF, 0);
    }
    Pool pool;
    if (!pool_init(&pool, records, record_count, workers)) {
        fprintf(stderr, "Could not initialize CPU workers or batch storage.\n");
        if (words && words != stdin) fclose(words);
        return EXIT_FAILURE;
    }
    uint64_t tested = 0, skipped = 0, pending_skipped = 0;
    size_t matched = 0, capacity = 0;
    char *line = NULL;
    bool exhausted = false;
    int status = EXIT_SUCCESS;
    double started = seconds_now(), reported = started;
    progress(wordlist, false, 0, 0, 0, record_count, mask->total, 0);
    while (!exhausted && matched != record_count) {
        pool.count = 0;
        double filling = seconds_now();
        while (pool.count < BATCH_SIZE && !exhausted) {
            if (wordlist && words == stdin && pool.count) {
                struct pollfd input = {.fd = fileno(words), .events = POLLIN};
                int ready;
                do { ready = poll(&input, 1, 0); } while (ready < 0 && errno == EINTR);
                if (ready < 0) { perror("Polling wordlist"); status = EXIT_FAILURE; exhausted = true; break; }
                if (!ready) break;
            }
            Candidate *candidate = &pool.candidates[pool.count];
            if (wordlist) {
                ssize_t length = getline(&line, &capacity, words);
                if (length < 0) { exhausted = true; break; }
                if (length && line[length - 1] == '\n') {
                    line[--length] = '\0';
                    if (length && line[length - 1] == '\r') line[--length] = '\0';
                }
                if (length < 1 || length > MAX_PASSWORD || memchr(line, '\0', (size_t)length)) {
                    ++pending_skipped;
                    if (seconds_now() - filling >= 0.5) break;
                    continue;
                }
                candidate->length = (size_t)length;
                memcpy(candidate->password, line, (size_t)length);
                candidate->password[length] = '\0';
            } else {
                candidate->length = mask->length;
                memcpy(candidate->password, mask->password, mask->length + 1);
                exhausted = !next_password(mask);
            }
            candidate->skipped = pending_skipped;
            pending_skipped = 0;
            ++pool.count;
        }
        if (pool.count) pool_run(&pool);
        for (size_t c = 0; c < pool.count; ++c) {
            Candidate *candidate = &pool.candidates[c];
            ++tested;
            skipped += candidate->skipped;
            if (pool.errors[c]) {
                fprintf(stderr, "OpenSSL password derivation or MIC computation failed.\n");
                status = EXIT_FAILURE;
                goto done;
            }
            for (size_t r = 0; r < record_count; ++r) {
                if (records[r].matched || !pool.results[c * record_count + r]) continue;
                records[r].matched = true;
                ++matched;
                if (wordlist) {
                    printf("MATCH line=%zu password_hex=", records[r].line);
                    for (size_t j = 0; j < candidate->length; ++j)
                        printf("%02x", (unsigned char)candidate->password[j]);
                    printf("\n");
                } else {
                    printf("Record line: %zu\nMatch found with password: %s\n", records[r].line, candidate->password);
                }
            }
            if (matched == record_count) goto done;
        }
        /* Remaining skipped lines follow every candidate in this batch. */
        skipped += pending_skipped;
        pending_skipped = 0;
        double now = seconds_now();
        if (now - reported >= 0.5) {
            progress(wordlist, false, tested, skipped, matched, record_count, mask->total, now - started);
            reported = now;
        }
    }
done:
    if (words && ferror(words)) { perror("Reading wordlist"); status = EXIT_FAILURE; }
    if (!wordlist && matched != record_count && status == EXIT_SUCCESS)
        printf("Password could not be found.\n");
    progress(wordlist, wordlist || status == EXIT_SUCCESS, tested, skipped, matched, record_count, mask->total, seconds_now() - started);
    pool_destroy(&pool);
    free(line);
    if (words && words != stdin) fclose(words);
    return status;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    long available = sysconf(_SC_NPROCESSORS_ONLN);
    size_t workers = available > 0 ? (size_t)available : 1;
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;
    /* Preserve existing positional invocations; an optional trailing override
     * makes single-core validation and tuning available to CLI callers. */
    if (argc >= 3 && !strcmp(argv[argc - 2], "--threads")) {
        const char *value = argv[argc - 1];
        char *end;
        errno = 0;
        unsigned long parsed = strtoul(value, &end, 10);
        if (errno || value[0] < '0' || value[0] > '9' || *end || parsed < 1 || parsed > MAX_WORKERS) {
            fprintf(stderr, "--threads requires an integer from 1 to %d.\n", MAX_WORKERS);
            return EXIT_FAILURE;
        }
        workers = (size_t)parsed;
        argc -= 2;
    }
    bool wordlist = argc == 4 && !strcmp(argv[2], "--wordlist");
    if (argc != 3 && !wordlist) {
        fprintf(stderr, "Usage: %s <hash file> <guess mask> [--threads 1-%d]\n"
                        "       %s <hash file> --wordlist <file or -> [--threads 1-%d]\n",
                argv[0], MAX_WORKERS, argv[0], MAX_WORKERS);
        return EXIT_FAILURE;
    }
    Mask mask = {0};
    if (!wordlist && !parse_mask(argv[2], &mask)) {
        fprintf(stderr, "Invalid mask: use 1–63 characters and ?u ?l ?d ?s ?a ?c.\n");
        return EXIT_FAILURE;
    }
    FILE *file = fopen(argv[1], "r");
    if (!file) { fprintf(stderr, "File could not be opened: %s: %s\n", argv[1], strerror(errno)); return EXIT_FAILURE; }
    unsigned char magic[4];
    size_t magic_len = fread(magic, 1, sizeof(magic), file);
    rewind(file);
    if (magic_len == 4 && (memcmp(magic, "\x0a\x0d\x0d\x0a", 4) == 0
        || memcmp(magic, "\xd4\xc3\xb2\xa1", 4) == 0 || memcmp(magic, "\xa1\xb2\xc3\xd4", 4) == 0
        || memcmp(magic, "\x4d\x3c\xb2\xa1", 4) == 0 || memcmp(magic, "\xa1\xb2\x3c\x4d", 4) == 0)) {
        fprintf(stderr, "Packet capture input: convert to hc22000 first using hcxpcapngtool (hcxtools).\n");
        fclose(file);
        return EXIT_FAILURE;
    }
    size_t count = 0;
    Record *records = read_records(file, &count);
    fclose(file);
    if (!records) return EXIT_FAILURE;
    int status = search(records, count, wordlist ? argv[3] : NULL, &mask, workers);
    free(records);
    return status;
}
