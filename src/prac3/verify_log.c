#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

#define KEY_FILE "audit.key"
#define LOG_FILE "audit.log"
#define HMAC_HEX_LEN 64

void compute_hmac(const char *data, const char *key, size_t key_len, char *out_hex) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    HMAC(EVP_sha256(), key, key_len, (const unsigned char *)data, strlen(data), digest, &digest_len);
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(&out_hex[i * 2], "%02x", digest[i]);
    }
    out_hex[digest_len * 2] = '\0';
}

int main() {
    FILE *kf = fopen(KEY_FILE, "r");
    if (!kf) { fprintf(stderr, "Error: Cannot open %s\n", KEY_FILE); return 1; }
    char key[256];
    size_t key_len = fread(key, 1, sizeof(key), kf);
    fclose(kf);

    FILE *lf = fopen(LOG_FILE, "r");
    if (!lf) { fprintf(stderr, "Error: Cannot open %s\n", LOG_FILE); return 1; }

    char line[1024];
    char prev_hmac[HMAC_HEX_LEN + 1];
    memset(prev_hmac, '0', HMAC_HEX_LEN);
    prev_hmac[HMAC_HEX_LEN] = '\0';

    int line_num = 0, errors = 0;

    while (fgets(line, sizeof(line), lf)) {
        line_num++;
        line[strcspn(line, "\r\n")] = 0;

        char *last_pipe = strrchr(line, '|');
        if (!last_pipe) { printf("Line %d: Invalid format\n", line_num); errors++; continue; }
        
        *last_pipe = '\0';
        char *current_hmac = last_pipe + 1;

        int pipe_count = 0;
        char *fourth_pipe = NULL;
        for (char *p = line; *p; p++) {
            if (*p == '|') {
                pipe_count++;
                if (pipe_count == 4) { fourth_pipe = p; break; }
            }
        }
        
        if (!fourth_pipe) { printf("Line %d: Invalid format\n", line_num); errors++; continue; }
        
        *fourth_pipe = '\0'; 
        char data_to_hash[512];
        snprintf(data_to_hash, sizeof(data_to_hash), "%s|%s", line, prev_hmac);
        
        char computed_hmac[HMAC_HEX_LEN + 1];
        compute_hmac(data_to_hash, key, key_len, computed_hmac);
        
        if (strcmp(computed_hmac, current_hmac) != 0) {
            printf("Line %d: INTEGRITY VIOLATION DETECTED!\n", line_num);
            errors++;
        }
        strncpy(prev_hmac, current_hmac, HMAC_HEX_LEN + 1);
    }
    fclose(lf);

    if (errors == 0) printf("Log integrity check PASSED. All %d lines are valid.\n", line_num);
    else printf("Log integrity check FAILED. %d errors found.\n", errors);

    return errors > 0 ? 1 : 0;
}