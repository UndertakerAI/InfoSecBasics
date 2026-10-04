#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <openssl/hmac.h>
#include <utmp.h>

#define KEY_FILE "audit.key"
#define LOG_FILE "audit.log"
#define HMAC_HEX_LEN 64

void get_timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

void compute_hmac(const char *data, const char *key, size_t key_len, char *out_hex) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    HMAC(EVP_sha256(), key, key_len, (const unsigned char *)data, strlen(data), digest, &digest_len);
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(&out_hex[i * 2], "%02x", digest[i]);
    }
    out_hex[digest_len * 2] = '\0';
}

void log_event(const char *event_type, const char *user, const char *object, const char *key, size_t key_len, char *prev_hmac) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    char data_to_hash[512];
    snprintf(data_to_hash, sizeof(data_to_hash), "%s|%s|%s|%s|%s", timestamp, event_type, user, object, prev_hmac);
    
    char current_hmac[HMAC_HEX_LEN + 1];
    compute_hmac(data_to_hash, key, key_len, current_hmac);
    
    char log_line[1024];
    snprintf(log_line, sizeof(log_line), "%s|%s\n", data_to_hash, current_hmac);
    
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fputs(log_line, f);
        fclose(f);
    }
    strncpy(prev_hmac, current_hmac, HMAC_HEX_LEN + 1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory_to_monitor>\n", argv[0]);
        return 1;
    }

    FILE *kf = fopen(KEY_FILE, "r");
    if (!kf) {
        fprintf(stderr, "Error: Cannot open %s. Generate it first.\n", KEY_FILE);
        return 1;
    }
    char key[256];
    size_t key_len = fread(key, 1, sizeof(key), kf);
    fclose(kf);

    char prev_hmac[HMAC_HEX_LEN + 1];
    memset(prev_hmac, '0', HMAC_HEX_LEN);
    prev_hmac[HMAC_HEX_LEN] = '\0';

    int fd = inotify_init();
    if (fd < 0) { perror("inotify_init"); return 1; }

    int wd = inotify_add_watch(fd, argv[1], IN_CREATE | IN_MODIFY | IN_DELETE | IN_ACCESS);
    if (wd < 0) { perror("inotify_add_watch"); return 1; }

    printf("Monitoring directory: %s\nPress Ctrl+C to stop.\n", argv[1]);

    time_t last_wtmp_check = time(NULL);
    time_t last_login_time = 0;

    while (1) {
        time_t now = time(NULL);
        if (now - last_wtmp_check >= 5) {
            struct utmp *ut;
            setutent();
            while ((ut = getutent()) != NULL) {
                if (ut->ut_type == USER_PROCESS && ut->ut_tv.tv_sec > last_login_time) {
                    last_login_time = ut->ut_tv.tv_sec;
                    log_event("LOGIN", ut->ut_user, ut->ut_line, key, key_len, prev_hmac);
                }
            }
            endutent();
            last_wtmp_check = now;
        }

        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        struct timeval tv = {1, 0};

        if (select(fd + 1, &fds, NULL, NULL, &tv) > 0) {
            ssize_t len = read(fd, buf, sizeof(buf));
            if (len > 0) {
                for (char *ptr = buf; ptr < buf + len; ) {
                    struct inotify_event *event = (struct inotify_event *)ptr;
                    if (event->len > 0) {
                        const char *etype = "FILE_ACCESS";
                        if (event->mask & IN_CREATE) etype = "FILE_CREATE";
                        else if (event->mask & IN_MODIFY) etype = "FILE_MODIFY";
                        else if (event->mask & IN_DELETE) etype = "FILE_DELETE";
                        
                        char *user = getenv("USER");
                        if (!user) user = "unknown";
                        log_event(etype, user, event->name, key, key_len, prev_hmac);
                    }
                    ptr += sizeof(struct inotify_event) + event->len;
                }
            }
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}