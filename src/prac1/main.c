#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

long long total_files = 0;
long long total_dirs = 0;
long long file_counter = 0;

void get_perms_string(mode_t mode, char *perms_str) {
    perms_str[0] = (mode & S_IRUSR) ? 'r' : '-';
    perms_str[1] = (mode & S_IWUSR) ? 'w' : '-';
    perms_str[2] = (mode & S_IXUSR) ? 'x' : '-';
    perms_str[3] = (mode & S_IRGRP) ? 'r' : '-';
    perms_str[4] = (mode & S_IWGRP) ? 'w' : '-';
    perms_str[5] = (mode & S_IXGRP) ? 'x' : '-';
    perms_str[6] = (mode & S_IROTH) ? 'r' : '-';
    perms_str[7] = (mode & S_IWOTH) ? 'w' : '-';
    perms_str[8] = (mode & S_IXOTH) ? 'x' : '-';
    perms_str[9] = '\0';
}

int has_secret_extension(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    if (strcmp(dot, ".key") == 0 || strcmp(dot, ".crt") == 0 || strcmp(dot, ".pem") == 0) {
        return 1;
    }
    return 0;
}

const char* classify_file(const char *name, struct stat *st, int *level) {
    if (st->st_uid == 0 || (st->st_mode & S_ISVTX) || has_secret_extension(name)) {
        *level = 4;
        return "Секретный";
    }

    mode_t perm = st->st_mode & 0777;

    if ((perm & S_IROTH) && (perm & S_IWOTH)) {
        *level = 1;
        return "Публичный";
    }

    if ((perm & 0077) == 0) {
        *level = 3;
        return "Конфиденциальный";
    }

    *level = 2;
    return "Внутренний";
}

void listdir(const char *name, FILE *report_file)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name))) {
        fprintf(stderr, "Ошибка открытия директории %s: %s\n", name, strerror(errno));
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char path[2048];
        snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);

        struct stat st;
        if (lstat(path, &st) == -1) {
            continue; 
        }

        if (S_ISLNK(st.st_mode)) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            total_dirs++;
        } else {
            total_files++;
        }
        file_counter++;

        char perms_str[10];
        get_perms_string(st.st_mode, perms_str);
        mode_t octal_perms = st.st_mode & 0777;

        int level_num = 0;
        const char* level_name = classify_file(entry->d_name, &st, &level_num);

        char time_str[20];
        struct tm *tm_info = localtime(&st.st_mtime);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);

        printf("%-4lld %-40.40s %-10lld %s (%03o)  %-4d:%-9d %-16s %s (Ур. %d)\n",
               file_counter, path, (long long)st.st_size, perms_str, octal_perms, 
               st.st_uid, st.st_gid, time_str, level_name, level_num);

        fprintf(report_file, "%-4lld | %-60s | %-12lld | %s (%03o) | %d:%d | %-16s | %s (Ур. %d)\n",
               file_counter, path, (long long)st.st_size, perms_str, octal_perms, 
               st.st_uid, st.st_gid, time_str, level_name, level_num);

        if (S_ISDIR(st.st_mode)) {
            listdir(path, report_file);
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    char root_dir[1024];

    if (argc >= 2) {
        strncpy(root_dir, argv[1], sizeof(root_dir) - 1);
        root_dir[sizeof(root_dir) - 1] = '\0';
    } else {
        strcpy(root_dir, ".");
    }

    const char *report_filename = "report.txt";
    FILE *report_file = fopen(report_filename, "w");
    if (!report_file) {
        fprintf(stderr, "Не удалось создать файл отчета: %s\n", strerror(errno));
        return 1;
    }

    printf("%-6s %-44s %-16s %-21s %-14s %-24s %s\n", 
           "№", "Путь", "Размер", "Права", "UID:GID", "Время изм.", "Уровень доступа");
    
    fprintf(report_file, "ДИРЕКТОРИЯ: %s\n", root_dir);
    fprintf(report_file, "%-6s | %-64s | %-18s | %-20s | %-9s | %-24s | %s\n",
           "№", "Путь", "Размер (B)", "Права", "UID:GID", "Время изм.", "Уровень доступа");

    listdir(root_dir, report_file);

    printf("Всего обработано каталогов: %lld\n", total_dirs);
    printf("Всего обработано файлов: %lld\n", total_files);
    printf("Отчет сохранен в файл: %s", report_filename);

    fprintf(report_file, "Всего обработано каталогов: %lld\n", total_dirs);
    fprintf(report_file, "Всего обработано файлов: %lld", total_files);

    fclose(report_file);
    return 0;
}