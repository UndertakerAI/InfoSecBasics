#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

// Преобразование st_mode в символьную строку вида "rwxr-xr--"
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

// Получение имени пользователя по UID
const char *get_user_name(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    return pw ? pw->pw_name : "unknown";
}

// Получение имени группы по GID
const char *get_group_name(gid_t gid) {
    struct group *gr = getgrgid(gid);
    return gr ? gr->gr_name : "unknown";
}

// Вывод подробной информации о файле
void print_file_info(const char *path, struct stat *st) {
    char perms_str[10];
    get_perms_string(st->st_mode, perms_str);

    char time_str[32];
    struct tm *tm_info = localtime(&st->st_mtime);
    strftime(time_str, sizeof(time_str), "%a %b %d %H:%M:%S %Y", tm_info);

    printf("Файл: %s\n", path);
    printf("Права: %s (%03o)\n", perms_str, st->st_mode & 0777);
    printf("Владелец: %s (UID=%d)\n", get_user_name(st->st_uid), st->st_uid);
    printf("Группа: %s (GID=%d)\n", get_group_name(st->st_gid), st->st_gid);
    printf("Размер: %lld байт\n", (long long)st->st_size);
    printf("Последнее изменение: %s\n", time_str);
}

// Разбор символьного режима прав
int parse_symbolic_mode(const char *spec, mode_t current_mode, mode_t *new_mode) {
    mode_t mode = current_mode;
    const char *p = spec;

    // Разбор категорий
    int who = 0; // битовая маска:
    while (*p == 'u' || *p == 'g' || *p == 'o' || *p == 'a') {
        switch (*p) {
            case 'u': who |= 4; break;
            case 'g': who |= 2; break;
            case 'o': who |= 1; break;
            case 'a': who |= 7; break;
        }
        p++;
    }
    if (who == 0) who = 7; // по умолчанию — все категории, как в chmod

    // Разбор операции
    char op = *p;
    if (op != '+' && op != '-' && op != '=') {
        fprintf(stderr, "Ошибка: неверная операция '%c' в режиме '%s'\n", op, spec);
        return -1;
    }
    p++;

    // Разбор прав
    mode_t perm_bits = 0;
    while (*p == 'r' || *p == 'w' || *p == 'x') {
        switch (*p) {
            case 'r': perm_bits |= 4; break;
            case 'w': perm_bits |= 2; break;
            case 'x': perm_bits |= 1; break;
        }
        p++;
    }
    if (*p != '\0') {
        fprintf(stderr, "Ошибка: недопустимый символ '%c' в режиме '%s'\n", *p, spec);
        return -1;
    }

    // Вычисление новой маски
    mode_t mask_u = 0700, mask_g = 0070, mask_o = 0007;

    // Для операции '=' сначала сбрасываем указанные категории
    if (op == '=') {
        if (who & 4) mode &= ~mask_u;
        if (who & 2) mode &= ~mask_g;
        if (who & 1) mode &= ~mask_o;
    }

    // Применяем права к каждой указанной категории
    for (int cat = 0; cat < 3; cat++) {
        int cat_bit = (cat == 0) ? 4 : (cat == 1) ? 2 : 1;
        if (!(who & cat_bit)) continue;

        mode_t mask = (cat == 0) ? mask_u : (cat == 1) ? mask_g : mask_o;
        mode_t bits = perm_bits << ((2 - cat) * 3);

        switch (op) {
            case '+': mode |= bits;        break;
            case '-': mode &= ~bits;       break;
            case '=': mode |= bits;        break;
        }
    }

    *new_mode = mode;
    return 0;
}

// Проверка наличия права у категории
int check_permission(mode_t mode, char category, char perm) {
    mode_t bit = 0;

    switch (category) {
        case 'u':
            bit = (perm == 'r') ? S_IRUSR : (perm == 'w') ? S_IWUSR : (perm == 'x') ? S_IXUSR : 0;
            break;
        case 'g':
            bit = (perm == 'r') ? S_IRGRP : (perm == 'w') ? S_IWGRP : (perm == 'x') ? S_IXGRP : 0;
            break;
        case 'o':
            bit = (perm == 'r') ? S_IROTH : (perm == 'w') ? S_IWOTH : (perm == 'x') ? S_IXOTH : 0;
            break;
        default:
            return -1;
    }

    if (bit == 0) return -1;
    return (mode & bit) ? 1 : 0;
}

// функция для вывода примеров корректного вызова программы
void usage(const char *prog) {
    fprintf(stderr,
        "Использование:\n"
        "  %s <file>                       — просмотр информации о файле\n"
        "  %s <file> <mode>                — установка прав (восьмерично или символьно)\n"
        "  %s -c <file> <category> <perm>  — проверка права (category: u/g/o, perm: r/w/x)\n"
        "\n"
        "Примеры:\n"
        "  %s test.txt\n"
        "  %s test.txt 644\n"
        "  %s test.txt u+x\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    // проверка права
    if (argc >= 2 && strcmp(argv[1], "-c") == 0) {
        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }

        const char *path = argv[2];
        char category = argv[3][0];
        char perm = argv[4][0];

        struct stat st;
        if (stat(path, &st) == -1) {
            fprintf(stderr, "Ошибка stat(%s): %s\n", path, strerror(errno));
            return 1;
        }

        int result = check_permission(st.st_mode, category, perm);
        if (result < 0) {
            fprintf(stderr, "Ошибка: неверная категория '%c' или право '%c'\n",
                    category, perm);
            return 1;
        }

        if (result) {
            printf("Право '%c' для категории '%c' у файла '%s' УСТАНОВЛЕНО.\n",
                   perm, category, path);
            return 0; // код 0 — право есть
        } else {
            printf("Право '%c' для категории '%c' у файла '%s' НЕ установлено.\n",
                   perm, category, path);
            return 1; // код 1 — права нет
        }
    }

    // Режим просмотра информации
    if (argc == 2) {
        const char *path = argv[1];
        struct stat st;
        if (stat(path, &st) == -1) {
            fprintf(stderr, "Ошибка stat(%s): %s\n", path, strerror(errno));
            return 1;
        }
        print_file_info(path, &st);
        return 0;
    }

    // Режим установки прав для файла
    if (argc == 3) {
        const char *path = argv[1];
        const char *mode_spec = argv[2];

        struct stat st;
        if (stat(path, &st) == -1) {
            fprintf(stderr, "Ошибка stat(%s): %s\n", path, strerror(errno));
            return 1;
        }

        mode_t new_mode;
        int is_octal = 1;
        for (const char *p = mode_spec; *p; p++) {
            if (*p < '0' || *p > '7') { is_octal = 0; break; }
        }

        if (is_octal) {
            // Восьмеричный формат
            char *endptr;
            long val = strtol(mode_spec, &endptr, 8);
            if (*endptr != '\0' || val < 0 || val > 07777) {
                fprintf(stderr, "Ошибка: неверный восьмеричный режим '%s'\n", mode_spec);
                return 1;
            }
            new_mode = (mode_t)val;
        } else {
            // Символьный формат
            if (parse_symbolic_mode(mode_spec, st.st_mode & 07777, &new_mode) != 0) {
                return 1;
            }
        }

        if (chmod(path, new_mode) == -1) {
            fprintf(stderr, "Ошибка chmod(%s): %s\n", path, strerror(errno));
            return 1;
        }

        printf("Права для '%s' успешно изменены.\n", path);

        if (stat(path, &st) == 0) {
            print_file_info(path, &st);
        }
        return 0;
    }

    // При неверном числе аргументов
    usage(argv[0]);
    return 1;
}