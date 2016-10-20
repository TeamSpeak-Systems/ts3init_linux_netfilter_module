#ifndef _TS3INIT_COOKIE_SEED_H
#define _TS3INIT_COOKIE_SEED_H

enum {
    RANDOM_SEED_LEN = 60,
    RANDOM_SEED_PATH_MAX = 256,
};

/* 
 * Parses a hexstring into dest.
 * It is assumed that RANDOM_SEED_LEN bytes are to be parsed.
 */
static inline bool parse_random_seed(const char *src, __u8* dst)
{
    int i, j;
    for (i = 0; i < RANDOM_SEED_LEN; ++i)
    {
        int v = 0;
        for ( j = 0; j < 2; ++j)
        {
            uint8_t byte = *src++; 
                if (byte >= '0' && byte <= '9') byte = byte - '0';
                else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
                else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;
            else return false;
                v = (v << 4) | byte;
        }
        *dst++ = v;
    }
    return true;
}

#ifndef __KERNEL__

/* 
 * Reads a cookie seed from a file.
 */
static inline bool read_random_seed_from_file(const char *module_name, const char *path, __u8* dst)
{
    int n, fd;
    char text[RANDOM_SEED_LEN * 2], error_message[256];
    if (strlen(path) > RANDOM_SEED_PATH_MAX)
    {
        xtables_error(PARAMETER_PROBLEM, "%s: path is too long.", module_name);
        return false;
    }

    fd = open(path, O_RDONLY);
    if (fd == -1) goto io_error;
    if (lseek(fd, 0, SEEK_END) == sizeof(text))
    {
        xtables_error(PARAMETER_PROBLEM, "%s: %s must contain exactly %lu characters", module_name, path, sizeof(text));
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) == -1) goto io_error;

    n = read(fd, text, sizeof(text));
    if (n == -1) goto io_error; 
    else if (n != sizeof(text) || parse_random_seed(text, dst) == false)
    {
        xtables_error(PARAMETER_PROBLEM, "%s: %s must contain exactly %lu lowercase hex characters", module_name, path, sizeof(text));
        return false;
    }
    return true;
io_error:
    strerror_r(errno, error_message, sizeof(error_message));
    xtables_error(PARAMETER_PROBLEM, "%s: %s.", 
        module_name,
        error_message);
    return false;
}

#endif /* __KERNEL__ */
#endif /* _TS3INIT_COOKIE_SEED_H */
