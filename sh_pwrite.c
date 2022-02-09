#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <file> <data> <size> <offset>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    const char *data = argv[2];
    long data_size = atol(argv[3]);
    long offset = atol(argv[4]);

    if (data_size < 0) {
        fprintf(stderr, "size must be nonnegative\n");
        return 1;
    }
    if (offset < 0) {
        fprintf(stderr, "offset must be nonnegative\n");
        return 1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (pwrite(fd, data, data_size, offset) < 0) {
        perror("pwrite");
        return 1;
    }

    return 0;
}
