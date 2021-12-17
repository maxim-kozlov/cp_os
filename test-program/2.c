//testKernelIO.c
#include <fcntl.h>

int main()
{
    int fd1 = open("alphabet.txt", O_RDONLY);
    int fd2 = open("test.txt", O_RDONLY);

    close(fd1);
    close(fd2);
    return 0;
}
