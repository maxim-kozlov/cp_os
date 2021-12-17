#include <fcntl.h>

int main()
{
    int fd1 = open("alphabet.txt", O_RDONLY);
    int fd2 = open("test.txt", O_RDONLY);
    // int fd3 = open("notFound", O_RDONLY);

    close(fd1);
    close(fd2);
    // close(fd3);
    return 0;
}
