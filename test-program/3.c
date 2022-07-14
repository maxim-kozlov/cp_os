#include <stdio.h>

// int main()
// {
//     FILE *f = fopen("alphabet.txt", "r");
//     char buf[128];

//     fscanf(f, "%s", buf);
//     printf("%s", buf);

//     fclose(f);
//     return 0;
// }

#include <fcntl.h>
int main()
{
    int fd = open("alphabet.txt", O_RDONLY);
    char buf[128];

    int len = read(fd, buf, 128);
    buf[len] = 0;
    write(1, buf, len);

    close(fd);
    return 0;
}