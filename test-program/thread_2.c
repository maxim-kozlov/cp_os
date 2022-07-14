#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>

void *read_file(void *arg)
{
    int fd = open("alphabet.txt", O_RDONLY);

    char c;
    while (read(fd, &c, 1) == 1)
        write(1, &c, 1);

    return 0;
}

int main()
{    
    pthread_t thread;
    int code = pthread_create(&thread, NULL, read_file, NULL);
    if (code != 0)
    {
        printf("can't create thread, code = %d\n", code);
        return -1;
    }

    read_file(NULL);
    pthread_join(thread, NULL);
    
    return 0;
}