#include <stdio.h>
#include <sys/stat.h>
#include <pthread.h>

#define THREADS 4
void *write_file(void *arg)
{
    int num = (int)arg;
    struct stat statbuf;
    FILE *f = fopen("write_thread.txt", "w");
    stat("write_thread.txt", &statbuf);
    printf("fopen file #%d inode  = %ld, buffsize = %ld blocksize= %ld\n", num, statbuf.st_ino, statbuf.st_size, statbuf.st_blksize);

    for (char c = 'a' + num; c <= 'z'; c += THREADS)
        fprintf(f, "%c", c);

    fclose(f);
    stat("write_thread.txt", &statbuf);
    printf("fclose file #%d inode  = %ld, buffsize = %ld blocksize= %ld\n", num, statbuf.st_ino, statbuf.st_size, statbuf.st_blksize);
    return 0;   
}

int main()
{
    pthread_t threads[THREADS];

    for (int i = 0; i < THREADS; i++) 
    {
        int code = pthread_create(threads + i, NULL, write_file, i);
        if (code != 0)
        {
            printf("can't create thread, code = %d\n", code);
            return code;
        }
    }

    
    for (int i = 0; i < THREADS; i++) 
        pthread_join(threads[i], NULL);
    return 0;
}