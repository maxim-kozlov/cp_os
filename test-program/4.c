#include <stdio.h>

int main()
{
    FILE *f = fopen("test.txt", "w");
    char buf[128] = "1234567890";

    fprintf(f, "%s", buf);
    fclose(f);
    return 0;
}