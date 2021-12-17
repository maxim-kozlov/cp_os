#include <stdio.h>

int main()
{
    FILE *f = fopen("alphabet.txt", "r");
    char buf[128];

    fscanf(f, "%s", buf);
    printf("%s", buf);

    fclose(f);
    return 0;
}