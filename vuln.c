#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
    char buffer[1000] = "";
    strcpy(buffer, argv[1]);
    printf("Copied a %u-byte-long buffer\n", strlen(buffer));
    return 0;
}
