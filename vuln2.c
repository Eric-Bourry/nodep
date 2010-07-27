#include <stdio.h>
#include <string.h>
#include <unistd.h>

int my_execlp() 
{
    const char *file, *arg;
    __asm__ __volatile__ 
    (
        "movl %%eax, %0\n"
        "movl %%ebx, %1"
        : "=m" (file), "=m" (arg)
    );
    return execlp(file, arg);
}

int foo()
{
    volatile int x = 0xaac358bb;
    return x-0x11c3db31;
}

int main(int argc, char** argv)
{
    char buffer[1000] = "";
    strcpy(buffer, argv[1]);
    printf("Copied a %u-byte-long buffer\n", strlen(buffer));
    return 0;
}
