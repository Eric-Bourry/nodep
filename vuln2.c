#include <stdio.h>
#include <string.h>
#include <unistd.h>

// pop eax; ret         : /x58/xc3                  0x0804846e
// xor ebx,ebx ; ret  : /x31/xdb/xc3          0x08048475

// echo -e "pop %eax \n ret" | as -al | tail -n +4 ; rm a.out

int my_execlp() // 0x8048444
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
