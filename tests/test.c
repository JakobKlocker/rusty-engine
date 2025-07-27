#include <stdio.h>
#include <unistd.h>
int main() {
    puts("Test program started, going to sleep.");
    sleep(30);
    puts("Test program finishing.");
    return 0;
}
