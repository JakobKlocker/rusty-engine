// test.c
#include <stdio.h>

void foo() {
    printf("In foo\n");
}

void bar() {
    foo();
    printf("In bar\n");
}

int main() {
    
    bar();
    printf("In main\n");
    getchar();
    return 0;
}
