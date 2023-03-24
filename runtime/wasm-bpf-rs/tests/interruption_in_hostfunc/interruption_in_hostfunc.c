#include <stdio.h>
__attribute__((import_module("test"), import_name("long_sleep"))) void
long_sleep(void);
int main() {
    puts("Call to long sleep..");
    long_sleep();
    return 0;
}
