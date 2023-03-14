#include <stdio.h>
#include <unistd.h>
#include <assert.h>
int main() {
    while (1) {
        char buf[] = "Tick!\n";
        int ret = fwrite(buf, 1, sizeof(buf), stdout);
        fflush(stdout);
        // Write debug information to stderr
        fprintf(stderr, "ret=%d\n", ret);
        usleep(1000 * 1000);
    }
    // Although it will never return..
    return 0;
}