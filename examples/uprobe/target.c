#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

int uprobe_add(int a, int b){
    return a + b;
}

int uprobe_sub(int a, int b){
    return a - b;
}

int main(){
    while (1) {
        int a = 1;
        int b = 1;
        printf("%d %d\n", uprobe_add(a, b), uprobe_sub(a, b));
        sleep(2);
    }
}