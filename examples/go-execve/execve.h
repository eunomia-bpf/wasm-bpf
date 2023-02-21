#define COMM_SIZE 352
#define MAX_ARG_NUM 8

#define ARG_LEN COMM_SIZE / MAX_ARG_NUM

struct comm_event {
    int pid;
    char parent_proc[16];
    char command[COMM_SIZE];
};