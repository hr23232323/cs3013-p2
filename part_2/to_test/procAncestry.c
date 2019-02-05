#include <sys/syscall.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

// Syscall number found from syscall_32.tbl from project 1
// Used to avoid table lookup from user porgram
#define __NR_cs3013_syscall2 378

// Struct given in the problem to hold ancestry
typedef struct ancestry{
  pid_t ancestors[10];
  pid_t siblings[100];
  pid_t children[100];
} ancestry;



int main(int argc, char* argv[]){
	// Need to enter pid
	if(argc<2){
		printf("No process ID entered!!!\n\n");
		exit(-1);
	}

	unsigned short pid;
	unsigned short* pid_val;
	unsigned long return_val;


	pid = atoi(argv[1]);
	pid_val = &pid;

	// Assign memory in user space as defined by project description
	ancestry* info = (ancestry*)malloc(sizeof(ancestry));

	// Run Sys call using manually found sys call number
	return_val = (long) syscall(__NR_cs3013_syscall2, pid_val, info);
	printf("Testing syscalls new!!\n");
	printf("%d\n", pid);
	printf("%ld\n", return_val);
	return 0;
}