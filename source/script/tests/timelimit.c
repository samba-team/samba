/* run a command with a limited timeout
   tridge@samba.org, June 2005

   attempt to be as portable as possible (fighting posix all the way)
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

static pid_t child_pid;

static void usage(void)
{
	printf("usage: timelimit <time> <command>\n");
	printf("   SIGALRM - passes SIGKILL to command's process group and exit(1)\n");
	printf("   SIGUSR1 - passes SIGTERM to command's process group\n");
	printf("   SIGTERM - passes SIGTERM to command's process group and exit(0)\n");
}

static void sig_alrm(int sig)
{
	fprintf(stderr, "\nMaximum time expired in timelimit - killing\n");
	kill(-child_pid, SIGKILL);
	exit(1);
}

static void sig_term(int sig)
{
	kill(-child_pid, SIGTERM);
	exit(0);
}

static void sig_usr1(int sig)
{
	kill(-child_pid, SIGTERM);
}

static void new_process_group(void)
{
#ifdef BSD_SETPGRP
	if (setpgrp(0,0) == -1) {
		perror("setpgrp");
		exit(1);
	}
#else
	if (setpgrp() == -1) {
		perror("setpgrp");
		exit(1);
	}
#endif
}


int main(int argc, char *argv[])
{
	int maxtime, ret=1;
	pid_t pgid;

	if (argc < 3) {
		usage();
		exit(1);
	}

	maxtime = atoi(argv[1]);

	child_pid = fork();
	if (child_pid == 0) {
		new_process_group();
		execvp(argv[2], argv+2);
		perror(argv[2]);
		exit(1);
	}

	signal(SIGTERM, sig_term);
	signal(SIGUSR1, sig_usr1);
	signal(SIGALRM, sig_alrm);
	alarm(maxtime);

	do {
		int status;
		pid_t pid = wait(&status);
		if (pid != -1) {
			ret = WEXITSTATUS(status);
		} else if (errno == ECHILD) {
			break;
		}
	} while (1);

	kill(-child_pid, SIGKILL);

	exit(ret);
}
