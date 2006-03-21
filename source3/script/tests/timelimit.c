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

static void usage(void)
{
	printf("usage: timelimit <time> <command>\n");
}

static void sig_alrm(int sig)
{
	kill(0, SIGKILL);
	exit(1);
}

static void sig_term_kill(int sig)
{
	static int c = 0;

	if (c > 2) {
		kill(0, SIGKILL);
		exit(0);
	}

	c++;
}

static void sig_term(int sig)
{
	kill(0, SIGTERM);
	signal(SIGTERM, sig_term_kill);
}

int main(int argc, char *argv[])
{
	int maxtime, ret=1;

	if (argc < 3) {
		usage();
		exit(1);
	}

	if (setpgrp() == -1) {
		perror("setpgrp");
		exit(1);
	}

	maxtime = atoi(argv[1]);
	signal(SIGALRM, sig_alrm);
	alarm(maxtime);
	signal(SIGTERM, sig_term);

	if (fork() == 0) {
		execvp(argv[2], argv+2);
	}

	do {
		int status;
		pid_t pid = wait(&status);
		if (pid != -1) {
			ret = WEXITSTATUS(status);
		} else if (errno == ECHILD) {
			break;
		}
	} while (1);

	exit(ret);
}
