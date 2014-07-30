/*
   ctdb event script helper

   Copyright (C) Amitay Isaacs  2013

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "ctdb_private.h"

static char *progname = NULL;


/* CTDB sends SIGTERM, when process must die */
static void sigterm(int sig)
{
	pid_t pid;

	/* all the child processes are running in the same process group */
	pid = getpgrp();
	if (pid == -1) {
		kill(-getpid(), SIGKILL);
	} else {
		kill(-pid, SIGKILL);
	}
	_exit(0);
}

static int check_executable(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0) {
		fprintf(stderr, "Failed to access '%s' - %s\n",
			path, strerror(errno));
		return errno;
	}

	if (!(st.st_mode & S_IXUSR)) {
		return ENOEXEC;
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: %s <log-fd> <output-fd> <script_path> <event> [<args>]\n",
		progname);
}

int main(int argc, char *argv[])
{
	int log_fd, write_fd;
	pid_t pid;
	int status, output;

	progname = argv[0];

	if (argc < 5) {
		usage();
		exit(1);
	}

	reset_scheduler();

	log_fd = atoi(argv[1]);
	write_fd = atoi(argv[2]);

	set_close_on_exec(write_fd);

	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	dup2(log_fd, STDOUT_FILENO);
	dup2(log_fd, STDERR_FILENO);
	close(log_fd);

	if (setpgid(0, 0) != 0) {
		fprintf(stderr, "Failed to create process group for event script - %s\n",
			strerror(errno));
		exit(1);
	}

	signal(SIGTERM, sigterm);

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork - %s\n", strerror(errno));
		exit(errno);
	}

	if (pid == 0) {
		int save_errno;

		execv(argv[3], &argv[3]);
		if (errno == EACCES) {
			save_errno = check_executable(argv[3]);
		} else {
			save_errno = errno;
			fprintf(stderr, "Error executing '%s' - %s\n",
				argv[3], strerror(errno));
		}
		_exit(save_errno);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		output = WEXITSTATUS(status);
		if (output == ENOENT || output == ENOEXEC) {
			output = -output;
		}
		sys_write(write_fd, &output, sizeof(output));
		exit(output);
	}

	exit(1);
}
