/*
 * CTDB test helper to run a command with a socket on stdin
 *
 * Copyright 2026, DataDirect Networks, Inc. All rights reserved.
 * Author: Martin Schwenke <mschwenke@ddn.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The other end of the socket is held open until the command exits,
 * like a parent process that starts a daemon.  Killing this process
 * closes it.
 */

#include "replace.h"
#include "system/network.h"
#include "system/wait.h"

int main(int argc, char *argv[])
{
	pid_t pid;
	int fd[2];
	int status;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <command> [<args>...]\n", argv[0]);
		exit(1);
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	if (ret != 0) {
		fprintf(stderr, "socketpair() failed (%d)\n", errno);
		exit(1);
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "fork() failed (%d)\n", errno);
		exit(1);
	}

	if (pid == 0) {
		close(fd[0]);
		ret = dup2(fd[1], STDIN_FILENO);
		if (ret == -1) {
			fprintf(stderr, "dup2() failed (%d)\n", errno);
			_exit(1);
		}
		close(fd[1]);
		execvp(argv[1], &argv[1]);
		fprintf(stderr, "Failed to execute %s (%d)\n", argv[1], errno);
		_exit(1);
	}

	close(fd[1]);

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret == -1 && errno == EINTR);
	if (ret == -1) {
		fprintf(stderr, "waitpid() failed (%d)\n", errno);
		exit(1);
	}

	close(fd[0]);

	if (WIFSIGNALED(status)) {
		exit(128 + WTERMSIG(status));
	}

	exit(WEXITSTATUS(status));
}
