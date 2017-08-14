/*
 * Test async connect
 * Copyright (C) Ralph Boehme 2015
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <tevent.h>
#include "lib/async_req/async_sock.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, const char *argv[])
{
	int result, listen_sock, status, exit_status;
	uint16_t port;
	struct sockaddr_in addr = { 0 };
	pid_t pid;

	listen_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (listen_sock == -1) {
		perror("socket() failed");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	for (port = 1024; port < UINT16_MAX; port++) {
		addr.sin_port = htons(port);
		result = bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
		if (result == 0) {
			break;
		}
	}

	if (port == UINT16_MAX) {
		printf("Huh, no free port?\n");
		return 1;
	}

	result = listen(listen_sock, 1);
	if (result == -1) {
		perror("listen() failed");
		close(listen_sock);
		return 1;
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		struct tevent_context *ev;
		struct tevent_req *req;
		int fd;

		ev = tevent_context_init(NULL);
		if (ev == NULL) {
			fprintf(stderr, "tevent_context_init failed\n");
			return 1;
		}

		fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			perror("socket");
			return 1;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");

		req = async_connect_send(ev, ev, fd,
					 (struct sockaddr *)&addr,
					 sizeof(struct sockaddr_in),
					 NULL, NULL, NULL);

		if (!tevent_req_poll(req, ev)) {
			perror("tevent_req_poll() failed");
			return 1;
		}

		status = 0;
		result = async_connect_recv(req, &status);
		if (result != 0) {
			return status;
		}
		return 0;
	}

	result = waitpid(pid, &status, 0);
	if (result == -1) {
		perror("waitpid");
		return 1;
	}

	if (!WIFEXITED(status)) {
		printf("child status: %d\n", status);
		return 2;
	}

	exit_status = WEXITSTATUS(status);
	printf("test done: status=%d\n", exit_status);

	if (exit_status != 0) {
		return exit_status;
	}

	return 0;
}
