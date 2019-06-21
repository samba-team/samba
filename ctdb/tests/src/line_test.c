/*
   Test code for line based I/O over fds

   Copyright (C) Amitay Isaacs  2018

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

#include "replace.h"
#include "system/filesys.h"

#include <talloc.h>
#include <assert.h>

#include "common/line.c"

static int line_print(char *line, void *private_data)
{
	printf("%s\n", line);
	fflush(stdout);

	return 0;
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	size_t hint = 32;
	pid_t pid;
	int ret, lines = 0;
	int pipefd[2];

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <filename> [<hint>]\n", argv[0]);
		exit(1);
	}

	if (argc == 3) {
		long value;

		value = atol(argv[2]);
		assert(value > 0);
		hint = value;
	}

	ret = pipe(pipefd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		char buffer[16];
		ssize_t n, n2;
		int fd;

		close(pipefd[0]);

		fd = open(argv[1], O_RDONLY);
		assert(fd != -1);

		while (1) {
			n = read(fd, buffer, sizeof(buffer));
			assert(n >= 0 && (size_t)n <= sizeof(buffer));

			if (n == 0) {
				break;
			}

			n2 = write(pipefd[1], buffer, n);
			assert(n2 == n);
		}

		close(pipefd[1]);
		close(fd);

		exit(0);
	}

	close(pipefd[1]);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ret = line_read(pipefd[0], hint, NULL, line_print, NULL, &lines);
	assert(ret == 0);

	talloc_free(mem_ctx);

	return lines;
}
