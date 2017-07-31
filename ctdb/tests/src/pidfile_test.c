/*
   pidfile tests

   Copyright (C) Amitay Isaacs  2016

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
#include "system/wait.h"

#include <assert.h>

#include "common/pidfile.c"


/* create pid file, check pid file exists, check pid and remove pid file */
static void test1(const char *pidfile)
{
	struct pidfile_context *pid_ctx;
	int ret;
	struct stat st;
	FILE *fp;
	pid_t pid;

	ret = pidfile_context_create(NULL, pidfile, &pid_ctx);
	assert(ret == 0);
	assert(pid_ctx != NULL);

	ret = stat(pidfile, &st);
	assert(ret == 0);
	assert(S_ISREG(st.st_mode));

	fp = fopen(pidfile, "r");
	assert(fp != NULL);
	ret = fscanf(fp, "%d", &pid);
	assert(ret == 1);
	assert(pid == getpid());
	fclose(fp);

	TALLOC_FREE(pid_ctx);

	ret = stat(pidfile, &st);
	assert(ret == -1);
}

/* create pid file in two processes */
static void test2(const char *pidfile)
{
	struct pidfile_context *pid_ctx;
	pid_t pid, pid2;
	int fd[2];
	int ret;
	size_t nread;
	FILE *fp;
	struct stat st;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		ssize_t nwritten;

		close(fd[0]);

		ret = pidfile_context_create(NULL, pidfile, &pid_ctx);
		assert(ret == 0);
		assert(pid_ctx != NULL);

		nwritten = write(fd[1], &ret, sizeof(ret));
		assert(nwritten == sizeof(ret));

		sleep(10);

		TALLOC_FREE(pid_ctx);

		nwritten = write(fd[1], &ret, sizeof(ret));
		assert(nwritten == sizeof(ret));

		exit(1);
	}

	close(fd[1]);

	nread = read(fd[0], &ret, sizeof(ret));
	assert(nread == sizeof(ret));
	assert(ret == 0);

	fp = fopen(pidfile, "r");
	assert(fp != NULL);
	ret = fscanf(fp, "%d", &pid2);
	assert(ret == 1);
	assert(pid == pid2);
	fclose(fp);

	ret = pidfile_context_create(NULL, pidfile, &pid_ctx);
	assert(ret != 0);

	nread = read(fd[0], &ret, sizeof(ret));
	assert(nread == sizeof(ret));
	assert(ret == 0);

	ret = pidfile_context_create(NULL, pidfile, &pid_ctx);
	assert(ret == 0);
	assert(pid_ctx != NULL);

	TALLOC_FREE(pid_ctx);

	ret = stat(pidfile, &st);
	assert(ret == -1);
}

/* create pid file, fork, try to remove pid file in separate process */
static void test3(const char *pidfile)
{
	struct pidfile_context *pid_ctx;
	pid_t pid;
	int fd[2];
	int ret;
	size_t nread;
	struct stat st;

	ret = pidfile_context_create(NULL, pidfile, &pid_ctx);
	assert(ret == 0);
	assert(pid_ctx != NULL);

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		ssize_t nwritten;

		close(fd[0]);

		TALLOC_FREE(pid_ctx);

		nwritten = write(fd[1], &ret, sizeof(ret));
		assert(nwritten == sizeof(ret));

		exit(1);
	}

	close(fd[1]);

	nread = read(fd[0], &ret, sizeof(ret));
	assert(nread == sizeof(ret));

	ret = stat(pidfile, &st);
	assert(ret == 0);

	TALLOC_FREE(pid_ctx);

	ret = stat(pidfile, &st);
	assert(ret == -1);
}

/* create pid file, kill process, overwrite pid file in different process */
static void test4(const char *pidfile)
{
	struct pidfile_context *pid_ctx;
	pid_t pid, pid2;
	int fd[2];
	int ret;
	size_t nread;
	struct stat st;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		ssize_t nwritten;

		close(fd[0]);

		ret = pidfile_context_create(NULL, pidfile, &pid_ctx);

		nwritten = write(fd[1], &ret, sizeof(ret));
		assert(nwritten == sizeof(ret));

		sleep(99);
		exit(1);
	}

	close(fd[1]);

	nread = read(fd[0], &ret, sizeof(ret));
	assert(nread == sizeof(ret));
	assert(ret == 0);

	ret = stat(pidfile, &st);
	assert(ret == 0);

	ret = kill(pid, SIGKILL);
	assert(ret == 0);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);

	ret = pidfile_context_create(NULL, pidfile, &pid_ctx);
	assert(ret == 0);
	assert(pid_ctx != NULL);

	ret = stat(pidfile, &st);
	assert(ret == 0);

	TALLOC_FREE(pid_ctx);
}

int main(int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pidfile>\n", argv[0]);
		exit(1);
	}

	test1(argv[1]);
	test2(argv[1]);
	test3(argv[1]);
	test4(argv[1]);

	return 0;
}
