/*
   Robust mutex test

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

/*
 * Run this test as follows:
 *
 * 1. Running all processes at normal priority
 *
 *  $ while true ; do ./bin/test_mutex_raw /tmp/foo 10 0 ; done
 *
 * 2. Running all processes at real-time priority
 *
 *  # while true ; do ./bin/test_mutex_raw /tmp/foo 10 1 ; done
 *
 * The test will block after few iterations.  At this time none of the 
 * child processes is holding the mutex.
 *
 * To check which process is holding a lock:
 *
 *  $ ./bin/test_mutex_raw /tmp/foo debug
 *
 *  If no pid is printed, then no process is holding the mutex.
 */

#include "replace.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "system/shmem.h"
#include "system/threads.h"

static void set_realtime(void)
{
	struct sched_param p;
	int ret;

	p.sched_priority = 1;

	ret = sched_setscheduler(0, SCHED_FIFO, &p);
	if (ret == -1) {
		fprintf(stderr, "Failed to set scheduler to SCHED_FIFO\n");
	}
}

static void high_priority(void)
{
	int ret;

	ret = nice(-20);
	if (ret == -1) {
		fprintf(stderr, "Failed to set high priority\n");
	}
}

static void run_child(const char *filename)
{
	pthread_mutex_t *mutex;
	void *addr;
	int ret, fd;

	fd = open(filename, O_RDWR, 0600);
	if (fd == -1) {
		exit(1);
	}

	addr = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE,
		    MAP_SHARED|MAP_FILE, fd, 0);
	if (addr == NULL) {
		exit(2);
	}

	mutex = (pthread_mutex_t *)addr;

again:
	ret = pthread_mutex_lock(mutex);
	if (ret == EOWNERDEAD) {
		ret = pthread_mutex_consistent(mutex);
	} else if (ret == EAGAIN) {
		goto again;
	}
	if (ret != 0) {
		fprintf(stderr, "pid %u lock failed, ret=%d\n", getpid(), ret);
		exit(3);
	}

	fprintf(stderr, "pid %u locked\n", getpid());
	kill(getpid(), SIGKILL);
}

#define PRIO_NORMAL	0
#define PRIO_REALTIME	1
#define PRIO_NICE_20	2

int main(int argc, const char **argv)
{
	pthread_mutexattr_t ma;
	pthread_mutex_t *mutex;
	int fd, ret, i;
	pid_t pid;
	void *addr;
	int num_children;
	int priority = PRIO_NORMAL;

	if (argc < 3 || argc > 4) {
		fprintf(stderr, "Usage: %s <file> <n> [0|1|2]\n", argv[0]);
		fprintf(stderr, "       %s <file> debug\n", argv[0]);
		exit(1);
	}

	if (argc == 4) {
		priority = atoi(argv[3]);
	}

	if (priority == PRIO_REALTIME) {
		set_realtime();
	} else if (priority == PRIO_NICE_20) {
		high_priority();
	}

	fd = open(argv[1], O_CREAT|O_RDWR, 0600);
	if (fd == -1) {
		fprintf(stderr, "open failed\n");
		exit(1);
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret != 0) {
		fprintf(stderr, "lseek failed\n");
		exit(1);
	}

	ret = ftruncate(fd, sizeof(pthread_mutex_t));
	if (ret != 0) {
		fprintf(stderr, "ftruncate failed\n");
		exit(1);
	}

	addr = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE,
		    MAP_SHARED|MAP_FILE, fd, 0);
	if (addr == NULL) {
		fprintf(stderr, "mmap failed\n");
		exit(1);
	}

	mutex = (pthread_mutex_t *)addr;

	if (strcmp(argv[2], "debug") == 0) {
		ret = pthread_mutex_trylock(mutex);
		if (ret == EOWNERDEAD) {
			ret = pthread_mutex_consistent(mutex);
			if (ret == 0) {
				pthread_mutex_unlock(mutex);
			}
		} else if (ret == EBUSY) {
			printf("pid=%u\n", mutex->__data.__owner);
		} else if (ret == 0) {
			pthread_mutex_unlock(mutex);
		}
		exit(0);
	}

	ret = pthread_mutexattr_init(&ma);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutexattr_init failed\n");
		exit(1);
	}

	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutexattr_settype failed\n");
		exit(1);
	}

	ret = pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutexattr_setpshared failed\n");
		exit(1);
	}

	ret = pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutexattr_setrobust failed\n");
		exit(1);
	}

	ret = pthread_mutex_init(mutex, &ma);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutex_init failed\n");
		exit(1);
	}

	ret = pthread_mutex_lock(mutex);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutex_lock failed\n");
		exit(1);
	}

	setpgid(0, 0);

	fprintf(stderr, "Creating children\n");
	num_children = atoi(argv[2]);

	for (i=0; i<num_children; i++) {
		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "fork() failed\n");
			exit(1);
		}
		if (pid == 0) {
			close(fd);
			run_child(argv[1]);
			exit(1);
		}
	}

	fprintf(stderr, "Waiting for children\n");

	ret = pthread_mutex_unlock(mutex);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutex_unlock failed\n");
		exit(1);
	}

	for (i=0; i<num_children; i++) {
		int status;

		pid = waitpid(-1, &status, 0);
		if (pid <= 0) {
			fprintf(stderr, "waitpid() failed\n");
		}
	}

	close(fd);
	unlink(argv[1]);
	exit(0);
}
