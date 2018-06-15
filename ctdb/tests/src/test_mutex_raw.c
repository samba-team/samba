/*
 * Test the system robust mutex implementation
 *
 * Copyright (C) 2016 Amitay Isaacs
 * Copyright (C) 2018 Red Hat Inc.
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * To run the test do the following:
 *
 * (a) Compile the test.
 *
 *     gcc -O2 -g3 -o test-robust-mutex test-robust-mutex.c -lpthread
 *
 * (b) Start the "init" process.
 *
 *     ./test-robust-mutex /tmp/shared-mutex init
 *
 * (c) Start any number of "worker" instances.
 *
 *     ./test-robust-mutex <Shared memory file> worker <#> <Priority>
 *
 *     <Shared memory file> e.g. /tmp/shared-mutex.
 *
 *     <#> : Number of children processes.
 *
 *     <Priority> : 0 - Normal, 1 - Realtime, 2 - Nice 20.
 *
 *    For example:
 *
 *     As non-root:
 *
 *     $ while true ; do ./test-robust-mutex /tmp/foo worker 10 0 ; done;
 *
 *     As root:
 *
 *     while true ; do ./test-robust-mutex /tmp/foo worker 10 1 ; done;
 *
 *    This creates 20 processes, 10 at normal priority and 10 at realtime
 *    priority, all taking the lock, being killed and recovering the lock.
 *
 * If while runnig (c) the processes block, it might mean that a futex wakeup
 * was lost, or that the handoff of EOWNERDEAD did not happen correctly. In
 * either case you can debug the resulting mutex like this:
 *
 *     $ ./test-robust-mutex /tmp/shared-mutex debug
 *
 * This prints the PID of the process holding the mutex or nothing if
 * the value was cleared by the kernel and now no process holds the mutex.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>

/* Define DEBUG to 1 to enable verbose debugging.  */
#define DEBUG 0

/* Implement the worker.  The worker has to do the following things:

   * Succeed at locking the mutex, including possible recovery.
   * Kill itself.

   Other workers are attempting exactly the same thing in order to
   test the loss and recovery of the robust mutex.  */
static void worker (const char *filename)
{
	pthread_mutex_t *mutex;
	void *addr;
	int ret, fd;

	/* Open the file and map the shared robust mutex.  */
	fd = open(filename, O_RDWR, 0600);
	if (fd == -1) {
		perror ("FAIL: open");
		exit(EXIT_FAILURE);
	}

	addr = mmap(NULL,
		    sizeof(pthread_mutex_t),
		    PROT_READ|PROT_WRITE,
		    MAP_SHARED|MAP_FILE,
		    fd,
		    0);
	if (addr == NULL) {
		perror ("FAIL: mmap");
		exit(EXIT_FAILURE);
	}

	mutex = (pthread_mutex_t *)addr;

	/* Every process will lock once, and die once.  */
	printf("INFO: pid %u locking\n", getpid());
	do {
		ret = pthread_mutex_lock(mutex);

#if DEBUG
		fprintf(stderr,
			"DEBUG: pid %u lock attempt, ret=%d\n",
			getpid(),
			ret);
#endif

		if (ret == EOWNERDEAD) {
			int rc;

			rc = pthread_mutex_consistent(mutex);
			if (rc == 0) {
				pthread_mutex_unlock(mutex);
			} else {
				fprintf(stderr,
					"FAIL: pthread_mutex_consistent "
					"failed\n");
				exit(EXIT_FAILURE);
			}
#if DEBUG
			fprintf(stderr,
				"DEBUG: pid %u recovery lock attempt, ret=%d\n",
				getpid(),
				ret);
#endif
			/* Will loop and try to lock again.  */
		}

	} while (ret != 0);

	printf ("INFO: pid %u locked, now killing\n", getpid());
	kill(getpid(), SIGKILL);
}

/* One of three priority modes.  */
#define PRIO_NORMAL	0
#define PRIO_REALTIME	1
#define PRIO_NICE_20	2

/* One of three operation modes.  */
#define MODE_INIT	0
#define MODE_WORKER	1
#define MODE_DEBUG	2

/* Print usage information and exit.  */
static void usage (const char *name)
{
	fprintf(stderr,
		"Usage: %s <file> [init|worker|debug] [#] [0|1|2]\n",
		name);
	exit(EXIT_FAILURE);
}

/* Set the process priority.  */
static void set_priority (int priority)
{
	struct sched_param p;
	int ret;

	switch (priority) {
	case PRIO_REALTIME:
		p.sched_priority = 1;
		ret = sched_setscheduler(0, SCHED_FIFO, &p);
		if (ret == -1)
			perror("FAIL: sched_setscheduler");
		break;

	case PRIO_NICE_20:
		ret = nice(-20);
		if (ret == -1)
			perror("FAIL: nice");
		break;

	case PRIO_NORMAL:
	default:
		/* Normal priority is the default.  */
		break;
	}
}

int main(int argc, const char **argv)
{
	int i, fd, ret, num_children, mode = -1, priority = PRIO_NORMAL;
	const char *mode_str;
	const char *file;
	char *addr;
	pthread_mutex_t *mutex;
	pthread_mutexattr_t mattr;
	pid_t pid;

	/* One of three modes, init, worker, or debug.  */
	if (argc < 3 || argc > 5)
		usage (argv[0]);

	/*
	 * The shared memory file.  Care should be taken here because if glibc
	 * is upgraded between runs the internals of the robust mutex could
	 * change. See this blog post about the dangers:
	 * https://developers.redhat.com/blog/2017/03/13/cc-library-upgrades-and-opaque-data-types-in-process-shared-memory/
	 * and how to avoid problems inherent in this.
	 */
	file = argv[1];

	/* Set the mode.  */
	mode_str = argv[2];
	if (strcmp ("init", mode_str) == 0) {
		mode = MODE_INIT;
	} else if (strcmp ("worker", mode_str) == 0) {
		mode = MODE_WORKER;
	} else if (strcmp ("debug", mode_str) == 0) {
		mode = MODE_DEBUG;
	} else {
		usage (argv[0]);
	}

	/* This is "worker" mode, so set the priority.  */
	if (mode == MODE_WORKER) {
		priority = atoi(argv[4]);
		set_priority(priority);
	}

	/* All modes open the file.  */
	fd = open(argv[1], O_CREAT|O_RDWR, 0600);
	if (fd == -1) {
		perror("FAIL: open");
		exit(EXIT_FAILURE);
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret != 0) {
		perror("FAIL: lseek");
		exit(EXIT_FAILURE);
	}

	/* Truncate the file backing the mutex only in the init phase.  */
	if (mode == MODE_INIT) {
		ret = ftruncate(fd, sizeof(pthread_mutex_t));
		if (ret != 0) {
			perror("FAIL: ftruncate");
			exit(EXIT_FAILURE);
		}
	}

	/* Map the robust mutex.  */
	addr = mmap(NULL,
		    sizeof(pthread_mutex_t),
		    PROT_READ|PROT_WRITE,
		    MAP_SHARED|MAP_FILE,
		    fd,
		    0);
	if (addr == NULL) {
		perror("FAIL: mmap");
		exit(EXIT_FAILURE);
	}

	mutex = (pthread_mutex_t *)(void *)addr;

	/*
	 * In the debug mode we try to recover the mutex and print it.
	 * WARNING: All other processes should be stuck, otherwise they may
	 * change the value of the lock between trylock and the printing after
	 * EBUSY.
	 */
	if (mode == MODE_DEBUG) {
		ret = pthread_mutex_trylock(mutex);
		if (ret == EOWNERDEAD) {
			ret = pthread_mutex_consistent(mutex);
			if (ret == 0) {
				pthread_mutex_unlock(mutex);
			} else {
				fprintf(stderr,
					"FAIL: pthread_mutex_consistent "
					"failed\n");
				exit (EXIT_FAILURE);
			}
		} else if (ret == EBUSY) {
			printf("INFO: pid=%u\n", mutex->__data.__owner);
		} else if (ret == 0) {
			pthread_mutex_unlock(mutex);
		}
		exit(EXIT_SUCCESS);
	}

	/*
	 * Only the initializing process does initialization because it is
	 * undefined behaviour to re-initialize an already initialized mutex
	 * that was not destroyed.
	 */
	if (mode == MODE_INIT) {

		ret = pthread_mutexattr_init(&mattr);
		if (ret != 0) {
			fprintf(stderr,
				"FAIL: pthread_mutexattr_init failed\n");
			exit(EXIT_FAILURE);
		}

		ret = pthread_mutexattr_settype(&mattr,
						PTHREAD_MUTEX_ERRORCHECK);
		if (ret != 0) {
			fprintf(stderr,
				"FAIL: pthread_mutexattr_settype failed\n");
			exit(EXIT_FAILURE);
		}

		ret = pthread_mutexattr_setpshared(&mattr,
						   PTHREAD_PROCESS_SHARED);
		if (ret != 0) {
			fprintf(stderr,
				"FAIL: pthread_mutexattr_setpshared failed\n");
			exit(EXIT_FAILURE);
		}

		ret = pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
		if (ret != 0) {
			fprintf(stderr,
				"FAIL: pthread_mutexattr_setrobust failed\n");
			exit(EXIT_FAILURE);
		}

		ret = pthread_mutex_init(mutex, &mattr);
		if (ret != 0) {
			fprintf(stderr, "FAIL: pthread_mutex_init failed\n");
			exit(EXIT_FAILURE);
		}

		printf ("INFO: init: Mutex initialization complete.\n");
		/* Never exit.  */
		for (;;)
			sleep (1);
	}

	/* Acquire the mutext for the first time. Might be dead.
	   Might also be concurrent with the high-priority threads.  */
	fprintf(stderr,
		"INFO: parent: Acquiring mutex (pid = %d).\n",
		getpid());
	do {
		ret = pthread_mutex_lock(mutex);

		/* Not consistent? Try to make it so.  */
		if (ret == EOWNERDEAD) {
			int rc;

			rc = pthread_mutex_consistent(mutex);
			if (rc == 0) {
				pthread_mutex_unlock (mutex);
			} else {
				fprintf(stderr,
					"FAIL: pthread_mutex_consistent "
					"failed\n");
				exit (EXIT_FAILURE);
			}

			/* Will loop and try to lock again.  */
			fprintf(stderr,
				"INFO: parent: Unlock recovery ret = %d\n",
				ret);
		}

	} while (ret != 0);

	/*
	 * Set the parent process into it's own process group (hides the
	 * children).
	 */
	setpgid(0, 0);

	/* Create # of children.  */
	fprintf(stderr, "INFO: parent: Creating children\n");
	num_children = atoi(argv[3]);

	for (i = 0; i < num_children; i++) {
		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "FAIL: fork() failed\n");
			exit(EXIT_FAILURE);
		}
		if (pid == 0) {
			close(fd);
			worker(file);
			exit(EXIT_FAILURE);
		}
	}

	fprintf(stderr, "INFO: parent: Waiting for children\n");

	/* Unlock the recently acquired mutex or the old lost mutex. */
	ret = pthread_mutex_unlock(mutex);
	if (ret != 0) {
		fprintf(stderr, "FAIL: pthread_mutex_unlock failed\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * All threads are running now, and each will take the lock and
	 * die in turn. When they are all dead we will exit and be started
	 * again by the caller.
	 */
	for (i = 0; i < num_children; i++) {
		int status;
		pid = waitpid(-1, &status, 0);
		if (pid <= 0) {
			fprintf(stderr, "FAIL: waitpid() failed\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr,
			"INFO: parent: Reaped %u\n",
			(unsigned int) pid);
	}

	/* We never unlink fd.  The file must be cleaned up by the caller. */
	close(fd);

	exit(EXIT_SUCCESS);
}
