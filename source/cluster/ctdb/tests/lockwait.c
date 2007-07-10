/* 
   test a lock wait idea

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "popt.h"
#include "cmdline.h"


struct lockwait_handle {
	struct fd_event *fde;
	int fd[2];
	pid_t child;
	void *private_data;
	void (*callback)(void *);
};

static void lockwait_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct lockwait_handle *h = talloc_get_type(private_data, 
						     struct lockwait_handle);
	void (*callback)(void *) = h->callback;
	void *p = h->private_data;
	talloc_set_destructor(h, NULL);
	close(h->fd[0]);
	talloc_free(h);	
	callback(p);
	waitpid(h->child, NULL, 0);
}

static int lockwait_destructor(struct lockwait_handle *h)
{
	close(h->fd[0]);
	kill(h->child, SIGKILL);
	waitpid(h->child, NULL, 0);
	return 0;
}


static struct lockwait_handle *lockwait(struct event_context *ev, 
					TALLOC_CTX *mem_ctx,
					int fd, off_t ofs, size_t len,
					void (*callback)(void *), void *private_data)
{
	struct lockwait_handle *h;
	int ret;

	h = talloc_zero(mem_ctx, struct lockwait_handle);
	if (h == NULL) {
		return NULL;
	}

	ret = pipe(h->fd);
	if (ret != 0) {
		talloc_free(h);
		return NULL;
	}

	h->child = fork();
	if (h->child == (pid_t)-1) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	h->callback = callback;
	h->private_data = private_data;

	if (h->child == 0) {
		/* in child */
		struct flock lock;
		close(h->fd[0]);
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = ofs;
		lock.l_len = len;
		lock.l_pid = 0;
		fcntl(fd,F_SETLKW,&lock);
		_exit(0);
	}

	close(h->fd[1]);
	talloc_set_destructor(h, lockwait_destructor);

	h->fde = event_add_fd(ev, h, h->fd[0], EVENT_FD_READ, lockwait_handler, h);
	if (h->fde == NULL) {
		talloc_free(h);
		return NULL;
	}

	return h;
}




static void fcntl_lock_callback(void *p)
{
	int *got_lock = (int *)p;
	*got_lock = 1;
}

/*
  get an fcntl lock - waiting if necessary
 */
static int fcntl_lock(struct event_context *ev,
		      int fd, int op, off_t offset, off_t count, int type)
{
	struct flock lock;
	int ret;
	int use_lockwait = (op == F_SETLKW);
	int got_lock = 0;

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = offset;
	lock.l_len = count;
	lock.l_pid = 0;

	do {
		ret = fcntl(fd,use_lockwait?F_SETLK:op,&lock);
		if (ret == 0) {
			return 0;
		}
		if (ret == -1 && 
		    (errno == EACCES || errno == EAGAIN || errno == EDEADLK)) {
			struct lockwait_handle *h;
			h = lockwait(ev, ev, fd, offset, count, 
				     fcntl_lock_callback, &got_lock);
			if (h == NULL) {
				errno = ENOLCK;
				return -1;
			}
			/* in real code we would return to the event loop */
			while (!got_lock) {
				event_loop_once(ev);
			}
			got_lock = 0;
		}
	} while (!got_lock);

	return ret;
}

static void child(struct event_context *ev, int n)
{
	int fd;
	int count=0;
	struct timeval tv;
	fd = open("test.dat", O_CREAT|O_RDWR, 0666);
	if (fd == -1) {
		perror("test.dat");
		exit(1);
	}

	tv = timeval_current();

	while (timeval_elapsed(&tv) < 10) {
		int ret;
		ret = fcntl_lock(ev, fd, F_SETLKW, 0, 1, F_WRLCK);
		if (ret != 0) {
			printf("Failed to get lock in child %d!\n", n);
			break;
		}
		fcntl_lock(ev, fd, F_SETLK, 0, 1, F_UNLCK);
		count++;
	}

	printf("child %2d %.0f ops/sec\n", n, count/timeval_elapsed(&tv));
	_exit(0);
}

static int timelimit = 10;

/*
  main program
*/
int main(int argc, const char *argv[])
{
	pid_t *pids;
	int nprogs = 2;
	int i;
	struct event_context *ev;
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "timelimit", 't', POPT_ARG_INT, &timelimit, 0, "timelimit", "integer" },
		{ "num-progs", 'n', POPT_ARG_INT, &nprogs, 0, "num_progs", "integer" },
		POPT_TABLEEND
	};
	poptContext pc;
	int opt;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	ev = event_context_init(NULL);

	pids = talloc_array(ev, pid_t, nprogs);

	/* create N processes fighting over the same lock */
	for (i=0;i<nprogs;i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			child(ev, i);
		}
	}

	printf("Waiting for %d children ...\n", nprogs);

	/* wait for our kids to finish playing */
	for (i=0;i<nprogs;i++) {
		waitpid(pids[i], NULL, 0);
	}	

	return 0;
}
