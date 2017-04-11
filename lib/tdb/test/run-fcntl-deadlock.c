#include "../common/tdb_private.h"
#include "../common/io.c"
#include "../common/tdb.c"
#include "../common/lock.c"
#include "../common/freelist.c"
#include "../common/traverse.c"
#include "../common/transaction.c"
#include "../common/error.c"
#include "../common/open.c"
#include "../common/check.c"
#include "../common/hash.c"
#include "../common/mutex.c"
#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include <errno.h>
#include "tap-interface.h"

/*
 * This tests the low level locking requirement
 * for the allrecord lock/prepare_commit and traverse_read interaction.
 *
 * The pattern with the traverse_read and prepare_commit interaction is
 * the following:
 *
 * 1. transaction_start got the allrecord lock with F_RDLCK.
 *
 * 2. the traverse_read code walks the database in a sequence like this
 * (per chain):
 *    2.1  chainlock(chainX, F_RDLCK)
 *    2.2  recordlock(chainX.record1, F_RDLCK)
 *    2.3  chainunlock(chainX, F_RDLCK)
 *    2.4  callback(chainX.record1)
 *    2.5  chainlock(chainX, F_RDLCK)
 *    2.6  recordunlock(chainX.record1, F_RDLCK)
 *    2.7  recordlock(chainX.record2, F_RDLCK)
 *    2.8  chainunlock(chainX, F_RDLCK)
 *    2.9  callback(chainX.record2)
 *    2.10 chainlock(chainX, F_RDLCK)
 *    2.11 recordunlock(chainX.record2, F_RDLCK)
 *    2.12 chainunlock(chainX, F_RDLCK)
 *    2.13 goto next chain
 *
 *    So it has always one record locked in F_RDLCK mode and tries to
 *    get the 2nd one before it releases the first one.
 *
 * 3. prepare_commit tries to upgrade the allrecord lock to F_RWLCK
 *    If that happens at the time of 2.4, the operation of
 *    2.5 may deadlock with the allrecord lock upgrade.
 *    On Linux step 2.5 works in order to make some progress with the
 *    locking, but on solaris it might fail because the kernel
 *    wants to satisfy the 1st lock requester before the 2nd one.
 *
 * I think the first step is a standalone test that does this:
 *
 * process1: F_RDLCK for ofs=0 len=2
 * process2: F_RDLCK for ofs=0 len=1
 * process1: upgrade ofs=0 len=2 to F_RWLCK (in blocking mode)
 * process2: F_RDLCK for ofs=1 len=1
 * process2: unlock ofs=0 len=2
 * process1: should continue at that point
 *
 * Such a test follows here...
 */

static int raw_fcntl_lock(int fd, int rw, off_t off, off_t len, bool waitflag)
{
	struct flock fl;
	int cmd;
	fl.l_type = rw;
	fl.l_whence = SEEK_SET;
	fl.l_start = off;
	fl.l_len = len;
	fl.l_pid = 0;

	cmd = waitflag ? F_SETLKW : F_SETLK;

	return fcntl(fd, cmd, &fl);
}

static int raw_fcntl_unlock(int fd, off_t off, off_t len)
{
	struct flock fl;
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = off;
	fl.l_len = len;
	fl.l_pid = 0;

	return fcntl(fd, F_SETLKW, &fl);
}


int pipe_r;
int pipe_w;
char buf[2];

static void expect_char(char c)
{
	read(pipe_r, buf, 1);
	if (*buf != c) {
		fail("We were expecting %c, but got %c", c, buf[0]);
	}
}

static void send_char(char c)
{
	write(pipe_w, &c, 1);
}


int main(int argc, char *argv[])
{
	int process;
	int fd;
	const char *filename = "run-fcntl-deadlock.lck";
	int pid;
	int pipes_1_2[2];
	int pipes_2_1[2];
	int ret;

	pipe(pipes_1_2);
	pipe(pipes_2_1);
	fd = open(filename, O_RDWR | O_CREAT, 0755);

	pid = fork();
	if (pid == 0) {
		pipe_r = pipes_1_2[0];
		pipe_w = pipes_2_1[1];
		process = 2;
		alarm(15);
	} else {
		pipe_r = pipes_2_1[0];
		pipe_w = pipes_1_2[1];
		process = 1;
		alarm(15);
	}

	/* a: process1: F_RDLCK for ofs=0 len=2 */
	if (process == 1) {
		ret = raw_fcntl_lock(fd, F_RDLCK, 0, 2, true);
		ok(ret == 0,
		   "process 1 lock ofs=0 len=2: %d - %s",
		   ret, strerror(errno));
		diag("process 1 took read lock on range 0,2");
		send_char('a');
	}

	/* process2: F_RDLCK for ofs=0 len=1 */
	if (process == 2) {
		expect_char('a');
		ret = raw_fcntl_lock(fd, F_RDLCK, 0, 1, true);
		ok(ret == 0,
		   "process 2 lock ofs=0 len=1: %d - %s",
		   ret, strerror(errno));;
		diag("process 2 took read lock on range 0,1");
		send_char('b');
	}

	/* process1: upgrade ofs=0 len=2 to F_RWLCK (in blocking mode) */
	if (process == 1) {
		expect_char('b');
		send_char('c');
		diag("process 1 starts upgrade on range 0,2");
		ret = raw_fcntl_lock(fd, F_WRLCK, 0, 2, true);
		ok(ret == 0,
		   "process 1 RW lock ofs=0 len=2: %d - %s",
		   ret, strerror(errno));
		diag("process 1 got read upgrade done");
		/* at this point process 1 is blocked on 2 releasing the
		   read lock */
	}

	/*
	 * process2: F_RDLCK for ofs=1 len=1
	 * process2: unlock ofs=0 len=2
	 */
	if (process == 2) {
		expect_char('c'); /* we know process 1 is *about* to lock */
		sleep(1);
		ret = raw_fcntl_lock(fd, F_RDLCK, 1, 1, true);
		ok(ret == 0,
		  "process 2 lock ofs=1 len=1: %d - %s",
		  ret, strerror(errno));
		diag("process 2 got read lock on 1,1\n");
		ret = raw_fcntl_unlock(fd, 0, 2);
		ok(ret == 0,
		  "process 2 unlock ofs=0 len=2: %d - %s",
		  ret, strerror(errno));
		diag("process 2 released read lock on 0,2\n");
		sleep(1);
		send_char('d');
	}

	if (process == 1) {
		expect_char('d');
	}

	diag("process %d has got to the end\n", process);

	return 0;
}
