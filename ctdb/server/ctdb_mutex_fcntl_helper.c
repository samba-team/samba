/*
   CTDB mutex fcntl lock file helper

   Copyright (C) Martin Schwenke 2015

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
#include "system/network.h"

/* protocol.h is just needed for ctdb_sock_addr, which is used in system.h */
#include "protocol/protocol.h"
#include "common/system.h"

static char *progname = NULL;

static char fcntl_lock(const char *file, int *outfd)
{
	int fd;
	struct flock lock;

	fd = open(file, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		fprintf(stderr, "%s: Unable to open %s - (%s)\n",
			progname, file, strerror(errno));
		return '3';
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 1;
	lock.l_pid = 0;

	if (fcntl(fd, F_SETLK, &lock) != 0) {
		int saved_errno = errno;
		close(fd);
		fd = -1;
		if (saved_errno == EACCES ||
		    saved_errno == EAGAIN) {
			/* Lock contention, fail silently */
			return '1';
		}

		/* Log an error for any other failure */
		fprintf(stderr,
			"%s: Failed to get lock on '%s' - (%s)\n",
			progname, file, strerror(saved_errno));
		return '3';
	}

	*outfd = fd;

	return '0';
}

int main(int argc, char *argv[])
{
	char result;
	int ppid;
	const char *file = NULL;
	int fd = -1;

	progname = argv[0];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", progname);
		exit(1);
	}

	ppid = getppid();

	if (ppid == 1) {
		/* The original parent is gone and the process has
		 * been reparented to init.  This can happen if the
		 * helper is started just as the parent is killed
		 * during shutdown.  The error message doesn't need to
		 * be stellar, since there won't be anything around to
		 * capture and log it...
		 */
		fprintf(stderr, "%s: PPID == 1\n", progname);
		exit(1);
	}

	file = argv[1];

	result = fcntl_lock(file, &fd);
	sys_write(STDOUT_FILENO, &result, 1);

	ctdb_wait_for_process_to_exit(ppid);

	if (fd != -1) {
		close(fd);
	}

	return 0;
}
