#define NBDEBUG 0

/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

#define MAX_FILES 1000

static char buf[70000];
extern int line_count;
extern int nbio_id;
static int nprocs;
static BOOL bypass_io;

static struct {
	int fd;
	int handle;
} ftable[MAX_FILES];

static struct {
	double bytes_in, bytes_out;
	int line;
	int done;
} *children;

double nbio_total(void)
{
	int i;
	double total = 0;
	for (i=0;i<nprocs;i++) {
		total += children[i].bytes_out + children[i].bytes_in;
	}
	return total;
}

void nb_alarm(void)
{
	int i;
	int lines=0, num_clients=0;
	if (nbio_id != -1) return;

	for (i=0;i<nprocs;i++) {
		lines += children[i].line;
		if (!children[i].done) num_clients++;
	}

	printf("%4d  %8d  %.2f MB/sec\r", num_clients, lines/nprocs, 1.0e-6 * nbio_total() / end_timer());

	signal(SIGALRM, nb_alarm);
	alarm(1);	
}

void nbio_shmem(int n)
{
	nprocs = n;
	children = shm_setup(sizeof(*children) * nprocs);
	if (!children) {
		printf("Failed to setup shared memory!\n");
		exit(1);
	}
}

static int find_handle(int handle)
{
	int i;
	children[nbio_id].line = line_count;
	for (i=0;i<MAX_FILES;i++) {
		if (ftable[i].handle == handle) return i;
	}
	printf("(%d) ERROR: handle %d was not found\n", 
	       line_count, handle);
	exit(1);

	return -1;		/* Not reached */
}


static struct cli_state *c;

static void sigsegv(int sig)
{
	char line[200];
	printf("segv at line %d\n", line_count);
	slprintf(line, sizeof(line), "/usr/X11R6/bin/xterm -e gdb /proc/%d/exe %d", 
		(int)getpid(), (int)getpid());
	system(line);
	exit(1);
}

void nb_setup(struct cli_state *cli)
{
	signal(SIGSEGV, sigsegv);
	c = cli;
	start_timer();
	children[nbio_id].done = 0;
	if (bypass_io)
		printf("skipping I/O\n");
}


void nb_unlink(const char *fname)
{
	if (!cli_unlink(c->tree, fname)) {
#if NBDEBUG
		printf("(%d) unlink %s failed (%s)\n", 
		       line_count, fname, cli_errstr(c));
#endif
	}
}


void nb_createx(const char *fname, 
		unsigned create_options, unsigned create_disposition, int handle)
{
	int fd, i;
	uint32 desired_access;

	if (create_options & NTCREATEX_OPTIONS_DIRECTORY) {
		desired_access = SA_RIGHT_FILE_READ_DATA;
	} else {
		desired_access = SA_RIGHT_FILE_READ_DATA | SA_RIGHT_FILE_WRITE_DATA;
	}

	fd = cli_nt_create_full(c->tree, fname, 0, 
				desired_access,
				0x0,
				NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, 
				create_disposition, 
				create_options, 0);
	if (fd == -1 && handle != -1) {
		printf("ERROR: cli_nt_create_full failed for %s - %s\n",
		       fname, cli_errstr(c->tree));
		exit(1);
	}
	if (fd != -1 && handle == -1) {
		printf("ERROR: cli_nt_create_full succeeded for %s\n", fname);
		exit(1);
	}
	if (fd == -1) return;

	for (i=0;i<MAX_FILES;i++) {
		if (ftable[i].handle == 0) break;
	}
	if (i == MAX_FILES) {
		printf("(%d) file table full for %s\n", line_count, 
		       fname);
		exit(1);
	}
	ftable[i].handle = handle;
	ftable[i].fd = fd;
}

void nb_writex(int handle, int offset, int size, int ret_size)
{
	int i;

	if (buf[0] == 0) memset(buf, 1, sizeof(buf));

	i = find_handle(handle);
	if (!bypass_io && cli_write(c->tree, ftable[i].fd, 0, buf, offset, size) != ret_size) {
		printf("(%d) ERROR: write failed on handle %d, fd %d \
errno %d (%s)\n", line_count, handle, ftable[i].fd, errno, strerror(errno));
		exit(1);
	}

	children[nbio_id].bytes_out += ret_size;
}

void nb_readx(int handle, int offset, int size, int ret_size)
{
	int i, ret;

	i = find_handle(handle);
	if (!bypass_io && (ret=cli_read(c->tree, ftable[i].fd, buf, offset, size)) != ret_size) {
		printf("(%d) ERROR: read failed on handle %d ofs=%d size=%d res=%d fd %d errno %d (%s)\n",
			line_count, handle, offset, size, ret, ftable[i].fd, errno, strerror(errno));
		exit(1);
	}
	children[nbio_id].bytes_in += ret_size;
}

void nb_close(int handle)
{
	int i;
	i = find_handle(handle);
	if (!cli_close(c->tree, ftable[i].fd)) {
		printf("(%d) close failed on handle %d\n", line_count, handle);
		exit(1);
	}
	ftable[i].handle = 0;
}

void nb_rmdir(const char *fname)
{
	if (!cli_rmdir(c->tree, fname)) {
		printf("ERROR: rmdir %s failed (%s)\n", 
		       fname, cli_errstr(c->tree));
		exit(1);
	}
}

void nb_rename(const char *old, const char *new)
{
	if (!cli_rename(c->tree, old, new)) {
		printf("ERROR: rename %s %s failed (%s)\n", 
		       old, new, cli_errstr(c->tree));
		exit(1);
	}
}


void nb_qpathinfo(const char *fname)
{
	cli_qpathinfo(c->tree, fname, NULL, NULL, NULL, NULL, NULL);
}

void nb_qfileinfo(int fnum)
{
	int i;
	i = find_handle(fnum);
	cli_qfileinfo(c->tree, ftable[i].fd, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

void nb_qfsinfo(int level)
{
	int bsize, total, avail;
	/* this is not the right call - we need cli_qfsinfo() */
	cli_dskattr(c->tree, &bsize, &total, &avail);
}

static void find_fn(file_info *finfo, const char *name, void *state)
{
	/* noop */
}

void nb_findfirst(const char *mask)
{
	cli_list(c->tree, mask, 0, find_fn, NULL);
}

void nb_flush(int fnum)
{
	struct smb_flush io;
	int i;
	i = find_handle(fnum);
	io.in.fnum = ftable[i].fd;
	smb_raw_flush(c->tree, &io);
}

void nb_deltree(const char *dname)
{
	int total_deleted;

	total_deleted = cli_deltree(c->tree, dname);

	if (total_deleted == -1) {
		printf("Failed to cleanup tree %s - exiting\n", dname);
		exit(1);
	}

	if (total_deleted > 0) printf("WARNING: Cleaned up %d files\n", total_deleted);
}


void nb_cleanup(void)
{
	cli_rmdir(c->tree, "clients");
	children[nbio_id].done = 1;
}
