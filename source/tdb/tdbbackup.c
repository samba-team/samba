/* 
   Unix SMB/CIFS implementation.
   low level tdb backup and restore utility
   Copyright (C) Andrew Tridgell              2002

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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>
#include "tdb.h"

static int failed;

static int copy_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	TDB_CONTEXT *tdb_new = (TDB_CONTEXT *)state;

	if (tdb_store(tdb_new, key, dbuf, TDB_INSERT) != 0) {
		fprintf(stderr,"Failed to insert into %s\n", tdb_new->name);
		failed = 1;
		return 1;
	}
	return 0;
}


static int test_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	return 0;
}

/*
  carefully backup a tdb to %s.bak, validating the contents and
  only doing the backup if its OK
*/
static int backup_tdb(const char *fname)
{
	TDB_CONTEXT *tdb;
	TDB_CONTEXT *tdb_new;
	char *tmp_name = NULL;
	char *bak_name = NULL;
	struct stat st;
	int count1, count2;

	asprintf(&tmp_name, "%s.tmp", fname);

	/* stat the old tdb to find its permissions */
	if (stat(fname, &st) != 0) {
		perror(fname);
		return 1;
	}

	/* open the old tdb */
	tdb = tdb_open(fname, 0, 0, O_RDWR, 0);
	if (!tdb) {
		printf("Failed to open %s\n", fname);
		return 1;
	}

	/* create the new tdb */
	unlink(tmp_name);
	tdb_new = tdb_open(tmp_name, 0, TDB_DEFAULT, O_RDWR|O_CREAT|O_EXCL, 
			   st.st_mode & 0777);
	if (!tdb_new) {
		perror(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* lock the old tdb */
	if (tdb_lockall(tdb) != 0) {
		fprintf(stderr,"Failed to lock %s\n", fname);
		tdb_close(tdb);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	failed = 0;

	/* traverse and copy */
	count1 = tdb_traverse(tdb, copy_fn, (void *)tdb_new);
	if (count1 < 0 || failed) {
		fprintf(stderr,"failed to backup %s\n", fname);
		tdb_close(tdb);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* close the old tdb */
	tdb_close(tdb);

	/* close the new tdb and re-open read-only */
	tdb_close(tdb_new);
	tdb_new = tdb_open(tmp_name, 0, TDB_DEFAULT, O_RDONLY, 0);
	if (!tdb_new) {
		fprintf(stderr,"failed to reopen %s\n", tmp_name);
		unlink(tmp_name);
		perror(tmp_name);
		free(tmp_name);
		return 1;
	}
	
	/* traverse the new tdb to confirm */
	count2 = tdb_traverse(tdb_new, test_fn, 0);
	if (count2 != count1) {
		fprintf(stderr,"failed to backup %s\n", fname);
		tdb_close(tdb_new);
		unlink(tmp_name);
		free(tmp_name);
		return 1;
	}

	/* close the new tdb and rename it to .bak */
	tdb_close(tdb_new);
	asprintf(&bak_name, "%s.bak", fname);
	unlink(bak_name);
	if (rename(tmp_name, bak_name) != 0) {
		perror(bak_name);
		free(tmp_name);
		free(bak_name);
		return 1;
	}

	printf("%s : %d records\n", fname, count1);
	free(tmp_name);
	free(bak_name);

	return 0;
}

 int main(int argc, char *argv[])
{
	int i;
	int ret = 0;

	if (argc < 2) {
		printf("Usage: tdbbackup [options] <fname...>\n");
		exit(1);
	}

	for (i=1; i<argc; i++) {
		if (backup_tdb(argv[i]) != 0) ret = 1;
	}

	return ret;
}
