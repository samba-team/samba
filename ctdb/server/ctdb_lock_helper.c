/*
   ctdb lock helper

   Copyright (C) Amitay Isaacs  2013

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

#include "includes.h"
#include "tdb.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"

static char *progname = NULL;

static void send_result(int fd, char result)
{
	write(fd, &result, 1);
	if (result == 1) {
		exit(1);
	}
}


static void usage(void)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: %s <ctdbd-pid> <output-fd> RECORD <db-path> <db-key>\n",
		progname);
	fprintf(stderr, "       %s <ctdbd-pid> <output-fd> DB <db1-path> [<db2-path> ...]\n",
		progname);
}


static int lock_record(const char *dbpath, const char *dbkey)
{
	TDB_DATA key;
	struct tdb_context *tdb;

	/* Convert hex key to key */
	if (strcmp(dbkey, "NULL") == 0) {
		key.dptr = NULL;
		key.dsize = 0;
	} else {
		key.dptr = hex_decode_talloc(NULL, dbkey, &key.dsize);
	}

	tdb = tdb_open(dbpath, 0, TDB_DEFAULT, O_RDWR, 0600);
	if (tdb == NULL) {
		fprintf(stderr, "%s: Error opening database %s\n", progname, dbpath);
		return 1;
	}

	if (tdb_chainlock(tdb, key) < 0) {
		fprintf(stderr, "%s: Error getting record lock (%s)\n",
			progname, tdb_errorstr(tdb));
		return 1;
	}

	return 0;

}


static int lock_db(const char *dbpath)
{
	struct tdb_context *tdb;

	tdb = tdb_open(dbpath, 0, TDB_DEFAULT, O_RDWR, 0600);
	if (tdb == NULL) {
		fprintf(stderr, "%s: Error opening database %s\n", progname, dbpath);
		return 1;
	}

	if (tdb_lockall(tdb) < 0) {
		fprintf(stderr, "%s: Error getting db lock (%s)\n",
			progname, tdb_errorstr(tdb));
		return 1;
	}

	return 0;
}


int main(int argc, char *argv[])
{
	int write_fd;
	char result = 0;
	int ppid;
	const char *lock_type;

	progname = argv[0];

	if (argc < 4) {
		usage();
		exit(1);
	}

	ppid = atoi(argv[1]);
	write_fd = atoi(argv[2]);
	lock_type = argv[3];

	if (strcmp(lock_type, "RECORD") == 0) {
		if (argc != 6) {
			fprintf(stderr, "%s: Invalid number of arguments (%d)\n",
				progname, argc);
			usage();
			exit(1);
		}
		result = lock_record(argv[4], argv[5]);

	} else if (strcmp(lock_type, "DB") == 0) {
		int n;

		/* If there are no databases specified, no need for lock */
		if (argc > 4) {
			for (n=4; n<argc; n++) {
				result = lock_db(argv[n]);
				if (result != 0) {
					break;
				}
			}
		}

	} else {
		fprintf(stderr, "%s: Invalid lock-type '%s'\n", progname, lock_type);
		usage();
		exit(1);
	}

	send_result(write_fd, result);

	while (kill(ppid, 0) == 0 || errno != ESRCH) {
		sleep(5);
	}
	return 0;
}
