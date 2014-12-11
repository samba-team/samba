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
#include "ctdb_private.h"

static char *progname = NULL;

static void send_result(int fd, char result)
{
	sys_write(fd, &result, 1);
	if (result == 1) {
		exit(1);
	}
}


static void usage(void)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: %s <log-fd> <ctdbd-pid> <output-fd> RECORD <db-path> <db-flags> <db-key>\n",
		progname);
	fprintf(stderr, "       %s <log-fd> <ctdbd-pid> <output-fd> DB <db1-path> <db1-flags> [<db2-path> <db2-flags>...]\n",
		progname);
}

static uint8_t *hex_decode_talloc(TALLOC_CTX *mem_ctx,
				  const char *hex_in, size_t *len)
{
	int i, num;
	uint8_t *buffer;

	*len = strlen(hex_in) / 2;
	buffer = talloc_array(mem_ctx, unsigned char, *len);

	for (i=0; i<*len; i++) {
		sscanf(&hex_in[i*2], "%02X", &num);
		buffer[i] = (uint8_t)num;
	}

	return buffer;
}

static int lock_record(const char *dbpath, const char *dbflags, const char *dbkey)
{
	TDB_DATA key;
	struct tdb_context *tdb;
	int tdb_flags;

	/* No error checking since CTDB always passes sane values */
	tdb_flags = strtol(dbflags, NULL, 0);

	/* Convert hex key to key */
	if (strcmp(dbkey, "NULL") == 0) {
		key.dptr = NULL;
		key.dsize = 0;
	} else {
		key.dptr = hex_decode_talloc(NULL, dbkey, &key.dsize);
	}

	tdb = tdb_open(dbpath, 0, tdb_flags, O_RDWR, 0600);
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


static int lock_db(const char *dbpath, const char *dbflags)
{
	struct tdb_context *tdb;
	int tdb_flags;

	/* No error checking since CTDB always passes sane values */
	tdb_flags = strtol(dbflags, NULL, 0);

	tdb = tdb_open(dbpath, 0, tdb_flags, O_RDWR, 0600);
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
	int write_fd, log_fd;
	char result = 0;
	int ppid;
	const char *lock_type;

	progname = argv[0];

	if (argc < 5) {
		usage();
		exit(1);
	}

	if (!set_scheduler()) {
		fprintf(stderr, "%s: Unable to set real-time scheduler priority\n",
			progname);
	}

	log_fd = atoi(argv[1]);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	dup2(log_fd, STDOUT_FILENO);
	dup2(log_fd, STDERR_FILENO);
	close(log_fd);

	ppid = atoi(argv[2]);
	write_fd = atoi(argv[3]);
	lock_type = argv[4];

	if (strcmp(lock_type, "RECORD") == 0) {
		if (argc != 8) {
			fprintf(stderr, "%s: Invalid number of arguments (%d)\n",
				progname, argc);
			usage();
			exit(1);
		}
		result = lock_record(argv[5], argv[6], argv[7]);

	} else if (strcmp(lock_type, "DB") == 0) {
		int n;

		/* If there are no databases specified, no need for lock */
		if (argc > 5) {
			for (n=5; n+1<argc; n+=2) {
				result = lock_db(argv[n], argv[n+1]);
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
