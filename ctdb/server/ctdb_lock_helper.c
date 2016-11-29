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

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "lib/util/sys_rw.h"

#include "protocol/protocol.h"

#include "common/system.h"

static char *progname = NULL;
static bool realtime = true;

static void set_priority(void)
{
	const char *ptr;

	ptr = getenv("CTDB_NOSETSCHED");
	if (ptr != NULL) {
		realtime = false;
	}

	if (! realtime) {
		return;
	}

	realtime = set_scheduler();
	if (! realtime) {
		fprintf(stderr,
			"locking: Unable to set real-time scheduler priority\n");
	}
}

static void reset_priority(void)
{
	if (realtime) {
		reset_scheduler();
	}
}

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
	fprintf(stderr, "Usage: %s <ctdbd-pid> <output-fd> RECORD <db-path> <db-flags> <db-key>\n", progname);
	fprintf(stderr, "       %s <ctdbd-pid> <output-fd> DB <db-path> <db-flags>\n", progname);
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
		fprintf(stderr, "locking: Error opening database %s\n", dbpath);
		return 1;
	}

	set_priority();

	if (tdb_chainlock(tdb, key) < 0) {
		fprintf(stderr, "locking: Error getting record lock (%s)\n",
			tdb_errorstr(tdb));
		return 1;
	}

	reset_priority();

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
		fprintf(stderr, "locking: Error opening database %s\n", dbpath);
		return 1;
	}

	set_priority();

	if (tdb_lockall(tdb) < 0) {
		fprintf(stderr, "locking: Error getting db lock (%s)\n",
			tdb_errorstr(tdb));
		return 1;
	}

	reset_priority();

	return 0;
}


int main(int argc, char *argv[])
{
	int write_fd;
	char result = 0;
	int ppid;
	const char *lock_type;

	reset_scheduler();

	progname = argv[0];

	if (argc < 4) {
		usage();
		exit(1);
	}

	ppid = atoi(argv[1]);
	write_fd = atoi(argv[2]);
	lock_type = argv[3];

	if (strcmp(lock_type, "RECORD") == 0) {
		if (argc != 7) {
			fprintf(stderr,
				"locking: Invalid number of arguments (%d)\n",
				argc);
			usage();
			exit(1);
		}
		result = lock_record(argv[4], argv[5], argv[6]);

	} else if (strcmp(lock_type, "DB") == 0) {
		if (argc != 6) {
			fprintf(stderr,
				"locking: Invalid number of arguments (%d)\n",
				argc);
			usage();
			exit(1);
		}
		result = lock_db(argv[4], argv[5]);

	} else {
		fprintf(stderr, "locking: Invalid lock-type '%s'\n", lock_type);
		usage();
		exit(1);
	}

	send_result(write_fd, result);

	ctdb_wait_for_process_to_exit(ppid);
	return 0;
}
