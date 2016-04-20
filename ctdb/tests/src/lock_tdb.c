/*
   Lock a tdb and sleep

   Copyright (C) Amitay Isaacs  2012

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

#include <tdb.h>

const char *tdb_file;
TDB_CONTEXT *tdb;

static void signal_handler(int signum)
{
	tdb_close(tdb);
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s <tdb file>\n", argv[0]);
		exit(1);
	}

	tdb_file = argv[1];

	tdb = tdb_open(tdb_file, 0, 0, O_RDWR, 0);
	if (tdb == NULL) {
		fprintf(stderr, "Failed to open TDB file %s\n", tdb_file);
		exit(1);
	}

	signal(SIGINT, signal_handler);

	if (tdb_lockall(tdb) != 0) {
		fprintf(stderr, "Failed to lock database %s\n", tdb_file);
		tdb_close(tdb);
		exit(1);
	}

	sleep(999999);

	return 0;
}
