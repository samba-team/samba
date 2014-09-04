#include <stdio.h>
#include <fcntl.h>

#include "includes.h"

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
