#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "tdb.h"

/* this tests tdb by doing lots of ops from several simultaneous
   writers - that stresses the locking code. Build with TDB_DEBUG=1
   for best effect */



#define DELETE_PROB 7
#define STORE_PROB 5
#define KEYLEN 3
#define DATALEN 100

static TDB_CONTEXT *db;

static void fatal(char *why)
{
	perror(why);
	exit(1);
}

static char *randbuf(int len)
{
	char *buf;
	int i;
	buf = (char *)malloc(len+1);

	for (i=0;i<len;i++) {
		buf[i] = 'a' + (rand() % 26);
	}
	buf[i] = 0;
	return buf;
}

static void addrec_db(void)
{
	int klen, dlen;
	char *k, *d;
	TDB_DATA key, data;

	klen = 1 + (rand() % KEYLEN);
	dlen = 1 + (rand() % DATALEN);

	k = randbuf(klen);
	d = randbuf(dlen);

	key.dptr = k;
	key.dsize = klen+1;

	data.dptr = d;
	data.dsize = dlen+1;

	if (rand() % DELETE_PROB == 0) {
		tdb_delete(db, key);
	} else if (rand() % STORE_PROB == 0) {
		if (tdb_store(db, key, data, TDB_REPLACE) != 0) {
			fatal("tdb_store failed");
		}
	} else {
		data = tdb_fetch(db, key);
		if (data.dptr) free(data.dptr);
	}

	free(k);
	free(d);
}

static int traverse_fn(TDB_CONTEXT *db, TDB_DATA key, TDB_DATA dbuf,
                       void *state)
{
	tdb_delete(db, key);
	return 0;
}

#ifndef NPROC
#define NPROC 8
#endif

#ifndef NLOOPS
#define NLOOPS 50000
#endif

int main(int argc, char *argv[])
{
	int i, seed=0;
	int loops = NLOOPS;

	for (i=0;i<NPROC-1;i++) {
		if (fork() == 0) break;
	}

	db = tdb_open("test.tdb", 0, TDB_CLEAR_IF_FIRST, 
		      O_RDWR | O_CREAT, 0600);
	if (!db) {
		fatal("db open failed");
	}

	srand(seed + getpid());
	for (i=0;i<loops;i++) addrec_db();

	printf("traversed %d records\n", tdb_traverse(db, NULL, NULL));
	printf("traversed %d records\n", tdb_traverse(db, traverse_fn, NULL));
	printf("traversed %d records\n", tdb_traverse(db, traverse_fn, NULL));

	tdb_close(db);

	return 0;
}
