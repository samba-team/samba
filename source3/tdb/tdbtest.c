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
#include <gdbm.h>

/* a test program for tdb - the trivial database */



#define DELETE_PROB 7
#define STORE_PROB 5

static TDB_CONTEXT *db;
static GDBM_FILE gdbm;

struct timeval tp1,tp2;

static void start_timer()
{
	gettimeofday(&tp1,NULL);
}

static double end_timer()
{
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) + 
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}

static void fatal(char *why)
{
	perror(why);
	exit(1);
}


static void compare_db(void)
{
	TDB_DATA d, key, nextkey;
	datum gd, gkey, gnextkey;

	key = tdb_firstkey(db);
	while (key.dptr) {
		d = tdb_fetch(db, key);
		gkey.dptr = key.dptr;
		gkey.dsize = key.dsize;

		gd = gdbm_fetch(gdbm, gkey);

		if (!gd.dptr) fatal("key not in gdbm");
		if (gd.dsize != d.dsize) fatal("data sizes differ");
		if (memcmp(gd.dptr, d.dptr, d.dsize)) {
			fatal("data differs");
		}

		nextkey = tdb_nextkey(db, key);
		free(key.dptr);
		free(d.dptr);
		free(gd.dptr);
		key = nextkey;
	}

	gkey = gdbm_firstkey(gdbm);
	while (gkey.dptr) {
		gd = gdbm_fetch(gdbm, gkey);
		key.dptr = gkey.dptr;
		key.dsize = gkey.dsize;

		d = tdb_fetch(db, key);

		if (!d.dptr) fatal("key not in db");
		if (d.dsize != gd.dsize) fatal("data sizes differ");
		if (memcmp(d.dptr, gd.dptr, gd.dsize)) {
			fatal("data differs");
		}

		gnextkey = gdbm_nextkey(gdbm, gkey);
		free(gkey.dptr);
		free(gd.dptr);
		free(d.dptr);
		gkey = gnextkey;
	}
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

	klen = 1 + (rand() % 4);
	dlen = 1 + (rand() % 100);

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

static void addrec_gdbm(void)
{
	int klen, dlen;
	char *k, *d;
	datum key, data;

	klen = 1 + (rand() % 4);
	dlen = 1 + (rand() % 100);

	k = randbuf(klen);
	d = randbuf(dlen);

	key.dptr = k;
	key.dsize = klen+1;

	data.dptr = d;
	data.dsize = dlen+1;

	if (rand() % DELETE_PROB == 0) {
		gdbm_delete(gdbm, key);
	} else if (rand() % STORE_PROB == 0) {
		if (gdbm_store(gdbm, key, data, GDBM_REPLACE) != 0) {
			fatal("gdbm_store failed");
		}
	} else {
		data = gdbm_fetch(gdbm, key);
		if (data.dptr) free(data.dptr);
	}

	free(k);
	free(d);
}

static int traverse_fn(TDB_CONTEXT *db, TDB_DATA key, TDB_DATA dbuf)
{
#if 0
	printf("[%s] [%s]\n", key.dptr, dbuf.dptr);
#endif
	tdb_delete(db, key);
	return 0;
}

int main(int argc, char *argv[])
{
	int i, seed=0;
	int loops = 50000;

	unlink("test.gdbm");

	db = tdb_open("test.db", 0, O_RDWR | O_CREAT | O_TRUNC, 0600);
	gdbm = gdbm_open("test.gdbm", 512, GDBM_WRITER|GDBM_NEWDB|GDBM_FAST, 
			 0600, NULL);

	if (!db || !gdbm) {
		fatal("db open failed");
	}

	
#if 1
	srand(seed);
	start_timer();
	for (i=0;i<loops;i++) addrec_gdbm();
	printf("gdbm took %g secs\n", end_timer());
#endif

	srand(seed);
	start_timer();
	for (i=0;i<loops;i++) addrec_db();
	printf("tdb took %g secs\n", end_timer());

	compare_db();

	printf("traversed %d records\n", tdb_traverse(db, traverse_fn));
	printf("traversed %d records\n", tdb_traverse(db, traverse_fn));

	tdb_close(db);
	gdbm_close(gdbm);

	return 0;
}
