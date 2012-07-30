#include "../common/tdb_private.h"

/* Speed up the tests, but do the actual sync tests. */
static unsigned int sync_counts = 0;
static inline int fake_fsync(int fd)
{
	sync_counts++;
	return 0;
}
#define fsync fake_fsync

#ifdef MS_SYNC
static inline int fake_msync(void *addr, size_t length, int flags)
{
	sync_counts++;
	return 0;
}
#define msync fake_msync
#endif

#ifdef HAVE_FDATASYNC
static inline int fake_fdatasync(int fd)
{
	sync_counts++;
	return 0;
}
#define fdatasync fake_fdatasync
#endif

#include "../common/io.c"
#include "../common/tdb.c"
#include "../common/lock.c"
#include "../common/freelist.c"
#include "../common/traverse.c"
#include "../common/transaction.c"
#include "../common/error.c"
#include "../common/open.c"
#include "../common/check.c"
#include "../common/hash.c"
#include "tap-interface.h"
#include <stdlib.h>
#include "logging.h"

static void write_record(struct tdb_context *tdb, size_t extra_len,
			 TDB_DATA *data)
{
	TDB_DATA key;
	key.dsize = strlen("hi");
	key.dptr = (void *)"hi";

	data->dsize += extra_len;
	tdb_transaction_start(tdb);
	tdb_store(tdb, key, *data, TDB_REPLACE);
	tdb_transaction_commit(tdb);
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	size_t i;
	TDB_DATA data;
	struct tdb_record rec;
	tdb_off_t off;

	/* Do *not* suppress sync for this test; we do it ourselves. */
	unsetenv("TDB_NO_FSYNC");

	plan_tests(5);
	tdb = tdb_open_ex("run-transaction-expand.tdb",
			  1024, TDB_CLEAR_IF_FIRST,
			  O_CREAT|O_TRUNC|O_RDWR, 0600, &taplogctx, NULL);
	ok1(tdb);

	data.dsize = 0;
	data.dptr = calloc(1000, getpagesize());

	/* Simulate a slowly growing record. */
	for (i = 0; i < 1000; i++)
		write_record(tdb, getpagesize(), &data);

	tdb_ofs_read(tdb, TDB_RECOVERY_HEAD, &off);
	tdb_read(tdb, off, &rec, sizeof(rec), DOCONV());
	diag("TDB size = %zu, recovery = %llu-%llu",
	     (size_t)tdb->map_size, (unsigned long long)off, (unsigned long long)(off + sizeof(rec) + rec.rec_len));

	/* We should only be about 5 times larger than largest record. */
	ok1(tdb->map_size < 6 * i * getpagesize());
	tdb_close(tdb);

	tdb = tdb_open_ex("run-transaction-expand.tdb",
			  1024, TDB_CLEAR_IF_FIRST,
			  O_CREAT|O_TRUNC|O_RDWR, 0600, &taplogctx, NULL);
	ok1(tdb);

	data.dsize = 0;

	/* Simulate a slowly growing record, repacking to keep
	 * recovery area at end. */
	for (i = 0; i < 1000; i++) {
		write_record(tdb, getpagesize(), &data);
		if (i % 10 == 0)
			tdb_repack(tdb);
	}

	tdb_ofs_read(tdb, TDB_RECOVERY_HEAD, &off);
	tdb_read(tdb, off, &rec, sizeof(rec), DOCONV());
	diag("TDB size = %zu, recovery = %llu-%llu",
	     (size_t)tdb->map_size, (unsigned long long)off, (unsigned long long)(off + sizeof(rec) + rec.rec_len));

	/* We should only be about 4 times larger than largest record. */
	ok1(tdb->map_size < 5 * i * getpagesize());

	/* We should have synchronized multiple times. */
	ok1(sync_counts);
	tdb_close(tdb);
	free(data.dptr);

	return exit_status();
}
