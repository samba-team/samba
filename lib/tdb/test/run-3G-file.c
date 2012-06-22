#include "../common/tdb_private.h"
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

static int tdb_expand_file_sparse(struct tdb_context *tdb,
				  tdb_off_t size,
				  tdb_off_t addition)
{
	if (tdb->read_only || tdb->traverse_read) {
		tdb->ecode = TDB_ERR_RDONLY;
		return -1;
	}

	if (ftruncate(tdb->fd, size+addition) == -1) {
		char b = 0;
		ssize_t written = pwrite(tdb->fd,  &b, 1, (size+addition) - 1);
		if (written == 0) {
			/* try once more, potentially revealing errno */
			written = pwrite(tdb->fd,  &b, 1, (size+addition) - 1);
		}
		if (written == 0) {
			/* again - give up, guessing errno */
			errno = ENOSPC;
		}
		if (written != 1) {
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "expand_file to %d failed (%s)\n",
				 size+addition, strerror(errno)));
			return -1;
		}
	}

	return 0;
}

static const struct tdb_methods large_io_methods = {
	tdb_read,
	tdb_write,
	tdb_next_hash_chain,
	tdb_oob,
	tdb_expand_file_sparse
};

static int test_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data,
			 void *_data)
{
	TDB_DATA *expect = _data;
	ok1(key.dsize == strlen("hi"));
	ok1(memcmp(key.dptr, "hi", strlen("hi")) == 0);
	ok1(data.dsize == expect->dsize);
	ok1(memcmp(data.dptr, expect->dptr, data.dsize) == 0);
	return 0;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	TDB_DATA key, orig_data, data;
	uint32_t hash;
	tdb_off_t rec_ptr;
	struct tdb_record rec;
	int ret;

	plan_tests(24);
	tdb = tdb_open_ex("run-36-file.tdb", 1024, TDB_CLEAR_IF_FIRST,
			  O_CREAT|O_TRUNC|O_RDWR, 0600, &taplogctx, NULL);

	ok1(tdb);
	tdb->methods = &large_io_methods;

	key.dsize = strlen("hi");
	key.dptr = (void *)"hi";
	orig_data.dsize = strlen("world");
	orig_data.dptr = (void *)"world";

	/* Enlarge the file (internally multiplies by 2). */
	ret = tdb_expand(tdb, 1500000000);
#ifdef HAVE_INCOHERENT_MMAP
	/* This can fail due to mmap failure on 32 bit systems. */
	if (ret == -1) {
		/* These should now fail. */
		ok1(tdb_store(tdb, key, orig_data, TDB_INSERT) == -1);
		data = tdb_fetch(tdb, key);
		ok1(data.dptr == NULL);
		ok1(tdb_traverse(tdb, test_traverse, &orig_data) == -1);
		ok1(tdb_delete(tdb, key) == -1);
		ok1(tdb_traverse(tdb, test_traverse, NULL) == -1);
		/* Skip the rest... */
		for (ret = 0; ret < 24 - 6; ret++)
			ok1(1);
		tdb_close(tdb);
		return exit_status();
	}
#endif
	ok1(ret == 0);

	/* Put an entry in, and check it. */
	ok1(tdb_store(tdb, key, orig_data, TDB_INSERT) == 0);

	data = tdb_fetch(tdb, key);
	ok1(data.dsize == strlen("world"));
	ok1(memcmp(data.dptr, "world", strlen("world")) == 0);
	free(data.dptr);

	/* That currently fills at the end, make sure that's true. */
	hash = tdb->hash_fn(&key);
	rec_ptr = tdb_find_lock_hash(tdb, key, hash, F_RDLCK, &rec);
	ok1(rec_ptr);
	ok1(rec_ptr > 2U*1024*1024*1024);
	tdb_unlock(tdb, BUCKET(rec.full_hash), F_RDLCK);

	/* Traverse must work. */
	ok1(tdb_traverse(tdb, test_traverse, &orig_data) == 1);

	/* Delete should work. */
	ok1(tdb_delete(tdb, key) == 0);

	ok1(tdb_traverse(tdb, test_traverse, NULL) == 0);

	/* Transactions should work. */
	ok1(tdb_transaction_start(tdb) == 0);
	ok1(tdb_store(tdb, key, orig_data, TDB_INSERT) == 0);

	data = tdb_fetch(tdb, key);
	ok1(data.dsize == strlen("world"));
	ok1(memcmp(data.dptr, "world", strlen("world")) == 0);
	free(data.dptr);
	ok1(tdb_transaction_commit(tdb) == 0);

	ok1(tdb_traverse(tdb, test_traverse, &orig_data) == 1);
	tdb_close(tdb);

	return exit_status();
}
