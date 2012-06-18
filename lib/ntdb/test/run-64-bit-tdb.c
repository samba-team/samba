#include "ntdb-source.h"
#include "tap-interface.h"
#include "logging.h"

/* The largest 32-bit value which is still a multiple of NTDB_PGSIZE */
#define ALMOST_4G ((uint32_t)-NTDB_PGSIZE)
/* And this pushes it over 32 bits */
#define A_LITTLE_BIT (NTDB_PGSIZE * 2)

int main(int argc, char *argv[])
{
	unsigned int i;
	struct ntdb_context *ntdb;
	int flags[] = { NTDB_DEFAULT, NTDB_NOMMAP,
			NTDB_CONVERT,
			NTDB_NOMMAP|NTDB_CONVERT };

	if (sizeof(off_t) <= 4) {
		plan_tests(1);
		pass("No 64 bit off_t");
		return exit_status();
	}

	plan_tests(sizeof(flags) / sizeof(flags[0]) * 14);
	for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		off_t old_size;
		NTDB_DATA k, d;
		struct hash_info h;
		struct ntdb_used_record rec;
		ntdb_off_t off;

		ntdb = ntdb_open("run-64-bit-ntdb.ntdb", flags[i],
			       O_RDWR|O_CREAT|O_TRUNC, 0600, &tap_log_attr);
		ok1(ntdb);
		if (!ntdb)
			continue;

		old_size = ntdb->file->map_size;

		/* This makes a sparse file */
		ok1(ftruncate(ntdb->file->fd, ALMOST_4G) == 0);
		ok1(add_free_record(ntdb, old_size, ALMOST_4G - old_size,
				    NTDB_LOCK_WAIT, false) == NTDB_SUCCESS);

		/* Now add a little record past the 4G barrier. */
		ok1(ntdb_expand_file(ntdb, A_LITTLE_BIT) == NTDB_SUCCESS);
		ok1(add_free_record(ntdb, ALMOST_4G, A_LITTLE_BIT,
				    NTDB_LOCK_WAIT, false)
		    == NTDB_SUCCESS);

		ok1(ntdb_check(ntdb, NULL, NULL) == NTDB_SUCCESS);

		/* Test allocation path. */
		k = ntdb_mkdata("key", 4);
		d = ntdb_mkdata("data", 5);
		ok1(ntdb_store(ntdb, k, d, NTDB_INSERT) == 0);
		ok1(ntdb_check(ntdb, NULL, NULL) == NTDB_SUCCESS);

		/* Make sure it put it at end as we expected. */
		off = find_and_lock(ntdb, k, F_RDLCK, &h, &rec, NULL);
		ok1(off >= ALMOST_4G);
		ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range, F_RDLCK);

		ok1(ntdb_fetch(ntdb, k, &d) == 0);
		ok1(d.dsize == 5);
		ok1(strcmp((char *)d.dptr, "data") == 0);
		free(d.dptr);

		ok1(ntdb_delete(ntdb, k) == 0);
		ok1(ntdb_check(ntdb, NULL, NULL) == NTDB_SUCCESS);

		ntdb_close(ntdb);
	}

	/* We might get messages about mmap failing, so don't test
	 * tap_log_messages */
	return exit_status();
}
