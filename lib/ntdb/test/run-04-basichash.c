#include "ntdb-source.h"
#include "tap-interface.h"
#include "logging.h"

/* We rig the hash so adjacent-numbered records always clash. */
static uint64_t clash(const void *key, size_t len, uint64_t seed, void *priv)
{
	return ((uint64_t)*(const unsigned int *)key)
		<< (64 - NTDB_TOPLEVEL_HASH_BITS - 1);
}

int main(int argc, char *argv[])
{
	unsigned int i, j;
	struct ntdb_context *ntdb;
	unsigned int v;
	struct ntdb_used_record rec;
	NTDB_DATA key = { (unsigned char *)&v, sizeof(v) };
	NTDB_DATA dbuf = { (unsigned char *)&v, sizeof(v) };
	union ntdb_attribute hattr = { .hash = { .base = { NTDB_ATTRIBUTE_HASH },
						.fn = clash } };
	int flags[] = { NTDB_INTERNAL, NTDB_DEFAULT, NTDB_NOMMAP,
			NTDB_INTERNAL|NTDB_CONVERT, NTDB_CONVERT,
			NTDB_NOMMAP|NTDB_CONVERT,
	};

	hattr.base.next = &tap_log_attr;

	plan_tests(sizeof(flags) / sizeof(flags[0])
		   * (91 + (2 * ((1 << NTDB_HASH_GROUP_BITS) - 1))) + 1);
	for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		struct hash_info h;
		ntdb_off_t new_off, off, subhash;

		ntdb = ntdb_open("run-04-basichash.ntdb", flags[i],
			       O_RDWR|O_CREAT|O_TRUNC, 0600, &hattr);
		ok1(ntdb);
		if (!ntdb)
			continue;

		v = 0;
		/* Should not find it. */
		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL) == 0);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in group 0, bucket 0. */
		ok1(h.group_start == offsetof(struct ntdb_header, hashtable));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS);

		/* Should have lock on bucket 0 */
		ok1(h.hlock_start == 0);
		ok1(h.hlock_range ==
		    1ULL << (64-(NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS)));
		ok1((ntdb->flags & NTDB_NOLOCK) || ntdb->file->num_lockrecs == 1);
		ok1((ntdb->flags & NTDB_NOLOCK)
		    || ntdb->file->lockrecs[0].off == NTDB_HASH_LOCK_START);
		/* FIXME: Check lock length */

		/* Allocate a new record. */
		new_off = alloc(ntdb, key.dsize, dbuf.dsize, h.h,
				NTDB_USED_MAGIC, false);
		ok1(!NTDB_OFF_IS_ERR(new_off));

		/* We should be able to add it now. */
		ok1(add_to_hash(ntdb, &h, new_off) == 0);

		/* Make sure we fill it in for later finding. */
		off = new_off + sizeof(struct ntdb_used_record);
		ok1(!ntdb->io->twrite(ntdb, off, key.dptr, key.dsize));
		off += key.dsize;
		ok1(!ntdb->io->twrite(ntdb, off, dbuf.dptr, dbuf.dsize));

		/* We should be able to unlock that OK. */
		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_WRLCK) == 0);

		/* Database should be consistent. */
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		/* Now, this should give a successful lookup. */
		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL)
		    == new_off);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in group 0, bucket 0. */
		ok1(h.group_start == offsetof(struct ntdb_header, hashtable));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS);

		/* Should have lock on bucket 0 */
		ok1(h.hlock_start == 0);
		ok1(h.hlock_range ==
		    1ULL << (64-(NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS)));
		ok1((ntdb->flags & NTDB_NOLOCK) || ntdb->file->num_lockrecs == 1);
		ok1((ntdb->flags & NTDB_NOLOCK)
		    || ntdb->file->lockrecs[0].off == NTDB_HASH_LOCK_START);
		/* FIXME: Check lock length */

		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_WRLCK) == 0);

		/* Database should be consistent. */
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		/* Test expansion. */
		v = 1;
		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL) == 0);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in group 0, bucket 1. */
		ok1(h.group_start == offsetof(struct ntdb_header, hashtable));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 1);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS);

		/* Should have lock on bucket 0 */
		ok1(h.hlock_start == 0);
		ok1(h.hlock_range ==
		    1ULL << (64-(NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS)));
		ok1((ntdb->flags & NTDB_NOLOCK) || ntdb->file->num_lockrecs == 1);
		ok1((ntdb->flags & NTDB_NOLOCK)
		    || ntdb->file->lockrecs[0].off == NTDB_HASH_LOCK_START);
		/* FIXME: Check lock length */

		/* Make it expand 0'th bucket. */
		ok1(expand_group(ntdb, &h) == 0);
		/* First one should be subhash, next should be empty. */
		ok1(is_subhash(h.group[0]));
		subhash = (h.group[0] & NTDB_OFF_MASK);
		for (j = 1; j < (1 << NTDB_HASH_GROUP_BITS); j++)
			ok1(h.group[j] == 0);

		ok1(ntdb_write_convert(ntdb, h.group_start,
				      h.group, sizeof(h.group)) == 0);
		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_WRLCK) == 0);

		/* Should be happy with expansion. */
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		/* Should be able to find it. */
		v = 0;
		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL)
		    == new_off);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in expanded group 0, bucket 0. */
		ok1(h.group_start == subhash + sizeof(struct ntdb_used_record));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS
		    + NTDB_SUBLEVEL_HASH_BITS);

		/* Should have lock on bucket 0 */
		ok1(h.hlock_start == 0);
		ok1(h.hlock_range ==
		    1ULL << (64-(NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS)));
		ok1((ntdb->flags & NTDB_NOLOCK) || ntdb->file->num_lockrecs == 1);
		ok1((ntdb->flags & NTDB_NOLOCK)
		    || ntdb->file->lockrecs[0].off == NTDB_HASH_LOCK_START);
		/* FIXME: Check lock length */

		/* Simple delete should work. */
		ok1(delete_from_hash(ntdb, &h) == 0);
		ok1(add_free_record(ntdb, new_off,
				    sizeof(struct ntdb_used_record)
				    + rec_key_length(&rec)
				    + rec_data_length(&rec)
				    + rec_extra_padding(&rec),
				    NTDB_LOCK_NOWAIT, false) == 0);
		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_WRLCK) == 0);
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		/* Test second-level expansion: should expand 0th bucket. */
		v = 0;
		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL) == 0);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in group 0, bucket 0. */
		ok1(h.group_start == subhash + sizeof(struct ntdb_used_record));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS+NTDB_SUBLEVEL_HASH_BITS);

		/* Should have lock on bucket 0 */
		ok1(h.hlock_start == 0);
		ok1(h.hlock_range ==
		    1ULL << (64-(NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS)));
		ok1((ntdb->flags & NTDB_NOLOCK) || ntdb->file->num_lockrecs == 1);
		ok1((ntdb->flags & NTDB_NOLOCK)
		    || ntdb->file->lockrecs[0].off == NTDB_HASH_LOCK_START);
		/* FIXME: Check lock length */

		ok1(expand_group(ntdb, &h) == 0);
		/* First one should be subhash, next should be empty. */
		ok1(is_subhash(h.group[0]));
		subhash = (h.group[0] & NTDB_OFF_MASK);
		for (j = 1; j < (1 << NTDB_HASH_GROUP_BITS); j++)
			ok1(h.group[j] == 0);
		ok1(ntdb_write_convert(ntdb, h.group_start,
				      h.group, sizeof(h.group)) == 0);
		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_WRLCK) == 0);

		/* Should be happy with expansion. */
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL) == 0);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in group 0, bucket 0. */
		ok1(h.group_start == subhash + sizeof(struct ntdb_used_record));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS
		    + NTDB_SUBLEVEL_HASH_BITS * 2);

		/* We should be able to add it now. */
		/* Allocate a new record. */
		new_off = alloc(ntdb, key.dsize, dbuf.dsize, h.h,
				NTDB_USED_MAGIC, false);
		ok1(!NTDB_OFF_IS_ERR(new_off));
		ok1(add_to_hash(ntdb, &h, new_off) == 0);

		/* Make sure we fill it in for later finding. */
		off = new_off + sizeof(struct ntdb_used_record);
		ok1(!ntdb->io->twrite(ntdb, off, key.dptr, key.dsize));
		off += key.dsize;
		ok1(!ntdb->io->twrite(ntdb, off, dbuf.dptr, dbuf.dsize));

		/* We should be able to unlock that OK. */
		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_WRLCK) == 0);

		/* Database should be consistent. */
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		/* Should be able to find it. */
		v = 0;
		ok1(find_and_lock(ntdb, key, F_WRLCK, &h, &rec, NULL)
		    == new_off);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in expanded group 0, bucket 0. */
		ok1(h.group_start == subhash + sizeof(struct ntdb_used_record));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS
		    + NTDB_SUBLEVEL_HASH_BITS * 2);

		ntdb_close(ntdb);
	}

	ok1(tap_log_messages == 0);
	return exit_status();
}
