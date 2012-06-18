#include "ntdb-source.h"
#include "tap-interface.h"
#include "logging.h"

static uint64_t myhash(const void *key, size_t len, uint64_t seed, void *priv)
{
	return *(const uint64_t *)key;
}

static void add_bits(uint64_t *val, unsigned new, unsigned new_bits,
		     unsigned *done)
{
	*done += new_bits;
	*val |= ((uint64_t)new << (64 - *done));
}

static uint64_t make_key(unsigned topgroup, unsigned topbucket,
			 unsigned subgroup1, unsigned subbucket1,
			 unsigned subgroup2, unsigned subbucket2)
{
	uint64_t key = 0;
	unsigned done = 0;

	add_bits(&key, topgroup, NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS,
		 &done);
	add_bits(&key, topbucket, NTDB_HASH_GROUP_BITS, &done);
	add_bits(&key, subgroup1, NTDB_SUBLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS,
		 &done);
	add_bits(&key, subbucket1, NTDB_HASH_GROUP_BITS, &done);
	add_bits(&key, subgroup2, NTDB_SUBLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS,
		 &done);
	add_bits(&key, subbucket2, NTDB_HASH_GROUP_BITS, &done);
	return key;
}

int main(int argc, char *argv[])
{
	unsigned int i, j;
	struct ntdb_context *ntdb;
	uint64_t kdata;
	struct ntdb_used_record rec;
	NTDB_DATA key = { (unsigned char *)&kdata, sizeof(kdata) };
	NTDB_DATA dbuf = { (unsigned char *)&kdata, sizeof(kdata) };
	union ntdb_attribute hattr = { .hash = { .base = { NTDB_ATTRIBUTE_HASH },
						.fn = myhash } };
	int flags[] = { NTDB_INTERNAL, NTDB_DEFAULT, NTDB_NOMMAP,
			NTDB_INTERNAL|NTDB_CONVERT, NTDB_CONVERT,
			NTDB_NOMMAP|NTDB_CONVERT,
	};

	hattr.base.next = &tap_log_attr;

	plan_tests(sizeof(flags) / sizeof(flags[0])
		   * (9 + (20 + 2 * ((1 << NTDB_HASH_GROUP_BITS) - 2))
		      * (1 << NTDB_HASH_GROUP_BITS)) + 1);
	for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		struct hash_info h;

		ntdb = ntdb_open("run-20-growhash.ntdb", flags[i],
			       O_RDWR|O_CREAT|O_TRUNC, 0600, &hattr);
		ok1(ntdb);
		if (!ntdb)
			continue;

		/* Fill a group. */
		for (j = 0; j < (1 << NTDB_HASH_GROUP_BITS); j++) {
			kdata = make_key(0, j, 0, 0, 0, 0);
			ok1(ntdb_store(ntdb, key, dbuf, NTDB_INSERT) == 0);
		}
		ok1(ntdb_check(ntdb, NULL, NULL) == 0);

		/* Check first still exists. */
		kdata = make_key(0, 0, 0, 0, 0, 0);
		ok1(find_and_lock(ntdb, key, F_RDLCK, &h, &rec, NULL) != 0);
		/* Should have created correct hash. */
		ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
		/* Should have located space in group 0, bucket 0. */
		ok1(h.group_start == offsetof(struct ntdb_header, hashtable));
		ok1(h.home_bucket == 0);
		ok1(h.found_bucket == 0);
		ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS);
		/* Entire group should be full! */
		for (j = 0; j < (1 << NTDB_HASH_GROUP_BITS); j++)
			ok1(h.group[j] != 0);

		ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
				      F_RDLCK) == 0);

		/* Now, add one more to each should expand (that) bucket. */
		for (j = 0; j < (1 << NTDB_HASH_GROUP_BITS); j++) {
			unsigned int k;
			kdata = make_key(0, j, 0, 1, 0, 0);
			ok1(ntdb_store(ntdb, key, dbuf, NTDB_INSERT) == 0);
			ok1(ntdb_check(ntdb, NULL, NULL) == 0);

			ok1(find_and_lock(ntdb, key, F_RDLCK, &h, &rec, NULL));
			/* Should have created correct hash. */
			ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
			/* Should have moved to subhash */
			ok1(h.group_start >= sizeof(struct ntdb_header));
			ok1(h.home_bucket == 1);
			ok1(h.found_bucket == 1);
			ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS
			    + NTDB_SUBLEVEL_HASH_BITS);
			ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
					      F_RDLCK) == 0);

			/* Keep adding, make it expand again. */
			for (k = 2; k < (1 << NTDB_HASH_GROUP_BITS); k++) {
				kdata = make_key(0, j, 0, k, 0, 0);
				ok1(ntdb_store(ntdb, key, dbuf, NTDB_INSERT) == 0);
				ok1(ntdb_check(ntdb, NULL, NULL) == 0);
			}

			/* This should tip it over to sub-sub-hash. */
			kdata = make_key(0, j, 0, 0, 0, 1);
			ok1(ntdb_store(ntdb, key, dbuf, NTDB_INSERT) == 0);
			ok1(ntdb_check(ntdb, NULL, NULL) == 0);

			ok1(find_and_lock(ntdb, key, F_RDLCK, &h, &rec, NULL));
			/* Should have created correct hash. */
			ok1(h.h == ntdb_hash(ntdb, key.dptr, key.dsize));
			/* Should have moved to subhash */
			ok1(h.group_start >= sizeof(struct ntdb_header));
			ok1(h.home_bucket == 1);
			ok1(h.found_bucket == 1);
			ok1(h.hash_used == NTDB_TOPLEVEL_HASH_BITS
			    + NTDB_SUBLEVEL_HASH_BITS + NTDB_SUBLEVEL_HASH_BITS);
			ok1(ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range,
					      F_RDLCK) == 0);
		}
		ntdb_close(ntdb);
	}

	ok1(tap_log_messages == 0);
	return exit_status();
}
