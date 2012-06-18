 /*
   Trivial Database 2: hash handling
   Copyright (C) Rusty Russell 2010

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include "private.h"
#include <ccan/hash/hash.h>
#include <assert.h>

/* Default hash function. */
uint64_t ntdb_jenkins_hash(const void *key, size_t length, uint64_t seed,
			  void *unused)
{
	uint64_t ret;
	/* hash64_stable assumes lower bits are more important; they are a
	 * slightly better hash.  We use the upper bits first, so swap them. */
	ret = hash64_stable((const unsigned char *)key, length, seed);
	return (ret >> 32) | (ret << 32);
}

uint64_t ntdb_hash(struct ntdb_context *ntdb, const void *ptr, size_t len)
{
	return ntdb->hash_fn(ptr, len, ntdb->hash_seed, ntdb->hash_data);
}

uint64_t hash_record(struct ntdb_context *ntdb, ntdb_off_t off)
{
	const struct ntdb_used_record *r;
	const void *key;
	uint64_t klen, hash;

	r = ntdb_access_read(ntdb, off, sizeof(*r), true);
	if (NTDB_PTR_IS_ERR(r)) {
		/* FIXME */
		return 0;
	}

	klen = rec_key_length(r);
	ntdb_access_release(ntdb, r);

	key = ntdb_access_read(ntdb, off + sizeof(*r), klen, false);
	if (NTDB_PTR_IS_ERR(key)) {
		return 0;
	}

	hash = ntdb_hash(ntdb, key, klen);
	ntdb_access_release(ntdb, key);
	return hash;
}

/* Get bits from a value. */
static uint32_t bits_from(uint64_t val, unsigned start, unsigned num)
{
	assert(num <= 32);
	return (val >> start) & ((1U << num) - 1);
}

/* We take bits from the top: that way we can lock whole sections of the hash
 * by using lock ranges. */
static uint32_t use_bits(struct hash_info *h, unsigned num)
{
	h->hash_used += num;
	return bits_from(h->h, 64 - h->hash_used, num);
}

static ntdb_bool_err key_matches(struct ntdb_context *ntdb,
				const struct ntdb_used_record *rec,
				ntdb_off_t off,
				const NTDB_DATA *key)
{
	ntdb_bool_err ret = false;
	const char *rkey;

	if (rec_key_length(rec) != key->dsize) {
		ntdb->stats.compare_wrong_keylen++;
		return ret;
	}

	rkey = ntdb_access_read(ntdb, off + sizeof(*rec), key->dsize, false);
	if (NTDB_PTR_IS_ERR(rkey)) {
		return (ntdb_bool_err)NTDB_PTR_ERR(rkey);
	}
	if (memcmp(rkey, key->dptr, key->dsize) == 0)
		ret = true;
	else
		ntdb->stats.compare_wrong_keycmp++;
	ntdb_access_release(ntdb, rkey);
	return ret;
}

/* Does entry match? */
static ntdb_bool_err match(struct ntdb_context *ntdb,
			  struct hash_info *h,
			  const NTDB_DATA *key,
			  ntdb_off_t val,
			  struct ntdb_used_record *rec)
{
	ntdb_off_t off;
	enum NTDB_ERROR ecode;

	ntdb->stats.compares++;
	/* Desired bucket must match. */
	if (h->home_bucket != (val & NTDB_OFF_HASH_GROUP_MASK)) {
		ntdb->stats.compare_wrong_bucket++;
		return false;
	}

	/* Top bits of offset == next bits of hash. */
	if (bits_from(val, NTDB_OFF_HASH_EXTRA_BIT, NTDB_OFF_UPPER_STEAL_EXTRA)
	    != bits_from(h->h, 64 - h->hash_used - NTDB_OFF_UPPER_STEAL_EXTRA,
		    NTDB_OFF_UPPER_STEAL_EXTRA)) {
		ntdb->stats.compare_wrong_offsetbits++;
		return false;
	}

	off = val & NTDB_OFF_MASK;
	ecode = ntdb_read_convert(ntdb, off, rec, sizeof(*rec));
	if (ecode != NTDB_SUCCESS) {
		return (ntdb_bool_err)ecode;
	}

	if ((h->h & ((1 << 11)-1)) != rec_hash(rec)) {
		ntdb->stats.compare_wrong_rechash++;
		return false;
	}

	return key_matches(ntdb, rec, off, key);
}

static ntdb_off_t hbucket_off(ntdb_off_t group_start, unsigned bucket)
{
	return group_start
		+ (bucket % (1 << NTDB_HASH_GROUP_BITS)) * sizeof(ntdb_off_t);
}

bool is_subhash(ntdb_off_t val)
{
	return (val >> NTDB_OFF_UPPER_STEAL_SUBHASH_BIT) & 1;
}

/* FIXME: Guess the depth, don't over-lock! */
static ntdb_off_t hlock_range(ntdb_off_t group, ntdb_off_t *size)
{
	*size = 1ULL << (64 - (NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS));
	return group << (64 - (NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS));
}

static ntdb_off_t COLD find_in_chain(struct ntdb_context *ntdb,
				    NTDB_DATA key,
				    ntdb_off_t chain,
				    struct hash_info *h,
				    struct ntdb_used_record *rec,
				    struct traverse_info *tinfo)
{
	ntdb_off_t off, next;
	enum NTDB_ERROR ecode;

	/* In case nothing is free, we set these to zero. */
	h->home_bucket = h->found_bucket = 0;

	for (off = chain; off; off = next) {
		unsigned int i;

		h->group_start = off;
		ecode = ntdb_read_convert(ntdb, off, h->group, sizeof(h->group));
		if (ecode != NTDB_SUCCESS) {
			return NTDB_ERR_TO_OFF(ecode);
		}

		for (i = 0; i < (1 << NTDB_HASH_GROUP_BITS); i++) {
			ntdb_off_t recoff;
			if (!h->group[i]) {
				/* Remember this empty bucket. */
				h->home_bucket = h->found_bucket = i;
				continue;
			}

			/* We can insert extra bits via add_to_hash
			 * empty bucket logic. */
			recoff = h->group[i] & NTDB_OFF_MASK;
			ecode = ntdb_read_convert(ntdb, recoff, rec,
						 sizeof(*rec));
			if (ecode != NTDB_SUCCESS) {
				return NTDB_ERR_TO_OFF(ecode);
			}

			ecode = NTDB_OFF_TO_ERR(key_matches(ntdb, rec, recoff,
							   &key));
			if (ecode < 0) {
				return NTDB_ERR_TO_OFF(ecode);
			}
			if (ecode == (enum NTDB_ERROR)1) {
				h->home_bucket = h->found_bucket = i;

				if (tinfo) {
					tinfo->levels[tinfo->num_levels]
						.hashtable = off;
					tinfo->levels[tinfo->num_levels]
						.total_buckets
						= 1 << NTDB_HASH_GROUP_BITS;
					tinfo->levels[tinfo->num_levels].entry
						= i;
					tinfo->num_levels++;
				}
				return recoff;
			}
		}
		next = ntdb_read_off(ntdb, off
				    + offsetof(struct ntdb_chain, next));
		if (NTDB_OFF_IS_ERR(next)) {
			return next;
		}
		if (next)
			next += sizeof(struct ntdb_used_record);
	}
	return 0;
}

/* This is the core routine which searches the hashtable for an entry.
 * On error, no locks are held and -ve is returned.
 * Otherwise, hinfo is filled in (and the optional tinfo).
 * If not found, the return value is 0.
 * If found, the return value is the offset, and *rec is the record. */
ntdb_off_t find_and_lock(struct ntdb_context *ntdb,
			NTDB_DATA key,
			int ltype,
			struct hash_info *h,
			struct ntdb_used_record *rec,
			struct traverse_info *tinfo)
{
	uint32_t i, group;
	ntdb_off_t hashtable;
	enum NTDB_ERROR ecode;

	h->h = ntdb_hash(ntdb, key.dptr, key.dsize);
	h->hash_used = 0;
	group = use_bits(h, NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS);
	h->home_bucket = use_bits(h, NTDB_HASH_GROUP_BITS);

	h->hlock_start = hlock_range(group, &h->hlock_range);
	ecode = ntdb_lock_hashes(ntdb, h->hlock_start, h->hlock_range, ltype,
				NTDB_LOCK_WAIT);
	if (ecode != NTDB_SUCCESS) {
		return NTDB_ERR_TO_OFF(ecode);
	}

	hashtable = offsetof(struct ntdb_header, hashtable);
	if (tinfo) {
		tinfo->toplevel_group = group;
		tinfo->num_levels = 1;
		tinfo->levels[0].entry = 0;
		tinfo->levels[0].hashtable = hashtable
			+ (group << NTDB_HASH_GROUP_BITS) * sizeof(ntdb_off_t);
		tinfo->levels[0].total_buckets = 1 << NTDB_HASH_GROUP_BITS;
	}

	while (h->hash_used <= 64) {
		/* Read in the hash group. */
		h->group_start = hashtable
			+ group * (sizeof(ntdb_off_t) << NTDB_HASH_GROUP_BITS);

		ecode = ntdb_read_convert(ntdb, h->group_start, &h->group,
					 sizeof(h->group));
		if (ecode != NTDB_SUCCESS) {
			goto fail;
		}

		/* Pointer to another hash table?  Go down... */
		if (is_subhash(h->group[h->home_bucket])) {
			hashtable = (h->group[h->home_bucket] & NTDB_OFF_MASK)
				+ sizeof(struct ntdb_used_record);
			if (tinfo) {
				/* When we come back, use *next* bucket */
				tinfo->levels[tinfo->num_levels-1].entry
					+= h->home_bucket + 1;
			}
			group = use_bits(h, NTDB_SUBLEVEL_HASH_BITS
					 - NTDB_HASH_GROUP_BITS);
			h->home_bucket = use_bits(h, NTDB_HASH_GROUP_BITS);
			if (tinfo) {
				tinfo->levels[tinfo->num_levels].hashtable
					= hashtable;
				tinfo->levels[tinfo->num_levels].total_buckets
					= 1 << NTDB_SUBLEVEL_HASH_BITS;
				tinfo->levels[tinfo->num_levels].entry
					= group << NTDB_HASH_GROUP_BITS;
				tinfo->num_levels++;
			}
			continue;
		}

		/* It's in this group: search (until 0 or all searched) */
		for (i = 0, h->found_bucket = h->home_bucket;
		     i < (1 << NTDB_HASH_GROUP_BITS);
		     i++, h->found_bucket = ((h->found_bucket+1)
					     % (1 << NTDB_HASH_GROUP_BITS))) {
			ntdb_bool_err berr;
			if (is_subhash(h->group[h->found_bucket]))
				continue;

			if (!h->group[h->found_bucket])
				break;

			berr = match(ntdb, h, &key, h->group[h->found_bucket],
				     rec);
			if (berr < 0) {
				ecode = NTDB_OFF_TO_ERR(berr);
				goto fail;
			}
			if (berr) {
				if (tinfo) {
					tinfo->levels[tinfo->num_levels-1].entry
						+= h->found_bucket;
				}
				return h->group[h->found_bucket] & NTDB_OFF_MASK;
			}
		}
		/* Didn't find it: h indicates where it would go. */
		return 0;
	}

	return find_in_chain(ntdb, key, hashtable, h, rec, tinfo);

fail:
	ntdb_unlock_hashes(ntdb, h->hlock_start, h->hlock_range, ltype);
	return NTDB_ERR_TO_OFF(ecode);
}

/* I wrote a simple test, expanding a hash to 2GB, for the following
 * cases:
 * 1) Expanding all the buckets at once,
 * 2) Expanding the bucket we wanted to place the new entry into.
 * 3) Expanding the most-populated bucket,
 *
 * I measured the worst/average/best density during this process.
 * 1) 3%/16%/30%
 * 2) 4%/20%/38%
 * 3) 6%/22%/41%
 *
 * So we figure out the busiest bucket for the moment.
 */
static unsigned fullest_bucket(struct ntdb_context *ntdb,
			       const ntdb_off_t *group,
			       unsigned new_bucket)
{
	unsigned counts[1 << NTDB_HASH_GROUP_BITS] = { 0 };
	unsigned int i, best_bucket;

	/* Count the new entry. */
	counts[new_bucket]++;
	best_bucket = new_bucket;

	for (i = 0; i < (1 << NTDB_HASH_GROUP_BITS); i++) {
		unsigned this_bucket;

		if (is_subhash(group[i]))
			continue;
		this_bucket = group[i] & NTDB_OFF_HASH_GROUP_MASK;
		if (++counts[this_bucket] > counts[best_bucket])
			best_bucket = this_bucket;
	}

	return best_bucket;
}

static bool put_into_group(ntdb_off_t *group,
			   unsigned bucket, ntdb_off_t encoded)
{
	unsigned int i;

	for (i = 0; i < (1 << NTDB_HASH_GROUP_BITS); i++) {
		unsigned b = (bucket + i) % (1 << NTDB_HASH_GROUP_BITS);

		if (group[b] == 0) {
			group[b] = encoded;
			return true;
		}
	}
	return false;
}

static void force_into_group(ntdb_off_t *group,
			     unsigned bucket, ntdb_off_t encoded)
{
	if (!put_into_group(group, bucket, encoded))
		abort();
}

static ntdb_off_t encode_offset(ntdb_off_t new_off, struct hash_info *h)
{
	return h->home_bucket
		| new_off
		| ((uint64_t)bits_from(h->h,
				  64 - h->hash_used - NTDB_OFF_UPPER_STEAL_EXTRA,
				  NTDB_OFF_UPPER_STEAL_EXTRA)
		   << NTDB_OFF_HASH_EXTRA_BIT);
}

/* Simply overwrite the hash entry we found before. */
enum NTDB_ERROR replace_in_hash(struct ntdb_context *ntdb,
			       struct hash_info *h,
			       ntdb_off_t new_off)
{
	return ntdb_write_off(ntdb, hbucket_off(h->group_start, h->found_bucket),
			     encode_offset(new_off, h));
}

/* We slot in anywhere that's empty in the chain. */
static enum NTDB_ERROR COLD add_to_chain(struct ntdb_context *ntdb,
					ntdb_off_t subhash,
					ntdb_off_t new_off)
{
	ntdb_off_t entry;
	enum NTDB_ERROR ecode;

	entry = ntdb_find_zero_off(ntdb, subhash, 1<<NTDB_HASH_GROUP_BITS);
	if (NTDB_OFF_IS_ERR(entry)) {
		return NTDB_OFF_TO_ERR(entry);
	}

	if (entry == 1 << NTDB_HASH_GROUP_BITS) {
		ntdb_off_t next;

		next = ntdb_read_off(ntdb, subhash
				    + offsetof(struct ntdb_chain, next));
		if (NTDB_OFF_IS_ERR(next)) {
			return NTDB_OFF_TO_ERR(next);
		}

		if (!next) {
			next = alloc(ntdb, 0, sizeof(struct ntdb_chain), 0,
				     NTDB_CHAIN_MAGIC, false);
			if (NTDB_OFF_IS_ERR(next))
				return NTDB_OFF_TO_ERR(next);
			ecode = zero_out(ntdb,
					 next+sizeof(struct ntdb_used_record),
					 sizeof(struct ntdb_chain));
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
			ecode = ntdb_write_off(ntdb, subhash
					      + offsetof(struct ntdb_chain,
							 next),
					      next);
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
		}
		return add_to_chain(ntdb, next, new_off);
	}

	return ntdb_write_off(ntdb, subhash + entry * sizeof(ntdb_off_t),
			     new_off);
}

/* Add into a newly created subhash. */
static enum NTDB_ERROR add_to_subhash(struct ntdb_context *ntdb, ntdb_off_t subhash,
				     unsigned hash_used, ntdb_off_t val)
{
	ntdb_off_t off = (val & NTDB_OFF_MASK), *group;
	struct hash_info h;
	unsigned int gnum;

	h.hash_used = hash_used;

	if (hash_used + NTDB_SUBLEVEL_HASH_BITS > 64)
		return add_to_chain(ntdb, subhash, off);

	h.h = hash_record(ntdb, off);
	gnum = use_bits(&h, NTDB_SUBLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS);
	h.group_start = subhash
		+ gnum * (sizeof(ntdb_off_t) << NTDB_HASH_GROUP_BITS);
	h.home_bucket = use_bits(&h, NTDB_HASH_GROUP_BITS);

	group = ntdb_access_write(ntdb, h.group_start,
				 sizeof(*group) << NTDB_HASH_GROUP_BITS, true);
	if (NTDB_PTR_IS_ERR(group)) {
		return NTDB_PTR_ERR(group);
	}
	force_into_group(group, h.home_bucket, encode_offset(off, &h));
	return ntdb_access_commit(ntdb, group);
}

static enum NTDB_ERROR expand_group(struct ntdb_context *ntdb, struct hash_info *h)
{
	unsigned bucket, num_vals, i, magic;
	size_t subsize;
	ntdb_off_t subhash;
	ntdb_off_t vals[1 << NTDB_HASH_GROUP_BITS];
	enum NTDB_ERROR ecode;

	/* Attach new empty subhash under fullest bucket. */
	bucket = fullest_bucket(ntdb, h->group, h->home_bucket);

	if (h->hash_used == 64) {
		ntdb->stats.alloc_chain++;
		subsize = sizeof(struct ntdb_chain);
		magic = NTDB_CHAIN_MAGIC;
	} else {
		ntdb->stats.alloc_subhash++;
		subsize = (sizeof(ntdb_off_t) << NTDB_SUBLEVEL_HASH_BITS);
		magic = NTDB_HTABLE_MAGIC;
	}

	subhash = alloc(ntdb, 0, subsize, 0, magic, false);
	if (NTDB_OFF_IS_ERR(subhash)) {
		return NTDB_OFF_TO_ERR(subhash);
	}

	ecode = zero_out(ntdb, subhash + sizeof(struct ntdb_used_record),
			 subsize);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	/* Remove any which are destined for bucket or are in wrong place. */
	num_vals = 0;
	for (i = 0; i < (1 << NTDB_HASH_GROUP_BITS); i++) {
		unsigned home_bucket = h->group[i] & NTDB_OFF_HASH_GROUP_MASK;
		if (!h->group[i] || is_subhash(h->group[i]))
			continue;
		if (home_bucket == bucket || home_bucket != i) {
			vals[num_vals++] = h->group[i];
			h->group[i] = 0;
		}
	}
	/* FIXME: This assert is valid, but we do this during unit test :( */
	/* assert(num_vals); */

	/* Overwrite expanded bucket with subhash pointer. */
	h->group[bucket] = subhash | (1ULL << NTDB_OFF_UPPER_STEAL_SUBHASH_BIT);

	/* Point to actual contents of record. */
	subhash += sizeof(struct ntdb_used_record);

	/* Put values back. */
	for (i = 0; i < num_vals; i++) {
		unsigned this_bucket = vals[i] & NTDB_OFF_HASH_GROUP_MASK;

		if (this_bucket == bucket) {
			ecode = add_to_subhash(ntdb, subhash, h->hash_used,
					       vals[i]);
			if (ecode != NTDB_SUCCESS)
				return ecode;
		} else {
			/* There should be room to put this back. */
			force_into_group(h->group, this_bucket, vals[i]);
		}
	}
	return NTDB_SUCCESS;
}

enum NTDB_ERROR delete_from_hash(struct ntdb_context *ntdb, struct hash_info *h)
{
	unsigned int i, num_movers = 0;
	ntdb_off_t movers[1 << NTDB_HASH_GROUP_BITS];

	h->group[h->found_bucket] = 0;
	for (i = 1; i < (1 << NTDB_HASH_GROUP_BITS); i++) {
		unsigned this_bucket;

		this_bucket = (h->found_bucket+i) % (1 << NTDB_HASH_GROUP_BITS);
		/* Empty bucket?  We're done. */
		if (!h->group[this_bucket])
			break;

		/* Ignore subhashes. */
		if (is_subhash(h->group[this_bucket]))
			continue;

		/* If this one is not happy where it is, we'll move it. */
		if ((h->group[this_bucket] & NTDB_OFF_HASH_GROUP_MASK)
		    != this_bucket) {
			movers[num_movers++] = h->group[this_bucket];
			h->group[this_bucket] = 0;
		}
	}

	/* Put back the ones we erased. */
	for (i = 0; i < num_movers; i++) {
		force_into_group(h->group, movers[i] & NTDB_OFF_HASH_GROUP_MASK,
				 movers[i]);
	}

	/* Now we write back the hash group */
	return ntdb_write_convert(ntdb, h->group_start,
				 h->group, sizeof(h->group));
}

enum NTDB_ERROR add_to_hash(struct ntdb_context *ntdb, struct hash_info *h,
			   ntdb_off_t new_off)
{
	enum NTDB_ERROR ecode;

	/* We hit an empty bucket during search?  That's where it goes. */
	if (!h->group[h->found_bucket]) {
		h->group[h->found_bucket] = encode_offset(new_off, h);
		/* Write back the modified group. */
		return ntdb_write_convert(ntdb, h->group_start,
					 h->group, sizeof(h->group));
	}

	if (h->hash_used > 64)
		return add_to_chain(ntdb, h->group_start, new_off);

	/* We're full.  Expand. */
	ecode = expand_group(ntdb, h);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	if (is_subhash(h->group[h->home_bucket])) {
		/* We were expanded! */
		ntdb_off_t hashtable;
		unsigned int gnum;

		/* Write back the modified group. */
		ecode = ntdb_write_convert(ntdb, h->group_start, h->group,
					  sizeof(h->group));
		if (ecode != NTDB_SUCCESS) {
			return ecode;
		}

		/* Move hashinfo down a level. */
		hashtable = (h->group[h->home_bucket] & NTDB_OFF_MASK)
			+ sizeof(struct ntdb_used_record);
		gnum = use_bits(h,NTDB_SUBLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS);
		h->home_bucket = use_bits(h, NTDB_HASH_GROUP_BITS);
		h->group_start = hashtable
			+ gnum * (sizeof(ntdb_off_t) << NTDB_HASH_GROUP_BITS);
		ecode = ntdb_read_convert(ntdb, h->group_start, &h->group,
					 sizeof(h->group));
		if (ecode != NTDB_SUCCESS) {
			return ecode;
		}
	}

	/* Expanding the group must have made room if it didn't choose this
	 * bucket. */
	if (put_into_group(h->group, h->home_bucket, encode_offset(new_off,h))){
		return ntdb_write_convert(ntdb, h->group_start,
					 h->group, sizeof(h->group));
	}

	/* This can happen if all hashes in group (and us) dropped into same
	 * group in subhash. */
	return add_to_hash(ntdb, h, new_off);
}

/* Traverse support: returns offset of record, or 0 or -ve error. */
static ntdb_off_t iterate_hash(struct ntdb_context *ntdb,
			      struct traverse_info *tinfo)
{
	ntdb_off_t off, val, i;
	struct traverse_level *tlevel;

	tlevel = &tinfo->levels[tinfo->num_levels-1];

again:
	for (i = ntdb_find_nonzero_off(ntdb, tlevel->hashtable,
				      tlevel->entry, tlevel->total_buckets);
	     i != tlevel->total_buckets;
	     i = ntdb_find_nonzero_off(ntdb, tlevel->hashtable,
				      i+1, tlevel->total_buckets)) {
		if (NTDB_OFF_IS_ERR(i)) {
			return i;
		}

		val = ntdb_read_off(ntdb, tlevel->hashtable+sizeof(ntdb_off_t)*i);
		if (NTDB_OFF_IS_ERR(val)) {
			return val;
		}

		off = val & NTDB_OFF_MASK;

		/* This makes the delete-all-in-traverse case work
		 * (and simplifies our logic a little). */
		if (off == tinfo->prev)
			continue;

		tlevel->entry = i;

		if (!is_subhash(val)) {
			/* Found one. */
			tinfo->prev = off;
			return off;
		}

		/* When we come back, we want the next one */
		tlevel->entry++;
		tinfo->num_levels++;
		tlevel++;
		tlevel->hashtable = off + sizeof(struct ntdb_used_record);
		tlevel->entry = 0;
		/* Next level is a chain? */
		if (unlikely(tinfo->num_levels == NTDB_MAX_LEVELS + 1))
			tlevel->total_buckets = (1 << NTDB_HASH_GROUP_BITS);
		else
			tlevel->total_buckets = (1 << NTDB_SUBLEVEL_HASH_BITS);
		goto again;
	}

	/* Nothing there? */
	if (tinfo->num_levels == 1)
		return 0;

	/* Handle chained entries. */
	if (unlikely(tinfo->num_levels == NTDB_MAX_LEVELS + 1)) {
		tlevel->hashtable = ntdb_read_off(ntdb, tlevel->hashtable
						 + offsetof(struct ntdb_chain,
							    next));
		if (NTDB_OFF_IS_ERR(tlevel->hashtable)) {
			return tlevel->hashtable;
		}
		if (tlevel->hashtable) {
			tlevel->hashtable += sizeof(struct ntdb_used_record);
			tlevel->entry = 0;
			goto again;
		}
	}

	/* Go back up and keep searching. */
	tinfo->num_levels--;
	tlevel--;
	goto again;
}

/* Return success if we find something, NTDB_ERR_NOEXIST if none. */
enum NTDB_ERROR next_in_hash(struct ntdb_context *ntdb,
			    struct traverse_info *tinfo,
			    NTDB_DATA *kbuf, size_t *dlen)
{
	const unsigned group_bits = NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS;
	ntdb_off_t hl_start, hl_range, off;
	enum NTDB_ERROR ecode;

	while (tinfo->toplevel_group < (1 << group_bits)) {
		hl_start = (ntdb_off_t)tinfo->toplevel_group
			<< (64 - group_bits);
		hl_range = 1ULL << group_bits;
		ecode = ntdb_lock_hashes(ntdb, hl_start, hl_range, F_RDLCK,
					NTDB_LOCK_WAIT);
		if (ecode != NTDB_SUCCESS) {
			return ecode;
		}

		off = iterate_hash(ntdb, tinfo);
		if (off) {
			struct ntdb_used_record rec;

			if (NTDB_OFF_IS_ERR(off)) {
				ecode = NTDB_OFF_TO_ERR(off);
				goto fail;
			}

			ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec));
			if (ecode != NTDB_SUCCESS) {
				goto fail;
			}
			if (rec_magic(&rec) != NTDB_USED_MAGIC) {
				ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						   NTDB_LOG_ERROR,
						   "next_in_hash:"
						   " corrupt record at %llu",
						   (long long)off);
				goto fail;
			}

			kbuf->dsize = rec_key_length(&rec);

			/* They want data as well? */
			if (dlen) {
				*dlen = rec_data_length(&rec);
				kbuf->dptr = ntdb_alloc_read(ntdb,
							    off + sizeof(rec),
							    kbuf->dsize
							    + *dlen);
			} else {
				kbuf->dptr = ntdb_alloc_read(ntdb,
							    off + sizeof(rec),
							    kbuf->dsize);
			}
			ntdb_unlock_hashes(ntdb, hl_start, hl_range, F_RDLCK);
			if (NTDB_PTR_IS_ERR(kbuf->dptr)) {
				return NTDB_PTR_ERR(kbuf->dptr);
			}
			return NTDB_SUCCESS;
		}

		ntdb_unlock_hashes(ntdb, hl_start, hl_range, F_RDLCK);

		tinfo->toplevel_group++;
		tinfo->levels[0].hashtable
			+= (sizeof(ntdb_off_t) << NTDB_HASH_GROUP_BITS);
		tinfo->levels[0].entry = 0;
	}
	return NTDB_ERR_NOEXIST;

fail:
	ntdb_unlock_hashes(ntdb, hl_start, hl_range, F_RDLCK);
	return ecode;

}

enum NTDB_ERROR first_in_hash(struct ntdb_context *ntdb,
			     struct traverse_info *tinfo,
			     NTDB_DATA *kbuf, size_t *dlen)
{
	tinfo->prev = 0;
	tinfo->toplevel_group = 0;
	tinfo->num_levels = 1;
	tinfo->levels[0].hashtable = offsetof(struct ntdb_header, hashtable);
	tinfo->levels[0].entry = 0;
	tinfo->levels[0].total_buckets = (1 << NTDB_HASH_GROUP_BITS);

	return next_in_hash(ntdb, tinfo, kbuf, dlen);
}

/* Even if the entry isn't in this hash bucket, you'd have to lock this
 * bucket to find it. */
static enum NTDB_ERROR chainlock(struct ntdb_context *ntdb, const NTDB_DATA *key,
				int ltype, enum ntdb_lock_flags waitflag,
				const char *func)
{
	enum NTDB_ERROR ecode;
	uint64_t h = ntdb_hash(ntdb, key->dptr, key->dsize);
	ntdb_off_t lockstart, locksize;
	unsigned int group, gbits;

	gbits = NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS;
	group = bits_from(h, 64 - gbits, gbits);

	lockstart = hlock_range(group, &locksize);

	ecode = ntdb_lock_hashes(ntdb, lockstart, locksize, ltype, waitflag);
	ntdb_trace_1rec(ntdb, func, *key);
	return ecode;
}

/* lock/unlock one hash chain. This is meant to be used to reduce
   contention - it cannot guarantee how many records will be locked */
_PUBLIC_ enum NTDB_ERROR ntdb_chainlock(struct ntdb_context *ntdb, NTDB_DATA key)
{
	return ntdb->last_error = chainlock(ntdb, &key, F_WRLCK, NTDB_LOCK_WAIT,
					   "ntdb_chainlock");
}

_PUBLIC_ void ntdb_chainunlock(struct ntdb_context *ntdb, NTDB_DATA key)
{
	uint64_t h = ntdb_hash(ntdb, key.dptr, key.dsize);
	ntdb_off_t lockstart, locksize;
	unsigned int group, gbits;

	gbits = NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS;
	group = bits_from(h, 64 - gbits, gbits);

	lockstart = hlock_range(group, &locksize);

	ntdb_trace_1rec(ntdb, "ntdb_chainunlock", key);
	ntdb_unlock_hashes(ntdb, lockstart, locksize, F_WRLCK);
}

_PUBLIC_ enum NTDB_ERROR ntdb_chainlock_read(struct ntdb_context *ntdb, NTDB_DATA key)
{
	return ntdb->last_error = chainlock(ntdb, &key, F_RDLCK, NTDB_LOCK_WAIT,
					   "ntdb_chainlock_read");
}

_PUBLIC_ void ntdb_chainunlock_read(struct ntdb_context *ntdb, NTDB_DATA key)
{
	uint64_t h = ntdb_hash(ntdb, key.dptr, key.dsize);
	ntdb_off_t lockstart, locksize;
	unsigned int group, gbits;

	gbits = NTDB_TOPLEVEL_HASH_BITS - NTDB_HASH_GROUP_BITS;
	group = bits_from(h, 64 - gbits, gbits);

	lockstart = hlock_range(group, &locksize);

	ntdb_trace_1rec(ntdb, "ntdb_chainunlock_read", key);
	ntdb_unlock_hashes(ntdb, lockstart, locksize, F_RDLCK);
}
