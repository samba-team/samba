 /*
   Trivial Database 2: free list/block handling
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
#include <ccan/likely/likely.h>
#include <ccan/asearch/asearch.h>

/* We keep an ordered array of offsets. */
static bool append(struct ntdb_context *ntdb,
		   ntdb_off_t **arr, size_t *num, ntdb_off_t off)
{
	ntdb_off_t *new;

	if (*num == 0) {
		new = ntdb->alloc_fn(ntdb, sizeof(ntdb_off_t), ntdb->alloc_data);
	} else {
		new = ntdb->expand_fn(*arr, (*num + 1) * sizeof(ntdb_off_t),
				  ntdb->alloc_data);
	}
	if (!new)
		return false;
	new[(*num)++] = off;
	*arr = new;
	return true;
}

static enum NTDB_ERROR check_header(struct ntdb_context *ntdb, ntdb_off_t *recovery,
				   uint64_t *features, size_t *num_capabilities)
{
	uint64_t hash_test;
	struct ntdb_header hdr;
	enum NTDB_ERROR ecode;
	ntdb_off_t off, next;

	ecode = ntdb_read_convert(ntdb, 0, &hdr, sizeof(hdr));
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}
	/* magic food should not be converted, so convert back. */
	ntdb_convert(ntdb, hdr.magic_food, sizeof(hdr.magic_food));

	hash_test = NTDB_HASH_MAGIC;
	hash_test = ntdb_hash(ntdb, &hash_test, sizeof(hash_test));
	if (hdr.hash_test != hash_test) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "check: hash test %llu should be %llu",
				  (long long)hdr.hash_test,
				  (long long)hash_test);
	}

	if (strcmp(hdr.magic_food, NTDB_MAGIC_FOOD) != 0) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "check: bad magic '%.*s'",
				  (unsigned)sizeof(hdr.magic_food),
				  hdr.magic_food);
	}

	/* Features which are used must be a subset of features offered. */
	if (hdr.features_used & ~hdr.features_offered) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "check: features used (0x%llx) which"
				  " are not offered (0x%llx)",
				  (long long)hdr.features_used,
				  (long long)hdr.features_offered);
	}

	*features = hdr.features_offered;
	*recovery = hdr.recovery;
	if (*recovery) {
		if (*recovery < sizeof(hdr)
		    || *recovery > ntdb->file->map_size) {
			return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
					  "ntdb_check:"
					  " invalid recovery offset %zu",
					  (size_t)*recovery);
		}
	}

	for (off = hdr.capabilities; off && ecode == NTDB_SUCCESS; off = next) {
		const struct ntdb_capability *cap;
		enum NTDB_ERROR e;

		cap = ntdb_access_read(ntdb, off, sizeof(*cap), true);
		if (NTDB_PTR_IS_ERR(cap)) {
			return NTDB_PTR_ERR(cap);
		}

		/* All capabilities are unknown. */
		e = unknown_capability(ntdb, "ntdb_check", cap->type);
		next = cap->next;
		ntdb_access_release(ntdb, cap);
		if (e)
			return e;
		(*num_capabilities)++;
	}

	/* Don't check reserved: they *can* be used later. */
	return NTDB_SUCCESS;
}

static enum NTDB_ERROR check_hash_tree(struct ntdb_context *ntdb,
				      ntdb_off_t off, unsigned int group_bits,
				      uint64_t hprefix,
				      unsigned hprefix_bits,
				      ntdb_off_t used[],
				      size_t num_used,
				      size_t *num_found,
				      enum NTDB_ERROR (*check)(NTDB_DATA,
							      NTDB_DATA, void *),
				      void *data);

static enum NTDB_ERROR check_hash_chain(struct ntdb_context *ntdb,
				       ntdb_off_t off,
				       uint64_t hash,
				       ntdb_off_t used[],
				       size_t num_used,
				       size_t *num_found,
				       enum NTDB_ERROR (*check)(NTDB_DATA,
							       NTDB_DATA,
							       void *),
				       void *data)
{
	struct ntdb_used_record rec;
	enum NTDB_ERROR ecode;

	ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec));
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	if (rec_magic(&rec) != NTDB_CHAIN_MAGIC) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Bad hash chain magic %llu",
				  (long long)rec_magic(&rec));
	}

	if (rec_data_length(&rec) != sizeof(struct ntdb_chain)) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check:"
				  " Bad hash chain length %llu vs %zu",
				  (long long)rec_data_length(&rec),
				  sizeof(struct ntdb_chain));
	}
	if (rec_key_length(&rec) != 0) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Bad hash chain key length %llu",
				  (long long)rec_key_length(&rec));
	}
	if (rec_hash(&rec) != 0) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Bad hash chain hash value %llu",
				  (long long)rec_hash(&rec));
	}

	off += sizeof(rec);
	ecode = check_hash_tree(ntdb, off, 0, hash, 64,
				used, num_used, num_found, check, data);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	off = ntdb_read_off(ntdb, off + offsetof(struct ntdb_chain, next));
	if (NTDB_OFF_IS_ERR(off)) {
		return NTDB_OFF_TO_ERR(off);
	}
	if (off == 0)
		return NTDB_SUCCESS;
	(*num_found)++;
	return check_hash_chain(ntdb, off, hash, used, num_used, num_found,
				check, data);
}

static enum NTDB_ERROR check_hash_record(struct ntdb_context *ntdb,
					ntdb_off_t off,
					uint64_t hprefix,
					unsigned hprefix_bits,
					ntdb_off_t used[],
					size_t num_used,
					size_t *num_found,
					enum NTDB_ERROR (*check)(NTDB_DATA,
								NTDB_DATA,
								void *),
					void *data)
{
	struct ntdb_used_record rec;
	enum NTDB_ERROR ecode;

	if (hprefix_bits >= 64)
		return check_hash_chain(ntdb, off, hprefix, used, num_used,
					num_found, check, data);

	ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec));
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	if (rec_magic(&rec) != NTDB_HTABLE_MAGIC) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Bad hash table magic %llu",
				  (long long)rec_magic(&rec));
	}
	if (rec_data_length(&rec)
	    != sizeof(ntdb_off_t) << NTDB_SUBLEVEL_HASH_BITS) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check:"
				  " Bad hash table length %llu vs %llu",
				  (long long)rec_data_length(&rec),
				  (long long)sizeof(ntdb_off_t)
				  << NTDB_SUBLEVEL_HASH_BITS);
	}
	if (rec_key_length(&rec) != 0) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Bad hash table key length %llu",
				  (long long)rec_key_length(&rec));
	}
	if (rec_hash(&rec) != 0) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Bad hash table hash value %llu",
				  (long long)rec_hash(&rec));
	}

	off += sizeof(rec);
	return check_hash_tree(ntdb, off,
			       NTDB_SUBLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS,
			       hprefix, hprefix_bits,
			       used, num_used, num_found, check, data);
}

static int off_cmp(const ntdb_off_t *a, const ntdb_off_t *b)
{
	/* Can overflow an int. */
	return *a > *b ? 1
		: *a < *b ? -1
		: 0;
}

static uint64_t get_bits(uint64_t h, unsigned num, unsigned *used)
{
	*used += num;

	return (h >> (64 - *used)) & ((1U << num) - 1);
}

static enum NTDB_ERROR check_hash_tree(struct ntdb_context *ntdb,
				      ntdb_off_t off, unsigned int group_bits,
				      uint64_t hprefix,
				      unsigned hprefix_bits,
				      ntdb_off_t used[],
				      size_t num_used,
				      size_t *num_found,
				      enum NTDB_ERROR (*check)(NTDB_DATA,
							      NTDB_DATA, void *),
				      void *data)
{
	unsigned int g, b;
	const ntdb_off_t *hash;
	struct ntdb_used_record rec;
	enum NTDB_ERROR ecode;

	hash = ntdb_access_read(ntdb, off,
			       sizeof(ntdb_off_t)
			       << (group_bits + NTDB_HASH_GROUP_BITS),
			       true);
	if (NTDB_PTR_IS_ERR(hash)) {
		return NTDB_PTR_ERR(hash);
	}

	for (g = 0; g < (1 << group_bits); g++) {
		const ntdb_off_t *group = hash + (g << NTDB_HASH_GROUP_BITS);
		for (b = 0; b < (1 << NTDB_HASH_GROUP_BITS); b++) {
			unsigned int bucket, i, used_bits;
			uint64_t h;
			ntdb_off_t *p;
			if (group[b] == 0)
				continue;

			off = group[b] & NTDB_OFF_MASK;
			p = asearch(&off, used, num_used, off_cmp);
			if (!p) {
				ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						   NTDB_LOG_ERROR,
						   "ntdb_check: Invalid offset"
						   " %llu in hash",
						   (long long)off);
				goto fail;
			}
			/* Mark it invalid. */
			*p ^= 1;
			(*num_found)++;

			if (hprefix_bits == 64) {
				/* Chained entries are unordered. */
				if (is_subhash(group[b])) {
					ecode = NTDB_ERR_CORRUPT;
					ntdb_logerr(ntdb, ecode,
						   NTDB_LOG_ERROR,
						   "ntdb_check: Invalid chain"
						   " entry subhash");
					goto fail;
				}
				h = hash_record(ntdb, off);
				if (h != hprefix) {
					ecode = NTDB_ERR_CORRUPT;
					ntdb_logerr(ntdb, ecode,
						   NTDB_LOG_ERROR,
						   "check: bad hash chain"
						   " placement"
						   " 0x%llx vs 0x%llx",
						   (long long)h,
						   (long long)hprefix);
					goto fail;
				}
				ecode = ntdb_read_convert(ntdb, off, &rec,
							 sizeof(rec));
				if (ecode != NTDB_SUCCESS) {
					goto fail;
				}
				goto check;
			}

			if (is_subhash(group[b])) {
				uint64_t subprefix;
				subprefix = (hprefix
				     << (group_bits + NTDB_HASH_GROUP_BITS))
					+ g * (1 << NTDB_HASH_GROUP_BITS) + b;

				ecode = check_hash_record(ntdb,
					       group[b] & NTDB_OFF_MASK,
					       subprefix,
					       hprefix_bits
						       + group_bits
						       + NTDB_HASH_GROUP_BITS,
					       used, num_used, num_found,
					       check, data);
				if (ecode != NTDB_SUCCESS) {
					goto fail;
				}
				continue;
			}
			/* A normal entry */

			/* Does it belong here at all? */
			h = hash_record(ntdb, off);
			used_bits = 0;
			if (get_bits(h, hprefix_bits, &used_bits) != hprefix
			    && hprefix_bits) {
				ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						   NTDB_LOG_ERROR,
						   "check: bad hash placement"
						   " 0x%llx vs 0x%llx",
						   (long long)h,
						   (long long)hprefix);
				goto fail;
			}

			/* Does it belong in this group? */
			if (get_bits(h, group_bits, &used_bits) != g) {
				ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						   NTDB_LOG_ERROR,
						   "check: bad group %llu"
						   " vs %u",
						   (long long)h, g);
				goto fail;
			}

			/* Are bucket bits correct? */
			bucket = group[b] & NTDB_OFF_HASH_GROUP_MASK;
			if (get_bits(h, NTDB_HASH_GROUP_BITS, &used_bits)
			    != bucket) {
				used_bits -= NTDB_HASH_GROUP_BITS;
				ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						   NTDB_LOG_ERROR,
						   "check: bad bucket %u vs %u",
						   (unsigned)get_bits(h,
							NTDB_HASH_GROUP_BITS,
							&used_bits),
						   bucket);
				goto fail;
			}

			/* There must not be any zero entries between
			 * the bucket it belongs in and this one! */
			for (i = bucket;
			     i != b;
			     i = (i + 1) % (1 << NTDB_HASH_GROUP_BITS)) {
				if (group[i] == 0) {
					ecode = NTDB_ERR_CORRUPT;
					ntdb_logerr(ntdb, ecode,
						   NTDB_LOG_ERROR,
						   "check: bad group placement"
						   " %u vs %u",
						   b, bucket);
					goto fail;
				}
			}

			ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec));
			if (ecode != NTDB_SUCCESS) {
				goto fail;
			}

			/* Bottom bits must match header. */
			if ((h & ((1 << 11)-1)) != rec_hash(&rec)) {
				ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						   NTDB_LOG_ERROR,
						   "ntdb_check: Bad hash magic"
						   " at offset %llu"
						   " (0x%llx vs 0x%llx)",
						   (long long)off,
						   (long long)h,
						   (long long)rec_hash(&rec));
				goto fail;
			}

		check:
			if (check) {
				NTDB_DATA k, d;
				const unsigned char *kptr;

				kptr = ntdb_access_read(ntdb,
						       off + sizeof(rec),
						       rec_key_length(&rec)
						       + rec_data_length(&rec),
						       false);
				if (NTDB_PTR_IS_ERR(kptr)) {
					ecode = NTDB_PTR_ERR(kptr);
					goto fail;
				}

				k = ntdb_mkdata(kptr, rec_key_length(&rec));
				d = ntdb_mkdata(kptr + k.dsize,
					       rec_data_length(&rec));
				ecode = check(k, d, data);
				ntdb_access_release(ntdb, kptr);
				if (ecode != NTDB_SUCCESS) {
					goto fail;
				}
			}
		}
	}
	ntdb_access_release(ntdb, hash);
	return NTDB_SUCCESS;

fail:
	ntdb_access_release(ntdb, hash);
	return ecode;
}

static enum NTDB_ERROR check_hash(struct ntdb_context *ntdb,
				 ntdb_off_t used[],
				 size_t num_used, size_t num_other_used,
				 enum NTDB_ERROR (*check)(NTDB_DATA, NTDB_DATA, void *),
				 void *data)
{
	/* Free tables and capabilities also show up as used. */
	size_t num_found = num_other_used;
	enum NTDB_ERROR ecode;

	ecode = check_hash_tree(ntdb, offsetof(struct ntdb_header, hashtable),
				NTDB_TOPLEVEL_HASH_BITS-NTDB_HASH_GROUP_BITS,
				0, 0, used, num_used, &num_found,
				check, data);
	if (ecode == NTDB_SUCCESS) {
		if (num_found != num_used) {
			ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
					   "ntdb_check: Not all entries"
					   " are in hash");
		}
	}
	return ecode;
}

static enum NTDB_ERROR check_free(struct ntdb_context *ntdb,
				 ntdb_off_t off,
				 const struct ntdb_free_record *frec,
				 ntdb_off_t prev, unsigned int ftable,
				 unsigned int bucket)
{
	enum NTDB_ERROR ecode;

	if (frec_magic(frec) != NTDB_FREE_MAGIC) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: offset %llu bad magic 0x%llx",
				  (long long)off,
				  (long long)frec->magic_and_prev);
	}
	if (frec_ftable(frec) != ftable) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: offset %llu bad freetable %u",
				  (long long)off, frec_ftable(frec));

	}

	ecode = ntdb_oob(ntdb, off,
			 frec_len(frec) + sizeof(struct ntdb_used_record),
			 false);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}
	if (size_to_bucket(frec_len(frec)) != bucket) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: offset %llu in wrong bucket"
				  " (%u vs %u)",
				  (long long)off,
				  bucket, size_to_bucket(frec_len(frec)));
	}
	if (prev && prev != frec_prev(frec)) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: offset %llu bad prev"
				  " (%llu vs %llu)",
				  (long long)off,
				  (long long)prev, (long long)frec_len(frec));
	}
	return NTDB_SUCCESS;
}

static enum NTDB_ERROR check_free_table(struct ntdb_context *ntdb,
				       ntdb_off_t ftable_off,
				       unsigned ftable_num,
				       ntdb_off_t fr[],
				       size_t num_free,
				       size_t *num_found)
{
	struct ntdb_freetable ft;
	ntdb_off_t h;
	unsigned int i;
	enum NTDB_ERROR ecode;

	ecode = ntdb_read_convert(ntdb, ftable_off, &ft, sizeof(ft));
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	if (rec_magic(&ft.hdr) != NTDB_FTABLE_MAGIC
	    || rec_key_length(&ft.hdr) != 0
	    || rec_data_length(&ft.hdr) != sizeof(ft) - sizeof(ft.hdr)
	    || rec_hash(&ft.hdr) != 0) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: Invalid header on free table");
	}

	for (i = 0; i < NTDB_FREE_BUCKETS; i++) {
		ntdb_off_t off, prev = 0, *p, first = 0;
		struct ntdb_free_record f;

		h = bucket_off(ftable_off, i);
		for (off = ntdb_read_off(ntdb, h); off; off = f.next) {
			if (NTDB_OFF_IS_ERR(off)) {
				return NTDB_OFF_TO_ERR(off);
			}
			if (!first) {
				off &= NTDB_OFF_MASK;
				first = off;
			}
			ecode = ntdb_read_convert(ntdb, off, &f, sizeof(f));
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
			ecode = check_free(ntdb, off, &f, prev, ftable_num, i);
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}

			/* FIXME: Check hash bits */
			p = asearch(&off, fr, num_free, off_cmp);
			if (!p) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: Invalid offset"
						  " %llu in free table",
						  (long long)off);
			}
			/* Mark it invalid. */
			*p ^= 1;
			(*num_found)++;
			prev = off;
		}

		if (first) {
			/* Now we can check first back pointer. */
			ecode = ntdb_read_convert(ntdb, first, &f, sizeof(f));
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
			ecode = check_free(ntdb, first, &f, prev, ftable_num, i);
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
		}
	}
	return NTDB_SUCCESS;
}

/* Slow, but should be very rare. */
ntdb_off_t dead_space(struct ntdb_context *ntdb, ntdb_off_t off)
{
	size_t len;
	enum NTDB_ERROR ecode;

	for (len = 0; off + len < ntdb->file->map_size; len++) {
		char c;
		ecode = ntdb->io->tread(ntdb, off, &c, 1);
		if (ecode != NTDB_SUCCESS) {
			return NTDB_ERR_TO_OFF(ecode);
		}
		if (c != 0 && c != 0x43)
			break;
	}
	return len;
}

static enum NTDB_ERROR check_linear(struct ntdb_context *ntdb,
				   ntdb_off_t **used, size_t *num_used,
				   ntdb_off_t **fr, size_t *num_free,
				   uint64_t features, ntdb_off_t recovery)
{
	ntdb_off_t off;
	ntdb_len_t len;
	enum NTDB_ERROR ecode;
	bool found_recovery = false;

	for (off = sizeof(struct ntdb_header);
	     off < ntdb->file->map_size;
	     off += len) {
		union {
			struct ntdb_used_record u;
			struct ntdb_free_record f;
			struct ntdb_recovery_record r;
		} rec;
		/* r is larger: only get that if we need to. */
		ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec.f));
		if (ecode != NTDB_SUCCESS) {
			return ecode;
		}

		/* If we crash after ftruncate, we can get zeroes or fill. */
		if (rec.r.magic == NTDB_RECOVERY_INVALID_MAGIC
		    || rec.r.magic ==  0x4343434343434343ULL) {
			ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec.r));
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
			if (recovery == off) {
				found_recovery = true;
				len = sizeof(rec.r) + rec.r.max_len;
			} else {
				len = dead_space(ntdb, off);
				if (NTDB_OFF_IS_ERR(len)) {
					return NTDB_OFF_TO_ERR(len);
				}
				if (len < sizeof(rec.r)) {
					return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
							  NTDB_LOG_ERROR,
							  "ntdb_check: invalid"
							  " dead space at %zu",
							  (size_t)off);
				}

				ntdb_logerr(ntdb, NTDB_SUCCESS, NTDB_LOG_WARNING,
					   "Dead space at %zu-%zu (of %zu)",
					   (size_t)off, (size_t)(off + len),
					   (size_t)ntdb->file->map_size);
			}
		} else if (rec.r.magic == NTDB_RECOVERY_MAGIC) {
			ecode = ntdb_read_convert(ntdb, off, &rec, sizeof(rec.r));
			if (ecode != NTDB_SUCCESS) {
				return ecode;
			}
			if (recovery != off) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: unexpected"
						  " recovery record at offset"
						  " %zu",
						  (size_t)off);
			}
			if (rec.r.len > rec.r.max_len) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: invalid recovery"
						  " length %zu",
						  (size_t)rec.r.len);
			}
			if (rec.r.eof > ntdb->file->map_size) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: invalid old EOF"
						  " %zu", (size_t)rec.r.eof);
			}
			found_recovery = true;
			len = sizeof(rec.r) + rec.r.max_len;
		} else if (frec_magic(&rec.f) == NTDB_FREE_MAGIC) {
			len = sizeof(rec.u) + frec_len(&rec.f);
			if (off + len > ntdb->file->map_size) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: free overlength"
						  " %llu at offset %llu",
						  (long long)len,
						  (long long)off);
			}
			/* This record should be in free lists. */
			if (frec_ftable(&rec.f) != NTDB_FTABLE_NONE
			    && !append(ntdb, fr, num_free, off)) {
				return ntdb_logerr(ntdb, NTDB_ERR_OOM,
						  NTDB_LOG_ERROR,
						  "ntdb_check: tracking %zu'th"
						  " free record.", *num_free);
			}
		} else if (rec_magic(&rec.u) == NTDB_USED_MAGIC
			   || rec_magic(&rec.u) == NTDB_CHAIN_MAGIC
			   || rec_magic(&rec.u) == NTDB_HTABLE_MAGIC
			   || rec_magic(&rec.u) == NTDB_FTABLE_MAGIC
			   || rec_magic(&rec.u) == NTDB_CAP_MAGIC) {
			uint64_t klen, dlen, extra;

			/* This record is used! */
			if (!append(ntdb, used, num_used, off)) {
				return ntdb_logerr(ntdb, NTDB_ERR_OOM,
						  NTDB_LOG_ERROR,
						  "ntdb_check: tracking %zu'th"
						  " used record.", *num_used);
			}

			klen = rec_key_length(&rec.u);
			dlen = rec_data_length(&rec.u);
			extra = rec_extra_padding(&rec.u);

			len = sizeof(rec.u) + klen + dlen + extra;
			if (off + len > ntdb->file->map_size) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: used overlength"
						  " %llu at offset %llu",
						  (long long)len,
						  (long long)off);
			}

			if (len < sizeof(rec.f)) {
				return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
						  NTDB_LOG_ERROR,
						  "ntdb_check: too short record"
						  " %llu at %llu",
						  (long long)len,
						  (long long)off);
			}

			/* Check that records have correct 0 at end (but may
			 * not in future). */
			if (extra && !features
			    && rec_magic(&rec.u) != NTDB_CAP_MAGIC) {
				const char *p;
				char c;
				p = ntdb_access_read(ntdb, off + sizeof(rec.u)
						    + klen + dlen, 1, false);
				if (NTDB_PTR_IS_ERR(p))
					return NTDB_PTR_ERR(p);
				c = *p;
				ntdb_access_release(ntdb, p);

				if (c != '\0') {
					return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
							  NTDB_LOG_ERROR,
							  "ntdb_check:"
							  " non-zero extra"
							  " at %llu",
							  (long long)off);
				}
			}
		} else {
			return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT,
					  NTDB_LOG_ERROR,
					  "ntdb_check: Bad magic 0x%llx"
					  " at offset %zu",
					  (long long)rec_magic(&rec.u),
					  (size_t)off);
		}
	}

	/* We must have found recovery area if there was one. */
	if (recovery != 0 && !found_recovery) {
		return ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				  "ntdb_check: expected a recovery area at %zu",
				  (size_t)recovery);
	}

	return NTDB_SUCCESS;
}

_PUBLIC_ enum NTDB_ERROR ntdb_check_(struct ntdb_context *ntdb,
			  enum NTDB_ERROR (*check)(NTDB_DATA, NTDB_DATA, void *),
			  void *data)
{
	ntdb_off_t *fr = NULL, *used = NULL, ft, recovery;
	size_t num_free = 0, num_used = 0, num_found = 0, num_ftables = 0,
		num_capabilities = 0;
	uint64_t features;
	enum NTDB_ERROR ecode;

	if (ntdb->flags & NTDB_CANT_CHECK) {
		return ntdb_logerr(ntdb, NTDB_SUCCESS, NTDB_LOG_WARNING,
				  "ntdb_check: database has unknown capability,"
				  " cannot check.");
	}

	ecode = ntdb_allrecord_lock(ntdb, F_RDLCK, NTDB_LOCK_WAIT, false);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	ecode = ntdb_lock_expand(ntdb, F_RDLCK);
	if (ecode != NTDB_SUCCESS) {
		ntdb_allrecord_unlock(ntdb, F_RDLCK);
		return ecode;
	}

	ecode = check_header(ntdb, &recovery, &features, &num_capabilities);
	if (ecode != NTDB_SUCCESS)
		goto out;

	/* First we do a linear scan, checking all records. */
	ecode = check_linear(ntdb, &used, &num_used, &fr, &num_free, features,
			     recovery);
	if (ecode != NTDB_SUCCESS)
		goto out;

	for (ft = first_ftable(ntdb); ft; ft = next_ftable(ntdb, ft)) {
		if (NTDB_OFF_IS_ERR(ft)) {
			ecode = NTDB_OFF_TO_ERR(ft);
			goto out;
		}
		ecode = check_free_table(ntdb, ft, num_ftables, fr, num_free,
					 &num_found);
		if (ecode != NTDB_SUCCESS)
			goto out;
		num_ftables++;
	}

	/* FIXME: Check key uniqueness? */
	ecode = check_hash(ntdb, used, num_used, num_ftables + num_capabilities,
			   check, data);
	if (ecode != NTDB_SUCCESS)
		goto out;

	if (num_found != num_free) {
		ecode = ntdb_logerr(ntdb, NTDB_ERR_CORRUPT, NTDB_LOG_ERROR,
				   "ntdb_check: Not all entries are in"
				   " free table");
	}

out:
	ntdb_allrecord_unlock(ntdb, F_RDLCK);
	ntdb_unlock_expand(ntdb, F_RDLCK);
	ntdb->free_fn(fr, ntdb->alloc_data);
	ntdb->free_fn(used, ntdb->alloc_data);
	return ecode;
}
