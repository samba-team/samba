/*
 * Unix SMB/CIFS implementation.
 * store smbd profiling information in shared memory
 * Copyright (C) Andrew Tridgell 1999
 * Copyright (C) James Peach 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <tdb.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/crypto/gnutls_helpers.h"
#include "lib/util/byteorder.h"
#include "source3/include/smbprofile.h"

void smbprofile_stats_accumulate(struct profile_stats *acc,
				 const struct profile_stats *add)
{
#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name)                    \
	do {                                            \
		acc->values.name##_stats.count +=       \
			add->values.name##_stats.count; \
	} while (0);
#define SMBPROFILE_STATS_TIME(name)                    \
	do {                                           \
		acc->values.name##_stats.time +=       \
			add->values.name##_stats.time; \
	} while (0);
#define SMBPROFILE_STATS_BASIC(name)                    \
	do {                                            \
		acc->values.name##_stats.count +=       \
			add->values.name##_stats.count; \
		acc->values.name##_stats.time +=        \
			add->values.name##_stats.time;  \
	} while (0);
#define SMBPROFILE_STATS_BYTES(name)                    \
	do {                                            \
		acc->values.name##_stats.count +=       \
			add->values.name##_stats.count; \
		acc->values.name##_stats.time +=        \
			add->values.name##_stats.time;  \
		acc->values.name##_stats.idle +=        \
			add->values.name##_stats.idle;  \
		acc->values.name##_stats.bytes +=       \
			add->values.name##_stats.bytes; \
	} while (0);
#define SMBPROFILE_STATS_IOBYTES(name)                     \
	do {                                               \
		acc->values.name##_stats.count +=          \
			add->values.name##_stats.count;    \
		acc->values.name##_stats.time +=           \
			add->values.name##_stats.time;     \
		acc->values.name##_stats.buckets[0] +=     \
			add->values.name##_stats.buckets[0]; \
		acc->values.name##_stats.buckets[1] +=     \
			add->values.name##_stats.buckets[1]; \
		acc->values.name##_stats.buckets[2] +=     \
			add->values.name##_stats.buckets[2]; \
		acc->values.name##_stats.buckets[3] +=     \
			add->values.name##_stats.buckets[3]; \
		acc->values.name##_stats.buckets[4] +=     \
			add->values.name##_stats.buckets[4]; \
		acc->values.name##_stats.buckets[5] +=     \
			add->values.name##_stats.buckets[5]; \
		acc->values.name##_stats.buckets[6] +=     \
			add->values.name##_stats.buckets[6]; \
		acc->values.name##_stats.buckets[7] +=     \
			add->values.name##_stats.buckets[7]; \
		acc->values.name##_stats.buckets[8] +=     \
			add->values.name##_stats.buckets[8]; \
		acc->values.name##_stats.buckets[9] +=     \
			add->values.name##_stats.buckets[9]; \
		acc->values.name##_stats.idle +=           \
			add->values.name##_stats.idle;     \
		acc->values.name##_stats.inbytes +=        \
			add->values.name##_stats.inbytes;  \
		acc->values.name##_stats.outbytes +=       \
			add->values.name##_stats.outbytes; \
	} while (0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END
}

int smbprofile_magic(const struct profile_stats *stats, uint64_t *_magic)
{
	uint8_t digest[gnutls_hash_get_len(GNUTLS_DIG_SHA1)];
	gnutls_hash_hd_t hash_hnd = NULL;
	int rc;

	GNUTLS_FIPS140_SET_LAX_MODE();

	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA1);
	if (rc < 0) {
		goto out;
	}
	rc = gnutls_hash(hash_hnd, stats, sizeof(*stats));

#define __UPDATE(str)                                          \
	do {                                                   \
		rc |= gnutls_hash(hash_hnd, str, strlen(str)); \
	} while (0)
#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display) \
	do {                                          \
		__UPDATE(#name "+" #display);         \
	} while (0);
#define SMBPROFILE_STATS_COUNT(name)      \
	do {                              \
		__UPDATE(#name "+count"); \
	} while (0);
#define SMBPROFILE_STATS_TIME(name)      \
	do {                             \
		__UPDATE(#name "+time"); \
	} while (0);
#define SMBPROFILE_STATS_BASIC(name)      \
	do {                              \
		__UPDATE(#name "+count"); \
		__UPDATE(#name "+time");  \
	} while (0);
#define SMBPROFILE_STATS_BYTES(name)      \
	do {                              \
		__UPDATE(#name "+count"); \
		__UPDATE(#name "+time");  \
		__UPDATE(#name "+idle");  \
		__UPDATE(#name "+bytes"); \
	} while (0);
#define SMBPROFILE_STATS_IOBYTES(name)       \
	do {                                 \
		__UPDATE(#name "+count");    \
		__UPDATE(#name "+time");     \
		__UPDATE(#name "+idle");     \
		__UPDATE(#name "+inbytes");  \
		__UPDATE(#name "+outbytes"); \
	} while (0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef __UPDATE
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END
	if (rc != 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		goto out;
	}

	gnutls_hash_deinit(hash_hnd, digest);
out:
	GNUTLS_FIPS140_SET_STRICT_MODE();

	if (rc == 0) {
		uint64_t magic = PULL_LE_U64(digest, 0);
		if (magic == 0) {
			magic = PULL_LE_U64(digest, 0);
		}
		*_magic = magic;
	}

	return rc;
}

static int smbprofile_collect_fn(struct tdb_context *tdb,
				 TDB_DATA key,
				 TDB_DATA value,
				 void *private_data)
{
	struct profile_stats *acc = (struct profile_stats *)private_data;
	const struct profile_stats *v;

	if (value.dsize != sizeof(struct profile_stats)) {
		return 0;
	}

	v = (const struct profile_stats *)value.dptr;

	if (v->magic != acc->magic) {
		return 0;
	}

	smbprofile_stats_accumulate(acc, v);
	return 0;
}

void smbprofile_collect_tdb(struct tdb_context *tdb,
			    uint64_t magic,
			    struct profile_stats *stats)
{
	*stats = (struct profile_stats){.magic = magic};

	tdb_traverse_read(tdb, smbprofile_collect_fn, stats);
}
