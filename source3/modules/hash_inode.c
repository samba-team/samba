/*
 * Unix SMB/Netbios implementation.
 *
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

#include "includes.h"
#include "hash_inode.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/crypto/gnutls_helpers.h"

SMB_INO_T hash_inode(const SMB_STRUCT_STAT *sbuf, const char *sname)
{
	gnutls_hash_hd_t hash_hnd = NULL;
	uint8_t digest[gnutls_hash_get_len(GNUTLS_DIG_SHA1)];
	char *upper_sname = NULL;
	SMB_INO_T result = 0;
	int rc;

	DBG_DEBUG("hash_inode called for %ju/%ju [%s]\n",
		  (uintmax_t)sbuf->st_ex_dev,
		  (uintmax_t)sbuf->st_ex_ino,
		  sname);

	upper_sname = talloc_strdup_upper(talloc_tos(), sname);
	SMB_ASSERT(upper_sname != NULL);

	GNUTLS_FIPS140_SET_LAX_MODE();

	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA1);
	if (rc < 0) {
		goto out;
	}

	rc = gnutls_hash(hash_hnd,
			 &(sbuf->st_ex_dev),
			 sizeof(sbuf->st_ex_dev));
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		goto out;
	}
	rc = gnutls_hash(hash_hnd,
			 &(sbuf->st_ex_ino),
			 sizeof(sbuf->st_ex_ino));
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		goto out;
	}
	rc = gnutls_hash(hash_hnd,
			 upper_sname,
			 talloc_get_size(upper_sname) - 1);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		goto out;
	}

	gnutls_hash_deinit(hash_hnd, digest);

	memcpy(&result, digest, sizeof(result));
	DBG_DEBUG("fruit_inode \"%s\": ino=%ju\n",
		  sname, (uintmax_t)result);

out:
	GNUTLS_FIPS140_SET_STRICT_MODE();
	TALLOC_FREE(upper_sname);

	DBG_DEBUG("hash_inode '%s': ino=%ju\n",
		  sname,
		  (uintmax_t)result);

	return result;
}
