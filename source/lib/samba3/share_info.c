/* 
 *  Unix SMB/CIFS implementation.
 *  Share Info parsing
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Jeremy Allison					2001.
 *  Copyright (C) Nigel Williams					2001.
 *  Copyright (C) Jelmer Vernooij					2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "lib/samba3/samba3.h"
#include "system/filesys.h"

#define SHARE_DATABASE_VERSION_V1 1
#define SHARE_DATABASE_VERSION_V2 2 /* version id in little endian. */

NTSTATUS samba3_read_share_info(const char *fn, TALLOC_CTX *ctx, struct samba3 *db)
{
	int32_t vers_id;
	TDB_CONTEXT *tdb;
	TDB_DATA kbuf, vbuf;
	DATA_BLOB blob;
 
	tdb = tdb_open(fn, 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open share info database %s (%s)\n",
			fn, strerror(errno) ));
		return NT_STATUS_UNSUCCESSFUL;
	}
 
	/* Cope with byte-reversed older versions of the db. */
	vers_id = tdb_fetch_int32(tdb, "INFO/version");
	if ((vers_id == SHARE_DATABASE_VERSION_V1) || (IREV(vers_id) == SHARE_DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */
		vers_id = SHARE_DATABASE_VERSION_V2;
	}

	if (vers_id != SHARE_DATABASE_VERSION_V2) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	for (kbuf = tdb_firstkey(tdb); kbuf.dptr; kbuf = tdb_nextkey(tdb, kbuf)) 
	{
		struct ndr_pull *pull;
		struct samba3_share_info *share;
		char *name;
		
		if (strncmp((char *)kbuf.dptr, "SECDESC/", strlen("SECDESC/")) != 0)
			continue;

		name = talloc_strndup(ctx, (char *)kbuf.dptr+strlen("SECDESC/"), kbuf.dsize-strlen("SECDESC/"));

		db->shares = talloc_realloc(db, db->shares, struct samba3_share_info, db->share_count+1);
		share = &db->shares[db->share_count];
		db->share_count++;

		share->name = talloc_strdup(db, name);

		vbuf = tdb_fetch(tdb, kbuf);
		blob.data = (uint8_t *)vbuf.dptr;
		blob.length = vbuf.dsize;

		pull = ndr_pull_init_blob(&blob, ctx);

		ndr_pull_security_descriptor(pull, NDR_SCALARS|NDR_BUFFERS, &share->secdesc);

		talloc_free(pull);
	}

	tdb_close(tdb);

	return NT_STATUS_OK;
}
