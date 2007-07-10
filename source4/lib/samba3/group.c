/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
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
#include "lib/samba3/samba3.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "system/filesys.h"
#include "libcli/security/security.h"

#define DATABASE_VERSION_V1 1 /* native byte format. */
#define DATABASE_VERSION_V2 2 /* le format. */

#define GROUP_PREFIX "UNIXGROUP/"

/* Alias memberships are stored reverse, as memberships. The performance
 * critical operation is to determine the aliases a SID is member of, not
 * listing alias members. So we store a list of alias SIDs a SID is member of
 * hanging of the member as key.
 */
#define MEMBEROF_PREFIX "MEMBEROF/"

/****************************************************************************
 Open the group mapping tdb.
****************************************************************************/
NTSTATUS samba3_read_grouptdb(const char *file, TALLOC_CTX *ctx, struct samba3_groupdb *db)
{
	int32_t vers_id;
	TDB_DATA kbuf, dbuf, newkey;
	int ret;
	TDB_CONTEXT *tdb; 

	tdb = tdb_open(file, 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open group mapping database\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Cope with byte-reversed older versions of the db. */
	vers_id = tdb_fetch_int32(tdb, "INFO/version");
	if ((vers_id == DATABASE_VERSION_V1) || (IREV(vers_id) == DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */
		vers_id = DATABASE_VERSION_V2;
	}

	if (vers_id != DATABASE_VERSION_V2) {
		DEBUG(0, ("Group database version mismatch: %d\n", vers_id));
		return NT_STATUS_UNSUCCESSFUL;
	}

	db->groupmappings = NULL;
	db->groupmap_count = 0;
	db->aliases = NULL;
	db->alias_count = 0;

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), free(kbuf.dptr), kbuf=newkey) {
		struct samba3_groupmapping map;
		const char *k = (const char *)kbuf.dptr;

		if (strncmp(k, GROUP_PREFIX, strlen(GROUP_PREFIX)) == 0)
		{
			dbuf = tdb_fetch(tdb, kbuf);
			if (!dbuf.dptr)
				continue;

			ZERO_STRUCT(map);

			map.sid = dom_sid_parse_talloc(ctx, k+strlen(GROUP_PREFIX));

			ret = tdb_unpack(tdb, (char *)dbuf.dptr, dbuf.dsize, "dd",
							 &map.gid, &map.sid_name_use);
			
			if ( ret == -1 ) {
				DEBUG(3,("enum_group_mapping: tdb_unpack failure\n"));
				continue;
			}

			map.nt_name = talloc_strdup(ctx, (const char *)(dbuf.dptr+ret));
			map.comment = talloc_strdup(ctx, (const char *)(dbuf.dptr+ret+strlen(map.nt_name)));

			db->groupmappings = talloc_realloc(ctx, db->groupmappings, struct samba3_groupmapping, db->groupmap_count+1);

			if (!db->groupmappings) 
				return NT_STATUS_NO_MEMORY;

			db->groupmappings[db->groupmap_count] = map;

			db->groupmap_count++;
		} else if (strncmp(k, MEMBEROF_PREFIX, strlen(MEMBEROF_PREFIX)) == 0)
		{
			struct samba3_alias alias;
			const char **member_strlist;
			int i;

			dbuf = tdb_fetch(tdb, kbuf);
			if (!dbuf.dptr)
				continue;

			alias.sid = dom_sid_parse_talloc(ctx, k+strlen(MEMBEROF_PREFIX));
			alias.member_count = 0;
			alias.members = NULL;

			member_strlist = str_list_make_shell(ctx, (const char *)dbuf.dptr, " ");

			for (i = 0; member_strlist[i]; i++) {
				alias.members = talloc_realloc(ctx, alias.members, struct dom_sid *, alias.member_count+1);
				alias.members[alias.member_count] = dom_sid_parse_talloc(ctx, member_strlist[i]);
				alias.member_count++;
			}

			talloc_free(member_strlist);

			db->aliases = talloc_realloc(ctx, db->aliases, struct samba3_alias, db->alias_count+1);
			db->aliases[db->alias_count] = alias;
			db->alias_count++;
		}
	}

	tdb_close(tdb);

	return NT_STATUS_OK;
}
