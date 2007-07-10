/* 
   Unix SMB/CIFS implementation.

   idmap TDB backend

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Simo Sorce 2003
   Copyright (C) Jelmer Vernooij 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "lib/samba3/samba3.h"
#include "system/filesys.h"
#include "libcli/security/security.h"

/* High water mark keys */
#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

/* idmap version determines auto-conversion */
#define IDMAP_VERSION 2

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/

NTSTATUS samba3_read_idmap(const char *fn, TALLOC_CTX *ctx, struct samba3_idmapdb *idmap)
{
	TDB_CONTEXT *tdb;
	TDB_DATA key, val;
	int32_t version;

	/* Open idmap repository */
	if (!(tdb = tdb_open(fn, 0, TDB_DEFAULT, O_RDONLY, 0644))) {
		DEBUG(0, ("idmap_init: Unable to open idmap database '%s'\n", fn));
		return NT_STATUS_UNSUCCESSFUL;
	}

	idmap->mapping_count = 0;
	idmap->mappings = NULL;
	idmap->user_hwm = tdb_fetch_int32(tdb, HWM_USER);
	idmap->group_hwm = tdb_fetch_int32(tdb, HWM_GROUP);

	/* check against earlier versions */
	version = tdb_fetch_int32(tdb, "IDMAP_VERSION");
	if (version != IDMAP_VERSION) {
		DEBUG(0, ("idmap_init: Unable to open idmap database, it's in an old format!\n"));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	for (key = tdb_firstkey(tdb); key.dptr; key = tdb_nextkey(tdb, key)) 
	{
		struct samba3_idmap_mapping map;
		const char *k = (const char *)key.dptr;
		const char *v;

		if (strncmp(k, "GID ", 4) == 0) {
			map.type = IDMAP_GROUP;
			map.unix_id = atoi(k+4);
			val = tdb_fetch(tdb, key);
			v = (const char *)val.dptr;
			map.sid = dom_sid_parse_talloc(ctx, v);
		} else if (strncmp(k, "UID ", 4) == 0) {
			map.type = IDMAP_USER;
			map.unix_id = atoi(k+4);
			val = tdb_fetch(tdb, key);
			v = (const char *)val.dptr;
			map.sid = dom_sid_parse_talloc(ctx, v);
		} else {
			continue;
		}

		idmap->mappings = talloc_realloc(ctx, idmap->mappings, struct samba3_idmap_mapping, idmap->mapping_count+1);

		idmap->mappings[idmap->mapping_count] = map;
		idmap->mapping_count++;
	}

	tdb_close(tdb);

	return NT_STATUS_OK;
}
