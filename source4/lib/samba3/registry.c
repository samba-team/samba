/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Jelmer Vernooij		    2005
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
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Implementation of internal registry database functions. */

#include "includes.h"
#include "lib/samba3/samba3.h"
#include "librpc/gen_ndr/winreg.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "system/filesys.h"
#include "pstring.h"

#define VALUE_PREFIX	"SAMBA_REGVAL"
#define REGVER_V1	1	/* first db version with write support */

/****************************************************************************
 Unpack a list of registry values from the TDB
 ***************************************************************************/
 
static int regdb_unpack_values(TDB_CONTEXT *tdb, TALLOC_CTX *ctx, struct samba3_regkey *key, TDB_DATA data )
{
	int 		len = 0;
	uint32_t	type;
	uint32_t	size;
	uint8_t *data_p;
	uint32_t	num_values = 0;
	int 		i;
	fstring valuename;
	
	/* loop and unpack the rest of the registry values */
	
	len += tdb_unpack(tdb, (char *)data.dptr+len, data.dsize-len, "d", &num_values);
	
	for ( i=0; i<num_values; i++ ) {
		struct samba3_regval val;
		/* unpack the next regval */
		
		type = REG_NONE;
		size = 0;
		data_p = NULL;
		len += tdb_unpack(tdb, (char *)data.dptr+len, data.dsize-len, "fdB",
				  valuename,
				  &val.type,
				  &size,
				  &data_p);
		val.name = talloc_strdup(ctx, valuename);
		val.data = data_blob_talloc(ctx, data_p, size);

		key->values = talloc_realloc(ctx, key->values, struct samba3_regval, key->value_count+1);
		key->values[key->value_count] = val;
		key->value_count++;
	}

	return len;
}


	
/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
NTSTATUS samba3_read_regdb ( const char *fn, TALLOC_CTX *ctx, struct samba3_regdb *db )
{
	uint32_t vers_id;
	TDB_CONTEXT *tdb;
	TDB_DATA kbuf, vbuf;

	/* placeholder tdb; reinit upon startup */
	
	if ( !(tdb = tdb_open(fn, 0, TDB_DEFAULT, O_RDONLY, 0600)) )
	{
		DEBUG(0, ("Unable to open registry database %s\n", fn));
		return NT_STATUS_UNSUCCESSFUL;
	}

	vers_id = tdb_fetch_int32(tdb, "INFO/version");

	db->key_count = 0;
	db->keys = NULL;
	
	if (vers_id != -1 && vers_id >= REGVER_V1) {
		DEBUG(0, ("Registry version mismatch: %d\n", vers_id));
		return NT_STATUS_UNSUCCESSFUL;
	}

	for (kbuf = tdb_firstkey(tdb); kbuf.dptr; kbuf = tdb_nextkey(tdb, kbuf))
	{
		uint32_t len;
		int i;
		struct samba3_regkey key;
		char *skey;
			
		if (strncmp((char *)kbuf.dptr, VALUE_PREFIX, strlen(VALUE_PREFIX)) == 0)
			continue;

		vbuf = tdb_fetch(tdb, kbuf);

		key.name = talloc_strdup(ctx, (char *)kbuf.dptr); 

		len = tdb_unpack(tdb, (char *)vbuf.dptr, vbuf.dsize, "d", &key.subkey_count);

		key.value_count = 0;
		key.values = NULL;
		key.subkeys = talloc_array(ctx, char *, key.subkey_count);
	
		for (i = 0; i < key.subkey_count; i++) {
			fstring tmp;
			len += tdb_unpack( tdb, (char *)vbuf.dptr+len, vbuf.dsize-len, "f", tmp );
			key.subkeys[i] = talloc_strdup(ctx, tmp);
		}

		skey = talloc_asprintf(ctx, "%s/%s", VALUE_PREFIX, kbuf.dptr );
	
		vbuf = tdb_fetch_bystring( tdb, skey );
	
		if ( vbuf.dptr ) {
			regdb_unpack_values( tdb, ctx, &key, vbuf );
		}

		db->keys = talloc_realloc(ctx, db->keys, struct samba3_regkey, db->key_count+1);
		db->keys[db->key_count] = key;
		db->key_count++;
	}

	tdb_close(tdb);

	return NT_STATUS_OK;
}
