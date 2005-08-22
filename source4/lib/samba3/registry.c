/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Jelmer Vernooij		    2005
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
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

/* Implementation of internal registry database functions. */

#include "includes.h"

#define VALUE_PREFIX	"SAMBA_REGVAL"
#define REGVER_V1	1	/* first db version with write support */
	
/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
static TDB_CONTEXT *samba3_open_registry ( const char *fn )
{
	uint32_t vers_id;

	/* placeholder tdb; reinit upon startup */
	
	if ( !(tdb = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDONLY, 0600)) )
	{
		return NULL;
	}

	vers_id = tdb_fetch_int32(tdb, "INFO/version");
	
	if (vers_id > REGVER_V1) 
		return NULL;

	return True;
}

/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  
 ***********************************************************************/

int regdb_fetch_keys( TDB_CONTEXT *tdb, const char* key, REGSUBKEY_CTR *ctr )
{
	char *path;
	uint32_t num_items;
	TDB_DATA dbuf;
	char *buf;
	uint32_t buflen, len;
	int i;
	fstring subkeyname;

	DEBUG(11,("regdb_fetch_keys: Enter key => [%s]\n", key ? key : "NULL"));
	
	path = talloc_strdup(key);
	
	/* convert to key format */
	for ( i = 0; path[i]; i++) {
		if ( path[i] == '\\' )
			path[i] = '/';
	}
	strupper_m( path );
	
	dbuf = tdb_fetch_bystring( tdb, path );
	
	buf = dbuf.dptr;
	buflen = dbuf.dsize;
	
	if ( !buf ) {
		DEBUG(5,("regdb_fetch_keys: tdb lookup failed to locate key [%s]\n", key));
		return -1;
	}
	
	len = tdb_unpack( buf, buflen, "d", &num_items);
	
	for (i=0; i<num_items; i++) {
		len += tdb_unpack( buf+len, buflen-len, "f", subkeyname );
		regsubkey_ctr_addkey( ctr, subkeyname );
	}

	SAFE_FREE( dbuf.dptr );
	
	DEBUG(11,("regdb_fetch_keys: Exit [%d] items\n", num_items));
	
	return num_items;
}

/****************************************************************************
 Unpack a list of registry values frem the TDB
 ***************************************************************************/
 
static int regdb_unpack_values(REGVAL_CTR *values, char *buf, int buflen)
{
	int 		len = 0;
	uint32_t	type;
	char 		*valuename;
	uint32_t	size;
	uint8_t		*data_p;
	uint32_t	num_values = 0;
	int 		i;
	
	/* loop and unpack the rest of the registry values */
	
	len += tdb_unpack(buf+len, buflen-len, "d", &num_values);
	
	for ( i=0; i<num_values; i++ ) {
		/* unpack the next regval */
		
		type = REG_NONE;
		size = 0;
		data_p = NULL;
		len += tdb_unpack(buf+len, buflen-len, "fdB",
				  valuename,
				  &type,
				  &size,
				  &data_p);
				
		/* add the new value. Paranoid protective code -- make sure data_p is valid */

		if ( size && data_p ) {
			regval_ctr_addvalue( values, valuename, type, (const char *)data_p, size );
			SAFE_FREE(data_p); /* 'B' option to tdb_unpack does a malloc() */
		}

		DEBUG(8,("specific: [%s], len: %d\n", valuename, size));
	}

	return len;
}

/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.
 ***********************************************************************/

int regdb_fetch_values( TDB_CONTEXT *tdb, const char* key, REGVAL_CTR *values )
{
	TDB_DATA data;
	pstring keystr;

	DEBUG(10,("regdb_fetch_values: Looking for value of key [%s] \n", key));
	
	pstr_sprintf( keystr, "%s/%s", VALUE_PREFIX, key );
	normalize_reg_path( keystr );
	
	data = tdb_fetch_bystring( tdb, keystr );
	
	if ( !data.dptr ) {
		/* all keys have zero values by default */
		return 0;
	}
	
	regdb_unpack_values( values, data.dptr, data.dsize );
	
	SAFE_FREE( data.dptr );
	
	return regval_ctr_numvals(values);
}
