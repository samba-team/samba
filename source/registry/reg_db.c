/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static TDB_CONTEXT *tdb_reg;

#define VALUE_PREFIX	"SAMBA_REGVAL"

static BOOL regdb_store_reg_keys( const char *keyname, REGSUBKEY_CTR *subkeys );
static BOOL regdb_store_reg_values( const char *keyname, REGVAL_CTR *values);
static int regdb_fetch_reg_keys( const char* key, REGSUBKEY_CTR *subkeys );
static int regdb_fetch_reg_values( const char* key, REGVAL_CTR *values );




/* List the deepest path into the registry.  All part components will be created.*/

/* If you want to have a part of the path controlled by the tdb abd part by
   a virtual registry db (e.g. printing), then you have to list the deepest path.
   For example,"HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Print" 
   allows the reg_db backend to handle everything up to 
   "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" and then we'll hook 
   the reg_printing backend onto the last component of the path (see 
   KEY_PRINTING_2K in include/rpc_reg.h)   --jerry */

static const char *builtin_registry_paths[] = {
	"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print",
	"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports",
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print",
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
	"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares",
	"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog",
	"HKLM\\SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters",
	"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
	"HKU",
	"HKCR",
	 NULL };

struct builtin_regkey_value {
	const char *path;
	const char *valuename;
	uint32 type;
	union {
		const char *string;
		uint32 dw_value;
	} data;
};

static struct builtin_regkey_value builtin_registry_values[] = {
	{ "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 	"SystemRoot", 	REG_SZ, 	{ "c:\\Windows" } },
	{ NULL, NULL, 0, { NULL } }
};

#define REGVER_V1	1	/* first db version with write support */
	
/***********************************************************************
 Open the registry data in the tdb
 ***********************************************************************/
 
static BOOL init_registry_data( void )
{
	pstring path, base, remaining;
	fstring keyname, subkeyname;
	REGSUBKEY_CTR	subkeys;
	REGVAL_CTR values;
	int i;
	const char *p, *p2;
	UNISTR2 data;
	
	/* loop over all of the predefined paths and add each component */
	
	for ( i=0; builtin_registry_paths[i] != NULL; i++ ) {

		DEBUG(6,("init_registry_data: Adding [%s]\n", builtin_registry_paths[i]));

		pstrcpy( path, builtin_registry_paths[i] );
		pstrcpy( base, "" );
		p = path;
		
		while ( next_token(&p, keyname, "\\", sizeof(keyname)) ) {
		
			/* build up the registry path from the components */
			
			if ( *base )
				pstrcat( base, "\\" );
			pstrcat( base, keyname );
			
			/* get the immediate subkeyname (if we have one ) */
			
			*subkeyname = '\0';
			if ( *p ) {
				pstrcpy( remaining, p );
				p2 = remaining;
				
				if ( !next_token(&p2, subkeyname, "\\", sizeof(subkeyname)) )
					fstrcpy( subkeyname, p2 );
			}

			DEBUG(10,("init_registry_data: Storing key [%s] with subkey [%s]\n",
				base, *subkeyname ? subkeyname : "NULL"));
			
			/* we don't really care if the lookup succeeds or not since
			   we are about to update the record.  We just want any 
			   subkeys already present */
			
			regsubkey_ctr_init( &subkeys );
						   
			regdb_fetch_reg_keys( base, &subkeys );
			if ( *subkeyname ) 
				regsubkey_ctr_addkey( &subkeys, subkeyname );
			if ( !regdb_store_reg_keys( base, &subkeys ))
				return False;
			
			regsubkey_ctr_destroy( &subkeys );
		}
	}

	/* loop over all of the predefined values and add each component */
	
	for ( i=0; builtin_registry_values[i].path != NULL; i++ ) {
		regval_ctr_init( &values );
		
		regdb_fetch_reg_values( builtin_registry_values[i].path, &values );
		switch( builtin_registry_values[i].type ) {
			case REG_DWORD:
				regval_ctr_addvalue( &values, 
				                     builtin_registry_values[i].valuename,
						     REG_DWORD,
						     (char*)&builtin_registry_values[i].data.dw_value,
						     sizeof(uint32) );
				break;
				
			case REG_SZ:
				init_unistr2( &data, builtin_registry_values[i].data.string, UNI_STR_TERMINATE);
				regval_ctr_addvalue( &values, 
				                     builtin_registry_values[i].valuename,
						     REG_SZ,
						     (char*)data.buffer,
						     data.uni_str_len*sizeof(uint16) );
				break;
			
			default:
				DEBUG(0,("init_registry_data: invalid value type in builtin_registry_values [%d]\n",
					builtin_registry_values[i].type));
		}
		regdb_store_reg_values( builtin_registry_values[i].path, &values );
		
		regval_ctr_destroy( &values );
	}
	
	return True;
}

/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
BOOL init_registry_db( void )
{
	const char *vstring = "INFO/version";
	uint32 vers_id;

	if ( tdb_reg )
		return True;

	/* placeholder tdb; reinit upon startup */
	
	if ( !(tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR, 0600)) )
	{
		tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
		if ( !tdb_reg ) {
			DEBUG(0,("init_registry: Failed to open registry %s (%s)\n",
				lock_path("registry.tdb"), strerror(errno) ));
			return False;
		}
		
		DEBUG(10,("init_registry: Successfully created registry tdb\n"));
	}
		

	vers_id = tdb_fetch_int32(tdb_reg, vstring);

	if ( vers_id != REGVER_V1 ) {

		/* create the registry here */

		if ( !init_registry_data() ) {
			DEBUG(0,("init_registry: Failed to initiailize data in registry!\n"));
			return False;
		}
	}

	return True;
}

/***********************************************************************
 Add subkey strings to the registry tdb under a defined key
 fmt is the same format as tdb_pack except this function only supports
 fstrings
 ***********************************************************************/
 
static BOOL regdb_store_reg_keys_internal( const char *key, REGSUBKEY_CTR *ctr )
{
	TDB_DATA kbuf, dbuf;
	char *buffer, *tmpbuf;
	int i = 0;
	uint32 len, buflen;
	BOOL ret = True;
	uint32 num_subkeys = regsubkey_ctr_numkeys( ctr );
	pstring keyname;
	
	if ( !key )
		return False;

	pstrcpy( keyname, key );
	normalize_reg_path( keyname );

	/* allocate some initial memory */
		
	buffer = SMB_MALLOC(sizeof(pstring));
	buflen = sizeof(pstring);
	len = 0;
	
	/* store the number of subkeys */
	
	len += tdb_pack(buffer+len, buflen-len, "d", num_subkeys );
	
	/* pack all the strings */
	
	for (i=0; i<num_subkeys; i++) {
		len += tdb_pack( buffer+len, buflen-len, "f", regsubkey_ctr_specific_key(ctr, i) );
		if ( len > buflen ) {
			/* allocate some extra space */
			if ((tmpbuf = SMB_REALLOC( buffer, len*2 )) == NULL) {
				DEBUG(0,("regdb_store_reg_keys: Failed to realloc memory of size [%d]\n", len*2));
				ret = False;
				goto done;
			}
			buffer = tmpbuf;
			buflen = len*2;
					
			len = tdb_pack( buffer+len, buflen-len, "f", regsubkey_ctr_specific_key(ctr, i) );
		}		
	}
	
	/* finally write out the data */
	
	kbuf.dptr = keyname;
	kbuf.dsize = strlen(keyname)+1;
	dbuf.dptr = buffer;
	dbuf.dsize = len;
	if ( tdb_store( tdb_reg, kbuf, dbuf, TDB_REPLACE ) == -1) {
		ret = False;
		goto done;
	}

done:		
	SAFE_FREE( buffer );
	
	return ret;
}

/***********************************************************************
 Store the new subkey record and create any child key records that 
 do not currently exist
 ***********************************************************************/

static BOOL regdb_store_reg_keys( const char *key, REGSUBKEY_CTR *ctr )
{
	int num_subkeys, i;
	pstring path;
	REGSUBKEY_CTR subkeys, old_subkeys;
	char *oldkeyname;
	
	/* fetch a list of the old subkeys so we can determine if any were deleted */
	
	regsubkey_ctr_init( &old_subkeys );
	regdb_fetch_reg_keys( key, &old_subkeys );
	
	/* store the subkey list for the parent */
	
	if ( !regdb_store_reg_keys_internal( key, ctr ) ) {
		DEBUG(0,("regdb_store_reg_keys: Failed to store new subkey list for parent [%s}\n", key ));
		return False;
	}
	
	/* now delete removed keys */
	
	num_subkeys = regsubkey_ctr_numkeys( &old_subkeys );
	for ( i=0; i<num_subkeys; i++ ) {
		oldkeyname = regsubkey_ctr_specific_key( &old_subkeys, i );
		if ( !regsubkey_ctr_key_exists( ctr, oldkeyname ) ) {
			pstr_sprintf( path, "%s%c%s", key, '/', oldkeyname );
			normalize_reg_path( path );
			tdb_delete_bystring( tdb_reg, path );
		}
	}

	regsubkey_ctr_destroy( &old_subkeys );
	
	/* now create records for any subkeys that don't already exist */
	
	num_subkeys = regsubkey_ctr_numkeys( ctr );
	for ( i=0; i<num_subkeys; i++ ) {
		pstr_sprintf( path, "%s%c%s", key, '/', regsubkey_ctr_specific_key( ctr, i ) );
		regsubkey_ctr_init( &subkeys );
		if ( regdb_fetch_reg_keys( path, &subkeys ) == -1 ) {
			/* create a record with 0 subkeys */
			if ( !regdb_store_reg_keys_internal( path, &subkeys ) ) {
				DEBUG(0,("regdb_store_reg_keys: Failed to store new record for key [%s}\n", path ));
				regsubkey_ctr_destroy( &subkeys );
				return False;
			}
		}
		regsubkey_ctr_destroy( &subkeys );
	}
	
	return True;
}


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  
 ***********************************************************************/

static int regdb_fetch_reg_keys( const char* key, REGSUBKEY_CTR *ctr )
{
	pstring path;
	uint32 num_items;
	TDB_DATA dbuf;
	char *buf;
	uint32 buflen, len;
	int i;
	fstring subkeyname;

	DEBUG(10,("regdb_fetch_reg_keys: Enter key => [%s]\n", key ? key : "NULL"));
	
	pstrcpy( path, key );
	
	/* convert to key format */
	pstring_sub( path, "\\", "/" ); 
	strupper_m( path );
	
	dbuf = tdb_fetch_bystring( tdb_reg, path );
	
	buf = dbuf.dptr;
	buflen = dbuf.dsize;
	
	if ( !buf ) {
		DEBUG(5,("regdb_fetch_reg_keys: tdb lookup failed to locate key [%s]\n", key));
		return -1;
	}
	
	len = tdb_unpack( buf, buflen, "d", &num_items);
	
	for (i=0; i<num_items; i++) {
		len += tdb_unpack( buf+len, buflen-len, "f", subkeyname );
		regsubkey_ctr_addkey( ctr, subkeyname );
	}

	SAFE_FREE( dbuf.dptr );
	
	DEBUG(10,("regdb_fetch_reg_keys: Exit [%d] items\n", num_items));
	
	return num_items;
}

/****************************************************************************
 Unpack a list of registry values frem the TDB
 ***************************************************************************/
 
static int regdb_unpack_values(REGVAL_CTR *values, char *buf, int buflen)
{
	int 		len = 0;
	uint32		type;
	pstring		valuename;
	uint32		size;
	uint8		*data_p;
	uint32 		num_values = 0;
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

/****************************************************************************
 Pack all values in all printer keys
 ***************************************************************************/
 
static int regdb_pack_values(REGVAL_CTR *values, char *buf, int buflen)
{
	int 		len = 0;
	int 		i;
	REGISTRY_VALUE	*val;
	int		num_values = regval_ctr_numvals( values );

	if ( !values )
		return 0;

	/* pack the number of values first */
	
	len += tdb_pack( buf+len, buflen-len, "d", num_values );
	
	/* loop over all values */
		
	for ( i=0; i<num_values; i++ ) {			
		val = regval_ctr_specific_value( values, i );
		len += tdb_pack(buf+len, buflen-len, "fdB",
				regval_name(val),
				regval_type(val),
				regval_size(val),
				regval_data_p(val) );
	}

	return len;
}

/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.
 ***********************************************************************/

static int regdb_fetch_reg_values( const char* key, REGVAL_CTR *values )
{
	TDB_DATA data;
	pstring keystr;
	int len;

	DEBUG(10,("regdb_fetch_reg_values: Looking for value of key [%s] \n", key));
	
	pstr_sprintf( keystr, "%s/%s", VALUE_PREFIX, key );
	normalize_reg_path( keystr );
	
	data = tdb_fetch_bystring( tdb_reg, keystr );
	
	if ( !data.dptr ) {
		/* all keys have zero values by default */
		return 0;
	}
	
	len = regdb_unpack_values( values, data.dptr, data.dsize );
	
	SAFE_FREE( data.dptr );
	
	return regval_ctr_numvals(values);
}

/***********************************************************************
 Stub function since we do not currently support storing registry 
 values in the registry.tdb
 ***********************************************************************/

static BOOL regdb_store_reg_values( const char *key, REGVAL_CTR *values )
{
	TDB_DATA data;
	pstring keystr;
	int len, ret;
	
	DEBUG(10,("regdb_store_reg_values: Looking for value of key [%s] \n", key));
	
	ZERO_STRUCT( data );
	
	len = regdb_pack_values( values, data.dptr, data.dsize );
	if ( len <= 0 ) {
		DEBUG(0,("regdb_store_reg_values: unable to pack values. len <= 0\n"));
		return False;
	}
	
	data.dptr = SMB_MALLOC_ARRAY( char, len );
	data.dsize = len;
	
	len = regdb_pack_values( values, data.dptr, data.dsize );
	
	SMB_ASSERT( len == data.dsize );
	
	pstr_sprintf( keystr, "%s/%s", VALUE_PREFIX, key );
	normalize_reg_path( keystr );
	
	ret = tdb_store_bystring(tdb_reg, keystr, data, TDB_REPLACE);
	
	SAFE_FREE( data.dptr );
	
	return ret != -1 ;
}


/* 
 * Table of function pointers for default access
 */
 
REGISTRY_OPS regdb_ops = {
	regdb_fetch_reg_keys,
	regdb_fetch_reg_values,
	regdb_store_reg_keys,
	regdb_store_reg_values,
	NULL
};


