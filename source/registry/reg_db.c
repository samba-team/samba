/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                     2002.
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


/***********************************************************************
 Open the registry data in the tdb
 ***********************************************************************/
 
static BOOL init_registry_data( void )
{
	pstring 	keyname;
	REGSUBKEY_CTR	subkeys;

	ZERO_STRUCTP( &subkeys );

	/* HKEY_LOCAL_MACHINE */
	
	regsubkey_ctr_init( &subkeys );
	pstrcpy( keyname, KEY_HKLM );
	regsubkey_ctr_addkey( &subkeys, "SYSTEM" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	regsubkey_ctr_destroy( &subkeys );
		
	regsubkey_ctr_init( &subkeys );
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM" );
	regsubkey_ctr_addkey( &subkeys, "CurrentControlSet" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	regsubkey_ctr_destroy( &subkeys );
		
	regsubkey_ctr_init( &subkeys );
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet" );
	regsubkey_ctr_addkey( &subkeys, "Control" );
	regsubkey_ctr_addkey( &subkeys, "Services" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	regsubkey_ctr_destroy( &subkeys );

	regsubkey_ctr_init( &subkeys );
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control" );
	regsubkey_ctr_addkey( &subkeys, "Print" );
	regsubkey_ctr_addkey( &subkeys, "ProductOptions" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	regsubkey_ctr_destroy( &subkeys );

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control/ProductOptions" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;

	regsubkey_ctr_init( &subkeys );
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Services" );
	regsubkey_ctr_addkey( &subkeys, "Netlogon" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	regsubkey_ctr_destroy( &subkeys );
		
	regsubkey_ctr_init( &subkeys );
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Services/Netlogon" );
	regsubkey_ctr_addkey( &subkeys, "Parameters" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	regsubkey_ctr_destroy( &subkeys );
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Services/Netlogon/Parameters" );
	if ( !regdb_store_reg_keys( keyname, &subkeys ))
		return False;
	
	/* HKEY_USER */
		
	pstrcpy( keyname, KEY_HKU );
	if ( !regdb_store_reg_keys( keyname, &subkeys ) )
		return False;
		
	/* HKEY_CLASSES_ROOT*/
		
	pstrcpy( keyname, KEY_HKCR );
	if ( !regdb_store_reg_keys( keyname, &subkeys ) )
		return False;
		
	return True;
}

/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
BOOL init_registry_db( void )
{
	static pid_t local_pid;

	if (tdb_reg && local_pid == sys_getpid())
		return True;

	/* 
	 * try to open first without creating so we can determine
	 * if we need to init the data in the registry
	 */
	
	tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR, 0600);
	if ( !tdb_reg ) 
	{
		tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
		if ( !tdb_reg ) {
			DEBUG(0,("init_registry: Failed to open registry %s (%s)\n",
				lock_path("registry.tdb"), strerror(errno) ));
			return False;
		}
		
		DEBUG(10,("init_registry: Successfully created registry tdb\n"));
		
		/* create the registry here */
		if ( !init_registry_data() ) {
			DEBUG(0,("init_registry: Failed to initiailize data in registry!\n"));
			return False;
		}
	}

	local_pid = sys_getpid();
		
	return True;
}



/***********************************************************************
 Add subkey strings to the registry tdb under a defined key
 fmt is the same format as tdb_pack except this function only supports
 fstrings

 The full path to the registry key is used as database after the 
 \'s are converted to /'s.  Key string is also normalized to UPPER
 case.
 ***********************************************************************/
 
BOOL regdb_store_reg_keys( char *keyname, REGSUBKEY_CTR *ctr )
{
	TDB_DATA kbuf, dbuf;
	char *buffer, *tmpbuf;
	int i = 0;
	uint32 len, buflen;
	BOOL ret = True;
	uint32 num_subkeys = regsubkey_ctr_numkeys( ctr );
	
	if ( !keyname )
		return False;
	
	strupper_m( keyname  );
	
	/* allocate some initial memory */
		
	buffer = malloc(sizeof(pstring));
	buflen = sizeof(pstring);
	len = 0;
	
	/* store the number of subkeys */
	
	len += tdb_pack(buffer+len, buflen-len, "d", num_subkeys );
	
	/* pack all the strings */
	
	for (i=0; i<num_subkeys; i++) {
		len += tdb_pack( buffer+len, buflen-len, "f", regsubkey_ctr_specific_key(ctr, i) );
		if ( len > buflen ) {
			/* allocate some extra space */
			if ((tmpbuf = Realloc( buffer, len*2 )) == NULL) {
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
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  The subkeys are stored in a catenated string
 of null terminated character strings
 ***********************************************************************/

int regdb_fetch_reg_keys( char* key, REGSUBKEY_CTR *ctr )
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


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  The subkeys are stored in a catenated string
 of null terminated character strings
 ***********************************************************************/

int regdb_fetch_reg_values( char* key, REGVAL_CTR *val )
{
	return 0;
}

/***********************************************************************
 Stub function since we do not currently support storing registry 
 values in the registry.tdb
 ***********************************************************************/

BOOL regdb_store_reg_values( char *key, REGVAL_CTR *val )
{
	return False;
}


/* 
 * Table of function pointers for default access
 */
 
REGISTRY_OPS regdb_ops = {
	regdb_fetch_reg_keys,
	regdb_fetch_reg_values,
	regdb_store_reg_keys,
	regdb_store_reg_values
};


