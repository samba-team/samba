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
	pstring keyname;
	char *subkeys[3];

	/* HKEY_LOCAL_MACHINE */
	
	pstrcpy( keyname, KEY_HKLM );
	subkeys[0] = "SYSTEM";
	if ( !regdb_store_reg_keys( keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM" );
	subkeys[0] = "CurrentControlSet";
	if ( !regdb_store_reg_keys( keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet" );
	subkeys[0] = "Control";
	subkeys[1] = "services";
	if ( !regdb_store_reg_keys( keyname, subkeys, 2 ))
		return False;

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control" );
	subkeys[0] = "Print";
	subkeys[1] = "ProduceOptions";
	if ( !regdb_store_reg_keys( keyname, subkeys, 2 ))
		return False;

#if 0	/* JERRY */
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control/Print" );
	subkeys[0] = "Environments";
	subkeys[1] = "Forms";
	subkeys[2] = "Printers";
	if ( !regdb_store_reg_keys( keyname, subkeys, 0 ))
		return False;
#endif

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control/ProductOptions" );
	if ( !regdb_store_reg_keys( keyname, subkeys, 0 ))
		return False;

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/services" );
	subkeys[0] = "Netlogon";
	if ( !regdb_store_reg_keys( keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/services/Netlogon" );
	subkeys[0] = "parameters";
	if ( !regdb_store_reg_keys( keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/services/Netlogon/parameters" );
	if ( !regdb_store_reg_keys( keyname, subkeys, 0 ))
		return False;

	
	/* HKEY_USER */
		
	pstrcpy( keyname, KEY_HKU );
	if ( !regdb_store_reg_keys( keyname, subkeys, 0 ) )
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
 \'s are converted to /'s.
 ***********************************************************************/
 
BOOL regdb_store_reg_keys( char *keyname, char **subkeys, uint32 num_subkeys  )
{
	TDB_DATA kbuf, dbuf;
	char *buffer, *tmpbuf;
	int i = 0;
	uint32 len, buflen;
	BOOL ret = True;
	
	if ( !keyname )
		return False;
	
	/* allocate some initial memory */
		
	buffer = malloc(sizeof(pstring));
	buflen = sizeof(pstring);
	len = 0;
	
	/* store the number of subkeys */
	
	len += tdb_pack(buffer+len, buflen-len, "d", num_subkeys);
	
	/* pack all the strings */
	
	for (i=0; i<num_subkeys; i++) {
		len += tdb_pack(buffer+len, buflen-len, "f", subkeys[i]);
		if ( len > buflen ) {
			/* allocate some extra space */
			if ((tmpbuf = Realloc( buffer, len*2 )) == NULL) {
				DEBUG(0,("store_reg_keys: Failed to realloc memory of size [%d]\n", len*2));
				ret = False;
				goto done;
			}
			buffer = tmpbuf;
			buflen = len*2;
					
			len = tdb_pack(buffer+len, buflen-len, "f", subkeys[i]);
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

int regdb_fetch_reg_keys( char* key, char **subkeys )
{
	pstring path;
	uint32 num_items;
	TDB_DATA dbuf;
	char *buf;
	uint32 buflen, len;
	int i;
	char *s;

	
	pstrcpy( path, key );
	
	/* convert to key format */
	pstring_sub( path, "\\", "/" );
	
	dbuf = tdb_fetch_by_string( tdb_reg, path );
	
	buf = dbuf.dptr;
	buflen = dbuf.dsize;
	
	if ( !buf ) {
		DEBUG(5,("fetch_reg_keys: Failed to fetch any subkeys for [%s]\n", key));
		return 0;
	}
	
	len = tdb_unpack( buf, buflen, "d", &num_items);
	if (num_items) {
		if ( (*subkeys = (char*)malloc(sizeof(fstring)*num_items)) == NULL ) {
			DEBUG(0,("fetch_reg_keys: Failed to malloc memory for subkey array containing [%d] items!\n",
				num_items));
			num_items = -1;
			goto done;
		}
	}
	
	s = *subkeys;
	for (i=0; i<num_items; i++) {
		len += tdb_unpack( buf+len, buflen-len, "f", s );
		s += strlen(s) + 1;
	}

done:	
	SAFE_FREE(dbuf.dptr);
	return num_items;
}

/***********************************************************************
 retreive a specific subkey specified by index.  The subkey parameter
 is assumed to be an fstring.
 ***********************************************************************/

BOOL regdb_fetch_reg_keys_specific( char* key, char** subkey, uint32 key_index )
{
	int num_subkeys, i;
	char *subkeys = NULL;
	char *s;
	
	num_subkeys = regdb_fetch_reg_keys( key, &subkeys );
	if ( num_subkeys == -1 )
		return False;

	s = subkeys;
	for ( i=0; i<num_subkeys; i++ ) {
		/* copy the key if the index matches */
		if ( i == key_index ) {
			*subkey = strdup( s );
			break;
		}
		
		/* go onto the next string */
		s += strlen(s) + 1;
	}
	
	SAFE_FREE(subkeys);
	
	return True;
}


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  The subkeys are stored in a catenated string
 of null terminated character strings
 ***********************************************************************/

int regdb_fetch_reg_values( char* key, REGISTRY_VALUE **val )
{
	return 0;
}

