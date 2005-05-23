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


static BOOL regdb_store_reg_keys( char *keyname, REGSUBKEY_CTR *ctr );
static int regdb_fetch_reg_keys( char* key, REGSUBKEY_CTR *ctr );



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
	
/***********************************************************************
 Open the registry data in the tdb
 ***********************************************************************/
 
static BOOL init_registry_data( void )
{
	pstring path, base, remaining;
	fstring keyname, subkeyname;
	REGSUBKEY_CTR	subkeys;
	int i;
	const char *p, *p2;
	
	ZERO_STRUCTP( &subkeys );
	
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

	/* placeholder tdb; reinit upon startup */
	
	tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT|TDB_CLEAR_IF_FIRST, O_RDWR, 0600);
	if ( !tdb_reg ) 
	{
		tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
		if ( !tdb_reg ) {
			DEBUG(0,("init_registry: Failed to open registry %s (%s)\n",
				lock_path("registry.tdb"), strerror(errno) ));
			return False;
		}
		
		DEBUG(10,("init_registry: Successfully created registry tdb\n"));
	}
		
	/* create the registry here */

	if ( !init_registry_data() ) {
		DEBUG(0,("init_registry: Failed to initiailize data in registry!\n"));
		return False;
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
 
static BOOL regdb_store_reg_keys( char *key, REGSUBKEY_CTR *ctr )
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
	
	/* convert to key format */
	
	pstring_sub( keyname, "\\", "/" ); 
	strupper_m( keyname  );
	
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
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  The subkeys are stored in a catenated string
 of null terminated character strings
 ***********************************************************************/

static int regdb_fetch_reg_keys( char* key, REGSUBKEY_CTR *ctr )
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

static int regdb_fetch_reg_values( char* key, REGVAL_CTR *val )
{
	UNISTR2 data;
	int    num_vals;
	char   *hname;
	fstring mydomainname;

	DEBUG(10,("regdb_fetch_reg_values: Looking for value of key [%s] \n", key));

	num_vals = 0;

	if ( strequal(key, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ) ) {
		DEBUG(10,("regdb_fetch_reg_values: Supplying SystemRoot \n"));
		init_unistr2( &data, "c:\\Windows", UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "SystemRoot",REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
		num_vals = 1;
	} else if ( strequal(key, "HKLM\\System\\CurrentControlSet\\Control\\ProductOptions" ) ) {
		DEBUG(10,("regdb_fetch_reg_values: Supplying ProductType \n"));
		init_unistr2( &data, "WinNT", UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "ProductType",REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
		num_vals = 1;
	} else if ( strequal(key, "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" ) ) {
		DEBUG(10,("regdb_fetch_reg_values: Supplying Hostname & Domain Name\n"));
		hname = SMB_STRDUP(myhostname());
		get_mydnsdomname(mydomainname);
		init_unistr2( &data, hname, UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "Hostname",REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
		init_unistr2( &data, mydomainname, UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "Domain",REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
		num_vals = 2;
	}



	return num_vals;
}

/***********************************************************************
 Stub function since we do not currently support storing registry 
 values in the registry.tdb
 ***********************************************************************/

static BOOL regdb_store_reg_values( char *key, REGVAL_CTR *val )
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


