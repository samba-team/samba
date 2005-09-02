/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Gerald (Jerry) Carter      2005.
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
 
#include "includes.h"


/**********************************************************************
 Enumerate registry subkey names given a registry path.  
*********************************************************************/

static int elog_fetch_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	const char    **elogs = lp_eventlog_list();
	char          *path;
	int           i;
    
	path = reg_remaining_path( key + strlen(KEY_EVENTLOG) );
	
	DEBUG(10,("elog_fetch_keys: entire key => [%s], subkey => [%s]\n", 
		key, path));
    
	if ( !path ) { 
		
		if ( !elogs || !*elogs ) 
			return 0;

		DEBUG(10,("elog_fetch_keys: Adding eventlog subkeys from smb.conf\n"));	
		
		for ( i=0; elogs[i]; i++ ) 
			regsubkey_ctr_addkey( subkeys, elogs[i] );

		return regsubkey_ctr_numkeys( subkeys );
	} 
	
	/* if we get <logname>/<logname> then we don't add anymore */

 	if ( strchr( path, '\\' ) ) {
 		DEBUG(10,("elog_fetch_keys: Not adding subkey to %s\n",path));	
 		return 0;
 	}

	/* add in a subkey with the same name as the eventlog... */

	DEBUG(10,("elog_fetch_keys: Looking to add eventlog subkey to %s\n",path));	

	/* look for a match */

	if ( !elogs )
		return -1; 

	for ( i=0; elogs[i]; i++ ) { 
		/* just verify that the keyname is a valid log name */
		if ( strequal( path, elogs[i] ) )
			return 0;
	}
	
	return -1;
}

/**********************************************************************
 Enumerate registry values given a registry path.  
 Caller is responsible for freeing memory 
*********************************************************************/

static int elog_fetch_values( const char *key, REGVAL_CTR *values )
{
	char 	*path;
	uint32  uiDisplayNameId, uiMaxSize, uiRetention;
	char    *base, *new_path;
	UNISTR2 data;
	
	DEBUG(10,("elog_fetch_values: key=>[%s]\n", key));
	
	path = reg_remaining_path( key + strlen(KEY_EVENTLOG) );
	
	/* check to see if we are dealing with the top level key */
	
	if ( !path ) 
		return regdb_fetch_values( KEY_EVENTLOG, values );
		
	/* deal with a log name */
    
	reg_split_path( path, &base, &new_path );
    	
	/* MaxSize is limited to 0xFFFF0000 (UINT_MAX - USHRT_MAX) as per MSDN documentation */
	
    
	if ( !new_path ) {
		
		/* try to fetch from the registry */
		
		regdb_fetch_values( key, values );

		/* just verify one of the important keys.  If this 
		   fails, then assume the values have not been initialized */
		
		if ( regval_ctr_getvalue( values, "Retention" ) )
			return regval_ctr_numvals( values );	

		/* hard code some initial values */
				
		uiDisplayNameId = 0x00000100;
		uiMaxSize       = 0x00080000;	
		uiRetention     = 0x93A80;
		
		regval_ctr_addvalue( values, "MaxSize", REG_DWORD, (char*)&uiMaxSize, sizeof(uint32));
		regval_ctr_addvalue( values, "Retention", REG_DWORD, (char *)&uiRetention, sizeof(uint32));
		
		init_unistr2( &data, base, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "PrimaryModule", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
		init_unistr2( &data, base, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Sources", REG_MULTI_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
		
		/* store them for later updates.  Complain if this fails but continue on */
		
		if ( !regdb_store_values( key, values ) ) {
			DEBUG(0,("elog_fetch_values: Failed to store initial values for log [%s]\n",
				base ));
		}
	
		return regval_ctr_numvals( values );	
	} 

#if 0
	/* hmmm....what to do here?  A subkey underneath the log name ? */

	uiDisplayNameId = 0x07;
	regval_ctr_addvalue( values, "CategoryCount",    REG_DWORD, (char*)&uiDisplayNameId,       sizeof(uint32) ); 
	
	init_unistr2( &data, "%SystemRoot%\\system32\\eventlog.dll", UNI_STR_TERMINATE);
	regval_ctr_addvalue( values, "CategoryMessageFile", REG_EXPAND_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
#endif
	
	return regval_ctr_numvals( values );
}

/**********************************************************************
*********************************************************************/

static BOOL elog_store_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	/* cannot create any subkeys here */
	
	return False;
}

/**********************************************************************
 Allow storing of particular values related to eventlog operation. 
*********************************************************************/

static BOOL elog_store_value( const char *key, REGVAL_CTR *values )
{
	/* the client had to have a valid handle to get here 
	   so just hand off to the registry tdb */
	
	return regdb_store_values( key, values );
}

/******************************************************************** 
 Table of function pointers for accessing eventlog data
 *******************************************************************/
 
REGISTRY_OPS eventlog_ops = {
	elog_fetch_keys,
	elog_fetch_values,
	elog_store_keys,
	elog_store_value,
	NULL
};
