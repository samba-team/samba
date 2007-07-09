/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
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

/* Implementation of registry frontend view functions. */

/* Legacy registry frontend functions only used in
 * rpc_server/srv_winreg_nt.c anymore. */

#include <includes.h>

/***********************************************************************
 retreive a specific subkey specified by index.  Caller is 
 responsible for freeing memory
 ***********************************************************************/

BOOL fetch_reg_keys_specific( REGISTRY_KEY *key, char** subkey, uint32 key_index )
{
	static REGSUBKEY_CTR *ctr = NULL;
	static pstring save_path;
	char *s;
	
	*subkey = NULL;
	
	/* simple caching for performance; very basic heuristic */

	DEBUG(8,("fetch_reg_keys_specific: Looking for key [%d] of  [%s]\n", key_index, key->name));
	
	if ( !ctr ) {
		DEBUG(8,("fetch_reg_keys_specific: Initializing cache of subkeys for [%s]\n", key->name));

		if ( !(ctr = TALLOC_ZERO_P( NULL, REGSUBKEY_CTR )) ) {
			DEBUG(0,("fetch_reg_keys_specific: talloc() failed!\n"));
			return False;
		}
		
		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_keys( key, ctr) == -1 )
			return False;
			
	}
	/* clear the cache when key_index == 0 or the path has changed */
	else if ( !key_index || StrCaseCmp( save_path, key->name) ) {

		DEBUG(8,("fetch_reg_keys_specific: Updating cache of subkeys for [%s]\n", key->name));
		
		TALLOC_FREE( ctr );

		if ( !(ctr = TALLOC_ZERO_P( NULL, REGSUBKEY_CTR )) ) {
			DEBUG(0,("fetch_reg_keys_specific: talloc() failed!\n"));
			return False;
		}
		
		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_keys( key, ctr) == -1 )
			return False;
	}
	
	if ( !(s = regsubkey_ctr_specific_key( ctr, key_index )) )
		return False;

	*subkey = SMB_STRDUP( s );

	return True;
}

/***********************************************************************
 retreive a specific subkey specified by index.  Caller is 
 responsible for freeing memory
 ***********************************************************************/

BOOL fetch_reg_values_specific( REGISTRY_KEY *key, REGISTRY_VALUE **val, uint32 val_index )
{
	static REGVAL_CTR 	*ctr = NULL;
	static pstring		save_path;
	REGISTRY_VALUE		*v;
	
	*val = NULL;
	
	/* simple caching for performance; very basic heuristic */
	
	if ( !ctr ) {
		DEBUG(8,("fetch_reg_values_specific: Initializing cache of values for [%s]\n", key->name));

		if ( !(ctr = TALLOC_ZERO_P( NULL, REGVAL_CTR )) ) {
			DEBUG(0,("fetch_reg_values_specific: talloc() failed!\n"));
			return False;
		}

		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_values( key, ctr) == -1 )
			return False;
	}
	/* clear the cache when val_index == 0 or the path has changed */
	else if ( !val_index || !strequal(save_path, key->name) ) {

		DEBUG(8,("fetch_reg_values_specific: Updating cache of values for [%s]\n", key->name));		
		
		TALLOC_FREE( ctr );

		if ( !(ctr = TALLOC_ZERO_P( NULL, REGVAL_CTR )) ) {
			DEBUG(0,("fetch_reg_values_specific: talloc() failed!\n"));
			return False;
		}

		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_values( key, ctr) == -1 )
			return False;
	}
	
	if ( !(v = regval_ctr_specific_value( ctr, val_index )) )
		return False;

	*val = dup_registry_value( v );

	return True;
}
