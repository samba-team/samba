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

/* Implementation of registry frontend view functions. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

extern REGISTRY_OPS printing_ops;

/* array of REGISTRY_HOOK's which are read into a tree for easy access */


REGISTRY_HOOK reg_hooks[] = {
  { KEY_PRINTING, &printing_ops },
  { NULL, NULL }
};


/***********************************************************************
 Open the registry database and initialize the REGISTRY_HOOK cache
 ***********************************************************************/
 
BOOL init_registry( void )
{
	int i;
	
	if ( !init_registry_db() ) {
		DEBUG(0,("init_registry: failed to initialize the registry tdb!\n"));
		return False;
	}
		
	/* build the cache tree of registry hooks */
	
	reghook_cache_init();
	
	for ( i=0; reg_hooks[i].keyname; i++ ) {
		if ( !reghook_cache_add(&reg_hooks[i]) )
			return False;
	}

	reghook_dump_cache(20);

	return True;
}




/***********************************************************************
 High level wrapper function for storing registry subkeys
 ***********************************************************************/
 
BOOL store_reg_keys( REGISTRY_KEY *key, char **subkeys, uint32 num_subkeys  )
{
	return regdb_store_reg_keys( key->name, subkeys, num_subkeys );

}

/***********************************************************************
 High level wrapper function for storing registry values
 ***********************************************************************/
 
BOOL store_reg_values( REGISTRY_KEY *key, REGISTRY_VALUE **val, uint32 num_values )
{
	return True;
}


/***********************************************************************
 High level wrapper function for enumerating registry subkeys
 ***********************************************************************/

int fetch_reg_keys( REGISTRY_KEY *key, char **subkeys )
{
	int num_subkeys;
	
	if ( key->hook && key->hook->ops && key->hook->ops->subkey_fn )
		num_subkeys = key->hook->ops->subkey_fn( key->name, subkeys );
	else 
		num_subkeys = regdb_fetch_reg_keys( key->name, subkeys );

	return num_subkeys;
}

/***********************************************************************
 High level wrapper function for retreiving a specific registry subkey
 given and index.
 ***********************************************************************/

BOOL fetch_reg_keys_specific( REGISTRY_KEY *key, char** subkey, uint32 key_index )
{
	BOOL result;
		
	if ( key->hook && key->hook->ops && key->hook->ops->subkey_specific_fn )
		result = key->hook->ops->subkey_specific_fn( key->name, subkey, key_index );
	else
		result = regdb_fetch_reg_keys_specific( key->name, subkey, key_index );
	
	return result;
}


/***********************************************************************
 High level wrapper function for enumerating registry values
 ***********************************************************************/

int fetch_reg_values( REGISTRY_KEY *key, REGISTRY_VALUE **val )
{
	int num_values;
	
	if ( key->hook && key->hook->ops && key->hook->ops->value_fn )
		num_values = key->hook->ops->value_fn( key->name, val );
	else 
		num_values = regdb_fetch_reg_values( key->name, val );
		
	return num_values;
}


