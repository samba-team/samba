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
extern REGISTRY_OPS regdb_ops;		/* these are the default */

/* array of REGISTRY_HOOK's which are read into a tree for easy access */


REGISTRY_HOOK reg_hooks[] = {
  { KEY_PRINTING,   &printing_ops },
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

	if ( DEBUGLEVEL >= 20 )
		reghook_dump_cache(20);

	return True;
}




/***********************************************************************
 High level wrapper function for storing registry subkeys
 ***********************************************************************/
 
BOOL store_reg_keys( REGISTRY_KEY *key, REGSUBKEY_CTR *subkeys )
{
	if ( key->hook && key->hook->ops && key->hook->ops->store_subkeys_fn )
		return key->hook->ops->store_subkeys_fn( key->name, subkeys );
	else
		return False;

}

/***********************************************************************
 High level wrapper function for storing registry values
 ***********************************************************************/
 
BOOL store_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	if ( key->hook && key->hook->ops && key->hook->ops->store_values_fn )
		return key->hook->ops->store_values_fn( key->name, val );
	else
		return False;
}


/***********************************************************************
 High level wrapper function for enumerating registry subkeys
 Initialize the TALLOC_CTX if necessary
 ***********************************************************************/

int fetch_reg_keys( REGISTRY_KEY *key, REGSUBKEY_CTR *subkey_ctr )
{
	int result = -1;
	
	if ( key->hook && key->hook->ops && key->hook->ops->subkey_fn )
		result = key->hook->ops->subkey_fn( key->name, subkey_ctr );

	return result;
}

/***********************************************************************
 retreive a specific subkey specified by index.  Caller is 
 responsible for freeing memory
 ***********************************************************************/

BOOL fetch_reg_keys_specific( REGISTRY_KEY *key, char** subkey, uint32 key_index )
{
	static REGSUBKEY_CTR ctr;
	static pstring save_path;
	static BOOL ctr_init = False;
	char *s;
	
	*subkey = NULL;
	
	/* simple caching for performance; very basic heuristic */
	
	if ( !ctr_init ) {
		DEBUG(8,("fetch_reg_keys_specific: Initializing cache of subkeys for [%s]\n", key->name));
		ZERO_STRUCTP( &ctr );	
		regsubkey_ctr_init( &ctr );
		
		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_keys( key, &ctr) == -1 )
			return False;
			
		ctr_init = True;
	}
	/* clear the cache when key_index == 0 or the path has changed */
	else if ( !key_index || StrCaseCmp( save_path, key->name) ) {

		DEBUG(8,("fetch_reg_keys_specific: Updating cache of subkeys for [%s]\n", key->name));
		
		regsubkey_ctr_destroy( &ctr );	
		regsubkey_ctr_init( &ctr );
		
		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_keys( key, &ctr) == -1 )
			return False;
	}
	
	if ( !(s = regsubkey_ctr_specific_key( &ctr, key_index )) )
		return False;

	*subkey = strdup( s );

	return True;
}


/***********************************************************************
 High level wrapper function for enumerating registry values
 Initialize the TALLOC_CTX if necessary
 ***********************************************************************/

int fetch_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	int result = -1;
	
	if ( key->hook && key->hook->ops && key->hook->ops->value_fn )
		result = key->hook->ops->value_fn( key->name, val );

	return result;
}


/***********************************************************************
 retreive a specific subkey specified by index.  Caller is 
 responsible for freeing memory
 ***********************************************************************/

BOOL fetch_reg_values_specific( REGISTRY_KEY *key, REGISTRY_VALUE **val, uint32 val_index )
{
	static REGVAL_CTR 	ctr;
	static pstring		save_path;
	static BOOL		ctr_init = False;
	REGISTRY_VALUE		*v;
	
	*val = NULL;
	
	/* simple caching for performance; very basic heuristic */
	
	if ( !ctr_init ) {
		DEBUG(8,("fetch_reg_values_specific: Initializing cache of values for [%s]\n", key->name));

		ZERO_STRUCTP( &ctr );	
		regval_ctr_init( &ctr );
		
		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_values( key, &ctr) == -1 )
			return False;
			
		ctr_init = True;
	}
	/* clear the cache when val_index == 0 or the path has changed */
	else if ( !val_index || StrCaseCmp(save_path, key->name) ) {

		DEBUG(8,("fetch_reg_values_specific: Updating cache of values for [%s]\n", key->name));		
		
		regval_ctr_destroy( &ctr );	
		regval_ctr_init( &ctr );
		
		pstrcpy( save_path, key->name );
		
		if ( fetch_reg_values( key, &ctr) == -1 )
			return False;
	}
	
	if ( !(v = regval_ctr_specific_value( &ctr, val_index )) )
		return False;

	*val = dup_registry_value( v );

	return True;
}

/***********************************************************************
 Utility function for splitting the base path of a registry path off
 by setting base and new_path to the apprapriate offsets withing the
 path.
 
 WARNING!!  Does modify the original string!
 ***********************************************************************/

BOOL reg_split_path( char *path, char **base, char **new_path )
{
	char *p;
	
	*new_path = *base = NULL;
	
	if ( !path)
		return False;
	
	*base = path;
	
	p = strchr( path, '\\' );
	
	if ( p ) {
		*p = '\0';
		*new_path = p+1;
	}
	
	return True;
}



