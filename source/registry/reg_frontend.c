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
  { KEY_TREE_ROOT,  &regdb_ops    },
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
	char *s;
	REGSUBKEY_CTR ctr;
	
	ZERO_STRUCTP( &ctr );
	
	regsubkey_ctr_init( &ctr );
	
	if ( fetch_reg_keys( key, &ctr) == -1 )
		return False;

	if ( !(s = regsubkey_ctr_specific_key( &ctr, key_index )) )
		return False;

	*subkey = strdup( s );

	regsubkey_ctr_destroy( &ctr ); 
	
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


/*
 * Utility functions for REGSUBKEY_CTR
 */

/***********************************************************************
 Init the talloc context held by a REGSUBKEY_CTR structure
 **********************************************************************/

void regsubkey_ctr_init( REGSUBKEY_CTR *ctr )
{
	if ( !ctr->ctx )
		ctr->ctx = talloc_init();
}

/***********************************************************************
 Add a new key to the array
 **********************************************************************/

int regsubkey_ctr_addkey( REGSUBKEY_CTR *ctr, char *keyname )
{
	uint32 len;
	
	if ( keyname )
	{
		len = strlen( keyname );

		if (  ctr->subkeys == 0 )
			ctr->subkeys = talloc( ctr->ctx, 1 );
		else
			talloc_realloc(	ctr->ctx, ctr->subkeys, ctr->num_subkeys+1 );

		ctr->subkeys[ctr->num_subkeys] = talloc( ctr->ctx, len+1 );
		strncpy( ctr->subkeys[ctr->num_subkeys], keyname, len+1 );
		ctr->num_subkeys++;
	}
	
	return ctr->num_subkeys;
}
 
/***********************************************************************
 How many keys does the container hold ?
 **********************************************************************/

int regsubkey_ctr_numkeys( REGSUBKEY_CTR *ctr )
{
	return ctr->num_subkeys;
}

/***********************************************************************
 Retreive a specific key string
 **********************************************************************/

char* regsubkey_ctr_specific_key( REGSUBKEY_CTR *ctr, uint32 index )
{
	if ( ! (index < ctr->num_subkeys) )
		return NULL;
		
	return ctr->subkeys[index];
}

/***********************************************************************
 free memory held by a REGSUBKEY_CTR structure
 **********************************************************************/

void regsubkey_ctr_destroy( REGSUBKEY_CTR *ctr )
{
	if ( ctr )
		talloc_destroy( ctr->ctx );
		
	ctr->num_subkeys  = 0;
	ctr->subkeys      = NULL;
}


/*
 * Utility functions for REGVAL_CTR
 */

/***********************************************************************
 Init the talloc context held by a REGSUBKEY_CTR structure
 **********************************************************************/

void regval_ctr_init( REGVAL_CTR *ctr )
{
	if ( !ctr->ctx )
		ctr->ctx = talloc_init();
}

/***********************************************************************
 How many keys does the container hold ?
 **********************************************************************/

int regval_ctr_numvals( REGVAL_CTR *ctr )
{
	return ctr->num_values;
}

/***********************************************************************
 free memory held by a REGVAL_CTR structure
 **********************************************************************/

void regval_ctr_destroy( REGVAL_CTR *ctr )
{
	if ( ctr )
		talloc_destroy( ctr->ctx );
		
	ctr->num_values  = 0;
	ctr->values      = NULL;
}

