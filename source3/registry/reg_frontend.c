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
	char **pp;
	
	if ( keyname )
	{
		len = strlen( keyname );

		/* allocate a space for the char* in the array */
		
		if (  ctr->subkeys == 0 )
			ctr->subkeys = talloc( ctr->ctx, sizeof(char*) );
		else {
			pp = talloc_realloc( ctr->ctx, ctr->subkeys, sizeof(char*)*(ctr->num_subkeys+1) );
			if ( pp )
				ctr->subkeys = pp;
		}

		/* allocate the string and save it in the array */
		
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

char* regsubkey_ctr_specific_key( REGSUBKEY_CTR *ctr, uint32 key_index )
{
	if ( ! (key_index < ctr->num_subkeys) )
		return NULL;
		
	return ctr->subkeys[key_index];
}

/***********************************************************************
 free memory held by a REGSUBKEY_CTR structure
 **********************************************************************/

void regsubkey_ctr_destroy( REGSUBKEY_CTR *ctr )
{
	if ( ctr ) {
		talloc_destroy( ctr->ctx );	
		ZERO_STRUCTP( ctr );
	}
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
 allocate memory for and duplicate a REGISTRY_VALUE.
 This is malloc'd memory so the caller should free it when done
 **********************************************************************/

REGISTRY_VALUE* dup_registry_value( REGISTRY_VALUE *val )
{
	REGISTRY_VALUE 	*copy = NULL;
	
	if ( !val )
		return NULL;
	
	if ( !(copy = malloc( sizeof(REGISTRY_VALUE) )) ) {
		DEBUG(0,("dup_registry_value: malloc() failed!\n"));
		return NULL;
	}
	
	/* copy all the non-pointer initial data */
	
	memcpy( copy, val, sizeof(REGISTRY_VALUE) );
	if ( val->data_p ) 
	{
		if ( !(copy->data_p = memdup( val->data_p, val->size )) ) {
			DEBUG(0,("dup_registry_value: memdup() failed for [%d] bytes!\n",
				val->size));
			SAFE_FREE( copy );
		}
	}
	
	return copy;	
}

/**********************************************************************
 free the memory allocated to a REGISTRY_VALUE 
 *********************************************************************/
 
void free_registry_value( REGISTRY_VALUE *val )
{
	if ( !val )
		return;
		
	SAFE_FREE( val->data_p );
	SAFE_FREE( val );
	
	return;
}

/**********************************************************************
 *********************************************************************/

uint8* regval_data_p( REGISTRY_VALUE *val )
{
	return val->data_p;
}

/**********************************************************************
 *********************************************************************/

int regval_size( REGISTRY_VALUE *val )
{
	return val->size;
}

/**********************************************************************
 *********************************************************************/

char* regval_name( REGISTRY_VALUE *val )
{
	return val->valuename;
}

/**********************************************************************
 *********************************************************************/

uint32 regval_type( REGISTRY_VALUE *val )
{
	return val->type;
}

/***********************************************************************
 Retreive a pointer to a specific value.  Caller shoud dup the structure
 since this memory may go away with a regval_ctr_destroy()
 **********************************************************************/

REGISTRY_VALUE* regval_ctr_specific_value( REGVAL_CTR *ctr, uint32 idx )
{
	if ( !(idx < ctr->num_values) )
		return NULL;
		
	return ctr->values[idx];
}

/***********************************************************************
 Retrive the TALLOC_CTX associated with a REGISTRY_VALUE 
 **********************************************************************/

TALLOC_CTX* regval_ctr_getctx( REGVAL_CTR *val )
{
	if ( !val )
		return NULL;

	return val->ctx;
}

/***********************************************************************
 Add a new registry value to the array
 **********************************************************************/

int regval_ctr_addvalue( REGVAL_CTR *ctr, char *name, uint16 type, 
                         char *data_p, size_t size )
{
	REGISTRY_VALUE **ppreg;
	
	if ( name )
	{
		/* allocate a slot in the array of pointers */
		
		if (  ctr->num_values == 0 )
			ctr->values = talloc( ctr->ctx, sizeof(REGISTRY_VALUE*) );
		else {
			ppreg = talloc_realloc( ctr->ctx, ctr->values, sizeof(REGISTRY_VALUE*)*(ctr->num_values+1) );
			if ( ppreg )
				ctr->values = ppreg;
		}

		/* allocate a new value and store the pointer in the arrya */
		
		ctr->values[ctr->num_values] = talloc( ctr->ctx, sizeof(REGISTRY_VALUE) );

		/* init the value */
	
		fstrcpy( ctr->values[ctr->num_values]->valuename, name );
		ctr->values[ctr->num_values]->type = type;
		ctr->values[ctr->num_values]->data_p = talloc_memdup( ctr->ctx, data_p, size );
		ctr->values[ctr->num_values]->size = size;
		ctr->num_values++;
	}

	return ctr->num_values;
}

/***********************************************************************
 Add a new registry value to the array
 **********************************************************************/

int regval_ctr_copyvalue( REGVAL_CTR *ctr, REGISTRY_VALUE *val )
{
	REGISTRY_VALUE **ppreg;
	
	if ( val )
	{
		/* allocate a slot in the array of pointers */
		
		if (  ctr->num_values == 0 )
			ctr->values = talloc( ctr->ctx, sizeof(REGISTRY_VALUE*) );
		else {
			ppreg = talloc_realloc( ctr->ctx, ctr->values, sizeof(REGISTRY_VALUE*)*(ctr->num_values+1) );
			if ( ppreg )
				ctr->values = ppreg;
		}

		/* allocate a new value and store the pointer in the arrya */
		
		ctr->values[ctr->num_values] = talloc( ctr->ctx, sizeof(REGISTRY_VALUE) );

		/* init the value */
	
		fstrcpy( ctr->values[ctr->num_values]->valuename, val->valuename );
		ctr->values[ctr->num_values]->type = val->type;
		ctr->values[ctr->num_values]->data_p = talloc_memdup( ctr->ctx, val->data_p, val->size );
		ctr->values[ctr->num_values]->size = val->size;
		ctr->num_values++;
	}

	return ctr->num_values;
}

/***********************************************************************
 Delete a single value from the registry container.
 No need to free memory since it is talloc'd.
 **********************************************************************/

int regval_ctr_delvalue( REGVAL_CTR *ctr, char *name )
{
	int 	i;
	
	/* search for the value */
	
	for ( i=0; i<ctr->num_values; i++ ) {
		if ( strcmp( ctr->values[i]->valuename, name ) == 0)
			break;
	}
	
	/* just return if we don't find it */
	
	if ( i == ctr->num_values )
		return ctr->num_values;
	
	/* just shift everything down one */
	
	for ( /* use previous i */; i<(ctr->num_values-1); i++ )
		memcpy( ctr->values[i], ctr->values[i+1], sizeof(REGISTRY_VALUE) );
		
	/* paranoia */
	
	ZERO_STRUCTP( ctr->values[i] );
	
	ctr->num_values--;
	
	return ctr->num_values;
}

/***********************************************************************
 Delete a single value from the registry container.
 No need to free memory since it is talloc'd.
 **********************************************************************/

REGISTRY_VALUE* regval_ctr_getvalue( REGVAL_CTR *ctr, char *name )
{
	int 	i;
	
	/* search for the value */
	
	for ( i=0; i<ctr->num_values; i++ ) {
		if ( strequal( ctr->values[i]->valuename, name ) )
			return ctr->values[i];
	}
	
	return NULL;
}

/***********************************************************************
 free memory held by a REGVAL_CTR structure
 **********************************************************************/

void regval_ctr_destroy( REGVAL_CTR *ctr )
{
	if ( ctr ) {
		talloc_destroy( ctr->ctx );
		ZERO_STRUCTP( ctr );
	}
}

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



