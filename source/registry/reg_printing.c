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

/* Implementation of registry virtual views for printing information */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define MAX_TOP_LEVEL_KEYS	3

/* some symbolic indexes into the top_level_keys */

#define KEY_INDEX_ENVIR		0
#define KEY_INDEX_FORMS		1
#define KEY_INDEX_PRINTER	2

static char *top_level_keys[MAX_TOP_LEVEL_KEYS] = { 
	"Environments", 
	"Forms",
	"Printers" 
};

/**********************************************************************
 It is safe to assume that every registry path passed into on of 
 the exported functions here begins with KEY_PRINTING else
 these functions would have never been called.  This is a small utility
 function to strip the beginning of the path and make a copy that the 
 caller can modify.  Note that the caller is responsible for releasing
 the memory allocated here.
 **********************************************************************/

static char* trim_reg_path( char *path )
{
	char *p;
	
	p = path + strlen(KEY_PRINTING);
	
	if ( *p )
		return strdup(p);
	else
		return NULL;
}

/**********************************************************************
 handle enumeration of subkeys below KEY_PRINTING.
 *********************************************************************/
 
static int handle_printing_subpath( char *key, char **subkeys, uint32 index )
{
	int result = 0;
	char *p, *base;
	int i;
		
	
	/* 
	 * break off the first part of the path 
	 * topmost base **must** be one of the strings 
	 * in top_level_keys[]
	 */
	
	base = key;
	p = strchr( key, '\\' );
	if ( p )
		*p = '\0';
		
	for ( i=0; i<MAX_TOP_LEVEL_KEYS; i++ ) {
		if ( StrCaseCmp( top_level_keys[i], base ) == 0 )
			break;
	}
	
	if ( !(i < MAX_TOP_LEVEL_KEYS) )
		return -1;
	
	/* Call routine to handle each top level key */
	switch ( i )
	{
		case KEY_INDEX_ENVIR:
			break;
		
		case KEY_INDEX_FORMS:
			break;
			
		case KEY_INDEX_PRINTER:
			break;
	
		/* default case for top level key that has no handler */
		
		default:
			break;
	}
	
	
	
	return result;

}
/**********************************************************************
 Enumerate registry subkey names given a registry path.  
 Caller is responsible for freeing memory to **subkeys
 *********************************************************************/
 
int printing_subkey_info( char *key, char **subkeys )
{
	char 		*path;
	BOOL		top_level = False;
	int		num_subkeys = 0;
	
	DEBUG(10,("printing_subkey_info: key=>[%s]\n", key));
	
	path = trim_reg_path( key );
	
	/* check to see if we are dealing with the top level key */
	
	if ( !path )
		top_level = True;
		
	if ( top_level ) {
		if ( ! (*subkeys = malloc( sizeof(top_level_keys) )) )
			goto done;
			
		num_subkeys = MAX_TOP_LEVEL_KEYS;
		memcpy( *subkeys, top_level_keys, sizeof(top_level_keys) );
	}
	else
		num_subkeys = handle_printing_subpath( path, subkeys, -1 );
	
done:
	SAFE_FREE( path );
	return num_subkeys;
}

/**********************************************************************
 Count the registry subkey names given a registry path.  
 Caller is responsible for freeing memory to **subkey
 *********************************************************************/
 
BOOL printing_subkey_specific( char *key, char** subkey, uint32 indx )
{
	char 		*path;
	BOOL		top_level = False;
	BOOL		result = False;
	
	DEBUG(10,("printing_subkey_specific: key=>[%s], index=>[%d]\n", key, indx));
	
	path = trim_reg_path( key );
	
	/* check to see if we are dealing with the top level key */
	
	if ( !path )
		top_level = True;
	
	
		
	if ( top_level ) {
	
		/* make sure the index is in range */
		
		if ( !(indx < MAX_TOP_LEVEL_KEYS) )
			goto done;

		if ( !(*subkey = malloc( strlen(top_level_keys[indx])+1 )) )
			goto done;
			
		strncpy( *subkey, top_level_keys[indx], strlen(top_level_keys[indx])+1 );
		
		result = True;
	}
	else {
		if ( handle_printing_subpath( path, subkey, indx ) != -1 )
			result = True;
	}
	
done:
	SAFE_FREE( path );

	return result;
}

/**********************************************************************
 Enumerate registry values given a registry path.  
 Caller is responsible for freeing memory 
 *********************************************************************/

int printing_value_info( char *key, REGISTRY_VALUE **val )
{
	DEBUG(10,("printing_value_info: key=>[%s]\n", key));
	
	return 0;
}

/**********************************************************************
 Stub function which always returns failure since we don't want
 people storing printing information directly via regostry calls
 (for now at least)
 *********************************************************************/

BOOL printing_store_subkey( char *key, char **subkeys, uint32 num_subkeys )
{
	return False;
}

/**********************************************************************
 Stub function which always returns failure since we don't want
 people storing printing information directly via regostry calls
 (for now at least)
 *********************************************************************/

BOOL printing_store_value( char *key, REGISTRY_VALUE **val, uint32 num_values )
{
	return False;
}

/* 
 * Table of function pointers for accessing printing data
 */
 
REGISTRY_OPS printing_ops = {
	printing_subkey_info,
	printing_subkey_specific,
	printing_value_info,
	printing_store_subkey,
	printing_store_value
};

