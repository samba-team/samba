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

/* Implementation of registry hook cache tree */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static SORTED_TREE *cache_tree;

/**********************************************************************
 Initialize the cache tree
 *********************************************************************/

BOOL reghook_cache_init( void )
{
	cache_tree = sorted_tree_init( NULL, NULL );

	return ( cache_tree == NULL );
}

/**********************************************************************
 Add a new REGISTRY_HOOK to the cache.  Note that the keyname
 is not in the exact format that a SORTED_TREE expects.
 *********************************************************************/

BOOL reghook_cache_add( REGISTRY_HOOK *hook )
{
	pstring key;
	
	if ( !hook )
		return False;
		
	pstrcpy( key, "\\");
	pstrcat( key, hook->keyname );	
	
	pstring_sub( key, "\\", "/" );

	DEBUG(10,("reghook_cache_add: Adding key [%s]\n", key));
		
	return sorted_tree_add( cache_tree, key, hook );
}

/**********************************************************************
 Initialize the cache tree
 *********************************************************************/

REGISTRY_HOOK* reghook_cache_find( char *keyname )
{
	char *key;
	
	if ( !keyname )
		return NULL;
		
	if ( (key = strdup( keyname )) == NULL ) {
		DEBUG(0,("reghook_cache_find: strdup() failed for string [%s] !?!?!\n",
			keyname));
		return NULL;
	}
	
	string_sub( key, "\\", "/", 0 );
		
	DEBUG(10,("reghook_cache_find: Searching for keyname [%s]\n", key));
	
	return sorted_tree_find( cache_tree, key ) ;
}

/**********************************************************************
 Initialize the cache tree
 *********************************************************************/

void reghook_dump_cache( int debuglevel )
{
	DEBUG(debuglevel,("reghook_dump_cache: Starting cache dump now...\n"));
	
	sorted_tree_print_keys( cache_tree, debuglevel );
}
