/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002.
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
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Implementation of registry hook cache tree */

#include "includes.h"
#include "adt_tree.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

static SORTED_TREE *cache_tree = NULL;
extern REGISTRY_OPS regdb_ops;		/* these are the default */

/**********************************************************************
 Initialize the cache tree if it has not been initialized yet.
 *********************************************************************/

bool reghook_cache_init( void )
{
	if (cache_tree == NULL) {
		cache_tree = pathtree_init(&regdb_ops, NULL);
		if (cache_tree !=0) {
			DEBUG(10, ("reghook_cache_init: new tree with default "
				   "ops %p for key [%s]\n", (void *)&regdb_ops,
				   KEY_TREE_ROOT));
		}
	}

	return (cache_tree != NULL);
}

/**********************************************************************
 Add a new registry hook to the cache.  Note that the keyname
 is not in the exact format that a SORTED_TREE expects.
 *********************************************************************/

bool reghook_cache_add(const char *keyname, REGISTRY_OPS *ops)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *key = NULL;

	if ((keyname == NULL) || (ops == NULL)) {
		return false;
	}

	key = talloc_asprintf(ctx, "\\%s", keyname);
	if (!key) {
		return false;
	}
	key = talloc_string_sub(ctx, key, "\\", "/");
	if (!key) {
		return false;
	}

	DEBUG(10, ("reghook_cache_add: Adding ops %p for key [%s]\n",
		   (void *)ops, key));

	return pathtree_add(cache_tree, key, ops);
}

/**********************************************************************
 Initialize the cache tree
 *********************************************************************/

REGISTRY_OPS *reghook_cache_find(const char *keyname)
{
	char *key;
	int len;
	REGISTRY_OPS *ops;
	
	if ( !keyname )
		return NULL;
	
	/* prepend the string with a '\' character */
	
	len = strlen( keyname );
	if ( !(key = (char *)SMB_MALLOC( len + 2 )) ) {
		DEBUG(0,("reghook_cache_find: malloc failed for string [%s] !?!?!\n",
			keyname));
		return NULL;
	}

	*key = '\\';
	strncpy( key+1, keyname, len+1);
	
	/* swap to a form understood by the SORTED_TREE */

	string_sub( key, "\\", "/", 0 );
		
	DEBUG(10,("reghook_cache_find: Searching for keyname [%s]\n", key));
	
	ops = (REGISTRY_OPS *)pathtree_find(cache_tree, key);

	DEBUG(10, ("reghook_cache_find: found ops %p for key [%s]\n",
		   ops ? (void *)ops : 0, key));
	
	SAFE_FREE( key );
	
	return ops;
}

/**********************************************************************
 Initialize the cache tree
 *********************************************************************/

void reghook_dump_cache( int debuglevel )
{
	DEBUG(debuglevel,("reghook_dump_cache: Starting cache dump now...\n"));
	
	pathtree_print_keys( cache_tree, debuglevel );
}
