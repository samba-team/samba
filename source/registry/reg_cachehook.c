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

static char *keyname_to_path(TALLOC_CTX *mem_ctx, const char *keyname)
{
	char *path = NULL;

	if ((keyname == NULL)) {
		return NULL;
	}

	path = talloc_asprintf(mem_ctx, "\\%s", keyname);
	if (path == NULL) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		return NULL;
	}

	path = talloc_string_sub(mem_ctx, path, "\\", "/");
	if (path == NULL) {
		DEBUG(0, ("talloc_string_sub_failed!\n"));
	}

	return path;
}

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
	bool ret;
	char *key = NULL;

	key = keyname_to_path(talloc_tos(), keyname);

	if ((key == NULL) || (ops == NULL)) {
		return false;
	}

	DEBUG(10, ("reghook_cache_add: Adding ops %p for key [%s]\n",
		   (void *)ops, key));

	ret = pathtree_add(cache_tree, key, ops);
	TALLOC_FREE(key);
	return ret;
}

/**********************************************************************
 Find a key in the cache.
 *********************************************************************/

REGISTRY_OPS *reghook_cache_find(const char *keyname)
{
	char *key;
	REGISTRY_OPS *ops;

	key = keyname_to_path(talloc_tos(), keyname);

	if (key == NULL) {
		return NULL;
	}

	DEBUG(10,("reghook_cache_find: Searching for keyname [%s]\n", key));

	ops = (REGISTRY_OPS *)pathtree_find(cache_tree, key);

	DEBUG(10, ("reghook_cache_find: found ops %p for key [%s]\n",
		   ops ? (void *)ops : 0, key));

	TALLOC_FREE(key);

	return ops;
}

/**********************************************************************
 Print out the cache tree structure for debugging.
 *********************************************************************/

void reghook_dump_cache( int debuglevel )
{
	DEBUG(debuglevel,("reghook_dump_cache: Starting cache dump now...\n"));

	pathtree_print_keys( cache_tree, debuglevel );
}
