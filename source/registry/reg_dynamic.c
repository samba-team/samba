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
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Implementation of registry frontend view functions. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

struct reg_dyn_values {
	const char *path;
	int (*fetch_values) ( REGVAL_CTR *val );
};

/***********************************************************************
 Structure holding the registry paths and pointers to the value 
 enumeration functions
***********************************************************************/

static struct reg_dyn_values dynamic_values[] = {
	{ NULL, NULL }
};

/***********************************************************************
***********************************************************************/

int fetch_dynamic_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	int i;
	char *path = NULL;
	TALLOC_CTX *ctx = talloc_tos();

	path = talloc_strdup(ctx, key->name);
	if (!path) {
		return -1;
	}
	path = normalize_reg_path(ctx, path);
	if (!path) {
		return -1;
	}

	for ( i=0; dynamic_values[i].path; i++ ) {
		if ( strcmp( path, dynamic_values[i].path ) == 0 )
			return dynamic_values[i].fetch_values( val );
	}

	return -1;
}

/***********************************************************************
***********************************************************************/

bool check_dynamic_reg_values( REGISTRY_KEY *key )
{
	int i;
	char *path = NULL;
	TALLOC_CTX *ctx = talloc_tos();

	path = talloc_strdup(ctx, key->name);
	if (!path) {
		return false;
	}
	path = normalize_reg_path(ctx, path);
	if (!path) {
		return false;
	}

	for ( i=0; dynamic_values[i].path; i++ ) {
		/* can't write to dynamic keys */
		if ( strcmp( path, dynamic_values[i].path ) == 0 )
			return true;
	}

	return false;
}
