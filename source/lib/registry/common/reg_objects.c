/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                     2002.
 *  Copyright (C) Jelmer Vernooij					2003-2004.
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
#include "lib/registry/common/registry.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/***********************************************************************
 allocate memory for and duplicate a REG_VAL.
 This is malloc'd memory so the caller should free it when done
 **********************************************************************/

REG_VAL* reg_val_dup( REG_VAL *val )
{
	REG_VAL 	*copy = NULL;
	
	if ( !val ) 
		return NULL;
	
	if ( !(copy = malloc( sizeof(REG_VAL) )) ) {
		DEBUG(0,("dup_registry_value: malloc() failed!\n"));
		return NULL;
	}
	
	/* copy all the non-pointer initial data */
	
	memcpy( copy, val, sizeof(REG_VAL) );
	if ( val->data_blk ) 
	{
		if ( !(copy->data_blk = memdup( val->data_blk, val->data_len )) ) {
			DEBUG(0,("dup_registry_value: memdup() failed for [%d] bytes!\n",
				val->data_len));
			SAFE_FREE( copy );
		}
	}
	
	return copy;	
}

/**********************************************************************
 free the memory allocated to a REG_VAL 
 *********************************************************************/
 
void reg_val_free( REG_VAL *val )
{
	if ( !val )
		return;

	if(val->handle->functions->free_val_backend_data)
		val->handle->functions->free_val_backend_data(val);
		
	SAFE_FREE( val->data_blk );
	SAFE_FREE( val );

	return;
}

/**********************************************************************
 *********************************************************************/

uint8* reg_val_data_blk( REG_VAL *val )
{
	return val->data_blk;
}

/**********************************************************************
 *********************************************************************/

int reg_val_size( REG_VAL *val )
{
	return val->data_len;
}

/**********************************************************************
 *********************************************************************/

char *reg_val_name( REG_VAL *val )
{
	return val->name;
}

/**********************************************************************
 *********************************************************************/

uint32 reg_val_type( REG_VAL *val )
{
	return val->data_type;
}

/**********************************************************************
 *********************************************************************/

char *reg_key_name( REG_KEY *key )
{
	return key->name;
}

REG_KEY *reg_key_dup(REG_KEY *key)
{
	key->ref++;
	return key;
}

void reg_key_free(REG_KEY *key)
{
	if(!key)
		return;
	
	key->ref--;
	if(key->ref) return;
	
	if(key->handle->functions->free_key_backend_data)
		key->handle->functions->free_key_backend_data(key);

	if(key->cache_values) {
		int i;
		for(i = 0; i < key->cache_values_count; i++) {
			reg_val_free(key->cache_values[i]);
		}
		SAFE_FREE(key->cache_values);
	}

	if(key->cache_subkeys) {
		int i;
		for(i = 0; i < key->cache_subkeys_count; i++) {
			reg_key_free(key->cache_subkeys[i]);
		}
		SAFE_FREE(key->cache_subkeys);
	}

	SAFE_FREE(key->path);
	SAFE_FREE(key->name);
	SAFE_FREE(key);
}

char *reg_val_get_path(REG_VAL *v)
{
	/* FIXME */
	return NULL;
}

const char *reg_key_get_path(REG_KEY *k)
{
	SMB_REG_ASSERT(k);
	return k->path;
}

/* For use by the backends _ONLY_ */
REG_KEY *reg_key_new_abs(const char *path, REG_HANDLE *h, void *data)
{
	REG_KEY *r = malloc(sizeof(REG_KEY));
	ZERO_STRUCTP(r);
	r->handle = h;
	r->path = strdup(path);
	r->name = strdup(strrchr(path, '\\')?strrchr(path,'\\')+1:path);
	r->backend_data = data;
	r->ref = 1;
	return r;
}

REG_KEY *reg_key_new_rel(const char *name, REG_KEY *k, void *data)
{
	REG_KEY *r = malloc(sizeof(REG_KEY));
	ZERO_STRUCTP(r);
	r->handle = k->handle;
	r->name = strdup(name);
	r->backend_data = data;
	r->ref = 1;
	return r;
}

REG_VAL *reg_val_new(REG_KEY *parent, void *data)
{
	REG_VAL *r = malloc(sizeof(REG_VAL));
	ZERO_STRUCTP(r);
	r->handle = parent->handle;
	r->backend_data = data;
	r->ref = 1;
	return r;
}
