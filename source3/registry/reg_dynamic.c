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
***********************************************************************/

static int perflib_params( REGVAL_CTR *regvals )
{
	int base_index = -1;
	int last_counter = -1;
	int last_help = -1;
	int version = 0x00010001;
	
	base_index = reg_perfcount_get_base_index();
	regval_ctr_addvalue(regvals, "Base Index", REG_DWORD, (char *)&base_index, sizeof(base_index));
	last_counter = reg_perfcount_get_last_counter(base_index);
	regval_ctr_addvalue(regvals, "Last Counter", REG_DWORD, (char *)&last_counter, sizeof(last_counter));
	last_help = reg_perfcount_get_last_help(last_counter);
	regval_ctr_addvalue(regvals, "Last Help", REG_DWORD, (char *)&last_help, sizeof(last_help));
	regval_ctr_addvalue(regvals, "Version", REG_DWORD, (char *)&version, sizeof(version));

	return regval_ctr_numvals( regvals );
}

/***********************************************************************
***********************************************************************/

static int perflib_009_params( REGVAL_CTR *regvals )
{
	int base_index;
	int buffer_size;
	char *buffer = NULL;

	base_index = reg_perfcount_get_base_index();
	buffer_size = reg_perfcount_get_counter_names(base_index, &buffer);
	regval_ctr_addvalue(regvals, "Counter", REG_MULTI_SZ, buffer, buffer_size);
	if(buffer_size > 0)
		SAFE_FREE(buffer);
	buffer_size = reg_perfcount_get_counter_help(base_index, &buffer);
	regval_ctr_addvalue(regvals, "Help", REG_MULTI_SZ, buffer, buffer_size);
	if(buffer_size > 0)
		SAFE_FREE(buffer);
	
	return regval_ctr_numvals( regvals );
}

/***********************************************************************
***********************************************************************/

static int hkpt_params( REGVAL_CTR *regvals )
{
	uint32 base_index;
	uint32 buffer_size;
	char *buffer = NULL;

	/* This is ALMOST the same as perflib_009_params, but HKPT has
	   a "Counters" entry instead of a "Counter" key. <Grrrr> */
	   
	base_index = reg_perfcount_get_base_index();
	buffer_size = reg_perfcount_get_counter_names(base_index, &buffer);
	regval_ctr_addvalue(regvals, "Counters", REG_MULTI_SZ, buffer, buffer_size);
	
	if(buffer_size > 0)
		SAFE_FREE(buffer);
		
	buffer_size = reg_perfcount_get_counter_help(base_index, &buffer);
	regval_ctr_addvalue(regvals, "Help", REG_MULTI_SZ, buffer, buffer_size);
	if(buffer_size > 0)
		SAFE_FREE(buffer);
	
	return regval_ctr_numvals( regvals );
}

/***********************************************************************
***********************************************************************/

static int current_version( REGVAL_CTR *values )
{
	const char *sysroot_string = "c:\\Windows";
	fstring sysversion;
	fstring value;
	uint32 value_length;
	
	value_length = push_ucs2( value, value, sysroot_string, sizeof(value), 
		STR_TERMINATE|STR_NOALIGN );
	regval_ctr_addvalue( values, "SystemRoot", REG_SZ, value, value_length );
	
	fstr_sprintf( sysversion, "%d.%d", lp_major_announce_version(), lp_minor_announce_version() );
	value_length = push_ucs2( value, value, sysversion, sizeof(value), 
		STR_TERMINATE|STR_NOALIGN );
	regval_ctr_addvalue( values, "CurrentVersion", REG_SZ, value, value_length );
	
		
	return regval_ctr_numvals( values );
}


/***********************************************************************
 Structure holding the registry paths and pointers to the value 
 enumeration functions
***********************************************************************/

static struct reg_dyn_values dynamic_values[] = {
	{ "HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION/PERFLIB",  &perflib_params   }, 
	{ "HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION/PERFLIB/009", &perflib_009_params }, 
	{ "HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION",          &current_version }, 
	{ "HKPT", &hkpt_params },
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
