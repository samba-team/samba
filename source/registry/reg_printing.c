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
	uint16 key_len = strlen(KEY_PRINTING);
	
	/* 
	 * sanity check...this really should never be True.
	 * It is only here to prevent us from accessing outside
	 * the path buffer in the extreme case.
	 */
	
	if ( strlen(path) < key_len ) {
		DEBUG(0,("trim_reg_path: Registry path too short! [%s]\n", path));
		DEBUG(0,("trim_reg_path: KEY_PRINTING => [%s]!\n", KEY_PRINTING));
		return NULL;
	}
	
	
	p = path + strlen(KEY_PRINTING);
	
	if ( *p == '\\' )
		p++;
	
	if ( *p )
		return strdup(p);
	else
		return NULL;
}

/**********************************************************************
 handle enumeration of subkeys below KEY_PRINTING\Environments
 *********************************************************************/
 
static int print_subpath_environments( char *key, REGSUBKEY_CTR *subkeys, int32 idx )
{
	DEBUG(10,("print_subpath_environments: key=>[%s]\n", key ? key : "NULL" ));
	
	if ( !key )
	{
		/* listed architectures of installed drivers */
		
	}
	
	
	return 0;
}

/**********************************************************************
 handle enumeration of subkeys below KEY_PRINTING\Forms
 *********************************************************************/
 
static int print_subpath_forms( char *key, REGSUBKEY_CTR *subkeys, int32 idx )
{
	DEBUG(10,("print_subpath_forms: key=>[%s]\n", key ? key : "NULL" ));
	
	return 0;
}

/**********************************************************************
 handle enumeration of values below KEY_PRINTING\Forms
 *********************************************************************/
 
static int print_values_forms( char *key, REGVAL_CTR *val, int idx )
{
	int num_values = 0;
	
	DEBUG(10,("print_values_forms: key=>[%s]\n", key ? key : "NULL" ));
	
	/* handle ..\Forms\ */
	
#if 0	/* JERRY */
	if ( !key )
	{
		nt_forms_struct *forms = NULL;
		int i;
		
		if ( (num_values = get_ntforms( &forms )) == 0 )
			return 0;
		
		if ( !(*values = malloc(sizeof(REGISTRY_VALUE) * num_values)) ) {
			DEBUG(0,("print_values_forms: Failed to malloc memory for [%d] REGISTRY_VALUE structs!\n",
				num_values));
			return -1;
		}
		
		for ( i=0; i<num_values; i++ )
		{
			
		
		}
	}
#endif
	
	return num_values;
}

/**********************************************************************
 handle enumeration of subkeys below KEY_PRINTING\Printers
 *********************************************************************/
 
static int print_subpath_printers( char *key, REGSUBKEY_CTR *subkeys, int32 idx )
{
	DEBUG(10,("print_subpath_printers: key=>[%s]\n", key ? key : "NULL" ));
	
	return 0;
}

/**********************************************************************
 Routine to handle enumeration of subkeys and values 
 below KEY_PRINTING (depending on whether or not subkeys/val are 
 valid pointers. 
 *********************************************************************/
 
static int handle_printing_subpath( char *key, REGSUBKEY_CTR *subkeys,
                                    REGVAL_CTR *val, int32 key_index, int32 val_index )
{
	int result = 0;
	char *p, *base;
	int i;
	
	DEBUG(10,("handle_printing_subpath: key=>[%s], key_index == [%d], val_index == [%d]\n",
		key, key_index, val_index));	
	
	/* 
	 * break off the first part of the path 
	 * topmost base **must** be one of the strings 
	 * in top_level_keys[]
	 */
	
	reg_split_path( key, &base, &p);
		
	for ( i=0; i<MAX_TOP_LEVEL_KEYS; i++ ) {
		if ( StrCaseCmp( top_level_keys[i], base ) == 0 )
			break;
	}
	
	DEBUG(10,("handle_printing_subpath: base=>[%s], i==[%d]\n", base, i));	
		
	if ( (key_index != -1) && !(i < MAX_TOP_LEVEL_KEYS) )
		return -1;
			
	/* Call routine to handle each top level key */
	switch ( i )
	{
		case KEY_INDEX_ENVIR:
			if ( subkeys )
				print_subpath_environments( p, subkeys, key_index );
#if 0	/* JERRY */
			if ( val )
				print_subpath_values_environments( p, val, val_index );
#endif
			break;
		
		case KEY_INDEX_FORMS:
			result = print_subpath_forms( p, subkeys, key_index );
			break;
			
		case KEY_INDEX_PRINTER:
			result = print_subpath_printers( p, subkeys, key_index );
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
 
int printing_subkey_info( char *key, REGSUBKEY_CTR *subkey_ctr )
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
		for ( num_subkeys=0; num_subkeys<MAX_TOP_LEVEL_KEYS; num_subkeys++ )
			regsubkey_ctr_addkey( subkey_ctr, top_level_keys[num_subkeys] );
	}
	else
		num_subkeys = handle_printing_subpath( path, subkey_ctr, NULL, -1, -1 );
	
	SAFE_FREE( path );
	
	return num_subkeys;
}

/**********************************************************************
 Enumerate registry values given a registry path.  
 Caller is responsible for freeing memory 
 *********************************************************************/

int printing_value_info( char *key, REGVAL_CTR *val )
{
	char 		*path;
	BOOL		top_level = False;
	int		num_values = 0;
	
	DEBUG(10,("printing_value_info: key=>[%s]\n", key));
	
	path = trim_reg_path( key );
	
	/* check to see if we are dealing with the top level key */
	
	if ( !path )
		top_level = True;
	
	/* fill in values from the getprinterdata_printer_server() */
	if ( top_level )
	{
		num_values = 0;
	}
	else
		num_values = handle_printing_subpath( path, NULL, val, -1, -1 );
		
	
	return num_values;
}

/**********************************************************************
 Stub function which always returns failure since we don't want
 people storing printing information directly via regostry calls
 (for now at least)
 *********************************************************************/

BOOL printing_store_subkey( char *key, REGSUBKEY_CTR *subkeys )
{
	return False;
}

/**********************************************************************
 Stub function which always returns failure since we don't want
 people storing printing information directly via regostry calls
 (for now at least)
 *********************************************************************/

BOOL printing_store_value( char *key, REGVAL_CTR *val )
{
	return False;
}

/* 
 * Table of function pointers for accessing printing data
 */
 
REGISTRY_OPS printing_ops = {
	printing_subkey_info,
	printing_value_info,
	printing_store_subkey,
	printing_store_value
};


