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
	
	
	p = path + strlen( KEY_PRINTING );
	
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
 
static int print_subpath_environments( char *key, REGSUBKEY_CTR *subkeys )
{
	char *environments[] = {
		"Windows 4.0",
		"Windows NT x86",
		"Windows NT R4000",
		"Windows NT Alpha_AXP",
		"Windows NT PowerPC",
		NULL };
	fstring *drivers = NULL;
	int i, env_index, num_drivers;
	BOOL valid_env = False;
	char *base, *new_path;
	char *keystr;
	char *key2 = NULL;
	int num_subkeys = -1;

	DEBUG(10,("print_subpath_environments: key=>[%s]\n", key ? key : "NULL" ));
	
	/* listed architectures of installed drivers */
	
	if ( !key ) 
	{
		/* Windows 9x drivers */
		
		if ( get_ntdrivers( &drivers, environments[0], 0 ) )
			regsubkey_ctr_addkey( subkeys, 	environments[0] );
		SAFE_FREE( drivers );
					
		/* Windows NT/2k intel drivers */
		
		if ( get_ntdrivers( &drivers, environments[1], 2 ) 
			|| get_ntdrivers( &drivers, environments[1], 3 ) )
		{
			regsubkey_ctr_addkey( subkeys, 	environments[1] );
		}
		SAFE_FREE( drivers );
		
		/* Windows NT 4.0; non-intel drivers */
		for ( i=2; environments[i]; i++ ) {
			if ( get_ntdrivers( &drivers, environments[i], 2 ) )
				regsubkey_ctr_addkey( subkeys, 	environments[i] );
		
		}
		SAFE_FREE( drivers );

		num_subkeys = regsubkey_ctr_numkeys( subkeys );	
		goto done;
	}
	
	/* we are dealing with a subkey of "Environments */
	
	key2 = strdup( key );
	keystr = key2;
	reg_split_path( keystr, &base, &new_path );
	
	/* sanity check */
	
	for ( env_index=0; environments[env_index]; env_index++ ) {
		if ( StrCaseCmp( environments[env_index], base ) == 0 ) {
			valid_env = True;
			break;
		}
	}
		
	if ( !valid_env )
		return -1;

	/* enumerate driver versions; environment is environments[env_index] */
	
	if ( !new_path ) {
		switch ( env_index ) {
			case 0:	/* Win9x */
				if ( get_ntdrivers( &drivers, environments[0], 0 ) ) {
					regsubkey_ctr_addkey( subkeys, "0" );
					SAFE_FREE( drivers );
				}
				break;
			case 1: /* Windows NT/2k - intel */
				if ( get_ntdrivers( &drivers, environments[1], 2 ) ) {
					regsubkey_ctr_addkey( subkeys, "2" );
					SAFE_FREE( drivers );
				}
				if ( get_ntdrivers( &drivers, environments[1], 3 ) ) {
					regsubkey_ctr_addkey( subkeys, "3" );
					SAFE_FREE( drivers );
				}
				break;
			default: /* Windows NT - nonintel */
				if ( get_ntdrivers( &drivers, environments[env_index], 2 ) ) {
					regsubkey_ctr_addkey( subkeys, "2" );
					SAFE_FREE( drivers );
				}
			
		}
		
		num_subkeys = regsubkey_ctr_numkeys( subkeys );	
		goto done;
	}
	
	/* we finally get to enumerate the drivers */
	
	keystr = new_path;
	reg_split_path( keystr, &base, &new_path );
	
	if ( !new_path ) {
		num_drivers = get_ntdrivers( &drivers, environments[env_index], atoi(base) );
		for ( i=0; i<num_drivers; i++ )
			regsubkey_ctr_addkey( subkeys, drivers[i] );
			
		num_subkeys = regsubkey_ctr_numkeys( subkeys );	
		goto done;
	}
	
done:
	SAFE_FREE( key2 );
		
	return num_subkeys;
}

/***********************************************************************
 simple function to prune a pathname down to the basename of a file 
 **********************************************************************/
 
static char* dos_basename ( char *path )
{
	char *p;
	
	p = strrchr( path, '\\' );
	if ( p )
		p++;
	else
		p = path;
		
	return p;
}

/**********************************************************************
 handle enumeration of values below 
 KEY_PRINTING\Environments\<arch>\<version>\<drivername>
 *********************************************************************/
 
static int print_subpath_values_environments( char *key, REGVAL_CTR *val )
{
	char 		*keystr;
	char		*key2 = NULL;
	char 		*base, *new_path;
	fstring		env;
	fstring		driver;
	int		version;
	NT_PRINTER_DRIVER_INFO_LEVEL	driver_ctr;
	NT_PRINTER_DRIVER_INFO_LEVEL_3	*info3;
	WERROR		w_result;
	char 		*buffer = NULL;
	char		*buffer2 = NULL;
	int		buffer_size = 0;
	int 		i, length;
	char 		*filename;
	
	DEBUG(8,("print_subpath_values_environments: Enter key => [%s]\n", key ? key : "NULL"));
	
	if ( !key )
		return 0;
		
	/* 
	 * The only key below KEY_PRINTING\Environments that 
	 * posseses values is each specific printer driver 
	 * First get the arch, version, & driver name
	 */
	
	/* env */
	
	key2 = strdup( key );
	keystr = key2;
	reg_split_path( keystr, &base, &new_path );
	if ( !base || !new_path )
		return 0;
	fstrcpy( env, base );
	
	/* version */
	
	keystr = new_path;
	reg_split_path( keystr, &base, &new_path );
	if ( !base || !new_path )
		return 0;
	version = atoi( base );

	/* printer driver name */
	
	keystr = new_path;
	reg_split_path( keystr, &base, &new_path );
	/* new_path should be NULL here since this must be the last key */
	if ( !base || new_path )
		return 0;
	fstrcpy( driver, base );

	w_result = get_a_printer_driver( &driver_ctr, 3, driver, env, version );

	if ( !W_ERROR_IS_OK(w_result) )
		return -1;
		
	/* build the values out of the driver information */
	info3 = driver_ctr.info_3;
	
	filename = dos_basename( info3->driverpath );
	regval_ctr_addvalue( val, "Driver",             REG_SZ,       filename, strlen(filename)+1 );
	filename = dos_basename( info3->configfile );
	regval_ctr_addvalue( val, "Configuration File", REG_SZ,       filename, strlen(filename)+1 );
	filename = dos_basename( info3->datafile );
	regval_ctr_addvalue( val, "Data File",          REG_SZ,       filename, strlen(filename)+1 );
	filename = dos_basename( info3->helpfile );
	regval_ctr_addvalue( val, "Help File",          REG_SZ,       filename, strlen(filename)+1 );
		
	regval_ctr_addvalue( val, "Data Type",          REG_SZ,       info3->defaultdatatype, strlen(info3->defaultdatatype)+1 );
	
	regval_ctr_addvalue( val, "Version",            REG_DWORD,    (char*)&info3->cversion, sizeof(info3->cversion) );
	
	if ( info3->dependentfiles )
	{
		/* place the list of dependent files in a single 
		   character buffer, separating each file name by
		   a NULL */
		   
		for ( i=0; strcmp(info3->dependentfiles[i], ""); i++ )
		{
			/* strip the path to only the file's base name */
		
			filename = dos_basename( info3->dependentfiles[i] );
			
			length = strlen(filename);
		
			buffer2 = Realloc( buffer, buffer_size + length + 1 );
			if ( !buffer2 )
				break;
			buffer = buffer2;
		
			memcpy( buffer+buffer_size, filename, length+1 );
		
			buffer_size += length + 1;
		}
		
		/* terminated by double NULL.  Add the final one here */
		
		buffer2 = Realloc( buffer, buffer_size + 1 );
		if ( !buffer2 ) {
			SAFE_FREE( buffer );
			buffer_size = 0;
		}
		else {
			buffer = buffer2;
			buffer[buffer_size++] = '\0';
		}
	}
	
	regval_ctr_addvalue( val, "Dependent Files",    REG_MULTI_SZ, buffer, buffer_size );
	
	free_a_printer_driver( driver_ctr, 3 );
	SAFE_FREE( key2 );
	SAFE_FREE( buffer );
		
	DEBUG(8,("print_subpath_values_environments: Exit\n"));
	
	return regval_ctr_numvals( val );
}


/**********************************************************************
 handle enumeration of subkeys below KEY_PRINTING\Forms
 Really just a stub function, but left here in case it needs to
 be expanded later on
 *********************************************************************/
 
static int print_subpath_forms( char *key, REGSUBKEY_CTR *subkeys )
{
	DEBUG(10,("print_subpath_forms: key=>[%s]\n", key ? key : "NULL" ));
	
	/* there are no subkeys */
	
	if ( key )
		return -1;
	
	return 0;
}

/**********************************************************************
 handle enumeration of values below KEY_PRINTING\Forms
 *********************************************************************/
 
static int print_subpath_values_forms( char *key, REGVAL_CTR *val )
{
	int 		num_values = 0;
	uint32 		data[8];
	int		form_index = 1;
	
	DEBUG(10,("print_values_forms: key=>[%s]\n", key ? key : "NULL" ));
	
	/* handle ..\Forms\ */
	
	if ( !key )
	{
		nt_forms_struct *forms_list = NULL;
		nt_forms_struct *form = NULL;
		int i;
		
		if ( (num_values = get_ntforms( &forms_list )) == 0 ) 
			return 0;
		
		DEBUG(10,("print_subpath_values_forms: [%d] user defined forms returned\n",
			num_values));

		/* handle user defined forms */
				
		for ( i=0; i<num_values; i++ )
		{
			form = &forms_list[i];
			
			data[0] = form->width;
			data[1] = form->length;
			data[2] = form->left;
			data[3] = form->top;
			data[4] = form->right;
			data[5] = form->bottom;
			data[6] = form_index++;
			data[7] = form->flag;
			
			regval_ctr_addvalue( val, form->name, REG_BINARY, (char*)data, sizeof(data) );
		
		}
		
		SAFE_FREE( forms_list );
		forms_list = NULL;
		
		/* handle built-on forms */
		
		if ( (num_values = get_builtin_ntforms( &forms_list )) == 0 ) 
			return 0;
		
		DEBUG(10,("print_subpath_values_forms: [%d] built-in forms returned\n",
			num_values));
			
		for ( i=0; i<num_values; i++ )
		{
			form = &forms_list[i];
			
			data[0] = form->width;
			data[1] = form->length;
			data[2] = form->left;
			data[3] = form->top;
			data[4] = form->right;
			data[5] = form->bottom;
			data[6] = form_index++;
			data[7] = form->flag;
					
			regval_ctr_addvalue( val, form->name, REG_BINARY, (char*)data, sizeof(data) );
		}
		
		SAFE_FREE( forms_list );
	}
	
	return num_values;
}

/**********************************************************************
 handle enumeration of subkeys below KEY_PRINTING\Printers
 *********************************************************************/
 
static int print_subpath_printers( char *key, REGSUBKEY_CTR *subkeys )
{
	int n_services = lp_numservices();	
	int snum;
	fstring sname;
	
	DEBUG(10,("print_subpath_printers: key=>[%s]\n", key ? key : "NULL" ));
	
	if ( !key )
	{
		/* enumerate all printers */
		
		for (snum=0; snum<n_services; snum++) {
			if ( !(lp_snum_ok(snum) && lp_print_ok(snum) ) )
				continue;
				
			fstrcpy( sname, lp_servicename(snum) );
				
			regsubkey_ctr_addkey( subkeys, sname );
		}
	}
	else 
	{
		/* get information for a specific printer */
	}
	
	return regsubkey_ctr_numkeys( subkeys );
}

/**********************************************************************
 Routine to handle enumeration of subkeys and values 
 below KEY_PRINTING (depending on whether or not subkeys/val are 
 valid pointers. 
 *********************************************************************/
 
static int handle_printing_subpath( char *key, REGSUBKEY_CTR *subkeys, REGVAL_CTR *val )
{
	int result = 0;
	char *p, *base;
	int i;
	
	DEBUG(10,("handle_printing_subpath: key=>[%s]\n", key ));
	
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
		
	if ( !(i < MAX_TOP_LEVEL_KEYS) )
		return -1;
						
	/* Call routine to handle each top level key */
	switch ( i )
	{
		case KEY_INDEX_ENVIR:
			if ( subkeys )
				print_subpath_environments( p, subkeys );
			if ( val )
				print_subpath_values_environments( p, val );
			break;
		
		case KEY_INDEX_FORMS:
			if ( subkeys )
				print_subpath_forms( p, subkeys );
			if ( val )
				print_subpath_values_forms( p, val );
			break;
			
		case KEY_INDEX_PRINTER:
			if ( subkeys )
				print_subpath_printers( p, subkeys );
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
		num_subkeys = handle_printing_subpath( path, subkey_ctr, NULL );
	
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
		num_values = 0;
	else
		num_values = handle_printing_subpath( path, NULL, val );
		
	
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


