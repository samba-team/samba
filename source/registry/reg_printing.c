/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
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

/* registrt paths used in the print_registry[] */

#define KEY_MONITORS		"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/PRINT/MONITORS"
#define KEY_FORMS		"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/PRINT/FORMS"
#define KEY_CONTROL_PRINTERS	"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/PRINT/PRINTERS"
#define KEY_ENVIRONMENTS	"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/PRINT/ENVIRONMENTS"
#define KEY_CONTROL_PRINT	"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/PRINT"
#define KEY_WINNT_PRINTERS	"HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION/PRINT/PRINTERS"
#define KEY_WINNT_PRINT		"HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION/PRINT"
#define KEY_PORTS		"HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION/PORTS"

/* callback table for various registry paths below the ones we service in this module */
	
struct reg_dyn_tree {
	/* full key path in normalized form */
	const char *path;
	
	/* callbscks for fetch/store operations */
	int ( *fetch_subkeys) ( const char *path, REGSUBKEY_CTR *subkeys );
	BOOL (*store_subkeys) ( const char *path, REGSUBKEY_CTR *subkeys );
	int  (*fetch_values)  ( const char *path, REGVAL_CTR *values );
	BOOL (*store_values)  ( const char *path, REGVAL_CTR *values );
};


/**********************************************************************
 move to next non-delimter character
*********************************************************************/

static char* remaining_path( const char *key )
{
	static pstring new_path;
	char *p;
	
	if ( !key || !*key )
		return NULL;

	pstrcpy( new_path, key );
	/* normalize_reg_path( new_path ); */
	
	if ( !(p = strchr( new_path, '\\' )) ) 
	{
		if ( !(p = strchr( new_path, '/' )) )
			p = new_path;
		else 
			p++;
	}
	else
		p++;
		
	return p;
}

/***********************************************************************
 simple function to prune a pathname down to the basename of a file 
 **********************************************************************/
 
static char* dos_basename ( char *path )
{
	char *p;
	
	if ( !(p = strrchr( path, '\\' )) )
		p = path;
	else
		p++;
		
	return p;
}

/**********************************************************************
 *********************************************************************/

static int key_forms_fetch_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	char *p = remaining_path( key + strlen(KEY_FORMS) );
	
	/* no keys below Forms */
	
	if ( p )
		return -1;
		
	return 0;
}

static int key_forms_fetch_values( const char *key, REGVAL_CTR *values )
{
	uint32 		data[8];
	int		i, num_values, form_index = 1;
	nt_forms_struct *forms_list = NULL;
	nt_forms_struct *form;
		
	DEBUG(10,("print_values_forms: key=>[%s]\n", key ? key : "NULL" ));
	
	num_values = get_ntforms( &forms_list );
		
	DEBUG(10,("hive_forms_fetch_values: [%d] user defined forms returned\n",
		num_values));

	/* handle user defined forms */
				
	for ( i=0; i<num_values; i++ ) {
		form = &forms_list[i];
			
		data[0] = form->width;
		data[1] = form->length;
		data[2] = form->left;
		data[3] = form->top;
		data[4] = form->right;
		data[5] = form->bottom;
		data[6] = form_index++;
		data[7] = form->flag;
			
		regval_ctr_addvalue( values, form->name, REG_BINARY, (char*)data, sizeof(data) );	
	}
		
	SAFE_FREE( forms_list );
	forms_list = NULL;
		
	/* handle built-on forms */
		
	num_values = get_builtin_ntforms( &forms_list );
		
	DEBUG(10,("print_subpath_values_forms: [%d] built-in forms returned\n",
		num_values));
			
	for ( i=0; i<num_values; i++ ) {
		form = &forms_list[i];
			
		data[0] = form->width;
		data[1] = form->length;
		data[2] = form->left;
		data[3] = form->top;
		data[4] = form->right;
		data[5] = form->bottom;
		data[6] = form_index++;
		data[7] = form->flag;
					
		regval_ctr_addvalue( values, form->name, REG_BINARY, (char*)data, sizeof(data) );
	}
		
	SAFE_FREE( forms_list );
	
	return regval_ctr_numvals( values );
}

/**********************************************************************
 *********************************************************************/

static int key_printer_fetch_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	int n_services = lp_numservices();	
	int snum;
	fstring sname;
	int i;
	int num_subkeys = 0;
	char *keystr;
	char *base, *new_path;
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	fstring *subkey_names = NULL;
	pstring path;
	
	DEBUG(10,("print_subpath_printers: key=>[%s]\n", key ? key : "NULL" ));
	
	pstrcpy( path, key );
	normalize_reg_path( path );

	/* normalizing the path does not change length, just key delimiters and case */

	if ( strncmp( path, KEY_WINNT_PRINTERS, strlen(KEY_WINNT_PRINTERS) ) == 0 )
		keystr = remaining_path( key + strlen(KEY_WINNT_PRINTERS) );
	else
		keystr = remaining_path( key + strlen(KEY_CONTROL_PRINTERS) );
	
	
	if ( !keystr ) {
		/* enumerate all printers */
		
		for (snum=0; snum<n_services; snum++) {
			if ( !(lp_snum_ok(snum) && lp_print_ok(snum) ) )
				continue;

			/* don't report the [printers] share */

			if ( strequal( lp_servicename(snum), PRINTERS_NAME ) )
				continue;
				
			fstrcpy( sname, lp_servicename(snum) );
				
			regsubkey_ctr_addkey( subkeys, sname );
		}
		
		num_subkeys = regsubkey_ctr_numkeys( subkeys );
		goto done;
	}

	/* get information for a specific printer */
	
	reg_split_path( keystr, &base, &new_path );

		if ( !W_ERROR_IS_OK( get_a_printer(NULL, &printer, 2, base) ) )
		goto done;

	num_subkeys = get_printer_subkeys( &printer->info_2->data, new_path?new_path:"", &subkey_names );
	
	for ( i=0; i<num_subkeys; i++ )
		regsubkey_ctr_addkey( subkeys, subkey_names[i] );
	
	free_a_printer( &printer, 2 );
			
	/* no other subkeys below here */

done:	
	SAFE_FREE( subkey_names );
	
	return num_subkeys;
}

static BOOL key_printer_store_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	return True;
}

static int key_printer_fetch_values( const char *key, REGVAL_CTR *values )
{
	int 		num_values = 0;
	char		*keystr, *key2 = NULL;
	char		*base, *new_path;
	NT_PRINTER_INFO_LEVEL 	*printer = NULL;
	NT_PRINTER_INFO_LEVEL_2 *info2;
	DEVICEMODE	*devmode;
	prs_struct	prs;
	uint32		offset;
	int		snum;
	fstring		printername; 
	NT_PRINTER_DATA	*p_data;
	int		i, key_index;
	UNISTR2		data;
	pstring 	path;
	
	/* 
	 * Theres are tw cases to deal with here
	 * (1) enumeration of printer_info_2 values
	 * (2) enumeration of the PrinterDriverData subney
	 */
	 
	pstrcpy( path, key );
	normalize_reg_path( path );

	/* normalizing the path does not change length, just key delimiters and case */

	if ( strncmp( path, KEY_WINNT_PRINTERS, strlen(KEY_WINNT_PRINTERS) ) == 0 )
		keystr = remaining_path( key + strlen(KEY_WINNT_PRINTERS) );
	else
		keystr = remaining_path( key + strlen(KEY_CONTROL_PRINTERS) );
	
	if ( !keystr ) {
		/* top level key has no values */
		goto done;
	}
	
	key2 = SMB_STRDUP( keystr );
	keystr = key2;
	reg_split_path( keystr, &base, &new_path );
	
	fstrcpy( printername, base );
	
	if ( !new_path ) {
		char *p;
		uint32 printer_status = PRINTER_STATUS_OK;

		/* we are dealing with the printer itself */

		if ( !W_ERROR_IS_OK( get_a_printer(NULL, &printer, 2, printername) ) )
			goto done;

		info2 = printer->info_2;
		

		regval_ctr_addvalue( values, "Attributes",       REG_DWORD, (char*)&info2->attributes,       sizeof(info2->attributes) );
		regval_ctr_addvalue( values, "Priority",         REG_DWORD, (char*)&info2->priority,         sizeof(info2->attributes) );
		regval_ctr_addvalue( values, "ChangeID",         REG_DWORD, (char*)&info2->changeid,         sizeof(info2->changeid) );
		regval_ctr_addvalue( values, "Default Priority", REG_DWORD, (char*)&info2->default_priority, sizeof(info2->default_priority) );

		/* lie and say everything is ok since we don't want to call print_queue_length() to get the real status */
		regval_ctr_addvalue( values, "Status",           REG_DWORD, (char*)&printer_status,          sizeof(info2->status) );

		regval_ctr_addvalue( values, "StartTime",        REG_DWORD, (char*)&info2->starttime,        sizeof(info2->starttime) );
		regval_ctr_addvalue( values, "UntilTime",        REG_DWORD, (char*)&info2->untiltime,        sizeof(info2->untiltime) );

		/* strip the \\server\ from this string */
		if ( !(p = strrchr( info2->printername, '\\' ) ) )
			p = info2->printername;
		else
			p++;
		init_unistr2( &data, p, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Name", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->location, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Location", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->comment, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Description", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->parameters, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Parameters", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->portname, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Port", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->sharename, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Share Name", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->drivername, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Printer Driver", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, info2->sepfile, UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Separator File", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, "WinPrint", UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Print Processor",  REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		init_unistr2( &data, "RAW", UNI_STR_TERMINATE);
		regval_ctr_addvalue( values, "Datatype", REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );

		
		/* use a prs_struct for converting the devmode and security 
		   descriptor to REG_BINARY */
		
		prs_init( &prs, MAX_PDU_FRAG_LEN, regval_ctr_getctx(values), MARSHALL);

		/* stream the device mode */
		
		snum = lp_servicenumber(info2->sharename);
		if ( (devmode = construct_dev_mode( snum )) != NULL )
		{			
			if ( spoolss_io_devmode( "devmode", &prs, 0, devmode ) ) {
			
				offset = prs_offset( &prs );
				
				regval_ctr_addvalue( values, "Default Devmode", REG_BINARY, prs_data_p(&prs), offset );
			}
			
			
		}
		
		prs_mem_clear( &prs );
		prs_set_offset( &prs, 0 );
		
		if ( info2->secdesc_buf && info2->secdesc_buf->len ) 
		{
			if ( sec_io_desc("sec_desc", &info2->secdesc_buf->sec, &prs, 0 ) ) {
			
				offset = prs_offset( &prs );
			
				regval_ctr_addvalue( values, "Security", REG_BINARY, prs_data_p(&prs), offset );
			}
		}

		prs_mem_free( &prs );
		
		num_values = regval_ctr_numvals( values );	
		
		goto done;
		
	}
		
	/* now enumerate the key */
	
	if ( !W_ERROR_IS_OK( get_a_printer(NULL, &printer, 2, printername) ) )
		goto done;
	
	/* iterate over all printer data and fill the regval container */
	
	p_data = &printer->info_2->data;
	if ( (key_index = lookup_printerkey( p_data, new_path )) == -1  ) {
		DEBUG(10,("key_printer_fetch_values: Unknown keyname [%s]\n", new_path));
		goto done;
	}
	
	num_values = regval_ctr_numvals( &p_data->keys[key_index].values );
	
	for ( i=0; i<num_values; i++ )
		regval_ctr_copyvalue( values, regval_ctr_specific_value(&p_data->keys[key_index].values, i) );
			

done:
	if ( printer )
		free_a_printer( &printer, 2 );
		
	SAFE_FREE( key2 ); 
	
	return num_values;
}

static BOOL key_printer_store_values( const char *key, REGVAL_CTR *values )
{
	return True;
}

/**********************************************************************
 *********************************************************************/
#define ENVIRONMENT_DRIVERS	1
#define ENVIRONMENT_PRINTPROC	2

static int key_driver_fetch_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	const char *environments[] = {
		"Windows 4.0",
		"Windows NT x86",
		"Windows NT R4000",
		"Windows NT Alpha_AXP",
		"Windows NT PowerPC",
		"Windows IA64",
		"Windows x64",
		NULL };
	fstring *drivers = NULL;
	int i, env_index, num_drivers;
	char *keystr, *base, *subkeypath;
	pstring key2;
	int num_subkeys = -1;
	int env_subkey_type = 0;
	int version;

	DEBUG(10,("key_driver_fetch_keys key=>[%s]\n", key ? key : "NULL" ));
	
	keystr = remaining_path( key + strlen(KEY_ENVIRONMENTS) );	
	
	/* list all possible architectures */
	
	if ( !keystr ) {
		for ( num_subkeys=0; environments[num_subkeys]; num_subkeys++ ) 
			regsubkey_ctr_addkey( subkeys, 	environments[num_subkeys] );

		return num_subkeys;
	}
	
	/* we are dealing with a subkey of "Environments */
	
	pstrcpy( key2, keystr );
	keystr = key2;
	reg_split_path( keystr, &base, &subkeypath );
	
	/* sanity check */
	
	for ( env_index=0; environments[env_index]; env_index++ ) {
		if ( strequal( environments[env_index], base ) )
			break;
	}
	if ( !environments[env_index] )
		return -1;
	
	/* ...\Print\Environements\...\ */
	
	if ( !subkeypath ) {
		regsubkey_ctr_addkey( subkeys, "Drivers" );
		regsubkey_ctr_addkey( subkeys, "Print Processors" );
				
		return 2;
	}
	
	/* more of the key path to process */
	
	keystr = subkeypath;
	reg_split_path( keystr, &base, &subkeypath );	
		
	/* ...\Print\Environements\...\Drivers\ */
	
	if ( strequal(base, "Drivers") )
		env_subkey_type = ENVIRONMENT_DRIVERS;
	else if ( strequal(base, "Print Processors") )
		env_subkey_type = ENVIRONMENT_PRINTPROC;
	else
		/* invalid path */
		return -1;
	
	if ( !subkeypath ) {
		switch ( env_subkey_type ) {
		case ENVIRONMENT_DRIVERS:
			switch ( env_index ) {
				case 0:	/* Win9x */
					regsubkey_ctr_addkey( subkeys, "Version-0" );
					break;
				default: /* Windows NT based systems */
					regsubkey_ctr_addkey( subkeys, "Version-2" );
					regsubkey_ctr_addkey( subkeys, "Version-3" );
					break;			
			}
		
			return regsubkey_ctr_numkeys( subkeys );
		
		case ENVIRONMENT_PRINTPROC:
			if ( env_index == 1 || env_index == 5 || env_index == 6 )
				regsubkey_ctr_addkey( subkeys, "winprint" );
				
			return regsubkey_ctr_numkeys( subkeys );
		}
	}
	
	/* we finally get to enumerate the drivers */
	
	keystr = subkeypath;
	reg_split_path( keystr, &base, &subkeypath );

	/* get thr print processors key out of the way */
	if ( env_subkey_type == ENVIRONMENT_PRINTPROC ) {
		if ( !strequal( base, "winprint" ) )
			return -1;
		return !subkeypath ? 0 : -1;
	}
	
	/* only dealing with drivers from here on out */
	
	version = atoi(&base[strlen(base)-1]);
			
	switch (env_index) {
	case 0:
		if ( version != 0 )
			return -1;
		break;
	default:
		if ( version != 2 && version != 3 )
			return -1;
		break;
	}

	
	if ( !subkeypath ) {
		num_drivers = get_ntdrivers( &drivers, environments[env_index], version );
		for ( i=0; i<num_drivers; i++ )
			regsubkey_ctr_addkey( subkeys, drivers[i] );
			
		return regsubkey_ctr_numkeys( subkeys );	
	}	
	
	/* if anything else left, just say if has no subkeys */
	
	DEBUG(1,("key_driver_fetch_keys unhandled key [%s] (subkey == %s\n", 
		key, subkeypath ));
	
	return 0;
}

static BOOL key_driver_store_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	return True;
}

static int key_driver_fetch_values( const char *key, REGVAL_CTR *values )
{
	char 		*keystr, *base, *subkeypath;
	pstring 	key2;
	fstring		arch_environment;
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
	UNISTR2		data;
	int		env_subkey_type = 0;
	
	
	DEBUG(8,("print_subpath_values_environments: Enter key => [%s]\n", key ? key : "NULL"));

	keystr = remaining_path( key + strlen(KEY_ENVIRONMENTS) );	
	
	if ( !keystr )
		return 0;
		
	/* The only keys below KEY_PRINTING\Environments is the 
	   specific printer driver info */
	
	/* environment */
	
	pstrcpy( key2, keystr);
	keystr = key2;
	reg_split_path( keystr, &base, &subkeypath );
	if ( !subkeypath ) 
		return 0;
	fstrcpy( arch_environment, base );
	
	/* Driver */
	
	keystr = subkeypath;
	reg_split_path( keystr, &base, &subkeypath );

	if ( strequal(base, "Drivers") )
		env_subkey_type = ENVIRONMENT_DRIVERS;
	else if ( strequal(base, "Print Processors") )
		env_subkey_type = ENVIRONMENT_PRINTPROC;
	else
		/* invalid path */
		return -1;
	
	if ( !subkeypath )
		return 0;

	/* for now bail out if we are seeing anything other than the drivers key */
	
	if ( env_subkey_type == ENVIRONMENT_PRINTPROC )
		return 0;
		
	keystr = subkeypath;
	reg_split_path( keystr, &base, &subkeypath );
		
	version = atoi(&base[strlen(base)-1]);

	/* printer driver name */
	
	keystr = subkeypath;
	reg_split_path( keystr, &base, &subkeypath );
	/* don't go any deeper for now */
	if ( subkeypath )
		return 0;
	fstrcpy( driver, base );

	w_result = get_a_printer_driver( &driver_ctr, 3, driver, arch_environment, version );

	if ( !W_ERROR_IS_OK(w_result) )
		return -1;
		
	/* build the values out of the driver information */
	info3 = driver_ctr.info_3;
	
	filename = dos_basename( info3->driverpath );
	init_unistr2( &data, filename, UNI_STR_TERMINATE);
	regval_ctr_addvalue( values, "Driver",             REG_SZ,       (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	filename = dos_basename( info3->configfile );
	init_unistr2( &data, filename, UNI_STR_TERMINATE);
	regval_ctr_addvalue( values, "Configuration File", REG_SZ,       (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	filename = dos_basename( info3->datafile );
	init_unistr2( &data, filename, UNI_STR_TERMINATE);
	regval_ctr_addvalue( values, "Data File",          REG_SZ,       (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	filename = dos_basename( info3->helpfile );
	init_unistr2( &data, filename, UNI_STR_TERMINATE);
	regval_ctr_addvalue( values, "Help File",          REG_SZ,       (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	init_unistr2( &data, info3->defaultdatatype, UNI_STR_TERMINATE);
	regval_ctr_addvalue( values, "Data Type",          REG_SZ,       (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	regval_ctr_addvalue( values, "Version",            REG_DWORD,    (char*)&info3->cversion, sizeof(info3->cversion) );
	
	if ( info3->dependentfiles ) {
		/* place the list of dependent files in a single 
		   character buffer, separating each file name by
		   a NULL */
		   
		for ( i=0; strcmp(info3->dependentfiles[i], ""); i++ ) {
			/* strip the path to only the file's base name */
		
			filename = dos_basename( info3->dependentfiles[i] );
			
			length = strlen(filename);
		
			buffer2 = SMB_REALLOC( buffer, buffer_size + (length + 1)*sizeof(uint16) );
			if ( !buffer2 )
				break;
			buffer = buffer2;
			
			init_unistr2( &data, filename, UNI_STR_TERMINATE);
			memcpy( buffer+buffer_size, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
		
			buffer_size += (length + 1)*sizeof(uint16);
		}
		
		/* terminated by double NULL.  Add the final one here */
		
		buffer2 = SMB_REALLOC( buffer, buffer_size + 2 );
		if ( !buffer2 ) {
			SAFE_FREE( buffer );
			buffer_size = 0;
		} else {
			buffer = buffer2;
			buffer[buffer_size++] = '\0';
			buffer[buffer_size++] = '\0';
		}
	}
	
	regval_ctr_addvalue( values, "Dependent Files",    REG_MULTI_SZ, buffer, buffer_size );
	
	free_a_printer_driver( driver_ctr, 3 );
	
	SAFE_FREE( buffer );
		
	DEBUG(8,("print_subpath_values_environments: Exit\n"));
	
	return regval_ctr_numvals( values );
}

static BOOL key_driver_store_values( const char *key, REGVAL_CTR *values )
{
	return True;
}

/**********************************************************************
 Deal with the 'Print' key the same whether it came from SYSTEM
 or SOFTWARE
 *********************************************************************/

static int key_print_fetch_keys( const char *key, REGSUBKEY_CTR *subkeys )
{	
	int key_len = strlen(key);
	
	/* no keys below 'Print' handled here */
	
	if ( (key_len != strlen(KEY_CONTROL_PRINT)) && (key_len != strlen(KEY_WINNT_PRINT)) )
		return -1;

	regsubkey_ctr_addkey( subkeys, "Environments" );
	regsubkey_ctr_addkey( subkeys, "Monitors" );
	regsubkey_ctr_addkey( subkeys, "Forms" );
	regsubkey_ctr_addkey( subkeys, "Printers" );
	
	return regsubkey_ctr_numkeys( subkeys );
}

/**********************************************************************
 If I can get rid of the 'enumports command', this code becomes 
 a tdb lookup.
 *********************************************************************/

static int key_ports_fetch_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	/* no keys below ports */
	
	if ( remaining_path( key + strlen(KEY_PORTS) ) )
		return -1;
		
	return 0;
}

static BOOL key_ports_store_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	return True;
}

static int key_ports_fetch_values( const char *key, REGVAL_CTR *values )
{
	int numlines, i;
	char **lines;
	UNISTR2	data;
	WERROR result;
	char *p = remaining_path( key + strlen(KEY_PORTS) );
	
	/* no keys below ports */
	if ( p )
		return -1;

	if ( !W_ERROR_IS_OK(result = enumports_hook( &numlines, &lines )) )
		return -1;

	init_unistr2( &data, "", UNI_STR_TERMINATE);
	for ( i=0; i<numlines; i++ )
		regval_ctr_addvalue( values, lines[i], REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	return regval_ctr_numvals( values );
}

static BOOL key_ports_store_values( const char *key, REGVAL_CTR *values )
{
	return True;
}

/**********************************************************************
 Structure to hold dispatch table of ops for various printer keys.
 Make sure to always store deeper keys along the same path first so 
 we ge a more specific match.
 *********************************************************************/

static struct reg_dyn_tree print_registry[] = {
/* just pass the monitor onto the registry tdb */
{ KEY_MONITORS,
	&regdb_fetch_keys, 
	&regdb_store_keys,
	&regdb_fetch_values,
	&regdb_store_values },
{ KEY_FORMS, 
	&key_forms_fetch_keys, 
	NULL, 
	&key_forms_fetch_values,
	NULL },
{ KEY_CONTROL_PRINTERS, 
	&key_printer_fetch_keys,
	&key_printer_store_keys,
	&key_printer_fetch_values,
	&key_printer_store_values },
{ KEY_ENVIRONMENTS,
	&key_driver_fetch_keys,
	&key_driver_store_keys,
	&key_driver_fetch_values,
	&key_driver_store_values },
{ KEY_CONTROL_PRINT,
	&key_print_fetch_keys,
	NULL,
	NULL,
	NULL },
{ KEY_WINNT_PRINTERS,
	&key_printer_fetch_keys,
	&key_printer_store_keys,
	&key_printer_fetch_values,
	&key_printer_store_values },
{ KEY_PORTS,
	&key_ports_fetch_keys,
	&key_ports_store_keys,
	&key_ports_fetch_values,
	&key_ports_store_values },
	
{ NULL, NULL, NULL, NULL, NULL }
};


/**********************************************************************
 *********************************************************************/
 
static int match_registry_path( const char *key )
{
	int i;
	pstring path;
	
	if ( !key )
		return -1;

	pstrcpy( path, key );
	normalize_reg_path( path );
	
	for ( i=0; print_registry[i].path; i++ ) {
		if ( strncmp( path, print_registry[i].path, strlen(print_registry[i].path) ) == 0 )
			return i;
	}
	
	return -1;
}

/**********************************************************************
 *********************************************************************/
 
static int regprint_fetch_reg_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	int i = match_registry_path( key );
	
	if ( i == -1 )
		return -1;
		
	if ( !print_registry[i].fetch_subkeys )
		return -1;
		
	return print_registry[i].fetch_subkeys( key, subkeys );
}

/**********************************************************************
 *********************************************************************/

static BOOL regprint_store_reg_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	int i = match_registry_path( key );
	
	if ( i == -1 )
		return False;
	
	if ( !print_registry[i].store_subkeys )
		return False;
		
	return print_registry[i].store_subkeys( key, subkeys );
}

/**********************************************************************
 *********************************************************************/

static int regprint_fetch_reg_values( const char *key, REGVAL_CTR *values )
{
	int i = match_registry_path( key );
	
	if ( i == -1 )
		return -1;
	
	/* return 0 values by default since we know the key had 
	   to exist because the client opened a handle */
	   
	if ( !print_registry[i].fetch_values )
		return 0;
		
	return print_registry[i].fetch_values( key, values );
}

/**********************************************************************
 *********************************************************************/

static BOOL regprint_store_reg_values( const char *key, REGVAL_CTR *values )
{
	int i = match_registry_path( key );
	
	if ( i == -1 )
		return False;
	
	if ( !print_registry[i].store_values )
		return False;
		
	return print_registry[i].store_values( key, values );
}

/* 
 * Table of function pointers for accessing printing data
 */
 
REGISTRY_OPS printing_ops = {
	regprint_fetch_reg_keys,
	regprint_fetch_reg_values,
	regprint_store_reg_keys,
	regprint_store_reg_values,
	NULL
};


