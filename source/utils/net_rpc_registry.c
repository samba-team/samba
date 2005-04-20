/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) Gerald (Jerry) Carter          2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
#include "includes.h"
#include "utils/net.h"
#include "regfio.h"


/********************************************************************
********************************************************************/

char* dump_regval_type( uint32 type )
{
	static fstring string;
	
	switch (type) {
	case REG_SZ:
		fstrcpy( string, "REG_SZ" );
		break;
	case REG_MULTI_SZ:
		fstrcpy( string, "REG_MULTI_SZ" );
		break;
	case REG_DWORD:
		fstrcpy( string, "REG_DWORD" );
		break;
	case REG_BINARY:
		fstrcpy( string, "REG_BINARY" );
		break;
	default:
		fstrcpy( string, "UNKNOWN" );
	}
	
	return string;
}
/********************************************************************
********************************************************************/

void dump_regval_buffer( uint32 type, REGVAL_BUFFER *buffer )
{
	pstring string;
	uint32 value;
	
	switch (type) {
	case REG_SZ:
		rpcstr_pull( string, buffer->buffer, sizeof(string), -1, STR_TERMINATE );
		d_printf("%s\n", string);
		break;
	case REG_MULTI_SZ:
		d_printf("\n");
		break;
	case REG_DWORD:
		value = IVAL( buffer->buffer, 0 );
		d_printf( "0x%x\n", value );
		break;
	case REG_BINARY:
		d_printf("\n");
		break;
	
	
	default:
		d_printf( "\tUnknown type [%d]\n", type );
	}
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_registry_enumerate_internal( const DOM_SID *domain_sid, const char *domain_name, 
                                           struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                           int argc, const char **argv )
{
	WERROR result = WERR_GENERAL_FAILURE;
	uint32 hive;
	pstring subpath;
	POLICY_HND pol_hive, pol_key; 
	uint32 idx;
	
	if (argc != 1 ) {
		d_printf("Usage:    net rpc enumerate <path> [recurse]\n");
		d_printf("Example:: net rpc enumerate 'HKLM\\Software\\Samba'\n");
		return NT_STATUS_OK;
	}
	
	if ( !reg_split_hive( argv[0], &hive, subpath ) ) {
		d_printf("invalid registry path\n");
		return NT_STATUS_OK;
	}
	
	/* open the top level hive and then the registry key */
	
	result = cli_reg_connect( cli, mem_ctx, hive, MAXIMUM_ALLOWED_ACCESS, &pol_hive );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Unable to connect to remote registry\n");
		return werror_to_ntstatus(result);
	}
	
	result = cli_reg_open_entry( cli, mem_ctx, &pol_hive, subpath, MAXIMUM_ALLOWED_ACCESS, &pol_key );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Unable to open [%s]\n", argv[0]);
		return werror_to_ntstatus(result);
	}
	
	/* get the subkeys */
	
	result = WERR_OK;
	idx = 0;
	while ( W_ERROR_IS_OK(result) ) {
		time_t modtime;
		fstring keyname, classname;
		
		result = cli_reg_enum_key( cli, mem_ctx, &pol_key, idx, 
			keyname, classname, &modtime );
			
		if ( W_ERROR_EQUAL(result, WERR_NO_MORE_ITEMS) ) {
			result = WERR_OK;
			break;
		}
			
		d_printf("Keyname   = %s\n", keyname );
		d_printf("Classname = %s\n", classname );
		d_printf("Modtime   = %s\n", http_timestring(modtime) );
		d_printf("\n" );

		idx++;
	}

	if ( !W_ERROR_IS_OK(result) )
		goto out;
	
	/* get the values */
	
	result = WERR_OK;
	idx = 0;
	while ( W_ERROR_IS_OK(result) ) {
		uint32 type;
		fstring name;
		REGVAL_BUFFER value;
		
		fstrcpy( name, "" );
		ZERO_STRUCT( value );
		
		result = cli_reg_enum_val( cli, mem_ctx, &pol_key, idx, 
			name, &type, &value );
			
		if ( W_ERROR_EQUAL(result, WERR_NO_MORE_ITEMS) ) {
			result = WERR_OK;
			break;
		}
			
		d_printf("Valuename  = %s\n", name );
		d_printf("Type       = %s\n", dump_regval_type(type) );
		d_printf("Data       = " );
		dump_regval_buffer( type, &value );
		d_printf("\n" );

		idx++;
	}
	
	
out:
	/* cleanup */
	
	cli_reg_close( cli, mem_ctx, &pol_key );
	cli_reg_close( cli, mem_ctx, &pol_hive );

	return werror_to_ntstatus(result);
}

/********************************************************************
********************************************************************/

static int rpc_registry_enumerate( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_WINREG, 0, 
		rpc_registry_enumerate_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_registry_backup_internal( const DOM_SID *domain_sid, const char *domain_name, 
                                           struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                           int argc, const char **argv )
{
	WERROR result = WERR_GENERAL_FAILURE;
	uint32 hive;
	pstring subpath;
	POLICY_HND pol_hive, pol_key; 
	REGF_FILE *regfile;
	
	if (argc != 2 ) {
		d_printf("Usage:    net rpc backup <path> <file> \n");
		return NT_STATUS_OK;
	}
	
	if ( !reg_split_hive( argv[0], &hive, subpath ) ) {
		d_printf("invalid registry path\n");
		return NT_STATUS_OK;
	}
	
	/* open the top level hive and then the registry key */
	
	result = cli_reg_connect( cli, mem_ctx, hive, MAXIMUM_ALLOWED_ACCESS, &pol_hive );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Unable to connect to remote registry\n");
		return werror_to_ntstatus(result);
	}
	
	result = cli_reg_open_entry( cli, mem_ctx, &pol_hive, subpath, MAXIMUM_ALLOWED_ACCESS, &pol_key );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Unable to open [%s]\n", argv[0]);
		return werror_to_ntstatus(result);
	}
	
	/* open the file */
	
	if ( !(regfile = regfio_open( argv[1], (O_RDWR|O_CREAT|O_TRUNC), 0600 )) ) {
		d_printf("Unable to open registry file [%s]\n", argv[1]);
		return werror_to_ntstatus(WERR_GENERAL_FAILURE);
	}
	
	
	/* cleanup */
	
	regfio_close( regfile );
	cli_reg_close( cli, mem_ctx, &pol_key );
	cli_reg_close( cli, mem_ctx, &pol_hive );

	return werror_to_ntstatus(result);
}

/********************************************************************
********************************************************************/

static int rpc_registry_backup( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_WINREG, 0, 
		rpc_registry_backup_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int rpc_registry_dump( int argc, const char **argv )
{

	return 0;
}

/********************************************************************
********************************************************************/

static int net_help_registry( int argc, const char **argv )
{
	d_printf("net rpc registry enumerate <path> [recurse]  Enumerate the subkeya and values for a given registry path\n");
	d_printf("net rpc registry backup <path> <file>        Backup a registry tree to a local file\n");
	d_printf("net rpc registry dump <file>                 Dump the contents of a registry file to stdout\n");
	
	return -1;
}

/********************************************************************
********************************************************************/

int net_rpc_registry(int argc, const char **argv) 
{
	struct functable func[] = {
		{"enumerate", rpc_registry_enumerate},
		{"backup",    rpc_registry_backup},
		{"dump",      rpc_registry_dump},
		{NULL, NULL}
	};
	
	if ( argc )
		return net_run_function( argc, argv, func, net_help_registry );
		
	return net_help_registry( argc, argv );
}


