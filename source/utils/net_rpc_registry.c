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
	
	if (argc != 1 ) {
		d_printf("Usage:    net rpc enumerate <path> [recurse]\n");
		d_printf("Example:: net rpc enumerate 'HKLM\\Software\\Samba'\n");
		return NT_STATUS_OK;
	}
	
	if ( !reg_split_hive( argv[0], &hive, subpath ) ) {
		d_printf("invalid registry path\n");
		return NT_STATUS_OK;
	}
	
	result = cli_reg_connect( cli, mem_ctx, hive, MAXIMUM_ALLOWED_ACCESS, &pol_hive );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Unable to connect to remote registry\n");
		return NT_STATUS_OK;
	}
	
	result = cli_reg_open_entry( cli, mem_ctx, &pol_hive, subpath, MAXIMUM_ALLOWED_ACCESS, &pol_key );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Unable to open [%s]\n", argv[0]);
		return NT_STATUS_OK;
	}
	
	
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

static int net_help_registry( int argc, const char **argv )
{
	d_printf("net rpc registry enumerate <path> [recurse]  Enumerate the subkeya and values for a given registry path\n");
	
	return -1;
}

/********************************************************************
********************************************************************/

int net_rpc_registry(int argc, const char **argv) 
{
	struct functable func[] = {
		{"enumerate", rpc_registry_enumerate},
		{NULL, NULL}
	};
	
	if ( argc )
		return net_run_function( argc, argv, func, net_help_registry );
		
	return net_help_registry( argc, argv );
}


