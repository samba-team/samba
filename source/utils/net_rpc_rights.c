/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) Gerald (Jerry) Carter          2004

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

static NTSTATUS rpc_rights_list_internal( const DOM_SID *domain_sid, const char *domain_name, 
                            struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                            int argc, const char **argv )
{
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_rights_grant_internal( const DOM_SID *domain_sid, const char *domain_name, 
                            struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                            int argc, const char **argv )
{
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_rights_revoke_internal( const DOM_SID *domain_sid, const char *domain_name, 
                              struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                              int argc, const char **argv )
{
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

static int rpc_rights_list( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_LSARPC, 0, 
		rpc_rights_list_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int rpc_rights_grant( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_LSARPC, 0, 
		rpc_rights_grant_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int rpc_rights_revoke( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_LSARPC, 0, 
		rpc_rights_revoke_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int net_help_rights( int argc, const char **argv )
{
	d_printf("net rpc rights list       View available privileges\n");
	d_printf("net rpc rights grant      View available privileges\n");
	d_printf("net rpc rights revoke     View available privileges\n");
	
	d_printf("Both 'grant' and 'revoke' require a SID and a commaa separated\n");
	d_printf("list of privilege names.  For example\n");
	d_printf("  net rpc grant S-1-5-32-550 SePrintOperatorsPrivilege\n");
	d_printf("would grant the printer admin right to the 'BUILTIN\\Print Operators' group\n");
	
	
	return -1;
}

/********************************************************************
********************************************************************/

int net_rpc_rights(int argc, const char **argv) 
{
	struct functable func[] = {
		{"list", rpc_rights_list},
		{"grant", rpc_rights_grant},
		{"revoke", rpc_rights_revoke},
		{NULL, NULL}
	};
	
	if ( argc )
		return net_run_function( argc, argv, func, net_help_rights );
		
	return net_help_rights( argc, argv );
}


