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

static NTSTATUS rpc_service_list_internal( const DOM_SID *domain_sid, const char *domain_name, 
                                           struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                           int argc, const char **argv )
{
	POLICY_HND hSCM;
	WERROR result = WERR_GENERAL_FAILURE;
	
	if (argc != 0 ) {
		d_printf("Usage: net rpc service list\n");
		return NT_STATUS_OK;
	}

	if ( !W_ERROR_IS_OK(result = cli_svcctl_open_scm( cli, mem_ctx, &hSCM, SC_RIGHT_MGR_ENUMERATE_SERVICE  )) ) {
		d_printf("Failed to open Service Control Manager.  [%s]\n", dos_errstr(result));
		return werror_to_ntstatus(result);
	}
	
	d_printf("Successfully opened Service Control Manager.\n");
	
	
	
	close_service_handle( cli, mem_ctx, &hSCM  );
		
	return NT_STATUS_OK;
}	


/********************************************************************
********************************************************************/

static int rpc_service_list( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_SVCCTL, 0, 
		rpc_service_list_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int rpc_service_start( int argc, const char **argv )
{
	d_printf("not implemented\n");
	return 0;
}

/********************************************************************
********************************************************************/

static int rpc_service_stop( int argc, const char **argv )
{
	d_printf("not implemented\n");
	return 0;
}

/********************************************************************
********************************************************************/

static int rpc_service_pause( int argc, const char **argv )
{
	d_printf("not implemented\n");
	return 0;
}

/********************************************************************
********************************************************************/

static int rpc_service_status( int argc, const char **argv )
{
	d_printf("not implemented\n");
	return 0;
}

/********************************************************************
********************************************************************/

static int net_help_service( int argc, const char **argv )
{
	d_printf("net rpc service list               View configured Win32 services\n");
	d_printf("net rpc service start <service>    Start a service\n");
	d_printf("net rpc service stop <service>     Stop a service\n");
	d_printf("net rpc service pause <service>    Pause a service\n");
	d_printf("net rpc service status <service>   View the current status of a service\n");
	
	return -1;
}

/********************************************************************
********************************************************************/

int net_rpc_service(int argc, const char **argv) 
{
	struct functable func[] = {
		{"list", rpc_service_list},
		{"start", rpc_service_start},
		{"stop", rpc_service_stop},
		{"pause", rpc_service_pause},
		{"status", rpc_service_status},
		{NULL, NULL}
	};
	
	if ( argc )
		return net_run_function( argc, argv, func, net_help_service );
		
	return net_help_service( argc, argv );
}


