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
	ENUM_SERVICES_STATUS *services;
	WERROR result = WERR_GENERAL_FAILURE;
	fstring servicename;
	fstring displayname;
	uint32 num_services = 0;
	int i;
	
	if (argc != 0 ) {
		d_printf("Usage: net rpc service list\n");
		return NT_STATUS_OK;
	}

	result = cli_svcctl_open_scm( cli, mem_ctx, &hSCM, SC_RIGHT_MGR_ENUMERATE_SERVICE  );
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Failed to open Service Control Manager.  [%s]\n", dos_errstr(result));
		return werror_to_ntstatus(result);
	}
	
	result = cli_svcctl_enumerate_services( cli, mem_ctx, &hSCM, SVCCTL_TYPE_WIN32,
		SVCCTL_STATE_ALL, &num_services, &services );
	
	if ( !W_ERROR_IS_OK(result) ) {
		d_printf("Failed to enumerate services.  [%s]\n", dos_errstr(result));
		goto done;
	}
	
	if ( num_services == 0 )
		d_printf("No services returned\n");
	
	for ( i=0; i<num_services; i++ ) {
		rpcstr_pull( servicename, services[i].servicename.buffer, sizeof(servicename), -1, STR_TERMINATE );
		rpcstr_pull( displayname, services[i].displayname.buffer, sizeof(displayname), -1, STR_TERMINATE );
		
		d_printf("%s (%s)\n", displayname, servicename);
	}

done:	
	close_service_handle( cli, mem_ctx, &hSCM  );
		
	return werror_to_ntstatus(result);
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


