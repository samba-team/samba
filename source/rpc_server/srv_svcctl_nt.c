/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Gerald (Jerry) Carter             2004
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

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV


/********************************************************************
********************************************************************/

NTSTATUS _svcctl_open_scmanager(pipes_struct *p, SVCCTL_Q_OPEN_SCMANAGER *q_u, SVCCTL_R_OPEN_SCMANAGER *r_u)
{
	/* just fake it for now */
	
	if ( !create_policy_hnd( p, &r_u->handle, NULL, NULL ) )
		return NT_STATUS_ACCESS_DENIED;
	
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

NTSTATUS _svcctl_open_service(pipes_struct *p, SVCCTL_Q_OPEN_SERVICE *q_u, SVCCTL_R_OPEN_SERVICE *r_u)
{
	return NT_STATUS_ACCESS_DENIED;
}

/********************************************************************
********************************************************************/

NTSTATUS _svcctl_close_service(pipes_struct *p, SVCCTL_Q_CLOSE_SERVICE *q_u, SVCCTL_R_CLOSE_SERVICE *r_u)
{
	if ( !close_policy_hnd( p, &q_u->handle ) )
		return NT_STATUS_INVALID_HANDLE;
	
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

NTSTATUS _svcctl_get_display_name(pipes_struct *p, SVCCTL_Q_GET_DISPLAY_NAME *q_u, SVCCTL_R_GET_DISPLAY_NAME *r_u)
{
	fstring service;
	fstring displayname;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);

	DEBUG(10,("_svcctl_get_display_name: service name [%s]\n", service));

	if ( !strequal( service, "NETLOGON" ) )
		return NT_STATUS_ACCESS_DENIED;

	fstrcpy( displayname, "Net Logon");
	init_svcctl_r_get_display_name( r_u, displayname );

	return NT_STATUS_OK;
}
