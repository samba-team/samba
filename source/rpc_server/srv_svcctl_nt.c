/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005
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

WERROR _svcctl_open_scmanager(pipes_struct *p, SVCCTL_Q_OPEN_SCMANAGER *q_u, SVCCTL_R_OPEN_SCMANAGER *r_u)
{
	/* just fake it for now */
	
	if ( !create_policy_hnd( p, &r_u->handle, NULL, NULL ) )
		return WERR_ACCESS_DENIED;
	
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_open_service(pipes_struct *p, SVCCTL_Q_OPEN_SERVICE *q_u, SVCCTL_R_OPEN_SERVICE *r_u)
{
	fstring service;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);

	if ( !(strequal( service, "NETLOGON") || strequal(service, "Spooler")) )
		return WERR_NO_SUCH_SERVICE;

	if ( !create_policy_hnd( p, &r_u->handle, NULL, NULL ) )
		return WERR_ACCESS_DENIED;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_close_service(pipes_struct *p, SVCCTL_Q_CLOSE_SERVICE *q_u, SVCCTL_R_CLOSE_SERVICE *r_u)
{
	if ( !close_policy_hnd( p, &q_u->handle ) )
		return WERR_BADFID;
	
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_get_display_name(pipes_struct *p, SVCCTL_Q_GET_DISPLAY_NAME *q_u, SVCCTL_R_GET_DISPLAY_NAME *r_u)
{
	fstring service;
	fstring displayname;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);

	DEBUG(10,("_svcctl_get_display_name: service name [%s]\n", service));

	if ( !strequal( service, "NETLOGON" ) )
		return WERR_ACCESS_DENIED;

	fstrcpy( displayname, "Net Logon");
	init_svcctl_r_get_display_name( r_u, displayname );

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_status(pipes_struct *p, SVCCTL_Q_QUERY_STATUS *q_u, SVCCTL_R_QUERY_STATUS *r_u)
{

	r_u->svc_status.type = 0x0110;
	r_u->svc_status.state = 0x0004;
	r_u->svc_status.controls_accepted = 0x0005;

	return WERR_OK;
}
