/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
********************************************************************/

static bool svcctl_io_service_status( const char *desc, struct SERVICE_STATUS *status, prs_struct *ps, int depth )
{

	prs_debug(ps, depth, desc, "svcctl_io_service_status");
	depth++;

	if(!prs_uint32("type", ps, depth, &status->type))
		return False;

	if(!prs_uint32("state", ps, depth, &status->state))
		return False;

	if(!prs_uint32("controls_accepted", ps, depth, &status->controls_accepted))
		return False;

	if(!prs_werror("win32_exit_code", ps, depth, &status->win32_exit_code))
		return False;

	if(!prs_uint32("service_exit_code", ps, depth, &status->service_exit_code))
		return False;

	if(!prs_uint32("check_point", ps, depth, &status->check_point))
		return False;

	if(!prs_uint32("wait_hint", ps, depth, &status->wait_hint))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

bool svcctl_io_enum_services_status( const char *desc, ENUM_SERVICES_STATUS *enum_status, RPC_BUFFER *buffer, int depth )
{
	prs_struct *ps=&buffer->prs;
	
	prs_debug(ps, depth, desc, "svcctl_io_enum_services_status");
	depth++;
	
	if ( !smb_io_relstr("servicename", buffer, depth, &enum_status->servicename) )
		return False;
	if ( !smb_io_relstr("displayname", buffer, depth, &enum_status->displayname) )
		return False;

	if ( !svcctl_io_service_status("svc_status", &enum_status->status, ps, depth) )
		return False;
	
	return True;
}

/*******************************************************************
********************************************************************/

uint32 svcctl_sizeof_enum_services_status( ENUM_SERVICES_STATUS *status )
{
	uint32 size = 0;
	
	size += size_of_relative_string( &status->servicename );
	size += size_of_relative_string( &status->displayname );
	size += sizeof(struct SERVICE_STATUS);

	return size;
}

/*******************************************************************
********************************************************************/

bool svcctl_io_q_enum_services_status(const char *desc, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_enum_services_status");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("scm_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("type", ps, depth, &q_u->type))
		return False;
	if(!prs_uint32("state", ps, depth, &q_u->state))
		return False;
	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	if(!prs_pointer("resume", ps, depth, (void*)&q_u->resume, sizeof(uint32), (PRS_POINTER_CAST)prs_uint32))
		return False;
	
	return True;
}

/*******************************************************************
********************************************************************/

bool svcctl_io_r_enum_services_status(const char *desc, SVCCTL_R_ENUM_SERVICES_STATUS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_enum_services_status");
	depth++;

	if(!prs_align(ps))
		return False;

	if (!prs_rpcbuffer("", ps, depth, &r_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
	if(!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;

	if(!prs_pointer("resume", ps, depth, (void*)&r_u->resume, sizeof(uint32), (PRS_POINTER_CAST)prs_uint32))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}
