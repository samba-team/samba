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

static bool svcctl_io_service_status( const char *desc, SERVICE_STATUS *status, prs_struct *ps, int depth )
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

bool svcctl_io_service_status_process( const char *desc, SERVICE_STATUS_PROCESS *status, RPC_BUFFER *buffer, int depth )
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "svcctl_io_service_status_process");
	depth++;

	if ( !svcctl_io_service_status("status", &status->status, ps, depth) )
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("process_id", ps, depth, &status->process_id))
		return False;
	if(!prs_uint32("service_flags", ps, depth, &status->service_flags))
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
	size += sizeof(SERVICE_STATUS);

	return size;
}

/********************************************************************
********************************************************************/

static uint32 sizeof_unistr2( UNISTR2 *string )
{
	uint32 size = 0;

	if ( !string ) 
		return 0;	

	size  = sizeof(uint32) * 3;		/* length fields */
	size += 2 * string->uni_max_len;	/* string data */
	size += size % 4;			/* alignment */

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

/*******************************************************************
********************************************************************/

bool svcctl_io_q_query_service_config2(const char *desc, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_query_service_config2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

void init_service_description_buffer(SERVICE_DESCRIPTION *desc, const char *service_desc )
{
	desc->unknown = 0x04;	/* always 0x0000 0004 (no idea what this is) */
	init_unistr( &desc->description, service_desc );
}

/*******************************************************************
********************************************************************/

bool svcctl_io_service_description( const char *desc, SERVICE_DESCRIPTION *description, RPC_BUFFER *buffer, int depth )
{
        prs_struct *ps = &buffer->prs;

        prs_debug(ps, depth, desc, "svcctl_io_service_description");
        depth++;

	if ( !prs_uint32("unknown", ps, depth, &description->unknown) )
		return False;
	if ( !prs_unistr("description", ps, depth, &description->description) )
		return False;

	return True;
} 

/*******************************************************************
********************************************************************/

uint32 svcctl_sizeof_service_description( SERVICE_DESCRIPTION *desc )
{
	if ( !desc )
		return 0;

	/* make sure to include the terminating NULL */
	return ( sizeof(uint32) + (2*(str_len_uni(&desc->description)+1)) );
}

/*******************************************************************
********************************************************************/

static bool svcctl_io_action( const char *desc, SC_ACTION *action, prs_struct *ps, int depth )
{

	prs_debug(ps, depth, desc, "svcctl_io_action");
	depth++;

	if ( !prs_uint32("type", ps, depth, &action->type) )
		return False;
	if ( !prs_uint32("delay", ps, depth, &action->delay) )
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

bool svcctl_io_service_fa( const char *desc, SERVICE_FAILURE_ACTIONS *fa, RPC_BUFFER *buffer, int depth )
{
        prs_struct *ps = &buffer->prs;
	int i;

        prs_debug(ps, depth, desc, "svcctl_io_service_description");
        depth++;

	if ( !prs_uint32("reset_period", ps, depth, &fa->reset_period) )
		return False;

	if ( !prs_pointer( desc, ps, depth, (void*)&fa->rebootmsg, sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2 ) )
		return False;
	if ( !prs_pointer( desc, ps, depth, (void*)&fa->command, sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2 ) )
		return False;

	if ( !prs_uint32("num_actions", ps, depth, &fa->num_actions) )
		return False;

	if ( UNMARSHALLING(ps)) {
		if (fa->num_actions) {
			if ( !(fa->actions = TALLOC_ARRAY( talloc_tos(), SC_ACTION, fa->num_actions )) ) {
				DEBUG(0,("svcctl_io_service_fa: talloc() failure!\n"));
				return False;
			}
		} else {
			fa->actions = NULL;
		}
	}

	for ( i=0; i<fa->num_actions; i++ ) {
		if ( !svcctl_io_action( "actions", &fa->actions[i], ps, depth ) )
			return False;
	}

	return True;
} 

/*******************************************************************
********************************************************************/

uint32 svcctl_sizeof_service_fa( SERVICE_FAILURE_ACTIONS *fa)
{
	uint32 size = 0;

	if ( !fa )
		return 0;

	size  = sizeof(uint32) * 2;
	size += sizeof_unistr2( fa->rebootmsg );
	size += sizeof_unistr2( fa->command );
	size += sizeof(SC_ACTION) * fa->num_actions;

	return size;
}

/*******************************************************************
********************************************************************/

bool svcctl_io_r_query_service_config2(const char *desc, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u, prs_struct *ps, int depth)
{
	if ( !r_u )
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_query_service_config2");
	depth++;

	if ( !prs_align(ps) )
		return False;

	if (!prs_rpcbuffer("", ps, depth, &r_u->buffer))
		return False;
	if(!prs_align(ps))
		return False;

	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

bool svcctl_io_q_query_service_status_ex(const char *desc, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_query_service_status_ex");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	return True;

}

/*******************************************************************
********************************************************************/

bool svcctl_io_r_query_service_status_ex(const char *desc, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u, prs_struct *ps, int depth)
{
	if ( !r_u )
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_query_service_status_ex");
	depth++;

	if (!prs_rpcbuffer("", ps, depth, &r_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}
