/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005.
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
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
********************************************************************/

static BOOL svcctl_io_service_status( const char *desc, SERVICE_STATUS *status, prs_struct *ps, int depth )
{

	prs_debug(ps, depth, desc, "svcctl_io_service_status");
	depth++;

	if(!prs_uint32("type", ps, depth, &status->type))
		return False;

	if(!prs_uint32("state", ps, depth, &status->state))
		return False;

	if(!prs_uint32("controls_accepted", ps, depth, &status->controls_accepted))
		return False;

	if(!prs_uint32("win32_exit_code", ps, depth, &status->win32_exit_code))
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

static BOOL svcctl_io_service_config( const char *desc, SERVICE_CONFIG *config, prs_struct *ps, int depth )
{

	prs_debug(ps, depth, desc, "svcctl_io_service_config");
	depth++;

	if(!prs_uint32("service_type", ps, depth, &config->service_type))
		return False;
	if(!prs_uint32("start_type", ps, depth, &config->start_type))
		return False;
	if(!prs_uint32("error_control", ps, depth, &config->error_control))
		return False;

	if (!prs_io_unistr2_p("", ps, depth, &config->executablepath))
		return False;
	if (!prs_io_unistr2_p("", ps, depth, &config->loadordergroup))
		return False;

	if(!prs_uint32("tag_id", ps, depth, &config->tag_id))
		return False;

	if (!prs_io_unistr2_p("", ps, depth, &config->dependencies))
		return False;
	if (!prs_io_unistr2_p("", ps, depth, &config->startname))
		return False;
	if (!prs_io_unistr2_p("", ps, depth, &config->displayname))
		return False;

	if (!prs_io_unistr2("", ps, depth, config->executablepath))
		return False;
	if (!prs_io_unistr2("", ps, depth, config->loadordergroup))
		return False;
	if (!prs_io_unistr2("", ps, depth, config->dependencies))
		return False;
	if (!prs_io_unistr2("", ps, depth, config->startname))
		return False;
	if (!prs_io_unistr2("", ps, depth, config->displayname))
		return False;

	return True;
}
/*******************************************************************
********************************************************************/

BOOL svcctl_io_service_description( const char *desc, UNISTR2 *svcdesc, prs_struct *ps, int depth )
{

	prs_debug(ps, depth, desc, "svcctl_io_service_description");
	depth++;

	if (!prs_io_unistr2("", ps, depth, svcdesc))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

BOOL svcctl_io_enum_services_status( const char *desc, ENUM_SERVICES_STATUS *enum_status, RPC_BUFFER *buffer, int depth )
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
	size += sizeof(SERVICE_STATUS);

	return size;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_close_service(const char *desc, SVCCTL_Q_CLOSE_SERVICE *q_u, prs_struct *ps, int depth)
{
        
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_close_service");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("scm_pol", &q_u->handle, ps, depth))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_close_service(const char *desc, SVCCTL_R_CLOSE_SERVICE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_close_service");
	depth++;

	if(!prs_align(ps))
	    return False;

	if(!smb_io_pol_hnd("pol_handle", &r_u->handle, ps, depth))
	   return False; 

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_open_scmanager(const char *desc, SVCCTL_Q_OPEN_SCMANAGER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_open_scmanager");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_pointer("servername", ps, depth, (void**)&q_u->servername, sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_pointer("database", ps, depth, (void**)&q_u->database, sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("access", ps, depth, &q_u->access))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_open_scmanager(const char *desc, SVCCTL_R_OPEN_SCMANAGER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_open_scmanager");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("scm_pol", &r_u->handle, ps, depth))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_get_display_name(const char *desc, SVCCTL_Q_GET_DISPLAY_NAME *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_get_display_name");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("scm_pol", &q_u->handle, ps, depth))
		return False;

	if(!smb_io_unistr2("servicename", &q_u->servicename, 1, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("display_name_len", ps, depth, &q_u->display_name_len))
		return False;
	
	return True;
}

/*******************************************************************
********************************************************************/

BOOL init_svcctl_r_get_display_name( SVCCTL_R_GET_DISPLAY_NAME *r_u, const char *displayname )
{
	r_u->display_name_len = strlen(displayname);
	init_unistr2( &r_u->displayname, displayname, UNI_STR_TERMINATE );

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_get_display_name(const char *desc, SVCCTL_R_GET_DISPLAY_NAME *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_get_display_name");
	depth++;

	if(!prs_align(ps))
		return False;

	
	if(!smb_io_unistr2("displayname", &r_u->displayname, 1, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("display_name_len", ps, depth, &r_u->display_name_len))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_open_service(const char *desc, SVCCTL_Q_OPEN_SERVICE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_open_service");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("scm_pol", &q_u->handle, ps, depth))
		return False;

	if(!smb_io_unistr2("servicename", &q_u->servicename, 1, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("access", ps, depth, &q_u->access))
		return False;
	
	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_open_service(const char *desc, SVCCTL_R_OPEN_SERVICE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_open_service");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &r_u->handle, ps, depth))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_query_status(const char *desc, SVCCTL_Q_QUERY_STATUS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_query_status");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;
	
	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_query_status(const char *desc, SVCCTL_R_QUERY_STATUS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_query_status");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!svcctl_io_service_status("service_status", &r_u->svc_status, ps, depth))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_enum_services_status(const char *desc, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, prs_struct *ps, int depth)
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

	if(!prs_pointer("resume", ps, depth, (void**)&q_u->resume, sizeof(uint32), (PRS_POINTER_CAST)prs_uint32))
		return False;
	
	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_enum_services_status(const char *desc, SVCCTL_R_ENUM_SERVICES_STATUS *r_u, prs_struct *ps, int depth)
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

	if(!prs_pointer("resume", ps, depth, (void**)&r_u->resume, sizeof(uint32), (PRS_POINTER_CAST)prs_uint32))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_start_service(const char *desc, SVCCTL_Q_START_SERVICE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_start_service");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("parmcount", ps, depth, &q_u->parmcount))
		return False;

	if ( !prs_pointer("rights", ps, depth, (void**)&q_u->parameters, sizeof(UNISTR4_ARRAY), (PRS_POINTER_CAST)prs_unistr4_array) )
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_start_service(const char *desc, SVCCTL_R_START_SERVICE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_start_service");
	depth++;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_enum_dependent_services(const char *desc, SVCCTL_Q_ENUM_DEPENDENT_SERVICES *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_enum_dependent_services");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("state", ps, depth, &q_u->state))
		return False;
	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_enum_dependent_services(const char *desc, SVCCTL_R_ENUM_DEPENDENT_SERVICES *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_enum_dependent_services");
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

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_control_service(const char *desc, SVCCTL_Q_CONTROL_SERVICE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_control_service");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("control", ps, depth, &q_u->control))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_control_service(const char *desc, SVCCTL_R_CONTROL_SERVICE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_control_service");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!svcctl_io_service_status("service_status", &r_u->svc_status, ps, depth))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_query_service_config(const char *desc, SVCCTL_Q_QUERY_SERVICE_CONFIG *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_query_service_config");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_query_service_config(const char *desc, SVCCTL_R_QUERY_SERVICE_CONFIG *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_query_service_config");
	depth++;


	if(!prs_align(ps))
		return False;

	if(!svcctl_io_service_config("config", &r_u->config, ps, depth))
		return False;

	if(!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;


 	return True;
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_query_service_config2(const char *desc, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_query_service_config2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("info_level", ps, depth, &q_u->info_level))
		return False;

	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	return True;
}


/*******************************************************************
 Creates a service description response buffer.
 The format seems to be DWORD:length of buffer
                        DWORD:offset (fixed as four)
                        UNISTR: unicode description in the rest of the buffer
********************************************************************/

void init_service_description_buffer(RPC_DATA_BLOB *str,  const char *service_desc, int blob_length)
{
	uint32 offset;
	char *bp;

	ZERO_STRUCTP(str);

	offset = 4;

	/* set up string lengths. */

	str->buf_len = create_rpc_blob(str, blob_length);
	DEBUG(10, ("init_service_description buffer: Allocated a blob of [%d] \n",str->buf_len));

	if ( str && str->buffer && str->buf_len) {
		memset(str->buffer,0,str->buf_len);
		memcpy(str->buffer, &offset, sizeof(uint32));
		bp = &str->buffer[4];
		if (service_desc) {
			rpcstr_push(bp, service_desc,str->buf_len-4,0);
		}
	}
}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_q_query_service_status_ex(const char *desc, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_q_query_service_status_ex");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("service_pol", &q_u->handle, ps, depth))
		return False;

	if(!prs_uint32("info_level", ps, depth, &q_u->info_level))
		return False;

	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;

	return True;

}

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_query_service_status_ex(const char *desc, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u, prs_struct *ps, int depth)
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

/*******************************************************************
********************************************************************/

BOOL svcctl_io_r_query_service_config2(const char *desc, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u, prs_struct *ps, int depth)
{
	if ( !r_u )
		return False;

	prs_debug(ps, depth, desc, "svcctl_io_r_query_service_config2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;

	if (r_u->returned > 4) {
		if (!prs_uint32("offset", ps, depth, &r_u->offset))
			return False;
		if(!prs_unistr2(True, "description     ", ps, depth, r_u->description))
			return False;
		if(!prs_align(ps))
			return False;
	} else {
		/* offset does double duty here */
		r_u->offset = 0;
		if (!prs_uint32("offset", ps, depth, &r_u->offset))
			return False;
	}

	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}


