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

	if(!prs_uint32("srv_ptr", ps, depth, &q_u->ptr_srv))
		return False;
	if(!smb_io_unistr2("", &q_u->servername, q_u->ptr_srv, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("db_ptr", ps, depth, &q_u->ptr_db))
		return False;
	if(!smb_io_unistr2("", &q_u->database, q_u->ptr_db, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("access_mask", ps, depth, &q_u->access_mask))
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

	if(!smb_io_unistr2("", &q_u->servicename, 1, ps, depth))
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

	
	if(!smb_io_unistr2("", &r_u->displayname, 1, ps, depth))
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

	if(!smb_io_unistr2("", &q_u->servicename, 1, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("access_mask", ps, depth, &q_u->access_mask))
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

static BOOL svcctl_io_service_status( const char *desc, SERVICE_STATUS *status, prs_struct *ps, int depth )
{

	prs_debug(ps, depth, desc, "svcctl_io_r_query_status");
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
