/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Gerald (Jerry) Carter             2004.
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

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
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

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
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

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
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

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}

