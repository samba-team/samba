
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Paul Ashton                  1997-1999.
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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/*******************************************************************
 make_wks_q_query_info
 ********************************************************************/

BOOL make_wks_q_query_info(WKS_Q_QUERY_INFO *q_u,
				char *server, uint16 switch_value)  
{
	DEBUG(5,("make_wks_q_query_info\n"));

	make_buf_unistr2(&(q_u->uni_srv_name), &(q_u->ptr_srv_name), server);
	q_u->switch_value = switch_value;

	return True;
}

/*******************************************************************
 Reads or writes a WKS_Q_QUERY_INFO structure.
********************************************************************/

BOOL wks_io_q_query_info(char *desc, WKS_Q_QUERY_INFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "wks_io_q_query_info");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	if(!smb_io_unistr2("", &q_u->uni_srv_name, q_u->ptr_srv_name, ps, depth))
		return False;
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value));
	prs_align(ps);

	return True;
}

/*******************************************************************
 wks_info_100
 ********************************************************************/

BOOL make_wks_info_100(WKS_INFO_100 *inf,
				uint32 platform_id, uint32 ver_major, uint32 ver_minor,
				char *my_name, char *domain_name)
{
	DEBUG(5,("WKS_INFO_100: %d\n", __LINE__));

	inf->platform_id = platform_id; /* 0x0000 01f4 - unknown */
	inf->ver_major   = ver_major;   /* os major version */
	inf->ver_minor   = ver_minor;   /* os minor version */

	make_buf_unistr2(&(inf->uni_compname), &(inf->ptr_compname), my_name    );
	make_buf_unistr2(&(inf->uni_lan_grp ), &(inf->ptr_lan_grp ), domain_name);

	return True;
}

/*******************************************************************
 Reads or writes a WKS_INFO_100 structure.
********************************************************************/

static BOOL wks_io_wks_info_100(char *desc, WKS_INFO_100 *inf, prs_struct *ps, int depth)
{
	if (inf == NULL)
		return False;

	prs_debug(ps, depth, desc, "wks_io_wks_info_100");
	depth++;

	prs_align(ps);

	prs_uint32("platform_id ", ps, depth, &(inf->platform_id )); /* 0x0000 01f4 - unknown */
	prs_uint32("ptr_compname", ps, depth, &(inf->ptr_compname)); /* pointer to computer name */
	prs_uint32("ptr_lan_grp ", ps, depth, &(inf->ptr_lan_grp )); /* pointer to LAN group name */
	prs_uint32("ver_major   ", ps, depth, &(inf->ver_major   )); /* 4 - major os version */
	prs_uint32("ver_minor   ", ps, depth, &(inf->ver_minor   )); /* 0 - minor os version */

	if(!smb_io_unistr2("", &inf->uni_compname, inf->ptr_compname, ps, depth))
		return False;
	prs_align(ps);

	if(!smb_io_unistr2("", &inf->uni_lan_grp, inf->ptr_lan_grp , ps, depth))
		return False;
	prs_align(ps);

	return True;
}

/*******************************************************************
 make_wks_r_query_info

 only supports info level 100 at the moment.

 ********************************************************************/

BOOL make_wks_r_query_info(WKS_R_QUERY_INFO *r_u,
				uint32 switch_value, WKS_INFO_100 *wks100,
				int status)  
{
	DEBUG(5,("make_wks_r_unknown_0: %d\n", __LINE__));

	r_u->switch_value = switch_value;  /* same as in request */

	r_u->ptr_1     = 1;          /* pointer 1 */
	r_u->wks100    = wks100;

	r_u->status    = status;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL wks_io_r_query_info(char *desc,  WKS_R_QUERY_INFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "wks_io_r_query_info");
	depth++;

	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(r_u->switch_value)); /* level 100 (0x64) */
	prs_align(ps);

	prs_uint32("ptr_1       ", ps, depth, &(r_u->ptr_1       )); /* pointer 1 */
	if(!wks_io_wks_info_100("inf", r_u->wks100, ps, depth))
		return False;

	prs_uint32("status      ", ps, depth, &(r_u->status));

	return True;
}

