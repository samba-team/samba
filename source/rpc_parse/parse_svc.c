
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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

extern int DEBUGLEVEL;

/*******************************************************************
 make_svc_q_open_policy
 ********************************************************************/
void make_svc_q_open_policy(SVC_Q_OPEN_POLICY *q_u,
				char *server, uint16 unknown)  
{
	DEBUG(5,("make_svc_q_open_policy\n"));

	make_buf_unistr2(&(q_u->uni_srv_name), &(q_u->ptr_srv_name), server);
	q_u->unknown = unknown;

}

/*******************************************************************
reads or writes a SVC_Q_OPEN_POLICY structure.
********************************************************************/
void svc_io_q_open_policy(char *desc, SVC_Q_OPEN_POLICY *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_open_policy");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	smb_io_unistr2("", &(q_u->uni_srv_name), q_u->ptr_srv_name, ps, depth); 
	prs_align(ps);

	prs_uint32("unknown", ps, depth, &(q_u->unknown));
	prs_align(ps);
}

/*******************************************************************
 make_svc_r_open_policy
 ********************************************************************/
void make_svc_r_open_policy(SVC_R_OPEN_POLICY *r_u, POLICY_HND *hnd,
				uint32 status)  
{
	DEBUG(5,("make_svc_r_unknown_0: %d\n", __LINE__));

	memcpy(&(r_u->pol), hnd, sizeof(r_u->pol));
	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_open_policy(char *desc,  SVC_R_OPEN_POLICY *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_open_policy");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth);

	prs_uint32("status      ", ps, depth, &(r_u->status));
}

/*******************************************************************
makes an SVC_Q_CLOSE structure.
********************************************************************/
void make_svc_q_close(SVC_Q_CLOSE *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_svc_q_close\n"));

}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_q_close(char *desc,  SVC_Q_CLOSE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_close");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->pol), ps, depth); 
	prs_align(ps);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_close(char *desc,  SVC_R_CLOSE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_close");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

