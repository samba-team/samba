
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
 make_svc_q_open_sc_man
 ********************************************************************/
void make_svc_q_open_sc_man(SVC_Q_OPEN_SC_MAN *q_u,
				char *server, char *database,
				uint32 des_access)  
{
	DEBUG(5,("make_svc_q_open_sc_man\n"));

	make_buf_unistr2(&(q_u->uni_srv_name), &(q_u->ptr_srv_name), server);
	make_buf_unistr2(&(q_u->uni_db_name ), &(q_u->ptr_db_name), database);
	q_u->des_access = des_access;

}

/*******************************************************************
reads or writes a SVC_Q_OPEN_SC_MAN structure.
********************************************************************/
void svc_io_q_open_sc_man(char *desc, SVC_Q_OPEN_SC_MAN *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_open_sc_man");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	smb_io_unistr2("", &(q_u->uni_srv_name), q_u->ptr_srv_name, ps, depth); 
	prs_align(ps);

	prs_uint32("ptr_db_name", ps, depth, &(q_u->ptr_db_name));
	smb_io_unistr2("", &(q_u->uni_db_name), q_u->ptr_db_name, ps, depth); 
	prs_align(ps);

	prs_uint32("des_access", ps, depth, &(q_u->des_access));
	prs_align(ps);
}

/*******************************************************************
 make_svc_r_open_sc_man
 ********************************************************************/
void make_svc_r_open_sc_man(SVC_R_OPEN_SC_MAN *r_u, POLICY_HND *hnd,
				uint32 status)  
{
	DEBUG(5,("make_svc_r_unknown_0: %d\n", __LINE__));

	memcpy(&(r_u->pol), hnd, sizeof(r_u->pol));
	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_open_sc_man(char *desc,  SVC_R_OPEN_SC_MAN *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_open_sc_man");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth);

	prs_uint32("status      ", ps, depth, &(r_u->status));
}

/*******************************************************************
makes an SVC_Q_ENUM_SVCS_STATUS structure.
********************************************************************/
void make_svc_q_enum_svcs_status(SVC_Q_ENUM_SVCS_STATUS *q_c, POLICY_HND *hnd,
				uint32 service_type, uint32 service_state,
				uint32 buf_size, uint32 resume_hnd )
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_svc_q_enum_svcs_status\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
	q_c->service_type = service_type;
	q_c->service_state = service_state;
	q_c->buf_size = buf_size;
	make_enum_hnd(&q_c->resume_hnd, resume_hnd);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_q_enum_svcs_status(char *desc,  SVC_Q_ENUM_SVCS_STATUS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_enum_svcs_status");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("service_type ", ps, depth, &(q_u->service_type ));
	prs_uint32("service_state", ps, depth, &(q_u->service_state));
	prs_uint32("buf_size     ", ps, depth, &(q_u->buf_size     ));
	smb_io_enum_hnd("resume_hnd", &(q_u->resume_hnd), ps, depth); 
}

/*******************************************************************
makes an SVC_Q_CLOSE structure.
********************************************************************/
void make_svc_q_close(SVC_Q_CLOSE *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_svc_q_close\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
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

#if 0
/*******************************************************************
reads or writes a SEC_DESC_BUF structure.
********************************************************************/
void sec_io_desc_buf(char *desc, SEC_DESC_BUF *sec, prs_struct *ps, int depth)
{
	uint32 off_len;
	uint32 old_offset;
	uint32 size;

	if (sec == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_desc_buf");
	depth++;

	prs_align(ps);
	
	prs_uint32_pre("max_len", ps, depth, &(sec->max_len), &off_max_len);

	old_offset = ps->offset;

	if (sec->len != 0 && ps->io)
	{
		/* reading */
		sec->sec = malloc(sizeof(*sec->sec));
		ZERO_STRUCTP(sec->sec);

		if (sec->sec == NULL)
		{
			DEBUG(0,("INVALID SEC_DESC\n"));
			ps->offset = 0xfffffffe;
			return;
		}
	}

	/* reading, length is non-zero; writing, descriptor is non-NULL */
	if ((sec->len != 0 || (!ps->io)) && sec->sec != NULL)
	{
		sec_io_desc("sec   ", sec->sec, ps, depth);
	}

	size = ps->offset - old_offset;
	prs_uint32_post("max_len", ps, depth, &(sec->max_len), off_max_len, size == 0 ? sec->max_len : size);
}
#endif
