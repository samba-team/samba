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
#include "nterr.h"

extern int DEBUGLEVEL;


/*******************************************************************
makes a SAMR_Q_CLOSE_HND structure.
********************************************************************/
BOOL make_samr_q_close_hnd(SAMR_Q_CLOSE_HND *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_close_hnd\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_close_hnd(char *desc,  SAMR_Q_CLOSE_HND *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_close_hnd");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_close_hnd(char *desc,  SAMR_R_CLOSE_HND *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_close_hnd");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_LOOKUP_DOMAIN structure.
********************************************************************/
BOOL make_samr_q_lookup_domain(SAMR_Q_LOOKUP_DOMAIN *q_u,
		POLICY_HND *pol, const char *dom_name)
{
	int len_name = strlen(dom_name);

	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_lookup_domain\n"));

	memcpy(&(q_u->connect_pol), pol, sizeof(*pol));

	make_uni_hdr(&(q_u->hdr_domain), len_name);
	make_unistr2(&(q_u->uni_domain), dom_name, len_name);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_lookup_domain(char *desc, SAMR_Q_LOOKUP_DOMAIN *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_lookup_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(q_u->connect_pol), ps, depth);
	prs_align(ps);

	smb_io_unihdr("hdr_domain", &(q_u->hdr_domain), ps, depth);
	smb_io_unistr2("uni_domain", &(q_u->uni_domain),
		       q_u->hdr_domain.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAMR_R_LOOKUP_DOMAIN structure.
********************************************************************/
BOOL make_samr_r_lookup_domain(SAMR_R_LOOKUP_DOMAIN *r_u,
		DOM_SID *dom_sid, uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_lookup_domain\n"));

	r_u->status = status;
	r_u->ptr_sid = 0;
	if (status == 0x0)
	{
		r_u->ptr_sid = 1;
		make_dom_sid2(&(r_u->dom_sid), dom_sid);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_lookup_domain(char *desc, SAMR_R_LOOKUP_DOMAIN *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_lookup_domain");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr_sid));

	if (r_u->ptr_sid != 0)
	{
		smb_io_dom_sid2("sid", &(r_u->dom_sid), ps, depth);
		prs_align(ps);
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_samr_q_open_domain(SAMR_Q_OPEN_DOMAIN *q_u,
				const POLICY_HND *connect_pol, uint32 flags,
				const DOM_SID *sid)
{
	if (q_u == NULL) return False;

	DEBUG(5,("samr_make_samr_q_open_domain\n"));

	memcpy(&q_u->connect_pol, connect_pol, sizeof(q_u->connect_pol));
	q_u->flags = flags;
	make_dom_sid2(&(q_u->dom_sid), sid);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_domain(char *desc,  SAMR_Q_OPEN_DOMAIN *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_open_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(q_u->connect_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("flags", ps, depth, &(q_u->flags));

	smb_io_dom_sid2("sid", &(q_u->dom_sid), ps, depth); 
	prs_align(ps);

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_domain(char *desc,  SAMR_R_OPEN_DOMAIN *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_open_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(r_u->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_samr_q_get_usrdom_pwinfo(SAMR_Q_GET_USRDOM_PWINFO *q_u, POLICY_HND *user_pol)
{
	if (q_u == NULL) return False;

	DEBUG(5,("samr_make_samr_q_get_usrdom_pwinfo\n"));

	memcpy(&q_u->user_pol, user_pol, sizeof(q_u->user_pol));

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_get_usrdom_pwinfo(char *desc,  SAMR_Q_GET_USRDOM_PWINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_get_usrdom_pwinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(q_u->user_pol), ps, depth); 
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_samr_r_get_usrdom_pwinfo(SAMR_R_GET_USRDOM_PWINFO *q_u, uint32 status)
{
	if (q_u == NULL) return False;

	DEBUG(5,("samr_make_r_get_usrdom_pwinfo\n"));

	q_u->unknown_0 = 0x00150000;
	q_u->unknown_1 = 0x00000000;
	q_u->status    = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_get_usrdom_pwinfo(char *desc,  SAMR_R_GET_USRDOM_PWINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_get_usrdom_pwinfo");
	depth++;

	prs_align(ps);

	prs_uint32("unknown_0", ps, depth, &(r_u->unknown_0));
	prs_uint32("unknown_1", ps, depth, &(r_u->unknown_1));
	prs_uint32("status   ", ps, depth, &(r_u->status   ));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_samr_q_query_sec_obj(SAMR_Q_QUERY_SEC_OBJ *q_u,
				const POLICY_HND *user_pol, uint32 sec_info)
{
	if (q_u == NULL) return False;

	DEBUG(5,("samr_make_samr_q_query_sec_obj\n"));

	memcpy(&q_u->user_pol, user_pol, sizeof(q_u->user_pol));
	q_u->sec_info = sec_info;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_sec_obj(char *desc,  SAMR_Q_QUERY_SEC_OBJ *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_sec_obj");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(q_u->user_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("sec_info", ps, depth, &(q_u->sec_info));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_samr_q_query_dom_info(SAMR_Q_QUERY_DOMAIN_INFO *q_u,
				POLICY_HND *domain_pol, uint16 switch_value)
{
	if (q_u == NULL) return False;

	DEBUG(5,("samr_make_samr_q_query_dom_info\n"));

	memcpy(&q_u->domain_pol, domain_pol, sizeof(q_u->domain_pol));
	q_u->switch_value = switch_value;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_dom_info(char *desc,  SAMR_Q_QUERY_DOMAIN_INFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_dom_info");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value));
	prs_align(ps);

	return True;
}


/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_unk_info3(SAM_UNK_INFO_3 *u_3)
{
	if (u_3 == NULL) return False;

	u_3->unknown_0 = 0x00000000;
	u_3->unknown_1 = 0x80000000;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_unk_info3(char *desc, SAM_UNK_INFO_3 *u_3, prs_struct *ps, int depth)
{
	if (u_3 == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_unk_info3");
	depth++;

	prs_uint32("unknown_0", ps, depth, &u_3->unknown_0); /* 0x0000 0000 */
	prs_uint32("unknown_1", ps, depth, &u_3->unknown_1); /* 0x8000 0000 */

	prs_align(ps);


	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_unk_info6(SAM_UNK_INFO_6 *u_6)
{
	if (u_6 == NULL) return False;

	u_6->unknown_0 = 0x00000000;
	u_6->ptr_0 = 1;
	memset(u_6->padding, 0, sizeof(u_6->padding)); /* 12 bytes zeros */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_unk_info6(char *desc, SAM_UNK_INFO_6 *u_6, prs_struct *ps, int depth)
{
	if (u_6 == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_unk_info6");
	depth++;

	prs_uint32("unknown_0", ps, depth, &u_6->unknown_0); /* 0x0000 0000 */
	prs_uint32("ptr_0", ps, depth, &u_6->ptr_0);     /* pointer to unknown structure */
	prs_uint8s(False, "padding", ps, depth, u_6->padding, sizeof(u_6->padding)); /* 12 bytes zeros */

	prs_align(ps);


	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_unk_info7(SAM_UNK_INFO_7 *u_7)
{
	if (u_7 == NULL) return False;

	u_7->unknown_0 = 0x0003;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_unk_info7(char *desc, SAM_UNK_INFO_7 *u_7, prs_struct *ps, int depth)
{
	if (u_7 == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_unk_info7");
	depth++;

	prs_uint16("unknown_0", ps, depth, &u_7->unknown_0); /* 0x0003 */
	prs_align(ps);


	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_unk_info2(SAM_UNK_INFO_2 *u_2, char *domain, char *server)
{
	int len_domain = strlen(domain);
	int len_server = strlen(server);

	if (u_2 == NULL) return False;

	u_2->unknown_0 = 0x00000000;
	u_2->unknown_1 = 0x80000000;
	u_2->unknown_2 = 0x00000000;

	u_2->ptr_0 = 1;
	make_uni_hdr(&(u_2->hdr_domain), len_domain);
	make_uni_hdr(&(u_2->hdr_server), len_server);

	u_2->seq_num = 0x10000000;
	u_2->unknown_3 = 0x00000000;
	
	u_2->unknown_4  = 0x00000001;
	u_2->unknown_5  = 0x00000003;
	u_2->unknown_6  = 0x00000001;
	u_2->num_domain_usrs  = MAX_SAM_ENTRIES;
	u_2->num_domain_grps = MAX_SAM_ENTRIES;
	u_2->num_local_grps = MAX_SAM_ENTRIES;

	memset(u_2->padding, 0, sizeof(u_2->padding)); /* 12 bytes zeros */

	make_unistr2(&u_2->uni_domain, domain, len_domain);
	make_unistr2(&u_2->uni_server, server, len_server);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_unk_info2(char *desc, SAM_UNK_INFO_2 *u_2, prs_struct *ps, int depth)
{
	if (u_2 == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_unk_info2");
	depth++;

	prs_uint32("unknown_0", ps, depth, &u_2->unknown_0); /* 0x0000 0000 */
	prs_uint32("unknown_1", ps, depth, &u_2->unknown_1); /* 0x8000 0000 */
	prs_uint32("unknown_2", ps, depth, &u_2->unknown_2); /* 0x0000 0000 */

	prs_uint32("ptr_0", ps, depth, &u_2->ptr_0);     /* pointer to unknown structure */
	smb_io_unihdr("hdr_domain", &u_2->hdr_domain, ps, depth); /* domain name unicode header */
	smb_io_unihdr("hdr_server", &u_2->hdr_server, ps, depth); /* server name unicode header */

	/* put all the data in here, at the moment, including what the above
	   pointer is referring to
	 */

	prs_uint32("seq_num ", ps, depth, &u_2->seq_num ); /* 0x0000 0099 or 0x1000 0000 */
	prs_uint32("unknown_3 ", ps, depth, &u_2->unknown_3 ); /* 0x0000 0000 */
	
	prs_uint32("unknown_4 ", ps, depth, &u_2->unknown_4 ); /* 0x0000 0001 */
	prs_uint32("unknown_5 ", ps, depth, &u_2->unknown_5 ); /* 0x0000 0003 */
	prs_uint32("unknown_6 ", ps, depth, &u_2->unknown_6 ); /* 0x0000 0001 */
	prs_uint32("num_domain_usrs ", ps, depth, &u_2->num_domain_usrs ); /* 0x0000 0008 */
	prs_uint32("num_domain_grps", ps, depth, &u_2->num_domain_grps); /* 0x0000 0003 */
	prs_uint32("num_local_grps", ps, depth, &u_2->num_local_grps); /* 0x0000 0003 */

	prs_uint8s(False, "padding", ps, depth, u_2->padding, sizeof(u_2->padding)); /* 12 bytes zeros */

	smb_io_unistr2( "uni_domain", &u_2->uni_domain, u_2->hdr_domain.buffer, ps, depth); /* domain name unicode string */
	prs_align(ps);
	smb_io_unistr2( "uni_server", &u_2->uni_server, u_2->hdr_server.buffer, ps, depth); /* server name unicode string */

	prs_align(ps);


	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_unk_info1(SAM_UNK_INFO_1 *u_1)
{
	if (u_1 == NULL) return False;

	memset(u_1->padding, 0, sizeof(u_1->padding)); /* 12 bytes zeros */
	u_1->unknown_1 = 0x80000000;
	u_1->unknown_2 = 0x00000000;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_unk_info1(char *desc, SAM_UNK_INFO_1 *u_1, prs_struct *ps, int depth)
{
	if (u_1 == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_unk_info1");
	depth++;

	prs_uint8s(False, "padding", ps, depth, u_1->padding, sizeof(u_1->padding)); /* 12 bytes zeros */

	prs_uint32("unknown_1", ps, depth, &u_1->unknown_1); /* 0x8000 0000 */
	prs_uint32("unknown_2", ps, depth, &u_1->unknown_2); /* 0x0000 0000 */

	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAMR_R_QUERY_DOMAIN_INFO structure.
********************************************************************/
BOOL make_samr_r_query_dom_info(SAMR_R_QUERY_DOMAIN_INFO *r_u, 
				uint16 switch_value, SAM_UNK_CTR *ctr,
				uint32 status)
{
	if (r_u == NULL || ctr == NULL) return False;

	DEBUG(5,("make_samr_r_query_dom_info\n"));

	r_u->ptr_0 = 0;
	r_u->switch_value = 0;
	r_u->status = status; /* return status */

	if (status == 0)
	{
		r_u->switch_value = switch_value;
		r_u->ptr_0 = 1;
		r_u->ctr = ctr;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_dom_info(char *desc, SAMR_R_QUERY_DOMAIN_INFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_dom_info");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0       ", ps, depth, &(r_u->ptr_0));

	if (r_u->ptr_0 != 0 && r_u->ctr != NULL)
	{
		prs_uint16("switch_value", ps, depth, &(r_u->switch_value));
		prs_align(ps);

		switch (r_u->switch_value)
		{
			case 0x07:
			{
				sam_io_unk_info7("unk_inf7", &r_u->ctr->info.inf7, ps, depth);
				break;
			}
			case 0x06:
			{
				sam_io_unk_info6("unk_inf6", &r_u->ctr->info.inf6, ps, depth);
				break;
			}
			case 0x03:
			{
				sam_io_unk_info3("unk_inf3", &r_u->ctr->info.inf3, ps, depth);
				break;
			}
			case 0x02:
			{
				sam_io_unk_info2("unk_inf2", &r_u->ctr->info.inf2, ps, depth);
				break;
			}
			case 0x01:
			{
				sam_io_unk_info1("unk_inf1", &r_u->ctr->info.inf1, ps, depth);
				break;
			}
			default:
			{
				DEBUG(3,("samr_io_r_query_dom_info: unknown switch level 0x%x\n",
				          r_u->switch_value));
				r_u->status = 0xC0000000|NT_STATUS_INVALID_INFO_CLASS;
				return False;
			}
		}
	}

	prs_uint32("status      ", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
reads or writes a SAMR_R_QUERY_SEC_OBJ structure.

this one's odd, because the daft buggers use a different mechanism
for writing out the array of sids. they put the number of sids in
only one place: they've calculated the length of each sid and jumped
by that amount.  then, retrospectively, the length of the whole buffer
is put at the beginning of the data stream.

wierd.  

********************************************************************/
BOOL samr_io_r_query_sec_obj(char *desc,  SAMR_R_QUERY_SEC_OBJ *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_sec_obj");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	if (r_u->ptr != 0x0)
	{
		sec_io_desc_buf("sec", &r_u->buf, ps, depth);
	}
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
reads or writes a SAM_STR1 structure.
********************************************************************/
static BOOL sam_io_sam_str1(char *desc,  SAM_STR1 *sam, uint32 acct_buf, uint32 name_buf, uint32 desc_buf, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_str1");
	depth++;

	prs_align(ps);

	smb_io_unistr2("unistr2", &(sam->uni_acct_name), acct_buf, ps, depth); /* account name unicode string */
	prs_align(ps);
	smb_io_unistr2("unistr2", &(sam->uni_full_name), name_buf, ps, depth); /* full name unicode string */
	prs_align(ps);
	smb_io_unistr2("unistr2", &(sam->uni_acct_desc), desc_buf, ps, depth); /* account desc unicode string */
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAM_ENTRY1 structure.
********************************************************************/
static BOOL make_sam_entry1(SAM_ENTRY1 *sam, uint32 user_idx, 
				uint32 len_sam_name, uint32 len_sam_full, uint32 len_sam_desc,
				uint32 rid_user, uint16 acb_info)
{
	if (sam == NULL) return False;

	DEBUG(5,("make_sam_entry1\n"));

	sam->user_idx = user_idx;
	sam->rid_user = rid_user;
	sam->acb_info = acb_info;
	sam->pad      = 0;

	make_uni_hdr(&(sam->hdr_acct_name), len_sam_name);
	make_uni_hdr(&(sam->hdr_user_name), len_sam_full);
	make_uni_hdr(&(sam->hdr_user_desc), len_sam_desc);

	return True;
}

/*******************************************************************
reads or writes a SAM_ENTRY1 structure.
********************************************************************/
static BOOL sam_io_sam_entry1(char *desc,  SAM_ENTRY1 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry1");
	depth++;

	prs_align(ps);

	prs_uint32("user_idx ", ps, depth, &(sam->user_idx ));

	prs_uint32("rid_user ", ps, depth, &(sam->rid_user ));
	prs_uint16("acb_info ", ps, depth, &(sam->acb_info ));
	prs_uint16("pad      ", ps, depth, &(sam->pad      ));

	smb_io_unihdr("unihdr", &(sam->hdr_acct_name), ps, depth); /* account name unicode string header */
	smb_io_unihdr("unihdr", &(sam->hdr_user_name), ps, depth); /* account name unicode string header */
	smb_io_unihdr("unihdr", &(sam->hdr_user_desc), ps, depth); /* account name unicode string header */

	return True;
}

/*******************************************************************
reads or writes a SAM_STR2 structure.
********************************************************************/
static BOOL sam_io_sam_str2(char *desc,  SAM_STR2 *sam, uint32 acct_buf, uint32 desc_buf, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_str2");
	depth++;

	prs_align(ps);

	smb_io_unistr2("unistr2", &(sam->uni_srv_name), acct_buf, ps, depth); /* account name unicode string */
	prs_align(ps);
	smb_io_unistr2("unistr2", &(sam->uni_srv_desc), desc_buf, ps, depth); /* account desc unicode string */
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAM_ENTRY2 structure.
********************************************************************/
static BOOL make_sam_entry2(SAM_ENTRY2 *sam, uint32 user_idx, 
				uint32 len_sam_name, uint32 len_sam_desc,
				uint32 rid_user, uint16 acb_info)
{
	if (sam == NULL) return False;

	DEBUG(5,("make_sam_entry2\n"));

	sam->user_idx = user_idx;
	sam->rid_user = rid_user;
	sam->acb_info = acb_info;
	sam->pad      = 0;

	make_uni_hdr(&(sam->hdr_srv_name), len_sam_name);
	make_uni_hdr(&(sam->hdr_srv_desc), len_sam_desc);

	return True;
}

/*******************************************************************
reads or writes a SAM_ENTRY2 structure.
********************************************************************/
static BOOL sam_io_sam_entry2(char *desc,  SAM_ENTRY2 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry2");
	depth++;

	prs_align(ps);

	prs_uint32("user_idx ", ps, depth, &(sam->user_idx ));

	prs_uint32("rid_user ", ps, depth, &(sam->rid_user ));
	prs_uint16("acb_info ", ps, depth, &(sam->acb_info ));
	prs_uint16("pad      ", ps, depth, &(sam->pad      ));

	smb_io_unihdr("unihdr", &(sam->hdr_srv_name), ps, depth); /* account name unicode string header */
	smb_io_unihdr("unihdr", &(sam->hdr_srv_desc), ps, depth); /* account name unicode string header */

	return True;
}

/*******************************************************************
reads or writes a SAM_STR3 structure.
********************************************************************/
static BOOL sam_io_sam_str3(char *desc,  SAM_STR3 *sam, uint32 acct_buf, uint32 desc_buf, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_str3");
	depth++;

	prs_align(ps);

	smb_io_unistr2("unistr2", &(sam->uni_grp_name), acct_buf, ps, depth); /* account name unicode string */
	prs_align(ps);
	smb_io_unistr2("unistr2", &(sam->uni_grp_desc), desc_buf, ps, depth); /* account desc unicode string */
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAM_ENTRY3 structure.
********************************************************************/
static BOOL make_sam_entry3(SAM_ENTRY3 *sam, uint32 grp_idx, 
				uint32 len_grp_name, uint32 len_grp_desc, uint32 rid_grp)
{
	if (sam == NULL) return False;

	DEBUG(5,("make_sam_entry3\n"));

	sam->grp_idx = grp_idx;
	sam->rid_grp = rid_grp;
	sam->attr    = 0x07; /* group rid attributes - gets ignored by nt 4.0 */

	make_uni_hdr(&(sam->hdr_grp_name), len_grp_name);
	make_uni_hdr(&(sam->hdr_grp_desc), len_grp_desc);

	return True;
}

/*******************************************************************
reads or writes a SAM_ENTRY3 structure.
********************************************************************/
static BOOL sam_io_sam_entry3(char *desc,  SAM_ENTRY3 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry3");
	depth++;

	prs_align(ps);

	prs_uint32("grp_idx", ps, depth, &(sam->grp_idx));

	prs_uint32("rid_grp", ps, depth, &(sam->rid_grp));
	prs_uint32("attr   ", ps, depth, &(sam->attr   ));

	smb_io_unihdr("unihdr", &(sam->hdr_grp_name), ps, depth); /* account name unicode string header */
	smb_io_unihdr("unihdr", &(sam->hdr_grp_desc), ps, depth); /* account name unicode string header */

	return True;
}

/*******************************************************************
makes a SAM_ENTRY4 structure.
********************************************************************/
static BOOL make_sam_entry4(SAM_ENTRY4 *sam, uint32 user_idx, 
				uint32 len_acct_name)
{
	if (sam == NULL) return False;

	DEBUG(5,("make_sam_entry4\n"));

	sam->user_idx = user_idx;
	make_str_hdr(&(sam->hdr_acct_name), len_acct_name, len_acct_name,
		     len_acct_name != 0);

	return True;
}

/*******************************************************************
reads or writes a SAM_ENTRY4 structure.
********************************************************************/
static BOOL sam_io_sam_entry4(char *desc, SAM_ENTRY4 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry4");
	depth++;

	prs_align(ps);

	prs_uint32("user_idx", ps, depth, &(sam->user_idx));
	smb_io_strhdr("strhdr", &(sam->hdr_acct_name), ps, depth);

	return True;
}

/*******************************************************************
makes a SAM_ENTRY5 structure.
********************************************************************/
static BOOL make_sam_entry5(SAM_ENTRY5 *sam, uint32 grp_idx, 
				uint32 len_grp_name)
{
	if (sam == NULL) return False;

	DEBUG(5,("make_sam_entry5\n"));

	sam->grp_idx = grp_idx;
	make_str_hdr(&(sam->hdr_grp_name), len_grp_name, len_grp_name,
		     len_grp_name != 0);

	return True;
}

/*******************************************************************
reads or writes a SAM_ENTRY5 structure.
********************************************************************/
static BOOL sam_io_sam_entry5(char *desc, SAM_ENTRY5 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry5");
	depth++;

	prs_align(ps);

	prs_uint32("grp_idx", ps, depth, &(sam->grp_idx));
	smb_io_strhdr("strhdr", &(sam->hdr_grp_name), ps, depth);

	return True;
}

/*******************************************************************
makes a SAM_ENTRY structure.
********************************************************************/
BOOL make_sam_entry(SAM_ENTRY *sam, uint32 len_sam_name, uint32 rid)
{
	if (sam == NULL) return False;

	DEBUG(10,("make_sam_entry: %d %d\n", len_sam_name, rid));

	sam->rid = rid;
	make_uni_hdr(&(sam->hdr_name), len_sam_name);

	return True;
}

/*******************************************************************
reads or writes a SAM_ENTRY structure.
********************************************************************/
static BOOL sam_io_sam_entry(char *desc,  SAM_ENTRY *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry");
	depth++;

	prs_align(ps);
	prs_uint32("rid", ps, depth, &(sam->rid ));
	smb_io_unihdr("unihdr", &(sam->hdr_name), ps, depth); /* account name unicode string header */

	return True;
}


/*******************************************************************
makes a SAMR_Q_ENUM_DOM_USERS structure.
********************************************************************/
BOOL make_samr_q_enum_dom_users(SAMR_Q_ENUM_DOM_USERS *q_e, POLICY_HND *pol,
				uint32 start_idx, 
				uint16 acb_mask, uint16 unk_1, uint32 size)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_enum_dom_users\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->start_idx = start_idx; /* zero indicates lots */
	q_e->acb_mask  = acb_mask;
	q_e->unknown_1 = unk_1;
	q_e->max_size = size;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_enum_dom_users(char *desc,  SAMR_Q_ENUM_DOM_USERS *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_users");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("start_idx", ps, depth, &(q_e->start_idx));
	prs_uint16("acb_mask ", ps, depth, &(q_e->acb_mask ));
	prs_uint16("unknown_1", ps, depth, &(q_e->unknown_1));

	prs_uint32("max_size ", ps, depth, &(q_e->max_size ));

	prs_align(ps);

	return True;
}


/*******************************************************************
makes a SAMR_R_ENUM_DOM_USERS structure.
********************************************************************/
BOOL make_samr_r_enum_dom_users(SAMR_R_ENUM_DOM_USERS *r_u,
		uint32 next_idx,
		uint32 num_sam_entries)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_enum_dom_users\n"));

	r_u->next_idx = next_idx;

	if (num_sam_entries != 0)
	{
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		r_u->num_entries4 = num_sam_entries;
	}
	else
	{
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_enum_dom_users(char *desc, SAMR_R_ENUM_DOM_USERS *r_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_users");
	depth++;

	prs_align(ps);

	prs_uint32("next_idx    ", ps, depth, &(r_u->next_idx    ));
	prs_uint32("ptr_entries1", ps, depth, &(r_u->ptr_entries1));

	if (r_u->ptr_entries1 != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));
		prs_uint32("ptr_entries2", ps, depth, &(r_u->ptr_entries2));
		prs_uint32("num_entries3", ps, depth, &(r_u->num_entries3));

		if (ps->io)
		{
			r_u->sam = (SAM_ENTRY*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->sam[0]));
			r_u->uni_acct_name = (UNISTR2*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->uni_acct_name[0]));
		}

		if ((r_u->sam == NULL || r_u->uni_acct_name == NULL) && r_u->num_entries2 != 0)
		{
			DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOM_USERS\n"));
			r_u->num_entries4 = 0;
			r_u->status = 0xC0000000|NT_STATUS_MEMORY_NOT_ALLOCATED;
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			sam_io_sam_entry("", &(r_u->sam[i]), ps, depth);
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			smb_io_unistr2("", &(r_u->uni_acct_name[i]), r_u->sam[i].hdr_name.buffer, ps, depth);
			prs_align(ps);
		}

		prs_align(ps);

	}

	prs_uint32("num_entries4", ps, depth, &(r_u->num_entries4));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_DISPINFO structure.
********************************************************************/
BOOL make_samr_q_query_dispinfo(SAMR_Q_QUERY_DISPINFO *q_e, POLICY_HND *pol,
				uint16 switch_level, uint32 start_idx,
				uint32 max_entries)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_query_dispinfo\n"));

	memcpy(&(q_e->domain_pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;

	q_e->start_idx = start_idx;
	q_e->max_entries = max_entries;
	q_e->max_size = 0xffff; /* Not especially useful */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_dispinfo(char *desc,  SAMR_Q_QUERY_DISPINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_dispinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_e->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));
	prs_align(ps);

	prs_uint32("start_idx   ", ps, depth, &(q_e->start_idx   ));
	prs_uint32("max_entries ", ps, depth, &(q_e->max_entries ));
	prs_uint32("max_size    ", ps, depth, &(q_e->max_size    ));

	return True;
}


/*******************************************************************
makes a SAM_DISPINFO_1 structure.
********************************************************************/
BOOL make_sam_dispinfo_1(SAM_DISPINFO_1 *sam, uint32 *num_entries,
			 uint32 *data_size, uint32 start_idx,
			 SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES])
{
	uint32 len_sam_name, len_sam_full, len_sam_desc;
	uint32 max_entries, max_data_size;
	uint32 dsize = 0;
	uint32 i;

	if (sam == NULL || num_entries == NULL || data_size == NULL) return False;

	max_entries = *num_entries;
	max_data_size = *data_size;

	DEBUG(5,("make_sam_dispinfo_1: max_entries: %d max_dsize: 0x%x\n",
	           max_entries, max_data_size));

	for (i = 0; (i < max_entries) && (dsize < max_data_size); i++)
	{
		len_sam_name = pass[i].uni_user_name.uni_str_len;
		len_sam_full = pass[i].uni_full_name.uni_str_len;
		len_sam_desc = pass[i].uni_acct_desc.uni_str_len;

		make_sam_entry1(&(sam->sam[i]), start_idx + i + 1,
				len_sam_name, len_sam_full, len_sam_desc,
				pass[i].user_rid, pass[i].acb_info);

		copy_unistr2(&(sam->str[i].uni_acct_name), &(pass[i].uni_user_name));
		copy_unistr2(&(sam->str[i].uni_full_name), &(pass[i].uni_full_name));
		copy_unistr2(&(sam->str[i].uni_acct_desc), &(pass[i].uni_acct_desc));

		dsize += sizeof(SAM_ENTRY1);
		dsize += len_sam_name + len_sam_full + len_sam_desc;
	}

	*num_entries = i;
        *data_size = dsize;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_sam_dispinfo_1(char *desc, SAM_DISPINFO_1 *sam, uint32 num_entries, prs_struct *ps, int depth)
{
	uint32 i;

	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_dispinfo_1");
	depth++;

	prs_align(ps);

	SMB_ASSERT_ARRAY(sam->sam, num_entries);

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_entry1("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_str1 ("", &(sam->str[i]),
				 sam->sam[i].hdr_acct_name.buffer,
				 sam->sam[i].hdr_user_name.buffer,
				 sam->sam[i].hdr_user_desc.buffer,
				 ps, depth);
	}

	return True;
}


/*******************************************************************
makes a SAM_DISPINFO_2 structure.
********************************************************************/
BOOL make_sam_dispinfo_2(SAM_DISPINFO_2 *sam, uint32 *num_entries,
			 uint32 *data_size, uint32 start_idx,
			 SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES])
{
	uint32 len_sam_name, len_sam_desc;
	uint32 max_entries, max_data_size;
	uint32 dsize = 0;
	uint32 i;

	if (sam == NULL || num_entries == NULL || data_size == NULL) return False;

	DEBUG(5,("make_sam_dispinfo_2\n"));

	max_entries = *num_entries;
	max_data_size = *data_size;

	for (i = 0; (i < max_entries) && (dsize < max_data_size); i++)
	{
		len_sam_name = pass[i].uni_user_name.uni_str_len;
		len_sam_desc = pass[i].uni_acct_desc.uni_str_len;

		make_sam_entry2(&(sam->sam[i]), start_idx + i + 1,
				len_sam_name, len_sam_desc,
				pass[i].user_rid, pass[i].acb_info);

		copy_unistr2(&(sam->str[i].uni_srv_name), &(pass[i].uni_user_name));
		copy_unistr2(&(sam->str[i].uni_srv_desc), &(pass[i].uni_acct_desc));

		dsize += sizeof(SAM_ENTRY2);
		dsize += len_sam_name + len_sam_desc;
	}

	*num_entries = i;
        *data_size = dsize;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_sam_dispinfo_2(char *desc, SAM_DISPINFO_2 *sam, uint32 num_entries, prs_struct *ps, int depth)
{
	uint32 i;

	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_dispinfo_2");
	depth++;

	prs_align(ps);

	SMB_ASSERT_ARRAY(sam->sam, num_entries);

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_entry2("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_str2 ("", &(sam->str[i]),
				 sam->sam[i].hdr_srv_name.buffer,
				 sam->sam[i].hdr_srv_desc.buffer,
				 ps, depth);
	}

	return True;
}


/*******************************************************************
makes a SAM_DISPINFO_3 structure.
********************************************************************/
BOOL make_sam_dispinfo_3(SAM_DISPINFO_3 *sam, uint32 *num_entries,
			 uint32 *data_size, uint32 start_idx,
			 DOMAIN_GRP *grp)
{
	uint32 len_sam_name, len_sam_desc;
	uint32 max_entries, max_data_size;
	uint32 dsize = 0;
	uint32 i;

	if (sam == NULL || num_entries == NULL || data_size == NULL) return False;

	DEBUG(5,("make_sam_dispinfo_3\n"));

	max_entries = *num_entries;
	max_data_size = *data_size;

	for (i = 0; (i < max_entries) && (dsize < max_data_size); i++)
	{
		len_sam_name = strlen(grp[i].name);
		len_sam_desc = strlen(grp[i].comment);

		make_sam_entry3(&(sam->sam[i]), start_idx + i + 1,
				len_sam_name, len_sam_desc,
				grp[i].rid);

		make_unistr2(&(sam->str[i].uni_grp_name), grp[i].name   , len_sam_name);
		make_unistr2(&(sam->str[i].uni_grp_desc), grp[i].comment, len_sam_desc);

		dsize += sizeof(SAM_ENTRY3);
		dsize += (len_sam_name + len_sam_desc) * 2;
		dsize += 14;
	}

	*num_entries = i;
        *data_size = dsize;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_sam_dispinfo_3(char *desc, SAM_DISPINFO_3 *sam, uint32 num_entries, prs_struct *ps, int depth)
{
	uint32 i;

	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_dispinfo_3");
	depth++;

	prs_align(ps);

	SMB_ASSERT_ARRAY(sam->sam, num_entries);

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_entry3("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_str3 ("", &(sam->str[i]),
				 sam->sam[i].hdr_grp_name.buffer,
				 sam->sam[i].hdr_grp_desc.buffer,
				 ps, depth);
	}

	return True;
}


/*******************************************************************
makes a SAM_DISPINFO_4 structure.
********************************************************************/
BOOL make_sam_dispinfo_4(SAM_DISPINFO_4 *sam, uint32 *num_entries,
			 uint32 *data_size, uint32 start_idx,
			 SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES])
{
	fstring sam_name;
	uint32 len_sam_name;
	uint32 max_entries, max_data_size;
	uint32 dsize = 0;
	uint32 i;

	if (sam == NULL || num_entries == NULL || data_size == NULL) return False;

	DEBUG(5,("make_sam_dispinfo_4\n"));

	max_entries = *num_entries;
	max_data_size = *data_size;

	for (i = 0; (i < max_entries) && (dsize < max_data_size); i++)
	{
		len_sam_name = pass[i].uni_user_name.uni_str_len;

		make_sam_entry4(&(sam->sam[i]), start_idx + i + 1,
				len_sam_name);

		unistr2_to_ascii(sam_name, &(pass[i].uni_user_name), sizeof(sam_name));
		make_string2(&(sam->str[i].acct_name), sam_name, len_sam_name);

		dsize += sizeof(SAM_ENTRY4);
		dsize += len_sam_name;
	}

	*num_entries = i;
        *data_size = dsize;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_sam_dispinfo_4(char *desc, SAM_DISPINFO_4 *sam, uint32 num_entries, prs_struct *ps, int depth)
{
	uint32 i;

	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_dispinfo_4");
	depth++;

	prs_align(ps);

	SMB_ASSERT_ARRAY(sam->sam, num_entries);

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_entry4("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < num_entries; i++)
	{
		smb_io_string2("acct_name", &(sam->str[i].acct_name),
			       sam->sam[i].hdr_acct_name.buffer, ps, depth);
		prs_align(ps);
	}

	return True;
}


/*******************************************************************
makes a SAM_DISPINFO_5 structure.
********************************************************************/
BOOL make_sam_dispinfo_5(SAM_DISPINFO_5 *sam, uint32 *num_entries,
			 uint32 *data_size, uint32 start_idx,
			 DOMAIN_GRP *grp)
{
	uint32 len_sam_name;
	uint32 max_entries, max_data_size;
	uint32 dsize = 0;
	uint32 i;

	if (sam == NULL || num_entries == NULL || data_size == NULL) return False;

	DEBUG(5,("make_sam_dispinfo_5\n"));

	max_entries = *num_entries;
	max_data_size = *data_size;

	for (i = 0; (i < max_entries) && (dsize < max_data_size); i++)
	{
		len_sam_name = strlen(grp[i].name);

		make_sam_entry5(&(sam->sam[i]), start_idx + i + 1,
				len_sam_name);

		make_string2(&(sam->str[i].grp_name), grp[i].name,
			     len_sam_name);

		dsize += sizeof(SAM_ENTRY5);
		dsize += len_sam_name;
	}

	*num_entries = i;
        *data_size = dsize;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_sam_dispinfo_5(char *desc, SAM_DISPINFO_5 *sam, uint32 num_entries, prs_struct *ps, int depth)
{
	uint32 i;

	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_sam_dispinfo_5");
	depth++;

	prs_align(ps);

	SMB_ASSERT_ARRAY(sam->sam, num_entries);

	for (i = 0; i < num_entries; i++)
	{
		sam_io_sam_entry5("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < num_entries; i++)
	{
		smb_io_string2("grp_name", &(sam->str[i].grp_name),
			       sam->sam[i].hdr_grp_name.buffer, ps, depth);
		prs_align(ps);
	}

	return True;
}


/*******************************************************************
makes a SAMR_R_QUERY_DISPINFO structure.
********************************************************************/
BOOL make_samr_r_query_dispinfo(SAMR_R_QUERY_DISPINFO *r_u,
				uint32 num_entries, uint32 data_size,
				uint16 switch_level, SAM_DISPINFO_CTR *ctr,
				uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_dispinfo: level %d\n", switch_level));

	r_u->total_size = data_size; /* not calculated */
	r_u->data_size = data_size;

	r_u->switch_level = switch_level;
	r_u->num_entries = num_entries;
	r_u->ptr_entries = 1;
	r_u->num_entries2 = num_entries;
	r_u->ctr = ctr;

	r_u->status = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_dispinfo(char *desc, SAMR_R_QUERY_DISPINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_dispinfo");
	depth++;

	prs_align(ps);

	prs_uint32("total_size  ", ps, depth, &(r_u->total_size  ));
	prs_uint32("data_size   ", ps, depth, &(r_u->data_size   ));
	prs_uint16("switch_level", ps, depth, &(r_u->switch_level));
	prs_align(ps);

	prs_uint32("num_entries ", ps, depth, &(r_u->num_entries ));
	prs_uint32("ptr_entries ", ps, depth, &(r_u->ptr_entries ));
	prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));

	switch (r_u->switch_level)
	{
		case 0x1:
		{
			sam_io_sam_dispinfo_1("users", r_u->ctr->sam.info1, r_u->num_entries, ps, depth);
			break;
		}
		case 0x2:
		{
			sam_io_sam_dispinfo_2("servers", r_u->ctr->sam.info2, r_u->num_entries, ps, depth);
			break;
		}
		case 0x3:
		{
			sam_io_sam_dispinfo_3("groups", r_u->ctr->sam.info3, r_u->num_entries, ps, depth);
			break;
		}
		case 0x4:
		{
			sam_io_sam_dispinfo_4("user list", r_u->ctr->sam.info4,r_u->num_entries, ps, depth);
			break;
		}
		case 0x5:
		{
			sam_io_sam_dispinfo_5("group list", r_u->ctr->sam.info5, r_u->num_entries, ps, depth);
			break;
		}
		default:
		{
			DEBUG(5,("samr_io_r_query_dispinfo: unknown switch value\n"));
			break;
		}
	}

	prs_align(ps);
	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_OPEN_GROUP structure.
********************************************************************/
BOOL make_samr_q_open_group(SAMR_Q_OPEN_GROUP *q_c,
				const POLICY_HND *hnd,
				uint32 access_mask, uint32 rid)
{
	if (q_c == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_open_group\n"));

	memcpy(&(q_c->domain_pol), hnd, sizeof(q_c->domain_pol));
	q_c->access_mask = access_mask;
	q_c->rid_group = rid;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_group(char *desc,  SAMR_Q_OPEN_GROUP *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_open_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 

	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));
	prs_uint32("rid_group", ps, depth, &(q_u->rid_group));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_group(char *desc,  SAMR_R_OPEN_GROUP *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_open_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a GROUP_INFO1 structure.
********************************************************************/
BOOL make_samr_group_info1(GROUP_INFO1 *gr1,
				char *acct_name, char *acct_desc,
				uint32 num_members)
{
	int desc_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	int acct_len = acct_name != NULL ? strlen(acct_name) : 0;
	if (gr1 == NULL) return False;

	DEBUG(5,("make_samr_group_info1\n"));

	make_uni_hdr(&(gr1->hdr_acct_name), acct_len);

	gr1->unknown_1 = 0x3;
	gr1->num_members = num_members;

	make_uni_hdr(&(gr1->hdr_acct_desc), desc_len);

	make_unistr2(&(gr1->uni_acct_name), acct_name, acct_len);
	make_unistr2(&(gr1->uni_acct_desc), acct_desc, desc_len);

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_group_info1(char *desc,  GROUP_INFO1 *gr1, prs_struct *ps, int depth)
{
	if (gr1 == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_group_info1");
	depth++;

	prs_align(ps);

	smb_io_unihdr ("hdr_acct_name", &(gr1->hdr_acct_name) , ps, depth); 

	prs_uint32("unknown_1", ps, depth, &(gr1->unknown_1));
	prs_uint32("num_members", ps, depth, &(gr1->num_members));

	smb_io_unihdr ("hdr_acct_desc", &(gr1->hdr_acct_desc) , ps, depth); 

	smb_io_unistr2("uni_acct_name", &(gr1->uni_acct_name), gr1->hdr_acct_name.buffer, ps, depth);
	prs_align(ps);

	smb_io_unistr2("uni_acct_desc", &(gr1->uni_acct_desc), gr1->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a GROUP_INFO4 structure.
********************************************************************/
BOOL make_samr_group_info4(GROUP_INFO4 *gr4, const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (gr4 == NULL) return False;

	DEBUG(5,("make_samr_group_info4\n"));

	make_uni_hdr(&(gr4->hdr_acct_desc), acct_len);
	make_unistr2(&(gr4->uni_acct_desc), acct_desc, acct_len);

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_group_info4(char *desc,  GROUP_INFO4 *gr4, prs_struct *ps, int depth)
{
	if (gr4 == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_group_info4");
	depth++;

	prs_align(ps);

	smb_io_unihdr ("hdr_acct_desc", &(gr4->hdr_acct_desc) , ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(gr4->uni_acct_desc), gr4->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_group_info_ctr(char *desc,  GROUP_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return False;

	prs_debug(ps, depth, desc, "samr_group_info_ctr");
	depth++;

	prs_uint16("switch_value1", ps, depth, &(ctr->switch_value1));
	prs_uint16("switch_value2", ps, depth, &(ctr->switch_value2));

	switch (ctr->switch_value1)
	{
		case 1:
		{
			samr_io_group_info1("group_info1", &(ctr->group.info1), ps, depth);
			break;
		}
		case 4:
		{
			samr_io_group_info4("group_info4", &(ctr->group.info4), ps, depth);
			break;
		}
		default:
		{
			DEBUG(4,("samr_group_info_ctr: unsupported switch level\n"));
			break;
		}
	}

	prs_align(ps);

	return True;
}


/*******************************************************************
makes a SAMR_Q_CREATE_DOM_GROUP structure.
********************************************************************/
BOOL make_samr_q_create_dom_group(SAMR_Q_CREATE_DOM_GROUP *q_e,
				POLICY_HND *pol,
				const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_create_dom_group\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	make_uni_hdr(&(q_e->hdr_acct_desc), acct_len);
	make_unistr2(&(q_e->uni_acct_desc), acct_desc, acct_len);

	q_e->access_mask = 0x00020001;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_create_dom_group(char *desc,  SAMR_Q_CREATE_DOM_GROUP *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_create_dom_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	smb_io_unihdr ("hdr_acct_desc", &(q_e->hdr_acct_desc), ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(q_e->uni_acct_desc), q_e->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	prs_uint32("access", ps, depth, &(q_e->access_mask));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_create_dom_group(char *desc,  SAMR_R_CREATE_DOM_GROUP *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_create_dom_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("rid   ", ps, depth, &(r_u->rid   ));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_DELETE_DOM_GROUP structure.
********************************************************************/
BOOL make_samr_q_delete_dom_group(SAMR_Q_DELETE_DOM_GROUP *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_delete_dom_group\n"));

	memcpy(&(q_c->group_pol), hnd, sizeof(q_c->group_pol));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_delete_dom_group(char *desc,  SAMR_Q_DELETE_DOM_GROUP *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_delete_dom_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("group_pol", &(q_u->group_pol), ps, depth); 

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_delete_dom_group(char *desc,  SAMR_R_DELETE_DOM_GROUP *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_delete_dom_group");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}



/*******************************************************************
makes a SAMR_Q_DEL_GROUPMEM structure.
********************************************************************/
BOOL make_samr_q_del_groupmem(SAMR_Q_DEL_GROUPMEM *q_e,
				POLICY_HND *pol,
				uint32 rid)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_del_groupmem\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->rid = rid;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_del_groupmem(char *desc,  SAMR_Q_DEL_GROUPMEM *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_del_groupmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("rid    ", ps, depth, &(q_e->rid));

	return True;
}


/*******************************************************************
makes a SAMR_R_DEL_GROUPMEM structure.
********************************************************************/
BOOL make_samr_r_del_groupmem(SAMR_R_DEL_GROUPMEM *r_u, POLICY_HND *pol,
		uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_del_groupmem\n"));

	r_u->status = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_del_groupmem(char *desc,  SAMR_R_DEL_GROUPMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_del_groupmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_ADD_GROUPMEM structure.
********************************************************************/
BOOL make_samr_q_add_groupmem(SAMR_Q_ADD_GROUPMEM *q_e,
				POLICY_HND *pol,
				uint32 rid)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_add_groupmem\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->rid = rid;
	q_e->unknown = 0x0005;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_add_groupmem(char *desc,  SAMR_Q_ADD_GROUPMEM *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_add_groupmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("rid    ", ps, depth, &(q_e->rid));
	prs_uint32("unknown", ps, depth, &(q_e->unknown));

	return True;
}


/*******************************************************************
makes a SAMR_R_ADD_GROUPMEM structure.
********************************************************************/
BOOL make_samr_r_add_groupmem(SAMR_R_ADD_GROUPMEM *r_u, POLICY_HND *pol,
		uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_add_groupmem\n"));

	r_u->status = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_add_groupmem(char *desc,  SAMR_R_ADD_GROUPMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_add_groupmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_SET_GROUPINFO structure.
********************************************************************/
BOOL make_samr_q_set_groupinfo(SAMR_Q_SET_GROUPINFO *q_e,
				POLICY_HND *pol, GROUP_INFO_CTR *ctr)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_set_groupinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));
	q_e->ctr = ctr;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_set_groupinfo(char *desc,  SAMR_Q_SET_GROUPINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_set_groupinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	samr_group_info_ctr("ctr", q_e->ctr, ps, depth);

	return True;
}


/*******************************************************************
makes a SAMR_R_SET_GROUPINFO structure.
********************************************************************/
BOOL make_samr_r_set_groupinfo(SAMR_R_SET_GROUPINFO *r_u, 
		uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_set_groupinfo\n"));

	r_u->status = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_set_groupinfo(char *desc,  SAMR_R_SET_GROUPINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_set_groupinfo");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_GROUPINFO structure.
********************************************************************/
BOOL make_samr_q_query_groupinfo(SAMR_Q_QUERY_GROUPINFO *q_e,
				POLICY_HND *pol,
				uint16 switch_level)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_query_groupinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_groupinfo(char *desc,  SAMR_Q_QUERY_GROUPINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_groupinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));

	return True;
}


/*******************************************************************
makes a SAMR_R_QUERY_GROUPINFO structure.
********************************************************************/
BOOL make_samr_r_query_groupinfo(SAMR_R_QUERY_GROUPINFO *r_u, GROUP_INFO_CTR *ctr,
		uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_groupinfo\n"));

	r_u->ptr = (status == 0x0 && ctr != NULL) ? 1 : 0;
	r_u->ctr = ctr;
	r_u->status = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_groupinfo(char *desc,  SAMR_R_QUERY_GROUPINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_groupinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	
	if (r_u->ptr != 0)
	{
		samr_group_info_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_QUERY_GROUPMEM structure.
********************************************************************/
BOOL make_samr_q_query_groupmem(SAMR_Q_QUERY_GROUPMEM *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_query_groupmem\n"));

	memcpy(&(q_c->group_pol), hnd, sizeof(q_c->group_pol));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_groupmem(char *desc,  SAMR_Q_QUERY_GROUPMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_groupmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("group_pol", &(q_u->group_pol), ps, depth); 

	return True;
}

/*******************************************************************
makes a SAMR_R_QUERY_GROUPMEM structure.
********************************************************************/
BOOL make_samr_r_query_groupmem(SAMR_R_QUERY_GROUPMEM *r_u,
		uint32 num_entries, uint32 *rid, uint32 *attr, uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_groupmem\n"));

	if (status == 0x0)
	{
		r_u->ptr         = 1;
		r_u->num_entries = num_entries;

		r_u->ptr_attrs = attr != NULL ? 1 : 0;
		r_u->ptr_rids = rid != NULL ? 1 : 0;

		r_u->num_rids = num_entries;
		r_u->rid  = rid;

		r_u->num_attrs = num_entries;
		r_u->attr = attr;
	}
	else
	{
		r_u->ptr         = 0;
		r_u->num_entries = 0;
	}

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_groupmem(char *desc,  SAMR_R_QUERY_GROUPMEM *r_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_groupmem");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	prs_uint32("num_entries ", ps, depth, &(r_u->num_entries));

	if (r_u->ptr != 0)
	{
		prs_uint32("ptr_rids ", ps, depth, &(r_u->ptr_rids ));
		prs_uint32("ptr_attrs", ps, depth, &(r_u->ptr_attrs));

		if (r_u->ptr_rids != 0)
		{
			prs_uint32("num_rids", ps, depth, &(r_u->num_rids));
			if (r_u->num_rids != 0)
			{
				r_u->rid = (uint32*)Realloc(r_u->rid,
						       sizeof(r_u->rid[0]) *
						       r_u->num_rids);
				if (r_u->rid == NULL)
				{
					samr_free_r_query_groupmem(r_u);
					return False;
				}
			}
			for (i = 0; i < r_u->num_rids; i++)
			{
				prs_uint32("", ps, depth, &(r_u->rid[i]));
			}
		}

		if (r_u->ptr_attrs != 0)
		{
			prs_uint32("num_attrs", ps, depth, &(r_u->num_attrs));

			if (r_u->num_attrs != 0)
			{
				r_u->attr = (uint32*)Realloc(r_u->attr,
						       sizeof(r_u->attr[0]) *
						       r_u->num_attrs);
				if (r_u->attr == NULL)
				{
					samr_free_r_query_groupmem(r_u);
					return False;
				}
			}
			for (i = 0; i < r_u->num_attrs; i++)
			{
				prs_uint32("", ps, depth, &(r_u->attr[i]));
			}
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* storing.  memory no longer needed */
		samr_free_r_query_groupmem(r_u);
	}

	return True;
}


/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_r_query_groupmem(SAMR_R_QUERY_GROUPMEM *r_u)
{
	if (r_u->rid != NULL)
	{
		free(r_u->rid);
		r_u->rid = NULL;
	}
	if (r_u->attr != NULL)
	{
		free(r_u->attr);
		r_u->attr = NULL;
	}
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERGROUPS structure.
********************************************************************/
BOOL make_samr_q_query_usergroups(SAMR_Q_QUERY_USERGROUPS *q_u,
				POLICY_HND *hnd)
{
	if (q_u == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_query_usergroups\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_usergroups(char *desc,  SAMR_Q_QUERY_USERGROUPS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_usergroups");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAMR_R_QUERY_USERGROUPS structure.
********************************************************************/
BOOL make_samr_r_query_usergroups(SAMR_R_QUERY_USERGROUPS *r_u,
		uint32 num_gids, DOM_GID *gid, uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_usergroups\n"));

	if (status == 0x0)
	{
		r_u->ptr_0        = 1;
		r_u->num_entries  = num_gids;
		r_u->ptr_1        = (num_gids != 0) ? 1 : 0;
		r_u->num_entries2 = num_gids;

		r_u->gid = gid;
	}
	else
	{
		r_u->ptr_0       = 0;
		r_u->num_entries = 0;
		r_u->ptr_1       = 0;
		r_u->gid         = NULL;
	}

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_usergroups(char *desc,  SAMR_R_QUERY_USERGROUPS *r_u, prs_struct *ps, int depth)
{
	uint32 i;
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_usergroups");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0       ", ps, depth, &(r_u->ptr_0      ));

	if (r_u->ptr_0 != 0)
	{
		prs_uint32("num_entries ", ps, depth, &(r_u->num_entries));
		prs_uint32("ptr_1       ", ps, depth, &(r_u->ptr_1      ));

		if (r_u->num_entries != 0)
		{
			prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));

			if(ps->io)
				r_u->gid = g_renew(DOM_GID, r_u->gid,
						   r_u->num_entries2);
			if (r_u->gid == NULL)
			{
				return False;
			}

			for (i = 0; i < r_u->num_entries2; i++)
			{
				smb_io_gid("", &(r_u->gid[i]), ps, depth);
			}
		}
	}
	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* storing.  memory no longer needed */
		samr_free_r_query_usergroups(r_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_r_query_usergroups(SAMR_R_QUERY_USERGROUPS *r_u)
{
	r_u->ptr_0 = 0;
	r_u->num_entries = 0;
	if (r_u->gid)
	{
		free(r_u->gid);
		r_u->gid = NULL;
	}
}


/*******************************************************************
makes a SAMR_Q_ENUM_DOMAINS structure.
********************************************************************/
BOOL make_samr_q_enum_domains(SAMR_Q_ENUM_DOMAINS *q_e, POLICY_HND *pol,
				uint32 start_idx, uint32 size)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_enum_domains\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->start_idx = start_idx;
	q_e->max_size = size;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_enum_domains(char *desc, SAMR_Q_ENUM_DOMAINS *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_enum_domains");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("start_idx", ps, depth, &(q_e->start_idx));
	prs_uint32("max_size ", ps, depth, &(q_e->max_size ));

	prs_align(ps);

	return True;
}


/*******************************************************************
makes a SAMR_R_ENUM_DOMAINS structure.
********************************************************************/
BOOL make_samr_r_enum_domains(SAMR_R_ENUM_DOMAINS *r_u,
		uint32 next_idx, uint32 num_sam_entries)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_enum_domains\n"));

	r_u->next_idx = next_idx;

	if (num_sam_entries != 0)
	{
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		r_u->num_entries4 = num_sam_entries;
	}
	else
	{
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_enum_domains(char *desc, SAMR_R_ENUM_DOMAINS *r_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_enum_domains");
	depth++;

	prs_align(ps);

	prs_uint32("next_idx    ", ps, depth, &(r_u->next_idx    ));
	prs_uint32("ptr_entries1", ps, depth, &(r_u->ptr_entries1));

	if (r_u->ptr_entries1 != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));
		prs_uint32("ptr_entries2", ps, depth, &(r_u->ptr_entries2));
		prs_uint32("num_entries3", ps, depth, &(r_u->num_entries3));

		if (ps->io)
		{
			r_u->sam = (SAM_ENTRY*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->sam[0]));
			r_u->uni_dom_name = (UNISTR2*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->uni_dom_name[0]));
		}

		if ((r_u->sam == NULL || r_u->uni_dom_name == NULL) && r_u->num_entries2 != 0)
		{
			DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOMAINS\n"));
			r_u->num_entries4 = 0;
			r_u->status = 0xC0000000|NT_STATUS_MEMORY_NOT_ALLOCATED;
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			fstring tmp;
			slprintf(tmp, sizeof(tmp)-1, "dom[%d]", i);
			sam_io_sam_entry(tmp, &(r_u->sam[i]), ps, depth);
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			fstring tmp;
			slprintf(tmp, sizeof(tmp)-1, "dom[%d]", i);
			smb_io_unistr2(tmp, &(r_u->uni_dom_name[i]), r_u->sam[i].hdr_name.buffer, ps, depth);
			prs_align(ps);
		}

		prs_align(ps);

	}

	prs_uint32("num_entries4", ps, depth, &(r_u->num_entries4));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_ENUM_DOM_GROUPS structure.
********************************************************************/
BOOL make_samr_q_enum_dom_groups(SAMR_Q_ENUM_DOM_GROUPS *q_e, POLICY_HND *pol,
				uint32 start_idx, uint32 size)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_enum_dom_groups\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->start_idx = start_idx;
	q_e->max_size = size;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_enum_dom_groups(char *desc, SAMR_Q_ENUM_DOM_GROUPS *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_groups");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("start_idx", ps, depth, &(q_e->start_idx));
	prs_uint32("max_size ", ps, depth, &(q_e->max_size ));

	prs_align(ps);

	return True;
}


/*******************************************************************
makes a SAMR_R_ENUM_DOM_GROUPS structure.
********************************************************************/
BOOL make_samr_r_enum_dom_groups(SAMR_R_ENUM_DOM_GROUPS *r_u,
		uint32 next_idx, uint32 num_sam_entries)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_enum_dom_groups\n"));

	r_u->next_idx = next_idx;

	if (num_sam_entries != 0)
	{
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		r_u->num_entries4 = num_sam_entries;
	}
	else
	{
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_enum_dom_groups(char *desc, SAMR_R_ENUM_DOM_GROUPS *r_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_groups");
	depth++;

	prs_align(ps);

	prs_uint32("next_idx    ", ps, depth, &(r_u->next_idx    ));
	prs_uint32("ptr_entries1", ps, depth, &(r_u->ptr_entries1));

	if (r_u->ptr_entries1 != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));
		prs_uint32("ptr_entries2", ps, depth, &(r_u->ptr_entries2));
		prs_uint32("num_entries3", ps, depth, &(r_u->num_entries3));

		if (ps->io)
		{
			r_u->sam = (SAM_ENTRY*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->sam[0]));
			r_u->uni_grp_name = (UNISTR2*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->uni_grp_name[0]));
		}

		if ((r_u->sam == NULL || r_u->uni_grp_name == NULL) && r_u->num_entries2 != 0)
		{
			DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOM_GROUPS\n"));
			r_u->num_entries4 = 0;
			r_u->status = 0xC0000000|NT_STATUS_MEMORY_NOT_ALLOCATED;
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			sam_io_sam_entry("", &(r_u->sam[i]), ps, depth);
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			smb_io_unistr2("", &(r_u->uni_grp_name[i]), r_u->sam[i].hdr_name.buffer, ps, depth);
			prs_align(ps);
		}

		prs_align(ps);

	}

	prs_uint32("num_entries4", ps, depth, &(r_u->num_entries4));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_ENUM_DOM_ALIASES structure.
********************************************************************/
BOOL make_samr_q_enum_dom_aliases(SAMR_Q_ENUM_DOM_ALIASES *q_e, POLICY_HND *pol,
				uint32 start_idx, uint32 size)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_enum_dom_aliases\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->start_idx = start_idx;
	q_e->max_size = size;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_enum_dom_aliases(char *desc,  SAMR_Q_ENUM_DOM_ALIASES *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_aliases");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("start_idx", ps, depth, &(q_e->start_idx));
	prs_uint32("max_size ", ps, depth, &(q_e->max_size ));

	prs_align(ps);

	return True;
}


/*******************************************************************
makes a SAMR_R_ENUM_DOM_ALIASES structure.
********************************************************************/
BOOL make_samr_r_enum_dom_aliases(SAMR_R_ENUM_DOM_ALIASES *r_u,
		uint32 next_idx,
		uint32 num_sam_entries)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_enum_dom_aliases\n"));

	r_u->next_idx = next_idx;

	if (num_sam_entries != 0)
	{
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		r_u->num_entries4 = num_sam_entries;
	}
	else
	{
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_enum_dom_aliases(char *desc, SAMR_R_ENUM_DOM_ALIASES *r_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_aliases");
	depth++;

	prs_align(ps);

	prs_uint32("next_idx    ", ps, depth, &(r_u->next_idx    ));
	prs_uint32("ptr_entries1", ps, depth, &(r_u->ptr_entries1));

	if (r_u->ptr_entries1 != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));
		prs_uint32("ptr_entries2", ps, depth, &(r_u->ptr_entries2));
		prs_uint32("num_entries3", ps, depth, &(r_u->num_entries3));

		if (ps->io)
		{
			r_u->sam = (SAM_ENTRY*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->sam[0]));
			r_u->uni_grp_name = (UNISTR2*)Realloc(NULL, r_u->num_entries2 * sizeof(r_u->uni_grp_name[0]));
		}

		if ((r_u->sam == NULL || r_u->uni_grp_name == NULL) && r_u->num_entries2 != 0)
		{
			DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOM_ALIASES\n"));
			r_u->num_entries4 = 0;
			r_u->status = 0xC0000000|NT_STATUS_MEMORY_NOT_ALLOCATED;
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			sam_io_sam_entry("", &(r_u->sam[i]), ps, depth);
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			smb_io_unistr2("", &(r_u->uni_grp_name[i]), r_u->sam[i].hdr_name.buffer, ps, depth);
			prs_align(ps);
		}

		prs_align(ps);

	}

	prs_uint32("num_entries4", ps, depth, &(r_u->num_entries4));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a ALIAS_INFO3 structure.
********************************************************************/
BOOL make_samr_alias_info3(ALIAS_INFO3 *al3, const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (al3 == NULL) return False;

	DEBUG(5,("make_samr_alias_info3\n"));

	make_uni_hdr(&(al3->hdr_acct_desc), acct_len);
	make_unistr2(&(al3->uni_acct_desc), acct_desc, acct_len);

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_alias_info3(char *desc,  ALIAS_INFO3 *al3, prs_struct *ps, int depth)
{
	if (al3 == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_alias_info3");
	depth++;

	prs_align(ps);

	smb_io_unihdr ("hdr_acct_desc", &(al3->hdr_acct_desc) , ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(al3->uni_acct_desc), al3->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_alias_info_ctr(char *desc,  ALIAS_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return False;

	prs_debug(ps, depth, desc, "samr_alias_info_ctr");
	depth++;

	prs_uint16("switch_value1", ps, depth, &(ctr->switch_value1));
	prs_uint16("switch_value2", ps, depth, &(ctr->switch_value2));

	switch (ctr->switch_value1)
	{
		case 3:
		{
			samr_io_alias_info3("alias_info3", &(ctr->alias.info3), ps, depth);
			break;
		}
		default:
		{
			DEBUG(4,("samr_alias_info_ctr: unsupported switch level\n"));
			break;
		}
	}

	prs_align(ps);

	return True;
}


/*******************************************************************
makes a SAMR_Q_QUERY_ALIASINFO structure.
********************************************************************/
BOOL make_samr_q_query_aliasinfo(SAMR_Q_QUERY_ALIASINFO *q_e,
				POLICY_HND *pol,
				uint16 switch_level)
{
	if (q_e == NULL || pol == NULL) return False;

	DEBUG(5,("make_samr_q_query_aliasinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_aliasinfo(char *desc,  SAMR_Q_QUERY_ALIASINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_aliasinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));

	return True;
}


/*******************************************************************
makes a SAMR_R_QUERY_ALIASINFO structure.
********************************************************************/
BOOL make_samr_r_query_aliasinfo(SAMR_R_QUERY_ALIASINFO *r_u, ALIAS_INFO_CTR *ctr,
		uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_aliasinfo\n"));

	r_u->ptr = (status == 0x0 && ctr != NULL) ? 1 : 0;
	r_u->ctr = ctr;
	r_u->status = status;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_aliasinfo(char *desc,  SAMR_R_QUERY_ALIASINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_aliasinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	
	if (r_u->ptr != 0)
	{
		samr_alias_info_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_SET_ALIASINFO structure.
********************************************************************/
BOOL make_samr_q_set_aliasinfo(SAMR_Q_SET_ALIASINFO *q_u, POLICY_HND *hnd,
				ALIAS_INFO_CTR *ctr)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_set_aliasinfo\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
	q_u->ctr = ctr;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_set_aliasinfo(char *desc,  SAMR_Q_SET_ALIASINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_set_aliasinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
	samr_alias_info_ctr("ctr", q_u->ctr, ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_set_aliasinfo(char *desc,  SAMR_R_SET_ALIASINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_set_aliasinfo");
	depth++;

	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}



/*******************************************************************
makes a SAMR_Q_QUERY_USERALIASES structure.
********************************************************************/
BOOL make_samr_q_query_useraliases(SAMR_Q_QUERY_USERALIASES *q_u,
				const POLICY_HND *hnd,
				uint32 *ptr_sid, DOM_SID2 *sid)
{
	if (q_u == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_query_useraliases\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));

	q_u->num_sids1 = 1;
	q_u->ptr = 1;
	q_u->num_sids2 = 1;

	q_u->ptr_sid = ptr_sid;
	q_u->sid = sid;

	return True;
}

/*******************************************************************
reads or writes a SAMR_Q_QUERY_USERALIASES structure.
********************************************************************/
BOOL samr_io_q_query_useraliases(char *desc,  SAMR_Q_QUERY_USERALIASES *q_u, prs_struct *ps, int depth)
{
	fstring tmp;
	uint32 i;

	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_useraliases");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("num_sids1", ps, depth, &(q_u->num_sids1));
	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint32("num_sids2", ps, depth, &(q_u->num_sids2));

	if (q_u->num_sids2 != 0)
	{
		q_u->ptr_sid = (uint32*)Realloc(q_u->ptr_sid,
		                    sizeof(q_u->ptr_sid[0]) * q_u->num_sids2);
		if (q_u->ptr_sid == NULL)
		{
			samr_free_q_query_useraliases(q_u);
			return False;
		}

		q_u->sid = (DOM_SID2*)Realloc(q_u->sid,
				       sizeof(q_u->sid[0]) * q_u->num_sids2);
		if (q_u->sid == NULL)
		{
			samr_free_q_query_useraliases(q_u);
			return False;
		}
	}

	for (i = 0; i < q_u->num_sids2; i++)
	{
		slprintf(tmp, sizeof(tmp) - 1, "ptr[%02d]", i);
		prs_uint32(tmp, ps, depth, &(q_u->ptr_sid[i]));
	}

	for (i = 0; i < q_u->num_sids2; i++)
	{
		if (q_u->ptr_sid[i] != 0)
		{
			slprintf(tmp, sizeof(tmp)-1, "sid[%02d]", i);
			smb_io_dom_sid2(tmp, &(q_u->sid[i]), ps, depth); 
		}
	}

	prs_align(ps);

	if (!ps->io)
	{
		/* storing.  memory no longer needed */
		samr_free_q_query_useraliases(q_u);
	}
	return True;
}

/*******************************************************************
frees memory in a SAMR_Q_QUERY_USERALIASES structure.
********************************************************************/
void samr_free_q_query_useraliases(SAMR_Q_QUERY_USERALIASES *q_u)
{
	if (q_u->ptr_sid == NULL)
	{
		free(q_u->ptr_sid);
		q_u->ptr_sid = NULL;
	}

	if (q_u->sid == NULL)
	{
		free(q_u->sid);
		q_u->sid = NULL;
	}
}

/*******************************************************************
makes a SAMR_R_QUERY_USERALIASES structure.
********************************************************************/
BOOL make_samr_r_query_useraliases(SAMR_R_QUERY_USERALIASES *r_u,
		uint32 num_rids, uint32 *rid, uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_useraliases\n"));

	if (status == 0x0)
	{
		r_u->num_entries  = num_rids;
		r_u->ptr = 1;
		r_u->num_entries2 = num_rids;

		r_u->rid = rid;
	}
	else
	{
		r_u->num_entries  = 0;
		r_u->ptr = 0;
		r_u->num_entries2 = 0;
	}

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_useraliases(char *desc,  SAMR_R_QUERY_USERALIASES *r_u, prs_struct *ps, int depth)
{
	fstring tmp;
	uint32 i;
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_useraliases");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries", ps, depth, &(r_u->num_entries));
	prs_uint32("ptr        ", ps, depth, &(r_u->ptr        ));
	prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));

	if (r_u->num_entries != 0)
	{
		r_u->rid = (uint32*)Realloc(r_u->rid,
				       sizeof(r_u->rid[0]) * r_u->num_entries);
		if (r_u->rid == NULL)
		{
			samr_free_r_query_useraliases(r_u);
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)
		{
			slprintf(tmp, sizeof(tmp)-1, "rid[%02d]", i);
			prs_uint32(tmp, ps, depth, &(r_u->rid[i]));
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* storing.  memory no longer needed */
		samr_free_r_query_useraliases(r_u);
	}
	return True;
}

/*******************************************************************
frees memory in a SAMR_R_QUERY_USERALIASES structure.
********************************************************************/
void samr_free_r_query_useraliases(SAMR_R_QUERY_USERALIASES *r_u)
{
	if (r_u->rid == NULL)
	{
		free(r_u->rid);
		r_u->rid = NULL;
	}
}

/*******************************************************************
makes a SAMR_Q_OPEN_ALIAS structure.
********************************************************************/
BOOL make_samr_q_open_alias(SAMR_Q_OPEN_ALIAS *q_u, const POLICY_HND *pol,
				uint32 unknown_0, uint32 rid)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_open_alias\n"));

	memcpy(&(q_u->dom_pol), pol, sizeof(q_u->dom_pol));

	/* example values: 0x0000 0008 */
	q_u->unknown_0 = unknown_0; 

	q_u->rid_alias = rid; 

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_alias(char *desc,  SAMR_Q_OPEN_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_open_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("dom_pol", &(q_u->dom_pol), ps, depth); 

	prs_uint32("unknown_0", ps, depth, &(q_u->unknown_0));
	prs_uint32("rid_alias", ps, depth, &(q_u->rid_alias));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_alias(char *desc,  SAMR_R_OPEN_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_open_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_LOOKUP_RIDS structure.
********************************************************************/
BOOL make_samr_q_lookup_rids(SAMR_Q_LOOKUP_RIDS *q_u,
		const POLICY_HND *pol, uint32 flags,
		uint32 num_rids, const uint32 *rid)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_lookup_rids\n"));

	q_u->pol = *pol;

	q_u->num_rids1 = num_rids;
	q_u->flags     = flags;
	q_u->ptr       = 0;
	q_u->num_rids2 = num_rids;
	q_u->rid = (uint32 *) memdup(rid, num_rids * sizeof(q_u->rid[0]));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_lookup_rids(char *desc,  SAMR_Q_LOOKUP_RIDS *q_u, prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_lookup_rids");
	depth++;

	if (ps->io)
	{
		ZERO_STRUCTP(q_u);
	}

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("num_rids1", ps, depth, &(q_u->num_rids1));
	prs_uint32("flags    ", ps, depth, &(q_u->flags    ));
	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint32("num_rids2", ps, depth, &(q_u->num_rids2));

	if (q_u->num_rids2 != 0)
	{
		q_u->rid = (uint32*)Realloc(q_u->rid, sizeof(q_u->rid[0]) *
		                   q_u->num_rids2);
		if (q_u->rid == NULL)
		{
			samr_free_q_lookup_rids(q_u);
			return False;
		}
	}

	for (i = 0; i < q_u->num_rids2; i++)
	{
		slprintf(tmp, sizeof(tmp) - 1, "rid[%02d]  ", i);
		prs_uint32(tmp, ps, depth, &(q_u->rid[i]));
	}

	prs_align(ps);

	if (!ps->io)
	{
		/* storing.  don't need memory any more */
		samr_free_q_lookup_rids(q_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_q_lookup_rids(SAMR_Q_LOOKUP_RIDS *q_u)
{
	if (q_u->rid != NULL)
	{
		free(q_u->rid);
		q_u->rid = NULL;
	}
}


/*******************************************************************
makes a SAMR_R_LOOKUP_RIDS structure.
********************************************************************/
BOOL make_samr_r_lookup_rids(SAMR_R_LOOKUP_RIDS *r_u,
		uint32 num_names, UNIHDR *hdr_name, UNISTR2 *uni_name,
		uint32 *type)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_lookup_rids\n"));

	r_u->hdr_name = NULL;
	r_u->uni_name = NULL;
	r_u->type = NULL;

	if (num_names != 0)
	{
		r_u->num_names1 = num_names;
		r_u->ptr_names  = 1;
		r_u->num_names2 = num_names;

		r_u->num_types1 = num_names;
		r_u->ptr_types  = 1;
		r_u->num_types2 = num_names;

		r_u->hdr_name = hdr_name;
		r_u->uni_name = uni_name;
		r_u->type = type;
	}
	else
	{
		r_u->num_names1 = num_names;
		r_u->ptr_names  = 0;
		r_u->num_names2 = num_names;

		r_u->num_types1 = num_names;
		r_u->ptr_types  = 0;
		r_u->num_types2 = num_names;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_lookup_rids(char *desc, SAMR_R_LOOKUP_RIDS *r_u, prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_lookup_rids");
	depth++;

	prs_align(ps);

	prs_uint32("num_names1", ps, depth, &(r_u->num_names1));
	prs_uint32("ptr_names ", ps, depth, &(r_u->ptr_names ));
	prs_uint32("num_names2", ps, depth, &(r_u->num_names2));

	if (r_u->ptr_names != 0 && r_u->num_names1 != 0)
	{
		r_u->hdr_name = (UNIHDR*)Realloc(r_u->hdr_name,
		                   r_u->num_names2 * sizeof(r_u->hdr_name[0]));
		if (r_u->hdr_name == NULL)
		{
			return False;
		}

		r_u->uni_name = (UNISTR2*)Realloc(r_u->uni_name,
		                    r_u->num_names2 * sizeof(r_u->uni_name[0]));
		if (r_u->uni_name == NULL)
		{
			free(r_u->hdr_name);
			return False;
		}
		for (i = 0; i < r_u->num_names2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "hdr[%02d]  ", i);
			smb_io_unihdr ("", &(r_u->hdr_name[i]), ps, depth); 
		}
		for (i = 0; i < r_u->num_names2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "str[%02d]  ", i);
			smb_io_unistr2("", &(r_u->uni_name[i]), r_u->hdr_name[i].buffer, ps, depth); 
			prs_align(ps);
		}
	}

	prs_align(ps);

	prs_uint32("num_types1", ps, depth, &(r_u->num_types1));
	prs_uint32("ptr_types ", ps, depth, &(r_u->ptr_types ));
	prs_uint32("num_types2", ps, depth, &(r_u->num_types2));

	if (r_u->ptr_types != 0 && r_u->num_types1 != 0)
	{
		r_u->type = (uint32*)Realloc(r_u->type, r_u->num_types2 *
		                    sizeof(r_u->type[0]));
		if (r_u->type == NULL)
		{
			if (r_u->uni_name != NULL)
			{
				free(r_u->uni_name);
			}
			if (r_u->hdr_name != NULL)
			{
				free(r_u->hdr_name);
			}
			return False;
		}

		for (i = 0; i < r_u->num_types2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "type[%02d]  ", i);
			prs_uint32(tmp, ps, depth, &(r_u->type[i]));
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* storing.  don't need memory any more */
		samr_free_r_lookup_rids(r_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_r_lookup_rids(SAMR_R_LOOKUP_RIDS *r_u)
{
	if (r_u->uni_name != NULL)
	{
		free(r_u->uni_name);
		r_u->uni_name = NULL;
	}
	if (r_u->hdr_name != NULL)
	{
		free(r_u->hdr_name);
		r_u->hdr_name = NULL;
	}
	if (r_u->type != NULL)
	{
		free(r_u->type);
		r_u->type = NULL;
	}
}

/*******************************************************************
makes a SAMR_Q_OPEN_ALIAS structure.
********************************************************************/
BOOL make_samr_q_delete_alias(SAMR_Q_DELETE_DOM_ALIAS *q_u, POLICY_HND *hnd)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_delete_alias\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_delete_alias(char *desc,  SAMR_Q_DELETE_DOM_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_delete_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_delete_alias(char *desc,  SAMR_R_DELETE_DOM_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_delete_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_CREATE_DOM_ALIAS structure.
********************************************************************/
BOOL make_samr_q_create_dom_alias(SAMR_Q_CREATE_DOM_ALIAS *q_u, POLICY_HND *hnd,
				const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_create_dom_alias\n"));

	memcpy(&(q_u->dom_pol), hnd, sizeof(q_u->dom_pol));

	make_uni_hdr(&(q_u->hdr_acct_desc), acct_len);
	make_unistr2(&(q_u->uni_acct_desc), acct_desc, acct_len);

	q_u->access_mask = 0x001f000f;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_create_dom_alias(char *desc,  SAMR_Q_CREATE_DOM_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_create_dom_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("dom_pol", &(q_u->dom_pol), ps, depth); 

	smb_io_unihdr ("hdr_acct_desc", &(q_u->hdr_acct_desc) , ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(q_u->uni_acct_desc), q_u->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_create_dom_alias(char *desc,  SAMR_R_CREATE_DOM_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_create_dom_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(r_u->alias_pol), ps, depth); 
	prs_uint32("rid", ps, depth, &(r_u->rid));

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}



/*******************************************************************
makes a SAMR_Q_ADD_ALIASMEM structure.
********************************************************************/
BOOL make_samr_q_add_aliasmem(SAMR_Q_ADD_ALIASMEM *q_u, POLICY_HND *hnd,
				DOM_SID *sid)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_add_aliasmem\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
	make_dom_sid2(&q_u->sid, sid);

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_add_aliasmem(char *desc,  SAMR_Q_ADD_ALIASMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_add_aliasmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd ("alias_pol", &(q_u->alias_pol), ps, depth); 
	smb_io_dom_sid2("sid      ", &(q_u->sid      ), ps, depth); 

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_add_aliasmem(char *desc,  SAMR_R_ADD_ALIASMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_add_aliasmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_DEL_ALIASMEM structure.
********************************************************************/
BOOL make_samr_q_del_aliasmem(SAMR_Q_DEL_ALIASMEM *q_u, POLICY_HND *hnd,
				DOM_SID *sid)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_del_aliasmem\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
	make_dom_sid2(&q_u->sid, sid);

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_del_aliasmem(char *desc,  SAMR_Q_DEL_ALIASMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_del_aliasmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
	smb_io_dom_sid2("sid      ", &(q_u->sid      ), ps, depth); 

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_del_aliasmem(char *desc,  SAMR_R_DEL_ALIASMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_del_aliasmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_DELETE_DOM_ALIAS structure.
********************************************************************/
BOOL make_samr_q_delete_dom_alias(SAMR_Q_DELETE_DOM_ALIAS *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_delete_dom_alias\n"));

	memcpy(&(q_c->alias_pol), hnd, sizeof(q_c->alias_pol));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_delete_dom_alias(char *desc,  SAMR_Q_DELETE_DOM_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_delete_dom_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 

	return True;
}

/*******************************************************************
makes a SAMR_R_DELETE_DOM_ALIAS structure.
********************************************************************/
BOOL make_samr_r_delete_dom_alias(SAMR_R_DELETE_DOM_ALIAS *r_u,
		uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_delete_dom_alias\n"));

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_delete_dom_alias(char *desc,  SAMR_R_DELETE_DOM_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_delete_dom_alias");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_QUERY_ALIASMEM structure.
********************************************************************/
BOOL make_samr_q_query_aliasmem(SAMR_Q_QUERY_ALIASMEM *q_c,
				const POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_query_aliasmem\n"));

	memcpy(&(q_c->alias_pol), hnd, sizeof(q_c->alias_pol));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_aliasmem(char *desc,  SAMR_Q_QUERY_ALIASMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_aliasmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 

	return True;
}

/*******************************************************************
makes a SAMR_R_QUERY_ALIASMEM structure.
********************************************************************/
BOOL make_samr_r_query_aliasmem(SAMR_R_QUERY_ALIASMEM *r_u,
		uint32 num_sids, DOM_SID2 *sid, uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_aliasmem\n"));

	if (status == 0x0)
	{
		r_u->num_sids  = num_sids;
		r_u->ptr       = (num_sids != 0) ? 1 : 0;
		r_u->num_sids1 = num_sids;

		r_u->sid = sid;
	}
	else
	{
		r_u->ptr      = 0;
		r_u->num_sids = 0;
	}

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_aliasmem(char *desc,  SAMR_R_QUERY_ALIASMEM *r_u, prs_struct *ps, int depth)
{
	uint32 i;
	uint32 ptr_sid[MAX_LOOKUP_SIDS];

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_aliasmem");
	depth++;

	prs_align(ps);

	prs_uint32("num_sids ", ps, depth, &(r_u->num_sids));
	prs_uint32("ptr", ps, depth, &(r_u->ptr));

	if (r_u->ptr != 0)
	{
		SMB_ASSERT_ARRAY(ptr_sid, r_u->num_sids);

		if (r_u->num_sids != 0)
		{
			prs_uint32("num_sids1", ps, depth, &(r_u->num_sids1));

			for (i = 0; i < r_u->num_sids1; i++)
			{
				ptr_sid[i] = 1;
				prs_uint32("", ps, depth, &(ptr_sid[i]));
			}
			for (i = 0; i < r_u->num_sids1; i++)
			{
				if (ptr_sid[i] != 0)
				{
					smb_io_dom_sid2("", &(r_u->sid[i]), ps, depth);
				}
			}
		}
	}
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_LOOKUP_NAMES structure.
********************************************************************/
BOOL make_samr_q_lookup_names(SAMR_Q_LOOKUP_NAMES *q_u,
			      const POLICY_HND *pol, uint32 flags,
			      uint32 num_names, const char **name)
{
	uint32 i;
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_lookup_names\n"));

	memcpy(&(q_u->pol), pol, sizeof(*pol));

	q_u->num_names1 = num_names;
	q_u->flags     = flags;
	q_u->ptr       = 0;
	q_u->num_names2 = num_names;

	for (i = 0; i < num_names; i++)
	{
		int len_name = name[i] != NULL ? strlen(name[i]) : 0;
		make_uni_hdr(&(q_u->hdr_name[i]), len_name);  /* unicode header for user_name */
		make_unistr2(&(q_u->uni_name[i]), name[i], len_name);  /* unicode string for machine account */
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_lookup_names(char *desc,  SAMR_Q_LOOKUP_NAMES *q_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_lookup_names");
	depth++;

	if (ps->io)
	{
		ZERO_STRUCTP(q_u);
	}

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("num_names1", ps, depth, &(q_u->num_names1));
	prs_uint32("flags     ", ps, depth, &(q_u->flags     ));
	prs_uint32("ptr       ", ps, depth, &(q_u->ptr       ));
	prs_uint32("num_names2", ps, depth, &(q_u->num_names2));

	SMB_ASSERT_ARRAY(q_u->hdr_name, q_u->num_names2);

	for (i = 0; i < q_u->num_names2; i++)
	{
		smb_io_unihdr ("", &(q_u->hdr_name[i]), ps, depth); 
	}
	for (i = 0; i < q_u->num_names2; i++)
	{
		smb_io_unistr2("", &(q_u->uni_name[i]), q_u->hdr_name[i].buffer, ps, depth); 
		prs_align(ps);
	}

	prs_align(ps);

	if (!ps->io)
	{
		/* storing.  memory no longer needed */
		samr_free_q_lookup_names(q_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_q_lookup_names(SAMR_Q_LOOKUP_NAMES *q_l)
{
}

/*******************************************************************
makes a SAMR_R_LOOKUP_NAMES structure.
********************************************************************/
BOOL make_samr_r_lookup_names(SAMR_R_LOOKUP_NAMES *r_u,
			      uint32 num_rids,
			      const uint32 *rid, const uint32 *type,
			      uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_lookup_names\n"));

	if ((status == 0x0) && (num_rids != 0))
	{
		uint32 i;

		r_u->num_types1 = num_rids;
		r_u->ptr_types  = 1;
		r_u->num_types2 = num_rids;

		r_u->num_rids1 = num_rids;
		r_u->ptr_rids  = 1;
		r_u->num_rids2 = num_rids;

		r_u->rids  = g_new(uint32, num_rids);
		r_u->types = g_new(uint32, num_rids);

		if (! r_u->rids || ! r_u->types)
		{
			samr_free_r_lookup_names(r_u);
			return False;
		}

		for (i = 0; i < num_rids; i++)
		{
			r_u->rids [i] = rid [i];
			r_u->types[i] = type[i];
		}
	}
	else
	{
		r_u->num_types1 = 0;
		r_u->ptr_types  = 0;
		r_u->num_types2 = 0;

		r_u->num_rids1 = 0;
		r_u->ptr_rids  = 0;
		r_u->num_rids2 = 0;

		r_u->rids  = NULL;
		r_u->types = NULL;
	}

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_lookup_names(char *desc,  SAMR_R_LOOKUP_NAMES *r_u, prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_lookup_names");
	depth++;

	if (ps->io)
	{
		ZERO_STRUCTP(r_u);
	}

	prs_align(ps);

	prs_uint32("num_rids1", ps, depth, &(r_u->num_rids1));
	prs_uint32("ptr_rids ", ps, depth, &(r_u->ptr_rids ));

	if (r_u->ptr_rids != 0)
	{
		prs_uint32("num_rids2", ps, depth, &(r_u->num_rids2));

		if (r_u->num_rids2 != r_u->num_rids1)
		{
			/* RPC fault */
			return False;
		}

		if (ps->io)
			r_u->rids = g_new(uint32, r_u->num_rids2);

		if (! r_u->rids)
		{
			DEBUG(0, ("NULL rids in samr_io_r_lookup_names\n"));
			samr_free_r_lookup_names(r_u);
			return False;
		}

		for (i = 0; i < r_u->num_rids2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "rid[%02d]  ", i);
			prs_uint32(tmp, ps, depth, &(r_u->rids[i]));
		}
	}

	prs_uint32("num_types1", ps, depth, &(r_u->num_types1));
	prs_uint32("ptr_types ", ps, depth, &(r_u->ptr_types ));

	if (r_u->ptr_types != 0)
	{
		prs_uint32("num_types2", ps, depth, &(r_u->num_types2));

		if (r_u->num_types2 != r_u->num_types1)
		{
			/* RPC fault */
			return False;
		}

		if (ps->io)
			r_u->types = g_new(uint32, r_u->num_types2);

		if (! r_u->types)
		{
			DEBUG(0, ("NULL types in samr_io_r_lookup_names\n"));
			samr_free_r_lookup_names(r_u);
			return False;
		}

		for (i = 0; i < r_u->num_types2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "type[%02d]  ", i);
			prs_uint32(tmp, ps, depth, &(r_u->types[i]));
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* storing.  memory no longer needed */
		samr_free_r_lookup_names(r_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_r_lookup_names(SAMR_R_LOOKUP_NAMES *r_l)
{
	if (r_l->rids != NULL)
	{
		free(r_l->rids);
		r_l->rids = NULL;
	}
	if (r_l->types != NULL)
	{
		free(r_l->types);
		r_l->types = NULL;
	}
	r_l->num_types1 = 0;
	r_l->ptr_types  = 0;
	r_l->num_types2 = 0;

	r_l->num_rids1 = 0;
	r_l->ptr_rids  = 0;
	r_l->num_rids2 = 0;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_samr_q_open_user(SAMR_Q_OPEN_USER *q_u,
				const POLICY_HND *pol,
				uint32 access_mask, uint32 rid)
{
	if (q_u == NULL) return False;

	DEBUG(5,("samr_make_samr_q_open_user\n"));

	memcpy(&q_u->domain_pol, pol, sizeof(q_u->domain_pol));
	
	q_u->access_mask = access_mask;
	q_u->user_rid  = rid;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_user(char *desc,  SAMR_Q_OPEN_USER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_open_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));
	prs_uint32("user_rid ", ps, depth, &(q_u->user_rid ));

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_user(char *desc,  SAMR_R_OPEN_USER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_open_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(r_u->user_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_samr_q_create_user(SAMR_Q_CREATE_USER *q_u,
				POLICY_HND *pol,
				const char *name,
				uint16 acb_info, uint32 access_mask)
{
	int len_name;
	if (q_u == NULL) return False;
	len_name = strlen(name);

	DEBUG(5,("samr_make_samr_q_create_user\n"));

	memcpy(&q_u->domain_pol, pol, sizeof(q_u->domain_pol));
	
	make_uni_hdr(&(q_u->hdr_name), len_name);  
	make_unistr2(&(q_u->uni_name), name, len_name);

	q_u->acb_info = acb_info;
	q_u->access_mask = access_mask;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_create_user(char *desc,  SAMR_Q_CREATE_USER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_create_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 
	prs_align(ps);

	smb_io_unihdr ("unihdr", &(q_u->hdr_name), ps, depth); 
	smb_io_unistr2("unistr2", &(q_u->uni_name), q_u->hdr_name.buffer, ps, depth); 
	prs_align(ps);

	prs_uint16("acb_info   ", ps, depth, &(q_u->acb_info   ));
	prs_align(ps);
	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_create_user(char *desc,  SAMR_R_CREATE_USER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_create_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(r_u->user_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("unknown_0", ps, depth, &(r_u->unknown_0));
	prs_uint32("user_rid ", ps, depth, &(r_u->user_rid ));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERINFO structure.
********************************************************************/
BOOL make_samr_q_query_userinfo(SAMR_Q_QUERY_USERINFO *q_u,
				POLICY_HND *hnd, uint16 switch_value)
{
	if (q_u == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_query_userinfo\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));
	q_u->switch_value = switch_value;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_userinfo(char *desc,  SAMR_Q_QUERY_USERINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_query_userinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value)); /* 0x0015 or 0x0011 */

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a LOGON_HRS structure.
********************************************************************/
static BOOL sam_io_logon_hrs(char *desc,  LOGON_HRS *hrs, prs_struct *ps, int depth)
{
	if (hrs == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_logon_hrs");
	depth++;

	prs_align(ps);
	
	prs_uint32 (       "len  ", ps, depth, &(hrs->len ));

	if (hrs->len > 64)
	{
		DEBUG(5,("sam_io_logon_hrs: truncating length\n"));
		hrs->len = 64;
	}

	prs_uint8s (False, "hours", ps, depth, hrs->hours, hrs->len);

	return True;
}

/*******************************************************************
makes a SAM_USER_INFO_12 structure.
********************************************************************/
BOOL make_sam_user_info12(SAM_USER_INFO_12 *usr,
				uint16 acb_info,
				const uint8 lm_pwd[16],
				const uint8 nt_pwd[16])

{
	if (usr == NULL) return False;

	DEBUG(5,("make_sam_user_info12\n"));

	usr->acb_info = acb_info;

	if (lm_pwd == NULL)
	{
		bzero(usr->lm_pwd, sizeof(usr->lm_pwd));
	}
	else
	{
		memcpy(usr->lm_pwd, lm_pwd, sizeof(usr->lm_pwd));
	}

	if (nt_pwd == NULL)
	{
		bzero(usr->nt_pwd, sizeof(usr->nt_pwd));
	}
	else
	{
		memcpy(usr->nt_pwd, nt_pwd, sizeof(usr->nt_pwd));
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info12(char *desc,  SAM_USER_INFO_12 *u, prs_struct *ps, int depth)
{
	if (u == NULL) return False;

	DEBUG(0,("possible security breach!\n"));

	return False;
#if 0
	prs_debug(ps, depth, desc, "samr_io_r_user_info12");
	depth++;

	prs_align(ps);

	prs_uint16("acb_info", ps, depth, &u->acb_info);
	prs_align(ps);

	prs_uint8s(False, "lm_pwd", ps, depth, u->lm_pwd, sizeof(u->lm_pwd));
	prs_uint8s(False, "nt_pwd", ps, depth, u->nt_pwd, sizeof(u->nt_pwd));

	return True;
#endif
}

/*******************************************************************
makes a SAM_USER_INFO_10 structure.
********************************************************************/
BOOL make_sam_user_info10(SAM_USER_INFO_10 *usr,
				uint32 acb_info)
{
	if (usr == NULL) return False;

	DEBUG(5,("make_sam_user_info10\n"));

	usr->acb_info = acb_info;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info10(char *desc,  SAM_USER_INFO_10 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_user_info10");
	depth++;

	prs_align(ps);

	prs_uint32("acb_info", ps, depth, &(usr->acb_info));

	return True;
}

/*******************************************************************
makes a SAM_USER_INFO_11 structure.
********************************************************************/
BOOL make_sam_user_info11(SAM_USER_INFO_11 *usr,
				NTTIME *expiry,
				char *mach_acct,
				uint32 rid_user,
				uint32 rid_group,
				uint16 acct_ctrl)
				
{
	int len_mach_acct;
	if (usr == NULL || expiry == NULL || mach_acct == NULL) return False;

	DEBUG(5,("make_sam_user_info11\n"));

	len_mach_acct = strlen(mach_acct);

	memcpy(&(usr->expiry),expiry, sizeof(usr->expiry)); /* expiry time or something? */
	bzero(usr->padding_1, sizeof(usr->padding_1)); /* 0 - padding 24 bytes */

	make_uni_hdr(&(usr->hdr_mach_acct), len_mach_acct);  /* unicode header for machine account */
	usr->padding_2 = 0;               /* 0 - padding 4 bytes */

	usr->ptr_1        = 1;            /* pointer */
	bzero(usr->padding_3, sizeof(usr->padding_3)); /* 0 - padding 32 bytes */
	usr->padding_4    = 0;            /* 0 - padding 4 bytes */

	usr->ptr_2        = 1;            /* pointer */
	usr->padding_5    = 0;            /* 0 - padding 4 bytes */

	usr->ptr_3        = 1;          /* pointer */
	bzero(usr->padding_6, sizeof(usr->padding_6)); /* 0 - padding 32 bytes */

	usr->rid_user     = rid_user; 
	usr->rid_group    = rid_group;

	usr->acct_ctrl    = acct_ctrl;
	usr->unknown_3    = 0x0000;

	usr->unknown_4    = 0x003f;       /* 0x003f      - 16 bit unknown */
	usr->unknown_5    = 0x003c;       /* 0x003c      - 16 bit unknown */

	bzero(usr->padding_7, sizeof(usr->padding_7)); /* 0 - padding 16 bytes */
	usr->padding_8    = 0;            /* 0 - padding 4 bytes */
	
	make_unistr2(&(usr->uni_mach_acct), mach_acct, len_mach_acct);  /* unicode string for machine account */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info11(char *desc,  SAM_USER_INFO_11 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_11");
	depth++;

	prs_align(ps);

	prs_uint8s (False, "padding_0", ps, depth, usr->padding_0, sizeof(usr->padding_0)); 

	smb_io_time("time", &(usr->expiry), ps, depth); 

	prs_uint8s (False, "padding_1", ps, depth, usr->padding_1, sizeof(usr->padding_1));

	smb_io_unihdr ("unihdr", &(usr->hdr_mach_acct), ps, depth); 
	prs_uint32(        "padding_2", ps, depth, &(usr->padding_2));

	prs_uint32(        "ptr_1    ", ps, depth, &(usr->ptr_1    ));
	prs_uint8s (False, "padding_3", ps, depth, usr->padding_3, sizeof(usr->padding_3));
	prs_uint32(        "padding_4", ps, depth, &(usr->padding_4));

	prs_uint32(        "ptr_2    ", ps, depth, &(usr->ptr_2    ));
	prs_uint32(        "padding_5", ps, depth, &(usr->padding_5));

	prs_uint32(        "ptr_3    ", ps, depth, &(usr->ptr_3    ));
	prs_uint8s (False, "padding_6", ps, depth, usr->padding_6, sizeof(usr->padding_6));

	prs_uint32(        "rid_user ", ps, depth, &(usr->rid_user ));
	prs_uint32(        "rid_group", ps, depth, &(usr->rid_group));
	prs_uint16(        "acct_ctrl", ps, depth, &(usr->acct_ctrl));
	prs_uint16(        "unknown_3", ps, depth, &(usr->unknown_3));
	prs_uint16(        "unknown_4", ps, depth, &(usr->unknown_4));
	prs_uint16(        "unknown_5", ps, depth, &(usr->unknown_5));

	prs_uint8s (False, "padding_7", ps, depth, usr->padding_7, sizeof(usr->padding_7));
	prs_uint32(        "padding_8", ps, depth, &(usr->padding_8));
	
	smb_io_unistr2("unistr2", &(usr->uni_mach_acct), True, ps, depth); 
	prs_align(ps);

	prs_uint8s (False, "padding_9", ps, depth, usr->padding_9, sizeof(usr->padding_9));

	return True;
}

/*************************************************************************
 make_sam_user_infoa

 unknown_3 = 0x09f8 27fa
 unknown_5 = 0x0001 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
BOOL make_sam_user_info24(SAM_USER_INFO_24 *usr,
	const char newpass[516], uint16 passlen)
{
	DEBUG(10,("make_sam_user_info24: passlen: %d\n", passlen));
	memcpy(usr->pass, newpass, sizeof(usr->pass));
	usr->unk_0 = passlen;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_user_info24(char *desc, SAM_USER_INFO_24 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_user_info24");
	depth++;

	prs_align(ps);
	
	prs_uint8s (False, "password", ps, depth, usr->pass, sizeof(usr->pass));
	prs_uint16("unk_0", ps, depth, &(usr->unk_0));      /* unknown */
	prs_align(ps);

	return True;
}


/*************************************************************************
 make_sam_user_info23

 unknown_3 = 0x09f8 27fa
 unknown_5 = 0x0001 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
BOOL make_sam_user_info23W(SAM_USER_INFO_23 *usr,

	const NTTIME *logon_time, /* all zeros */
	const NTTIME *logoff_time, /* all zeros */
	const NTTIME *kickoff_time, /* all zeros */
	const NTTIME *pass_last_set_time, /* all zeros */
	const NTTIME *pass_can_change_time, /* all zeros */
	const NTTIME *pass_must_change_time, /* all zeros */

	const UNISTR2 *user_name, 
	const UNISTR2 *full_name,
	const UNISTR2 *home_dir,
	const UNISTR2 *dir_drive,
	const UNISTR2 *log_scr,
	const UNISTR2 *prof_path,
	const UNISTR2 *desc,
	const UNISTR2 *wkstas,
	const UNISTR2 *unk_str,
	const UNISTR2 *mung_dial,

	uint32 user_rid, /* 0x0000 0000 */
	uint32 group_rid,
	uint16 acb_info, 

	uint32 unknown_3,
	uint16 logon_divs,
	LOGON_HRS *hrs,
	uint32 unknown_5,
	char newpass[516]
#if 0
	, uint32 unknown_6
#endif
			)
{
	int len_user_name    = user_name != NULL ? user_name->uni_str_len : 0;
	int len_full_name    = full_name != NULL ? full_name->uni_str_len : 0;
	int len_home_dir     = home_dir  != NULL ? home_dir ->uni_str_len : 0;
	int len_dir_drive    = dir_drive != NULL ? dir_drive->uni_str_len : 0;
	int len_logon_script = log_scr   != NULL ? log_scr  ->uni_str_len : 0;
	int len_profile_path = prof_path != NULL ? prof_path->uni_str_len : 0;
	int len_description  = desc      != NULL ? desc     ->uni_str_len : 0;
	int len_workstations = wkstas    != NULL ? wkstas   ->uni_str_len : 0;
	int len_unknown_str  = unk_str   != NULL ? unk_str  ->uni_str_len : 0;
	int len_munged_dial  = mung_dial != NULL ? mung_dial->uni_str_len : 0;

	usr->logon_time            = *logon_time; /* all zeros */
	usr->logoff_time           = *logoff_time; /* all zeros */
	usr->kickoff_time          = *kickoff_time; /* all zeros */
	usr->pass_last_set_time    = *pass_last_set_time; /* all zeros */
	usr->pass_can_change_time  = *pass_can_change_time; /* all zeros */
	usr->pass_must_change_time = *pass_must_change_time; /* all zeros */

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   ); /* NULL */
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   );
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path);
	make_uni_hdr(&(usr->hdr_acct_desc   ), len_description );
	make_uni_hdr(&(usr->hdr_workstations), len_workstations);
	make_uni_hdr(&(usr->hdr_unknown_str ), len_unknown_str );
	make_uni_hdr(&(usr->hdr_munged_dial ), len_munged_dial );

	bzero(usr->nt_pwd, sizeof(usr->nt_pwd));
	bzero(usr->lm_pwd, sizeof(usr->lm_pwd));

	usr->user_rid  = user_rid; /* 0x0000 0000 */
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->unknown_3 = unknown_3; /* 09f8 27fa */

	usr->logon_divs = logon_divs; /* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;

	bzero(usr->padding1, sizeof(usr->padding1));

	usr->unknown_5 = unknown_5; /* 0x0001 0000 */

	memcpy(usr->pass, newpass, sizeof(usr->pass));

	copy_unistr2(&(usr->uni_user_name   ), user_name);
	copy_unistr2(&(usr->uni_full_name   ), full_name);
	copy_unistr2(&(usr->uni_home_dir    ), home_dir );
	copy_unistr2(&(usr->uni_dir_drive   ), dir_drive);
	copy_unistr2(&(usr->uni_logon_script), log_scr  );
	copy_unistr2(&(usr->uni_profile_path), prof_path);
	copy_unistr2(&(usr->uni_acct_desc   ), desc     );
	copy_unistr2(&(usr->uni_workstations), wkstas   );
	copy_unistr2(&(usr->uni_unknown_str ), unk_str  );
	copy_unistr2(&(usr->uni_munged_dial ), mung_dial);

#if 0
	usr->unknown_6 = unknown_6; /* 0x0000 04ec */
	usr->padding4 = 0;
#endif

	if (hrs)
	{
		memcpy(&(usr->logon_hrs), hrs, sizeof(usr->logon_hrs));
	}
	else
	{
		memset(&(usr->logon_hrs), 0xff, sizeof(usr->logon_hrs));
	}

	return True;
}

/*************************************************************************
 make_sam_user_info23

 unknown_3 = 0x09f8 27fa
 unknown_5 = 0x0001 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
BOOL make_sam_user_info23A(SAM_USER_INFO_23 *usr,

	NTTIME *logon_time, /* all zeros */
	NTTIME *logoff_time, /* all zeros */
	NTTIME *kickoff_time, /* all zeros */
	NTTIME *pass_last_set_time, /* all zeros */
	NTTIME *pass_can_change_time, /* all zeros */
	NTTIME *pass_must_change_time, /* all zeros */

	char *user_name, /* NULL */
	char *full_name,
	char *home_dir,
	char *dir_drive,
	char *log_scr,
	char *prof_path,
	char *desc,
	char *wkstas,
	char *unk_str,
	char *mung_dial,

	uint32 user_rid, /* 0x0000 0000 */
	uint32 group_rid,
	uint16 acb_info, 

	uint32 unknown_3,
	uint16 logon_divs,
	LOGON_HRS *hrs,
	uint32 unknown_5,
	char newpass[516]
#if 0
	, uint32 unknown_6
#endif
			)
{
	int len_user_name    = user_name != NULL ? strlen(user_name) : 0;
	int len_full_name    = full_name != NULL ? strlen(full_name) : 0;
	int len_home_dir     = home_dir  != NULL ? strlen(home_dir ) : 0;
	int len_dir_drive    = dir_drive != NULL ? strlen(dir_drive) : 0;
	int len_logon_script = log_scr   != NULL ? strlen(log_scr  ) : 0;
	int len_profile_path = prof_path != NULL ? strlen(prof_path) : 0;
	int len_description  = desc      != NULL ? strlen(desc     ) : 0;
	int len_workstations = wkstas    != NULL ? strlen(wkstas   ) : 0;
	int len_unknown_str  = unk_str   != NULL ? strlen(unk_str  ) : 0;
	int len_munged_dial  = mung_dial != NULL ? strlen(mung_dial) : 0;

	usr->logon_time            = *logon_time; /* all zeros */
	usr->logoff_time           = *logoff_time; /* all zeros */
	usr->kickoff_time          = *kickoff_time; /* all zeros */
	usr->pass_last_set_time    = *pass_last_set_time; /* all zeros */
	usr->pass_can_change_time  = *pass_can_change_time; /* all zeros */
	usr->pass_must_change_time = *pass_must_change_time; /* all zeros */

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   ); /* NULL */
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   );
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path);
	make_uni_hdr(&(usr->hdr_acct_desc   ), len_description );
	make_uni_hdr(&(usr->hdr_workstations), len_workstations);
	make_uni_hdr(&(usr->hdr_unknown_str ), len_unknown_str );
	make_uni_hdr(&(usr->hdr_munged_dial ), len_munged_dial );

	bzero(usr->nt_pwd, sizeof(usr->nt_pwd));
	bzero(usr->lm_pwd, sizeof(usr->lm_pwd));

	usr->user_rid  = user_rid; /* 0x0000 0000 */
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->unknown_3 = unknown_3; /* 09f8 27fa */

	usr->logon_divs = logon_divs; /* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;

	bzero(usr->padding1, sizeof(usr->padding1));

	usr->unknown_5 = unknown_5; /* 0x0001 0000 */

	memcpy(usr->pass, newpass, sizeof(usr->pass));

	make_unistr2(&(usr->uni_user_name   ), user_name   , len_user_name   ); /* NULL */
	make_unistr2(&(usr->uni_full_name   ), full_name   , len_full_name   );
	make_unistr2(&(usr->uni_home_dir    ), home_dir    , len_home_dir    );
	make_unistr2(&(usr->uni_dir_drive   ), dir_drive   , len_dir_drive   );
	make_unistr2(&(usr->uni_logon_script), log_scr, len_logon_script);
	make_unistr2(&(usr->uni_profile_path), prof_path, len_profile_path);
	make_unistr2(&(usr->uni_acct_desc ), desc , len_description );
	make_unistr2(&(usr->uni_workstations), wkstas, len_workstations);
	make_unistr2(&(usr->uni_unknown_str ), unk_str , len_unknown_str );
	make_unistr2(&(usr->uni_munged_dial ), mung_dial , len_munged_dial );

#if 0
	usr->unknown_6 = unknown_6; /* 0x0000 04ec */
	usr->padding4 = 0;
#endif

	if (hrs)
	{
		memcpy(&(usr->logon_hrs), hrs, sizeof(usr->logon_hrs));
	}
	else
	{
		memset(&(usr->logon_hrs), 0xff, sizeof(usr->logon_hrs));
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL sam_io_user_info23(char *desc,  SAM_USER_INFO_23 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_user_info23");
	depth++;

	prs_align(ps);
	
	smb_io_time("logon_time           ", &(usr->logon_time)           , ps, depth);
	smb_io_time("logoff_time          ", &(usr->logoff_time)          , ps, depth); 
	smb_io_time("kickoff_time         ", &(usr->kickoff_time)         , ps, depth); 
	smb_io_time("pass_last_set_time   ", &(usr->pass_last_set_time)   , ps, depth); 
	smb_io_time("pass_can_change_time ", &(usr->pass_can_change_time) , ps, depth); 
	smb_io_time("pass_must_change_time", &(usr->pass_must_change_time), ps, depth); 

	smb_io_unihdr("hdr_user_name   ", &(usr->hdr_user_name)   , ps, depth); /* username unicode string header */
	smb_io_unihdr("hdr_full_name   ", &(usr->hdr_full_name)   , ps, depth); /* user's full name unicode string header */
	smb_io_unihdr("hdr_home_dir    ", &(usr->hdr_home_dir)    , ps, depth); /* home directory unicode string header */
	smb_io_unihdr("hdr_dir_drive   ", &(usr->hdr_dir_drive)   , ps, depth); /* home directory drive */
	smb_io_unihdr("hdr_logon_script", &(usr->hdr_logon_script), ps, depth); /* logon script unicode string header */
	smb_io_unihdr("hdr_profile_path", &(usr->hdr_profile_path), ps, depth); /* profile path unicode string header */
	smb_io_unihdr("hdr_acct_desc   ", &(usr->hdr_acct_desc  ) , ps, depth); /* account desc */
	smb_io_unihdr("hdr_workstations", &(usr->hdr_workstations), ps, depth); /* wkstas user can log on from */
	smb_io_unihdr("hdr_unknown_str ", &(usr->hdr_unknown_str ), ps, depth); /* unknown string */
	smb_io_unihdr("hdr_munged_dial ", &(usr->hdr_munged_dial ), ps, depth); /* wkstas user can log on from */

	prs_uint8s (False, "lm_pwd        ", ps, depth, usr->lm_pwd   , sizeof(usr->lm_pwd   ));
	prs_uint8s (False, "nt_pwd        ", ps, depth, usr->nt_pwd   , sizeof(usr->nt_pwd   ));

	prs_uint32("user_rid      ", ps, depth, &(usr->user_rid     ));       /* User ID */
	prs_uint32("group_rid     ", ps, depth, &(usr->group_rid    ));      /* Group ID */
	prs_uint16("acb_info      ", ps, depth, &(usr->acb_info     ));      /* Group ID */
	prs_align(ps);

	prs_uint32("unknown_3     ", ps, depth, &(usr->unknown_3    ));
	prs_uint16("logon_divs    ", ps, depth, &(usr->logon_divs   ));     /* logon divisions per week */
	prs_align(ps);
	prs_uint32("ptr_logon_hrs ", ps, depth, &(usr->ptr_logon_hrs));
	prs_uint8s (False, "padding1      ", ps, depth, usr->padding1, sizeof(usr->padding1));
	prs_uint32("unknown_5     ", ps, depth, &(usr->unknown_5    ));

	prs_uint8s (False, "password      ", ps, depth, usr->pass, sizeof(usr->pass));

	/* here begins pointed-to data */

	smb_io_unistr2("uni_user_name   ", &(usr->uni_user_name)   , usr->hdr_user_name   .buffer, ps, depth); /* username unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_full_name   ", &(usr->uni_full_name)   , usr->hdr_full_name   .buffer, ps, depth); /* user's full name unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_home_dir    ", &(usr->uni_home_dir)    , usr->hdr_home_dir    .buffer, ps, depth); /* home directory unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_dir_drive   ", &(usr->uni_dir_drive)   , usr->hdr_dir_drive   .buffer, ps, depth); /* home directory drive unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_logon_script", &(usr->uni_logon_script), usr->hdr_logon_script.buffer, ps, depth); /* logon script unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_profile_path", &(usr->uni_profile_path), usr->hdr_profile_path.buffer, ps, depth); /* profile path unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_acct_desc   ", &(usr->uni_acct_desc   ), usr->hdr_acct_desc   .buffer, ps, depth); /* user desc unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_workstations", &(usr->uni_workstations), usr->hdr_workstations.buffer, ps, depth); /* worksations user can log on from */
	prs_align(ps);
	smb_io_unistr2("uni_unknown_str ", &(usr->uni_unknown_str ), usr->hdr_unknown_str .buffer, ps, depth); /* unknown string */
	prs_align(ps);
	smb_io_unistr2("uni_munged_dial ", &(usr->uni_munged_dial ), usr->hdr_munged_dial .buffer, ps, depth); /* worksations user can log on from */
	prs_align(ps);

#if 0
	prs_uint32("unknown_6     ", ps, depth, &(usr->unknown_6  ));
	prs_uint32("padding4      ", ps, depth, &(usr->padding4   ));
#endif

	if (usr->ptr_logon_hrs)
	{
		sam_io_logon_hrs("logon_hrs", &(usr->logon_hrs)   , ps, depth);
		prs_align(ps);
	}

	return True;
}


/*************************************************************************
 make_sam_user_info21W

 unknown_3 = 0x00ff ffff
 unknown_5 = 0x0002 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
BOOL make_sam_user_info21W(SAM_USER_INFO_21 *usr,

	const NTTIME *logon_time,
	const NTTIME *logoff_time,
	const NTTIME *kickoff_time,
	const NTTIME *pass_last_set_time,
	const NTTIME *pass_can_change_time,
	const NTTIME *pass_must_change_time,

	const UNISTR2 *user_name, 
	const UNISTR2 *full_name,
	const UNISTR2 *home_dir,
	const UNISTR2 *dir_drive,
	const UNISTR2 *log_scr,
	const UNISTR2 *prof_path,
	const UNISTR2 *desc,
	const UNISTR2 *wkstas,
	const UNISTR2 *unk_str,
	const UNISTR2 *mung_dial,

	const uchar lm_pwd[16],
	const uchar nt_pwd[16],

	uint32 user_rid,
	uint32 group_rid,
	uint16 acb_info, 

	uint32 unknown_3,
	uint16 logon_divs,
	const LOGON_HRS *hrs,
	uint32 unknown_5,
	uint32 unknown_6)
{
	int len_user_name    = user_name != NULL ? user_name->uni_str_len : 0;
	int len_full_name    = full_name != NULL ? full_name->uni_str_len : 0;
	int len_home_dir     = home_dir  != NULL ? home_dir ->uni_str_len : 0;
	int len_dir_drive    = dir_drive != NULL ? dir_drive->uni_str_len : 0;
	int len_logon_script = log_scr   != NULL ? log_scr  ->uni_str_len : 0;
	int len_profile_path = prof_path != NULL ? prof_path->uni_str_len : 0;
	int len_description  = desc      != NULL ? desc     ->uni_str_len : 0;
	int len_workstations = wkstas    != NULL ? wkstas   ->uni_str_len : 0;
	int len_unknown_str  = unk_str   != NULL ? unk_str  ->uni_str_len : 0;
	int len_munged_dial  = mung_dial != NULL ? mung_dial->uni_str_len : 0;

	usr->logon_time            = *logon_time;
	usr->logoff_time           = *logoff_time;
	usr->kickoff_time          = *kickoff_time;
	usr->pass_last_set_time    = *pass_last_set_time;
	usr->pass_can_change_time  = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   );
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   );
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path);
	make_uni_hdr(&(usr->hdr_acct_desc   ), len_description );
	make_uni_hdr(&(usr->hdr_workstations), len_workstations);
	make_uni_hdr(&(usr->hdr_unknown_str ), len_unknown_str );
	make_uni_hdr(&(usr->hdr_munged_dial ), len_munged_dial );

	if (lm_pwd == NULL)
	{
		bzero(usr->lm_pwd, sizeof(usr->lm_pwd));
	}
	else
	{
		memcpy(usr->lm_pwd, lm_pwd, sizeof(usr->lm_pwd));
	}
	if (nt_pwd == NULL)
	{
		bzero(usr->nt_pwd, sizeof(usr->nt_pwd));
	}
	else
	{
		memcpy(usr->nt_pwd, nt_pwd, sizeof(usr->nt_pwd));
	}

	usr->user_rid  = user_rid;
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->unknown_3 = unknown_3; /* 0x00ff ffff */

	usr->logon_divs = logon_divs; /* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;
	usr->unknown_5 = unknown_5; /* 0x0002 0000 */

	bzero(usr->padding1, sizeof(usr->padding1));

	copy_unistr2(&(usr->uni_user_name   ), user_name);
	copy_unistr2(&(usr->uni_full_name   ), full_name);
	copy_unistr2(&(usr->uni_home_dir    ), home_dir );
	copy_unistr2(&(usr->uni_dir_drive   ), dir_drive);
	copy_unistr2(&(usr->uni_logon_script), log_scr  );
	copy_unistr2(&(usr->uni_profile_path), prof_path);
	copy_unistr2(&(usr->uni_acct_desc   ), desc     );
	copy_unistr2(&(usr->uni_workstations), wkstas   );
	copy_unistr2(&(usr->uni_unknown_str ), unk_str  );
	copy_unistr2(&(usr->uni_munged_dial ), mung_dial);

	usr->unknown_6 = unknown_6; /* 0x0000 04ec */
	usr->padding4 = 0;

	if (hrs)
	{
		memcpy(&(usr->logon_hrs), hrs, sizeof(usr->logon_hrs));
	}
	else
	{
		memset(&(usr->logon_hrs), 0xff, sizeof(usr->logon_hrs));
	}

	return True;
}

/*************************************************************************
 make_sam_user_info21

 unknown_3 = 0x00ff ffff
 unknown_5 = 0x0002 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
BOOL make_sam_user_info21A(SAM_USER_INFO_21 *usr,

	NTTIME *logon_time,
	NTTIME *logoff_time,
	NTTIME *kickoff_time,
	NTTIME *pass_last_set_time,
	NTTIME *pass_can_change_time,
	NTTIME *pass_must_change_time,

	char *user_name,
	char *full_name,
	char *home_dir,
	char *dir_drive,
	char *log_scr,
	char *prof_path,
	char *desc,
	char *wkstas,
	char *unk_str,
	char *mung_dial,

	uint32 user_rid,
	uint32 group_rid,
	uint16 acb_info, 

	uint32 unknown_3,
	uint16 logon_divs,
	LOGON_HRS *hrs,
	uint32 unknown_5,
	uint32 unknown_6)
{
	int len_user_name    = user_name != NULL ? strlen(user_name) : 0;
	int len_full_name    = full_name != NULL ? strlen(full_name) : 0;
	int len_home_dir     = home_dir  != NULL ? strlen(home_dir ) : 0;
	int len_dir_drive    = dir_drive != NULL ? strlen(dir_drive) : 0;
	int len_logon_script = log_scr   != NULL ? strlen(log_scr  ) : 0;
	int len_profile_path = prof_path != NULL ? strlen(prof_path) : 0;
	int len_description  = desc      != NULL ? strlen(desc     ) : 0;
	int len_workstations = wkstas    != NULL ? strlen(wkstas   ) : 0;
	int len_unknown_str  = unk_str   != NULL ? strlen(unk_str  ) : 0;
	int len_munged_dial  = mung_dial != NULL ? strlen(mung_dial) : 0;

	usr->logon_time            = *logon_time;
	usr->logoff_time           = *logoff_time;
	usr->kickoff_time          = *kickoff_time;
	usr->pass_last_set_time    = *pass_last_set_time;
	usr->pass_can_change_time  = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   );
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   );
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path);
	make_uni_hdr(&(usr->hdr_acct_desc   ), len_description );
	make_uni_hdr(&(usr->hdr_workstations), len_workstations);
	make_uni_hdr(&(usr->hdr_unknown_str ), len_unknown_str );
	make_uni_hdr(&(usr->hdr_munged_dial ), len_munged_dial );

	bzero(usr->nt_pwd, sizeof(usr->nt_pwd));
	bzero(usr->lm_pwd, sizeof(usr->lm_pwd));

	usr->user_rid  = user_rid;
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->unknown_3 = unknown_3; /* 0x00ff ffff */

	usr->logon_divs = logon_divs; /* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;
	usr->unknown_5 = unknown_5; /* 0x0002 0000 */

	bzero(usr->padding1, sizeof(usr->padding1));

	make_unistr2(&(usr->uni_user_name   ), user_name   , len_user_name   );
	make_unistr2(&(usr->uni_full_name   ), full_name   , len_full_name   );
	make_unistr2(&(usr->uni_home_dir    ), home_dir    , len_home_dir    );
	make_unistr2(&(usr->uni_dir_drive   ), dir_drive   , len_dir_drive   );
	make_unistr2(&(usr->uni_logon_script), log_scr, len_logon_script);
	make_unistr2(&(usr->uni_profile_path), prof_path, len_profile_path);
	make_unistr2(&(usr->uni_acct_desc ), desc , len_description );
	make_unistr2(&(usr->uni_workstations), wkstas, len_workstations);
	make_unistr2(&(usr->uni_unknown_str ), unk_str , len_unknown_str );
	make_unistr2(&(usr->uni_munged_dial ), mung_dial , len_munged_dial );

	usr->unknown_6 = unknown_6; /* 0x0000 04ec */
	usr->padding4 = 0;

	if (hrs)
	{
		memcpy(&(usr->logon_hrs), hrs, sizeof(usr->logon_hrs));
	}
	else
	{
		memset(&(usr->logon_hrs), 0xff, sizeof(usr->logon_hrs));
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info21(char *desc,  SAM_USER_INFO_21 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return False;

	prs_debug(ps, depth, desc, "sam_io_user_info21");
	depth++;

	prs_align(ps);
	
	smb_io_time("logon_time           ", &(usr->logon_time)           , ps, depth);
	smb_io_time("logoff_time          ", &(usr->logoff_time)          , ps, depth); 
	smb_io_time("kickoff_time         ", &(usr->kickoff_time)         , ps, depth); 
	smb_io_time("pass_last_set_time   ", &(usr->pass_last_set_time)   , ps, depth); 
	smb_io_time("pass_can_change_time ", &(usr->pass_can_change_time) , ps, depth); 
	smb_io_time("pass_must_change_time", &(usr->pass_must_change_time), ps, depth); 

	smb_io_unihdr("hdr_user_name   ", &(usr->hdr_user_name)   , ps, depth); /* username unicode string header */
	smb_io_unihdr("hdr_full_name   ", &(usr->hdr_full_name)   , ps, depth); /* user's full name unicode string header */
	smb_io_unihdr("hdr_home_dir    ", &(usr->hdr_home_dir)    , ps, depth); /* home directory unicode string header */
	smb_io_unihdr("hdr_dir_drive   ", &(usr->hdr_dir_drive)   , ps, depth); /* home directory drive */
	smb_io_unihdr("hdr_logon_script", &(usr->hdr_logon_script), ps, depth); /* logon script unicode string header */
	smb_io_unihdr("hdr_profile_path", &(usr->hdr_profile_path), ps, depth); /* profile path unicode string header */
	smb_io_unihdr("hdr_acct_desc   ", &(usr->hdr_acct_desc  ) , ps, depth); /* account desc */
	smb_io_unihdr("hdr_workstations", &(usr->hdr_workstations), ps, depth); /* wkstas user can log on from */
	smb_io_unihdr("hdr_unknown_str ", &(usr->hdr_unknown_str ), ps, depth); /* unknown string */
	smb_io_unihdr("hdr_munged_dial ", &(usr->hdr_munged_dial ), ps, depth); /* wkstas user can log on from */

	prs_uint8s (False, "lm_pwd        ", ps, depth, usr->lm_pwd   , sizeof(usr->lm_pwd   ));
	prs_uint8s (False, "nt_pwd        ", ps, depth, usr->nt_pwd   , sizeof(usr->nt_pwd   ));

	prs_uint32("user_rid      ", ps, depth, &(usr->user_rid     ));       /* User ID */
	prs_uint32("group_rid     ", ps, depth, &(usr->group_rid    ));      /* Group ID */
	prs_uint16("acb_info      ", ps, depth, &(usr->acb_info     ));      /* Group ID */
	prs_align(ps);

	prs_uint32("unknown_3     ", ps, depth, &(usr->unknown_3    ));
	prs_uint16("logon_divs    ", ps, depth, &(usr->logon_divs   ));     /* logon divisions per week */
	prs_align(ps);
	prs_uint32("ptr_logon_hrs ", ps, depth, &(usr->ptr_logon_hrs));
	prs_uint32("unknown_5     ", ps, depth, &(usr->unknown_5    ));

	prs_uint8s (False, "padding1      ", ps, depth, usr->padding1, sizeof(usr->padding1));

	/* here begins pointed-to data */

	smb_io_unistr2("uni_user_name   ", &(usr->uni_user_name)   , usr->hdr_user_name   .buffer, ps, depth); /* username unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_full_name   ", &(usr->uni_full_name)   , usr->hdr_full_name   .buffer, ps, depth); /* user's full name unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_home_dir    ", &(usr->uni_home_dir)    , usr->hdr_home_dir    .buffer, ps, depth); /* home directory unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_dir_drive   ", &(usr->uni_dir_drive)   , usr->hdr_dir_drive   .buffer, ps, depth); /* home directory drive unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_logon_script", &(usr->uni_logon_script), usr->hdr_logon_script.buffer, ps, depth); /* logon script unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_profile_path", &(usr->uni_profile_path), usr->hdr_profile_path.buffer, ps, depth); /* profile path unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_acct_desc   ", &(usr->uni_acct_desc   ), usr->hdr_acct_desc   .buffer, ps, depth); /* user desc unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_workstations", &(usr->uni_workstations), usr->hdr_workstations.buffer, ps, depth); /* worksations user can log on from */
	prs_align(ps);
	smb_io_unistr2("uni_unknown_str ", &(usr->uni_unknown_str ), usr->hdr_unknown_str .buffer, ps, depth); /* unknown string */
	prs_align(ps);
	smb_io_unistr2("uni_munged_dial ", &(usr->uni_munged_dial ), usr->hdr_munged_dial .buffer, ps, depth); /* worksations user can log on from */
	prs_align(ps);

	prs_uint32("unknown_6     ", ps, depth, &(usr->unknown_6  ));
	prs_uint32("padding4      ", ps, depth, &(usr->padding4   ));

	if (usr->ptr_logon_hrs)
	{
		sam_io_logon_hrs("logon_hrs", &(usr->logon_hrs)   , ps, depth);
		prs_align(ps);
	}

	return True;
}

/*******************************************************************
makes a SAM_USERINFO_CTR structure.
********************************************************************/
uint32 make_samr_userinfo_ctr_usr21(SAM_USERINFO_CTR *ctr,
				uint16 switch_value,
				const SAM_USER_INFO_21 *usr)
{
	if (ctr == NULL || usr == NULL) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(5,("make_samr_userinfo_ctr\n"));

	ctr->switch_value  = switch_value;
	ctr->info.id = NULL;

	switch (switch_value)
	{
		case 0x10:
		{
			ctr->info.id = (SAM_USER_INFO_10*)Realloc(NULL,
					 sizeof(*ctr->info.id10));
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			make_sam_user_info10(ctr->info.id10, usr->acb_info); 
			break;
		}
#if 0
/* whoops - got this wrong.  i think.  or don't understand what's happening. */
		case 0x11:
		{
			NTTIME expire;
			info = (void*)&id11;
			
			expire.low  = 0xffffffff;
			expire.high = 0x7fffffff;

			ctr->info.id = (SAM_USER_INFO_11*)Realloc(NULL,
					 sizeof(*ctr->info.id11));
			make_sam_user_info11(ctr->info.id11, &expire,
					     "BROOKFIELDS$", /* name */
					     0x03ef, /* user rid */
					     0x201, /* group rid */
					     0x0080); /* acb info */

			break;
		}
#endif
		case 0x12:
		{
			ctr->info.id = (SAM_USER_INFO_12*)Realloc(NULL,
					 sizeof(*ctr->info.id12));
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			if (IS_BITS_SET_ALL(usr->acb_info, ACB_DISABLED))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
			make_sam_user_info12(ctr->info.id12,
			                     usr->acb_info,
			                     usr->lm_pwd, usr->nt_pwd); 
			break;
		}
		case 21:
		{
			SAM_USER_INFO_21 *cusr;
			cusr = (SAM_USER_INFO_21*)Realloc(NULL,
					 sizeof(*cusr));
			ctr->info.id = cusr;
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			memcpy(cusr, usr, sizeof(*usr));
			memset(cusr->lm_pwd, 0, sizeof(cusr->lm_pwd));
			memset(cusr->nt_pwd, 0, sizeof(cusr->nt_pwd));
			break;
		}
		default:
		{
			DEBUG(4,("make_samr_userinfo_ctr: unsupported info\n"));
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
makes a SAM_USERINFO_CTR structure.
********************************************************************/
BOOL make_samr_userinfo_ctr(SAM_USERINFO_CTR *ctr, const uchar *sess_key,
				uint16 switch_value, void *info)
{
	if (ctr == NULL) return False;

	DEBUG(5,("make_samr_userinfo_ctr\n"));

	ctr->switch_value  = switch_value;
	ctr->info.id = info;

	switch (switch_value)
	{
		case 0x18:
		{
			SamOEMhash(ctr->info.id24->pass, sess_key, 1);
			dump_data_pw("sess_key", sess_key, 16);
			dump_data_pw("passwd", ctr->info.id24->pass, 516);
			break;
		}
		case 0x17:
		{
			SamOEMhash(ctr->info.id23->pass, sess_key, 1);
			dump_data_pw("sess_key", sess_key, 16);
			dump_data_pw("passwd", ctr->info.id23->pass, 516);
			break;
		}
		default:
		{
			DEBUG(4,("make_samr_userinfo_ctr: unsupported switch level\n"));
			return False;
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_userinfo_ctr(char *desc,  SAM_USERINFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_userinfo_ctr");
	depth++;

	prs_uint16("switch_value", ps, depth, &(ctr->switch_value));
	prs_align(ps);

	switch (ctr->switch_value)
	{
		case 0x10:
		{
			if (ps->io)
			{
				/* reading */
				ctr->info.id = (SAM_USER_INFO_10*)Realloc(NULL,
						 sizeof(*ctr->info.id10));
			}
			if (ctr->info.id10 != NULL)
			{
				sam_io_user_info10("", ctr->info.id10, ps, depth);
			}
			else
			{
				DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			break;
		}
		case 0x11:
		{
			if (ps->io)
			{
				/* reading */
				ctr->info.id = (SAM_USER_INFO_11*)Realloc(NULL,
						 sizeof(*ctr->info.id11));
			}
			if (ctr->info.id11 != NULL)
			{
				sam_io_user_info11("", ctr->info.id11, ps, depth);
			}
			else
			{
				DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			break;
		}
		case 0x12:
		{
			DEBUG(0,("samr_io_userinfo_ctr: security breach!\n"));
			return False;
#if 0
			if (ps->io)
			{
				/* reading */
				ctr->info.id = (SAM_USER_INFO_12*)Realloc(NULL,
						 sizeof(*ctr->info.id12));
			}
			if (ctr->info.id12 != NULL)
			{
				sam_io_user_info12("", ctr->info.id12, ps, depth);
			}
			else
			{
				DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			break;
#endif
		}
		case 21:
		{
			if (ps->io)
			{
				/* reading */
				ctr->info.id = (SAM_USER_INFO_21*)Realloc(NULL,
						 sizeof(*ctr->info.id21));
			}
			if (ctr->info.id21 != NULL)
			{
				sam_io_user_info21("", ctr->info.id21, ps, depth);
			}
			else
			{
				DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			break;
		}
		case 23:
		{
			if (ps->io)
			{
				/* reading */
				ctr->info.id = (SAM_USER_INFO_23*)Realloc(NULL,
						 sizeof(*ctr->info.id23));
			}
			if (ctr->info.id23 != NULL)
			{
				sam_io_user_info23("", ctr->info.id23, ps, depth);
			}
			else
			{
				DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			break;
		}
		case 24:
		{
			if (ps->io)
			{
				/* reading */
				ctr->info.id = (SAM_USER_INFO_24*)Realloc(NULL,
						 sizeof(*ctr->info.id24));
			}
			if (ctr->info.id24 != NULL)
			{
				sam_io_user_info24("", ctr->info.id24, ps, depth);
			}
			else
			{
				DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			break;
		}
		default:
		{
			DEBUG(2,("samr_io_userinfo_ctr: unknown switch level\n"));
			break;
		}
			
	}

	prs_align(ps);

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void free_samr_userinfo_ctr(SAM_USERINFO_CTR *ctr)
{
	if (ctr->info.id == NULL)
	{
		free(ctr->info.id);
	}
	ctr->info.id = NULL;
}


/*******************************************************************
makes a SAMR_R_QUERY_USERINFO structure.
********************************************************************/
BOOL make_samr_r_query_userinfo(SAMR_R_QUERY_USERINFO *r_u,
				SAM_USERINFO_CTR *ctr, uint32 status)
				
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_query_userinfo\n"));

	r_u->ptr = 0;
	r_u->ctr = NULL;

	if (status == 0)
	{
		r_u->ptr = 1;
		r_u->ctr = ctr;
	}

	r_u->status = status;         /* return status */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_userinfo(char *desc,  SAMR_R_QUERY_USERINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_query_userinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));

	if (r_u->ptr != 0)
	{
		samr_io_userinfo_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* writing */
		if (r_u->ctr != NULL)
		{
			free_samr_userinfo_ctr(r_u->ctr);
		}
	}
	return True;
}

/*******************************************************************
makes a SAMR_Q_SET_USERINFO structure.
********************************************************************/
BOOL make_samr_q_set_userinfo(SAMR_Q_SET_USERINFO *q_u,
				POLICY_HND *hnd,
				uint16 switch_value, void *info)
{
	uchar sess_key[16];
	if (q_u == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_set_userinfo\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));
	q_u->switch_value = switch_value;

	if (!cli_get_usr_sesskey(hnd, sess_key))
	{
		DEBUG(0,("make_samr_set_userinfo: could not obtain session key\n"));
		return False;
	}
	if (!make_samr_userinfo_ctr(q_u->ctr, sess_key, switch_value, info))
	{
		return False;
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_set_userinfo(char *desc, SAMR_Q_SET_USERINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_set_userinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value));
	samr_io_userinfo_ctr("ctr", q_u->ctr, ps, depth);

	if (!ps->io)
	{
		/* writing */
		free_samr_q_set_userinfo(q_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void free_samr_q_set_userinfo(SAMR_Q_SET_USERINFO *q_u)
{
	free_samr_userinfo_ctr(q_u->ctr);
}

/*******************************************************************
makes a SAMR_R_SET_USERINFO structure.
********************************************************************/
BOOL make_samr_r_set_userinfo(SAMR_R_SET_USERINFO *r_u, uint32 status)
				
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_set_userinfo\n"));

	r_u->status = status;         /* return status */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_set_userinfo(char *desc,  SAMR_R_SET_USERINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_set_userinfo");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


/*******************************************************************
makes a SAMR_Q_SET_USERINFO2 structure.
********************************************************************/
BOOL make_samr_q_set_userinfo2(SAMR_Q_SET_USERINFO2 *q_u,
				POLICY_HND *hnd,
				uint16 switch_value, 
				SAM_USERINFO_CTR *ctr)
{
	if (q_u == NULL || hnd == NULL) return False;

	DEBUG(5,("make_samr_q_set_userinfo2\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));
	q_u->switch_value  = switch_value;
	q_u->ctr = ctr;

	if (q_u->ctr != NULL)
	{
		q_u->ctr->switch_value = switch_value;
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_set_userinfo2(char *desc, SAMR_Q_SET_USERINFO2 *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_set_userinfo2");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value ", ps, depth, &(q_u->switch_value )); 
	samr_io_userinfo_ctr("ctr", q_u->ctr, ps, depth);

	if (!ps->io)
	{
		/* writing */
		free_samr_q_set_userinfo2(q_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void free_samr_q_set_userinfo2(SAMR_Q_SET_USERINFO2 *q_u)
{
	free_samr_userinfo_ctr(q_u->ctr);
}

/*******************************************************************
makes a SAMR_R_SET_USERINFO2 structure.
********************************************************************/
BOOL make_samr_r_set_userinfo2(SAMR_R_SET_USERINFO2 *r_u,
				uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_samr_r_set_userinfo2\n"));

	r_u->status = status;         /* return status */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_set_userinfo2(char *desc,  SAMR_R_SET_USERINFO2 *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_set_userinfo2");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_CONNECT structure.
********************************************************************/
BOOL make_samr_q_connect(SAMR_Q_CONNECT *q_u,
				const char *srv_name, uint32 access_mask)
{
	int len_srv_name = strlen(srv_name);

	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_connect\n"));

	/* make PDC server name \\server */
	q_u->ptr_srv_name = len_srv_name > 0 ? 1 : 0; 
	make_unistr2(&(q_u->uni_srv_name), srv_name, len_srv_name+1);  

	/* example values: 0x0000 0002 */
	q_u->access_mask = access_mask; 

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_connect(char *desc,  SAMR_Q_CONNECT *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_connect");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	smb_io_unistr2("", &(q_u->uni_srv_name), q_u->ptr_srv_name, ps, depth); 

	prs_align(ps);

	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_connect(char *desc,  SAMR_R_CONNECT *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_connect");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(r_u->connect_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_CONNECT_ANON structure.
********************************************************************/
BOOL make_samr_q_connect_anon(SAMR_Q_CONNECT_ANON *q_u)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_connect_anon\n"));

	q_u->ptr       = 1;
	q_u->unknown_0 = 0x5c; /* server name (?!!) */
	q_u->unknown_1 = 0x01;
	q_u->access_mask = 0x20;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_connect_anon(char *desc,  SAMR_Q_CONNECT_ANON *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_connect_anon");
	depth++;

	prs_align(ps);

	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint16("unknown_0", ps, depth, &(q_u->unknown_0));
	prs_uint16("unknown_1", ps, depth, &(q_u->unknown_1));
	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_connect_anon(char *desc,  SAMR_R_CONNECT_ANON *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_connect_anon");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(r_u->connect_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
makes a SAMR_Q_GET_DOM_PWINFO structure.
********************************************************************/
BOOL make_samr_q_get_dom_pwinfo(SAMR_Q_GET_DOM_PWINFO *q_u, const char *srv_name)
{
	int len_srv_name = strlen(srv_name);

	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_get_dom_pwinfo\n"));

	q_u->ptr = 1;
	make_uni_hdr(&(q_u->hdr_srv_name), len_srv_name);
	make_unistr2(&(q_u->uni_srv_name), srv_name, len_srv_name);  


	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_get_dom_pwinfo(char *desc,  SAMR_Q_GET_DOM_PWINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_get_dom_pwinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(q_u->ptr));
	if (q_u->ptr != 0)
	{
		smb_io_unihdr ("", &(q_u->hdr_srv_name), ps, depth); 
		smb_io_unistr2("", &(q_u->uni_srv_name), q_u->hdr_srv_name.buffer, ps, depth); 
		prs_align(ps);
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_get_dom_pwinfo(char *desc,  SAMR_R_GET_DOM_PWINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_get_dom_pwinfo");
	depth++;

	prs_align(ps);

	prs_uint16("unk_0", ps, depth, &(r_u->unk_0));
	prs_align(ps);
	prs_uint16("unk_1", ps, depth, &(r_u->unk_1));
	prs_align(ps);
	prs_uint16("unk_2", ps, depth, &(r_u->unk_2));
	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
make a SAMR_ENC_PASSWD structure.
********************************************************************/
BOOL make_enc_passwd(SAMR_ENC_PASSWD *pwd, const char pass[512])
{
	ZERO_STRUCTP(pwd);

	if (pwd == NULL) return False;

	if (pass == NULL)
	{
		pwd->ptr = 0;
		return True;
	}
	pwd->ptr = 1;
	memcpy(pwd->pass, pass, sizeof(pwd->pass)); 

	return True;
}

/*******************************************************************
reads or writes a SAMR_ENC_PASSWD structure.
********************************************************************/
BOOL samr_io_enc_passwd(char *desc, SAMR_ENC_PASSWD *pwd, prs_struct *ps, int depth)
{
	if (pwd == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_enc_passwd");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(pwd->ptr));
	if (pwd->ptr != 0)
	{
		prs_uint8s(False, "pwd", ps, depth, pwd->pass, sizeof(pwd->pass)); 
	}

	return True;
}

/*******************************************************************
makes a SAMR_ENC_HASH structure.
********************************************************************/
BOOL make_enc_hash(SAMR_ENC_HASH *hsh, const uchar hash[16])
{
	ZERO_STRUCTP(hsh);

	if (hsh == NULL) return False;

	if (hash == NULL)
	{
		hsh->ptr = 0;
		return True;
	}

	hsh->ptr = 1;
	memcpy(hsh->hash, hash, sizeof(hsh->hash));

	return True;
}

/*******************************************************************
reads or writes a SAMR_ENC_HASH structure.
********************************************************************/
BOOL samr_io_enc_hash(char *desc, SAMR_ENC_HASH *hsh, prs_struct *ps, int depth)
{
	if (hsh == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_enc_hash");
	depth++;

	prs_align(ps);

	prs_uint32("ptr ", ps, depth, &(hsh->ptr));
	if (hsh->ptr != 0)
	{
		prs_uint8s(False, "hash", ps, depth, hsh->hash, sizeof(hsh->hash)); 
	}

	return True;
}

/*******************************************************************
makes a SAMR_R_GET_DOM_PWINFO structure.
********************************************************************/
BOOL make_samr_q_chgpasswd_user(SAMR_Q_CHGPASSWD_USER *q_u,
				const char *dest_host, const char *user_name,
				const char nt_newpass[516],
				const uchar nt_oldhash[16],
				const char lm_newpass[516],
				const uchar lm_oldhash[16])
{
	int len_dest_host = strlen(dest_host);
	int len_user_name = strlen(user_name);

	if (q_u == NULL) return False;

	DEBUG(5,("make_samr_q_chgpasswd_user\n"));

	q_u->ptr_0 = 1;
	make_uni_hdr(&(q_u->hdr_dest_host), len_dest_host);
	make_unistr2(&(q_u->uni_dest_host), dest_host, len_dest_host);  
	make_uni_hdr(&(q_u->hdr_user_name), len_user_name);
	make_unistr2(&(q_u->uni_user_name), user_name, len_user_name);  

	make_enc_passwd(&(q_u->nt_newpass), nt_newpass);
	make_enc_hash  (&(q_u->nt_oldhash), nt_oldhash);

	q_u->unknown = 0x01;

	make_enc_passwd(&(q_u->lm_newpass), lm_newpass);
	make_enc_hash  (&(q_u->lm_oldhash), lm_oldhash);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_chgpasswd_user(char *desc, SAMR_Q_CHGPASSWD_USER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_q_chgpasswd_user");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0", ps, depth, &(q_u->ptr_0));

	smb_io_unihdr ("", &(q_u->hdr_dest_host), ps, depth); 
	smb_io_unistr2("", &(q_u->uni_dest_host), q_u->hdr_dest_host.buffer, ps, depth); 
	prs_align(ps);

	smb_io_unihdr ("", &(q_u->hdr_user_name), ps, depth); 
	smb_io_unistr2("", &(q_u->uni_user_name), q_u->hdr_user_name.buffer, ps, depth); 
	prs_align(ps);

	samr_io_enc_passwd("nt_newpass", &(q_u->nt_newpass), ps, depth); 
	samr_io_enc_hash  ("nt_oldhash", &(q_u->nt_oldhash), ps, depth); 

	prs_uint32("unknown", ps, depth, &(q_u->unknown));

	samr_io_enc_passwd("lm_newpass", &(q_u->lm_newpass), ps, depth); 
	samr_io_enc_hash  ("lm_oldhash", &(q_u->lm_oldhash), ps, depth); 

	return True;
}

/*******************************************************************
makes a SAMR_R_CHGPASSWD_USER structure.
********************************************************************/
BOOL make_samr_r_chgpasswd_user(SAMR_R_CHGPASSWD_USER *r_u, uint32 status)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_r_chgpasswd_user\n"));

	r_u->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_chgpasswd_user(char *desc, SAMR_R_CHGPASSWD_USER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "samr_io_r_chgpasswd_user");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


