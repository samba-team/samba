/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
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
makes a SAMR_Q_CLOSE_HND structure.
********************************************************************/
void make_samr_q_close_hnd(SAMR_Q_CLOSE_HND *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_close_hnd\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_close_hnd(char *desc,  SAMR_Q_CLOSE_HND *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_close_hnd");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_close_hnd(char *desc,  SAMR_R_CLOSE_HND *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_close_hnd");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_samr_q_open_domain(SAMR_Q_OPEN_DOMAIN *q_u,
				POLICY_HND *connect_pol, uint32 rid,
				DOM_SID *sid)
{
	if (q_u == NULL) return;

	DEBUG(5,("samr_make_samr_q_open_domain\n"));

	memcpy(&q_u->connect_pol, connect_pol, sizeof(q_u->connect_pol));
	q_u->rid = rid;
	make_dom_sid2(&(q_u->dom_sid), sid);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_open_domain(char *desc,  SAMR_Q_OPEN_DOMAIN *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_open_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(q_u->connect_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("rid", ps, depth, &(q_u->rid));

	smb_io_dom_sid2("sid", &(q_u->dom_sid), ps, depth); 
	prs_align(ps);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_open_domain(char *desc,  SAMR_R_OPEN_DOMAIN *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_open_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(r_u->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_samr_q_unknown_2c(SAMR_Q_UNKNOWN_2C *q_u, POLICY_HND *user_pol)
{
	if (q_u == NULL) return;

	DEBUG(5,("samr_make_samr_q_unknown_2c\n"));

	memcpy(&q_u->user_pol, user_pol, sizeof(q_u->user_pol));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_unknown_2c(char *desc,  SAMR_Q_UNKNOWN_2C *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_unknown_2c");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(q_u->user_pol), ps, depth); 
	prs_align(ps);
}

/*******************************************************************
makes a structure.
********************************************************************/
void make_samr_r_unknown_2c(SAMR_R_UNKNOWN_2C *q_u, uint32 status)
{
	if (q_u == NULL) return;

	DEBUG(5,("samr_make_r_unknown_2c\n"));

	q_u->unknown_0 = 0x00160000;
	q_u->unknown_1 = 0x00000000;
	q_u->status    = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_unknown_2c(char *desc,  SAMR_R_UNKNOWN_2C *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_2c");
	depth++;

	prs_align(ps);

	prs_uint32("unknown_0", ps, depth, &(r_u->unknown_0));
	prs_uint32("unknown_1", ps, depth, &(r_u->unknown_1));
	prs_uint32("status   ", ps, depth, &(r_u->status   ));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_samr_q_unknown_3(SAMR_Q_UNKNOWN_3 *q_u,
				POLICY_HND *user_pol, uint16 switch_value)
{
	if (q_u == NULL) return;

	DEBUG(5,("samr_make_samr_q_unknown_3\n"));

	memcpy(&q_u->user_pol, user_pol, sizeof(q_u->user_pol));
	q_u->switch_value = switch_value;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_unknown_3(char *desc,  SAMR_Q_UNKNOWN_3 *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_unknown_3");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(q_u->user_pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value));
	prs_align(ps);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_samr_q_query_dom_info(SAMR_Q_QUERY_DOMAIN_INFO *q_u,
				POLICY_HND *domain_pol, uint16 switch_value)
{
	if (q_u == NULL) return;

	DEBUG(5,("samr_make_samr_q_query_dom_info\n"));

	memcpy(&q_u->domain_pol, domain_pol, sizeof(q_u->domain_pol));
	q_u->switch_value = switch_value;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_dom_info(char *desc,  SAMR_Q_QUERY_DOMAIN_INFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_dom_info");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value));
	prs_align(ps);
}

/*******************************************************************
makes a structure.
********************************************************************/
void make_unk_info2(SAM_UNK_INFO_2 *u_2, char *domain, char *server)
{
	int len_domain = strlen(domain);
	int len_server = strlen(server);

	if (u_2 == NULL) return;

	u_2->unknown_0 = 0x00000000;
	u_2->unknown_1 = 0x80000000;
	u_2->unknown_2 = 0x00000000;

	u_2->ptr_0 = 1;
	make_uni_hdr(&(u_2->hdr_domain), len_domain, len_domain, 1);
	make_uni_hdr(&(u_2->hdr_server), len_server, len_server, 1);

	u_2->seq_num = 0x10000000;
	u_2->unknown_3 = 0x00000000;
	
	u_2->unknown_4  = 0x00000001;
	u_2->unknown_5  = 0x00000003;
	u_2->unknown_6  = 0x00000001;
	u_2->num_domain_usrs  = 0x00000008;
	u_2->num_domain_grps = 0x00000003;
	u_2->num_local_grps = 0x00000003;

	memset(u_2->padding, 0, sizeof(u_2->padding)); /* 12 bytes zeros */

	make_unistr2(&u_2->uni_domain, domain, len_domain);
	make_unistr2(&u_2->uni_server, server, len_server);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void sam_io_unk_info2(char *desc, SAM_UNK_INFO_2 *u_2, prs_struct *ps, int depth)
{
	if (u_2 == NULL) return;

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
	smb_io_unistr2( "uni_server", &u_2->uni_server, u_2->hdr_server.buffer, ps, depth); /* server name unicode string */

	prs_align(ps);

}

/*******************************************************************
makes a SAMR_R_QUERY_DOMAIN_INFO structure.
********************************************************************/
void make_samr_r_query_dom_info(SAMR_R_QUERY_DOMAIN_INFO *r_u, 
				uint16 switch_value, SAM_UNK_CTR *ctr,
				uint32 status)
{
	if (r_u == NULL || ctr == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_dom_info(char *desc, SAMR_R_QUERY_DOMAIN_INFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_query_dom_info");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0       ", ps, depth, &(r_u->ptr_0));
	prs_uint16("switch_value", ps, depth, &(r_u->switch_value));
	prs_align(ps);

	if (r_u->ptr_0 != 0 && r_u->ctr != NULL)
	{
		switch (r_u->switch_value)
		{
			case 0x02:
			{
				sam_io_unk_info2("unk_inf2", &r_u->ctr->info.inf2, ps, depth);
				break;
			}
			default:
			{
				DEBUG(3,("samr_io_r_query_dom_info: unknown switch level 0x%x\n",
				          r_u->switch_value));
				return;
			}
		}
	}
}


/*******************************************************************
 makes a DOM_SID3 structure.

 calculate length by adding up the size of the components.
 ********************************************************************/
void make_dom_sid3(DOM_SID3 *sid3, uint16 unk_0, uint16 unk_1, DOM_SID *sid)
{
	if (sid3 == NULL) return;

    sid3->sid = *sid;
	sid3->len = 2 + 8 + sid3->sid.num_auths * 4;
}

/*******************************************************************
reads or writes a SAM_SID3 structure.

this one's odd, because the length (in bytes) is specified at the beginning.
the length _includes_ the length of the length, too :-)

********************************************************************/
static void sam_io_dom_sid3(char *desc,  DOM_SID3 *sid3, prs_struct *ps, int depth)
{
	if (sid3 == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_dom_sid3");
	depth++;

	prs_uint16("len", ps, depth, &(sid3->len));
	prs_align(ps);
	smb_io_dom_sid("", &(sid3->sid), ps, depth); 
}

/*******************************************************************
makes a SAMR_R_UNKNOWN3 structure.

unknown_2   : 0x0001
unknown_3   : 0x8004

unknown_4,5 : 0x0000 0014

unknown_6   : 0x0002
unknown_7   : 0x5800 or 0x0070

********************************************************************/
static void make_sam_sid_stuff(SAM_SID_STUFF *stf,
				uint16 unknown_2, uint16 unknown_3,
				uint32 unknown_4, uint16 unknown_6, uint16 unknown_7,
				int num_sid3s, DOM_SID3 sid3[MAX_SAM_SIDS])
{
	stf->unknown_2 = unknown_2;
	stf->unknown_3 = unknown_3;

	bzero(stf->padding1, sizeof(stf->padding1));

	stf->unknown_4 = unknown_4;
	stf->unknown_5 = unknown_4;

	stf->unknown_6 = unknown_6;
	stf->unknown_7 = unknown_7;

	stf->num_sids  = num_sid3s;

	stf->padding2  = 0x0000;

	memcpy(stf->sid, sid3, sizeof(DOM_SID3) * num_sid3s);
}

/*******************************************************************
reads or writes a SAM_SID_STUFF structure.
********************************************************************/
static void sam_io_sid_stuff(char *desc,  SAM_SID_STUFF *stf, prs_struct *ps, int depth)
{
	int i;

	if (stf == NULL) return;

	DEBUG(5,("make_sam_sid_stuff\n"));

	prs_uint16("unknown_2", ps, depth, &(stf->unknown_2));
	prs_uint16("unknown_3", ps, depth, &(stf->unknown_3));

	prs_uint8s(False, "padding1", ps, depth, stf->padding1, sizeof(stf->padding1)); 
	
	prs_uint32("unknown_4", ps, depth, &(stf->unknown_4));
	prs_uint32("unknown_5", ps, depth, &(stf->unknown_5));
	prs_uint16("unknown_6", ps, depth, &(stf->unknown_6));
	prs_uint16("unknown_7", ps, depth, &(stf->unknown_7));

	prs_uint32("num_sids ", ps, depth, &(stf->num_sids ));
	prs_uint16("padding2 ", ps, depth, &(stf->padding2 ));

	SMB_ASSERT_ARRAY(stf->sid, stf->num_sids);

	for (i = 0; i < stf->num_sids; i++)
	{
		sam_io_dom_sid3("", &(stf->sid[i]), ps, depth); 
	}
}

/*******************************************************************
reads or writes a SAMR_R_UNKNOWN3 structure.
********************************************************************/
void make_samr_r_unknown_3(SAMR_R_UNKNOWN_3 *r_u,
				uint16 unknown_2, uint16 unknown_3,
				uint32 unknown_4, uint16 unknown_6, uint16 unknown_7,
				int num_sid3s, DOM_SID3 sid3[MAX_SAM_SIDS],
				uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("samr_make_r_unknown_3\n"));

	r_u->ptr_0 = 0;
	r_u->ptr_1 = 0;

	if (status == 0x0)
	{
		r_u->ptr_0 = 1;
		r_u->ptr_1 = 1;
		make_sam_sid_stuff(&(r_u->sid_stuff), unknown_2, unknown_3,
	               unknown_4, unknown_6, unknown_7,
	               num_sid3s, sid3);
	}

	r_u->status = status;
}


/*******************************************************************
reads or writes a SAMR_R_UNKNOWN_3 structure.

this one's odd, because the daft buggers use a different mechanism
for writing out the array of sids. they put the number of sids in
only one place: they've calculated the length of each sid and jumped
by that amount.  then, retrospectively, the length of the whole buffer
is put at the beginning of the data stream.

wierd.  

********************************************************************/
void samr_io_r_unknown_3(char *desc,  SAMR_R_UNKNOWN_3 *r_u, prs_struct *ps, int depth)
{
	int ptr_len0=0;
	int ptr_len1=0;
	int ptr_sid_stuff = 0;

	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_3");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0         ", ps, depth, &(r_u->ptr_0         ));

	if (ps->io) 
	{
		/* reading.  do the length later */
		prs_uint32("sid_stuff_len0", ps, depth, &(r_u->sid_stuff_len0));
	}
	else
	{
		/* storing */
		ptr_len0 = ps->offset; ps->offset += 4;
	}

	if (r_u->ptr_0 != 0)
	{
		prs_uint32("ptr_1         ", ps, depth, &(r_u->ptr_1         ));
		if (ps->io)
		{
			/* reading.  do the length later */
			prs_uint32("sid_stuff_len1", ps, depth, &(r_u->sid_stuff_len1));
		}
		else
		{
			/* storing */
			ptr_len1 = ps->offset; ps->offset += 4;
		}

		if (r_u->ptr_1 != 0)
		{
			ptr_sid_stuff = ps->offset;
			sam_io_sid_stuff("", &(r_u->sid_stuff), ps, depth); 
		}
	}

	if (!(ps->io)) /* storing not reading.  do the length, now. */
	{
		if (ptr_sid_stuff != 0)
		{
			uint32 sid_stuff_len = ps->offset - ptr_sid_stuff;
			int old_len = ps->offset;

			ps->offset = ptr_len0;
			prs_uint32("sid_stuff_len0", ps, depth, &sid_stuff_len); 

			ps->offset = ptr_len1;
			prs_uint32("sid_stuff_len1", ps, depth, &sid_stuff_len);

			ps->offset = old_len;
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
reads or writes a SAM_STR1 structure.
********************************************************************/
static void sam_io_sam_str1(char *desc,  SAM_STR1 *sam, uint32 acct_buf, uint32 name_buf, uint32 desc_buf, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_str1");
	depth++;

	prs_align(ps);

	smb_io_unistr2("unistr2", &(sam->uni_acct_name), acct_buf, ps, depth); /* account name unicode string */
	smb_io_unistr2("unistr2", &(sam->uni_full_name), name_buf, ps, depth); /* full name unicode string */
	smb_io_unistr2("unistr2", &(sam->uni_acct_desc), desc_buf, ps, depth); /* account description unicode string */
}

/*******************************************************************
makes a SAM_ENTRY1 structure.
********************************************************************/
static void make_sam_entry1(SAM_ENTRY1 *sam, uint32 user_idx, 
				uint32 len_sam_name, uint32 len_sam_full, uint32 len_sam_desc,
				uint32 rid_user, uint16 acb_info)
{
	if (sam == NULL) return;

	DEBUG(5,("make_sam_entry1\n"));

	sam->user_idx = user_idx;
	sam->rid_user = rid_user;
	sam->acb_info = acb_info;
	sam->pad      = 0;

	make_uni_hdr(&(sam->hdr_acct_name), len_sam_name, len_sam_name, len_sam_name != 0);
	make_uni_hdr(&(sam->hdr_user_name), len_sam_full, len_sam_full, len_sam_full != 0);
	make_uni_hdr(&(sam->hdr_user_desc), len_sam_desc, len_sam_desc, len_sam_desc != 0);
}

/*******************************************************************
reads or writes a SAM_ENTRY1 structure.
********************************************************************/
static void sam_io_sam_entry1(char *desc,  SAM_ENTRY1 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

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
}

/*******************************************************************
reads or writes a SAM_STR2 structure.
********************************************************************/
static void sam_io_sam_str2(char *desc,  SAM_STR2 *sam, uint32 acct_buf, uint32 desc_buf, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_str2");
	depth++;

	prs_align(ps);

	smb_io_unistr2("unistr2", &(sam->uni_srv_name), acct_buf, ps, depth); /* account name unicode string */
	smb_io_unistr2("unistr2", &(sam->uni_srv_desc), desc_buf, ps, depth); /* account description unicode string */
}

/*******************************************************************
makes a SAM_ENTRY2 structure.
********************************************************************/
static void make_sam_entry2(SAM_ENTRY2 *sam, uint32 user_idx, 
				uint32 len_sam_name, uint32 len_sam_desc,
				uint32 rid_user, uint16 acb_info)
{
	if (sam == NULL) return;

	DEBUG(5,("make_sam_entry2\n"));

	sam->user_idx = user_idx;
	sam->rid_user = rid_user;
	sam->acb_info = acb_info;
	sam->pad      = 0;

	make_uni_hdr(&(sam->hdr_srv_name), len_sam_name, len_sam_name, len_sam_name != 0);
	make_uni_hdr(&(sam->hdr_srv_desc), len_sam_desc, len_sam_desc, len_sam_desc != 0);
}

/*******************************************************************
reads or writes a SAM_ENTRY2 structure.
********************************************************************/
static void sam_io_sam_entry2(char *desc,  SAM_ENTRY2 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_entry2");
	depth++;

	prs_align(ps);

	prs_uint32("user_idx ", ps, depth, &(sam->user_idx ));

	prs_uint32("rid_user ", ps, depth, &(sam->rid_user ));
	prs_uint16("acb_info ", ps, depth, &(sam->acb_info ));
	prs_uint16("pad      ", ps, depth, &(sam->pad      ));

	smb_io_unihdr("unihdr", &(sam->hdr_srv_name), ps, depth); /* account name unicode string header */
	smb_io_unihdr("unihdr", &(sam->hdr_srv_desc), ps, depth); /* account name unicode string header */
}

/*******************************************************************
reads or writes a SAM_STR3 structure.
********************************************************************/
static void sam_io_sam_str3(char *desc,  SAM_STR3 *sam, uint32 acct_buf, uint32 desc_buf, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_str3");
	depth++;

	prs_align(ps);

	smb_io_unistr2("unistr2", &(sam->uni_grp_name), acct_buf, ps, depth); /* account name unicode string */
	smb_io_unistr2("unistr2", &(sam->uni_grp_desc), desc_buf, ps, depth); /* account description unicode string */
}

/*******************************************************************
makes a SAM_ENTRY3 structure.
********************************************************************/
static void make_sam_entry3(SAM_ENTRY3 *sam, uint32 grp_idx, 
				uint32 len_grp_name, uint32 len_grp_desc, uint32 rid_grp)
{
	if (sam == NULL) return;

	DEBUG(5,("make_sam_entry3\n"));

	sam->grp_idx = grp_idx;
	sam->rid_grp = rid_grp;
	sam->attr    = 0x07; /* group rid attributes - gets ignored by nt 4.0 */

	make_uni_hdr(&(sam->hdr_grp_name), len_grp_name, len_grp_name, len_grp_name != 0);
	make_uni_hdr(&(sam->hdr_grp_desc), len_grp_desc, len_grp_desc, len_grp_desc != 0);
}

/*******************************************************************
reads or writes a SAM_ENTRY3 structure.
********************************************************************/
static void sam_io_sam_entry3(char *desc,  SAM_ENTRY3 *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_entry3");
	depth++;

	prs_align(ps);

	prs_uint32("grp_idx", ps, depth, &(sam->grp_idx));

	prs_uint32("rid_grp", ps, depth, &(sam->rid_grp));
	prs_uint32("attr   ", ps, depth, &(sam->attr   ));

	smb_io_unihdr("unihdr", &(sam->hdr_grp_name), ps, depth); /* account name unicode string header */
	smb_io_unihdr("unihdr", &(sam->hdr_grp_desc), ps, depth); /* account name unicode string header */
}

/*******************************************************************
makes a SAM_ENTRY structure.
********************************************************************/
static void make_sam_entry(SAM_ENTRY *sam, uint32 len_sam_name, uint32 rid)
{
	if (sam == NULL) return;

	DEBUG(5,("make_sam_entry\n"));

	sam->rid = rid;
	make_uni_hdr(&(sam->hdr_name), len_sam_name, len_sam_name, len_sam_name != 0);
}

/*******************************************************************
reads or writes a SAM_ENTRY structure.
********************************************************************/
static void sam_io_sam_entry(char *desc,  SAM_ENTRY *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_entry");
	depth++;

	prs_align(ps);
	prs_uint32("rid", ps, depth, &(sam->rid ));
	smb_io_unihdr("unihdr", &(sam->hdr_name), ps, depth); /* account name unicode string header */
}


/*******************************************************************
makes a SAMR_Q_ENUM_DOM_USERS structure.
********************************************************************/
void make_samr_q_enum_dom_users(SAMR_Q_ENUM_DOM_USERS *q_e, POLICY_HND *pol,
				uint16 req_num_entries, uint16 unk_0,
				uint16 acb_mask, uint16 unk_1, uint32 size)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_enum_dom_users\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->req_num_entries = req_num_entries; /* zero indicates lots */
	q_e->unknown_0 = unk_0; /* this gets returned in the response */
	q_e->acb_mask  = acb_mask;
	q_e->unknown_1 = unk_1;
	q_e->max_size = size;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_enum_dom_users(char *desc,  SAMR_Q_ENUM_DOM_USERS *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_users");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("req_num_entries", ps, depth, &(q_e->req_num_entries));
	prs_uint16("unknown_0      ", ps, depth, &(q_e->unknown_0      ));

	prs_uint16("acb_mask       ", ps, depth, &(q_e->acb_mask       ));
	prs_uint16("unknown_1      ", ps, depth, &(q_e->unknown_1      ));

	prs_uint32("max_size       ", ps, depth, &(q_e->max_size       ));

	prs_align(ps);
}


/*******************************************************************
makes a SAMR_R_ENUM_DOM_USERS structure.
********************************************************************/
void make_samr_r_enum_dom_users(SAMR_R_ENUM_DOM_USERS *r_u,
		uint16 total_num_entries, uint16 unk_0,
		uint32 num_sam_entries, SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES], uint32 status)
{
	int i;

	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_enum_dom_users\n"));

	if (num_sam_entries >= MAX_SAM_ENTRIES)
	{
		num_sam_entries = MAX_SAM_ENTRIES;
		DEBUG(5,("limiting number of entries to %d\n",
			 num_sam_entries));
	}

	r_u->total_num_entries = total_num_entries;
	r_u->unknown_0         = unk_0;

	if (total_num_entries > 0)
	{
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		SMB_ASSERT_ARRAY(r_u->sam, num_sam_entries);
		SMB_ASSERT_ARRAY(r_u->uni_acct_name, num_sam_entries);

		for (i = 0; i < num_sam_entries; i++)
		{
			make_sam_entry(&(r_u->sam[i]),
			               pass[i].uni_user_name.uni_str_len,
			               pass[i].user_rid);

			copy_unistr2(&(r_u->uni_acct_name[i]), &(pass[i].uni_user_name));
		}

		r_u->num_entries4 = num_sam_entries;
	}
	else
	{
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_enum_dom_users(char *desc,  SAMR_R_ENUM_DOM_USERS *r_u, prs_struct *ps, int depth)
{
	int i;

	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_users");
	depth++;

	prs_align(ps);

	prs_uint16("total_num_entries", ps, depth, &(r_u->total_num_entries));
	prs_uint16("unknown_0        ", ps, depth, &(r_u->unknown_0        ));
	prs_uint32("ptr_entries1", ps, depth, &(r_u->ptr_entries1));

	if (r_u->total_num_entries != 0 && r_u->ptr_entries1 != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));
		prs_uint32("ptr_entries2", ps, depth, &(r_u->ptr_entries2));
		prs_uint32("num_entries3", ps, depth, &(r_u->num_entries3));

		SMB_ASSERT_ARRAY(r_u->sam, r_u->num_entries2);

		for (i = 0; i < r_u->num_entries2; i++)
		{
			prs_grow(ps);
			sam_io_sam_entry("", &(r_u->sam[i]), ps, depth);
		}

		SMB_ASSERT_ARRAY(r_u->uni_acct_name, r_u->num_entries2);

		for (i = 0; i < r_u->num_entries2; i++)
		{
			prs_grow(ps);
			smb_io_unistr2("", &(r_u->uni_acct_name[i]), r_u->sam[i].hdr_name.buffer, ps, depth);
		}

		prs_align(ps);

		prs_uint32("num_entries4", ps, depth, &(r_u->num_entries4));
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_QUERY_DISPINFO structure.
********************************************************************/
void make_samr_q_query_dispinfo(SAMR_Q_QUERY_DISPINFO *q_e, POLICY_HND *pol,
				uint16 switch_level, uint32 start_idx, uint32 size)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_query_dispinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;

	q_e->unknown_0 = 0;
	q_e->start_idx = start_idx;
	q_e->unknown_1 = 0x000007d0;
	q_e->max_size  = size;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_dispinfo(char *desc,  SAMR_Q_QUERY_DISPINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_dispinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));
	prs_uint16("unknown_0   ", ps, depth, &(q_e->unknown_0   ));
	prs_uint32("start_idx   ", ps, depth, &(q_e->start_idx   ));
	prs_uint32("unknown_1   ", ps, depth, &(q_e->unknown_1   ));
	prs_uint32("max_size    ", ps, depth, &(q_e->max_size    ));

	prs_align(ps);
}


/*******************************************************************
makes a SAM_INFO_2 structure.
********************************************************************/
void make_sam_info_2(SAM_INFO_2 *sam, uint32 acb_mask,
		uint32 start_idx, uint32 num_sam_entries,
		SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES])
{
	int i;
	int entries_added;

	if (sam == NULL) return;

	DEBUG(5,("make_sam_info_2\n"));

	if (num_sam_entries >= MAX_SAM_ENTRIES)
	{
		num_sam_entries = MAX_SAM_ENTRIES;
		DEBUG(5,("limiting number of entries to %d\n", 
			 num_sam_entries));
	}

	for (i = start_idx, entries_added = 0; i < num_sam_entries; i++)
	{
		if (IS_BITS_SET_ALL(pass[i].acb_info, acb_mask))
		{
			make_sam_entry2(&(sam->sam[entries_added]),
			                start_idx + entries_added + 1,
			                pass[i].uni_user_name.uni_str_len,
			                pass[i].uni_acct_desc.uni_str_len,
			                pass[i].user_rid,
			                pass[i].acb_info);

			copy_unistr2(&(sam->str[entries_added].uni_srv_name), &(pass[i].uni_user_name));
			copy_unistr2(&(sam->str[entries_added].uni_srv_desc), &(pass[i].uni_acct_desc));

			entries_added++;
		}

		sam->num_entries   = entries_added;
		sam->ptr_entries   = 1;
		sam->num_entries2  = entries_added;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void sam_io_sam_info_2(char *desc,  SAM_INFO_2 *sam, prs_struct *ps, int depth)
{
	int i;

	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_info_2");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries  ", ps, depth, &(sam->num_entries  ));
	prs_uint32("ptr_entries  ", ps, depth, &(sam->ptr_entries  ));

	prs_uint32("num_entries2 ", ps, depth, &(sam->num_entries2 ));

	SMB_ASSERT_ARRAY(sam->sam, sam->num_entries);

	for (i = 0; i < sam->num_entries; i++)
	{
		prs_grow(ps);
		sam_io_sam_entry2("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < sam->num_entries; i++)
	{
		prs_grow(ps);
		sam_io_sam_str2 ("", &(sam->str[i]),
							 sam->sam[i].hdr_srv_name.buffer,
							 sam->sam[i].hdr_srv_desc.buffer,
							 ps, depth);
	}
}


/*******************************************************************
makes a SAM_INFO_1 structure.
********************************************************************/
void make_sam_info_1(SAM_INFO_1 *sam, uint32 acb_mask,
		uint32 start_idx, uint32 num_sam_entries,
		SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES])
{
	int i;
	int entries_added;

	if (sam == NULL) return;

	DEBUG(5,("make_sam_info_1\n"));

	if (num_sam_entries >= MAX_SAM_ENTRIES)
	{
		num_sam_entries = MAX_SAM_ENTRIES;
		DEBUG(5,("limiting number of entries to %d\n", 
			 num_sam_entries));
	}

	for (i = start_idx, entries_added = 0; i < num_sam_entries; i++)
	{
		if (IS_BITS_SET_ALL(pass[i].acb_info, acb_mask))
		{
			make_sam_entry1(&(sam->sam[entries_added]),
						start_idx + entries_added + 1,
						pass[i].uni_user_name.uni_str_len,
						pass[i].uni_full_name.uni_str_len, 
						pass[i].uni_acct_desc.uni_str_len,
						pass[i].user_rid,
						pass[i].acb_info);

			copy_unistr2(&(sam->str[entries_added].uni_acct_name), &(pass[i].uni_user_name));
			copy_unistr2(&(sam->str[entries_added].uni_full_name), &(pass[i].uni_full_name));
			copy_unistr2(&(sam->str[entries_added].uni_acct_desc), &(pass[i].uni_acct_desc));

			entries_added++;
		}
	}

	sam->num_entries   = entries_added;
	sam->ptr_entries   = 1;
	sam->num_entries2  = entries_added;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
static void sam_io_sam_info_1(char *desc,  SAM_INFO_1 *sam, prs_struct *ps, int depth)
{
	int i;

	if (sam == NULL) return;

	prs_debug(ps, depth, desc, "sam_io_sam_info_1");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries  ", ps, depth, &(sam->num_entries  ));
	prs_uint32("ptr_entries  ", ps, depth, &(sam->ptr_entries  ));

	prs_uint32("num_entries2 ", ps, depth, &(sam->num_entries2 ));

	SMB_ASSERT_ARRAY(sam->sam, sam->num_entries);

	for (i = 0; i < sam->num_entries; i++)
	{
		prs_grow(ps);
		sam_io_sam_entry1("", &(sam->sam[i]), ps, depth);
	}

	for (i = 0; i < sam->num_entries; i++)
	{
		prs_grow(ps);
		sam_io_sam_str1 ("", &(sam->str[i]),
							 sam->sam[i].hdr_acct_name.buffer,
							 sam->sam[i].hdr_user_name.buffer,
							 sam->sam[i].hdr_user_desc.buffer,
							 ps, depth);
	}
}


/*******************************************************************
makes a SAMR_R_QUERY_DISPINFO structure.
********************************************************************/
void make_samr_r_query_dispinfo(SAMR_R_QUERY_DISPINFO *r_u,
		uint16 switch_level, SAM_INFO_CTR *ctr, uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_query_dispinfo\n"));

	if (status == 0x0)
	{
		r_u->unknown_0 = 0x0000001;
		r_u->unknown_1 = 0x0000001;
	}
	else
	{
		r_u->unknown_0 = 0x0;
		r_u->unknown_1 = 0x0;
	}

	r_u->switch_level = switch_level;
	r_u->ctr = ctr;
	r_u->status = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_dispinfo(char *desc,  SAMR_R_QUERY_DISPINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_query_dispinfo");
	depth++;

	prs_align(ps);

	prs_uint32("unknown_0    ", ps, depth, &(r_u->unknown_0    ));
	prs_uint32("unknown_1    ", ps, depth, &(r_u->unknown_1    ));
	prs_uint16("switch_level ", ps, depth, &(r_u->switch_level ));

	prs_align(ps);

	switch (r_u->switch_level)
	{
		case 0x1:
		{
			sam_io_sam_info_1("users", r_u->ctr->sam.info1, ps, depth);
			break;
		}
		case 0x2:
		{
			sam_io_sam_info_2("servers", r_u->ctr->sam.info2, ps, depth);
			break;
		}
		default:
		{
			DEBUG(5,("samr_io_r_query_dispinfo: unknown switch value\n"));
			break;
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_OPEN_GROUP structure.
********************************************************************/
void make_samr_q_open_group(SAMR_Q_OPEN_GROUP *q_c,
				POLICY_HND *hnd, uint32 unk, uint32 rid)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_open_group\n"));

	memcpy(&(q_c->domain_pol), hnd, sizeof(q_c->domain_pol));
	q_c->unknown = unk;
	q_c->rid_group = rid;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_open_group(char *desc,  SAMR_Q_OPEN_GROUP *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_open_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 

	prs_uint32("unknown  ", ps, depth, &(q_u->unknown  ));
	prs_uint32("rid_group", ps, depth, &(q_u->rid_group));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_open_group(char *desc,  SAMR_R_OPEN_GROUP *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_open_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a GROUP_INFO1 structure.
********************************************************************/
void make_samr_group_info1(GROUP_INFO1 *gr1,
				char *acct_name, char *acct_desc)
{
	int desc_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	int acct_len = acct_name != NULL ? strlen(acct_name) : 0;
	if (gr1 == NULL) return;

	DEBUG(5,("make_samr_group_info1\n"));

	make_uni_hdr(&(gr1->hdr_acct_name), acct_len , acct_len, acct_name ? 1 : 0);

	gr1->unknown_1 = 0x3;
	gr1->unknown_2 = 0x3;

	make_uni_hdr(&(gr1->hdr_acct_desc), desc_len , desc_len, acct_desc ? 1 : 0);

	make_unistr2(&(gr1->uni_acct_name), acct_name, acct_len);
	make_unistr2(&(gr1->uni_acct_desc), acct_desc, desc_len);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_group_info1(char *desc,  GROUP_INFO1 *gr1, prs_struct *ps, int depth)
{
	if (gr1 == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_group_info1");
	depth++;

	prs_align(ps);

	smb_io_unihdr ("hdr_acct_name", &(gr1->hdr_acct_name) , ps, depth); 

	prs_uint32("unknown_1", ps, depth, &(gr1->unknown_1));
	prs_uint32("unknown_2", ps, depth, &(gr1->unknown_2));

	smb_io_unihdr ("hdr_acct_desc", &(gr1->hdr_acct_desc) , ps, depth); 

	smb_io_unistr2("uni_acct_name", &(gr1->uni_acct_name), gr1->hdr_acct_name.buffer, ps, depth);
	prs_align(ps);

	smb_io_unistr2("uni_acct_desc", &(gr1->uni_acct_desc), gr1->hdr_acct_desc.buffer, ps, depth);
}

/*******************************************************************
makes a GROUP_INFO4 structure.
********************************************************************/
void make_samr_group_info4(GROUP_INFO4 *gr4, const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (gr4 == NULL) return;

	DEBUG(5,("make_samr_group_info4\n"));

	make_uni_hdr(&(gr4->hdr_acct_desc), acct_len , acct_len, acct_desc ? 1 : 0);
	make_unistr2(&(gr4->uni_acct_desc), acct_desc, acct_len);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_group_info4(char *desc,  GROUP_INFO4 *gr4, prs_struct *ps, int depth)
{
	if (gr4 == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_group_info4");
	depth++;

	prs_align(ps);

	smb_io_unihdr ("hdr_acct_desc", &(gr4->hdr_acct_desc) , ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(gr4->uni_acct_desc), gr4->hdr_acct_desc.buffer, ps, depth);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_group_info_ctr(char *desc,  GROUP_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return;

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
}


/*******************************************************************
makes a SAMR_Q_CREATE_DOM_GROUP structure.
********************************************************************/
void make_samr_q_create_dom_group(SAMR_Q_CREATE_DOM_GROUP *q_e,
				POLICY_HND *pol,
				const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_create_dom_group\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	make_uni_hdr(&(q_e->hdr_acct_desc), acct_len , acct_len, acct_desc ? 1 : 0);
	make_unistr2(&(q_e->uni_acct_desc), acct_desc, acct_len);

	q_e->unknown_1 = 0x0002;
	q_e->unknown_2 = 0x0001;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_create_dom_group(char *desc,  SAMR_Q_CREATE_DOM_GROUP *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_create_dom_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	smb_io_unihdr ("hdr_acct_desc", &(q_e->hdr_acct_desc), ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(q_e->uni_acct_desc), q_e->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	prs_uint16("unknown_1", ps, depth, &(q_e->unknown_1));
	prs_uint16("unknown_2", ps, depth, &(q_e->unknown_2));
}


/*******************************************************************
makes a SAMR_R_CREATE_DOM_GROUP structure.
********************************************************************/
void make_samr_r_create_dom_group(SAMR_R_CREATE_DOM_GROUP *r_u, POLICY_HND *pol,
		uint32 rid, uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_create_dom_group\n"));

	memcpy(&(r_u->pol), pol, sizeof(*pol));

	r_u->rid    = rid   ;
	r_u->status = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_create_dom_group(char *desc,  SAMR_R_CREATE_DOM_GROUP *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_create_dom_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("rid   ", ps, depth, &(r_u->rid   ));
	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_ADD_GROUPMEM structure.
********************************************************************/
void make_samr_q_add_groupmem(SAMR_Q_ADD_GROUPMEM *q_e,
				POLICY_HND *pol,
				uint32 rid)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_add_groupmem\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->rid = rid;
	q_e->unknown = 0x0005;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_add_groupmem(char *desc,  SAMR_Q_ADD_GROUPMEM *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_add_groupmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("rid    ", ps, depth, &(q_e->rid));
	prs_uint32("unknown", ps, depth, &(q_e->unknown));
}


/*******************************************************************
makes a SAMR_R_ADD_GROUPMEM structure.
********************************************************************/
void make_samr_r_add_groupmem(SAMR_R_ADD_GROUPMEM *r_u, POLICY_HND *pol,
		uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_add_groupmem\n"));

	r_u->status = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_add_groupmem(char *desc,  SAMR_R_ADD_GROUPMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_add_groupmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_SET_GROUPINFO structure.
********************************************************************/
void make_samr_q_set_groupinfo(SAMR_Q_SET_GROUPINFO *q_e,
				POLICY_HND *pol, GROUP_INFO_CTR *ctr)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_set_groupinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));
	q_e->ctr = ctr;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_set_groupinfo(char *desc,  SAMR_Q_SET_GROUPINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_set_groupinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	samr_group_info_ctr("ctr", q_e->ctr, ps, depth);
}


/*******************************************************************
makes a SAMR_R_SET_GROUPINFO structure.
********************************************************************/
void make_samr_r_set_groupinfo(SAMR_R_SET_GROUPINFO *r_u, 
		uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_set_groupinfo\n"));

	r_u->status = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_set_groupinfo(char *desc,  SAMR_R_SET_GROUPINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_set_groupinfo");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_QUERY_GROUPINFO structure.
********************************************************************/
void make_samr_q_query_groupinfo(SAMR_Q_QUERY_GROUPINFO *q_e,
				POLICY_HND *pol,
				uint16 switch_level)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_query_groupinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_groupinfo(char *desc,  SAMR_Q_QUERY_GROUPINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_groupinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));
}


/*******************************************************************
makes a SAMR_R_QUERY_GROUPINFO structure.
********************************************************************/
void make_samr_r_query_groupinfo(SAMR_R_QUERY_GROUPINFO *r_u, GROUP_INFO_CTR *ctr,
		uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_query_groupinfo\n"));

	r_u->ptr = (status == 0x0 && ctr != NULL) ? 1 : 0;
	r_u->ctr = ctr;
	r_u->status = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_groupinfo(char *desc,  SAMR_R_QUERY_GROUPINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_query_groupinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	
	if (r_u->ptr != 0)
	{
		samr_group_info_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_QUERY_GROUPMEM structure.
********************************************************************/
void make_samr_q_query_groupmem(SAMR_Q_QUERY_GROUPMEM *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_query_groupmem\n"));

	memcpy(&(q_c->group_pol), hnd, sizeof(q_c->group_pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_groupmem(char *desc,  SAMR_Q_QUERY_GROUPMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_groupmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("group_pol", &(q_u->group_pol), ps, depth); 
}

/*******************************************************************
makes a SAMR_R_QUERY_GROUPMEM structure.
********************************************************************/
void make_samr_r_query_groupmem(SAMR_R_QUERY_GROUPMEM *r_u,
		uint32 num_entries, uint32 *rid, uint32 *attr, uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_query_groupmem\n"));

	if (status == 0x0)
	{
		r_u->ptr         = (num_entries != 0) ? 1 : 0;
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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_groupmem(char *desc,  SAMR_R_QUERY_GROUPMEM *r_u, prs_struct *ps, int depth)
{
	int i;

	if (r_u == NULL) return;

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
			for (i = 0; i < r_u->num_rids; i++)
			{
				prs_grow(ps);
				prs_uint32("", ps, depth, &(r_u->rid[i]));
			}
		}

		if (r_u->ptr_attrs != 0)
		{
			prs_uint32("num_attrs", ps, depth, &(r_u->num_attrs));
			for (i = 0; i < r_u->num_attrs; i++)
			{
				prs_grow(ps);
				prs_uint32("", ps, depth, &(r_u->attr[i]));
			}
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_ENUM_DOM_GROUPS structure.
********************************************************************/
void make_samr_q_enum_dom_groups(SAMR_Q_ENUM_DOM_GROUPS *q_e, POLICY_HND *pol,
				uint16 switch_level, uint32 start_idx, uint32 size)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_enum_dom_groups\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;

	q_e->unknown_0 = 0;
	q_e->start_idx = start_idx;
	q_e->unknown_1 = 0x000007d0;
	q_e->max_size  = size;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_enum_dom_groups(char *desc,  SAMR_Q_ENUM_DOM_GROUPS *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_groups");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));
	prs_uint16("unknown_0   ", ps, depth, &(q_e->unknown_0   ));
	prs_uint32("start_idx   ", ps, depth, &(q_e->start_idx   ));
	prs_uint32("unknown_1   ", ps, depth, &(q_e->unknown_1   ));
	prs_uint32("max_size    ", ps, depth, &(q_e->max_size    ));

	prs_align(ps);
}


/*******************************************************************
makes a SAMR_R_ENUM_DOM_GROUPS structure.
********************************************************************/
void make_samr_r_enum_dom_groups(SAMR_R_ENUM_DOM_GROUPS *r_u,
		uint32 start_idx, uint32 num_sam_entries,
		DOMAIN_GRP *grp,
		uint32 status)
{
	int i;
	int entries_added;

	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_enum_dom_groups\n"));

	if (num_sam_entries >= MAX_SAM_ENTRIES)
	{
		num_sam_entries = MAX_SAM_ENTRIES;
		DEBUG(5,("limiting number of entries to %d\n", 
			 num_sam_entries));
	}

	if (status == 0x0)
	{
		for (i = start_idx, entries_added = 0; i < num_sam_entries; i++)
		{
			int acct_name_len = strlen(grp[i].name);
			int acct_desc_len = strlen(grp[i].comment);

			make_sam_entry3(&(r_u->sam[entries_added]),
			                start_idx + entries_added + 1,
			                acct_name_len,
			                acct_desc_len,
			                grp[i].rid);

			make_unistr2(&(r_u->str[entries_added].uni_grp_name), grp[i].name   , acct_name_len);
			make_unistr2(&(r_u->str[entries_added].uni_grp_desc), grp[i].comment, acct_desc_len);

			entries_added++;
		}

		if (entries_added > 0)
		{
			r_u->unknown_0 = 0x0000492;
			r_u->unknown_1 = 0x000049a;
		}
		else
		{
			r_u->unknown_0 = 0x0;
			r_u->unknown_1 = 0x0;
		}
		r_u->switch_level  = 3;
		r_u->num_entries   = entries_added;
		r_u->ptr_entries   = 1;
		r_u->num_entries2  = entries_added;
	}
	else
	{
		r_u->switch_level = 0;
	}

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_enum_dom_groups(char *desc,  SAMR_R_ENUM_DOM_GROUPS *r_u, prs_struct *ps, int depth)
{
	int i;

	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_groups");
	depth++;

	prs_align(ps);

	prs_uint32("unknown_0    ", ps, depth, &(r_u->unknown_0    ));
	prs_uint32("unknown_1    ", ps, depth, &(r_u->unknown_1    ));
	prs_uint32("switch_level ", ps, depth, &(r_u->switch_level ));

	if (r_u->switch_level != 0)
	{
		prs_uint32("num_entries  ", ps, depth, &(r_u->num_entries  ));
		prs_uint32("ptr_entries  ", ps, depth, &(r_u->ptr_entries  ));

		prs_uint32("num_entries2 ", ps, depth, &(r_u->num_entries2 ));

		SMB_ASSERT_ARRAY(r_u->sam, r_u->num_entries);

		for (i = 0; i < r_u->num_entries; i++)
		{
			prs_grow(ps);
			sam_io_sam_entry3("", &(r_u->sam[i]), ps, depth);
		}

		for (i = 0; i < r_u->num_entries; i++)
		{
			prs_grow(ps);
			sam_io_sam_str3 ("", &(r_u->str[i]),
			                     r_u->sam[i].hdr_grp_name.buffer,
			                     r_u->sam[i].hdr_grp_desc.buffer,
			                     ps, depth);
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERGROUPS structure.
********************************************************************/
void make_samr_q_query_usergroups(SAMR_Q_QUERY_USERGROUPS *q_u,
				POLICY_HND *hnd)
{
	if (q_u == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_query_usergroups\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_usergroups(char *desc,  SAMR_Q_QUERY_USERGROUPS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_usergroups");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);
}

/*******************************************************************
makes a SAMR_R_QUERY_USERGROUPS structure.
********************************************************************/
void make_samr_r_query_usergroups(SAMR_R_QUERY_USERGROUPS *r_u,
		uint32 num_gids, DOM_GID *gid, uint32 status)
{
	if (r_u == NULL) return;

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
	}

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_usergroups(char *desc,  SAMR_R_QUERY_USERGROUPS *r_u, prs_struct *ps, int depth)
{
	int i;
	if (r_u == NULL) return;

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

			for (i = 0; i < r_u->num_entries2; i++)
			{
				prs_grow(ps);
				smb_io_gid("", &(r_u->gid[i]), ps, depth);
			}
		}
	}
	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_ENUM_DOM_ALIASES structure.
********************************************************************/
void make_samr_q_enum_dom_aliases(SAMR_Q_ENUM_DOM_ALIASES *q_e, POLICY_HND *pol, uint32 size)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_enum_dom_aliases\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->unknown_0 = 0;
	q_e->max_size = size;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_enum_dom_aliases(char *desc,  SAMR_Q_ENUM_DOM_ALIASES *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_aliases");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("unknown_0", ps, depth, &(q_e->unknown_0));
	prs_uint32("max_size ", ps, depth, &(q_e->max_size ));

	prs_align(ps);
}


/*******************************************************************
makes a SAMR_R_ENUM_DOM_ALIASES structure.
********************************************************************/
void make_samr_r_enum_dom_aliases(SAMR_R_ENUM_DOM_ALIASES *r_u,
		uint32 num_sam_entries, LOCAL_GRP *alss,
		uint32 status)
{
	int i;

	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_enum_dom_aliases\n"));

	if (num_sam_entries >= MAX_SAM_ENTRIES)
	{
		num_sam_entries = MAX_SAM_ENTRIES;
		DEBUG(5,("limiting number of entries to %d\n", 
			 num_sam_entries));
	}

	r_u->num_entries  = num_sam_entries;

	if (num_sam_entries > 0)
	{
		r_u->ptr_entries  = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
		r_u->num_entries3 = num_sam_entries;

		SMB_ASSERT_ARRAY(r_u->sam, num_sam_entries);

		for (i = 0; i < num_sam_entries; i++)
		{
			int acct_name_len = strlen(alss[i].name);

			make_sam_entry(&(r_u->sam[i]),
			                acct_name_len,
			                alss[i].rid);

			make_unistr2(&(r_u->uni_grp_name[i]), alss[i].name   , acct_name_len);
		}

		r_u->num_entries4 = num_sam_entries;
	}
	else
	{
		r_u->ptr_entries = 0;
	}

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_enum_dom_aliases(char *desc,  SAMR_R_ENUM_DOM_ALIASES *r_u, prs_struct *ps, int depth)
{
	int i;

	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_aliases");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries", ps, depth, &(r_u->num_entries));
	prs_uint32("ptr_entries", ps, depth, &(r_u->ptr_entries));
	
	if (r_u->num_entries != 0 && r_u->ptr_entries != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));
		prs_uint32("ptr_entries2", ps, depth, &(r_u->ptr_entries2));
		prs_uint32("num_entries3", ps, depth, &(r_u->num_entries3));

		SMB_ASSERT_ARRAY(r_u->sam, r_u->num_entries);

		for (i = 0; i < r_u->num_entries; i++)
		{
			sam_io_sam_entry("", &(r_u->sam[i]), ps, depth);
		}

		for (i = 0; i < r_u->num_entries; i++)
		{
			smb_io_unistr2("", &(r_u->uni_grp_name[i]), r_u->sam[i].hdr_name.buffer, ps, depth);
		}

		prs_align(ps);

		prs_uint32("num_entries4", ps, depth, &(r_u->num_entries4));
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a ALIAS_INFO3 structure.
********************************************************************/
void make_samr_alias_info3(ALIAS_INFO3 *al3, const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (al3 == NULL) return;

	DEBUG(5,("make_samr_alias_info3\n"));

	make_uni_hdr(&(al3->hdr_acct_desc), acct_len , acct_len, acct_desc ? 1 : 0);
	make_unistr2(&(al3->uni_acct_desc), acct_desc, acct_len);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_alias_info3(char *desc,  ALIAS_INFO3 *al3, prs_struct *ps, int depth)
{
	if (al3 == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_alias_info3");
	depth++;

	prs_align(ps);

	smb_io_unihdr ("hdr_acct_desc", &(al3->hdr_acct_desc) , ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(al3->uni_acct_desc), al3->hdr_acct_desc.buffer, ps, depth);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_alias_info_ctr(char *desc,  ALIAS_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return;

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
}


/*******************************************************************
makes a SAMR_Q_QUERY_ALIASINFO structure.
********************************************************************/
void make_samr_q_query_aliasinfo(SAMR_Q_QUERY_ALIASINFO *q_e,
				POLICY_HND *pol,
				uint16 switch_level)
{
	if (q_e == NULL || pol == NULL) return;

	DEBUG(5,("make_samr_q_query_aliasinfo\n"));

	memcpy(&(q_e->pol), pol, sizeof(*pol));

	q_e->switch_level = switch_level;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_aliasinfo(char *desc,  SAMR_Q_QUERY_ALIASINFO *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_aliasinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_e->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_level", ps, depth, &(q_e->switch_level));
}


/*******************************************************************
makes a SAMR_R_QUERY_ALIASINFO structure.
********************************************************************/
void make_samr_r_query_aliasinfo(SAMR_R_QUERY_ALIASINFO *r_u, ALIAS_INFO_CTR *ctr,
		uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_query_aliasinfo\n"));

	r_u->ptr = (status == 0x0 && ctr != NULL) ? 1 : 0;
	r_u->ctr = ctr;
	r_u->status = status;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_aliasinfo(char *desc,  SAMR_R_QUERY_ALIASINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_query_aliasinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	
	if (r_u->ptr != 0)
	{
		samr_alias_info_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_SET_ALIASINFO structure.
********************************************************************/
void make_samr_q_set_aliasinfo(SAMR_Q_SET_ALIASINFO *q_u, POLICY_HND *hnd,
				ALIAS_INFO_CTR *ctr)
{
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_set_aliasinfo\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
	q_u->ctr = ctr;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_set_aliasinfo(char *desc,  SAMR_Q_SET_ALIASINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_set_aliasinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
	samr_alias_info_ctr("ctr", q_u->ctr, ps, depth);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_set_aliasinfo(char *desc,  SAMR_R_SET_ALIASINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_set_aliasinfo");
	depth++;

	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_u->status));
}



/*******************************************************************
makes a SAMR_Q_QUERY_USERALIASES structure.
********************************************************************/
void make_samr_q_query_useraliases(SAMR_Q_QUERY_USERALIASES *q_u,
				POLICY_HND *hnd,
				DOM_SID *sid)
{
	if (q_u == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_query_useraliases\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));

	q_u->num_sids1 = 1;
	q_u->ptr = 0;
	q_u->num_sids2 = 1;

	{
		q_u->ptr_sid[0] = 1;
		make_dom_sid2(&q_u->sid[0], sid);
	}
}

/*******************************************************************
reads or writes a SAMR_Q_QUERY_USERALIASES structure.
********************************************************************/
void samr_io_q_query_useraliases(char *desc,  SAMR_Q_QUERY_USERALIASES *q_u, prs_struct *ps, int depth)
{
	fstring tmp;
	int i;

	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_useraliases");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("num_sids1", ps, depth, &(q_u->num_sids1));
	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint32("num_sids2", ps, depth, &(q_u->num_sids2));

	SMB_ASSERT_ARRAY(q_u->ptr_sid, q_u->num_sids2);

	for (i = 0; i < q_u->num_sids2; i++)
	{
		slprintf(tmp, sizeof(tmp) - 1, "ptr[%02d]", i);
		prs_uint32(tmp, ps, depth, &(q_u->ptr_sid[i]));
	}

	for (i = 0; i < q_u->num_sids2; i++)
	{
		if (q_u->ptr_sid[i] != 0)
		{
			prs_grow(ps);
			slprintf(tmp, sizeof(tmp)-1, "sid[%02d]", i);
			smb_io_dom_sid2(tmp, &(q_u->sid[i]), ps, depth); 
		}
	}

	prs_align(ps);
}


/*******************************************************************
makes a SAMR_R_QUERY_USERALIASES structure.
********************************************************************/
void make_samr_r_query_useraliases(SAMR_R_QUERY_USERALIASES *r_u,
		uint32 num_rids, uint32 *rid, uint32 status)
{
	if (r_u == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_useraliases(char *desc,  SAMR_R_QUERY_USERALIASES *r_u, prs_struct *ps, int depth)
{
	fstring tmp;
	int i;
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_query_useraliases");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries", ps, depth, &(r_u->num_entries));
	prs_uint32("ptr        ", ps, depth, &(r_u->ptr        ));
	prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));

	if (r_u->num_entries != 0)
	{
		for (i = 0; i < r_u->num_entries2; i++)
		{
			slprintf(tmp, sizeof(tmp)-1, "rid[%02d]", i);
			prs_uint32(tmp, ps, depth, &(r_u->rid[i]));
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_OPEN_ALIAS structure.
********************************************************************/
void make_samr_q_open_alias(SAMR_Q_OPEN_ALIAS *q_u, POLICY_HND *pol,
				uint32 unknown_0, uint32 rid)
{
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_open_alias\n"));

	memcpy(&(q_u->dom_pol), pol, sizeof(q_u->dom_pol));

	/* example values: 0x0000 0008 */
	q_u->unknown_0 = unknown_0; 

	q_u->rid_alias = rid; 
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_open_alias(char *desc,  SAMR_Q_OPEN_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_open_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("dom_pol", &(q_u->dom_pol), ps, depth); 

	prs_uint32("unknown_0", ps, depth, &(q_u->unknown_0));
	prs_uint32("rid_alias", ps, depth, &(q_u->rid_alias));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_open_alias(char *desc,  SAMR_R_OPEN_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_open_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_UNKNOWN_12 structure.
********************************************************************/
void make_samr_q_unknown_12(SAMR_Q_UNKNOWN_12 *q_u,
		POLICY_HND *pol, uint32 rid,
		uint32 num_gids, uint32 *gid)
{
	int i;
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_r_unknwon_12\n"));

	memcpy(&(q_u->pol), pol, sizeof(*pol));

	q_u->num_gids1 = num_gids;
	q_u->rid       = rid;
	q_u->ptr       = 0;
	q_u->num_gids2 = num_gids;

	for (i = 0; i < num_gids; i++)
	{
		q_u->gid[i] = gid[i];
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_unknown_12(char *desc,  SAMR_Q_UNKNOWN_12 *q_u, prs_struct *ps, int depth)
{
	int i;
	fstring tmp;

	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_unknown_12");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("num_gids1", ps, depth, &(q_u->num_gids1));
	prs_uint32("rid      ", ps, depth, &(q_u->rid      ));
	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint32("num_gids2", ps, depth, &(q_u->num_gids2));

	SMB_ASSERT_ARRAY(q_u->gid, q_u->num_gids2);

	for (i = 0; i < q_u->num_gids2; i++)
	{
		prs_grow(ps);
		slprintf(tmp, sizeof(tmp) - 1, "gid[%02d]  ", i);
		prs_uint32(tmp, ps, depth, &(q_u->gid[i]));
	}

	prs_align(ps);
}


/*******************************************************************
makes a SAMR_R_UNKNOWN_12 structure.
********************************************************************/
void make_samr_r_unknown_12(SAMR_R_UNKNOWN_12 *r_u,
		uint32 num_names, fstring *name, uint8 *type,
		uint32 status)
{
	int i;
	if (r_u == NULL || name == NULL || type == NULL) return;

	DEBUG(5,("make_samr_r_unknown_12\n"));

	if (status == 0x0)
	{
		r_u->num_names1 = num_names;
		r_u->ptr_names  = 1;
		r_u->num_names2 = num_names;

		r_u->num_types1 = num_names;
		r_u->ptr_types  = 1;
		r_u->num_types2 = num_names;

		SMB_ASSERT_ARRAY(r_u->hdr_name, num_names);

		for (i = 0; i < num_names; i++)
		{
			int len = name[i] != NULL ? strlen(name[i]) : 0;
			make_uni_hdr(&(r_u->hdr_name[i]), len    , len, name[i] ? 1 : 0);
			make_unistr2(&(r_u->uni_name[i]), name[i], len);
			r_u->type[i] = type[i];
		}
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

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_unknown_12(char *desc,  SAMR_R_UNKNOWN_12 *r_u, prs_struct *ps, int depth)
{
	int i;
	fstring tmp;
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_12");
	depth++;

	prs_align(ps);

	prs_uint32("num_names1", ps, depth, &(r_u->num_names1));
	prs_uint32("ptr_names ", ps, depth, &(r_u->ptr_names ));
	prs_uint32("num_names2", ps, depth, &(r_u->num_names2));

	if (r_u->ptr_names != 0 && r_u->num_names1 != 0)
	{
		SMB_ASSERT_ARRAY(r_u->hdr_name, r_u->num_names2);

		for (i = 0; i < r_u->num_names2; i++)
		{
			prs_grow(ps);
			slprintf(tmp, sizeof(tmp) - 1, "hdr[%02d]  ", i);
			smb_io_unihdr ("", &(r_u->hdr_name[i]), ps, depth); 
		}
		for (i = 0; i < r_u->num_names2; i++)
		{
			prs_grow(ps);
			slprintf(tmp, sizeof(tmp) - 1, "str[%02d]  ", i);
			smb_io_unistr2("", &(r_u->uni_name[i]), r_u->hdr_name[i].buffer, ps, depth); 
		}
	}

	prs_align(ps);

	prs_uint32("num_types1", ps, depth, &(r_u->num_types1));
	prs_uint32("ptr_types ", ps, depth, &(r_u->ptr_types ));
	prs_uint32("num_types2", ps, depth, &(r_u->num_types2));

	if (r_u->ptr_types != 0 && r_u->num_types1 != 0)
	{
		for (i = 0; i < r_u->num_types2; i++)
		{
			prs_grow(ps);
			slprintf(tmp, sizeof(tmp) - 1, "type[%02d]  ", i);
			prs_uint32(tmp, ps, depth, &(r_u->type[i]));
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_OPEN_ALIAS structure.
********************************************************************/
void make_samr_q_delete_alias(SAMR_Q_DELETE_DOM_ALIAS *q_u, POLICY_HND *hnd)
{
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_delete_alias\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_delete_alias(char *desc,  SAMR_Q_DELETE_DOM_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_delete_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_delete_alias(char *desc,  SAMR_R_DELETE_DOM_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_delete_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_CREATE_DOM_ALIAS structure.
********************************************************************/
void make_samr_q_create_dom_alias(SAMR_Q_CREATE_DOM_ALIAS *q_u, POLICY_HND *hnd,
				const char *acct_desc)
{
	int acct_len = acct_desc != NULL ? strlen(acct_desc) : 0;
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_create_dom_alias\n"));

	memcpy(&(q_u->dom_pol), hnd, sizeof(q_u->dom_pol));

	make_uni_hdr(&(q_u->hdr_acct_desc), acct_len , acct_len, acct_desc ? 1 : 0);
	make_unistr2(&(q_u->uni_acct_desc), acct_desc, acct_len);

	q_u->unknown_1 = 0x001f;
	q_u->unknown_2 = 0x000f;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_create_dom_alias(char *desc,  SAMR_Q_CREATE_DOM_ALIAS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_create_dom_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("dom_pol", &(q_u->dom_pol), ps, depth); 

	smb_io_unihdr ("hdr_acct_desc", &(q_u->hdr_acct_desc) , ps, depth); 
	smb_io_unistr2("uni_acct_desc", &(q_u->uni_acct_desc), q_u->hdr_acct_desc.buffer, ps, depth);

	prs_uint16("unknown_1", ps, depth, &(q_u->unknown_1));
	prs_uint16("unknown_2", ps, depth, &(q_u->unknown_2));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_create_dom_alias(char *desc,  SAMR_R_CREATE_DOM_ALIAS *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_create_dom_alias");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(r_u->alias_pol), ps, depth); 
	prs_uint32("rid", ps, depth, &(r_u->rid));

	prs_uint32("status", ps, depth, &(r_u->status));
	}



/*******************************************************************
makes a SAMR_Q_UNK_ALIASMEM structure.
********************************************************************/
void make_samr_q_unk_aliasmem(SAMR_Q_UNK_ALIASMEM *q_u, POLICY_HND *hnd,
				DOM_SID *sid)
{
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_unk_aliasmem\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
	sid_copy(&q_u->sid, sid);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_unk_aliasmem(char *desc,  SAMR_Q_UNK_ALIASMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_unk_aliasmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
	smb_io_dom_sid("sid      ", &(q_u->sid      ), ps, depth); 
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_unk_aliasmem(char *desc,  SAMR_R_UNK_ALIASMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unk_aliasmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_ADD_ALIASMEM structure.
********************************************************************/
void make_samr_q_add_aliasmem(SAMR_Q_ADD_ALIASMEM *q_u, POLICY_HND *hnd,
				DOM_SID *sid)
{
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_add_aliasmem\n"));

	memcpy(&(q_u->alias_pol), hnd, sizeof(q_u->alias_pol));
	sid_copy(&q_u->sid, sid);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_add_aliasmem(char *desc,  SAMR_Q_ADD_ALIASMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_add_aliasmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
	smb_io_dom_sid("sid      ", &(q_u->sid      ), ps, depth); 
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_add_aliasmem(char *desc,  SAMR_R_ADD_ALIASMEM *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_add_aliasmem");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_QUERY_ALIASMEM structure.
********************************************************************/
void make_samr_q_query_aliasmem(SAMR_Q_QUERY_ALIASMEM *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_query_aliasmem\n"));

	memcpy(&(q_c->alias_pol), hnd, sizeof(q_c->alias_pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_aliasmem(char *desc,  SAMR_Q_QUERY_ALIASMEM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_aliasmem");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("alias_pol", &(q_u->alias_pol), ps, depth); 
}

/*******************************************************************
makes a SAMR_R_QUERY_ALIASMEM structure.
********************************************************************/
void make_samr_r_query_aliasmem(SAMR_R_QUERY_ALIASMEM *r_u,
		uint32 num_sids, DOM_SID2 *sid, uint32 status)
{
	if (r_u == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_aliasmem(char *desc,  SAMR_R_QUERY_ALIASMEM *r_u, prs_struct *ps, int depth)
{
	int i;
	uint32 ptr_sid[MAX_LOOKUP_SIDS];

	if (r_u == NULL) return;

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
				prs_grow(ps);
				ptr_sid[i] = 1;
				prs_uint32("", ps, depth, &(ptr_sid[i]));
			}
			for (i = 0; i < r_u->num_sids1; i++)
			{
				prs_grow(ps);
				if (ptr_sid[i] != 0)
				{
					smb_io_dom_sid2("", &(r_u->sid[i]), ps, depth);
				}
			}
		}
	}
	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_lookup_names(char *desc,  SAMR_Q_LOOKUP_NAMES *q_u, prs_struct *ps, int depth)
{
	int i;

	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_lookup_names");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("num_rids1", ps, depth, &(q_u->num_rids1));
	prs_uint32("rid      ", ps, depth, &(q_u->rid      ));
	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint32("num_rids2", ps, depth, &(q_u->num_rids2));

	SMB_ASSERT_ARRAY(q_u->hdr_user_name, q_u->num_rids2);

	for (i = 0; i < q_u->num_rids2; i++)
	{
		prs_grow(ps);
		smb_io_unihdr ("", &(q_u->hdr_user_name[i]), ps, depth); 
	}
	for (i = 0; i < q_u->num_rids2; i++)
	{
		prs_grow(ps);
		smb_io_unistr2("", &(q_u->uni_user_name[i]), q_u->hdr_user_name[i].buffer, ps, depth); 
	}

	prs_align(ps);
}


/*******************************************************************
makes a SAMR_R_LOOKUP_NAMES structure.
********************************************************************/
void make_samr_r_lookup_names(SAMR_R_LOOKUP_NAMES *r_u,
		uint32 num_rids, uint32 *rid, uint8 *type, uint32 status)
{
	int i;
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_lookup_names\n"));

	if (status == 0x0)
	{
		r_u->num_entries  = num_rids;
		r_u->undoc_buffer = 1;
		r_u->num_entries2 = num_rids;

		SMB_ASSERT_ARRAY(r_u->dom_rid, num_rids);

		for (i = 0; i < num_rids; i++)
		{
			make_dom_rid3(&(r_u->dom_rid[i]), rid[i], type[i]);
		}
	}
	else
	{
		r_u->num_entries  = 0;
		r_u->undoc_buffer = 0;
		r_u->num_entries2 = 0;
	}

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_lookup_names(char *desc,  SAMR_R_LOOKUP_NAMES *r_u, prs_struct *ps, int depth)
{
	int i;
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_lookup_names");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries ", ps, depth, &(r_u->num_entries ));
	prs_uint32("undoc_buffer", ps, depth, &(r_u->undoc_buffer));
	prs_uint32("num_entries2", ps, depth, &(r_u->num_entries2));

	if (r_u->num_entries != 0)
	{
		SMB_ASSERT_ARRAY(r_u->dom_rid, r_u->num_entries2);

		for (i = 0; i < r_u->num_entries2; i++)
		{
			prs_grow(ps);
			smb_io_dom_rid3("", &(r_u->dom_rid[i]), ps, depth);
	}

	}

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_samr_q_open_user(SAMR_Q_OPEN_USER *q_u,
				POLICY_HND *pol,
				uint32 unk_0, uint32 rid)
{
	if (q_u == NULL) return;

	DEBUG(5,("samr_make_samr_q_open_user\n"));

	memcpy(&q_u->domain_pol, pol, sizeof(q_u->domain_pol));
	
	q_u->unknown_0 = unk_0;
	q_u->user_rid  = rid;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_open_user(char *desc,  SAMR_Q_OPEN_USER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_open_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("unknown_0", ps, depth, &(q_u->unknown_0));
	prs_uint32("user_rid ", ps, depth, &(q_u->user_rid ));

	prs_align(ps);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_open_user(char *desc,  SAMR_R_OPEN_USER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_open_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &(r_u->user_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERINFO structure.
********************************************************************/
void make_samr_q_query_userinfo(SAMR_Q_QUERY_USERINFO *q_u,
				POLICY_HND *hnd, uint16 switch_value)
{
	if (q_u == NULL || hnd == NULL) return;

	DEBUG(5,("make_samr_q_query_userinfo\n"));

	memcpy(&(q_u->pol), hnd, sizeof(q_u->pol));
	q_u->switch_value = switch_value;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_query_userinfo(char *desc,  SAMR_Q_QUERY_USERINFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_query_userinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value", ps, depth, &(q_u->switch_value)); /* 0x0015 or 0x0011 */

	prs_align(ps);
}

/*******************************************************************
reads or writes a LOGON_HRS structure.
********************************************************************/
static void sam_io_logon_hrs(char *desc,  LOGON_HRS *hrs, prs_struct *ps, int depth)
{
	if (hrs == NULL) return;

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
}

/*******************************************************************
makes a SAM_USER_INFO_10 structure.
********************************************************************/
void make_sam_user_info10(SAM_USER_INFO_10 *usr,
				uint32 acb_info)
{
	if (usr == NULL) return;

	DEBUG(5,("make_sam_user_info10\n"));

	usr->acb_info = acb_info;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void sam_io_user_info10(char *desc,  SAM_USER_INFO_10 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_user_info10");
	depth++;

	prs_align(ps);

	prs_uint32("acb_info", ps, depth, &(usr->acb_info));
}

/*******************************************************************
makes a SAM_USER_INFO_11 structure.
********************************************************************/
void make_sam_user_info11(SAM_USER_INFO_11 *usr,
				NTTIME *expiry,
				char *mach_acct,
				uint32 rid_user,
				uint32 rid_group,
				uint16 acct_ctrl)
				
{
	int len_mach_acct;
	if (usr == NULL || expiry == NULL || mach_acct == NULL) return;

	DEBUG(5,("make_sam_user_info11\n"));

	len_mach_acct = strlen(mach_acct);

	memcpy(&(usr->expiry),expiry, sizeof(usr->expiry)); /* expiry time or something? */
	bzero(usr->padding_1, sizeof(usr->padding_1)); /* 0 - padding 24 bytes */

	make_uni_hdr(&(usr->hdr_mach_acct), len_mach_acct, len_mach_acct, 4);  /* unicode header for machine account */
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

	bzero(usr->padding_9, sizeof(usr->padding_9)); /* 0 - padding 48 bytes */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void sam_io_user_info11(char *desc,  SAM_USER_INFO_11 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_24");
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
}
/*************************************************************************
 make_sam_user_info21

 unknown_3 = 0x00ff ffff
 unknown_5 = 0x0002 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
void make_sam_user_info21(SAM_USER_INFO_21 *usr,

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
	char *logon_script,
	char *profile_path,
	char *description,
	char *workstations,
	char *unknown_str,
	char *munged_dial,

	uint32 user_rid,
	uint32 group_rid,
	uint16 acb_info, 

	uint32 unknown_3,
	uint16 logon_divs,
	LOGON_HRS *hrs,
	uint32 unknown_5,
	uint32 unknown_6)
{
	int len_user_name    = user_name    != NULL ? strlen(user_name   ) : 0;
	int len_full_name    = full_name    != NULL ? strlen(full_name   ) : 0;
	int len_home_dir     = home_dir     != NULL ? strlen(home_dir    ) : 0;
	int len_dir_drive    = dir_drive    != NULL ? strlen(dir_drive   ) : 0;
	int len_logon_script = logon_script != NULL ? strlen(logon_script) : 0;
	int len_profile_path = profile_path != NULL ? strlen(profile_path) : 0;
	int len_description  = description  != NULL ? strlen(description ) : 0;
	int len_workstations = workstations != NULL ? strlen(workstations) : 0;
	int len_unknown_str  = unknown_str  != NULL ? strlen(unknown_str ) : 0;
	int len_munged_dial  = munged_dial  != NULL ? strlen(munged_dial ) : 0;

	usr->logon_time            = *logon_time;
	usr->logoff_time           = *logoff_time;
	usr->kickoff_time          = *kickoff_time;
	usr->pass_last_set_time    = *pass_last_set_time;
	usr->pass_can_change_time  = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   , len_user_name   , 1);
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   , len_full_name   , 1);
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    , len_home_dir    , 1);
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   , len_dir_drive   , 1);
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script, len_logon_script, 1);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path, len_profile_path, 1);
	make_uni_hdr(&(usr->hdr_acct_desc   ), len_description , len_description , 1);
	make_uni_hdr(&(usr->hdr_workstations), len_workstations, len_workstations, 1);
	make_uni_hdr(&(usr->hdr_unknown_str ), len_unknown_str , len_unknown_str , 1);
	make_uni_hdr(&(usr->hdr_munged_dial ), len_munged_dial , len_munged_dial , 1);

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
	make_unistr2(&(usr->uni_logon_script), logon_script, len_logon_script);
	make_unistr2(&(usr->uni_profile_path), profile_path, len_profile_path);
	make_unistr2(&(usr->uni_acct_desc ), description , len_description );
	make_unistr2(&(usr->uni_workstations), workstations, len_workstations);
	make_unistr2(&(usr->uni_unknown_str ), unknown_str , len_unknown_str );
	make_unistr2(&(usr->uni_munged_dial ), munged_dial , len_munged_dial );

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
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
static void sam_io_user_info21(char *desc,  SAM_USER_INFO_21 *usr, prs_struct *ps, int depth)
{
	if (usr == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_user_info");
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
	smb_io_unihdr("hdr_acct_desc   ", &(usr->hdr_acct_desc  ) , ps, depth); /* account description */
	smb_io_unihdr("hdr_workstations", &(usr->hdr_workstations), ps, depth); /* workstations user can log on from */
	smb_io_unihdr("hdr_unknown_str ", &(usr->hdr_unknown_str ), ps, depth); /* unknown string */
	smb_io_unihdr("hdr_munged_dial ", &(usr->hdr_munged_dial ), ps, depth); /* workstations user can log on from */

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
	smb_io_unistr2("uni_full_name   ", &(usr->uni_full_name)   , usr->hdr_full_name   .buffer, ps, depth); /* user's full name unicode string */
	smb_io_unistr2("uni_home_dir    ", &(usr->uni_home_dir)    , usr->hdr_home_dir    .buffer, ps, depth); /* home directory unicode string */
	smb_io_unistr2("uni_dir_drive   ", &(usr->uni_dir_drive)   , usr->hdr_dir_drive   .buffer, ps, depth); /* home directory drive unicode string */
	smb_io_unistr2("uni_logon_script", &(usr->uni_logon_script), usr->hdr_logon_script.buffer, ps, depth); /* logon script unicode string */
	smb_io_unistr2("uni_profile_path", &(usr->uni_profile_path), usr->hdr_profile_path.buffer, ps, depth); /* profile path unicode string */
	smb_io_unistr2("uni_acct_desc   ", &(usr->uni_acct_desc   ), usr->hdr_acct_desc   .buffer, ps, depth); /* user description unicode string */
	smb_io_unistr2("uni_workstations", &(usr->uni_workstations), usr->hdr_workstations.buffer, ps, depth); /* worksations user can log on from */
	smb_io_unistr2("uni_unknown_str ", &(usr->uni_unknown_str ), usr->hdr_unknown_str .buffer, ps, depth); /* unknown string */
	smb_io_unistr2("uni_munged_dial ", &(usr->uni_munged_dial ), usr->hdr_munged_dial .buffer, ps, depth); /* worksations user can log on from */

	prs_uint32("unknown_6     ", ps, depth, &(usr->unknown_6  ));
	prs_uint32("padding4      ", ps, depth, &(usr->padding4   ));

	if (usr->ptr_logon_hrs)
	{
		sam_io_logon_hrs("logon_hrs", &(usr->logon_hrs)   , ps, depth);
		prs_align(ps);
	}
}


/*******************************************************************
makes a SAMR_R_QUERY_USERINFO structure.
********************************************************************/
void make_samr_r_query_userinfo(SAMR_R_QUERY_USERINFO *r_u,
				uint16 switch_value, void *info, uint32 status)
				
{
	if (r_u == NULL || info == NULL) return;

	DEBUG(5,("make_samr_r_query_userinfo\n"));

	r_u->ptr = 0;
	r_u->switch_value = 0;

	if (status == 0)
	{
		r_u->switch_value = switch_value;

		switch (switch_value)
		{
			case 0x10:
			{
				r_u->ptr = 1;
				r_u->info.id10 = (SAM_USER_INFO_10*)info;

				break;
			}

			case 0x11:
			{
				r_u->ptr = 1;
				r_u->info.id11 = (SAM_USER_INFO_11*)info;

				break;
			}

			case 21:
			{
				r_u->ptr = 1;
				r_u->info.id21 = (SAM_USER_INFO_21*)info;

				break;
			}

			default:
			{
				DEBUG(4,("make_samr_r_query_userinfo: unsupported switch level\n"));
				break;
			}
		}
	}

	r_u->status = status;         /* return status */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_query_userinfo(char *desc,  SAMR_R_QUERY_USERINFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_query_userinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr         ", ps, depth, &(r_u->ptr         ));
	prs_uint16("switch_value", ps, depth, &(r_u->switch_value));
	prs_align(ps);

	if (r_u->ptr != 0 && r_u->switch_value != 0)
	{
		switch (r_u->switch_value)
		{
			case 0x10:
			{
				if (r_u->info.id10 != NULL)
				{
					sam_io_user_info10("", r_u->info.id10, ps, depth);
				}
				else
				{
					DEBUG(2,("samr_io_r_query_userinfo: info pointer not initialised\n"));
					return;
				}
				break;
			}
/*
			case 0x11:
			{
				if (r_u->info.id11 != NULL)
				{
					sam_io_user_info11("", r_u->info.id11, ps, depth);
				}
				else
				{
					DEBUG(2,("samr_io_r_query_userinfo: info pointer not initialised\n"));
					return;
				}
				break;
			}
*/
			case 21:
			{
				if (r_u->info.id21 != NULL)
				{
					sam_io_user_info21("", r_u->info.id21, ps, depth);
				}
				else
				{
					DEBUG(2,("samr_io_r_query_userinfo: info pointer not initialised\n"));
					return;
				}
				break;
			}
			default:
			{
				DEBUG(2,("samr_io_r_query_userinfo: unknown switch level\n"));
				break;
			}
				
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_unknown_32(char *desc,  SAMR_Q_UNKNOWN_32 *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_unknown_32");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth); 
	prs_align(ps);

	smb_io_unihdr ("", &(q_u->hdr_mach_acct), ps, depth); 
	smb_io_unistr2("", &(q_u->uni_mach_acct), q_u->hdr_mach_acct.buffer, ps, depth); 

	prs_align(ps);

	prs_uint32("acct_ctrl", ps, depth, &(q_u->acct_ctrl));
	prs_uint16("unknown_1", ps, depth, &(q_u->unknown_1));
	prs_uint16("unknown_2", ps, depth, &(q_u->unknown_2));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_unknown_32(char *desc,  SAMR_R_UNKNOWN_32 *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_32");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}


/*******************************************************************
makes a SAMR_Q_CONNECT structure.
********************************************************************/
void make_samr_q_connect(SAMR_Q_CONNECT *q_u,
				char *srv_name, uint32 unknown_0)
{
	int len_srv_name = strlen(srv_name);

	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_connect\n"));

	/* make PDC server name \\server */
	q_u->ptr_srv_name = len_srv_name > 0 ? 1 : 0; 
	make_unistr2(&(q_u->uni_srv_name), srv_name, len_srv_name+1);  

	/* example values: 0x0000 0002 */
	q_u->unknown_0 = unknown_0; 
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_connect(char *desc,  SAMR_Q_CONNECT *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_connect");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	smb_io_unistr2("", &(q_u->uni_srv_name), q_u->ptr_srv_name, ps, depth); 

	prs_align(ps);

	prs_uint32("unknown_0   ", ps, depth, &(q_u->unknown_0   ));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_connect(char *desc,  SAMR_R_CONNECT *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_connect");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(r_u->connect_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_CONNECT_ANON structure.
********************************************************************/
void make_samr_q_connect_anon(SAMR_Q_CONNECT_ANON *q_u)
{
	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_connect_anon\n"));

	q_u->ptr       = 1;
	q_u->unknown_0 = 0x5c; /* server name (?!!) */
	q_u->unknown_1 = 0x01;
	q_u->unknown_2 = 0x20;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_connect_anon(char *desc,  SAMR_Q_CONNECT_ANON *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_connect_anon");
	depth++;

	prs_align(ps);

	prs_uint32("ptr      ", ps, depth, &(q_u->ptr      ));
	prs_uint16("unknown_0", ps, depth, &(q_u->unknown_0));
	prs_uint16("unknown_1", ps, depth, &(q_u->unknown_1));
	prs_uint32("unknown_2", ps, depth, &(q_u->unknown_2));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_connect_anon(char *desc,  SAMR_R_CONNECT_ANON *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_connect_anon");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &(r_u->connect_pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

/*******************************************************************
makes a SAMR_Q_UNKNOWN_38 structure.
********************************************************************/
void make_samr_q_unknown_38(SAMR_Q_UNKNOWN_38 *q_u, char *srv_name)
{
	int len_srv_name = strlen(srv_name);

	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_unknown_38\n"));

	q_u->ptr = 1;
	make_uni_hdr(&(q_u->hdr_srv_name), len_srv_name, len_srv_name, len_srv_name != 0);
	make_unistr2(&(q_u->uni_srv_name), srv_name, len_srv_name);  

}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_unknown_38(char *desc,  SAMR_Q_UNKNOWN_38 *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_unknown_38");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(q_u->ptr));
	if (q_u->ptr != 0)
	{
		smb_io_unihdr ("", &(q_u->hdr_srv_name), ps, depth); 
		smb_io_unistr2("", &(q_u->uni_srv_name), q_u->hdr_srv_name.buffer, ps, depth); 
	}
}

/*******************************************************************
makes a SAMR_R_UNKNOWN_38 structure.
********************************************************************/
void make_samr_r_unknown_38(SAMR_R_UNKNOWN_38 *r_u)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_r_unknown_38\n"));

	r_u->unk_0 = 0;
	r_u->unk_1 = 0;
	r_u->unk_2 = 0;
	r_u->unk_3 = 0;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_unknown_38(char *desc,  SAMR_R_UNKNOWN_38 *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_38");
	depth++;

	prs_align(ps);

	prs_uint16("unk_0", ps, depth, &(r_u->unk_0));
	prs_align(ps);
	prs_uint16("unk_1", ps, depth, &(r_u->unk_1));
	prs_align(ps);
	prs_uint16("unk_2", ps, depth, &(r_u->unk_2));
	prs_align(ps);
	prs_uint16("unk_3", ps, depth, &(r_u->unk_3));
	prs_align(ps);
}

/*******************************************************************
make a SAMR_ENC_PASSWD structure.
********************************************************************/
void make_enc_passwd(SAMR_ENC_PASSWD *pwd, char pass[512])
{
	if (pwd == NULL) return;

	pwd->ptr = 1;
	memcpy(pwd->pass, pass, sizeof(pwd->pass)); 
}

/*******************************************************************
reads or writes a SAMR_ENC_PASSWD structure.
********************************************************************/
void samr_io_enc_passwd(char *desc, SAMR_ENC_PASSWD *pwd, prs_struct *ps, int depth)
{
	if (pwd == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_enc_passwd");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(pwd->ptr));
	prs_uint8s(False, "pwd", ps, depth, pwd->pass, sizeof(pwd->pass)); 
}

/*******************************************************************
makes a SAMR_ENC_HASH structure.
********************************************************************/
void make_enc_hash(SAMR_ENC_HASH *hsh, uchar hash[16])
{
	if (hsh == NULL) return;

	hsh->ptr = 1;
	memcpy(hsh->hash, hash, sizeof(hsh->hash));
}

/*******************************************************************
reads or writes a SAMR_ENC_HASH structure.
********************************************************************/
void samr_io_enc_hash(char *desc, SAMR_ENC_HASH *hsh, prs_struct *ps, int depth)
{
	if (hsh == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_enc_hash");
	depth++;

	prs_align(ps);

	prs_uint32("ptr ", ps, depth, &(hsh->ptr));
	prs_uint8s(False, "hash", ps, depth, hsh->hash, sizeof(hsh->hash)); 
}

/*******************************************************************
makes a SAMR_R_UNKNOWN_38 structure.
********************************************************************/
void make_samr_q_chgpasswd_user(SAMR_Q_CHGPASSWD_USER *q_u,
				char *dest_host, char *user_name,
				char nt_newpass[516], uchar nt_oldhash[16],
				char lm_newpass[516], uchar lm_oldhash[16])
{
	int len_dest_host = strlen(dest_host);
	int len_user_name = strlen(user_name);

	if (q_u == NULL) return;

	DEBUG(5,("make_samr_q_chgpasswd_user\n"));

	q_u->ptr_0 = 1;
	make_uni_hdr(&(q_u->hdr_dest_host), len_dest_host, len_dest_host, len_dest_host != 0);
	make_unistr2(&(q_u->uni_dest_host), dest_host, len_dest_host);  
	make_uni_hdr(&(q_u->hdr_user_name), len_user_name, len_user_name, len_user_name != 0);
	make_unistr2(&(q_u->uni_user_name), user_name, len_user_name);  

	make_enc_passwd(&(q_u->nt_newpass), nt_newpass);
	make_enc_hash  (&(q_u->nt_oldhash), nt_oldhash);

	q_u->unknown = 0x01;

	make_enc_passwd(&(q_u->lm_newpass), lm_newpass);
	make_enc_hash  (&(q_u->lm_oldhash), lm_oldhash);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_q_chgpasswd_user(char *desc, SAMR_Q_CHGPASSWD_USER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_q_chgpasswd_user");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0", ps, depth, &(q_u->ptr_0));

	smb_io_unihdr ("", &(q_u->hdr_dest_host), ps, depth); 
	smb_io_unistr2("", &(q_u->uni_dest_host), q_u->hdr_dest_host.buffer, ps, depth); 
	smb_io_unihdr ("", &(q_u->hdr_user_name), ps, depth); 
	smb_io_unistr2("", &(q_u->uni_user_name), q_u->hdr_user_name.buffer, ps, depth); 

	samr_io_enc_passwd("nt_newpass", &(q_u->nt_newpass), ps, depth); 
	prs_grow(ps);
	samr_io_enc_hash  ("nt_oldhash", &(q_u->nt_oldhash), ps, depth); 

	prs_uint32("unknown", ps, depth, &(q_u->unknown));

	samr_io_enc_passwd("lm_newpass", &(q_u->lm_newpass), ps, depth); 
	prs_grow(ps);
	samr_io_enc_hash  ("lm_oldhash", &(q_u->lm_oldhash), ps, depth); 
}

/*******************************************************************
makes a SAMR_R_CHGPASSWD_USER structure.
********************************************************************/
void make_samr_r_chgpasswd_user(SAMR_R_CHGPASSWD_USER *r_u, uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_r_chgpasswd_user\n"));

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void samr_io_r_chgpasswd_user(char *desc, SAMR_R_CHGPASSWD_USER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "samr_io_r_chgpasswd_user");
	depth++;

	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}


