/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Sander Striker                    2000
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
reads or writes a structure.
********************************************************************/
static BOOL net_io_neg_flags(char *desc,  NEG_FLAGS *neg, prs_struct *ps, int depth)
{
	if (neg == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_neg_flags");
	depth++;

	prs_align(ps);
	
	prs_uint32("neg_flags", ps, depth, &(neg->neg_flags));

	return True;
}

/*******************************************************************
reads or writes a NETLOGON_INFO_3 structure.
********************************************************************/
static BOOL net_io_netinfo_3(char *desc,  NETLOGON_INFO_3 *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_netinfo_3");
	depth++;

	prs_align(ps);
	
	prs_uint32("flags         ", ps, depth, &(info->flags         ));
	prs_uint32("logon_attempts", ps, depth, &(info->logon_attempts));
	prs_uint32("reserved_1    ", ps, depth, &(info->reserved_1    ));
	prs_uint32("reserved_2    ", ps, depth, &(info->reserved_2    ));
	prs_uint32("reserved_3    ", ps, depth, &(info->reserved_3    ));
	prs_uint32("reserved_4    ", ps, depth, &(info->reserved_4    ));
	prs_uint32("reserved_5    ", ps, depth, &(info->reserved_5    ));

	return True;
}


/*******************************************************************
reads or writes a NETLOGON_INFO_1 structure.
********************************************************************/
static BOOL net_io_netinfo_1(char *desc,  NETLOGON_INFO_1 *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_netinfo_1");
	depth++;

	prs_align(ps);
	
	prs_uint32("flags     ", ps, depth, &(info->flags     ));
	prs_uint32("pdc_status", ps, depth, &(info->pdc_status));

	return True;
}

/*******************************************************************
reads or writes a NETLOGON_INFO_2 structure.
********************************************************************/
static BOOL net_io_netinfo_2(char *desc,  NETLOGON_INFO_2 *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_netinfo_2");
	depth++;

	prs_align(ps);
	
	prs_uint32("flags              ", ps, depth, &(info->flags              ));
	prs_uint32("pdc_status         ", ps, depth, &(info->pdc_status         ));
	prs_uint32("ptr_trusted_dc_name", ps, depth, &(info->ptr_trusted_dc_name));
	prs_uint32("tc_status          ", ps, depth, &(info->tc_status          ));

	if (info->ptr_trusted_dc_name != 0)
	{
		smb_io_unistr2("unistr2", &(info->uni_trusted_dc_name), info->ptr_trusted_dc_name, ps, depth);
	}

	prs_align(ps);

	return True;
}

/*******************************************************************
makes an NET_Q_LOGON_CTRL2 structure.
********************************************************************/
BOOL make_q_logon_ctrl2(NET_Q_LOGON_CTRL2 *q_l, 
				const char* srv_name,
				uint32 function_code,
				uint32 query_level,
				uint32 switch_value)
{
	if (q_l == NULL) return False;

	DEBUG(5,("make_q_logon_ctrl2\n"));

	q_l->ptr = 1;

	make_unistr2(&(q_l->uni_server_name ), srv_name , strlen(srv_name )+1);

	q_l->function_code = function_code;
	q_l->query_level   = query_level;
	q_l->switch_value  = switch_value;

	return True;
}

/*******************************************************************
reads or writes an NET_Q_LOGON_CTRL2 structure.
********************************************************************/
BOOL net_io_q_logon_ctrl2(char *desc,  NET_Q_LOGON_CTRL2 *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_logon_ctrl2");
	depth++;

	prs_align(ps);

	prs_uint32("ptr          ", ps, depth, &(q_l->ptr          ));

	smb_io_unistr2 ("", &(q_l->uni_server_name), q_l->ptr, ps, depth);

	prs_align(ps);

	prs_uint32("function_code", ps, depth, &(q_l->function_code));
	prs_uint32("query_level  ", ps, depth, &(q_l->query_level  ));
	prs_uint32("switch_value ", ps, depth, &(q_l->switch_value ));

	return True;
}

/*******************************************************************
makes an NET_R_LOGON_CTRL2 structure.
********************************************************************/
BOOL make_r_logon_ctrl2(NET_R_LOGON_CTRL2 *r_l, 
				uint32 switch_value,
				NETLOGON_INFO *logon_info,
				uint32 status)
{
	if (r_l == NULL) return False;

	r_l->switch_value  = switch_value; /* should only be 0x1 */
	r_l->status = status;
	memcpy(&(r_l->logon), logon_info, sizeof(NETLOGON_INFO));
	
	if (status == NT_STATUS_NOPROBLEMO)
	{
		r_l->ptr = 1;
	}
	else
	{
		r_l->ptr = 0;
	}

	return True;
}

/*******************************************************************
reads or writes an NET_R_LOGON_CTRL2 structure.
********************************************************************/
BOOL net_io_r_logon_ctrl2(char *desc,  NET_R_LOGON_CTRL2 *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_logon_ctrl2");
	depth++;

	prs_uint32("switch_value ", ps, depth, &(r_l->switch_value ));
	prs_uint32("ptr          ", ps, depth, &(r_l->ptr          ));

	if (r_l->ptr != 0)
	{
		switch (r_l->switch_value)
		{
			case 1:
			{
				net_io_netinfo_1("", &(r_l->logon.info1), ps, depth);
				break;
			}
			case 2:
			{
				net_io_netinfo_2("", &(r_l->logon.info2), ps, depth);
				break;
			}
			case 3:
			{
				net_io_netinfo_3("", &(r_l->logon.info3), ps, depth);
				break;
			}
			default:
			{
				DEBUG(2,("net_io_r_logon_ctrl2: unsupported switch value %d\n",
					r_l->switch_value));
				break;
			}
		}
	}

	prs_uint32("status       ", ps, depth, &(r_l->status       ));

	return True;
}

/*******************************************************************
reads or writes an NET_R_TRUST_DOM_LIST structure.
********************************************************************/
BOOL net_io_r_trust_dom(char *desc,  NET_R_TRUST_DOM_LIST *r_t, prs_struct *ps, int depth)
{
	if (r_t == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_trust_dom");
	depth++;

	smb_io_buffer2("", &r_t->uni_trust_dom_name, True, ps, depth);
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_t->status));

	return True;
}


/*******************************************************************
reads or writes an NET_Q_TRUST_DOM_LIST structure.
********************************************************************/
BOOL net_io_q_trust_dom(char *desc,  NET_Q_TRUST_DOM_LIST *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_trust_dom");
	depth++;

	prs_uint32("ptr", ps, depth, &(q_l->ptr));
	smb_io_unistr2 ("name", &(q_l->uni_server_name), q_l->ptr, ps, depth);

	prs_align(ps);

	prs_uint32("function_code", ps, depth, &(q_l->function_code));

	return True;
}

/*******************************************************************
makes an NET_Q_REQ_CHAL structure.
********************************************************************/
BOOL make_q_req_chal(NET_Q_REQ_CHAL *q_c,
				const char *logon_srv, const char *logon_clnt,
				DOM_CHAL *clnt_chal)
{
	if (q_c == NULL) return False;

	DEBUG(5,("make_q_req_chal: %d\n", __LINE__));

	q_c->undoc_buffer = 1; /* don't know what this buffer is */

	make_unistr2(&(q_c->uni_logon_srv ), logon_srv , strlen(logon_srv )+1);
	make_unistr2(&(q_c->uni_logon_clnt), logon_clnt, strlen(logon_clnt)+1);

	memcpy(q_c->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));

	DEBUG(5,("make_q_req_chal: %d\n", __LINE__));

	return True;
}

/*******************************************************************
reads or writes an NET_Q_REQ_CHAL structure.
********************************************************************/
BOOL net_io_q_req_chal(char *desc,  NET_Q_REQ_CHAL *q_c, prs_struct *ps, int depth)
{
	int old_align;
	if (q_c == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_req_chal");
	depth++;

	prs_align(ps);
    
	prs_uint32("undoc_buffer", ps, depth, &(q_c->undoc_buffer));

	smb_io_unistr2("", &(q_c->uni_logon_srv ), True, ps, depth); /* logon server unicode string */
	smb_io_unistr2("", &(q_c->uni_logon_clnt), True, ps, depth); /* logon client unicode string */

	old_align = ps->align;
	ps->align = 0;
	/* client challenge is _not_ aligned after the unicode strings */
	smb_io_chal("", &(q_c->clnt_chal), ps, depth); /* client challenge */
	ps->align = old_align;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_req_chal(char *desc,  NET_R_REQ_CHAL *r_c, prs_struct *ps, int depth)
{
	if (r_c == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_req_chal");
	depth++;

	prs_align(ps);
    
	smb_io_chal("", &(r_c->srv_chal), ps, depth); /* server challenge */

	prs_uint32("status", ps, depth, &(r_c->status));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_q_auth(NET_Q_AUTH *q_a,
		const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name,
		DOM_CHAL *clnt_chal)
{
	if (q_a == NULL) return False;

	DEBUG(5,("make_q_auth: %d\n", __LINE__));

	make_log_info(&(q_a->clnt_id), logon_srv, acct_name, sec_chan, comp_name);
	memcpy(q_a->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));

	DEBUG(5,("make_q_auth: %d\n", __LINE__));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_auth(char *desc,  NET_Q_AUTH *q_a, prs_struct *ps, int depth)
{
	int old_align;
	if (q_a == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_auth");
	depth++;

	prs_align(ps);
    
	smb_io_log_info ("", &(q_a->clnt_id), ps, depth); /* client identification info */
	/* client challenge is _not_ aligned */
	old_align = ps->align;
	ps->align = 0;
	smb_io_chal     ("", &(q_a->clnt_chal), ps, depth); /* client-calculated credentials */
	ps->align = old_align;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_auth(char *desc,  NET_R_AUTH *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_auth");
	depth++;

	prs_align(ps);
    
	smb_io_chal     ("", &(r_a->srv_chal), ps, depth); /* server challenge */
	prs_uint32("status", ps, depth, &(r_a->status));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_q_auth_2(NET_Q_AUTH_2 *q_a,
		const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name,
		DOM_CHAL *clnt_chal, uint32 clnt_flgs)
{
	if (q_a == NULL) return False;

	DEBUG(5,("make_q_auth_2: %d\n", __LINE__));

	make_log_info(&(q_a->clnt_id), logon_srv, acct_name, sec_chan, comp_name);
	memcpy(q_a->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));
	q_a->clnt_flgs.neg_flags = clnt_flgs;

	DEBUG(5,("make_q_auth_2: %d\n", __LINE__));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_auth_2(char *desc,  NET_Q_AUTH_2 *q_a, prs_struct *ps, int depth)
{
	int old_align;
	if (q_a == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_auth_2");
	depth++;

	prs_align(ps);
    
	smb_io_log_info ("", &(q_a->clnt_id), ps, depth); /* client identification info */
	/* client challenge is _not_ aligned */
	old_align = ps->align;
	ps->align = 0;
	smb_io_chal     ("", &(q_a->clnt_chal), ps, depth); /* client-calculated credentials */
	ps->align = old_align;
	net_io_neg_flags("", &(q_a->clnt_flgs), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_auth_2(char *desc,  NET_R_AUTH_2 *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_auth_2");
	depth++;

	prs_align(ps);
    
	smb_io_chal     ("", &(r_a->srv_chal), ps, depth); /* server challenge */
	net_io_neg_flags("", &(r_a->srv_flgs), ps, depth);

	prs_uint32("status", ps, depth, &(r_a->status));

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_q_srv_pwset(NET_Q_SRV_PWSET *q_s,
				const char *logon_srv, const char *acct_name, 
                		uint16 sec_chan, const char *comp_name,
				DOM_CRED *cred, char nt_cypher[16])
{
	if (q_s == NULL || cred == NULL) return False;

	DEBUG(5,("make_q_srv_pwset\n"));

	make_clnt_info(&(q_s->clnt_id), logon_srv, acct_name, sec_chan, comp_name, cred);

	memcpy(q_s->pwd, nt_cypher, sizeof(q_s->pwd)); 

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_srv_pwset(char *desc,  NET_Q_SRV_PWSET *q_s, prs_struct *ps, int depth)
{
	if (q_s == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_srv_pwset");
	depth++;

	prs_align(ps);
    
	smb_io_clnt_info("", &(q_s->clnt_id), ps, depth); /* client identification/authentication info */
	prs_uint8s (False, "pwd", ps, depth, q_s->pwd, 16); /* new password - undocumented */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_srv_pwset(char *desc,  NET_R_SRV_PWSET *r_s, prs_struct *ps, int depth)
{
	if (r_s == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_srv_pwset");
	depth++;

	prs_align(ps);
    
	smb_io_cred("", &(r_s->srv_cred), ps, depth); /* server challenge */

	prs_uint32("status", ps, depth, &(r_s->status));

	return True;
}


/*************************************************************************
 make DOM_SID2 array from a string containing multiple sids
 *************************************************************************/
static int make_dom_sid2s(const char *sids_str, DOM_SID2 *sids, int max_sids)
{
	char *ptr;
	pstring s2;
	int count;

	DEBUG(4,("make_dom_sid2s: %s\n", sids_str ? sids_str:""));

	if (sids_str == NULL || *sids_str == 0) return 0;

	for (count = 0, ptr = sids_str; 
	     next_token(&ptr, s2, NULL, sizeof(s2)) && count < max_sids; 
	     count++) 
	{
                DOM_SID tmpsid;
                string_to_sid(&tmpsid, s2);
		make_dom_sid2(&sids[count], &tmpsid);
	}

	return count;

	return True;
}

/*******************************************************************
makes a NET_ID_INFO_1 structure.
********************************************************************/
BOOL make_id_info1(NET_ID_INFO_1 *id, const char *domain_name,
				uint32 param_ctrl,
				uint32 log_id_low,
				uint32 log_id_high,
				const char *user_name,
				const char *wksta_name,
				const char sess_key[16],
				const uchar lm_cypher[16],
				const uchar nt_cypher[16])
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );

	uchar lm_owf[16];
	uchar nt_owf[16];
	uchar key[16];

	if (id == NULL) return False;

	DEBUG(5,("make_id_info1: %d\n", __LINE__));

	id->ptr_id_info1 = 1;

	make_uni_hdr(&(id->hdr_domain_name), len_domain_name);

	id->param_ctrl = param_ctrl;
	id->logon_id.low = log_id_low;
	id->logon_id.high = log_id_high;

	make_uni_hdr(&(id->hdr_user_name  ), len_user_name  );
	make_uni_hdr(&(id->hdr_wksta_name ), len_wksta_name );

	memset(key, 0, 16);
	memcpy(key, sess_key, 8);

	if (lm_cypher != NULL)
	{
#ifdef DEBUG_PASSWORD
		DEBUG(100,("lm cypher:"));
		dump_data(100, lm_cypher, 16);
#endif

		memcpy(lm_owf, lm_cypher, 16);
		SamOEMhash(lm_owf, key, False);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of lm owf password:"));
		dump_data(100, lm_owf, 16);
#endif
		/* set up pointers to cypher blocks */
		lm_cypher = lm_owf;
	}

	if (nt_cypher != NULL)
	{
#ifdef DEBUG_PASSWORD
		DEBUG(100,("nt cypher:"));
		dump_data(100, nt_cypher, 16);
#endif

		memcpy(nt_owf, nt_cypher, 16);
		SamOEMhash(nt_owf, key, False);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of nt owf password:"));
		dump_data(100, nt_owf, 16);
#endif
		/* set up pointers to cypher blocks */
		nt_cypher = nt_owf;
	}

	make_owf_info(&(id->lm_owf), lm_cypher);
	make_owf_info(&(id->nt_owf), nt_cypher);

	make_unistr2(&(id->uni_domain_name), domain_name, len_domain_name);
	make_unistr2(&(id->uni_user_name  ), user_name  , len_user_name  );
	make_unistr2(&(id->uni_wksta_name ), wksta_name , len_wksta_name );

	return True;
}

/*******************************************************************
reads or writes an NET_ID_INFO_1 structure.
********************************************************************/
static BOOL net_io_id_info1(char *desc,  NET_ID_INFO_1 *id, prs_struct *ps, int depth)
{
	if (id == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_id_info1");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr_id_info1", ps, depth, &(id->ptr_id_info1));

	if (id->ptr_id_info1 != 0)
	{
		smb_io_unihdr("unihdr", &(id->hdr_domain_name), ps, depth);

		prs_uint32("param_ctrl", ps, depth, &(id->param_ctrl));
		smb_io_bigint("", &(id->logon_id), ps, depth);

		smb_io_unihdr("unihdr", &(id->hdr_user_name  ), ps, depth);
		smb_io_unihdr("unihdr", &(id->hdr_wksta_name ), ps, depth);

		smb_io_owf_info("", &(id->lm_owf), ps, depth);
		smb_io_owf_info("", &(id->nt_owf), ps, depth);

		smb_io_unistr2("unistr2", &(id->uni_domain_name), id->hdr_domain_name.buffer, ps, depth);
		smb_io_unistr2("unistr2", &(id->uni_user_name  ), id->hdr_user_name.buffer, ps, depth);
		smb_io_unistr2("unistr2", &(id->uni_wksta_name ), id->hdr_wksta_name.buffer, ps, depth);
	}

	return True;
}

/*******************************************************************
makes a NET_ID_INFO_4 structure.

This is a network logon packet. The log_id parameters
are what an NT server would generate for LUID once the
user is logged on. I don't think we care about them.

Note that this has no access to the NT and LM hashed passwords,
so it forwards the challenge, and the NT and LM responses (24
bytes each) over the secure channel to the Domain controller
for it to say yea or nay. This is the preferred method of 
checking for a logon as it doesn't export the password
hashes to anyone who has compromised the secure channel. JRA.
********************************************************************/

BOOL make_id_info4(NET_ID_INFO_4 *id, const char *domain_name,
				uint32 param_ctrl,
				uint32 log_id_low, uint32 log_id_high,
				const char *user_name, const char *wksta_name,
				const char *general)
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );
 	int len_general     = strlen(general);

	if (id == NULL) return False;

	DEBUG(5,("make_id_info4: %d\n", __LINE__));

	id->ptr_id_info4 = 1;

	make_uni_hdr(&(id->hdr_domain_name), len_domain_name);

	id->param_ctrl = param_ctrl;
	id->logon_id.low = log_id_low;
	id->logon_id.high = log_id_high;

	make_uni_hdr(&(id->hdr_user_name  ), len_user_name  );
	make_uni_hdr(&(id->hdr_wksta_name ), len_wksta_name );
	make_str_hdr(&(id->hdr_general    ), len_general, len_general, 1);

	make_unistr2(&(id->uni_domain_name), domain_name, len_domain_name);
	make_unistr2(&(id->uni_user_name  ), user_name  , len_user_name  );
	make_unistr2(&(id->uni_wksta_name ), wksta_name , len_wksta_name );
	make_string2(&(id->str_general    ), general    , len_general    );

	return True;
}

/*******************************************************************
reads or writes an NET_ID_INFO_4 structure.
********************************************************************/
static BOOL net_io_id_info4(char *desc,  NET_ID_INFO_4 *id, prs_struct *ps, int depth)
{
	if (id == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_id_info4");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr_id_info4", ps, depth, &(id->ptr_id_info4));

	if (id->ptr_id_info4 != 0)
	{
		smb_io_unihdr("unihdr", &(id->hdr_domain_name), ps, depth);

		prs_uint32("param_ctrl", ps, depth, &(id->param_ctrl));
		smb_io_bigint("", &(id->logon_id), ps, depth);

		smb_io_unihdr("hdr_user   ", &(id->hdr_user_name ), ps, depth);
		smb_io_unihdr("hdr_wksta  ", &(id->hdr_wksta_name), ps, depth);
		smb_io_strhdr("hdr_general", &(id->hdr_general   ), ps, depth);

		smb_io_unistr2("uni_domain_name", &(id->uni_domain_name), id->hdr_domain_name .buffer, ps, depth);
		smb_io_unistr2("uni_user_name  ", &(id->uni_user_name  ), id->hdr_user_name   .buffer, ps, depth);
		smb_io_unistr2("uni_wksta_name ", &(id->uni_wksta_name ), id->hdr_wksta_name  .buffer, ps, depth);
		smb_io_string2("str_general    ", &(id->str_general    ), id->hdr_general     .buffer, ps, depth);
	}

	return True;
}

/*******************************************************************
makes a NET_ID_INFO_2 structure.

This is a network logon packet. The log_id parameters
are what an NT server would generate for LUID once the
user is logged on. I don't think we care about them.

Note that this has no access to the NT and LM hashed passwords,
so it forwards the challenge, and the NT and LM responses (24
bytes each) over the secure channel to the Domain controller
for it to say yea or nay. This is the preferred method of 
checking for a logon as it doesn't export the password
hashes to anyone who has compromised the secure channel. JRA.
********************************************************************/

BOOL make_id_info2(NET_ID_INFO_2 *id, const char *domain_name,
				uint32 param_ctrl,
				uint32 log_id_low, uint32 log_id_high,
				const char *user_name, const char *wksta_name,
				const uchar lm_challenge[8],
				const uchar *lm_chal_resp,
				int lm_chal_len,
				const uchar *nt_chal_resp,
				int nt_chal_len)
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );
	uchar lm_owf[24];
	uchar nt_owf[128];

	if (id == NULL) return False;

	DEBUG(5,("make_id_info2: %d\n", __LINE__));

	id->ptr_id_info2 = 1;

	make_uni_hdr(&(id->hdr_domain_name), len_domain_name);

	id->param_ctrl = param_ctrl;
	id->logon_id.low = log_id_low;
	id->logon_id.high = log_id_high;

	make_uni_hdr(&(id->hdr_user_name  ), len_user_name  );
	make_uni_hdr(&(id->hdr_wksta_name ), len_wksta_name );

	if (nt_chal_resp != NULL)
	{
		/* oops.  can only send what-ever-it-is direct */
		memcpy(nt_owf, nt_chal_resp, MIN(nt_chal_len, sizeof(nt_owf)));
		nt_chal_resp = nt_owf;
	}
	if (lm_chal_resp != NULL)
	{
		/* oops.  can only send what-ever-it-is direct */
		memcpy(lm_owf, lm_chal_resp, MIN(nt_chal_len, sizeof(lm_owf)));
		lm_chal_resp = lm_owf;
	}

	memcpy(id->lm_chal, lm_challenge, sizeof(id->lm_chal));
	make_str_hdr(&(id->hdr_nt_chal_resp), sizeof(nt_owf), nt_chal_len, nt_chal_resp != NULL ? 1 : 0);
	make_str_hdr(&(id->hdr_lm_chal_resp), sizeof(lm_owf), lm_chal_len, lm_chal_resp != NULL ? 1 : 0);

	make_unistr2(&(id->uni_domain_name), domain_name, len_domain_name);
	make_unistr2(&(id->uni_user_name  ), user_name  , len_user_name  );
	make_unistr2(&(id->uni_wksta_name ), wksta_name , len_wksta_name );

	make_string2(&(id->nt_chal_resp ), nt_chal_resp , nt_chal_len);
	make_string2(&(id->lm_chal_resp ), lm_chal_resp , lm_chal_len);

	return True;
}

/*******************************************************************
reads or writes an NET_ID_INFO_2 structure.
********************************************************************/
static BOOL net_io_id_info2(char *desc,  NET_ID_INFO_2 *id, prs_struct *ps, int depth)
{
	if (id == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_id_info2");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr_id_info2", ps, depth, &(id->ptr_id_info2));

	if (id->ptr_id_info2 != 0)
	{
		smb_io_unihdr("unihdr", &(id->hdr_domain_name), ps, depth);

		prs_uint32("param_ctrl", ps, depth, &(id->param_ctrl));
		smb_io_bigint("", &(id->logon_id), ps, depth);

		smb_io_unihdr("unihdr", &(id->hdr_user_name  ), ps, depth);
		smb_io_unihdr("unihdr", &(id->hdr_wksta_name ), ps, depth);

		prs_uint8s (False, "lm_chal", ps, depth, id->lm_chal, 8); /* lm 8 byte challenge */

		smb_io_strhdr("hdr_nt_chal_resp", &(id->hdr_nt_chal_resp ), ps, depth);
		smb_io_strhdr("hdr_lm_chal_resp", &(id->hdr_lm_chal_resp ), ps, depth);

		smb_io_unistr2("uni_domain_name", &(id->uni_domain_name), id->hdr_domain_name .buffer, ps, depth);
		smb_io_unistr2("uni_user_name  ", &(id->uni_user_name  ), id->hdr_user_name   .buffer, ps, depth);
		smb_io_unistr2("uni_wksta_name ", &(id->uni_wksta_name ), id->hdr_wksta_name  .buffer, ps, depth);
		smb_io_string2("nt_chal_resp"   , &(id->nt_chal_resp)   , id->hdr_nt_chal_resp.buffer, ps, depth);
		smb_io_string2("lm_chal_resp"   , &(id->lm_chal_resp)   , id->hdr_lm_chal_resp.buffer, ps, depth);
	}

	return True;
}


/*******************************************************************
makes a DOM_SAM_INFO structure.
********************************************************************/
BOOL make_sam_info(DOM_SAM_INFO *sam,
				const char *logon_srv, const char *comp_name,
				DOM_CRED *clnt_cred,
				DOM_CRED *rtn_cred, uint16 logon_level,
				NET_ID_INFO_CTR *ctr)
{
	if (sam == NULL) return False;

	DEBUG(5,("make_sam_info: %d\n", __LINE__));

	make_clnt_info2(&(sam->client), logon_srv, comp_name, clnt_cred);

	if (rtn_cred != NULL)
	{
		sam->ptr_rtn_cred = 1;
		memcpy(&(sam->rtn_cred), rtn_cred, sizeof(sam->rtn_cred));
	}
	else
	{
		sam->ptr_rtn_cred = 0;
	}

	sam->logon_level  = logon_level;
	sam->ctr          = ctr;

	return True;
}

/*******************************************************************
reads or writes a DOM_SAM_INFO structure.
********************************************************************/
static BOOL net_io_id_info_ctr(char *desc,  NET_ID_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_sam_info");
	depth++;

	/* don't 4-byte align here! */

	prs_uint16("switch_value ", ps, depth, &(ctr->switch_value));

	switch (ctr->switch_value)
	{
		case INTERACTIVE_LOGON_TYPE:
		{
			net_io_id_info1("", &(ctr->auth.id1), ps, depth);
			break;
		}
		case NETWORK_LOGON_TYPE:
		{
			net_io_id_info2("", &(ctr->auth.id2), ps, depth);
			break;
		}
		case GENERAL_LOGON_TYPE:
		{
			net_io_id_info4("", &(ctr->auth.id4), ps, depth);
			break;
		}
		default:
		{
			/* PANIC! */
			DEBUG(4,("smb_io_sam_info: unknown switch_value!\n"));
			break;
		}
	}

	return True;
}

/*******************************************************************
reads or writes a DOM_SAM_INFO structure.
********************************************************************/
static BOOL smb_io_sam_info(char *desc,  DOM_SAM_INFO *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_sam_info");
	depth++;

	prs_align(ps);
	
	smb_io_clnt_info2("", &(sam->client  ), ps, depth);

	prs_uint32("ptr_rtn_cred ", ps, depth, &(sam->ptr_rtn_cred));
	smb_io_cred      ("", &(sam->rtn_cred), ps, depth);

	prs_uint16("logon_level  ", ps, depth, &(sam->logon_level ));

	if (sam->logon_level != 0 && sam->ctr != NULL)
	{
		net_io_id_info_ctr("logon_info", sam->ctr, ps, depth);
	}

	return True;
}

/*************************************************************************
 make_net_user_info3
 *************************************************************************/
BOOL make_net_user_info3W(NET_USER_INFO_3 *usr,

	const NTTIME *logon_time,
	const NTTIME *logoff_time,
	const NTTIME *kickoff_time,
	const NTTIME *pass_last_set_time,
	const NTTIME *pass_can_change_time,
	const NTTIME *pass_must_change_time,

	const UNISTR2 *user_name, 
	const UNISTR2 *full_name,
	const UNISTR2 *log_scr,
	const UNISTR2 *prof_path,
	const UNISTR2 *home_dir,
	const UNISTR2 *dir_drive,

	uint16 logon_count,
	uint16 bad_pw_count,

	uint32 user_id,
	uint32 group_id,
	uint32 num_groups,
	const DOM_GID *gids,
	uint32 user_flgs,

	const char sess_key[16],

	const UNISTR2 *logon_srv,
	const UNISTR2 *logon_dom,

	const char *padding,

	const DOM_SID *dom_sid,
	const char *other_sids)
{
	/* only cope with one "other" sid, right now. */
	/* need to count the number of space-delimited sids */
	uint32 i;
	int num_other_sids = 0;

	int len_user_name    = user_name != NULL ? user_name->uni_str_len : 0;
	int len_full_name    = full_name != NULL ? full_name->uni_str_len : 0;
	int len_logon_script = log_scr   != NULL ? log_scr  ->uni_str_len : 0;
	int len_profile_path = prof_path != NULL ? prof_path->uni_str_len : 0;
	int len_home_dir     = home_dir  != NULL ? home_dir ->uni_str_len : 0;
	int len_dir_drive    = dir_drive != NULL ? dir_drive->uni_str_len : 0;

	int len_logon_srv  = logon_srv   != NULL ? logon_srv ->uni_str_len : 0;
	int len_logon_dom  = logon_dom   != NULL ? logon_dom ->uni_str_len : 0;

	usr->ptr_user_info = 1; /* yes, we're bothering to put USER_INFO data here */

	usr->logon_time            = *logon_time;
	usr->logoff_time           = *logoff_time;
	usr->kickoff_time          = *kickoff_time;
	usr->pass_last_set_time    = *pass_last_set_time;
	usr->pass_can_change_time  = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   );
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path);
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   );

	usr->logon_count = logon_count;
	usr->bad_pw_count = bad_pw_count;

	usr->user_id = user_id;
	usr->group_id = group_id;
	usr->num_groups = num_groups;
	usr->buffer_groups = 1; /* indicates fill in groups, below, even if there are none */
	usr->user_flgs = user_flgs;

	if (sess_key != NULL)
	{
		memcpy(usr->user_sess_key, sess_key, sizeof(usr->user_sess_key));
	}
	else
	{
		bzero(usr->user_sess_key, sizeof(usr->user_sess_key));
	}

	make_uni_hdr(&(usr->hdr_logon_srv), len_logon_srv);
	make_uni_hdr(&(usr->hdr_logon_dom), len_logon_dom);

	usr->buffer_dom_id = dom_sid ? 1 : 0; /* yes, put a domain SID in */

	bzero(usr->padding, sizeof(usr->padding));
	if (padding != NULL)
	{	
		memcpy(usr->padding, padding, 8);
	}

	num_other_sids = make_dom_sid2s(other_sids, usr->other_sids, LSA_MAX_SIDS);

	usr->num_other_sids = num_other_sids;
	usr->buffer_other_sids = num_other_sids != 0 ? 1 : 0; 
	
	copy_unistr2(&(usr->uni_user_name   ), user_name);
	copy_unistr2(&(usr->uni_full_name   ), full_name);
	copy_unistr2(&(usr->uni_logon_script), log_scr  );
	copy_unistr2(&(usr->uni_profile_path), prof_path);
	copy_unistr2(&(usr->uni_home_dir    ), home_dir );
	copy_unistr2(&(usr->uni_dir_drive   ), dir_drive);

	usr->num_groups2 = num_groups;

	SMB_ASSERT_ARRAY(usr->gids, num_groups);

	for (i = 0; i < num_groups; i++)
	{
		usr->gids[i] = gids[i];
	}

	copy_unistr2(&(usr->uni_logon_srv ), logon_srv);
	copy_unistr2(&(usr->uni_logon_dom ), logon_dom);

	make_dom_sid2(&(usr->dom_sid), dom_sid);
	/* "other" sids are set up above */

	return True;
}

/*************************************************************************
 make_net_user_info3
 *************************************************************************/
BOOL make_net_user_info3(NET_USER_INFO_3 *usr,

	NTTIME *logon_time,
	NTTIME *logoff_time,
	NTTIME *kickoff_time,
	NTTIME *pass_last_set_time,
	NTTIME *pass_can_change_time,
	NTTIME *pass_must_change_time,

	char *user_name,
	char *full_name,
	char *logon_script,
	char *profile_path,
	char *home_dir,
	char *dir_drive,

	uint16 logon_count,
	uint16 bad_pw_count,

	uint32 user_id,
	uint32 group_id,
	uint32 num_groups,
	DOM_GID *gids,
	uint32 user_flgs,

	char sess_key[16],

	char *logon_srv,
	char *logon_dom,

	char *padding,

	DOM_SID *dom_sid,
	char *other_sids)
{
	/* only cope with one "other" sid, right now. */
	/* need to count the number of space-delimited sids */
	uint32 i;
	int num_other_sids = 0;

	int len_user_name    = strlen(user_name   );
	int len_full_name    = strlen(full_name   );
	int len_logon_script = strlen(logon_script);
	int len_profile_path = strlen(profile_path);
	int len_home_dir     = strlen(home_dir    );
	int len_dir_drive    = strlen(dir_drive   );

	int len_logon_srv    = strlen(logon_srv);
	int len_logon_dom    = strlen(logon_dom);

	usr->ptr_user_info = 1; /* yes, we're bothering to put USER_INFO data here */

	usr->logon_time            = *logon_time;
	usr->logoff_time           = *logoff_time;
	usr->kickoff_time          = *kickoff_time;
	usr->pass_last_set_time    = *pass_last_set_time;
	usr->pass_can_change_time  = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   );
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path);
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   );

	usr->logon_count = logon_count;
	usr->bad_pw_count = bad_pw_count;

	usr->user_id = user_id;
	usr->group_id = group_id;
	usr->num_groups = num_groups;
	usr->buffer_groups = 1; /* indicates fill in groups, below, even if there are none */
	usr->user_flgs = user_flgs;

	if (sess_key != NULL)
	{
		memcpy(usr->user_sess_key, sess_key, sizeof(usr->user_sess_key));
	}
	else
	{
		bzero(usr->user_sess_key, sizeof(usr->user_sess_key));
	}

	make_uni_hdr(&(usr->hdr_logon_srv), len_logon_srv);
	make_uni_hdr(&(usr->hdr_logon_dom), len_logon_dom);

	usr->buffer_dom_id = dom_sid ? 1 : 0; /* yes, we're bothering to put a domain SID in */

	bzero(usr->padding, sizeof(usr->padding));
	if (padding != NULL)
	{	
		memcpy(usr->padding, padding, 8);
	}

	num_other_sids = make_dom_sid2s(other_sids, usr->other_sids, LSA_MAX_SIDS);

	usr->num_other_sids = num_other_sids;
	usr->buffer_other_sids = num_other_sids != 0 ? 1 : 0; 
	
	make_unistr2(&(usr->uni_user_name   ), user_name   , len_user_name   );
	make_unistr2(&(usr->uni_full_name   ), full_name   , len_full_name   );
	make_unistr2(&(usr->uni_logon_script), logon_script, len_logon_script);
	make_unistr2(&(usr->uni_profile_path), profile_path, len_profile_path);
	make_unistr2(&(usr->uni_home_dir    ), home_dir    , len_home_dir    );
	make_unistr2(&(usr->uni_dir_drive   ), dir_drive   , len_dir_drive   );

	usr->num_groups2 = num_groups;

	SMB_ASSERT_ARRAY(usr->gids, num_groups);

	for (i = 0; i < num_groups; i++)
	{
		usr->gids[i] = gids[i];
	}

	make_unistr2(&(usr->uni_logon_srv), logon_srv, len_logon_srv);
	make_unistr2(&(usr->uni_logon_dom), logon_dom, len_logon_dom);

	make_dom_sid2(&(usr->dom_sid), dom_sid);
	/* "other" sids are set up above */

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_user_info3(char *desc,  NET_USER_INFO_3 *usr, prs_struct *ps, int depth)
{
	uint32 i;

	if (usr == NULL) return False;

	prs_debug(ps, depth, desc, "lsa_io_lsa_user_info");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr_user_info ", ps, depth, &(usr->ptr_user_info));

	if (usr->ptr_user_info != 0)
	{
		smb_io_time("time", &(usr->logon_time)           , ps, depth); /* logon time */
		smb_io_time("time", &(usr->logoff_time)          , ps, depth); /* logoff time */
		smb_io_time("time", &(usr->kickoff_time)         , ps, depth); /* kickoff time */
		smb_io_time("time", &(usr->pass_last_set_time)   , ps, depth); /* password last set time */
		smb_io_time("time", &(usr->pass_can_change_time) , ps, depth); /* password can change time */
		smb_io_time("time", &(usr->pass_must_change_time), ps, depth); /* password must change time */

		smb_io_unihdr("unihdr", &(usr->hdr_user_name)   , ps, depth); /* username unicode string header */
		smb_io_unihdr("unihdr", &(usr->hdr_full_name)   , ps, depth); /* user's full name unicode string header */
		smb_io_unihdr("unihdr", &(usr->hdr_logon_script), ps, depth); /* logon script unicode string header */
		smb_io_unihdr("unihdr", &(usr->hdr_profile_path), ps, depth); /* profile path unicode string header */
		smb_io_unihdr("unihdr", &(usr->hdr_home_dir)    , ps, depth); /* home directory unicode string header */
		smb_io_unihdr("unihdr", &(usr->hdr_dir_drive)   , ps, depth); /* home directory drive unicode string header */

		prs_uint16("logon_count   ", ps, depth, &(usr->logon_count ));  /* logon count */
		prs_uint16("bad_pw_count  ", ps, depth, &(usr->bad_pw_count)); /* bad password count */

		prs_uint32("user_id       ", ps, depth, &(usr->user_id      ));       /* User ID */
		prs_uint32("group_id      ", ps, depth, &(usr->group_id     ));      /* Group ID */
		prs_uint32("num_groups    ", ps, depth, &(usr->num_groups   ));    /* num groups */
		prs_uint32("buffer_groups ", ps, depth, &(usr->buffer_groups)); /* undocumented buffer pointer to groups. */
		prs_uint32("user_flgs     ", ps, depth, &(usr->user_flgs    ));     /* user flags */

		prs_uint8s (False, "user_sess_key", ps, depth, usr->user_sess_key, 16); /* unused user session key */

		smb_io_unihdr("unihdr", &(usr->hdr_logon_srv), ps, depth); /* logon server unicode string header */
		smb_io_unihdr("unihdr", &(usr->hdr_logon_dom), ps, depth); /* logon domain unicode string header */

		prs_uint32("buffer_dom_id ", ps, depth, &(usr->buffer_dom_id)); /* undocumented logon domain id pointer */
		prs_uint8s (False, "padding       ", ps, depth, usr->padding, 40); /* unused padding bytes? */

		prs_uint32("num_other_sids", ps, depth, &(usr->num_other_sids)); /* 0 - num_sids */
		prs_uint32("buffer_other_sids", ps, depth, &(usr->buffer_other_sids)); /* NULL - undocumented pointer to SIDs. */
		
		smb_io_unistr2("unistr2", &(usr->uni_user_name)   , usr->hdr_user_name   .buffer, ps, depth); /* username unicode string */
		smb_io_unistr2("unistr2", &(usr->uni_full_name)   , usr->hdr_full_name   .buffer, ps, depth); /* user's full name unicode string */
		smb_io_unistr2("unistr2", &(usr->uni_logon_script), usr->hdr_logon_script.buffer, ps, depth); /* logon script unicode string */
		smb_io_unistr2("unistr2", &(usr->uni_profile_path), usr->hdr_profile_path.buffer, ps, depth); /* profile path unicode string */
		smb_io_unistr2("unistr2", &(usr->uni_home_dir)    , usr->hdr_home_dir    .buffer, ps, depth); /* home directory unicode string */
		smb_io_unistr2("unistr2", &(usr->uni_dir_drive)   , usr->hdr_dir_drive   .buffer, ps, depth); /* home directory drive unicode string */

		prs_align(ps);
		prs_uint32("num_groups2   ", ps, depth, &(usr->num_groups2));        /* num groups */
		SMB_ASSERT_ARRAY(usr->gids, usr->num_groups2);
		for (i = 0; i < usr->num_groups2; i++)
		{
			smb_io_gid("", &(usr->gids[i]), ps, depth); /* group info */
		}

		smb_io_unistr2("unistr2", &( usr->uni_logon_srv), usr->hdr_logon_srv.buffer, ps, depth); /* logon server unicode string */
		smb_io_unistr2("unistr2", &( usr->uni_logon_dom), usr->hdr_logon_srv.buffer, ps, depth); /* logon domain unicode string */

		smb_io_dom_sid2("", &(usr->dom_sid), ps, depth);           /* domain SID */

		SMB_ASSERT_ARRAY(usr->other_sids, usr->num_other_sids);

		for (i = 0; i < usr->num_other_sids; i++)
		{
			smb_io_dom_sid2("", &(usr->other_sids[i]), ps, depth); /* other domain SIDs */
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_sam_logon(char *desc,  NET_Q_SAM_LOGON *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_logon");
	depth++;

	prs_align(ps);
	
	smb_io_sam_info("", &(q_l->sam_id), ps, depth);           /* domain SID */
	prs_uint16("validation_level", ps, depth, &(q_l->validation_level));

	return True;
}

/*******************************************************************
makes a NET_R_SAM_LOGON structure.
********************************************************************/
BOOL make_r_sam_logon(NET_R_SAM_LOGON *r_s, 
			    const DOM_CRED *srv_creds,
			    uint16 switch_value,
			    NET_USER_INFO_3 *user_info,
			    uint32 auth_resp,
			    uint32 status)
{
	if (r_s == NULL) return False;

	/* XXXX we may want this behaviour:
	if (status == NT_STATUS_NOPROBLEMO)
	{
	*/

	r_s->buffer_creds = 1;

	if (status == NT_STATUS_NOPROBLEMO)
	{
		memcpy(&(r_s->srv_creds), srv_creds, sizeof(r_s->srv_creds));
		/* store the user information, if there is any. */
		r_s->user = user_info;
		if (user_info != NULL && user_info->ptr_user_info != 0)
		{
			r_s->switch_value = 3; /* indicates type of validation user info */
		}
		else
		{
			r_s->switch_value = 0; /* indicates no info */
		}
	}
	else
	{
		/* XXXX we may want this behaviour:
		r_s->buffer_creds = 0;
		*/
		r_s->switch_value = 0;
		r_s->user = NULL;
	}

	r_s->status = status;
	r_s->auth_resp = auth_resp;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_sam_logon(char *desc,  NET_R_SAM_LOGON *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_logon");
	depth++;

	prs_uint32("buffer_creds", ps, depth, &(r_l->buffer_creds)); /* undocumented buffer pointer */
	smb_io_cred("", &(r_l->srv_creds), ps, depth); /* server credentials.  server time stamp appears to be ignored. */

	prs_uint16("switch_value", ps, depth, &(r_l->switch_value));
	prs_align(ps);

	if (r_l->switch_value != 0)
	{
		net_io_user_info3("", r_l->user, ps, depth);
	}

	prs_uint32("auth_resp   ", ps, depth, &(r_l->auth_resp)); /* 1 - Authoritative response; 0 - Non-Auth? */

	prs_uint32("status      ", ps, depth, &(r_l->status));

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_sam_logoff(char *desc,  NET_Q_SAM_LOGOFF *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_logoff");
	depth++;

	prs_align(ps);
	
	smb_io_sam_info("", &(q_l->sam_id), ps, depth);           /* domain SID */

	return True;
}

/*******************************************************************
makes a NET_R_SAM_LOGOFF structure.
********************************************************************/
BOOL make_r_sam_logoff(NET_R_SAM_LOGOFF *r_s, 
			    const DOM_CRED *srv_cred,
			    uint32 status)
{
	if (r_s == NULL) return False;

	/* XXXX we may want this behaviour:
	if (status == NT_STATUS_NOPROBLEMO)
	{
	*/
		/* XXXX maybe we want to say 'no', reject the client's credentials */
		r_s->buffer_creds = 1; /* yes, we have valid server credentials */
		memcpy(&(r_s->srv_creds), srv_cred, sizeof(r_s->srv_creds));

	/* XXXX we may want this behaviour:
	}
	else
	{
		r_s->buffer_creds = 0;
	}
	*/

	r_s->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_sam_logoff(char *desc,  NET_R_SAM_LOGOFF *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_logoff");
	depth++;

	prs_align(ps);
	
	prs_uint32("buffer_creds", ps, depth, &(r_l->buffer_creds)); /* undocumented buffer pointer */
	smb_io_cred("", &(r_l->srv_creds), ps, depth); /* server credentials.  server time stamp appears to be ignored. */

	prs_uint32("status      ", ps, depth, &(r_l->status));

	return True;
}

/*******************************************************************
makes a NET_Q_SAM_SYNC structure.
********************************************************************/
BOOL make_q_sam_sync(NET_Q_SAM_SYNC *q_s,
				const char *srv_name,
				const char *cli_name,
				DOM_CRED *cli_creds, uint32 database_id)
{
	if (q_s == NULL) return False;

	DEBUG(5,("make_q_sam_sync\n"));

	make_unistr2(&(q_s->uni_srv_name), srv_name, strlen(srv_name)+1);
	make_unistr2(&(q_s->uni_cli_name), cli_name, strlen(cli_name)+1);

	memcpy(&(q_s->cli_creds), cli_creds, sizeof(q_s->cli_creds));
	memset(&(q_s->ret_creds), 0, sizeof(q_s->ret_creds));

	q_s->database_id = database_id;
	q_s->restart_state = 0;
	q_s->sync_context = 0;
	q_s->max_size = 0xffff;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_sam_sync(char *desc, NET_Q_SAM_SYNC *q_s, prs_struct *ps, int depth)
{
	if (q_s == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_sync");
	depth++;

	smb_io_unistr2("", &(q_s->uni_srv_name), True, ps, depth);
	smb_io_unistr2("", &(q_s->uni_cli_name), True, ps, depth);

	smb_io_cred("", &(q_s->cli_creds), ps, depth);
	smb_io_cred("", &(q_s->ret_creds), ps, depth);

	prs_uint32("database_id  ", ps, depth, &(q_s->database_id  ));
	prs_uint32("restart_state", ps, depth, &(q_s->restart_state));
	prs_uint32("sync_context ", ps, depth, &(q_s->sync_context ));

	prs_uint32("max_size", ps, depth, &(q_s->max_size));

	return True;
}

/*******************************************************************
makes a SAM_DELTA_HDR structure.
********************************************************************/
BOOL make_sam_delta_hdr(SAM_DELTA_HDR *delta, uint16 type, uint32 rid)
{
	if (delta == NULL) return False;

	DEBUG(5,("make_sam_delta_hdr\n"));

	delta->type2 = delta->type = type;
	delta->target_rid = rid;

	delta->type3 = type;
	delta->ptr_delta = 1;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_delta_hdr(char *desc, SAM_DELTA_HDR *delta, prs_struct *ps, int depth)
{
	if (delta == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_delta_hdr");
	depth++;

	prs_uint16("type",       ps, depth, &(delta->type      ));
	prs_uint16("type2",      ps, depth, &(delta->type2     ));
	prs_uint32("target_rid", ps, depth, &(delta->target_rid));

	prs_uint32("type3",      ps, depth, &(delta->type3     ));
	prs_uint32("ptr_delta",  ps, depth, &(delta->ptr_delta ));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_domain_info(char *desc, SAM_DOMAIN_INFO *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_domain_info");
	depth++;

	smb_io_unihdr("hdr_dom_name" , &(info->hdr_dom_name) , ps, depth);
	smb_io_unihdr("hdr_oem_info" , &(info->hdr_oem_info) , ps, depth);

	smb_io_bigint("force_logoff" , &(info->force_logoff) , ps, depth);
	prs_uint16("min_pwd_len"     , ps, depth, &(info->min_pwd_len    ));
	prs_uint16("pwd_history_len" , ps, depth, &(info->pwd_history_len));
	smb_io_bigint("max_pwd_age"  , &(info->max_pwd_age)  , ps, depth);
	smb_io_bigint("min_pwd_age"  , &(info->min_pwd_age)  , ps, depth);
	smb_io_bigint("dom_mod_count", &(info->dom_mod_count), ps, depth);
	smb_io_time("creation_time"  , &(info->creation_time), ps, depth);

	smb_io_bufhdr2("hdr_sec_desc", &(info->hdr_sec_desc) , ps, depth);
	smb_io_unihdr ("hdr_unknown" , &(info->hdr_unknown)  , ps, depth);
	ps->offset += 40;

	smb_io_unistr2("uni_dom_name", &(info->uni_dom_name),
		       info->hdr_dom_name.buffer, ps, depth);
	smb_io_unistr2("buf_oem_info", &(info->buf_oem_info),
		       info->hdr_oem_info.buffer, ps, depth);

	smb_io_buffer4("buf_sec_desc", &(info->buf_sec_desc),
		       info->hdr_sec_desc.buffer, ps, depth);
	smb_io_unistr2("buf_unknown" , &(info->buf_unknown ),
		       info->hdr_unknown .buffer, ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_group_info(char *desc, SAM_GROUP_INFO *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_group_info");
	depth++;

	smb_io_unihdr ("hdr_grp_name", &(info->hdr_grp_name), ps, depth);
	smb_io_gid    ("gid",          &(info->gid),          ps, depth);
	smb_io_unihdr ("hdr_grp_desc", &(info->hdr_grp_desc), ps, depth);
	smb_io_bufhdr2("hdr_sec_desc", &(info->hdr_sec_desc), ps, depth);
	ps->offset += 48;

	smb_io_unistr2("uni_grp_name", &(info->uni_grp_name),
		       info->hdr_grp_name.buffer, ps, depth);
	smb_io_unistr2("uni_grp_desc", &(info->uni_grp_desc),
		       info->hdr_grp_desc.buffer, ps, depth);
	smb_io_buffer4("buf_sec_desc", &(info->buf_sec_desc),
		       info->hdr_sec_desc.buffer, ps, depth);

	return True;
}

/*******************************************************************
makes a SAM_ACCOUNT_INFO structure.
********************************************************************/
BOOL make_sam_account_info(SAM_ACCOUNT_INFO *info,
				const UNISTR2 *user_name,
				const UNISTR2 *full_name,
				uint32 user_rid, uint32 group_rid,
				const UNISTR2 *home_dir,
				const UNISTR2 *dir_drive,
				const UNISTR2 *log_scr,
				const UNISTR2 *desc,
				uint32 acb_info,
				const UNISTR2 *prof_path,
				const UNISTR2 *wkstas,
				const UNISTR2 *unk_str,
				const UNISTR2 *mung_dial)
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

	DEBUG(5,("make_sam_account_info\n"));

	make_uni_hdr(&(info->hdr_acct_name   ), len_user_name   );
	make_uni_hdr(&(info->hdr_full_name   ), len_full_name   );
	make_uni_hdr(&(info->hdr_home_dir    ), len_home_dir    );
	make_uni_hdr(&(info->hdr_dir_drive   ), len_dir_drive   );
	make_uni_hdr(&(info->hdr_logon_script), len_logon_script);
	make_uni_hdr(&(info->hdr_profile     ), len_profile_path);
	make_uni_hdr(&(info->hdr_acct_desc   ), len_description );
	make_uni_hdr(&(info->hdr_workstations), len_workstations);
	make_uni_hdr(&(info->hdr_comment     ), len_unknown_str );
	make_uni_hdr(&(info->hdr_parameters  ), len_munged_dial );

	/* not present */
	make_bufhdr2(&(info->hdr_sec_desc), 0, 0, 0);

	info->user_rid = user_rid;
	info->group_rid = group_rid;

	init_nt_time(&(info->logon_time));
	init_nt_time(&(info->logoff_time));
	init_nt_time(&(info->pwd_last_set_time));
	init_nt_time(&(info->acct_expiry_time));

	info->logon_divs = 0xA8;
	info->ptr_logon_hrs = 0; /* Don't care right now */

	info->bad_pwd_count = 0;
	info->logon_count = 0;
	info->acb_info = acb_info;
	info->nt_pwd_present = 0;
	info->lm_pwd_present = 0;
	info->pwd_expired = 0;
	info->country = 0;
	info->codepage = 0;

	info->unknown1 = 0x4EC;
	info->unknown2 = 0;

	copy_unistr2(&(info->uni_acct_name   ), user_name);
	copy_unistr2(&(info->uni_full_name   ), full_name);
	copy_unistr2(&(info->uni_home_dir    ), home_dir );
	copy_unistr2(&(info->uni_dir_drive   ), dir_drive);
	copy_unistr2(&(info->uni_logon_script), log_scr  );
	copy_unistr2(&(info->uni_profile     ), prof_path);
	copy_unistr2(&(info->uni_acct_desc   ), desc     );
	copy_unistr2(&(info->uni_workstations), wkstas   );
	copy_unistr2(&(info->uni_comment     ), unk_str  );
	copy_unistr2(&(info->uni_parameters  ), mung_dial);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_passwd_info(char *desc, SAM_PWD *pwd,
				prs_struct *ps, int depth)
{
	if (pwd == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_passwd_info");
	depth++;

	prs_uint32("unk_0 ", ps, depth, &(pwd->unk_0 ));

	smb_io_unihdr ("hdr_lm_pwd", &(pwd->hdr_lm_pwd), ps, depth);
	prs_uint8s(False, "buf_lm_pwd", ps, depth, pwd->buf_lm_pwd, 16);
	
	smb_io_unihdr ("hdr_nt_pwd", &(pwd->hdr_nt_pwd), ps, depth);
	prs_uint8s(False, "buf_nt_pwd", ps, depth, pwd->buf_nt_pwd, 16);

	smb_io_unihdr("", &(pwd->hdr_empty_lm), ps, depth);
	smb_io_unihdr("", &(pwd->hdr_empty_nt), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_account_info(char *desc, uint8 sess_key[16],
			SAM_ACCOUNT_INFO *info, prs_struct *ps, int depth)
{
	BUFHDR2 hdr_priv_data;
	uint32 i;

	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_account_info");
	depth++;

	smb_io_unihdr("hdr_acct_name", &(info->hdr_acct_name), ps, depth);
	smb_io_unihdr("hdr_full_name", &(info->hdr_full_name), ps, depth);

	prs_uint32("user_rid ", ps, depth, &(info->user_rid ));
	prs_uint32("group_rid", ps, depth, &(info->group_rid));

	smb_io_unihdr("hdr_home_dir "   , &(info->hdr_home_dir ), ps, depth);
	smb_io_unihdr("hdr_dir_drive"   , &(info->hdr_dir_drive), ps, depth);
	smb_io_unihdr("hdr_logon_script", &(info->hdr_logon_script), ps, depth);
	smb_io_unihdr("hdr_acct_desc"   , &(info->hdr_acct_desc), ps, depth);
	smb_io_unihdr("hdr_workstations", &(info->hdr_workstations), ps, depth);

	smb_io_time("logon_time" , &(info->logon_time ), ps, depth);
	smb_io_time("logoff_time", &(info->logoff_time), ps, depth);

	prs_uint32("logon_divs   ", ps, depth, &(info->logon_divs   ));
	prs_uint32("ptr_logon_hrs", ps, depth, &(info->ptr_logon_hrs));

	prs_uint16("bad_pwd_count", ps, depth, &(info->bad_pwd_count));
	prs_uint16("logon_count"  , ps, depth, &(info->logon_count  ));
	smb_io_time("pwd_last_set_time", &(info->pwd_last_set_time), ps, depth);
	smb_io_time("acct_expiry_time" , &(info->acct_expiry_time ), ps, depth);

	prs_uint32("acb_info", ps, depth, &(info->acb_info));
	prs_uint8s(False, "nt_pwd", ps, depth, info->nt_pwd, 16);
	prs_uint8s(False, "lm_pwd", ps, depth, info->lm_pwd, 16);
	prs_uint8("lm_pwd_present", ps, depth, &(info->lm_pwd_present));
	prs_uint8("nt_pwd_present", ps, depth, &(info->nt_pwd_present));
	prs_uint8("pwd_expired"   , ps, depth, &(info->pwd_expired   ));

	smb_io_unihdr("hdr_comment"   , &(info->hdr_comment   ), ps, depth);
	smb_io_unihdr("hdr_parameters", &(info->hdr_parameters), ps, depth);
	prs_uint16("country" , ps, depth, &(info->country ));
	prs_uint16("codepage", ps, depth, &(info->codepage));

	smb_io_bufhdr2("hdr_priv_data", &(hdr_priv_data), ps, depth);
	smb_io_bufhdr2("hdr_sec_desc" , &(info->hdr_sec_desc) , ps, depth);
	smb_io_unihdr ("hdr_profile"  , &(info->hdr_profile)  , ps, depth);

	for (i = 0; i < 3; i++)
	{
		smb_io_unihdr("hdr_reserved", &(info->hdr_reserved[i]), ps, depth);
	}

	for (i = 0; i < 4; i++)
	{
		prs_uint32("dw_reserved", ps, depth, &(info->dw_reserved[i]));
	}

	smb_io_unistr2("uni_acct_name", &(info->uni_acct_name),
		       info->hdr_acct_name.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_full_name", &(info->uni_full_name),
		       info->hdr_full_name.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_home_dir ", &(info->uni_home_dir ),
		       info->hdr_home_dir .buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_dir_drive", &(info->uni_dir_drive),
		       info->hdr_dir_drive.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_logon_script", &(info->uni_logon_script),
		       info->hdr_logon_script.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_acct_desc", &(info->uni_acct_desc),
		       info->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_workstations", &(info->uni_workstations),
		       info->hdr_workstations.buffer, ps, depth);
	prs_align(ps);

	prs_uint32("unknown1", ps, depth, &(info->unknown1));
	prs_uint32("unknown2", ps, depth, &(info->unknown2));

	smb_io_buffer4("buf_logon_hrs" , &(info->buf_logon_hrs ),
		       info->ptr_logon_hrs, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_comment"   , &(info->uni_comment   ),
		       info->hdr_comment.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_parameters", &(info->uni_parameters),
		       info->hdr_parameters.buffer, ps, depth);
	prs_align(ps);
	if (hdr_priv_data.buffer != 0)
	{
		int old_offset;
		uint32 len = 0x44;
		prs_uint32("pwd_len", ps, depth, &len);
		old_offset = ps->offset;
		if (len == 0x44)
		{
			if (ps->io)
			{
				/* reading */
				prs_hash1(ps, ps->offset, sess_key);
			}
			net_io_sam_passwd_info("pass", &(info->pass), ps, depth);
			if (!ps->io)
			{
				/* writing */
				prs_hash1(ps, old_offset, sess_key);
			}
		}
		ps->offset = old_offset + len;
	}
	smb_io_buffer4("buf_sec_desc"  , &(info->buf_sec_desc  ),
		       info->hdr_sec_desc.buffer, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_profile"   , &(info->uni_profile   ),
		       info->hdr_profile.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_group_mem_info(char *desc, SAM_GROUP_MEM_INFO *info, prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_group_mem_info");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_rids   ", ps, depth, &(info->ptr_rids   ));
	prs_uint32("ptr_attribs", ps, depth, &(info->ptr_attribs));
	prs_uint32("num_members", ps, depth, &(info->num_members));
	ps->offset += 16;

	if (info->ptr_rids != 0)
	{
		prs_uint32("num_members2", ps, depth, &(info->num_members2));
		if (info->num_members2 != info->num_members)
		{
			/* RPC fault */
			return False;
		}

		SMB_ASSERT_ARRAY(info->rids, info->num_members2);

		for (i = 0; i < info->num_members2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "rids[%02d]", i);
			prs_uint32(tmp, ps, depth, &(info->rids[i]));
		}
	}

	if (info->ptr_attribs != 0)
	{
		prs_uint32("num_members3", ps, depth, &(info->num_members3));
		if (info->num_members3 != info->num_members)
		{
			/* RPC fault */
			return False;
		}

		SMB_ASSERT_ARRAY(info->attribs, info->num_members3);

		for (i = 0; i < info->num_members3; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "attribs[%02d]", i);
			prs_uint32(tmp, ps, depth, &(info->attribs[i]));
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_alias_info(char *desc, SAM_ALIAS_INFO *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_alias_info");
	depth++;

	smb_io_unihdr ("hdr_als_name", &(info->hdr_als_name), ps, depth);
	prs_uint32("als_rid", ps, depth, &(info->als_rid));
	smb_io_bufhdr2("hdr_sec_desc", &(info->hdr_sec_desc), ps, depth);
	smb_io_unihdr ("hdr_als_desc", &(info->hdr_als_desc), ps, depth);
	ps->offset += 40;

	smb_io_unistr2("uni_als_name", &(info->uni_als_name),
		       info->hdr_als_name.buffer, ps, depth);
	smb_io_buffer4("buf_sec_desc", &(info->buf_sec_desc),
		       info->hdr_sec_desc.buffer, ps, depth);
	smb_io_unistr2("uni_als_desc", &(info->uni_als_desc),
		       info->hdr_als_name.buffer, ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_alias_mem_info(char *desc, SAM_ALIAS_MEM_INFO *info, prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_alias_mem_info");
	depth++;

	prs_align(ps);
	prs_uint32("num_members", ps, depth, &(info->num_members));
	prs_uint32("ptr_members", ps, depth, &(info->ptr_members));
	ps->offset += 16;

	if (info->ptr_members != 0)
	{
		prs_uint32("num_sids", ps, depth, &(info->num_sids));
		if (info->num_sids != info->num_members)
		{
			/* RPC fault */
			return False;
		}

		SMB_ASSERT_ARRAY(info->ptr_sids, info->num_sids);

		for (i = 0; i < info->num_sids; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "ptr_sids[%02d]", i);
			prs_uint32(tmp, ps, depth, &(info->ptr_sids[i]));
		}

		SMB_ASSERT_ARRAY(info->sids, info->num_sids);

		for (i = 0; i < info->num_sids; i++)
		{
			if (info->ptr_sids[i] != 0)
			{
				slprintf(tmp, sizeof(tmp) - 1, "sids[%02d]", i);
				smb_io_dom_sid2(tmp, &(info->sids[i]), ps, depth);
			}
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_delta_ctr(char *desc, uint8 sess_key[16],
				SAM_DELTA_CTR *delta, uint16 type,
				prs_struct *ps, int depth)
{
	if (delta == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_sam_delta_ctr");
	depth++;

	switch (type)
	{
		case 1:
		{
			net_io_sam_domain_info("", &(delta->domain_info),
			                           ps, depth);
			break;
		}
		case 2:
		{
			net_io_sam_group_info("", &(delta->group_info), 
			                           ps, depth);
			break;
		}
		case 5:
		{
			net_io_sam_account_info("", sess_key,
						&(delta->account_info), 
			                           ps, depth);
			break;
		}
		case 8:
		{
			net_io_sam_group_mem_info("", &(delta->grp_mem_info), 
			                           ps, depth);
			break;
		}
		case 9:
		{
			net_io_sam_alias_info("", &(delta->alias_info), 
			                           ps, depth);
			break;
		}
		case 0xC:
		{
			net_io_sam_alias_mem_info("", &(delta->als_mem_info), 
			                           ps, depth);
			break;
		}
		default:
		{
			DEBUG(0, ("Replication error: Unknown delta type %x\n", type));
			break;
		}
	}

	return True;
}

/*******************************************************************
makes a NET_R_SAM_SYNC structure.
********************************************************************/
BOOL make_r_sam_sync(NET_R_SAM_SYNC *r_s, 
			   const DOM_CRED *srv_cred,
			   uint32 sync_context,
			   uint32 num_deltas,
			   uint32 num_deltas2,
			   SAM_DELTA_HDR *hdr_deltas,
			   SAM_DELTA_CTR *deltas,
			   uint32 status)
{
	if (r_s == NULL) return False;

	memcpy(&(r_s->srv_creds), srv_cred, sizeof(r_s->srv_creds));
	r_s->sync_context = sync_context;
	r_s->num_deltas = num_deltas;
	r_s->num_deltas2 = num_deltas2;
	r_s->hdr_deltas = hdr_deltas;
	r_s->deltas = deltas;
	r_s->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_sam_sync(char *desc, uint8 sess_key[16],
				NET_R_SAM_SYNC *r_s, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_s == NULL) return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_sync");
	depth++;

	smb_io_cred("", &(r_s->srv_creds), ps, depth);
	prs_uint32("sync_context", ps, depth, &(r_s->sync_context));

	prs_uint32("ptr_deltas", ps, depth, &(r_s->ptr_deltas));
	if (r_s->ptr_deltas != 0)
	{
		prs_uint32("num_deltas ", ps, depth, &(r_s->num_deltas ));
		prs_uint32("ptr_deltas2", ps, depth, &(r_s->ptr_deltas2));
		if (r_s->ptr_deltas2 != 0)
		{
			prs_uint32("num_deltas2", ps, depth, &(r_s->num_deltas2));
			if (r_s->num_deltas2 != r_s->num_deltas)
			{
				/* RPC fault */
				return False;
			}

			for (i = 0; i < r_s->num_deltas2; i++)
			{
				net_io_sam_delta_hdr("", &r_s->hdr_deltas[i], ps, depth);
			}

			for (i = 0; i < r_s->num_deltas2; i++)
			{
				net_io_sam_delta_ctr("", sess_key,
				          &r_s->deltas[i],
				          r_s->hdr_deltas[i].type3, ps, depth);
			}
		}
	}

	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_s->status));

	return True;
}
