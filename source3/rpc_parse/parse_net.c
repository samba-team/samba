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
#include "nterr.h"

extern int DEBUGLEVEL;

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void net_io_neg_flags(char *desc,  NEG_FLAGS *neg, prs_struct *ps, int depth)
{
	if (neg == NULL) return;

	prs_debug(ps, depth, desc, "net_io_neg_flags");
	depth++;

	prs_align(ps);
	
	prs_uint32("neg_flags", ps, depth, &(neg->neg_flags));
}

/*******************************************************************
creates a NETLOGON_INFO_3 structure.
********************************************************************/
static void make_netinfo_3(NETLOGON_INFO_3 *info, uint32 flags, uint32 logon_attempts)
{
	info->flags          = flags;
	info->logon_attempts = logon_attempts;
	info->reserved_1     = 0x0;
	info->reserved_2     = 0x0;
	info->reserved_3     = 0x0;
	info->reserved_4     = 0x0;
	info->reserved_5     = 0x0;
}

/*******************************************************************
reads or writes a NETLOGON_INFO_3 structure.
********************************************************************/
static void net_io_netinfo_3(char *desc,  NETLOGON_INFO_3 *info, prs_struct *ps, int depth)
{
	if (info == NULL) return;

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
}


/*******************************************************************
creates a NETLOGON_INFO_1 structure.
********************************************************************/
static void make_netinfo_1(NETLOGON_INFO_1 *info, uint32 flags, uint32 pdc_status)
{
	info->flags      = flags;
	info->pdc_status = pdc_status;
}

/*******************************************************************
reads or writes a NETLOGON_INFO_1 structure.
********************************************************************/
static void net_io_netinfo_1(char *desc,  NETLOGON_INFO_1 *info, prs_struct *ps, int depth)
{
	if (info == NULL) return;

	prs_debug(ps, depth, desc, "net_io_netinfo_1");
	depth++;

	prs_align(ps);
	
	prs_uint32("flags     ", ps, depth, &(info->flags     ));
	prs_uint32("pdc_status", ps, depth, &(info->pdc_status));
}

/*******************************************************************
creates a NETLOGON_INFO_2 structure.
********************************************************************/
static void make_netinfo_2(NETLOGON_INFO_2 *info, uint32 flags, uint32 pdc_status,
				uint32 tc_status, char *trusted_dc_name)
{
	int len_dc_name = strlen(trusted_dc_name);
	info->flags      = flags;
	info->pdc_status = pdc_status;
	info->ptr_trusted_dc_name = 1;
	info->tc_status  = tc_status;

	if (trusted_dc_name != NULL)
	{
		make_unistr2(&(info->uni_trusted_dc_name), trusted_dc_name, len_dc_name+1);
	}
	else
	{
		make_unistr2(&(info->uni_trusted_dc_name), "", 1);
	}
}

/*******************************************************************
reads or writes a NETLOGON_INFO_2 structure.
********************************************************************/
static void net_io_netinfo_2(char *desc,  NETLOGON_INFO_2 *info, prs_struct *ps, int depth)
{
	if (info == NULL) return;

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
}

/*******************************************************************
reads or writes an NET_Q_LOGON_CTRL2 structure.
********************************************************************/
void net_io_q_logon_ctrl2(char *desc,  NET_Q_LOGON_CTRL2 *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return;

	prs_debug(ps, depth, desc, "net_io_q_logon_ctrl2");
	depth++;

	prs_align(ps);

	prs_uint32("ptr          ", ps, depth, &(q_l->ptr          ));

	smb_io_unistr2 ("", &(q_l->uni_server_name), q_l->ptr, ps, depth);

	prs_align(ps);

	prs_uint32("function_code", ps, depth, &(q_l->function_code));
	prs_uint32("query_level  ", ps, depth, &(q_l->query_level  ));
	prs_uint32("switch_value ", ps, depth, &(q_l->switch_value ));
}

/*******************************************************************
makes an NET_R_LOGON_CTRL2 structure.
********************************************************************/
void make_r_logon_ctrl2(NET_R_LOGON_CTRL2 *r_l, uint32 query_level,
				uint32 flags, uint32 pdc_status, uint32 logon_attempts,
				uint32 tc_status, char *trusted_domain_name)
{
	if (r_l == NULL) return;

	DEBUG(5,("make_r_logon_ctrl2\n"));

	r_l->switch_value  = query_level; /* should only be 0x1 */

	switch (query_level)
	{
		case 1:
		{
			r_l->ptr = 1; /* undocumented pointer */
			make_netinfo_1(&(r_l->logon.info1), flags, pdc_status);	
			r_l->status = 0;

			break;
		}
		case 2:
		{
			r_l->ptr = 1; /* undocumented pointer */
			make_netinfo_2(&(r_l->logon.info2), flags, pdc_status,
			               tc_status, trusted_domain_name);	
			r_l->status = 0;

			break;
		}
		case 3:
		{
			r_l->ptr = 1; /* undocumented pointer */
			make_netinfo_3(&(r_l->logon.info3), flags, logon_attempts);	
			r_l->status = 0;

			break;
		}
		default:
		{
			DEBUG(2,("make_r_logon_ctrl2: unsupported switch value %d\n",
				r_l->switch_value));
			r_l->ptr = 0; /* undocumented pointer */

			/* take a guess at an error code... */
			r_l->status = NT_STATUS_INVALID_INFO_CLASS;

			break;
		}
	}
}

/*******************************************************************
reads or writes an NET_R_LOGON_CTRL2 structure.
********************************************************************/
void net_io_r_logon_ctrl2(char *desc,  NET_R_LOGON_CTRL2 *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL) return;

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
}

/*******************************************************************
makes an NET_R_TRUST_DOM_LIST structure.
********************************************************************/
void make_r_trust_dom(NET_R_TRUST_DOM_LIST *r_t,
			uint32 num_doms, char *dom_name)
{
	int i = 0;

	if (r_t == NULL) return;

	DEBUG(5,("make_r_trust_dom\n"));

	for (i = 0; i < MAX_TRUST_DOMS; i++)
	{
		r_t->uni_trust_dom_name[i].uni_str_len = 0;
		r_t->uni_trust_dom_name[i].uni_max_len = 0;
	}
	if (num_doms > MAX_TRUST_DOMS) num_doms = MAX_TRUST_DOMS;

	for (i = 0; i < num_doms; i++)
	{
		fstring domain_name;
		fstrcpy(domain_name, dom_name);
		strupper(domain_name);
		make_unistr2(&(r_t->uni_trust_dom_name[i]), domain_name, strlen(domain_name)+1);
		/* the use of UNISTR2 here is non-standard. */
		r_t->uni_trust_dom_name[i].undoc = 0x1;
	}
	
	r_t->status = 0;
}

/*******************************************************************
reads or writes an NET_R_TRUST_DOM_LIST structure.
********************************************************************/
void net_io_r_trust_dom(char *desc,  NET_R_TRUST_DOM_LIST *r_t, prs_struct *ps, int depth)
{
	int i;
	if (r_t == NULL) return;

	prs_debug(ps, depth, desc, "net_io_r_trust_dom");
	depth++;

	for (i = 0; i < MAX_TRUST_DOMS; i++)
	{
		if (r_t->uni_trust_dom_name[i].uni_str_len == 0) break;
		smb_io_unistr2("", &(r_t->uni_trust_dom_name[i]), True, ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_t->status));
}


/*******************************************************************
reads or writes an NET_Q_TRUST_DOM_LIST structure.
********************************************************************/
void net_io_q_trust_dom(char *desc,  NET_Q_TRUST_DOM_LIST *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return;

	prs_debug(ps, depth, desc, "net_io_q_trust_dom");
	depth++;

	prs_uint32("ptr          ", ps, depth, &(q_l->ptr          ));
	smb_io_unistr2 ("", &(q_l->uni_server_name), q_l->ptr, ps, depth);

	prs_align(ps);

	prs_uint32("function_code", ps, depth, &(q_l->function_code));
}

/*******************************************************************
makes an NET_Q_REQ_CHAL structure.
********************************************************************/
void make_q_req_chal(NET_Q_REQ_CHAL *q_c,
				char *logon_srv, char *logon_clnt,
				DOM_CHAL *clnt_chal)
{
	if (q_c == NULL) return;

	DEBUG(5,("make_q_req_chal: %d\n", __LINE__));

	q_c->undoc_buffer = 1; /* don't know what this buffer is */

	make_unistr2(&(q_c->uni_logon_srv ), logon_srv , strlen(logon_srv )+1);
	make_unistr2(&(q_c->uni_logon_clnt), logon_clnt, strlen(logon_clnt)+1);

	memcpy(q_c->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));

	DEBUG(5,("make_q_req_chal: %d\n", __LINE__));
}

/*******************************************************************
reads or writes an NET_Q_REQ_CHAL structure.
********************************************************************/
void net_io_q_req_chal(char *desc,  NET_Q_REQ_CHAL *q_c, prs_struct *ps, int depth)
{
	int old_align;
	if (q_c == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_r_req_chal(char *desc,  NET_R_REQ_CHAL *r_c, prs_struct *ps, int depth)
{
	if (r_c == NULL) return;

	prs_debug(ps, depth, desc, "net_io_r_req_chal");
	depth++;

	prs_align(ps);
    
	smb_io_chal("", &(r_c->srv_chal), ps, depth); /* server challenge */

	prs_uint32("status", ps, depth, &(r_c->status));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_q_auth_2(NET_Q_AUTH_2 *q_a,
		const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name,
		DOM_CHAL *clnt_chal, uint32 clnt_flgs)
{
	if (q_a == NULL) return;

	DEBUG(5,("make_q_auth_2: %d\n", __LINE__));

	make_log_info(&(q_a->clnt_id), logon_srv, acct_name, sec_chan, comp_name);
	memcpy(q_a->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));
	q_a->clnt_flgs.neg_flags = clnt_flgs;

	DEBUG(5,("make_q_auth_2: %d\n", __LINE__));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_q_auth_2(char *desc,  NET_Q_AUTH_2 *q_a, prs_struct *ps, int depth)
{
	int old_align;
	if (q_a == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_r_auth_2(char *desc,  NET_R_AUTH_2 *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL) return;

	prs_debug(ps, depth, desc, "net_io_r_auth_2");
	depth++;

	prs_align(ps);
    
	smb_io_chal     ("", &(r_a->srv_chal), ps, depth); /* server challenge */
	net_io_neg_flags("", &(r_a->srv_flgs), ps, depth);

	prs_uint32("status", ps, depth, &(r_a->status));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void make_q_srv_pwset(NET_Q_SRV_PWSET *q_s, char *logon_srv, char *acct_name, 
                uint16 sec_chan, char *comp_name, DOM_CRED *cred, char nt_cypher[16])
{
	if (q_s == NULL || cred == NULL) return;

	DEBUG(5,("make_q_srv_pwset\n"));

	make_clnt_info(&(q_s->clnt_id), logon_srv, acct_name, sec_chan, comp_name, cred);

	memcpy(q_s->pwd, nt_cypher, sizeof(q_s->pwd)); 
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_q_srv_pwset(char *desc,  NET_Q_SRV_PWSET *q_s, prs_struct *ps, int depth)
{
	if (q_s == NULL) return;

	prs_debug(ps, depth, desc, "net_io_q_srv_pwset");
	depth++;

	prs_align(ps);
    
	smb_io_clnt_info("", &(q_s->clnt_id), ps, depth); /* client identification/authentication info */
	prs_uint8s (False, "pwd", ps, depth, q_s->pwd, 16); /* new password - undocumented */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_r_srv_pwset(char *desc,  NET_R_SRV_PWSET *r_s, prs_struct *ps, int depth)
{
	if (r_s == NULL) return;

	prs_debug(ps, depth, desc, "net_io_r_srv_pwset");
	depth++;

	prs_align(ps);
    
	smb_io_cred("", &(r_s->srv_cred), ps, depth); /* server challenge */

	prs_uint32("status", ps, depth, &(r_s->status));
}


/*************************************************************************
 make DOM_SID2 array from a string containing multiple sids
 *************************************************************************/
static int make_dom_sid2s(char *sids_str, DOM_SID2 *sids, int max_sids)
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
}

/*******************************************************************
makes a NET_ID_INFO_1 structure.
********************************************************************/
void make_id_info1(NET_ID_INFO_1 *id, char *domain_name,
				uint32 param_ctrl, uint32 log_id_low, uint32 log_id_high,
				char *user_name, char *wksta_name,
				char sess_key[16],
				unsigned char lm_cypher[16], unsigned char nt_cypher[16])
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );

	unsigned char lm_owf[16];
	unsigned char nt_owf[16];

	if (id == NULL) return;

	DEBUG(5,("make_id_info1: %d\n", __LINE__));

	id->ptr_id_info1 = 1;

	make_uni_hdr(&(id->hdr_domain_name), len_domain_name);

	id->param_ctrl = param_ctrl;
	make_logon_id(&(id->logon_id), log_id_low, log_id_high);

	make_uni_hdr(&(id->hdr_user_name  ), len_user_name  );
	make_uni_hdr(&(id->hdr_wksta_name ), len_wksta_name );

	if (lm_cypher && nt_cypher)
	{
		unsigned char key[16];
#ifdef DEBUG_PASSWORD
		DEBUG(100,("lm cypher:"));
		dump_data(100, lm_cypher, 16);

		DEBUG(100,("nt cypher:"));
		dump_data(100, nt_cypher, 16);
#endif

		memset(key, 0, 16);
		memcpy(key, sess_key, 8);

		memcpy(lm_owf, lm_cypher, 16);
		SamOEMhash(lm_owf, key, False);
		memcpy(nt_owf, nt_cypher, 16);
		SamOEMhash(nt_owf, key, False);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of lm owf password:"));
		dump_data(100, lm_owf, 16);

		DEBUG(100,("encrypt of nt owf password:"));
		dump_data(100, nt_owf, 16);
#endif
		/* set up pointers to cypher blocks */
		lm_cypher = lm_owf;
		nt_cypher = nt_owf;
	}

	make_owf_info(&(id->lm_owf), lm_cypher);
	make_owf_info(&(id->nt_owf), nt_cypher);

	make_unistr2(&(id->uni_domain_name), domain_name, len_domain_name);
	make_unistr2(&(id->uni_user_name  ), user_name  , len_user_name  );
	make_unistr2(&(id->uni_wksta_name ), wksta_name , len_wksta_name );
}

/*******************************************************************
reads or writes an NET_ID_INFO_1 structure.
********************************************************************/
static void net_io_id_info1(char *desc,  NET_ID_INFO_1 *id, prs_struct *ps, int depth)
{
	if (id == NULL) return;

	prs_debug(ps, depth, desc, "net_io_id_info1");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr_id_info1", ps, depth, &(id->ptr_id_info1));

	if (id->ptr_id_info1 != 0)
	{
		smb_io_unihdr("unihdr", &(id->hdr_domain_name), ps, depth);

		prs_uint32("param_ctrl", ps, depth, &(id->param_ctrl));
		smb_io_logon_id("", &(id->logon_id), ps, depth);

		smb_io_unihdr("unihdr", &(id->hdr_user_name  ), ps, depth);
		smb_io_unihdr("unihdr", &(id->hdr_wksta_name ), ps, depth);

		smb_io_owf_info("", &(id->lm_owf), ps, depth);
		smb_io_owf_info("", &(id->nt_owf), ps, depth);

		smb_io_unistr2("unistr2", &(id->uni_domain_name), id->hdr_domain_name.buffer, ps, depth);
		smb_io_unistr2("unistr2", &(id->uni_user_name  ), id->hdr_user_name.buffer, ps, depth);
		smb_io_unistr2("unistr2", &(id->uni_wksta_name ), id->hdr_wksta_name.buffer, ps, depth);
	}
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

void make_id_info2(NET_ID_INFO_2 *id, char *domain_name,
				uint32 param_ctrl, uint32 log_id_low, uint32 log_id_high,
				char *user_name, char *wksta_name,
				unsigned char lm_challenge[8],
				unsigned char lm_chal_resp[24],
				unsigned char nt_chal_resp[24])
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );
 	int nt_chal_resp_len = ((nt_chal_resp != NULL) ? 24 : 0);
	int lm_chal_resp_len = ((lm_chal_resp != NULL) ? 24 : 0);
	unsigned char lm_owf[24];
	unsigned char nt_owf[24];

	if (id == NULL) return;

	DEBUG(5,("make_id_info2: %d\n", __LINE__));

	id->ptr_id_info2 = 1;

	make_uni_hdr(&(id->hdr_domain_name), len_domain_name);

	id->param_ctrl = param_ctrl;
	make_logon_id(&(id->logon_id), log_id_low, log_id_high);

	make_uni_hdr(&(id->hdr_user_name  ), len_user_name  );
	make_uni_hdr(&(id->hdr_wksta_name ), len_wksta_name );

	if (nt_chal_resp)
	{
		/* oops.  can only send what-ever-it-is direct */
		memcpy(nt_owf, nt_chal_resp, 24);
		nt_chal_resp = nt_owf;
	}
	if (lm_chal_resp)
	{
		/* oops.  can only send what-ever-it-is direct */
		memcpy(lm_owf, lm_chal_resp, 24);
		lm_chal_resp = lm_owf;
	}

	memcpy(id->lm_chal, lm_challenge, sizeof(id->lm_chal));
	make_str_hdr(&(id->hdr_nt_chal_resp), 24, nt_chal_resp_len, nt_chal_resp != NULL ? 1 : 0);
	make_str_hdr(&(id->hdr_lm_chal_resp), 24, lm_chal_resp_len, lm_chal_resp != NULL ? 1 : 0);

	make_unistr2(&(id->uni_domain_name), domain_name, len_domain_name);
	make_unistr2(&(id->uni_user_name  ), user_name  , len_user_name  );
	make_unistr2(&(id->uni_wksta_name ), wksta_name , len_wksta_name );

	make_string2(&(id->nt_chal_resp ), (char *)nt_chal_resp , nt_chal_resp_len);
	make_string2(&(id->lm_chal_resp ), (char *)lm_chal_resp , lm_chal_resp_len);
}

/*******************************************************************
reads or writes an NET_ID_INFO_2 structure.
********************************************************************/
static void net_io_id_info2(char *desc,  NET_ID_INFO_2 *id, prs_struct *ps, int depth)
{
	if (id == NULL) return;

	prs_debug(ps, depth, desc, "net_io_id_info2");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr_id_info2", ps, depth, &(id->ptr_id_info2));

	if (id->ptr_id_info2 != 0)
	{
		smb_io_unihdr("unihdr", &(id->hdr_domain_name), ps, depth);

		prs_uint32("param_ctrl", ps, depth, &(id->param_ctrl));
		smb_io_logon_id("", &(id->logon_id), ps, depth);

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
}


/*******************************************************************
makes a DOM_SAM_INFO structure.
********************************************************************/
void make_sam_info(DOM_SAM_INFO *sam,
				char *logon_srv, char *comp_name, DOM_CRED *clnt_cred,
				DOM_CRED *rtn_cred, uint16 logon_level,
				NET_ID_INFO_CTR *ctr, uint16 validation_level)
{
	if (sam == NULL) return;

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
	sam->validation_level = validation_level;
}

/*******************************************************************
reads or writes a DOM_SAM_INFO structure.
********************************************************************/
static void net_io_id_info_ctr(char *desc,  NET_ID_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_sam_info");
	depth++;

	/* don't 4-byte align here! */

	prs_uint16("switch_value ", ps, depth, &(ctr->switch_value));

	switch (ctr->switch_value)
	{
		case 1:
		{
			net_io_id_info1("", &(ctr->auth.id1), ps, depth);
			break;
		}
		case 2:
		{
			net_io_id_info2("", &(ctr->auth.id2), ps, depth);
			break;
		}
		default:
		{
			/* PANIC! */
			DEBUG(4,("smb_io_sam_info: unknown switch_value!\n"));
			break;
		}
	}
}

/*******************************************************************
reads or writes a DOM_SAM_INFO structure.
********************************************************************/
static void smb_io_sam_info(char *desc,  DOM_SAM_INFO *sam, prs_struct *ps, int depth)
{
	if (sam == NULL) return;

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

	prs_uint16("validation_level", ps, depth, &(sam->validation_level));
}

/*************************************************************************
 make_net_user_info3
 *************************************************************************/
void make_net_user_info3(NET_USER_INFO_3 *usr,

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

	DOM_SID *dom_sid,
	char *other_sids)
{
	/* only cope with one "other" sid, right now. */
	/* need to count the number of space-delimited sids */
	int i;
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
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
static void net_io_user_info3(char *desc,  NET_USER_INFO_3 *usr, prs_struct *ps, int depth)
{
	int i;

	if (usr == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_q_sam_logon(char *desc,  NET_Q_SAM_LOGON *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return;

	prs_debug(ps, depth, desc, "net_io_q_sam_logon");
	depth++;

	prs_align(ps);
	
	smb_io_sam_info("", &(q_l->sam_id), ps, depth);           /* domain SID */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_r_sam_logon(char *desc,  NET_R_SAM_LOGON *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL) return;

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
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_q_sam_logoff(char *desc,  NET_Q_SAM_LOGOFF *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL) return;

	prs_debug(ps, depth, desc, "net_io_q_sam_logoff");
	depth++;

	prs_align(ps);
	
	smb_io_sam_info("", &(q_l->sam_id), ps, depth);           /* domain SID */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void net_io_r_sam_logoff(char *desc,  NET_R_SAM_LOGOFF *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL) return;

	prs_debug(ps, depth, desc, "net_io_r_sam_logoff");
	depth++;

	prs_align(ps);
	
	prs_uint32("buffer_creds", ps, depth, &(r_l->buffer_creds)); /* undocumented buffer pointer */
	smb_io_cred("", &(r_l->srv_creds), ps, depth); /* server credentials.  server time stamp appears to be ignored. */

	prs_uint32("status      ", ps, depth, &(r_l->status));
}


