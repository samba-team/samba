/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jean Francois Micouleau           2002.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool net_io_neg_flags(const char *desc, NEG_FLAGS *neg, prs_struct *ps, int depth)
{
	if (neg == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_neg_flags");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("neg_flags", ps, depth, &neg->neg_flags))
		return False;

	return True;
}

/*******************************************************************
 Inits an NET_Q_REQ_CHAL structure.
********************************************************************/

void init_q_req_chal(NET_Q_REQ_CHAL *q_c,
		     const char *logon_srv, const char *logon_clnt,
		     const DOM_CHAL *clnt_chal)
{
	DEBUG(5,("init_q_req_chal: %d\n", __LINE__));

	q_c->undoc_buffer = 1; /* don't know what this buffer is */

	init_unistr2(&q_c->uni_logon_srv, logon_srv , UNI_STR_TERMINATE);
	init_unistr2(&q_c->uni_logon_clnt, logon_clnt, UNI_STR_TERMINATE);

	memcpy(q_c->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));

	DEBUG(5,("init_q_req_chal: %d\n", __LINE__));
}

/*******************************************************************
 Reads or writes an NET_Q_REQ_CHAL structure.
********************************************************************/

bool net_io_q_req_chal(const char *desc,  NET_Q_REQ_CHAL *q_c, prs_struct *ps, int depth)
{
	if (q_c == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_req_chal");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!prs_uint32("undoc_buffer", ps, depth, &q_c->undoc_buffer))
		return False;

	if(!smb_io_unistr2("", &q_c->uni_logon_srv, True, ps, depth)) /* logon server unicode string */
		return False;
	if(!smb_io_unistr2("", &q_c->uni_logon_clnt, True, ps, depth)) /* logon client unicode string */
		return False;

	if(!smb_io_chal("", &q_c->clnt_chal, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_req_chal(const char *desc, NET_R_REQ_CHAL *r_c, prs_struct *ps, int depth)
{
	if (r_c == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_req_chal");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_chal("", &r_c->srv_chal, ps, depth)) /* server challenge */
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}


/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_auth(const char *desc, NET_Q_AUTH *q_a, prs_struct *ps, int depth)
{
	if (q_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_auth");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_log_info ("", &q_a->clnt_id, ps, depth)) /* client identification info */
		return False;
	if(!smb_io_chal("", &q_a->clnt_chal, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_auth(const char *desc, NET_R_AUTH *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_auth");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_chal("", &r_a->srv_chal, ps, depth)) /* server challenge */
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_a->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a NET_Q_AUTH_2 struct.
********************************************************************/

void init_q_auth_2(NET_Q_AUTH_2 *q_a,
		const char *logon_srv, const char *acct_name, uint16 sec_chan, const char *comp_name,
		const DOM_CHAL *clnt_chal, uint32 clnt_flgs)
{
	DEBUG(5,("init_q_auth_2: %d\n", __LINE__));

	init_log_info(&q_a->clnt_id, logon_srv, acct_name, sec_chan, comp_name);
	memcpy(q_a->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));
	q_a->clnt_flgs.neg_flags = clnt_flgs;

	DEBUG(5,("init_q_auth_2: %d\n", __LINE__));
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_auth_2(const char *desc, NET_Q_AUTH_2 *q_a, prs_struct *ps, int depth)
{
	if (q_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_auth_2");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_log_info ("", &q_a->clnt_id, ps, depth)) /* client identification info */
		return False;
	if(!smb_io_chal("", &q_a->clnt_chal, ps, depth))
		return False;
	if(!net_io_neg_flags("", &q_a->clnt_flgs, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_auth_2(const char *desc, NET_R_AUTH_2 *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_auth_2");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_chal("", &r_a->srv_chal, ps, depth)) /* server challenge */
		return False;
	if(!net_io_neg_flags("", &r_a->srv_flgs, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_a->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a NET_Q_AUTH_3 struct.
********************************************************************/

void init_q_auth_3(NET_Q_AUTH_3 *q_a,
		const char *logon_srv, const char *acct_name, uint16 sec_chan, const char *comp_name,
		const DOM_CHAL *clnt_chal, uint32 clnt_flgs)
{
	DEBUG(5,("init_q_auth_3: %d\n", __LINE__));

	init_log_info(&q_a->clnt_id, logon_srv, acct_name, sec_chan, comp_name);
	memcpy(q_a->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));
	q_a->clnt_flgs.neg_flags = clnt_flgs;

	DEBUG(5,("init_q_auth_3: %d\n", __LINE__));
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_auth_3(const char *desc, NET_Q_AUTH_3 *q_a, prs_struct *ps, int depth)
{
	if (q_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_auth_3");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_log_info ("", &q_a->clnt_id, ps, depth)) /* client identification info */
		return False;
	if(!smb_io_chal("", &q_a->clnt_chal, ps, depth))
		return False;
	if(!net_io_neg_flags("", &q_a->clnt_flgs, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_auth_3(const char *desc, NET_R_AUTH_3 *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_auth_3");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_chal("srv_chal", &r_a->srv_chal, ps, depth)) /* server challenge */
		return False;
	if(!net_io_neg_flags("srv_flgs", &r_a->srv_flgs, ps, depth))
		return False;
	if (!prs_uint32("unknown", ps, depth, &r_a->unknown))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_a->status))
		return False;

	return True;
}


/*******************************************************************
 Inits a NET_Q_SRV_PWSET.
********************************************************************/

void init_q_srv_pwset(NET_Q_SRV_PWSET *q_s,
		const char *logon_srv, const char *sess_key, const char *acct_name, 
                uint16 sec_chan, const char *comp_name,
		DOM_CRED *cred, const uchar hashed_mach_pwd[16])
{
	unsigned char nt_cypher[16];
	
	DEBUG(5,("init_q_srv_pwset\n"));
	
	/* Process the new password. */
	cred_hash3( nt_cypher, hashed_mach_pwd, (const unsigned char *)sess_key, 1);

	init_clnt_info(&q_s->clnt_id, logon_srv, acct_name, sec_chan, comp_name, cred);

	memcpy(q_s->pwd, nt_cypher, sizeof(q_s->pwd)); 
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_srv_pwset(const char *desc, NET_Q_SRV_PWSET *q_s, prs_struct *ps, int depth)
{
	if (q_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_srv_pwset");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_clnt_info("", &q_s->clnt_id, ps, depth)) /* client identification/authentication info */
		return False;
	if(!prs_uint8s (False, "pwd", ps, depth, q_s->pwd, 16)) /* new password - undocumented */
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_srv_pwset(const char *desc, NET_R_SRV_PWSET *r_s, prs_struct *ps, int depth)
{
	if (r_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_srv_pwset");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_cred("", &r_s->srv_cred, ps, depth)) /* server challenge */
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_s->status))
		return False;

	return True;
}

/*************************************************************************
 Init DOM_SID2 array from a string containing multiple sids
 *************************************************************************/

static int init_dom_sid2s(TALLOC_CTX *ctx, const char *sids_str, DOM_SID2 **ppsids)
{
	const char *ptr;
	char *s2;
	int count = 0;

	DEBUG(4,("init_dom_sid2s: %s\n", sids_str ? sids_str:""));

	*ppsids = NULL;

	if(sids_str) {
		int number;
		DOM_SID2 *sids;
		TALLOC_CTX *frame = talloc_stackframe();

		/* Count the number of valid SIDs. */
		for (count = 0, ptr = sids_str;
				next_token_talloc(frame,&ptr, &s2, NULL); ) {
			DOM_SID tmpsid;
			if (string_to_sid(&tmpsid, s2))
				count++;
		}

		/* Now allocate space for them. */
		if (count) {
			*ppsids = TALLOC_ZERO_ARRAY(ctx, DOM_SID2, count);
			if (*ppsids == NULL) {
				TALLOC_FREE(frame);
				return 0;
			}
		} else {
			*ppsids = NULL;
		}

		sids = *ppsids;

		for (number = 0, ptr = sids_str;
				next_token_talloc(frame, &ptr, &s2, NULL); ) {
			DOM_SID tmpsid;
			if (string_to_sid(&tmpsid, s2)) {
				/* count only valid sids */
				init_dom_sid2(&sids[number], &tmpsid);
				number++;
			}
		}
		TALLOC_FREE(frame);
	}

	return count;
}

/*******************************************************************
 Inits a NET_ID_INFO_1 structure.
********************************************************************/

void init_id_info1(NET_ID_INFO_1 *id, const char *domain_name,
				uint32 param_ctrl, uint32 log_id_low, uint32 log_id_high,
				const char *user_name, const char *wksta_name,
				const char *sess_key,
				unsigned char lm_cypher[16], unsigned char nt_cypher[16])
{
	unsigned char lm_owf[16];
	unsigned char nt_owf[16];

	DEBUG(5,("init_id_info1: %d\n", __LINE__));

	id->ptr_id_info1 = 1;

	id->param_ctrl = param_ctrl;
	init_logon_id(&id->logon_id, log_id_low, log_id_high);


	if (lm_cypher && nt_cypher) {
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
		SamOEMhash(lm_owf, key, 16);
		memcpy(nt_owf, nt_cypher, 16);
		SamOEMhash(nt_owf, key, 16);

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

	init_owf_info(&id->lm_owf, lm_cypher);
	init_owf_info(&id->nt_owf, nt_cypher);

	init_unistr2(&id->uni_domain_name, domain_name, UNI_FLAGS_NONE);
	init_uni_hdr(&id->hdr_domain_name, &id->uni_domain_name);
	init_unistr2(&id->uni_user_name, user_name, UNI_FLAGS_NONE);
	init_uni_hdr(&id->hdr_user_name, &id->uni_user_name);
	init_unistr2(&id->uni_wksta_name, wksta_name, UNI_FLAGS_NONE);
	init_uni_hdr(&id->hdr_wksta_name, &id->uni_wksta_name);
}

/*******************************************************************
 Reads or writes an NET_ID_INFO_1 structure.
********************************************************************/

static bool net_io_id_info1(const char *desc,  NET_ID_INFO_1 *id, prs_struct *ps, int depth)
{
	if (id == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_id_info1");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_id_info1", ps, depth, &id->ptr_id_info1))
		return False;

	if (id->ptr_id_info1 != 0) {
		if(!smb_io_unihdr("unihdr", &id->hdr_domain_name, ps, depth))
			return False;

		if(!prs_uint32("param_ctrl", ps, depth, &id->param_ctrl))
			return False;
		if(!smb_io_logon_id("", &id->logon_id, ps, depth))
			return False;

		if(!smb_io_unihdr("unihdr", &id->hdr_user_name, ps, depth))
			return False;
		if(!smb_io_unihdr("unihdr", &id->hdr_wksta_name, ps, depth))
			return False;

		if(!smb_io_owf_info("", &id->lm_owf, ps, depth))
			return False;
		if(!smb_io_owf_info("", &id->nt_owf, ps, depth))
			return False;

		if(!smb_io_unistr2("unistr2", &id->uni_domain_name,
				id->hdr_domain_name.buffer, ps, depth))
			return False;
		if(!smb_io_unistr2("unistr2", &id->uni_user_name,
				id->hdr_user_name.buffer, ps, depth))
			return False;
		if(!smb_io_unistr2("unistr2", &id->uni_wksta_name,
				id->hdr_wksta_name.buffer, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
Inits a NET_ID_INFO_2 structure.

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

void init_id_info2(NET_ID_INFO_2 * id, const char *domain_name,
		   uint32 param_ctrl,
		   uint32 log_id_low, uint32 log_id_high,
		   const char *user_name, const char *wksta_name,
		   const uchar lm_challenge[8],
		   const uchar * lm_chal_resp, size_t lm_chal_resp_len,
		   const uchar * nt_chal_resp, size_t nt_chal_resp_len)
{

	DEBUG(5,("init_id_info2: %d\n", __LINE__));

	id->ptr_id_info2 = 1;

	id->param_ctrl = param_ctrl;
	init_logon_id(&id->logon_id, log_id_low, log_id_high);

	memcpy(id->lm_chal, lm_challenge, sizeof(id->lm_chal));
	init_str_hdr(&id->hdr_nt_chal_resp, nt_chal_resp_len, nt_chal_resp_len, (nt_chal_resp != NULL) ? 1 : 0);
	init_str_hdr(&id->hdr_lm_chal_resp, lm_chal_resp_len, lm_chal_resp_len, (lm_chal_resp != NULL) ? 1 : 0);

	init_unistr2(&id->uni_domain_name, domain_name, UNI_FLAGS_NONE);
	init_uni_hdr(&id->hdr_domain_name, &id->uni_domain_name);
	init_unistr2(&id->uni_user_name, user_name, UNI_FLAGS_NONE);
	init_uni_hdr(&id->hdr_user_name, &id->uni_user_name);
	init_unistr2(&id->uni_wksta_name, wksta_name, UNI_FLAGS_NONE);
	init_uni_hdr(&id->hdr_wksta_name, &id->uni_wksta_name);

	init_string2(&id->nt_chal_resp, (const char *)nt_chal_resp, nt_chal_resp_len, nt_chal_resp_len);
	init_string2(&id->lm_chal_resp, (const char *)lm_chal_resp, lm_chal_resp_len, lm_chal_resp_len);

}

/*******************************************************************
 Reads or writes an NET_ID_INFO_2 structure.
********************************************************************/

static bool net_io_id_info2(const char *desc,  NET_ID_INFO_2 *id, prs_struct *ps, int depth)
{
	if (id == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_id_info2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_id_info2", ps, depth, &id->ptr_id_info2))
		return False;

	if (id->ptr_id_info2 != 0) {
		if(!smb_io_unihdr("unihdr", &id->hdr_domain_name, ps, depth))
			return False;

		if(!prs_uint32("param_ctrl", ps, depth, &id->param_ctrl))
			return False;
		if(!smb_io_logon_id("", &id->logon_id, ps, depth))
			return False;

		if(!smb_io_unihdr("unihdr", &id->hdr_user_name, ps, depth))
			return False;
		if(!smb_io_unihdr("unihdr", &id->hdr_wksta_name, ps, depth))
			return False;

		if(!prs_uint8s (False, "lm_chal", ps, depth, id->lm_chal, 8)) /* lm 8 byte challenge */
			return False;

		if(!smb_io_strhdr("hdr_nt_chal_resp", &id->hdr_nt_chal_resp, ps, depth))
			return False;
		if(!smb_io_strhdr("hdr_lm_chal_resp", &id->hdr_lm_chal_resp, ps, depth))
			return False;

		if(!smb_io_unistr2("uni_domain_name", &id->uni_domain_name,
				id->hdr_domain_name.buffer, ps, depth))
			return False;
		if(!smb_io_unistr2("uni_user_name  ", &id->uni_user_name,
				id->hdr_user_name.buffer, ps, depth))
			return False;
		if(!smb_io_unistr2("uni_wksta_name ", &id->uni_wksta_name,
				id->hdr_wksta_name.buffer, ps, depth))
			return False;
		if(!smb_io_string2("nt_chal_resp", &id->nt_chal_resp,
				id->hdr_nt_chal_resp.buffer, ps, depth))
			return False;
		if(!smb_io_string2("lm_chal_resp", &id->lm_chal_resp,
				id->hdr_lm_chal_resp.buffer, ps, depth))
			return False;
	}

	return True;
}


/*******************************************************************
 Inits a DOM_SAM_INFO structure.
********************************************************************/

void init_sam_info(DOM_SAM_INFO *sam,
				const char *logon_srv, const char *comp_name,
				DOM_CRED *clnt_cred,
				DOM_CRED *rtn_cred, uint16 logon_level,
				NET_ID_INFO_CTR *ctr)
{
	DEBUG(5,("init_sam_info: %d\n", __LINE__));

	init_clnt_info2(&sam->client, logon_srv, comp_name, clnt_cred);

	if (rtn_cred != NULL) {
		sam->ptr_rtn_cred = 1;
		memcpy(&sam->rtn_cred, rtn_cred, sizeof(sam->rtn_cred));
	} else {
		sam->ptr_rtn_cred = 0;
	}

	sam->logon_level  = logon_level;
	sam->ctr          = ctr;
}

/*******************************************************************
 Inits a DOM_SAM_INFO structure.
********************************************************************/

void init_sam_info_ex(DOM_SAM_INFO_EX *sam,
		      const char *logon_srv, const char *comp_name,
		      uint16 logon_level, NET_ID_INFO_CTR *ctr)
{
	DEBUG(5,("init_sam_info_ex: %d\n", __LINE__));

	init_clnt_srv(&sam->client, logon_srv, comp_name);
	sam->logon_level  = logon_level;
	sam->ctr          = ctr;
}

/*******************************************************************
 Reads or writes a DOM_SAM_INFO structure.
********************************************************************/

static bool net_io_id_info_ctr(const char *desc, NET_ID_INFO_CTR **pp_ctr, prs_struct *ps, int depth)
{
	NET_ID_INFO_CTR *ctr = *pp_ctr;

	prs_debug(ps, depth, desc, "smb_io_sam_info_ctr");
	depth++;

	if (UNMARSHALLING(ps)) {
		ctr = *pp_ctr = PRS_ALLOC_MEM(ps, NET_ID_INFO_CTR, 1);
		if (ctr == NULL)
			return False;
	}
	
	if (ctr == NULL)
		return False;

	/* don't 4-byte align here! */

	if(!prs_uint16("switch_value ", ps, depth, &ctr->switch_value))
		return False;

	switch (ctr->switch_value) {
	case 1:
		if(!net_io_id_info1("", &ctr->auth.id1, ps, depth))
			return False;
		break;
	case 2:
		if(!net_io_id_info2("", &ctr->auth.id2, ps, depth))
			return False;
		break;
	default:
		/* PANIC! */
		DEBUG(4,("smb_io_sam_info_ctr: unknown switch_value!\n"));
		break;
	}

	return True;
}

/*******************************************************************
 Reads or writes a DOM_SAM_INFO structure.
 ********************************************************************/

static bool smb_io_sam_info(const char *desc, DOM_SAM_INFO *sam, prs_struct *ps, int depth)
{
	if (sam == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_sam_info");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_clnt_info2("", &sam->client, ps, depth))
		return False;

	if(!prs_uint32("ptr_rtn_cred ", ps, depth, &sam->ptr_rtn_cred))
		return False;
	if (sam->ptr_rtn_cred) {
		if(!smb_io_cred("", &sam->rtn_cred, ps, depth))
			return False;
	}

	if(!prs_uint16("logon_level  ", ps, depth, &sam->logon_level))
		return False;

	if (sam->logon_level != 0) {
		if(!net_io_id_info_ctr("logon_info", &sam->ctr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
 Reads or writes a DOM_SAM_INFO_EX structure.
 ********************************************************************/

static bool smb_io_sam_info_ex(const char *desc, DOM_SAM_INFO_EX *sam, prs_struct *ps, int depth)
{
	if (sam == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_sam_info_ex");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_clnt_srv("", &sam->client, ps, depth))
		return False;

	if(!prs_uint16("logon_level  ", ps, depth, &sam->logon_level))
		return False;

	if (sam->logon_level != 0) {
		if(!net_io_id_info_ctr("logon_info", &sam->ctr, ps, depth))
			return False;
	}

	return True;
}

/*************************************************************************
 Inits a NET_USER_INFO_3 structure.

 This is a network logon reply packet, and contains much information about
 the user.  This information is passed as a (very long) paramater list
 to avoid having to link in the PASSDB code to every program that deals 
 with this file.
 *************************************************************************/

void init_net_user_info3(TALLOC_CTX *ctx, NET_USER_INFO_3 *usr, 
			 uint32                user_rid,
			 uint32                group_rid,

			 const char*		user_name,
			 const char*		full_name,
			 const char*		home_dir,
			 const char*		dir_drive,
			 const char*		logon_script,
			 const char*		profile_path,

			 time_t unix_logon_time,
			 time_t unix_logoff_time,
			 time_t unix_kickoff_time,
			 time_t unix_pass_last_set_time,
			 time_t unix_pass_can_change_time,
			 time_t unix_pass_must_change_time,
			 
			 uint16 logon_count, uint16 bad_pw_count,
 		 	 uint32 num_groups, const DOM_GID *gids,
			 uint32 user_flgs, uint32 acct_flags,
			 uchar user_session_key[16],
			 uchar lm_session_key[16],
 			 const char *logon_srv, const char *logon_dom,
			 const DOM_SID *dom_sid)
{
	/* only cope with one "other" sid, right now. */
	/* need to count the number of space-delimited sids */
	unsigned int i;
	int num_other_sids = 0;
	
	NTTIME 		logon_time, logoff_time, kickoff_time,
			pass_last_set_time, pass_can_change_time,
			pass_must_change_time;

	ZERO_STRUCTP(usr);

	usr->ptr_user_info = 1; /* yes, we're bothering to put USER_INFO data here */

	/* Create NTTIME structs */
	unix_to_nt_time (&logon_time, 		 unix_logon_time);
	unix_to_nt_time (&logoff_time, 		 unix_logoff_time);
	unix_to_nt_time (&kickoff_time, 	 unix_kickoff_time);
	unix_to_nt_time (&pass_last_set_time, 	 unix_pass_last_set_time);
	unix_to_nt_time (&pass_can_change_time,	 unix_pass_can_change_time);
	unix_to_nt_time (&pass_must_change_time, unix_pass_must_change_time);

	usr->logon_time            = logon_time;
	usr->logoff_time           = logoff_time;
	usr->kickoff_time          = kickoff_time;
	usr->pass_last_set_time    = pass_last_set_time;
	usr->pass_can_change_time  = pass_can_change_time;
	usr->pass_must_change_time = pass_must_change_time;

	usr->logon_count = logon_count;
	usr->bad_pw_count = bad_pw_count;

	usr->user_rid = user_rid;
	usr->group_rid = group_rid;
	usr->num_groups = num_groups;

	usr->buffer_groups = 1; /* indicates fill in groups, below, even if there are none */
	usr->user_flgs = user_flgs;
	usr->acct_flags = acct_flags;

	if (user_session_key != NULL)
		memcpy(usr->user_sess_key, user_session_key, sizeof(usr->user_sess_key));
	else
		memset((char *)usr->user_sess_key, '\0', sizeof(usr->user_sess_key));

	usr->buffer_dom_id = dom_sid ? 1 : 0; /* yes, we're bothering to put a domain SID in */

	memset((char *)usr->lm_sess_key, '\0', sizeof(usr->lm_sess_key));

	for (i=0; i<7; i++) {
		memset(&usr->unknown[i], '\0', sizeof(usr->unknown));
	}

	if (lm_session_key != NULL) {
		memcpy(usr->lm_sess_key, lm_session_key, sizeof(usr->lm_sess_key));
	}

	num_other_sids = init_dom_sid2s(ctx, NULL, &usr->other_sids);

	usr->num_other_sids = num_other_sids;
	usr->buffer_other_sids = (num_other_sids != 0) ? 1 : 0; 
	
	init_unistr2(&usr->uni_user_name, user_name, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_user_name, &usr->uni_user_name);
	init_unistr2(&usr->uni_full_name, full_name, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_full_name, &usr->uni_full_name);
	init_unistr2(&usr->uni_logon_script, logon_script, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_logon_script, &usr->uni_logon_script);
	init_unistr2(&usr->uni_profile_path, profile_path, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_profile_path, &usr->uni_profile_path);
	init_unistr2(&usr->uni_home_dir, home_dir, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_home_dir, &usr->uni_home_dir);
	init_unistr2(&usr->uni_dir_drive, dir_drive, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_dir_drive, &usr->uni_dir_drive);

	usr->num_groups2 = num_groups;

	if (num_groups) {
		usr->gids = TALLOC_ZERO_ARRAY(ctx,DOM_GID,num_groups);
		if (usr->gids == NULL)
	 		return;
	} else {
		usr->gids = NULL;
	}

	for (i = 0; i < num_groups; i++) 
		usr->gids[i] = gids[i];	
		
	init_unistr2(&usr->uni_logon_srv, logon_srv, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_logon_srv, &usr->uni_logon_srv);
	init_unistr2(&usr->uni_logon_dom, logon_dom, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_logon_dom, &usr->uni_logon_dom);

	init_dom_sid2(&usr->dom_sid, dom_sid);
	/* "other" sids are set up above */
}

static void dump_acct_flags(uint32 acct_flags) {

	int lvl = 10;
	DEBUG(lvl,("dump_acct_flags\n"));
	if (acct_flags & ACB_NORMAL) {
		DEBUGADD(lvl,("\taccount has ACB_NORMAL\n"));
	}
	if (acct_flags & ACB_PWNOEXP) {
		DEBUGADD(lvl,("\taccount has ACB_PWNOEXP\n"));
	}
	if (acct_flags & ACB_ENC_TXT_PWD_ALLOWED) {
		DEBUGADD(lvl,("\taccount has ACB_ENC_TXT_PWD_ALLOWED\n"));
	}
	if (acct_flags & ACB_NOT_DELEGATED) {
		DEBUGADD(lvl,("\taccount has ACB_NOT_DELEGATED\n"));
	}
	if (acct_flags & ACB_USE_DES_KEY_ONLY) {
		DEBUGADD(lvl,("\taccount has ACB_USE_DES_KEY_ONLY set, sig verify wont work\n"));
	}
	if (acct_flags & ACB_NO_AUTH_DATA_REQD) {
		DEBUGADD(lvl,("\taccount has ACB_NO_AUTH_DATA_REQD set\n"));
	}
	if (acct_flags & ACB_PW_EXPIRED) {
		DEBUGADD(lvl,("\taccount has ACB_PW_EXPIRED set\n"));
	}
}

static void dump_user_flgs(uint32 user_flags) {

	int lvl = 10;
	DEBUG(lvl,("dump_user_flgs\n"));
	if (user_flags & NETLOGON_EXTRA_SIDS) {
		DEBUGADD(lvl,("\taccount has NETLOGON_EXTRA_SIDS\n"));
	}
	if (user_flags & NETLOGON_RESOURCE_GROUPS) {
		DEBUGADD(lvl,("\taccount has NETLOGON_RESOURCE_GROUPS\n"));
	}
	if (user_flags & NETLOGON_NTLMV2_ENABLED) {
		DEBUGADD(lvl,("\taccount has NETLOGON_NTLMV2_ENABLED\n"));
	}
	if (user_flags & NETLOGON_CACHED_ACCOUNT) {
		DEBUGADD(lvl,("\taccount has NETLOGON_CACHED_ACCOUNT\n"));
	}
	if (user_flags & NETLOGON_PROFILE_PATH_RETURNED) {
		DEBUGADD(lvl,("\taccount has NETLOGON_PROFILE_PATH_RETURNED\n"));
	}
	if (user_flags & NETLOGON_SERVER_TRUST_ACCOUNT) {
		DEBUGADD(lvl,("\taccount has NETLOGON_SERVER_TRUST_ACCOUNT\n"));
	}


}

/*******************************************************************
 This code has been modified to cope with a NET_USER_INFO_2 - which is
 exactly the same as a NET_USER_INFO_3, minus the other sids parameters.
 We use validation level to determine if we're marshalling a info 2 or
 INFO_3 - be we always return an INFO_3. Based on code donated by Marc
 Jacobsen at HP. JRA.
********************************************************************/

bool net_io_user_info3(const char *desc, NET_USER_INFO_3 *usr, prs_struct *ps, 
		       int depth, uint16 validation_level, bool kerb_validation_level)
{
	unsigned int i;

	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_user_info3");
	depth++;

	if (UNMARSHALLING(ps))
		ZERO_STRUCTP(usr);

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_user_info ", ps, depth, &usr->ptr_user_info))
		return False;

	if (usr->ptr_user_info == 0)
		return True;

	if(!smb_io_time("logon time", &usr->logon_time, ps, depth)) /* logon time */
		return False;
	if(!smb_io_time("logoff time", &usr->logoff_time, ps, depth)) /* logoff time */
		return False;
	if(!smb_io_time("kickoff time", &usr->kickoff_time, ps, depth)) /* kickoff time */
		return False;
	if(!smb_io_time("last set time", &usr->pass_last_set_time, ps, depth)) /* password last set time */
		return False;
	if(!smb_io_time("can change time", &usr->pass_can_change_time , ps, depth)) /* password can change time */
		return False;
	if(!smb_io_time("must change time", &usr->pass_must_change_time, ps, depth)) /* password must change time */
		return False;

	if(!smb_io_unihdr("hdr_user_name", &usr->hdr_user_name, ps, depth)) /* username unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_full_name", &usr->hdr_full_name, ps, depth)) /* user's full name unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_logon_script", &usr->hdr_logon_script, ps, depth)) /* logon script unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_profile_path", &usr->hdr_profile_path, ps, depth)) /* profile path unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_home_dir", &usr->hdr_home_dir, ps, depth)) /* home directory unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_dir_drive", &usr->hdr_dir_drive, ps, depth)) /* home directory drive unicode string header */
		return False;

	if(!prs_uint16("logon_count   ", ps, depth, &usr->logon_count))  /* logon count */
		return False;
	if(!prs_uint16("bad_pw_count  ", ps, depth, &usr->bad_pw_count)) /* bad password count */
		return False;

	if(!prs_uint32("user_rid      ", ps, depth, &usr->user_rid))       /* User RID */
		return False;
	if(!prs_uint32("group_rid     ", ps, depth, &usr->group_rid))      /* Group RID */
		return False;
	if(!prs_uint32("num_groups    ", ps, depth, &usr->num_groups))    /* num groups */
		return False;
	if(!prs_uint32("buffer_groups ", ps, depth, &usr->buffer_groups)) /* undocumented buffer pointer to groups. */
		return False;
	if(!prs_uint32("user_flgs     ", ps, depth, &usr->user_flgs))     /* user flags */
		return False;
	dump_user_flgs(usr->user_flgs);
	if(!prs_uint8s(False, "user_sess_key", ps, depth, usr->user_sess_key, 16)) /* user session key */
		return False;

	if(!smb_io_unihdr("hdr_logon_srv", &usr->hdr_logon_srv, ps, depth)) /* logon server unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_logon_dom", &usr->hdr_logon_dom, ps, depth)) /* logon domain unicode string header */
		return False;

	if(!prs_uint32("buffer_dom_id ", ps, depth, &usr->buffer_dom_id)) /* undocumented logon domain id pointer */
		return False;

	if(!prs_uint8s(False, "lm_sess_key", ps, depth, usr->lm_sess_key, 8)) /* lm session key */
		return False;

	if(!prs_uint32("acct_flags ", ps, depth, &usr->acct_flags)) /* Account flags  */
		return False;
	dump_acct_flags(usr->acct_flags);
	for (i = 0; i < 7; i++)
	{
		if (!prs_uint32("unkown", ps, depth, &usr->unknown[i])) /* unknown */
                        return False;
	}

	if (validation_level == 3) {
		if(!prs_uint32("num_other_sids", ps, depth, &usr->num_other_sids)) /* 0 - num_sids */
			return False;
		if(!prs_uint32("buffer_other_sids", ps, depth, &usr->buffer_other_sids)) /* NULL - undocumented pointer to SIDs. */
			return False;
	} else {
		if (UNMARSHALLING(ps)) {
			usr->num_other_sids = 0;
			usr->buffer_other_sids = 0;
		}
	}
		
	/* get kerb validation info (not really part of user_info_3) - Guenther */

	if (kerb_validation_level) {

		if(!prs_uint32("ptr_res_group_dom_sid", ps, depth, &usr->ptr_res_group_dom_sid))
			return False;
		if(!prs_uint32("res_group_count", ps, depth, &usr->res_group_count))
			return False;
		if(!prs_uint32("ptr_res_groups", ps, depth, &usr->ptr_res_groups))
			return False;
	}

	if(!smb_io_unistr2("uni_user_name", &usr->uni_user_name, usr->hdr_user_name.buffer, ps, depth)) /* username unicode string */
		return False;
	if(!smb_io_unistr2("uni_full_name", &usr->uni_full_name, usr->hdr_full_name.buffer, ps, depth)) /* user's full name unicode string */
		return False;
	if(!smb_io_unistr2("uni_logon_script", &usr->uni_logon_script, usr->hdr_logon_script.buffer, ps, depth)) /* logon script unicode string */
		return False;
	if(!smb_io_unistr2("uni_profile_path", &usr->uni_profile_path, usr->hdr_profile_path.buffer, ps, depth)) /* profile path unicode string */
		return False;
	if(!smb_io_unistr2("uni_home_dir", &usr->uni_home_dir, usr->hdr_home_dir.buffer, ps, depth)) /* home directory unicode string */
		return False;
	if(!smb_io_unistr2("uni_dir_drive", &usr->uni_dir_drive, usr->hdr_dir_drive.buffer, ps, depth)) /* home directory drive unicode string */
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_groups2   ", ps, depth, &usr->num_groups2))        /* num groups2 */
		return False;

	if (usr->num_groups != usr->num_groups2) {
		DEBUG(3,("net_io_user_info3: num_groups mismatch! (%d != %d)\n", 
			 usr->num_groups, usr->num_groups2));
		return False;
	}

	if (UNMARSHALLING(ps)) {
		if (usr->num_groups) {
			usr->gids = PRS_ALLOC_MEM(ps, DOM_GID, usr->num_groups);
			if (usr->gids == NULL)
				return False;
		} else {
			usr->gids = NULL;
		}
	}

	for (i = 0; i < usr->num_groups; i++) {
		if(!smb_io_gid("", &usr->gids[i], ps, depth)) /* group info */
			return False;
	}

	if(!smb_io_unistr2("uni_logon_srv", &usr->uni_logon_srv, usr->hdr_logon_srv.buffer, ps, depth)) /* logon server unicode string */
		return False;
	if(!smb_io_unistr2("uni_logon_dom", &usr->uni_logon_dom, usr->hdr_logon_dom.buffer, ps, depth)) /* logon domain unicode string */
		return False;

	if(!smb_io_dom_sid2("", &usr->dom_sid, ps, depth))           /* domain SID */
		return False;

	if (validation_level == 3 && usr->buffer_other_sids) {

		uint32 num_other_sids = usr->num_other_sids;

		if (!(usr->user_flgs & NETLOGON_EXTRA_SIDS)) {
			DEBUG(10,("net_io_user_info3: user_flgs attribute does not have NETLOGON_EXTRA_SIDS\n"));
			/* return False; */
		}

		if (!prs_uint32("num_other_sids", ps, depth,
				&num_other_sids))
			return False;

		if (num_other_sids != usr->num_other_sids)
			return False;

		if (UNMARSHALLING(ps)) {
			if (usr->num_other_sids) {
				usr->other_sids = PRS_ALLOC_MEM(ps, DOM_SID2, usr->num_other_sids);
				usr->other_sids_attrib =
					PRS_ALLOC_MEM(ps, uint32, usr->num_other_sids);
			} else {
				usr->other_sids = NULL;
				usr->other_sids_attrib = NULL;
			}

			if ((num_other_sids != 0) &&
			    ((usr->other_sids == NULL) ||
			     (usr->other_sids_attrib == NULL)))
				return False;
		}

		/* First the pointers to the SIDS and attributes */

		depth++;

		for (i=0; i<usr->num_other_sids; i++) {
			uint32 ptr = 1;

			if (!prs_uint32("sid_ptr", ps, depth, &ptr))
				return False;

			if (UNMARSHALLING(ps) && (ptr == 0))
				return False;

			if (!prs_uint32("attribute", ps, depth,
					&usr->other_sids_attrib[i]))
				return False;
		}
	
		for (i = 0; i < usr->num_other_sids; i++) {
			if(!smb_io_dom_sid2("", &usr->other_sids[i], ps, depth)) /* other domain SIDs */
				return False;
		}

		depth--;
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_sam_logon(const char *desc, NET_Q_SAM_LOGON *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_logon");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_sam_info("", &q_l->sam_id, ps, depth))
		return False;

	if(!prs_align_uint16(ps))
		return False;

	if(!prs_uint16("validation_level", ps, depth, &q_l->validation_level))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_sam_logon(const char *desc, NET_R_SAM_LOGON *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_logon");
	depth++;

	if(!prs_uint32("buffer_creds", ps, depth, &r_l->buffer_creds)) /* undocumented buffer pointer */
		return False;
	if (&r_l->buffer_creds) {
		if(!smb_io_cred("", &r_l->srv_creds, ps, depth)) /* server credentials.  server time stamp appears to be ignored. */
			return False;
	}

	if(!prs_uint16("switch_value", ps, depth, &r_l->switch_value))
		return False;
	if(!prs_align(ps))
		return False;

#if 1 /* W2k always needs this - even for bad passwd. JRA */
	if(!net_io_user_info3("", r_l->user, ps, depth, r_l->switch_value, False))
		return False;
#else
	if (r_l->switch_value != 0) {
		if(!net_io_user_info3("", r_l->user, ps, depth, r_l->switch_value, False))
			return False;
	}
#endif

	if(!prs_uint32("auth_resp   ", ps, depth, &r_l->auth_resp)) /* 1 - Authoritative response; 0 - Non-Auth? */
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_l->status))
		return False;

	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_sam_logon_ex(const char *desc, NET_Q_SAM_LOGON_EX *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_logon_ex");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_sam_info_ex("", &q_l->sam_id, ps, depth))
		return False;

	if(!prs_align_uint16(ps))
		return False;

	if(!prs_uint16("validation_level", ps, depth, &q_l->validation_level))
		return False;

	if (!prs_align(ps))
		return False;

	if(!prs_uint32("flags  ", ps, depth, &q_l->flags))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_sam_logon_ex(const char *desc, NET_R_SAM_LOGON_EX *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_logon_ex");
	depth++;

	if(!prs_uint16("switch_value", ps, depth, &r_l->switch_value))
		return False;
	if(!prs_align(ps))
		return False;

#if 1 /* W2k always needs this - even for bad passwd. JRA */
	if(!net_io_user_info3("", r_l->user, ps, depth, r_l->switch_value, False))
		return False;
#else
	if (r_l->switch_value != 0) {
		if(!net_io_user_info3("", r_l->user, ps, depth, r_l->switch_value, False))
			return False;
	}
#endif

	if(!prs_uint32("auth_resp   ", ps, depth, &r_l->auth_resp)) /* 1 - Authoritative response; 0 - Non-Auth? */
		return False;

	if(!prs_uint32("flags   ", ps, depth, &r_l->flags))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_l->status))
		return False;

	if(!prs_align(ps))
		return False;

	return True;
}
