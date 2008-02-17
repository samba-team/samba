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
