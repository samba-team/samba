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

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static BOOL net_io_neg_flags(const char *desc, NEG_FLAGS *neg, prs_struct *ps, int depth)
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
 Inits a NETLOGON_INFO_3 structure.
********************************************************************/

static void init_netinfo_3(NETLOGON_INFO_3 *info, uint32 flags, uint32 logon_attempts)
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
 Reads or writes a NETLOGON_INFO_3 structure.
********************************************************************/

static BOOL net_io_netinfo_3(const char *desc,  NETLOGON_INFO_3 *info, prs_struct *ps, int depth)
{
	if (info == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_netinfo_3");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("flags         ", ps, depth, &info->flags))
		return False;
	if(!prs_uint32("logon_attempts", ps, depth, &info->logon_attempts))
		return False;
	if(!prs_uint32("reserved_1    ", ps, depth, &info->reserved_1))
		return False;
	if(!prs_uint32("reserved_2    ", ps, depth, &info->reserved_2))
		return False;
	if(!prs_uint32("reserved_3    ", ps, depth, &info->reserved_3))
		return False;
	if(!prs_uint32("reserved_4    ", ps, depth, &info->reserved_4))
		return False;
	if(!prs_uint32("reserved_5    ", ps, depth, &info->reserved_5))
		return False;

	return True;
}


/*******************************************************************
 Inits a NETLOGON_INFO_1 structure.
********************************************************************/

static void init_netinfo_1(NETLOGON_INFO_1 *info, uint32 flags, uint32 pdc_status)
{
	info->flags      = flags;
	info->pdc_status = pdc_status;
}

/*******************************************************************
 Reads or writes a NETLOGON_INFO_1 structure.
********************************************************************/

static BOOL net_io_netinfo_1(const char *desc, NETLOGON_INFO_1 *info, prs_struct *ps, int depth)
{
	if (info == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_netinfo_1");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("flags     ", ps, depth, &info->flags))
		return False;
	if(!prs_uint32("pdc_status", ps, depth, &info->pdc_status))
		return False;

	return True;
}

/*******************************************************************
 Inits a NETLOGON_INFO_2 structure.
********************************************************************/

static void init_netinfo_2(NETLOGON_INFO_2 *info, uint32 flags, uint32 pdc_status,
				uint32 tc_status, const char *trusted_dc_name)
{
	int len_dc_name = strlen(trusted_dc_name);
	info->flags      = flags;
	info->pdc_status = pdc_status;
	info->ptr_trusted_dc_name = 1;
	info->tc_status  = tc_status;

	if (trusted_dc_name != NULL)
		init_unistr2(&info->uni_trusted_dc_name, trusted_dc_name, len_dc_name+1);
	else
		init_unistr2(&info->uni_trusted_dc_name, "", 1);
}

/*******************************************************************
 Reads or writes a NETLOGON_INFO_2 structure.
********************************************************************/

static BOOL net_io_netinfo_2(const char *desc, NETLOGON_INFO_2 *info, prs_struct *ps, int depth)
{
	if (info == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_netinfo_2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("flags              ", ps, depth, &info->flags))
		return False;
	if(!prs_uint32("pdc_status         ", ps, depth, &info->pdc_status))
		return False;
	if(!prs_uint32("ptr_trusted_dc_name", ps, depth, &info->ptr_trusted_dc_name))
		return False;
	if(!prs_uint32("tc_status          ", ps, depth, &info->tc_status))
		return False;

	if (info->ptr_trusted_dc_name != 0) {
		if(!smb_io_unistr2("unistr2", &info->uni_trusted_dc_name, info->ptr_trusted_dc_name, ps, depth))
			return False;
	}

	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an NET_Q_LOGON_CTRL2 structure.
********************************************************************/

BOOL net_io_q_logon_ctrl2(const char *desc, NET_Q_LOGON_CTRL2 *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_logon_ctrl2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr          ", ps, depth, &q_l->ptr))
		return False;

	if(!smb_io_unistr2 ("", &q_l->uni_server_name, q_l->ptr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("function_code", ps, depth, &q_l->function_code))
		return False;
	if(!prs_uint32("query_level  ", ps, depth, &q_l->query_level))
		return False;
	if(!prs_uint32("switch_value ", ps, depth, &q_l->switch_value))
		return False;

	return True;
}

/*******************************************************************
 Inits an NET_Q_LOGON_CTRL2 structure.
********************************************************************/

void init_net_q_logon_ctrl2(NET_Q_LOGON_CTRL2 *q_l, const char *srv_name,
			    uint32 query_level)
{
	DEBUG(5,("init_q_logon_ctrl2\n"));

	q_l->function_code = 0x01;
	q_l->query_level = query_level;
	q_l->switch_value  = 0x01;

	init_unistr2(&q_l->uni_server_name, srv_name, strlen(srv_name) + 1);
}

/*******************************************************************
 Inits an NET_R_LOGON_CTRL2 structure.
********************************************************************/

void init_net_r_logon_ctrl2(NET_R_LOGON_CTRL2 *r_l, uint32 query_level,
			    uint32 flags, uint32 pdc_status, 
			    uint32 logon_attempts, uint32 tc_status, 
			    const char *trusted_domain_name)
{
	DEBUG(5,("init_r_logon_ctrl2\n"));

	r_l->switch_value  = query_level; /* should only be 0x1 */

	switch (query_level) {
	case 1:
		r_l->ptr = 1; /* undocumented pointer */
		init_netinfo_1(&r_l->logon.info1, flags, pdc_status);	
		r_l->status = NT_STATUS_OK;
		break;
	case 2:
		r_l->ptr = 1; /* undocumented pointer */
		init_netinfo_2(&r_l->logon.info2, flags, pdc_status,
		               tc_status, trusted_domain_name);	
		r_l->status = NT_STATUS_OK;
		break;
	case 3:
		r_l->ptr = 1; /* undocumented pointer */
		init_netinfo_3(&r_l->logon.info3, flags, logon_attempts);	
		r_l->status = NT_STATUS_OK;
		break;
	default:
		DEBUG(2,("init_r_logon_ctrl2: unsupported switch value %d\n",
			r_l->switch_value));
		r_l->ptr = 0; /* undocumented pointer */

		/* take a guess at an error code... */
		r_l->status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}
}

/*******************************************************************
 Reads or writes an NET_R_LOGON_CTRL2 structure.
********************************************************************/

BOOL net_io_r_logon_ctrl2(const char *desc, NET_R_LOGON_CTRL2 *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_logon_ctrl2");
	depth++;

	if(!prs_uint32("switch_value ", ps, depth, &r_l->switch_value))
		return False;
	if(!prs_uint32("ptr          ", ps, depth, &r_l->ptr))
		return False;

	if (r_l->ptr != 0) {
		switch (r_l->switch_value) {
		case 1:
			if(!net_io_netinfo_1("", &r_l->logon.info1, ps, depth))
				return False;
			break;
		case 2:
			if(!net_io_netinfo_2("", &r_l->logon.info2, ps, depth))
				return False;
			break;
		case 3:
			if(!net_io_netinfo_3("", &r_l->logon.info3, ps, depth))
				return False;
			break;
		default:
			DEBUG(2,("net_io_r_logon_ctrl2: unsupported switch value %d\n",
				r_l->switch_value));
			break;
		}
	}

	if(!prs_ntstatus("status       ", ps, depth, &r_l->status))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an NET_Q_LOGON_CTRL structure.
********************************************************************/

BOOL net_io_q_logon_ctrl(const char *desc, NET_Q_LOGON_CTRL *q_l, prs_struct *ps, 
			 int depth)
{
	prs_debug(ps, depth, desc, "net_io_q_logon_ctrl");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr          ", ps, depth, &q_l->ptr))
		return False;

	if(!smb_io_unistr2 ("", &q_l->uni_server_name, q_l->ptr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("function_code", ps, depth, &q_l->function_code))
		return False;
	if(!prs_uint32("query_level  ", ps, depth, &q_l->query_level))
		return False;

	return True;
}

/*******************************************************************
 Inits an NET_Q_LOGON_CTRL structure.
********************************************************************/

void init_net_q_logon_ctrl(NET_Q_LOGON_CTRL *q_l, const char *srv_name,
			   uint32 query_level)
{
	DEBUG(5,("init_q_logon_ctrl\n"));

	q_l->function_code = 0x01; /* ??? */
	q_l->query_level = query_level;

	init_unistr2(&q_l->uni_server_name, srv_name, strlen(srv_name) + 1);
}

/*******************************************************************
 Inits an NET_R_LOGON_CTRL structure.
********************************************************************/

void init_net_r_logon_ctrl(NET_R_LOGON_CTRL *r_l, uint32 query_level,
			   uint32 flags, uint32 pdc_status)
{
	DEBUG(5,("init_r_logon_ctrl\n"));

	r_l->switch_value  = query_level; /* should only be 0x1 */

	switch (query_level) {
	case 1:
		r_l->ptr = 1; /* undocumented pointer */
		init_netinfo_1(&r_l->logon.info1, flags, pdc_status);	
		r_l->status = NT_STATUS_OK;
		break;
	default:
		DEBUG(2,("init_r_logon_ctrl: unsupported switch value %d\n",
			r_l->switch_value));
		r_l->ptr = 0; /* undocumented pointer */

		/* take a guess at an error code... */
		r_l->status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}
}

/*******************************************************************
 Reads or writes an NET_R_LOGON_CTRL structure.
********************************************************************/

BOOL net_io_r_logon_ctrl(const char *desc, NET_R_LOGON_CTRL *r_l, prs_struct *ps, 
			 int depth)
{
	prs_debug(ps, depth, desc, "net_io_r_logon_ctrl");
	depth++;

	if(!prs_uint32("switch_value ", ps, depth, &r_l->switch_value))
		return False;
	if(!prs_uint32("ptr          ", ps, depth, &r_l->ptr))
		return False;

	if (r_l->ptr != 0) {
		switch (r_l->switch_value) {
		case 1:
			if(!net_io_netinfo_1("", &r_l->logon.info1, ps, depth))
				return False;
			break;
		default:
			DEBUG(2,("net_io_r_logon_ctrl: unsupported switch value %d\n",
				r_l->switch_value));
			break;
		}
	}

	if(!prs_ntstatus("status       ", ps, depth, &r_l->status))
		return False;

	return True;
}

/*******************************************************************
 Inits an NET_R_TRUST_DOM_LIST structure.
********************************************************************/

void init_r_trust_dom(NET_R_TRUST_DOM_LIST *r_t,
			uint32 num_doms, const char *dom_name)
{
	int i = 0;

	DEBUG(5,("init_r_trust_dom\n"));

	for (i = 0; i < MAX_TRUST_DOMS; i++) {
		r_t->uni_trust_dom_name[i].uni_str_len = 0;
		r_t->uni_trust_dom_name[i].uni_max_len = 0;
	}
	if (num_doms > MAX_TRUST_DOMS)
		num_doms = MAX_TRUST_DOMS;

	for (i = 0; i < num_doms; i++) {
		fstring domain_name;
		fstrcpy(domain_name, dom_name);
		strupper(domain_name);
		init_unistr2(&r_t->uni_trust_dom_name[i], domain_name, strlen(domain_name)+1);
		/* the use of UNISTR2 here is non-standard. */
		r_t->uni_trust_dom_name[i].undoc = 0x1;
	}
	
	r_t->status = NT_STATUS_OK;
}

/*******************************************************************
 Reads or writes an NET_R_TRUST_DOM_LIST structure.
********************************************************************/

BOOL net_io_r_trust_dom(const char *desc, NET_R_TRUST_DOM_LIST *r_t, prs_struct *ps, int depth)
{
	uint32 value;

	if (r_t == NULL)
		 return False;

	prs_debug(ps, depth, desc, "net_io_r_trust_dom");
	depth++;

	/* temporary code to give a valid response */
	value=2;
	if(!prs_uint32("status", ps, depth, &value))
		 return False;

	value=1;
	if(!prs_uint32("status", ps, depth, &value))
		 return False;
	value=2;
	if(!prs_uint32("status", ps, depth, &value))
		 return False;

	value=0;
	if(!prs_uint32("status", ps, depth, &value))
		 return False;

	value=0;
	if(!prs_uint32("status", ps, depth, &value))
		 return False;

/* old non working code */
#if 0
	int i;

	for (i = 0; i < MAX_TRUST_DOMS; i++) {
		if (r_t->uni_trust_dom_name[i].uni_str_len == 0)
			break;
		if(!smb_io_unistr2("", &r_t->uni_trust_dom_name[i], True, ps, depth))
			 return False;
	}

	if(!prs_ntstatus("status", ps, depth, &r_t->status))
		 return False;
#endif
	return True;
}


/*******************************************************************
 Reads or writes an NET_Q_TRUST_DOM_LIST structure.
********************************************************************/

BOOL net_io_q_trust_dom(const char *desc, NET_Q_TRUST_DOM_LIST *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL)
		 return False;

	prs_debug(ps, depth, desc, "net_io_q_trust_dom");
	depth++;

	if(!prs_uint32("ptr          ", ps, depth, &q_l->ptr))
		 return False;
	if(!smb_io_unistr2 ("", &q_l->uni_server_name, q_l->ptr, ps, depth))
		 return False;

	return True;
}

/*******************************************************************
 Inits an NET_Q_REQ_CHAL structure.
********************************************************************/

void init_q_req_chal(NET_Q_REQ_CHAL *q_c,
				const char *logon_srv, const char *logon_clnt,
				DOM_CHAL *clnt_chal)
{
	DEBUG(5,("init_q_req_chal: %d\n", __LINE__));

	q_c->undoc_buffer = 1; /* don't know what this buffer is */

	init_unistr2(&q_c->uni_logon_srv, logon_srv , strlen(logon_srv )+1);
	init_unistr2(&q_c->uni_logon_clnt, logon_clnt, strlen(logon_clnt)+1);

	memcpy(q_c->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));

	DEBUG(5,("init_q_req_chal: %d\n", __LINE__));
}

/*******************************************************************
 Reads or writes an NET_Q_REQ_CHAL structure.
********************************************************************/

BOOL net_io_q_req_chal(const char *desc,  NET_Q_REQ_CHAL *q_c, prs_struct *ps, int depth)
{
	int old_align;

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

	old_align = ps->align;
	ps->align = 0;
	/* client challenge is _not_ aligned after the unicode strings */
	if(!smb_io_chal("", &q_c->clnt_chal, ps, depth)) {
		/* client challenge */
		ps->align = old_align;
		return False;
	}
	ps->align = old_align;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_r_req_chal(const char *desc, NET_R_REQ_CHAL *r_c, prs_struct *ps, int depth)
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

BOOL net_io_q_auth(const char *desc, NET_Q_AUTH *q_a, prs_struct *ps, int depth)
{
	int old_align;
	if (q_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_auth");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_log_info ("", &q_a->clnt_id, ps, depth)) /* client identification info */
		return False;
	/* client challenge is _not_ aligned */
	old_align = ps->align;
	ps->align = 0;
	if(!smb_io_chal("", &q_a->clnt_chal, ps, depth)) {
		/* client-calculated credentials */
		ps->align = old_align;
		return False;
	}
	ps->align = old_align;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_r_auth(const char *desc, NET_R_AUTH *r_a, prs_struct *ps, int depth)
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
		DOM_CHAL *clnt_chal, uint32 clnt_flgs)
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

BOOL net_io_q_auth_2(const char *desc, NET_Q_AUTH_2 *q_a, prs_struct *ps, int depth)
{
	int old_align;
	if (q_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_auth_2");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_log_info ("", &q_a->clnt_id, ps, depth)) /* client identification info */
		return False;
	/* client challenge is _not_ aligned */
	old_align = ps->align;
	ps->align = 0;
	if(!smb_io_chal("", &q_a->clnt_chal, ps, depth)) {
		/* client-calculated credentials */
		ps->align = old_align;
		return False;
	}
	ps->align = old_align;
	if(!net_io_neg_flags("", &q_a->clnt_flgs, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_r_auth_2(const char *desc, NET_R_AUTH_2 *r_a, prs_struct *ps, int depth)
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
 Inits a NET_Q_SRV_PWSET.
********************************************************************/

void init_q_srv_pwset(NET_Q_SRV_PWSET *q_s, const char *logon_srv, const char *acct_name, 
                uint16 sec_chan, const char *comp_name, DOM_CRED *cred, char nt_cypher[16])
{
	DEBUG(5,("init_q_srv_pwset\n"));

	init_clnt_info(&q_s->clnt_id, logon_srv, acct_name, sec_chan, comp_name, cred);

	memcpy(q_s->pwd, nt_cypher, sizeof(q_s->pwd)); 
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_q_srv_pwset(const char *desc, NET_Q_SRV_PWSET *q_s, prs_struct *ps, int depth)
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

BOOL net_io_r_srv_pwset(const char *desc, NET_R_SRV_PWSET *r_s, prs_struct *ps, int depth)
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
	pstring s2;
	int count = 0;

	DEBUG(4,("init_dom_sid2s: %s\n", sids_str ? sids_str:""));

	*ppsids = NULL;

	if(sids_str) {
		int number;
		DOM_SID2 *sids;

		/* Count the number of SIDs. */
		for (count = 0, ptr = sids_str; 
	   	  next_token(&ptr, s2, NULL, sizeof(s2)); count++)
			;

		/* Now allocate space for them. */
		*ppsids = (DOM_SID2 *)talloc_zero(ctx, count * sizeof(DOM_SID2));
		if (*ppsids == NULL)
			return 0;

		sids = *ppsids;

		for (number = 0, ptr = sids_str; 
	   	  next_token(&ptr, s2, NULL, sizeof(s2)); number++) {
			DOM_SID tmpsid;
			string_to_sid(&tmpsid, s2);
			init_dom_sid2(&sids[number], &tmpsid);
		}
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
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );

	unsigned char lm_owf[16];
	unsigned char nt_owf[16];

	DEBUG(5,("init_id_info1: %d\n", __LINE__));

	id->ptr_id_info1 = 1;

	init_uni_hdr(&id->hdr_domain_name, len_domain_name);

	id->param_ctrl = param_ctrl;
	init_logon_id(&id->logon_id, log_id_low, log_id_high);

	init_uni_hdr(&id->hdr_user_name, len_user_name);
	init_uni_hdr(&id->hdr_wksta_name, len_wksta_name);

	if (lm_cypher && nt_cypher) {
		unsigned char key[16];
#ifdef DEBUG_PASSWORD
		DEBUG(100,("lm cypher:"));
		dump_data(100, (char *)lm_cypher, 16);

		DEBUG(100,("nt cypher:"));
		dump_data(100, (char *)nt_cypher, 16);
#endif

		memset(key, 0, 16);
		memcpy(key, sess_key, 8);

		memcpy(lm_owf, lm_cypher, 16);
		SamOEMhash(lm_owf, key, 16);
		memcpy(nt_owf, nt_cypher, 16);
		SamOEMhash(nt_owf, key, 16);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of lm owf password:"));
		dump_data(100, (char *)lm_owf, 16);

		DEBUG(100,("encrypt of nt owf password:"));
		dump_data(100, (char *)nt_owf, 16);
#endif
		/* set up pointers to cypher blocks */
		lm_cypher = lm_owf;
		nt_cypher = nt_owf;
	}

	init_owf_info(&id->lm_owf, lm_cypher);
	init_owf_info(&id->nt_owf, nt_cypher);

	init_unistr2(&id->uni_domain_name, domain_name, len_domain_name);
	init_unistr2(&id->uni_user_name, user_name, len_user_name);
	init_unistr2(&id->uni_wksta_name, wksta_name, len_wksta_name);
}

/*******************************************************************
 Reads or writes an NET_ID_INFO_1 structure.
********************************************************************/

static BOOL net_io_id_info1(const char *desc,  NET_ID_INFO_1 *id, prs_struct *ps, int depth)
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
		   const uchar * lm_chal_resp, int lm_chal_resp_len,
		   const uchar * nt_chal_resp, int nt_chal_resp_len)
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );
	unsigned char lm_owf[24];
	unsigned char nt_owf[128];

	DEBUG(5,("init_id_info2: %d\n", __LINE__));

	id->ptr_id_info2 = 1;

	init_uni_hdr(&id->hdr_domain_name, len_domain_name);

	id->param_ctrl = param_ctrl;
	init_logon_id(&id->logon_id, log_id_low, log_id_high);

	init_uni_hdr(&id->hdr_user_name, len_user_name);
	init_uni_hdr(&id->hdr_wksta_name, len_wksta_name);

	if (nt_chal_resp) {
		/* oops.  can only send what-ever-it-is direct */
		memcpy(nt_owf, nt_chal_resp, MIN(sizeof(nt_owf), nt_chal_resp_len));
		nt_chal_resp = nt_owf;
	}
	if (lm_chal_resp) {
		/* oops.  can only send what-ever-it-is direct */
		memcpy(lm_owf, lm_chal_resp, MIN(sizeof(lm_owf), lm_chal_resp_len));
		lm_chal_resp = lm_owf;
	}

	memcpy(id->lm_chal, lm_challenge, sizeof(id->lm_chal));
	init_str_hdr(&id->hdr_nt_chal_resp, nt_chal_resp_len, nt_chal_resp_len, (nt_chal_resp != NULL) ? 1 : 0);
	init_str_hdr(&id->hdr_lm_chal_resp, lm_chal_resp_len, lm_chal_resp_len, (lm_chal_resp != NULL) ? 1 : 0);

	init_unistr2(&id->uni_domain_name, domain_name, len_domain_name);
	init_unistr2(&id->uni_user_name, user_name, len_user_name);
	init_unistr2(&id->uni_wksta_name, wksta_name, len_wksta_name);

	init_string2(&id->nt_chal_resp, (const char *)nt_chal_resp, nt_chal_resp_len, nt_chal_resp_len);
	init_string2(&id->lm_chal_resp, (const char *)lm_chal_resp, lm_chal_resp_len, lm_chal_resp_len);

}

/*******************************************************************
 Reads or writes an NET_ID_INFO_2 structure.
********************************************************************/

static BOOL net_io_id_info2(const char *desc,  NET_ID_INFO_2 *id, prs_struct *ps, int depth)
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
				const char *logon_srv, const char *comp_name, DOM_CRED *clnt_cred,
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
 Reads or writes a DOM_SAM_INFO structure.
********************************************************************/

static BOOL net_io_id_info_ctr(const char *desc, NET_ID_INFO_CTR **pp_ctr, prs_struct *ps, int depth)
{
	NET_ID_INFO_CTR *ctr = *pp_ctr;

	prs_debug(ps, depth, desc, "smb_io_sam_info");
	depth++;

	if (UNMARSHALLING(ps)) {
		ctr = *pp_ctr = (NET_ID_INFO_CTR *)prs_alloc_mem(ps, sizeof(NET_ID_INFO_CTR));
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
		DEBUG(4,("smb_io_sam_info: unknown switch_value!\n"));
		break;
	}

	return True;
}

/*******************************************************************
 Reads or writes a DOM_SAM_INFO structure.
 ********************************************************************/

static BOOL smb_io_sam_info(const char *desc, DOM_SAM_INFO *sam, prs_struct *ps, int depth)
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
	if(!smb_io_cred("", &sam->rtn_cred, ps, depth))
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
 Init
 *************************************************************************/

void init_net_user_info3(TALLOC_CTX *ctx, NET_USER_INFO_3 *usr, SAM_ACCOUNT *sampw,
			 uint16 logon_count, uint16 bad_pw_count,
 		 	 uint32 num_groups, DOM_GID *gids,
			 uint32 user_flgs, uchar *sess_key,
 			 const char *logon_srv, const char *logon_dom,
			 DOM_SID *dom_sid, const char *other_sids)
{
	/* only cope with one "other" sid, right now. */
	/* need to count the number of space-delimited sids */
	int i;
	int num_other_sids = 0;
	
	NTTIME 		logon_time, logoff_time, kickoff_time,
			pass_last_set_time, pass_can_change_time,
			pass_must_change_time;

	int 		len_user_name, len_full_name, len_home_dir,
			len_dir_drive, len_logon_script, len_profile_path;
			
	const char*		user_name = pdb_get_username(sampw);
	const char*		full_name = pdb_get_fullname(sampw);
	const char*		home_dir  = pdb_get_homedir(sampw);
	const char*		dir_drive = pdb_get_dirdrive(sampw);
	const char*		logon_script = pdb_get_logon_script(sampw);
	const char*		profile_path = pdb_get_profile_path(sampw);

	int len_logon_srv    = strlen(logon_srv);
	int len_logon_dom    = strlen(logon_dom);

	len_user_name    = strlen(user_name   );
	len_full_name    = strlen(full_name   );
	len_home_dir     = strlen(home_dir    );
	len_dir_drive    = strlen(dir_drive   );
	len_logon_script = strlen(logon_script);
	len_profile_path = strlen(profile_path);


	ZERO_STRUCTP(usr);

	usr->ptr_user_info = 1; /* yes, we're bothering to put USER_INFO data here */


	/* Create NTTIME structs */
	unix_to_nt_time (&logon_time, 		pdb_get_logon_time(sampw));
	unix_to_nt_time (&logoff_time, 		TIME_T_MAX);
	unix_to_nt_time (&kickoff_time, 	TIME_T_MAX);
	unix_to_nt_time (&pass_last_set_time, 	pdb_get_pass_last_set_time(sampw));
	unix_to_nt_time (&pass_can_change_time,	pdb_get_pass_can_change_time(sampw));
	unix_to_nt_time (&pass_must_change_time,pdb_get_pass_must_change_time(sampw));

	usr->logon_time            = logon_time;
	usr->logoff_time           = logoff_time;
	usr->kickoff_time          = kickoff_time;
	usr->pass_last_set_time    = pass_last_set_time;
	usr->pass_can_change_time  = pass_can_change_time;
	usr->pass_must_change_time = pass_must_change_time;

	init_uni_hdr(&usr->hdr_user_name, len_user_name);
	init_uni_hdr(&usr->hdr_full_name, len_full_name);
	init_uni_hdr(&usr->hdr_logon_script, len_logon_script);
	init_uni_hdr(&usr->hdr_profile_path, len_profile_path);
	init_uni_hdr(&usr->hdr_home_dir, len_home_dir);
	init_uni_hdr(&usr->hdr_dir_drive, len_dir_drive);

	usr->logon_count = logon_count;
	usr->bad_pw_count = bad_pw_count;

	usr->user_rid = pdb_get_user_rid(sampw);
	usr->group_rid = pdb_get_group_rid(sampw);
	usr->num_groups = num_groups+1;

	usr->buffer_groups = 1; /* indicates fill in groups, below, even if there are none */
	usr->user_flgs = user_flgs;

	if (sess_key != NULL)
		memcpy(usr->user_sess_key, sess_key, sizeof(usr->user_sess_key));
	else
		memset((char *)usr->user_sess_key, '\0', sizeof(usr->user_sess_key));

	init_uni_hdr(&usr->hdr_logon_srv, len_logon_srv);
	init_uni_hdr(&usr->hdr_logon_dom, len_logon_dom);

	usr->buffer_dom_id = dom_sid ? 1 : 0; /* yes, we're bothering to put a domain SID in */

	memset((char *)usr->padding, '\0', sizeof(usr->padding));

	num_other_sids = init_dom_sid2s(ctx, other_sids, &usr->other_sids);

	usr->num_other_sids = num_other_sids;
	usr->buffer_other_sids = (num_other_sids != 0) ? 1 : 0; 
	
	init_unistr2(&usr->uni_user_name, user_name, len_user_name);
	init_unistr2(&usr->uni_full_name, full_name, len_full_name);
	init_unistr2(&usr->uni_logon_script, logon_script, len_logon_script);
	init_unistr2(&usr->uni_profile_path, profile_path, len_profile_path);
	init_unistr2(&usr->uni_home_dir, home_dir, len_home_dir);
	init_unistr2(&usr->uni_dir_drive, dir_drive, len_dir_drive);

	/* always have at least one group == the user's primary group */
	usr->num_groups2 = num_groups+1;

	usr->gids = (DOM_GID *)talloc_zero(ctx,sizeof(DOM_GID) * (num_groups+1));
	if (usr->gids == NULL)
		return;

	/* primary group **MUST** go first.  NT4's winmsd.exe will give
	   "The Network statistics are currently not available.  9-5"
	   What the heck is this?     -- jerry  */
	usr->gids[0].g_rid = usr->group_rid;
	usr->gids[0].attr  = 0x07;
	for (i = 0; i < num_groups; i++) 
		usr->gids[i+1] = gids[i];	
		
	init_unistr2(&usr->uni_logon_srv, logon_srv, len_logon_srv);
	init_unistr2(&usr->uni_logon_dom, logon_dom, len_logon_dom);

	init_dom_sid2(&usr->dom_sid, dom_sid);
	/* "other" sids are set up above */
}

/*******************************************************************
 This code has been modified to cope with a NET_USER_INFO_2 - which is
 exactly the same as a NET_USER_INFO_3, minus the other sids parameters.
 We use validation level to determine if we're marshalling a info 2 or
 INFO_3 - be we always return an INFO_3. Based on code donated by Marc
 Jacobsen at HP. JRA.
********************************************************************/

static BOOL net_io_user_info3(const char *desc, NET_USER_INFO_3 *usr, prs_struct *ps, int depth, uint16 validation_level)
{
	int i;

	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_lsa_user_info");
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

	if(!smb_io_unihdr("unihdr", &usr->hdr_user_name, ps, depth)) /* username unicode string header */
		return False;
	if(!smb_io_unihdr("unihdr", &usr->hdr_full_name, ps, depth)) /* user's full name unicode string header */
		return False;
	if(!smb_io_unihdr("unihdr", &usr->hdr_logon_script, ps, depth)) /* logon script unicode string header */
		return False;
	if(!smb_io_unihdr("unihdr", &usr->hdr_profile_path, ps, depth)) /* profile path unicode string header */
		return False;
	if(!smb_io_unihdr("unihdr", &usr->hdr_home_dir, ps, depth)) /* home directory unicode string header */
		return False;
	if(!smb_io_unihdr("unihdr", &usr->hdr_dir_drive, ps, depth)) /* home directory drive unicode string header */
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

	if(!prs_uint8s(False, "user_sess_key", ps, depth, usr->user_sess_key, 16)) /* unused user session key */
		return False;

	if(!smb_io_unihdr("unihdr", &usr->hdr_logon_srv, ps, depth)) /* logon server unicode string header */
		return False;
	if(!smb_io_unihdr("unihdr", &usr->hdr_logon_dom, ps, depth)) /* logon domain unicode string header */
		return False;

	if(!prs_uint32("buffer_dom_id ", ps, depth, &usr->buffer_dom_id)) /* undocumented logon domain id pointer */
		return False;
	if(!prs_uint8s (False, "padding       ", ps, depth, usr->padding, 40)) /* unused padding bytes? */
		return False;

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
		
	if(!smb_io_unistr2("unistr2", &usr->uni_user_name, usr->hdr_user_name.buffer, ps, depth)) /* username unicode string */
		return False;
	if(!smb_io_unistr2("unistr2", &usr->uni_full_name, usr->hdr_full_name.buffer, ps, depth)) /* user's full name unicode string */
		return False;
	if(!smb_io_unistr2("unistr2", &usr->uni_logon_script, usr->hdr_logon_script.buffer, ps, depth)) /* logon script unicode string */
		return False;
	if(!smb_io_unistr2("unistr2", &usr->uni_profile_path, usr->hdr_profile_path.buffer, ps, depth)) /* profile path unicode string */
		return False;
	if(!smb_io_unistr2("unistr2", &usr->uni_home_dir, usr->hdr_home_dir.buffer, ps, depth)) /* home directory unicode string */
		return False;
	if(!smb_io_unistr2("unistr2", &usr->uni_dir_drive, usr->hdr_dir_drive.buffer, ps, depth)) /* home directory drive unicode string */
		return False;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_groups2   ", ps, depth, &usr->num_groups2))        /* num groups */
		return False;

	if (UNMARSHALLING(ps) && usr->num_groups2 > 0) {
		usr->gids = (DOM_GID *)prs_alloc_mem(ps, sizeof(DOM_GID)*usr->num_groups2);
		if (usr->gids == NULL)
			return False;
	}

	for (i = 0; i < usr->num_groups2; i++) {
		if(!smb_io_gid("", &usr->gids[i], ps, depth)) /* group info */
			return False;
	}

	if(!smb_io_unistr2("unistr2", &usr->uni_logon_srv, usr->hdr_logon_srv.buffer, ps, depth)) /* logon server unicode string */
		return False;
	if(!smb_io_unistr2("unistr2", &usr->uni_logon_dom, usr->hdr_logon_srv.buffer, ps, depth)) /* logon domain unicode string */
		return False;

	if(!smb_io_dom_sid2("", &usr->dom_sid, ps, depth))           /* domain SID */
		return False;

	if (usr->num_other_sids) {

		if (UNMARSHALLING(ps)) {
			usr->other_sids = (DOM_SID2 *)prs_alloc_mem(ps, sizeof(DOM_SID2)*usr->num_other_sids);
			if (usr->other_sids == NULL)
				return False;
		}
	
		if(!prs_uint32("num_other_groups", ps, depth, &usr->num_other_groups))
			return False;

		if (UNMARSHALLING(ps) && usr->num_other_groups > 0) {
			usr->other_gids = (DOM_GID *)prs_alloc_mem(ps, sizeof(DOM_GID)*usr->num_other_groups);
			if (usr->other_gids == NULL)
				return False;
		}
	
		for (i = 0; i < usr->num_other_groups; i++) {
			if(!smb_io_gid("", &usr->other_gids[i], ps, depth)) /* other GIDs */
				return False;
		}
		for (i = 0; i < usr->num_other_sids; i++) {
			if(!smb_io_dom_sid2("", &usr->other_sids[i], ps, depth)) /* other domain SIDs */
				return False;
		}
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_q_sam_logon(const char *desc, NET_Q_SAM_LOGON *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_logon");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_sam_info("", &q_l->sam_id, ps, depth))
		return False;

	if(!prs_uint16("validation_level", ps, depth, &q_l->validation_level))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_r_sam_logon(const char *desc, NET_R_SAM_LOGON *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_logon");
	depth++;

	if(!prs_uint32("buffer_creds", ps, depth, &r_l->buffer_creds)) /* undocumented buffer pointer */
		return False;
	if(!smb_io_cred("", &r_l->srv_creds, ps, depth)) /* server credentials.  server time stamp appears to be ignored. */
		return False;

	if(!prs_uint16("switch_value", ps, depth, &r_l->switch_value))
		return False;
	if(!prs_align(ps))
		return False;

#if 1 /* W2k always needs this - even for bad passwd. JRA */
	if(!net_io_user_info3("", r_l->user, ps, depth, r_l->switch_value))
		return False;
#else
	if (r_l->switch_value != 0) {
		if(!net_io_user_info3("", r_l->user, ps, depth, r_l->switch_value))
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

BOOL net_io_q_sam_logoff(const char *desc,  NET_Q_SAM_LOGOFF *q_l, prs_struct *ps, int depth)
{
	if (q_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_sam_logoff");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_sam_info("", &q_l->sam_id, ps, depth))           /* domain SID */
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL net_io_r_sam_logoff(const char *desc, NET_R_SAM_LOGOFF *r_l, prs_struct *ps, int depth)
{
	if (r_l == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_sam_logoff");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("buffer_creds", ps, depth, &r_l->buffer_creds)) /* undocumented buffer pointer */
		return False;
	if(!smb_io_cred("", &r_l->srv_creds, ps, depth)) /* server credentials.  server time stamp appears to be ignored. */
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_l->status))
		return False;

	return True;
}

/*******************************************************************
makes a NET_Q_SAM_SYNC structure.
********************************************************************/
BOOL init_net_q_sam_sync(NET_Q_SAM_SYNC * q_s, const char *srv_name,
                         const char *cli_name, DOM_CRED * cli_creds, 
                         DOM_CRED *ret_creds, uint32 database_id)
{
	DEBUG(5, ("init_q_sam_sync\n"));

	init_unistr2(&q_s->uni_srv_name, srv_name, strlen(srv_name) + 1);
	init_unistr2(&q_s->uni_cli_name, cli_name, strlen(cli_name) + 1);

        if (cli_creds)
                memcpy(&q_s->cli_creds, cli_creds, sizeof(q_s->cli_creds));

	if (cli_creds)
                memcpy(&q_s->ret_creds, ret_creds, sizeof(q_s->ret_creds));
	else
                memset(&q_s->ret_creds, 0, sizeof(q_s->ret_creds));

	q_s->database_id = database_id;
	q_s->restart_state = 0;
	q_s->sync_context = 0;
	q_s->max_size = 0xffff;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_sam_sync(const char *desc, NET_Q_SAM_SYNC * q_s, prs_struct *ps,
		       int depth)
{
	prs_debug(ps, depth, desc, "net_io_q_sam_sync");
	depth++;

	if (!smb_io_unistr2("", &q_s->uni_srv_name, True, ps, depth))
                return False;
	if (!smb_io_unistr2("", &q_s->uni_cli_name, True, ps, depth))
                return False;

	if (!smb_io_cred("", &q_s->cli_creds, ps, depth))
                return False;
	if (!smb_io_cred("", &q_s->ret_creds, ps, depth))
                return False;

	if (!prs_uint32("database_id  ", ps, depth, &q_s->database_id))
                return False;
	if (!prs_uint32("restart_state", ps, depth, &q_s->restart_state))
                return False;
	if (!prs_uint32("sync_context ", ps, depth, &q_s->sync_context))
                return False;

	if (!prs_uint32("max_size", ps, depth, &q_s->max_size))
                return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_delta_hdr(const char *desc, SAM_DELTA_HDR * delta,
				 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_delta_hdr");
	depth++;

	if (!prs_uint16("type", ps, depth, &delta->type))
                return False;
	if (!prs_uint16("type2", ps, depth, &delta->type2))
                return False;
	if (!prs_uint32("target_rid", ps, depth, &delta->target_rid))
                return False;

	if (!prs_uint32("type3", ps, depth, &delta->type3))
                return False;

        /* Not sure why we need this but it seems to be necessary to get
           sam deltas working. */

        if (delta->type != 0x16) {
                if (!prs_uint32("ptr_delta", ps, depth, &delta->ptr_delta))
                        return False;
        }

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_delta_stamp(const char *desc, SAM_DELTA_STAMP *info,
                                   prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_delta_stamp");
	depth++;

        if (!prs_uint32("seqnum", ps, depth, &info->seqnum))
                return False;
        if (!prs_uint32("dom_mod_count_ptr", ps, depth, 
                        &info->dom_mod_count_ptr))
                return False;

        if (info->dom_mod_count_ptr) {
                if (!prs_uint64("dom_mod_count", ps, depth,
                                &info->dom_mod_count))
                        return False;
        }

        return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_domain_info(const char *desc, SAM_DOMAIN_INFO * info,
				   prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_domain_info");
	depth++;

	if (!smb_io_unihdr("hdr_dom_name", &info->hdr_dom_name, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_oem_info", &info->hdr_oem_info, ps, depth))
                return False;

        if (!prs_uint64("force_logoff", ps, depth, &info->force_logoff))
                return False;
	if (!prs_uint16("min_pwd_len", ps, depth, &info->min_pwd_len))
                return False;
	if (!prs_uint16("pwd_history_len", ps, depth, &info->pwd_history_len))
                return False;
	if (!prs_uint64("max_pwd_age", ps, depth, &info->max_pwd_age))
                return False;
	if (!prs_uint64("min_pwd_age", ps, depth, &info->min_pwd_age))
                return False;
	if (!prs_uint64("dom_mod_count", ps, depth, &info->dom_mod_count))
                return False;
	if (!smb_io_time("creation_time", &info->creation_time, ps, depth))
                return False;

	if (!smb_io_bufhdr2("hdr_sec_desc", &info->hdr_sec_desc, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_unknown", &info->hdr_unknown, ps, depth))
                return False;

	if (ps->data_offset + 40 > ps->buffer_size)
                return False;
        ps->data_offset += 40;

	if (!smb_io_unistr2("uni_dom_name", &info->uni_dom_name,
                            info->hdr_dom_name.buffer, ps, depth))
                return False;
	if (!smb_io_unistr2("buf_oem_info", &info->buf_oem_info,
                            info->hdr_oem_info.buffer, ps, depth))
                return False;

	if (!smb_io_buffer4("buf_sec_desc", &info->buf_sec_desc,
                            info->hdr_sec_desc.buffer, ps, depth))
                return False;
	if (!smb_io_unistr2("buf_unknown", &info->buf_unknown,
                            info->hdr_unknown.buffer, ps, depth))
                return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_group_info(const char *desc, SAM_GROUP_INFO * info,
				  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_group_info");
	depth++;

	if (!smb_io_unihdr("hdr_grp_name", &info->hdr_grp_name, ps, depth))
                return False;
	if (!smb_io_gid("gid", &info->gid, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_grp_desc", &info->hdr_grp_desc, ps, depth))
                return False;
	if (!smb_io_bufhdr2("hdr_sec_desc", &info->hdr_sec_desc, ps, depth))
                return False;

        if (ps->data_offset + 48 > ps->buffer_size)
                return False;
	ps->data_offset += 48;

	if (!smb_io_unistr2("uni_grp_name", &info->uni_grp_name,
                            info->hdr_grp_name.buffer, ps, depth))
                return False;
	if (!smb_io_unistr2("uni_grp_desc", &info->uni_grp_desc,
                            info->hdr_grp_desc.buffer, ps, depth))
                return False;
	if (!smb_io_buffer4("buf_sec_desc", &info->buf_sec_desc,
                            info->hdr_sec_desc.buffer, ps, depth))
                return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_passwd_info(const char *desc, SAM_PWD * pwd,
				   prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_passwd_info");
	depth++;

	if (!prs_uint32("unk_0 ", ps, depth, &pwd->unk_0))
                return False;

	if (!smb_io_unihdr("hdr_lm_pwd", &pwd->hdr_lm_pwd, ps, depth))
                return False;
	if (!prs_uint8s(False, "buf_lm_pwd", ps, depth, pwd->buf_lm_pwd, 16))
                return False;

	if (!smb_io_unihdr("hdr_nt_pwd", &pwd->hdr_nt_pwd, ps, depth))
                return False;
	if (!prs_uint8s(False, "buf_nt_pwd", ps, depth, pwd->buf_nt_pwd, 16))
                return False;

	if (!smb_io_unihdr("", &pwd->hdr_empty_lm, ps, depth))
                return False;
	if (!smb_io_unihdr("", &pwd->hdr_empty_nt, ps, depth))
                return False;

	return True;
}

/*******************************************************************
makes a SAM_ACCOUNT_INFO structure.
********************************************************************/
BOOL make_sam_account_info(SAM_ACCOUNT_INFO * info,
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
			   const UNISTR2 *unk_str, const UNISTR2 *mung_dial)
{
	int len_user_name = user_name != NULL ? user_name->uni_str_len : 0;
	int len_full_name = full_name != NULL ? full_name->uni_str_len : 0;
	int len_home_dir = home_dir != NULL ? home_dir->uni_str_len : 0;
	int len_dir_drive = dir_drive != NULL ? dir_drive->uni_str_len : 0;
	int len_logon_script = log_scr != NULL ? log_scr->uni_str_len : 0;
	int len_profile_path = prof_path != NULL ? prof_path->uni_str_len : 0;
	int len_description = desc != NULL ? desc->uni_str_len : 0;
	int len_workstations = wkstas != NULL ? wkstas->uni_str_len : 0;
	int len_unknown_str = unk_str != NULL ? unk_str->uni_str_len : 0;
	int len_munged_dial = mung_dial != NULL ? mung_dial->uni_str_len : 0;

	DEBUG(5, ("make_sam_account_info\n"));

	make_uni_hdr(&info->hdr_acct_name, len_user_name);
	make_uni_hdr(&info->hdr_full_name, len_full_name);
	make_uni_hdr(&info->hdr_home_dir, len_home_dir);
	make_uni_hdr(&info->hdr_dir_drive, len_dir_drive);
	make_uni_hdr(&info->hdr_logon_script, len_logon_script);
	make_uni_hdr(&info->hdr_profile, len_profile_path);
	make_uni_hdr(&info->hdr_acct_desc, len_description);
	make_uni_hdr(&info->hdr_workstations, len_workstations);
	make_uni_hdr(&info->hdr_comment, len_unknown_str);
	make_uni_hdr(&info->hdr_parameters, len_munged_dial);

	/* not present */
	make_bufhdr2(&info->hdr_sec_desc, 0, 0, 0);

	info->user_rid = user_rid;
	info->group_rid = group_rid;

	init_nt_time(&info->logon_time);
	init_nt_time(&info->logoff_time);
	init_nt_time(&info->pwd_last_set_time);
	init_nt_time(&info->acct_expiry_time);

	info->logon_divs = 0xA8;
	info->ptr_logon_hrs = 0;	/* Don't care right now */

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

	copy_unistr2(&info->uni_acct_name, user_name);
	copy_unistr2(&info->uni_full_name, full_name);
	copy_unistr2(&info->uni_home_dir, home_dir);
	copy_unistr2(&info->uni_dir_drive, dir_drive);
	copy_unistr2(&info->uni_logon_script, log_scr);
	copy_unistr2(&info->uni_profile, prof_path);
	copy_unistr2(&info->uni_acct_desc, desc);
	copy_unistr2(&info->uni_workstations, wkstas);
	copy_unistr2(&info->uni_comment, unk_str);
	copy_unistr2(&info->uni_parameters, mung_dial);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_account_info(const char *desc, uint8 sess_key[16],
				    SAM_ACCOUNT_INFO * info, prs_struct *ps,
				    int depth)
{
	BUFHDR2 hdr_priv_data;
	uint32 i;

	prs_debug(ps, depth, desc, "net_io_sam_account_info");
	depth++;

	if (!smb_io_unihdr("hdr_acct_name", &info->hdr_acct_name, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_full_name", &info->hdr_full_name, ps, depth))
                return False;

	if (!prs_uint32("user_rid ", ps, depth, &info->user_rid))
                return False;
	if (!prs_uint32("group_rid", ps, depth, &info->group_rid))
                return False;

	if (!smb_io_unihdr("hdr_home_dir ", &info->hdr_home_dir, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_dir_drive", &info->hdr_dir_drive, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_logon_script", &info->hdr_logon_script, ps,
                           depth))
                return False;

	if (!smb_io_unihdr("hdr_acct_desc", &info->hdr_acct_desc, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_workstations", &info->hdr_workstations, ps,
                           depth))
                return False;

	if (!smb_io_time("logon_time", &info->logon_time, ps, depth))
                return False;
	if (!smb_io_time("logoff_time", &info->logoff_time, ps, depth))
                return False;

	if (!prs_uint32("logon_divs   ", ps, depth, &info->logon_divs))
                return False;
	if (!prs_uint32("ptr_logon_hrs", ps, depth, &info->ptr_logon_hrs))
                return False;

	if (!prs_uint16("bad_pwd_count", ps, depth, &info->bad_pwd_count))
                return False;
	if (!prs_uint16("logon_count", ps, depth, &info->logon_count))
                return False;
	if (!smb_io_time("pwd_last_set_time", &info->pwd_last_set_time, ps,
                         depth))
                return False;
	if (!smb_io_time("acct_expiry_time", &info->acct_expiry_time, ps, 
                         depth))
                return False;

	if (!prs_uint32("acb_info", ps, depth, &info->acb_info))
                return False;
	if (!prs_uint8s(False, "nt_pwd", ps, depth, info->nt_pwd, 16))
                return False;
	if (!prs_uint8s(False, "lm_pwd", ps, depth, info->lm_pwd, 16))
                return False;
	if (!prs_uint8("lm_pwd_present", ps, depth, &info->lm_pwd_present))
                return False;
	if (!prs_uint8("nt_pwd_present", ps, depth, &info->nt_pwd_present))
                return False;
	if (!prs_uint8("pwd_expired", ps, depth, &info->pwd_expired))
                return False;

	if (!smb_io_unihdr("hdr_comment", &info->hdr_comment, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_parameters", &info->hdr_parameters, ps, 
                           depth))
                return False;
	if (!prs_uint16("country", ps, depth, &info->country))
                return False;
	if (!prs_uint16("codepage", ps, depth, &info->codepage))
                return False;

	if (!smb_io_bufhdr2("hdr_priv_data", &hdr_priv_data, ps, depth))
                return False;
	if (!smb_io_bufhdr2("hdr_sec_desc", &info->hdr_sec_desc, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_profile", &info->hdr_profile, ps, depth))
                return False;

	for (i = 0; i < 3; i++)
	{
		if (!smb_io_unihdr("hdr_reserved", &info->hdr_reserved[i], 
                                   ps, depth))
                        return False;                                          
	}

	for (i = 0; i < 4; i++)
	{
		if (!prs_uint32("dw_reserved", ps, depth, 
                                &info->dw_reserved[i]))
                        return False;
	}

	if (!smb_io_unistr2("uni_acct_name", &info->uni_acct_name,
                            info->hdr_acct_name.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_full_name", &info->uni_full_name,
                            info->hdr_full_name.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_home_dir ", &info->uni_home_dir,
                            info->hdr_home_dir.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_dir_drive", &info->uni_dir_drive,
                            info->hdr_dir_drive.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_logon_script", &info->uni_logon_script,
                            info->hdr_logon_script.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_acct_desc", &info->uni_acct_desc,
                            info->hdr_acct_desc.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_workstations", &info->uni_workstations,
                            info->hdr_workstations.buffer, ps, depth))
                return False;
	prs_align(ps);

	if (!prs_uint32("unknown1", ps, depth, &info->unknown1))
                return False;
	if (!prs_uint32("unknown2", ps, depth, &info->unknown2))
                return False;

	if (!smb_io_buffer4("buf_logon_hrs", &info->buf_logon_hrs,
                            info->ptr_logon_hrs, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_comment", &info->uni_comment,
                            info->hdr_comment.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_parameters", &info->uni_parameters,
                            info->hdr_parameters.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (hdr_priv_data.buffer != 0)
	{
		int old_offset = 0;
		uint32 len = 0x44;
		if (!prs_uint32("pwd_len", ps, depth, &len))
                        return False;
		old_offset = ps->data_offset;
		if (len == 0x44)
		{
			if (ps->io)
			{
				/* reading */
                                if (!prs_hash1(ps, ps->data_offset, sess_key))
                                        return False;
			}
			if (!net_io_sam_passwd_info("pass", &info->pass, 
                                                    ps, depth))
                                return False;

			if (!ps->io)
			{
				/* writing */
                                if (!prs_hash1(ps, old_offset, sess_key))
                                        return False;
			}
		}
                if (old_offset + len > ps->buffer_size)
                        return False;
		ps->data_offset = old_offset + len;
	}
	if (!smb_io_buffer4("buf_sec_desc", &info->buf_sec_desc,
                            info->hdr_sec_desc.buffer, ps, depth))
                return False;
	prs_align(ps);
	if (!smb_io_unistr2("uni_profile", &info->uni_profile,
                            info->hdr_profile.buffer, ps, depth))
                return False;

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_group_mem_info(const char *desc, SAM_GROUP_MEM_INFO * info,
				      prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	prs_debug(ps, depth, desc, "net_io_sam_group_mem_info");
	depth++;

	prs_align(ps);
	if (!prs_uint32("ptr_rids   ", ps, depth, &info->ptr_rids))
                return False;
	if (!prs_uint32("ptr_attribs", ps, depth, &info->ptr_attribs))
                return False;
	if (!prs_uint32("num_members", ps, depth, &info->num_members))
                return False;

        if (ps->data_offset + 16 > ps->buffer_size)
                return False;
	ps->data_offset += 16;

	if (info->ptr_rids != 0)
	{
		if (!prs_uint32("num_members2", ps, depth, 
                                &info->num_members2))
                        return False;

		if (info->num_members2 != info->num_members)
		{
			/* RPC fault */
			return False;
		}

                info->rids = talloc(ps->mem_ctx, sizeof(uint32) *
                                    info->num_members2);

                if (info->rids == NULL) {
                        DEBUG(0, ("out of memory allocating %d rids\n",
                                  info->num_members2));
                        return False;
                }

		for (i = 0; i < info->num_members2; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "rids[%02d]", i);
			if (!prs_uint32(tmp, ps, depth, &info->rids[i]))
                                return False;
		}
	}

	if (info->ptr_attribs != 0)
	{
		if (!prs_uint32("num_members3", ps, depth, 
                                &info->num_members3))
                        return False;
		if (info->num_members3 != info->num_members)
		{
			/* RPC fault */
			return False;
		}

                info->attribs = talloc(ps->mem_ctx, sizeof(uint32) *
                                       info->num_members3);

                if (info->attribs == NULL) {
                        DEBUG(0, ("out of memory allocating %d attribs\n",
                                  info->num_members3));
                        return False;
                }

		for (i = 0; i < info->num_members3; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "attribs[%02d]", i);
			if (!prs_uint32(tmp, ps, depth, &info->attribs[i]))
                                return False;
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_alias_info(const char *desc, SAM_ALIAS_INFO * info,
				  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_alias_info");
	depth++;

	if (!smb_io_unihdr("hdr_als_name", &info->hdr_als_name, ps, depth))
                return False;
	if (!prs_uint32("als_rid", ps, depth, &info->als_rid))
                return False;
	if (!smb_io_bufhdr2("hdr_sec_desc", &info->hdr_sec_desc, ps, depth))
                return False;
	if (!smb_io_unihdr("hdr_als_desc", &info->hdr_als_desc, ps, depth))
                return False;

        if (ps->data_offset + 40 > ps->buffer_size)
                return False;
	ps->data_offset += 40;

	if (!smb_io_unistr2("uni_als_name", &info->uni_als_name,
                            info->hdr_als_name.buffer, ps, depth))
                return False;
	if (!smb_io_buffer4("buf_sec_desc", &info->buf_sec_desc,
                            info->hdr_sec_desc.buffer, ps, depth))
                return False;
	if (!smb_io_unistr2("uni_als_desc", &info->uni_als_desc,
                            info->hdr_als_name.buffer, ps, depth))
                return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_alias_mem_info(const char *desc, SAM_ALIAS_MEM_INFO * info,
				      prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	prs_debug(ps, depth, desc, "net_io_sam_alias_mem_info");
	depth++;

	prs_align(ps);
	if (!prs_uint32("num_members", ps, depth, &info->num_members))
                return False;
	if (!prs_uint32("ptr_members", ps, depth, &info->ptr_members))
                return False;

	if (info->ptr_members != 0)
	{
                if (ps->data_offset + 16 > ps->buffer_size)
                        return False;
                ps->data_offset += 16;

		if (!prs_uint32("num_sids", ps, depth, &info->num_sids))
                        return False;
		if (info->num_sids != info->num_members)
		{
			/* RPC fault */
			return False;
		}

                info->ptr_sids = talloc(ps->mem_ctx, sizeof(uint32) *
                                        info->num_sids);
                
                if (info->ptr_sids == NULL) {
                        DEBUG(0, ("out of memory allocating %d ptr_sids\n",
                                  info->num_sids));
                        return False;
                }

		for (i = 0; i < info->num_sids; i++)
		{
			slprintf(tmp, sizeof(tmp) - 1, "ptr_sids[%02d]", i);
			if (!prs_uint32(tmp, ps, depth, &info->ptr_sids[i]))
                                return False;
		}

                info->sids = talloc(ps->mem_ctx, sizeof(DOM_SID2) *
                                    info->num_sids);

                if (info->sids == NULL) {
                        DEBUG(0, ("error allocating %d sids\n",
                                  info->num_sids));
                        return False;
                }

		for (i = 0; i < info->num_sids; i++)
		{
			if (info->ptr_sids[i] != 0)
			{
				slprintf(tmp, sizeof(tmp) - 1, "sids[%02d]",
					 i);
				if (!smb_io_dom_sid2(tmp, &info->sids[i], 
                                                     ps, depth))
                                        return False;
			}
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL net_io_sam_delta_ctr(const char *desc, uint8 sess_key[16],
				 SAM_DELTA_CTR * delta, uint16 type,
				 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "net_io_sam_delta_ctr");
	depth++;

	switch (type)
        {
                /* Seen in sam deltas */

                case SAM_DELTA_SAM_STAMP:
                {
                        if (!net_io_sam_delta_stamp("", &delta->stamp,
                                                    ps, depth))
                                return False;
                        break;
                }

		case SAM_DELTA_DOMAIN_INFO:
		{
			if (!net_io_sam_domain_info("", &delta->domain_info,
                                                    ps, depth))
                                return False;
			break;
		}
		case SAM_DELTA_GROUP_INFO:
		{
			if (!net_io_sam_group_info("", &delta->group_info,
                                                   ps, depth))
                                return False;
			break;
		}
		case SAM_DELTA_ACCOUNT_INFO:
		{
			if (!net_io_sam_account_info("", sess_key,
                                                     &delta->account_info,
                                                     ps, depth))
                                return False;
			break;
		}
		case SAM_DELTA_GROUP_MEM:
		{
			if (!net_io_sam_group_mem_info("", 
                                                       &delta->grp_mem_info,
                                                       ps, depth))
                                return False;
			break;
		}
		case SAM_DELTA_ALIAS_INFO:
		{
                        if (!net_io_sam_alias_info("", &delta->alias_info,
                                                   ps, depth))
                                return False;
			break;
		}
		case SAM_DELTA_ALIAS_MEM:
		{
			if (!net_io_sam_alias_mem_info("", 
                                                       &delta->als_mem_info,
                                                       ps, depth))
                                return False;
			break;
		}
		default:
		{
			DEBUG(0,
			      ("Replication error: Unknown delta type 0x%x\n",
			       type));
			break;
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_sam_sync(const char *desc, uint8 sess_key[16],
		       NET_R_SAM_SYNC * r_s, prs_struct *ps, int depth)
{
	uint32 i;

	prs_debug(ps, depth, desc, "net_io_r_sam_sync");
	depth++;

	if (!smb_io_cred("srv_creds", &r_s->srv_creds, ps, depth))
                return False;
	if (!prs_uint32("sync_context", ps, depth, &r_s->sync_context))
                return False;

	if (!prs_uint32("ptr_deltas", ps, depth, &r_s->ptr_deltas))
                return False;
	if (r_s->ptr_deltas != 0)
	{
		if (!prs_uint32("num_deltas ", ps, depth, &r_s->num_deltas))
                        return False;
		if (!prs_uint32("ptr_deltas2", ps, depth, &r_s->ptr_deltas2))
                        return False;
		if (r_s->ptr_deltas2 != 0)
		{
			if (!prs_uint32("num_deltas2", ps, depth,
                                        &r_s->num_deltas2))
                                return False;

			if (r_s->num_deltas2 != r_s->num_deltas)
			{
				/* RPC fault */
				return False;
			}

                        if (r_s->num_deltas2 > 0) {
                                r_s->hdr_deltas = (SAM_DELTA_HDR *)
                                        talloc(ps->mem_ctx, r_s->num_deltas2 *
                                               sizeof(SAM_DELTA_HDR));
                          
                                if (r_s->hdr_deltas == NULL) {
                                        DEBUG(0, ("error tallocating memory "
                                                  "for %d delta headers\n", 
                                                  r_s->num_deltas2));
                                        return False;
                                }
                        }

			for (i = 0; i < r_s->num_deltas2; i++)
			{
				if (!net_io_sam_delta_hdr("", 
                                                          &r_s->hdr_deltas[i],
                                                          ps, depth))
                                        return False;
			}

                        if (r_s->num_deltas2 > 0) {
                                r_s->deltas = (SAM_DELTA_CTR *)
                                        talloc(ps->mem_ctx, r_s->num_deltas2 *
                                               sizeof(SAM_DELTA_CTR));

                                if (r_s->deltas == NULL) {
                                        DEBUG(0, ("error tallocating memory "
                                                  "for %d deltas\n", 
                                                  r_s->num_deltas2));
                                        return False;
                                }
                        }

			for (i = 0; i < r_s->num_deltas2; i++)
			{
				if (!net_io_sam_delta_ctr(
                                        "", sess_key, &r_s->deltas[i],
                                        r_s->hdr_deltas[i].type3,
                                        ps, depth)) {
                                        DEBUG(0, ("hmm, failed on i=%d\n", i));
                                        return False;
                                }
			}
		}
	}

	prs_align(ps);
	if (!prs_ntstatus("status", ps, depth, &(r_s->status)))
		return False;

	return True;
}

/*******************************************************************
makes a NET_Q_SAM_DELTAS structure.
********************************************************************/
BOOL init_net_q_sam_deltas(NET_Q_SAM_DELTAS *q_s, const char *srv_name, 
                           const char *cli_name, DOM_CRED *cli_creds, 
                           uint32 database_id, UINT64_S dom_mod_count)
{
	DEBUG(5, ("init_net_q_sam_deltas\n"));

	init_unistr2(&q_s->uni_srv_name, srv_name, strlen(srv_name) + 1);
	init_unistr2(&q_s->uni_cli_name, cli_name, strlen(cli_name) + 1);

	memcpy(&q_s->cli_creds, cli_creds, sizeof(q_s->cli_creds));
	memset(&q_s->ret_creds, 0, sizeof(q_s->ret_creds));

	q_s->database_id = database_id;
        q_s->dom_mod_count.low = dom_mod_count.low;
        q_s->dom_mod_count.high = dom_mod_count.high;
	q_s->max_size = 0xffff;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_q_sam_deltas(const char *desc, NET_Q_SAM_DELTAS *q_s, prs_struct *ps,
                         int depth)
{
	prs_debug(ps, depth, desc, "net_io_q_sam_deltas");
	depth++;

	if (!smb_io_unistr2("", &q_s->uni_srv_name, True, ps, depth))
                return False;
	if (!smb_io_unistr2("", &q_s->uni_cli_name, True, ps, depth))
                return False;

	if (!smb_io_cred("", &q_s->cli_creds, ps, depth))
                return False;
	if (!smb_io_cred("", &q_s->ret_creds, ps, depth))
                return False;

	if (!prs_uint32("database_id  ", ps, depth, &q_s->database_id))
                return False;
        if (!prs_uint64("dom_mod_count", ps, depth, &q_s->dom_mod_count))
                return False;
	if (!prs_uint32("max_size", ps, depth, &q_s->max_size))
                return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL net_io_r_sam_deltas(const char *desc, uint8 sess_key[16],
                         NET_R_SAM_DELTAS *r_s, prs_struct *ps, int depth)
{
        int i;

	prs_debug(ps, depth, desc, "net_io_r_sam_deltas");
	depth++;

	if (!smb_io_cred("srv_creds", &r_s->srv_creds, ps, depth))
                return False;
        if (!prs_uint64("dom_mod_count", ps, depth, &r_s->dom_mod_count))
                return False;

	if (!prs_uint32("ptr_deltas", ps, depth, &r_s->ptr_deltas))
                return False;
	if (!prs_uint32("num_deltas", ps, depth, &r_s->num_deltas))
                return False;
	if (!prs_uint32("ptr_deltas2", ps, depth, &r_s->num_deltas2))
                return False;

	if (r_s->num_deltas2 != 0)
	{
		if (!prs_uint32("num_deltas2 ", ps, depth, &r_s->num_deltas2))
                        return False;

		if (r_s->ptr_deltas != 0)
		{
                        if (r_s->num_deltas > 0) {
                                r_s->hdr_deltas = (SAM_DELTA_HDR *)
                                        talloc(ps->mem_ctx, r_s->num_deltas *
                                               sizeof(SAM_DELTA_HDR));
                                if (r_s->hdr_deltas == NULL) {
                                        DEBUG(0, ("error tallocating memory "
                                                  "for %d delta headers\n", 
                                                  r_s->num_deltas));
                                        return False;
                                }
                        }

			for (i = 0; i < r_s->num_deltas; i++)
			{
				net_io_sam_delta_hdr("", &r_s->hdr_deltas[i],
                                                      ps, depth);
			}
                        
                        if (r_s->num_deltas > 0) {
                                r_s->deltas = (SAM_DELTA_CTR *)
                                        talloc(ps->mem_ctx, r_s->num_deltas *
                                               sizeof(SAM_DELTA_CTR));

                                if (r_s->deltas == NULL) {
                                        DEBUG(0, ("error tallocating memory "
                                                  "for %d deltas\n", 
                                                  r_s->num_deltas));
                                        return False;
                                }
                        }

			for (i = 0; i < r_s->num_deltas; i++)
			{
				if (!net_io_sam_delta_ctr(
                                        "", sess_key,
                                        &r_s->deltas[i],
                                        r_s->hdr_deltas[i].type2,
                                        ps, depth))
                                        
                                        return False;
			}
		}
	}

	prs_align(ps);
	if (!prs_ntstatus("status", ps, depth, &r_s->status))
                return False;

	return True;
}
