/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Jeremy Allison                    1998,
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
#include "nterr.h"
#include "sids.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

extern pstring global_myname;

/*************************************************************************
 api_net_req_chal
 *************************************************************************/
static BOOL api_net_req_chal(rpcsrv_struct * p,
			     prs_struct * data, prs_struct * rdata)
{
	NET_Q_REQ_CHAL q_r;
	NET_R_REQ_CHAL r_c;

	ZERO_STRUCT(q_r);
	ZERO_STRUCT(r_c);

	/* grab the challenge... */
	if (!net_io_q_req_chal("", &q_r, data, 0))
	{
		return False;
	}

	r_c.status = _net_req_chal(&q_r.uni_logon_srv, &q_r.uni_logon_clnt,
				   &q_r.clnt_chal, &r_c.srv_chal, p->key.pid);

	/* store the response in the SMB stream */
	return net_io_r_req_chal("", &r_c, rdata, 0);
}

/*************************************************************************
 api_net_auth
 *************************************************************************/
static BOOL api_net_auth(rpcsrv_struct * p,
			 prs_struct * data, prs_struct * rdata)
{
	NET_Q_AUTH q_a;
	NET_R_AUTH r_a;

	ZERO_STRUCT(q_a);
	ZERO_STRUCT(r_a);

	/* grab the challenge... */
	if (!net_io_q_auth("", &q_a, data, 0))
	{
		return False;
	}

	r_a.status =
		_net_auth(&q_a.clnt_id, &q_a.clnt_chal, &r_a.srv_chal,
			  p->key.pid);

	/* store the response in the SMB stream */
	return net_io_r_auth("", &r_a, rdata, 0);
}

/*************************************************************************
 api_net_auth_2
 *************************************************************************/
static BOOL api_net_auth_2(rpcsrv_struct * p,
			   prs_struct * data, prs_struct * rdata)
{
	NET_Q_AUTH_2 q_a;
	NET_R_AUTH_2 r_a;

	ZERO_STRUCT(q_a);
	ZERO_STRUCT(r_a);

	/* grab the challenge... */
	if (!net_io_q_auth_2("", &q_a, data, 0))
	{
		return False;
	}

	r_a.status =
		_net_auth_2(&q_a.clnt_id, &q_a.clnt_chal, &q_a.clnt_flgs,
			    &r_a.srv_chal, &r_a.srv_flgs, p->key.pid);

	/* store the response in the SMB stream */
	return net_io_r_auth_2("", &r_a, rdata, 0);
}

/*************************************************************************
 api_net_srv_pwset
 *************************************************************************/
static BOOL api_net_srv_pwset(rpcsrv_struct * p,
			      prs_struct * data, prs_struct * rdata)
{
	NET_Q_SRV_PWSET q_a;
	NET_R_SRV_PWSET r_s;

	ZERO_STRUCT(q_a);
	ZERO_STRUCT(r_s);

	/* grab the challenge and encrypted password ... */
	if (!net_io_q_srv_pwset("", &q_a, data, 0))
	{
		return False;
	}

	r_s.status =
		_net_srv_pwset(&q_a.clnt_id, q_a.pwd, &r_s.srv_cred,
			       p->key.pid);

	/* store the response in the SMB stream */
	return net_io_r_srv_pwset("", &r_s, rdata, 0);
}

/*************************************************************************
 api_net_sam_logoff
 *************************************************************************/
static BOOL api_net_sam_logoff(rpcsrv_struct * p,
			       prs_struct * data, prs_struct * rdata)
{
	NET_Q_SAM_LOGOFF q_l;
	NET_R_SAM_LOGOFF r_s;
	NET_ID_INFO_CTR ctr;
	DOM_CRED srv_cred;
	uint32 status;

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(r_s);

	/* the DOM_ID_INFO_1 structure is a bit big.  plus we might want to
	   dynamically allocate it inside net_io_q_sam_logon, at some point */
	q_l.sam_id.ctr = &ctr;

	/* grab the challenge... */
	if (!net_io_q_sam_logoff("", &q_l, data, 0))
	{
		return False;
	}

	status = _net_sam_logoff(&q_l.sam_id, &srv_cred, p->key.pid);
	make_r_sam_logoff(&r_s, &srv_cred, status);

	/* store the response in the SMB stream */
	return net_io_r_sam_logoff("", &r_s, rdata, 0);
}

/*************************************************************************
 api_net_sam_sync
 *************************************************************************/
static BOOL api_net_sam_sync(rpcsrv_struct * p,
			     prs_struct * data, prs_struct * rdata)
{
	NET_Q_SAM_SYNC q_s;
	NET_R_SAM_SYNC r_s;
	DOM_CRED srv_creds;
	uint32 num_deltas;
	uint32 num_deltas2;
	SAM_DELTA_HDR hdr_deltas[MAX_SAM_DELTAS];
	SAM_DELTA_CTR deltas[MAX_SAM_DELTAS];
	uint32 status;

	struct dcinfo dc;
	ZERO_STRUCT(dc);
	ZERO_STRUCT(srv_creds);

	/* grab the challenge... */
	if (!net_io_q_sam_sync("", &q_s, data, 0))
	{
		return False;
	}

	status = _net_sam_sync(&q_s.uni_srv_name,
				       &q_s.uni_cli_name,
				       &q_s.cli_creds,
				       &srv_creds,
				       q_s.database_id,
				       q_s.restart_state,
				       &q_s.sync_context,
				       q_s.max_size,
				       &num_deltas,
				       &num_deltas2, hdr_deltas, deltas,
				       p->key.pid);

	make_r_sam_sync(&r_s, &srv_creds,
			q_s.sync_context,
			num_deltas, num_deltas2, hdr_deltas, deltas, status);

	/* store the response in the SMB stream */
	return net_io_r_sam_sync("", dc.sess_key, &r_s, rdata, 0);
}

/*************************************************************************
 api_net_sam_logon
 *************************************************************************/
static BOOL api_net_sam_logon(rpcsrv_struct * p,
			      prs_struct * data, prs_struct * rdata)
{
	NET_Q_SAM_LOGON q_l;
	NET_R_SAM_LOGON r_s;
	NET_ID_INFO_CTR ctr;
	DOM_CRED srv_creds;
	NET_USER_INFO_CTR uctr;
	uint32 status;
	BOOL ret;

	ZERO_STRUCT(uctr);
	ZERO_STRUCT(q_l);
	ZERO_STRUCT(r_s);

	q_l.sam_id.ctr = &ctr;
	if (!net_io_q_sam_logon("", &q_l, data, 0))
	{
		return False;
	}

	status = _net_sam_logon(&q_l.sam_id,
				q_l.validation_level,
				&srv_creds, &uctr, p->key.pid,
				&r_s.auth_resp);
	make_r_sam_logon(&r_s, &srv_creds, q_l.validation_level,
			 status == NT_STATUS_NOPROBLEMO ? uctr.usr.id : NULL,
			 status);

	/* store the response in the SMB stream */
	ret = net_io_r_sam_logon("", &r_s, rdata, 0);
	free_net_user_info_ctr(&uctr);
	return ret;
}

/*************************************************************************
 api_net_trust_dom_list
 *************************************************************************/
static BOOL api_net_trust_dom_list(rpcsrv_struct * p,
				   prs_struct * data, prs_struct * rdata)
{
	NET_Q_TRUST_DOM_LIST q_t;
	NET_R_TRUST_DOM_LIST r_t;

	ZERO_STRUCT(q_t);
	ZERO_STRUCT(r_t);

	/* grab the lsa trusted domain list query... */
	if (!net_io_q_trust_dom("", &q_t, data, 0))
	{
		return False;
	}

	r_t.status = _net_trust_dom_list(&q_t.uni_server_name,
					 q_t.function_code,
					 &r_t.uni_trust_dom_name);

	/* store the response in the SMB stream */
	return net_io_r_trust_dom("", &r_t, rdata, 0);
}

/*************************************************************************
 api_net_logon_ctrl2
 *************************************************************************/
static BOOL api_net_logon_ctrl2(rpcsrv_struct * p,
				prs_struct * data, prs_struct * rdata)
{
	NET_Q_LOGON_CTRL2 q_l;
	NET_R_LOGON_CTRL2 r_l;

	NETLOGON_INFO logon_info;
	uint32 switch_value;
	uint32 status;

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(r_l);

	/* grab the lsa netlogon ctrl2 query... */
	if (!net_io_q_logon_ctrl2("", &q_l, data, 0))
	{
		return False;
	}

	status = _net_logon_ctrl2(&q_l.uni_server_name,
				  q_l.function_code,
				  q_l.query_level,
				  q_l.switch_value,
				  &switch_value, &logon_info);
	make_r_logon_ctrl2(&r_l, switch_value, &logon_info, status);

	/* store the response in the SMB stream */
	return net_io_r_logon_ctrl2("", &r_l, rdata, 0);
}

/*******************************************************************
 array of \PIPE\NETLOGON operations
 ********************************************************************/
static const struct api_struct api_net_cmds[] = {
	{"NET_REQCHAL", NET_REQCHAL, api_net_req_chal},
	{"NET_AUTH", NET_AUTH, api_net_auth},
	{"NET_AUTH2", NET_AUTH2, api_net_auth_2},
	{"NET_SRVPWSET", NET_SRVPWSET, api_net_srv_pwset},
	{"NET_SAMLOGON", NET_SAMLOGON, api_net_sam_logon},
	{"NET_SAMLOGOFF", NET_SAMLOGOFF, api_net_sam_logoff},
	{"NET_LOGON_CTRL2", NET_LOGON_CTRL2, api_net_logon_ctrl2},
	{"NET_TRUST_DOM_LIST", NET_TRUST_DOM_LIST, api_net_trust_dom_list},
	{"NET_SAM_SYNC", NET_SAM_SYNC, api_net_sam_sync},
	{NULL, 0, NULL}
};

/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
BOOL api_netlog_rpc(rpcsrv_struct * p)
{
	return api_rpcTNP(p, "api_netlog_rpc", api_net_cmds);
}
