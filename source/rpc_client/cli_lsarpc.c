
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
 obtain the sid from the PDC.  do some verification along the way...
****************************************************************************/
BOOL get_domain_sids(const char *domain, DOM_SID *sid3, DOM_SID *sid5)
{
	POLICY_HND pol;
	fstring srv_name;
	struct cli_connection *con = NULL;
	BOOL res = True;
	BOOL res1 = True;
	fstring dom3;
	fstring dom5;

	if (sid3 == NULL && sid5 == NULL)
	{
		/* don't waste my time... */
		return False;
	}

	if (!get_any_dc_name(domain, srv_name))
	{
		return False;
	}

	/*
	 * Ok - we have an anonymous connection to the IPC$ share.
	 * Now start the NT Domain stuff :-).
	 */

	fstrcpy(dom3, "");
	fstrcpy(dom5, "");
	if (sid3 != NULL)
	{
		ZERO_STRUCTP(sid3);
	}
	if (sid5 != NULL)
	{
		ZERO_STRUCTP(sid5);
	}

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name, &pol, False, 0x02000000) : False;

	if (sid3 != NULL)
	{
		/* send client info query, level 3.  receive domain name and sid */
		res1 = res ? lsa_query_info_pol(&pol, 3, dom3, sid3) : False;
	}

	if (sid5 != NULL)
	{
		/* send client info query, level 5.  receive domain name and sid */
		res1 = res1 ? lsa_query_info_pol(&pol, 5, dom5, sid5) : False;
	}

	/* close policy handle */
	res = res ? lsa_close(&pol) : False;

	/* close the session */
	cli_connection_unlink(con);

	if (res1)
	{
		pstring sid;
		DEBUG(2,("LSA Query Info Policy\n"));
		if (sid3 != NULL)
		{
			sid_to_string(sid, sid3);
			DEBUG(2,("Domain Member     - Domain: %s SID: %s\n", dom3, sid));
		}
		if (sid5 != NULL)
		{
			sid_to_string(sid, sid5);
			DEBUG(2,("Domain Controller - Domain: %s SID: %s\n", dom5, sid));
		}
	}
	else
	{
		DEBUG(1,("lsa query info failed\n"));
	}

	return res;
}

#if 0
/****************************************************************************
 obtain a sid and domain name from a Domain Controller.  
****************************************************************************/
BOOL get_trust_sid_and_domain(const char* myname, char *server,
				DOM_SID *sid,
				char *domain, size_t len)
{
	POLICY_HND pol;
	fstring srv_name;
	struct cli_connection *con = NULL;
	BOOL res = True;
	BOOL res1 = True;
	DOM_SID sid3;
	DOM_SID sid5;
	fstring dom3;
	fstring dom5;

	if (!cli_connection_init_list(server, PIPE_LSARPC, &con))
	{
		DEBUG(0,("get_trust_sid: unable to initialise client connection.\n"));
		return False;
	}

	fstrcpy(dom3, "");
	fstrcpy(dom5, "");
	ZERO_STRUCT(sid3);
	ZERO_STRUCT(sid5);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, myname);
	strupper(srv_name);

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name, &pol, False, 0x02000000) : False;

	/* send client info query, level 3.  receive domain name and sid */
	res1 = res ? lsa_query_info_pol(&pol, 3, dom3, &sid3) : False;

	/* send client info query, level 5.  receive domain name and sid */
	res1 = res1 ? lsa_query_info_pol(&pol, 5, dom5, &sid5) : False;

	/* close policy handle */
	res = res ? lsa_close(&pol) : False;

	/* close the session */
	cli_connection_unlink(con);

	if (res1)
	{
		pstring sid_str;
		DEBUG(2,("LSA Query Info Policy\n"));
		sid_to_string(sid_str, &sid3);
		DEBUG(2,("Domain Member     - Domain: %s SID: %s\n",
		          dom3, sid_str));
		sid_to_string(sid_str, &sid5);
		DEBUG(2,("Domain Controller - Domain: %s SID: %s\n",
		          dom5, sid_str));

		if (dom5[0] != 0 && sid_equal(&sid3, &sid5))
		{
			safe_strcpy(domain, dom5, len);
			sid_copy(sid, &sid5);
		}
		else
		{
			DEBUG(2,("Server %s is not a PDC\n", server));
			return False;
		}

	}
	else
	{
		DEBUG(1,("lsa query info failed\n"));
	}

	return res1;
}
#endif

/****************************************************************************
do a LSA Open Policy
****************************************************************************/
BOOL lsa_open_policy(const char *system_name, POLICY_HND *hnd,
			BOOL sec_qos, uint32 des_access)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_OPEN_POL q_o;
	LSA_SEC_QOS qos;
	BOOL valid_pol = False;
	struct cli_connection *con = NULL;

	if (!cli_connection_init(system_name, PIPE_LSARPC, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4,("LSA Open Policy\n"));

	/* store the parameters */
	if (sec_qos)
	{
		make_lsa_sec_qos(&qos, 2, 1, 0, des_access);
		make_q_open_pol(&q_o, 0x5c, 0, des_access, &qos);
	}
	else
	{
		make_q_open_pol(&q_o, 0x5c, 0, des_access, NULL);
	}

	/* turn parameters into data stream */
	lsa_io_q_open_pol("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, LSA_OPENPOLICY, &buf, &rbuf))
	{
		LSA_R_OPEN_POL r_o;
		BOOL p;

		lsa_io_r_open_pol("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENPOLICY: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.pol.data, sizeof(hnd->data));
			
			valid_pol = register_policy_hnd(get_global_hnd_cache(),
			                                cli_con_sec_ctx(con),
			                                hnd, des_access) &&
			            set_policy_con(get_global_hnd_cache(),
			                                 hnd, con, 
			                                 cli_connection_unlink);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_pol;
}

/****************************************************************************
do a LSA Open Policy2
****************************************************************************/
BOOL lsa_open_policy2( const char *system_name, POLICY_HND *hnd,
			BOOL sec_qos, uint32 des_access)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_OPEN_POL2 q_o;
	LSA_SEC_QOS qos;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(system_name, PIPE_LSARPC, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_OPENPOLICY2 */

	DEBUG(4,("LSA Open Policy2\n"));

	/* store the parameters */
	if (sec_qos)
	{
		make_lsa_sec_qos(&qos, 2, 1, 0, des_access);
		make_q_open_pol2(&q_o, system_name, 0, des_access, &qos);
	}
	else
	{
		make_q_open_pol2(&q_o, system_name, 0, des_access, NULL);
	}

	/* turn parameters into data stream */
	lsa_io_q_open_pol2("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, LSA_OPENPOLICY2, &buf, &rbuf))
	{
		LSA_R_OPEN_POL2 r_o;
		BOOL p;

		lsa_io_r_open_pol2("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENPOLICY2: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.pol.data, sizeof(hnd->data));

			valid_pol = register_policy_hnd(get_global_hnd_cache(),
			                                cli_con_sec_ctx(con),
			                                hnd, des_access) &&
			            set_policy_con(get_global_hnd_cache(),
			                                 hnd, con, 
			                                 cli_connection_unlink);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_pol;
}

/****************************************************************************
do a LSA Create Secret
****************************************************************************/
BOOL lsa_create_secret( const POLICY_HND *hnd,
				const char *secret_name,
				uint32 des_access,
				POLICY_HND *hnd_secret)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_CREATE_SECRET q_o;
	BOOL valid_pol = False;

	if (hnd == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_CREATE_SECRET */

	DEBUG(4,("LSA Create Secret\n"));

	make_q_create_secret(&q_o, hnd, secret_name, des_access);

	/* turn parameters into data stream */
	lsa_io_q_create_secret("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_CREATESECRET, &buf, &rbuf))
	{
		LSA_R_CREATE_SECRET r_o;
		BOOL p;

		lsa_io_r_create_secret("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENSECRET: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd_secret, r_o.pol.data, sizeof(hnd_secret->data));
			valid_pol = cli_pol_link(hnd_secret, hnd);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_pol;
}

/****************************************************************************
do a LSA Open Secret
****************************************************************************/
BOOL lsa_open_secret( const POLICY_HND *hnd,
				const char *secret_name,
				uint32 des_access,
				POLICY_HND *hnd_secret)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_OPEN_SECRET q_o;
	BOOL valid_pol = False;

	if (hnd == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_OPENSECRET */

	DEBUG(4,("LSA Open Secret\n"));

	make_q_open_secret(&q_o, hnd, secret_name, des_access);

	/* turn parameters into data stream */
	lsa_io_q_open_secret("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_OPENSECRET, &buf, &rbuf))
	{
		LSA_R_OPEN_SECRET r_o;
		BOOL p;

		lsa_io_r_open_secret("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENSECRET: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd_secret, r_o.pol.data, sizeof(hnd_secret->data));
			valid_pol = cli_pol_link(hnd_secret, hnd);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_pol;
}

/****************************************************************************
do a LSA Set Secret
****************************************************************************/
uint32 lsa_set_secret(POLICY_HND *hnd, const STRING2 *secret)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_SET_SECRET q_q;

	uchar sess_key[16];
	uint32 status = NT_STATUS_NOPROBLEMO;

	if (hnd == NULL) return NT_STATUS_INVALID_PARAMETER;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_SETSECRET */

	DEBUG(4,("LSA Set Secret\n"));

	memcpy(&q_q.pol, hnd, sizeof(q_q.pol));
	q_q.unknown = 0x0;
	q_q.value.ptr_secret = 0x1;
	make_strhdr2(&q_q.value.hdr_secret, secret->str_str_len,
	                                    secret->str_max_len, 1);

	if (!cli_get_usr_sesskey(hnd, sess_key))
	{
		return NT_STATUS_INVALID_PARAMETER;
	}
	dump_data_pw("sess_key:", sess_key, 16);
	if (!nt_encrypt_string2(&q_q.value.enc_secret, secret, sess_key))
	{
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* turn parameters into data stream */
	lsa_io_q_set_secret("", &q_q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_SETSECRET, &buf, &rbuf))
	{
		LSA_R_SET_SECRET r_q;
		BOOL p;

		lsa_io_r_set_secret("", &r_q, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_SETSECRET: %s\n", get_nt_error_msg(r_q.status)));
			status = NT_STATUS_INVALID_PARAMETER;
		}
		else
		{
			status = r_q.status;
		}
	}
	else
	{

		status = NT_STATUS_INVALID_PARAMETER;
	}
	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return status;
}

/****************************************************************************
do a LSA Query Secret
****************************************************************************/
BOOL lsa_query_secret(POLICY_HND *hnd, STRING2 *secret,
		      NTTIME *last_update)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_QUERY_SECRET q_q;
	BOOL valid_info = False;

	if (hnd == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_QUERYSECRET */

	DEBUG(4,("LSA Query Secret\n"));

	make_q_query_secret(&q_q, hnd);

	/* turn parameters into data stream */
	lsa_io_q_query_secret("", &q_q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_QUERYSECRET, &buf, &rbuf))
	{
		LSA_R_QUERY_SECRET r_q;
		BOOL p;

		lsa_io_r_query_secret("", &r_q, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_QUERYSECRET: %s\n", get_nt_error_msg(r_q.status)));
			p = False;
		}

		if (p && (r_q.info.ptr_value != 0) &&
		    (r_q.info.value.ptr_secret != 0) &&
		    (r_q.info.ptr_update != 0))
		{
			uchar sess_key[16];
			STRING2 enc_secret;
			memcpy(&enc_secret,  &(r_q.info.value.enc_secret), sizeof(STRING2));
			memcpy(last_update, &(r_q.info.last_update),      sizeof(NTTIME));
			if (!cli_get_usr_sesskey(hnd, sess_key))
			{
				return False;
			}
			dump_data_pw("sess key:", sess_key, 16);
			valid_info = nt_decrypt_string2(secret, &enc_secret,
			             sess_key);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_info;
}


/****************************************************************************
do a LSA Lookup Names
****************************************************************************/
BOOL lsa_lookup_names( POLICY_HND *hnd,
			int num_names,
			char **names,
			DOM_SID **sids,
			uint32 **types,
			int *num_sids)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_LOOKUP_NAMES q_l;
	BOOL valid_response = False;

	if (hnd == NULL || num_sids == 0 || sids == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_LOOKUP_NAMES */

	DEBUG(4,("LSA Lookup NAMEs\n"));

	/* store the parameters */
	make_q_lookup_names(&q_l, hnd, num_names, names);

	/* turn parameters into data stream */
	lsa_io_q_lookup_names("", &q_l, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_LOOKUPNAMES, &buf, &rbuf))
	{
		LSA_R_LOOKUP_NAMES r_l;
		DOM_R_REF ref;
		DOM_RID2 t_rids[MAX_LOOKUP_SIDS];
		BOOL p;

		ZERO_STRUCT(ref);
		ZERO_STRUCT(t_rids);

		r_l.dom_ref = &ref;
		r_l.dom_rid = t_rids;

		lsa_io_r_lookup_names("", &r_l, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_l.status != 0)
		{
			/* report error code */
			DEBUG(1,("LSA_LOOKUP_NAMES: %s\n", get_nt_error_msg(r_l.status)));
			p = False;
		}

		if (p)
		{
			if (r_l.ptr_dom_ref != 0 && r_l.ptr_entries != 0)
			{
				valid_response = True;
			}
		}

		if (num_sids != NULL && valid_response)
		{
			(*num_sids) = r_l.num_entries;
		}
		if (valid_response)
		{
			uint32 i;
			for (i = 0; i < r_l.num_entries; i++)
			{
				if (t_rids[i].rid_idx >= ref.num_ref_doms_1 &&
				    t_rids[i].rid_idx != 0xffffffff)
				{
					DEBUG(0,("LSA_LOOKUP_NAMES: domain index %d out of bounds\n",
					          t_rids[i].rid_idx));
					valid_response = False;
					break;
				}
			}
		}

		if (types != NULL && valid_response && r_l.num_entries != 0)
		{
			(*types) = (uint32*)malloc((*num_sids) * sizeof(uint32));
		}

		if (sids != NULL && valid_response && r_l.num_entries != 0)
		{
			(*sids) = (DOM_SID*)malloc((*num_sids) * sizeof(DOM_SID));
		}

		if (sids != NULL && (*sids) != NULL)
		{
			int i;
			/* take each name, construct a SID */
			for (i = 0; i < (*num_sids); i++)
			{
				uint32 dom_idx = t_rids[i].rid_idx;
				uint32 dom_rid = t_rids[i].rid;
				DOM_SID *sid = &(*sids)[i];
				if (dom_idx != 0xffffffff)
				{
					sid_copy(sid, &ref.ref_dom[dom_idx].ref_dom.sid);
					if (dom_rid != 0xffffffff)
					{
						sid_append_rid(sid, dom_rid);
					}
					if (types != NULL && (*types) != NULL)
					{
						(*types)[i] = t_rids[i].type;
					}
				}
				else
				{
					ZERO_STRUCTP(sid);
					if (types != NULL && (*types) != NULL)
					{
						(*types)[i] = SID_NAME_UNKNOWN;
					}
				}
			}
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Lookup SIDs
****************************************************************************/
BOOL lsa_lookup_sids(POLICY_HND *hnd,
			int num_sids,
			DOM_SID **sids,
			char ***names,
			uint32 **types,
			int *num_names)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_LOOKUP_SIDS q_l;
	BOOL valid_response = False;

	ZERO_STRUCT(q_l);

	if (hnd == NULL || num_sids == 0 || sids == NULL) return False;

	if (num_names != NULL)
	{
		*num_names = 0;
	}
	if (types != NULL)
	{
		*types = NULL;
	}
	if (names != NULL)
	{
		*names = NULL;
	}

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_LOOKUP_SIDS */

	DEBUG(4,("LSA Lookup SIDs\n"));

	/* store the parameters */
	make_q_lookup_sids(&q_l, hnd, num_sids, sids, 1);

	/* turn parameters into data stream */
	lsa_io_q_lookup_sids("", &q_l, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_LOOKUPSIDS, &buf, &rbuf))
	{
		LSA_R_LOOKUP_SIDS r_l;
		DOM_R_REF ref;
		LSA_TRANS_NAME_ENUM t_names;
		BOOL p;

		r_l.dom_ref = &ref;
		r_l.names   = &t_names;

		lsa_io_r_lookup_sids("", &r_l, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_l.status != 0 &&
		         r_l.status != 0x107 &&
		         r_l.status != (0xC0000000 | NT_STATUS_NONE_MAPPED))
		{
			/* report error code */
			DEBUG(1,("LSA_LOOKUP_SIDS: %s\n", get_nt_error_msg(r_l.status)));
			p = False;
		}

		if (p)
		{
			if (t_names.ptr_trans_names != 0 && r_l.ptr_dom_ref != 0)
			{
				valid_response = True;
			}
		}

		if (num_names != NULL && valid_response)
		{
			(*num_names) = t_names.num_entries;
		}
		if (valid_response)
		{
			uint32 i;
			for (i = 0; i < t_names.num_entries; i++)
			{
				if (t_names.name[i].domain_idx >= ref.num_ref_doms_1)
				{
					DEBUG(0,("LSA_LOOKUP_SIDS: domain index out of bounds\n"));
					valid_response = False;
					break;
				}
			}
		}

		if (types != NULL && valid_response && (*num_names) != 0)
		{
			(*types) = (uint32*)malloc((*num_names) * sizeof(uint32));
		}

		if (names != NULL && valid_response && (*num_names) != 0)
		{
			(*names) = (char**)malloc((*num_names) * sizeof(char*));
		}

		if (names != NULL && (*names) != NULL)
		{
			int i;
			/* take each name, construct a \DOMAIN\name string */
			for (i = 0; i < (*num_names); i++)
			{
				fstring name;
				fstring dom_name;
				fstring full_name;
				uint32 dom_idx = t_names.name[i].domain_idx;

				if (dom_idx != 0xffffffff)
				{
					unistr2_to_ascii(dom_name, &ref.ref_dom[dom_idx].uni_dom_name, sizeof(dom_name)-1);
					unistr2_to_ascii(name, &t_names.uni_name[i], sizeof(name)-1);
					
					memset(full_name, 0, sizeof(full_name));

					slprintf(full_name, sizeof(full_name)-1, "%s\\%s",
						 dom_name, name);

					(*names)[i] = strdup(full_name);
					if (types != NULL && (*types) != NULL)
					{
						(*types)[i] = t_names.name[i].sid_name_use;
					}
				}
				else
				{
					(*names)[i] = NULL;
					if (types != NULL && (*types) != NULL)
					{
						(*types)[i] = SID_NAME_UNKNOWN;
					}
				}
			}
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Query Info Policy
****************************************************************************/
BOOL lsa_query_info_pol(POLICY_HND *hnd, uint16 info_class,
			fstring domain_name, DOM_SID *domain_sid)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_QUERY_INFO q_q;
	BOOL valid_response = False;

	ZERO_STRUCTP(domain_sid);
	domain_name[0] = 0;

	if (hnd == NULL || domain_name == NULL || domain_sid == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_QUERYINFOPOLICY */

	DEBUG(4,("LSA Query Info Policy\n"));

	/* store the parameters */
	make_q_query(&q_q, hnd, info_class);

	/* turn parameters into data stream */
	lsa_io_q_query("", &q_q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_QUERYINFOPOLICY, &buf, &rbuf))
	{
		LSA_R_QUERY_INFO r_q;
		BOOL p;

		lsa_io_r_query("", &r_q, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_QUERYINFOPOLICY: %s\n", get_nt_error_msg(r_q.status)));
			p = False;
		}

		if (p && r_q.info_class != q_q.info_class)
		{
			/* report different info classes */
			DEBUG(0,("LSA_QUERYINFOPOLICY: error info_class (q,r) differ - (%x,%x)\n",
					q_q.info_class, r_q.info_class));
			p = False;
		}

		if (p)
		{
			fstring sid_str;
			/* ok, at last: we're happy. */
			switch (r_q.info_class)
			{
				case 3:
				{
					if (r_q.dom.id3.buffer_dom_name != 0)
					{
						unistr2_to_ascii(domain_name, &r_q.dom.id3.uni_domain_name, sizeof(fstring)-1);
					}
					if (r_q.dom.id3.buffer_dom_sid != 0)
					{
						*domain_sid = r_q.dom.id3.dom_sid.sid;
					}

					valid_response = True;
					break;
				}
				case 5:
				{
					if (r_q.dom.id5.buffer_dom_name != 0)
					{
						unistr2_to_ascii(domain_name, &r_q.dom.id5.uni_domain_name, sizeof(fstring)-1);
					}
					if (r_q.dom.id5.buffer_dom_sid != 0)
					{
						*domain_sid = r_q.dom.id5.dom_sid.sid;
					}

					valid_response = True;
					break;
				}
				default:
				{
					DEBUG(3,("LSA_QUERYINFOPOLICY: unknown info class\n"));
					domain_name[0] = 0;

					break;
				}
			}
		
			sid_to_string(sid_str, domain_sid);
			DEBUG(3,("LSA_QUERYINFOPOLICY (level %x): domain:%s  domain sid:%s\n",
			          r_q.info_class, domain_name, sid_str));
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Enumerate Trusted Domain 
****************************************************************************/
BOOL lsa_enum_trust_dom(POLICY_HND *hnd, uint32 *enum_ctx,
			uint32 *num_doms, char ***names,
			DOM_SID ***sids)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_ENUM_TRUST_DOM q_q;
	BOOL valid_response = False;

	if (hnd == NULL || num_doms == NULL || names == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	/* create and send a MSRPC command with api LSA_ENUMTRUSTDOM */

	DEBUG(4,("LSA Enum Trusted Domains\n"));

	/* store the parameters */
	make_q_enum_trust_dom(&q_q, hnd, *enum_ctx, 0xffffffff);

	/* turn parameters into data stream */
	lsa_io_q_enum_trust_dom("", &q_q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_ENUMTRUSTDOM, &buf, &rbuf))
	{
		LSA_R_ENUM_TRUST_DOM r_q;
		BOOL p;

		lsa_io_r_enum_trust_dom("", &r_q, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_ENUMTRUSTDOM: %s\n", get_nt_error_msg(r_q.status)));
			p = r_q.status == 0x8000001a;
		}

		if (p)
		{
			uint32 i;
			uint32 num_sids = 0;
			valid_response = True;

			for (i = 0; i < r_q.num_domains; i++)
			{
				fstring tmp;
				unistr2_to_ascii(tmp, &r_q.uni_domain_name[i],
				                 sizeof(tmp)-1);
				add_chars_to_array(num_doms, names, tmp);
				add_sid_to_array(&num_sids, sids,
				                 &r_q.domain_sid[i].sid);
			}

			if (r_q.status == NT_STATUS_NOPROBLEMO)
			{
				*enum_ctx = r_q.enum_context;
			}
			else
			{
				*enum_ctx = 0;
			}
		}

		lsa_free_r_enum_trust_dom(&r_q);
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Close
****************************************************************************/
BOOL lsa_close(POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_CLOSE q_c;
	BOOL valid_close = False;

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0   , 4, True );

	DEBUG(4,("LSA Close\n"));

	/* store the parameters */
	make_lsa_q_close(&q_c, hnd);

	/* turn parameters into data stream */
	lsa_io_q_close("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, LSA_CLOSE, &buf, &rbuf))
	{
		LSA_R_CLOSE r_c;
		BOOL p;

		lsa_io_r_close("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_CLOSE: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			/* check that the returned policy handle is all zeros */
			uint32 i;
			valid_close = True;

			for (i = 0; i < sizeof(r_c.pol.data); i++)
			{
				if (r_c.pol.data[i] != 0)
				{
					valid_close = False;
					break;
				}
			}	
			if (!valid_close)
			{
				DEBUG(0,("LSA_CLOSE: non-zero handle returned\n"));
			}
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	close_policy_hnd(get_global_hnd_cache(), hnd);

	return valid_close;
}

