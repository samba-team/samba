/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   Copyright (C) Andrew Tridgell              1992-1997,2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997,2000,
   Copyright (C) Paul Ashton                       1997,2000,
   Copyright (C) Elrond                                 2000.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/** @defgroup lsa LSA - Local Security Architecture
 *  @ingroup rpc_client
 *
 * @{
 **/

/**
 * @file cli_lsarpc.c
 *
 * RPC client routines for the LSA RPC pipe.  LSA means "local
 * security authority", which is half of a password database.
 **/

/** Opens a SMB connection and connects to the LSARPC pipe.
 *
 * @param cli Uninitialised client handle.
 * @param system_name NETBIOS name of the machine to connect to.
 * @param creds User credentials to connect as.
 * @returns Initialised client handle.
 */
struct cli_state *cli_lsa_initialise(struct cli_state *cli, char *system_name,
				     struct ntuser_creds *creds)
{
        return cli_pipe_initialise(cli, system_name, PIPE_LSARPC, creds);
}

/** Open a LSA policy handle
 *
 * @param cli Handle on an initialised SMB connection */

NTSTATUS cli_lsa_open_policy(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             BOOL sec_qos, uint32 des_access, POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	LSA_Q_OPEN_POL q;
	LSA_R_OPEN_POL r;
	LSA_SEC_QOS qos;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	if (sec_qos) {
		init_lsa_sec_qos(&qos, 2, 1, 0);
		init_q_open_pol(&q, '\\', 0, des_access, &qos);
	} else {
		init_q_open_pol(&q, '\\', 0, des_access, NULL);
	}

	/* Marshall data and send request */

	if (!lsa_io_q_open_pol("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_OPENPOLICY, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_open_pol("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*pol = r.pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Open a LSA policy handle
  *
  * @param cli Handle on an initialised SMB connection 
  */

NTSTATUS cli_lsa_open_policy2(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                              BOOL sec_qos, uint32 des_access, POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	LSA_Q_OPEN_POL2 q;
	LSA_R_OPEN_POL2 r;
	LSA_SEC_QOS qos;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	if (sec_qos) {
		init_lsa_sec_qos(&qos, 2, 1, 0);
		init_q_open_pol2(&q, cli->srv_name_slash, 0, des_access, 
                                 &qos);
	} else {
		init_q_open_pol2(&q, cli->srv_name_slash, 0, des_access, 
                                 NULL);
	}

	/* Marshall data and send request */

	if (!lsa_io_q_open_pol2("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_OPENPOLICY2, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_open_pol2("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*pol = r.pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Close a LSA policy handle */

NTSTATUS cli_lsa_close(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                       POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	LSA_Q_CLOSE q;
	LSA_R_CLOSE r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_lsa_q_close(&q, pol);

	if (!lsa_io_q_close("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_CLOSE, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_close("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*pol = r.pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Lookup a list of sids  */
/********************************************************************
 Converts SIDs to names. Outgoing names are in UNIX charset.
*********************************************************************/

NTSTATUS cli_lsa_lookup_sids(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             POLICY_HND *pol, int num_sids, DOM_SID *sids, 
                             char ***domains, char ***names, uint32 **types)
{
	prs_struct qbuf, rbuf;
	LSA_Q_LOOKUP_SIDS q;
	LSA_R_LOOKUP_SIDS r;
	DOM_R_REF ref;
	LSA_TRANS_NAME_ENUM t_names;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_q_lookup_sids(mem_ctx, &q, pol, num_sids, sids, 1);

	if (!lsa_io_q_lookup_sids("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_LOOKUPSIDS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	ZERO_STRUCT(ref);
	ZERO_STRUCT(t_names);

	r.dom_ref = &ref;
	r.names = &t_names;

	if (!lsa_io_r_lookup_sids("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

	if (!NT_STATUS_IS_OK(result) &&
	    NT_STATUS_V(result) != NT_STATUS_V(STATUS_SOME_UNMAPPED)) {
	  
		/* An actual error occured */

		goto done;
	}

	/* Return output parameters */

	if (r.mapped_count == 0) {
		result = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	if (!((*domains) = (char **)talloc(mem_ctx, sizeof(char *) *
					   num_sids))) {
		DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!((*names) = (char **)talloc(mem_ctx, sizeof(char *) *
					 num_sids))) {
		DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!((*types) = (uint32 *)talloc(mem_ctx, sizeof(uint32) *
					  num_sids))) {
		DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
		
	for (i = 0; i < num_sids; i++) {
		fstring name, dom_name;
		uint32 dom_idx = t_names.name[i].domain_idx;

		/* Translate optimised name through domain index array */

		if (dom_idx != 0xffffffff) {

			unistr2_to_unix(dom_name, &ref.ref_dom[dom_idx].uni_dom_name, sizeof(dom_name)- 1);
			unistr2_to_unix(name, &t_names.uni_name[i], sizeof(name) - 1);

			(*names)[i] = talloc_strdup(mem_ctx, name);
			(*domains)[i] = talloc_strdup(mem_ctx, dom_name);
			(*types)[i] = t_names.name[i].sid_name_use;
			
			if (((*names)[i] == NULL) || ((*domains)[i] == NULL)) {
				DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
				result = NT_STATUS_UNSUCCESSFUL;
				goto done;
			}

		} else {
			(*names)[i] = NULL;
			(*types)[i] = SID_NAME_UNKNOWN;
		}
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Lookup a list of names */
/********************************************************************
 Converts names to SIDs. Incoming names are in UNIX charset.
*********************************************************************/

NTSTATUS cli_lsa_lookup_names(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                              POLICY_HND *pol, int num_names, 
			      const char **names, DOM_SID **sids, 
			      uint32 **types)
{
	prs_struct qbuf, rbuf;
	LSA_Q_LOOKUP_NAMES q;
	LSA_R_LOOKUP_NAMES r;
	DOM_R_REF ref;
	NTSTATUS result;
	int i;
	
	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	/* This call converts from UNIX to DOS charset then to unicode. */
	init_q_lookup_names(mem_ctx, &q, pol, num_names, names);

	if (!lsa_io_q_lookup_names("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_LOOKUPNAMES, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	
	/* Unmarshall response */

	ZERO_STRUCT(ref);
	r.dom_ref = &ref;

	if (!lsa_io_r_lookup_names("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

	if (!NT_STATUS_IS_OK(result) && NT_STATUS_V(result) !=
	    NT_STATUS_V(STATUS_SOME_UNMAPPED)) {

		/* An actual error occured */

		goto done;
	}

	/* Return output parameters */

	if (r.mapped_count == 0) {
		result = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	if (!((*sids = (DOM_SID *)talloc(mem_ctx, sizeof(DOM_SID) *
					 num_names)))) {
		DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!((*types = (uint32 *)talloc(mem_ctx, sizeof(uint32) *
					 num_names)))) {
		DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	for (i = 0; i < num_names; i++) {
		DOM_RID2 *t_rids = r.dom_rid;
		uint32 dom_idx = t_rids[i].rid_idx;
		uint32 dom_rid = t_rids[i].rid;
		DOM_SID *sid = &(*sids)[i];

		/* Translate optimised sid through domain index array */

		if (dom_idx != 0xffffffff) {

			sid_copy(sid, &ref.ref_dom[dom_idx].ref_dom.sid);

			if (dom_rid != 0xffffffff) {
				sid_append_rid(sid, dom_rid);
			}

			(*types)[i] = t_rids[i].type;
		} else {
			ZERO_STRUCTP(sid);
			(*types)[i] = SID_NAME_UNKNOWN;
		}
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Query info policy
 *
 *  @param domain_sid - returned remote server's domain sid */

NTSTATUS cli_lsa_query_info_policy(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                   POLICY_HND *pol, uint16 info_class, 
                                   fstring domain_name, DOM_SID *domain_sid)
{
	prs_struct qbuf, rbuf;
	LSA_Q_QUERY_INFO q;
	LSA_R_QUERY_INFO r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_q_query(&q, pol, info_class);

	if (!lsa_io_q_query("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_QUERYINFOPOLICY, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_query("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	/* Return output parameters */

	ZERO_STRUCTP(domain_sid);
	domain_name[0] = '\0';

	switch (info_class) {

	case 3:
		if (r.dom.id3.buffer_dom_name != 0) {
			unistr2_to_unix(domain_name,
					 &r.dom.id3.
					 uni_domain_name,
					 sizeof (fstring) - 1);
		}

		if (r.dom.id3.buffer_dom_sid != 0) {
			*domain_sid = r.dom.id3.dom_sid.sid;
		}

		break;

	case 5:
		
		if (r.dom.id5.buffer_dom_name != 0) {
			unistr2_to_unix(domain_name, &r.dom.id5.
					 uni_domain_name,
					 sizeof (fstring) - 1);
		}
			
		if (r.dom.id5.buffer_dom_sid != 0) {
			*domain_sid = r.dom.id5.dom_sid.sid;
		}

		break;
		
	default:
		DEBUG(3, ("unknown info class %d\n", info_class));
		break;		      
	}
	
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Enumerate list of trusted domains */

NTSTATUS cli_lsa_enum_trust_dom(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                POLICY_HND *pol, uint32 *enum_ctx, 
                                uint32 *num_domains, char ***domain_names, 
                                DOM_SID **domain_sids)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUM_TRUST_DOM q;
	LSA_R_ENUM_TRUST_DOM r;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_q_enum_trust_dom(&q, pol, *enum_ctx, 0xffffffff);

	if (!lsa_io_q_enum_trust_dom("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_ENUMTRUSTDOM, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_enum_trust_dom("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

	if (!NT_STATUS_IS_OK(result) && 
	    NT_STATUS_V(result) != NT_STATUS_V(NT_STATUS_NO_MORE_ENTRIES)) {

		/* An actual error ocured */

		goto done;
	}

	result = NT_STATUS_OK;

	/* Return output parameters */

	if (r.num_domains) {

		/* Allocate memory for trusted domain names and sids */

		*domain_names = (char **)talloc(mem_ctx, sizeof(char *) *
						r.num_domains);

		if (!*domain_names) {
			DEBUG(0, ("cli_lsa_enum_trust_dom(): out of memory\n"));
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		*domain_sids = (DOM_SID *)talloc(mem_ctx, sizeof(DOM_SID) *
						 r.num_domains);
		if (!domain_sids) {
			DEBUG(0, ("cli_lsa_enum_trust_dom(): out of memory\n"));
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		/* Copy across names and sids */

		for (i = 0; i < r.num_domains; i++) {
			fstring tmp;

			unistr2_to_unix(tmp, &r.uni_domain_name[i], 
					 sizeof(tmp) - 1);
			(*domain_names)[i] = talloc_strdup(mem_ctx, tmp);
			sid_copy(&(*domain_sids)[i], &r.domain_sid[i].sid);
		}
	}

	*num_domains = r.num_domains;
	*enum_ctx = r.enum_context;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Enumerate privileges*/

NTSTATUS cli_lsa_enum_privilege(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                POLICY_HND *pol, uint32 *enum_context, uint32 pref_max_length,
				uint32 *count, char ***privs_name, uint32 **privs_high, uint32 **privs_low)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUM_PRIVS q;
	LSA_R_ENUM_PRIVS r;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_q_enum_privs(&q, pol, *enum_context, pref_max_length);

	if (!lsa_io_q_enum_privs("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_ENUM_PRIVS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_enum_privs("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	/* Return output parameters */

	*enum_context = r.enum_context;
	*count = r.count;

	if (!((*privs_name = (char **)talloc(mem_ctx, sizeof(char *) * r.count)))) {
		DEBUG(0, ("(cli_lsa_enum_privilege): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!((*privs_high = (uint32 *)talloc(mem_ctx, sizeof(uint32) * r.count)))) {
		DEBUG(0, ("(cli_lsa_enum_privilege): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!((*privs_low = (uint32 *)talloc(mem_ctx, sizeof(uint32) * r.count)))) {
		DEBUG(0, ("(cli_lsa_enum_privilege): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	for (i = 0; i < r.count; i++) {
		fstring name;

		unistr2_to_unix( name, &r.privs[i].name, sizeof(name)-1);

		(*privs_name)[i] = talloc_strdup(mem_ctx, name);

		(*privs_high)[i] = r.privs[i].luid_high;
		(*privs_low)[i] = r.privs[i].luid_low;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Get privilege name */

NTSTATUS cli_lsa_get_dispname(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, char *name, uint16 lang_id, uint16 lang_id_sys,
			      fstring description, uint16 *lang_id_desc)
{
	prs_struct qbuf, rbuf;
	LSA_Q_PRIV_GET_DISPNAME q;
	LSA_R_PRIV_GET_DISPNAME r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_lsa_priv_get_dispname(&q, pol, name, lang_id, lang_id_sys);

	if (!lsa_io_q_priv_get_dispname("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_PRIV_GET_DISPNAME, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_priv_get_dispname("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	/* Return output parameters */
	
	unistr2_to_unix(description ,&r.desc, sizeof(description)-1);
	*lang_id_desc = r.lang_id;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Enumerate list of SIDs  */

NTSTATUS cli_lsa_enum_sids(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                POLICY_HND *pol, uint32 *enum_ctx, uint32 pref_max_length, 
                                uint32 *num_sids, DOM_SID **sids)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUM_ACCOUNTS q;
	LSA_R_ENUM_ACCOUNTS r;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_lsa_q_enum_accounts(&q, pol, *enum_ctx, pref_max_length);

	if (!lsa_io_q_enum_accounts("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_ENUM_ACCOUNTS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_enum_accounts("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	if (r.sids.num_entries==0)
		goto done;

	/* Return output parameters */

	*sids = (DOM_SID *)talloc(mem_ctx, sizeof(DOM_SID) * r.sids.num_entries);
	if (!*sids) {
		DEBUG(0, ("(cli_lsa_enum_sids): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Copy across names and sids */

	for (i = 0; i < r.sids.num_entries; i++) {
		sid_copy(&(*sids)[i], &r.sids.sid[i].sid);
	}

	*num_sids= r.sids.num_entries;
	*enum_ctx = r.enum_context;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Open a LSA user handle
 *
 * @param cli Handle on an initialised SMB connection */

NTSTATUS cli_lsa_open_account(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             POLICY_HND *dom_pol, DOM_SID *sid, uint32 des_access, 
			     POLICY_HND *user_pol)
{
	prs_struct qbuf, rbuf;
	LSA_Q_OPENACCOUNT q;
	LSA_R_OPENACCOUNT r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_lsa_q_open_account(&q, dom_pol, sid, des_access);

	/* Marshall data and send request */

	if (!lsa_io_q_open_account("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_OPENACCOUNT, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_open_account("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*user_pol = r.pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Enumerate user privileges
 *
 * @param cli Handle on an initialised SMB connection */

NTSTATUS cli_lsa_enum_privsaccount(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             POLICY_HND *pol, uint32 *count, LUID_ATTR **set)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUMPRIVSACCOUNT q;
	LSA_R_ENUMPRIVSACCOUNT r;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_lsa_q_enum_privsaccount(&q, pol);

	/* Marshall data and send request */

	if (!lsa_io_q_enum_privsaccount("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_ENUMPRIVSACCOUNT, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_enum_privsaccount("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	if (r.count == 0)
		goto done;

	if (!((*set = (LUID_ATTR *)talloc(mem_ctx, sizeof(LUID_ATTR) * r.count)))) {
		DEBUG(0, ("(cli_lsa_enum_privsaccount): out of memory\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	for (i=0; i<r.count; i++) {
		(*set)[i].luid.low = r.set.set[i].luid.low;
		(*set)[i].luid.high = r.set.set[i].luid.high;
		(*set)[i].attr = r.set.set[i].attr;
	}

	*count=r.count;
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Get a privilege value given its name */

NTSTATUS cli_lsa_lookupprivvalue(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, char *name, LUID *luid)
{
	prs_struct qbuf, rbuf;
	LSA_Q_LOOKUPPRIVVALUE q;
	LSA_R_LOOKUPPRIVVALUE r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_lsa_q_lookupprivvalue(&q, pol, name);

	if (!lsa_io_q_lookupprivvalue("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_LOOKUPPRIVVALUE, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_lookupprivvalue("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	/* Return output parameters */

	(*luid).low=r.luid.low;
	(*luid).high=r.luid.high;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Query LSA security object */

NTSTATUS cli_lsa_query_secobj(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, uint32 sec_info, 
			      SEC_DESC_BUF **psdb)
{
	prs_struct qbuf, rbuf;
	LSA_Q_QUERY_SEC_OBJ q;
	LSA_R_QUERY_SEC_OBJ r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_q_query_sec_obj(&q, pol, sec_info);

	if (!lsa_io_q_query_sec_obj("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, LSA_QUERYSECOBJ, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!lsa_io_r_query_sec_obj("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	/* Return output parameters */

	if (psdb)
		*psdb = r.buf;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Fetch a DOMAIN sid. Does complete cli setup / teardown anonymously. */

BOOL fetch_domain_sid( char *domain, char *remote_machine, DOM_SID *psid)
{
	extern pstring global_myname;
	struct cli_state cli;
	NTSTATUS result;
	POLICY_HND lsa_pol;
	BOOL ret = False;
 
	ZERO_STRUCT(cli);
	if(cli_initialise(&cli) == False) {
		DEBUG(0,("fetch_domain_sid: unable to initialize client connection.\n"));
		return False;
	}
 
	if(!resolve_name( remote_machine, &cli.dest_ip, 0x20)) {
		DEBUG(0,("fetch_domain_sid: Can't resolve address for %s\n", remote_machine));
		goto done;
	}
 
	if (!cli_connect(&cli, remote_machine, &cli.dest_ip)) {
		DEBUG(0,("fetch_domain_sid: unable to connect to SMB server on \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		goto done;
	}

	if (!attempt_netbios_session_request(&cli, global_myname, remote_machine, &cli.dest_ip)) {
		DEBUG(0,("fetch_domain_sid: machine %s rejected the NetBIOS session request.\n", 
			remote_machine));
		goto done;
	}
 
	cli.protocol = PROTOCOL_NT1;
 
	if (!cli_negprot(&cli)) {
		DEBUG(0,("fetch_domain_sid: machine %s rejected the negotiate protocol. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		goto done;
	}
 
	if (cli.protocol != PROTOCOL_NT1) {
		DEBUG(0,("fetch_domain_sid: machine %s didn't negotiate NT protocol.\n",
			remote_machine));
		goto done;
	}
 
	/*
	 * Do an anonymous session setup.
	 */
 
	if (!cli_session_setup(&cli, "", "", 0, "", 0, "")) {
		DEBUG(0,("fetch_domain_sid: machine %s rejected the session setup. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		goto done;
	}
 
	if (!(cli.sec_mode & 1)) {
		DEBUG(0,("fetch_domain_sid: machine %s isn't in user level security mode\n",
			remote_machine));
		goto done;
	}

	if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
		DEBUG(0,("fetch_domain_sid: machine %s rejected the tconX on the IPC$ share. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
		goto done;
	}

	/* Fetch domain sid */
 
	if (!cli_nt_session_open(&cli, PIPE_LSARPC)) {
		DEBUG(0, ("fetch_domain_sid: Error connecting to SAM pipe\n"));
		goto done;
	}
 
	result = cli_lsa_open_policy(&cli, cli.mem_ctx, True, SEC_RIGHTS_QUERY_VALUE, &lsa_pol);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("fetch_domain_sid: Error opening lsa policy handle. %s\n",
			get_nt_error_msg(result) ));
		goto done;
	}
 
	result = cli_lsa_query_info_policy(&cli, cli.mem_ctx, &lsa_pol, 5, domain, psid);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("fetch_domain_sid: Error querying lsa policy handle. %s\n",
			get_nt_error_msg(result) ));
		goto done;
	}
 
	ret = True;

  done:

	cli_shutdown(&cli);
	return ret;
}
/** @} **/
