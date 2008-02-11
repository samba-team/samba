/*
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   Copyright (C) Andrew Tridgell              1992-1997,2000,
   Copyright (C) Rafal Szczesniak                       2002
   Copyright (C) Jeremy Allison				2005.
   Copyright (C) Michael Adam				2007.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

/** Open a LSA policy handle
 *
 * @param cli Handle on an initialised SMB connection */

NTSTATUS rpccli_lsa_open_policy(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				bool sec_qos, uint32 des_access,
				POLICY_HND *pol)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	uint16_t system_name = '\\';

	if (sec_qos) {
		init_lsa_sec_qos(&qos, 0xc, 2, 1, 0);
		init_lsa_obj_attr(&attr,
				  0x18,
				  NULL,
				  NULL,
				  0,
				  NULL,
				  &qos);
	} else {
		init_lsa_obj_attr(&attr,
				  0x18,
				  NULL,
				  NULL,
				  0,
				  NULL,
				  NULL);
	}

	return rpccli_lsa_OpenPolicy(cli, mem_ctx,
				     &system_name,
				     &attr,
				     des_access,
				     pol);
}

/** Open a LSA policy handle
  *
  * @param cli Handle on an initialised SMB connection
  */

NTSTATUS rpccli_lsa_open_policy2(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx, bool sec_qos,
				 uint32 des_access, POLICY_HND *pol)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	char *srv_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", cli->cli->desthost);

	if (sec_qos) {
		init_lsa_sec_qos(&qos, 0xc, 2, 1, 0);
		init_lsa_obj_attr(&attr,
				  0x18,
				  NULL,
				  NULL,
				  0,
				  NULL,
				  &qos);
	} else {
		init_lsa_obj_attr(&attr,
				  0x18,
				  NULL,
				  NULL,
				  0,
				  NULL,
				  NULL);
	}

	return rpccli_lsa_OpenPolicy2(cli, mem_ctx,
				      srv_name_slash,
				      &attr,
				      des_access,
				      pol);
}

/* Lookup a list of sids
 *
 * internal version withOUT memory allocation of the target arrays.
 * this assumes suffciently sized arrays to store domains, names and types. */

static NTSTATUS rpccli_lsa_lookup_sids_noalloc(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       POLICY_HND *pol,
					       int num_sids,
					       const DOM_SID *sids,
					       char **domains,
					       char **names,
					       enum lsa_SidType *types)
{
	prs_struct qbuf, rbuf;
	LSA_Q_LOOKUP_SIDS q;
	LSA_R_LOOKUP_SIDS r;
	DOM_R_REF ref;
	NTSTATUS result = NT_STATUS_OK;
	TALLOC_CTX *tmp_ctx = NULL;
	int i;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		DEBUG(0, ("rpccli_lsa_lookup_sids_noalloc: out of memory!\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	init_q_lookup_sids(tmp_ctx, &q, pol, num_sids, sids, 1);

	ZERO_STRUCT(ref);

	r.dom_ref = &ref;

	CLI_DO_RPC( cli, tmp_ctx, PI_LSARPC, LSA_LOOKUPSIDS,
			q, r,
			qbuf, rbuf,
			lsa_io_q_lookup_sids,
			lsa_io_r_lookup_sids,
			NT_STATUS_UNSUCCESSFUL );

	DEBUG(10, ("LSA_LOOKUPSIDS returned '%s', mapped count = %d'\n",
		   nt_errstr(r.status), r.mapped_count));

	if (!NT_STATUS_IS_OK(r.status) &&
	    !NT_STATUS_EQUAL(r.status, NT_STATUS_NONE_MAPPED) &&
	    !NT_STATUS_EQUAL(r.status, STATUS_SOME_UNMAPPED))
	{
		/* An actual error occured */
		result = r.status;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_EQUAL(r.status, NT_STATUS_NONE_MAPPED) ||
	    (r.mapped_count == 0))
	{
		for (i = 0; i < num_sids; i++) {
			(names)[i] = NULL;
			(domains)[i] = NULL;
			(types)[i] = SID_NAME_UNKNOWN;
		}
		result = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	for (i = 0; i < num_sids; i++) {
		fstring name, dom_name;
		uint32 dom_idx = r.names.name[i].domain_idx;

		/* Translate optimised name through domain index array */

		if (dom_idx != 0xffffffff) {

			rpcstr_pull_unistr2_fstring(
                                dom_name, &ref.ref_dom[dom_idx].uni_dom_name);
			rpcstr_pull_unistr2_fstring(
                                name, &r.names.uni_name[i]);

			(names)[i] = talloc_strdup(mem_ctx, name);
			(domains)[i] = talloc_strdup(mem_ctx, dom_name);
			(types)[i] = r.names.name[i].sid_name_use;

			if (((names)[i] == NULL) || ((domains)[i] == NULL)) {
				DEBUG(0, ("cli_lsa_lookup_sids_noalloc(): out of memory\n"));
				result = NT_STATUS_UNSUCCESSFUL;
				goto done;
			}

		} else {
			(names)[i] = NULL;
			(domains)[i] = NULL;
			(types)[i] = SID_NAME_UNKNOWN;
		}
	}

done:
	TALLOC_FREE(tmp_ctx);
	return result;
}

/* Lookup a list of sids
 *
 * do it the right way: there is a limit (of 20480 for w2k3) entries
 * returned by this call. when the sids list contains more entries,
 * empty lists are returned. This version of lsa_lookup_sids passes
 * the list of sids in hunks of LOOKUP_SIDS_HUNK_SIZE to the lsa call. */

/* This constant defines the limit of how many sids to look up
 * in one call (maximum). the limit from the server side is
 * at 20480 for win2k3, but we keep it at a save 1000 for now. */
#define LOOKUP_SIDS_HUNK_SIZE 1000

NTSTATUS rpccli_lsa_lookup_sids(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				POLICY_HND *pol,
				int num_sids,
				const DOM_SID *sids,
				char ***domains,
				char ***names,
				enum lsa_SidType **types)
{
	NTSTATUS result = NT_STATUS_OK;
	int sids_left = 0;
	int sids_processed = 0;
	const DOM_SID *hunk_sids = sids;
	char **hunk_domains = NULL;
	char **hunk_names = NULL;
	enum lsa_SidType *hunk_types = NULL;

	if (num_sids) {
		if (!((*domains) = TALLOC_ARRAY(mem_ctx, char *, num_sids))) {
			DEBUG(0, ("rpccli_lsa_lookup_sids(): out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		if (!((*names) = TALLOC_ARRAY(mem_ctx, char *, num_sids))) {
			DEBUG(0, ("rpccli_lsa_lookup_sids(): out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		if (!((*types) = TALLOC_ARRAY(mem_ctx, enum lsa_SidType, num_sids))) {
			DEBUG(0, ("rpccli_lsa_lookup_sids(): out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	} else {
		(*domains) = NULL;
		(*names) = NULL;
		(*types) = NULL;
	}

	sids_left = num_sids;
	hunk_domains = *domains;
	hunk_names = *names;
	hunk_types = *types;

	while (sids_left > 0) {
		int hunk_num_sids;
		NTSTATUS hunk_result = NT_STATUS_OK;

		hunk_num_sids = ((sids_left > LOOKUP_SIDS_HUNK_SIZE)
				? LOOKUP_SIDS_HUNK_SIZE
				: sids_left);

		DEBUG(10, ("rpccli_lsa_lookup_sids: processing items "
			   "%d -- %d of %d.\n",
			   sids_processed,
			   sids_processed + hunk_num_sids - 1,
			   num_sids));

		hunk_result = rpccli_lsa_lookup_sids_noalloc(cli,
							     mem_ctx,
							     pol,
							     hunk_num_sids,
							     hunk_sids,
							     hunk_domains,
							     hunk_names,
							     hunk_types);

		if (!NT_STATUS_IS_OK(hunk_result) &&
		    !NT_STATUS_EQUAL(hunk_result, STATUS_SOME_UNMAPPED) &&
		    !NT_STATUS_EQUAL(hunk_result, NT_STATUS_NONE_MAPPED))
		{
			/* An actual error occured */
			result = hunk_result;
			goto fail;
		}

		/* adapt overall result */
		if (( NT_STATUS_IS_OK(result) &&
		     !NT_STATUS_IS_OK(hunk_result))
		    ||
		    ( NT_STATUS_EQUAL(result, NT_STATUS_NONE_MAPPED) &&
		     !NT_STATUS_EQUAL(hunk_result, NT_STATUS_NONE_MAPPED)))
		{
			result = STATUS_SOME_UNMAPPED;
		}

		sids_left -= hunk_num_sids;
		sids_processed += hunk_num_sids; /* only used in DEBUG */
		hunk_sids += hunk_num_sids;
		hunk_domains += hunk_num_sids;
		hunk_names += hunk_num_sids;
		hunk_types += hunk_num_sids;
	}

	return result;

fail:
	TALLOC_FREE(*domains);
	TALLOC_FREE(*names);
	TALLOC_FREE(*types);
	return result;
}

/** Lookup a list of names */

NTSTATUS rpccli_lsa_lookup_names(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 POLICY_HND *pol, int num_names,
				 const char **names,
				 const char ***dom_names,
				 int level,
				 DOM_SID **sids,
				 enum lsa_SidType **types)
{
	prs_struct qbuf, rbuf;
	LSA_Q_LOOKUP_NAMES q;
	LSA_R_LOOKUP_NAMES r;
	DOM_R_REF ref;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	ZERO_STRUCT(ref);
	r.dom_ref = &ref;

	init_q_lookup_names(mem_ctx, &q, pol, num_names, names, level);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_LOOKUPNAMES,
			q, r,
			qbuf, rbuf,
			lsa_io_q_lookup_names,
			lsa_io_r_lookup_names,
			NT_STATUS_UNSUCCESSFUL);

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

	if (num_names) {
		if (!((*sids = TALLOC_ARRAY(mem_ctx, DOM_SID, num_names)))) {
			DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		if (!((*types = TALLOC_ARRAY(mem_ctx, enum lsa_SidType, num_names)))) {
			DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		if (dom_names != NULL) {
			*dom_names = TALLOC_ARRAY(mem_ctx, const char *, num_names);
			if (*dom_names == NULL) {
				DEBUG(0, ("cli_lsa_lookup_sids(): out of memory\n"));
				result = NT_STATUS_NO_MEMORY;
				goto done;
			}
		}
	} else {
		*sids = NULL;
		*types = NULL;
		if (dom_names != NULL) {
			*dom_names = NULL;
		}
	}

	for (i = 0; i < num_names; i++) {
		DOM_RID *t_rids = r.dom_rid;
		uint32 dom_idx = t_rids[i].rid_idx;
		uint32 dom_rid = t_rids[i].rid;
		DOM_SID *sid = &(*sids)[i];

		/* Translate optimised sid through domain index array */

		if (dom_idx == 0xffffffff) {
			/* Nothing to do, this is unknown */
			ZERO_STRUCTP(sid);
			(*types)[i] = SID_NAME_UNKNOWN;
			continue;
		}

		sid_copy(sid, &ref.ref_dom[dom_idx].ref_dom.sid);

		if (dom_rid != 0xffffffff) {
			sid_append_rid(sid, dom_rid);
		}

		(*types)[i] = t_rids[i].type;

		if (dom_names == NULL) {
			continue;
		}

		(*dom_names)[i] = rpcstr_pull_unistr2_talloc(
			*dom_names, &ref.ref_dom[dom_idx].uni_dom_name);
	}

 done:

	return result;
}

/**
 * Enumerate list of trusted domains
 *
 * @param cli client state (cli_state) structure of the connection
 * @param mem_ctx memory context
 * @param pol opened lsa policy handle
 * @param enum_ctx enumeration context ie. index of first returned domain entry
 * @param pref_num_domains preferred max number of entries returned in one response
 * @param num_domains total number of trusted domains returned by response
 * @param domain_names returned trusted domain names
 * @param domain_sids returned trusted domain sids
 *
 * @return nt status code of response
 **/

NTSTATUS rpccli_lsa_enum_trust_dom(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   POLICY_HND *pol, uint32 *enum_ctx,
				   uint32 *num_domains,
				   char ***domain_names, DOM_SID **domain_sids)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUM_TRUST_DOM in;
	LSA_R_ENUM_TRUST_DOM out;
	int i;
	fstring tmp;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	/* 64k is enough for about 2000 trusted domains */

        init_q_enum_trust_dom(&in, pol, *enum_ctx, 0x10000);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_ENUMTRUSTDOM,
	            in, out,
	            qbuf, rbuf,
	            lsa_io_q_enum_trust_dom,
	            lsa_io_r_enum_trust_dom,
	            NT_STATUS_UNSUCCESSFUL );


	/* check for an actual error */

	if ( !NT_STATUS_IS_OK(out.status)
		&& !NT_STATUS_EQUAL(out.status, NT_STATUS_NO_MORE_ENTRIES)
		&& !NT_STATUS_EQUAL(out.status, STATUS_MORE_ENTRIES) )
	{
		return out.status;
	}

	/* Return output parameters */

	*num_domains  = out.count;
	*enum_ctx     = out.enum_context;

	if ( out.count ) {

		/* Allocate memory for trusted domain names and sids */

		if ( !(*domain_names = TALLOC_ARRAY(mem_ctx, char *, out.count)) ) {
			DEBUG(0, ("cli_lsa_enum_trust_dom(): out of memory\n"));
			return NT_STATUS_NO_MEMORY;
		}

		if ( !(*domain_sids = TALLOC_ARRAY(mem_ctx, DOM_SID, out.count)) ) {
			DEBUG(0, ("cli_lsa_enum_trust_dom(): out of memory\n"));
			return NT_STATUS_NO_MEMORY;
		}

		/* Copy across names and sids */

		for (i = 0; i < out.count; i++) {

			rpcstr_pull( tmp, out.domlist->domains[i].name.string->buffer,
				sizeof(tmp), out.domlist->domains[i].name.length, 0);
			(*domain_names)[i] = talloc_strdup(mem_ctx, tmp);

			sid_copy(&(*domain_sids)[i], &out.domlist->domains[i].sid->sid );
		}
	}

	return out.status;
}

/** Get privilege name */

NTSTATUS rpccli_lsa_get_dispname(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, const char *name,
			      uint16 lang_id, uint16 lang_id_sys,
			      fstring description, uint16 *lang_id_desc)
{
	prs_struct qbuf, rbuf;
	LSA_Q_PRIV_GET_DISPNAME q;
	LSA_R_PRIV_GET_DISPNAME r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	init_lsa_priv_get_dispname(&q, pol, name, lang_id, lang_id_sys);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_PRIV_GET_DISPNAME,
		q, r,
		qbuf, rbuf,
		lsa_io_q_priv_get_dispname,
		lsa_io_r_priv_get_dispname,
		NT_STATUS_UNSUCCESSFUL);

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Return output parameters */

	rpcstr_pull_unistr2_fstring(description , &r.desc);
	*lang_id_desc = r.lang_id;

 done:

	return result;
}

/** Enumerate list of SIDs  */

NTSTATUS rpccli_lsa_enum_sids(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
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

        init_lsa_q_enum_accounts(&q, pol, *enum_ctx, pref_max_length);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_ENUM_ACCOUNTS,
		q, r,
		qbuf, rbuf,
		lsa_io_q_enum_accounts,
		lsa_io_r_enum_accounts,
		NT_STATUS_UNSUCCESSFUL);

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (r.sids.num_entries==0)
		goto done;

	/* Return output parameters */

	*sids = TALLOC_ARRAY(mem_ctx, DOM_SID, r.sids.num_entries);
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

	return result;
}

/** Enumerate user privileges
 *
 * @param cli Handle on an initialised SMB connection */

NTSTATUS rpccli_lsa_enum_privsaccount(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                             POLICY_HND *pol, uint32 *count, LUID_ATTR **set)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUMPRIVSACCOUNT q;
	LSA_R_ENUMPRIVSACCOUNT r;
	NTSTATUS result;
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	init_lsa_q_enum_privsaccount(&q, pol);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_ENUMPRIVSACCOUNT,
		q, r,
		qbuf, rbuf,
		lsa_io_q_enum_privsaccount,
		lsa_io_r_enum_privsaccount,
		NT_STATUS_UNSUCCESSFUL);

	/* Return output parameters */

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (r.count == 0)
		goto done;

	if (!((*set = TALLOC_ARRAY(mem_ctx, LUID_ATTR, r.count)))) {
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

	return result;
}

/** Get a privilege value given its name */

NTSTATUS rpccli_lsa_lookup_priv_value(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 POLICY_HND *pol, const char *name, LUID *luid)
{
	prs_struct qbuf, rbuf;
	LSA_Q_LOOKUP_PRIV_VALUE q;
	LSA_R_LOOKUP_PRIV_VALUE r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

	init_lsa_q_lookup_priv_value(&q, pol, name);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_LOOKUPPRIVVALUE,
		q, r,
		qbuf, rbuf,
		lsa_io_q_lookup_priv_value,
		lsa_io_r_lookup_priv_value,
		NT_STATUS_UNSUCCESSFUL);

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Return output parameters */

	(*luid).low=r.luid.low;
	(*luid).high=r.luid.high;

 done:

	return result;
}

/* Enumerate account rights This is similar to enum_privileges but
   takes a SID directly, avoiding the open_account call.
*/

NTSTATUS rpccli_lsa_enum_account_rights(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				     POLICY_HND *pol, DOM_SID *sid,
				     uint32 *count, char ***priv_names)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ENUM_ACCT_RIGHTS q;
	LSA_R_ENUM_ACCT_RIGHTS r;
	NTSTATUS result;
	int i;
	fstring *privileges;
	char **names;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */
	init_q_enum_acct_rights(&q, pol, 2, sid);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_ENUMACCTRIGHTS,
		q, r,
		qbuf, rbuf,
		lsa_io_q_enum_acct_rights,
		lsa_io_r_enum_acct_rights,
		NT_STATUS_UNSUCCESSFUL);

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	*count = r.count;
	if (! *count) {
		goto done;
	}


	privileges = TALLOC_ARRAY( mem_ctx, fstring, *count );
	names      = TALLOC_ARRAY( mem_ctx, char *, *count );

	if ((privileges == NULL) || (names == NULL)) {
		TALLOC_FREE(privileges);
		TALLOC_FREE(names);
		return NT_STATUS_NO_MEMORY;
	}

	for ( i=0; i<*count; i++ ) {
		UNISTR4 *uni_string = &r.rights->strings[i];

		if ( !uni_string->string )
			continue;

		rpcstr_pull( privileges[i], uni_string->string->buffer, sizeof(privileges[i]), -1, STR_TERMINATE );

		/* now copy to the return array */
		names[i] = talloc_strdup( mem_ctx, privileges[i] );
	}

	*priv_names = names;

done:

	return result;
}



/* add account rights to an account. */

NTSTATUS rpccli_lsa_add_account_rights(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *pol, DOM_SID sid,
					uint32 count, const char **privs_name)
{
	prs_struct qbuf, rbuf;
	LSA_Q_ADD_ACCT_RIGHTS q;
	LSA_R_ADD_ACCT_RIGHTS r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */
	init_q_add_acct_rights(&q, pol, &sid, count, privs_name);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_ADDACCTRIGHTS,
		q, r,
		qbuf, rbuf,
		lsa_io_q_add_acct_rights,
		lsa_io_r_add_acct_rights,
		NT_STATUS_UNSUCCESSFUL);

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
done:

	return result;
}


/* remove account rights for an account. */

NTSTATUS rpccli_lsa_remove_account_rights(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				       POLICY_HND *pol, DOM_SID sid, bool removeall,
				       uint32 count, const char **privs_name)
{
	prs_struct qbuf, rbuf;
	LSA_Q_REMOVE_ACCT_RIGHTS q;
	LSA_R_REMOVE_ACCT_RIGHTS r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */
	init_q_remove_acct_rights(&q, pol, &sid, removeall?1:0, count, privs_name);

	CLI_DO_RPC( cli, mem_ctx, PI_LSARPC, LSA_REMOVEACCTRIGHTS,
		q, r,
		qbuf, rbuf,
		lsa_io_q_remove_acct_rights,
		lsa_io_r_remove_acct_rights,
		NT_STATUS_UNSUCCESSFUL);

	result = r.status;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
done:

	return result;
}


#if 0

/** An example of how to use the routines in this file.  Fetch a DOMAIN
    sid. Does complete cli setup / teardown anonymously. */

bool fetch_domain_sid( char *domain, char *remote_machine, DOM_SID *psid)
{
	struct cli_state cli;
	NTSTATUS result;
	POLICY_HND lsa_pol;
	bool ret = False;

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

	if (!attempt_netbios_session_request(&cli, global_myname(), remote_machine, &cli.dest_ip)) {
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

	if (!(cli.sec_mode & NEGOTIATE_SECURITY_USER_LEVEL)) {
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

	if (!cli_nt_session_open(&cli, PI_LSARPC)) {
		DEBUG(0, ("fetch_domain_sid: Error connecting to SAM pipe\n"));
		goto done;
	}

	result = cli_lsa_open_policy(&cli, cli.mem_ctx, True, SEC_RIGHTS_QUERY_VALUE, &lsa_pol);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("fetch_domain_sid: Error opening lsa policy handle. %s\n",
			nt_errstr(result) ));
		goto done;
	}

	result = cli_lsa_query_info_policy(&cli, cli.mem_ctx, &lsa_pol, 5, domain, psid);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("fetch_domain_sid: Error querying lsa policy handle. %s\n",
			nt_errstr(result) ));
		goto done;
	}

	ret = True;

  done:

	cli_shutdown(&cli);
	return ret;
}

#endif
