/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   Copyright (C) Andrew Tridgell              1992-1997,2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997,2000,
   Copyright (C) Paul Ashton                       1997,2000,
   Copyright (C) Elrond                                 2000,
   Copyright (C) Rafal Szczesniak                       2002.
   
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

/* Connect to SAMR database */

NTSTATUS cli_samr_connect(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                          uint32 access_mask, POLICY_HND *connect_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CONNECT q;
	SAMR_R_CONNECT r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_connect to %s\n", cli->desthost));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_connect(&q, cli->desthost, access_mask);

	if (!samr_io_q_connect("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CONNECT, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_connect("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*connect_pol = r.connect_pol;
#ifdef __INSURE__
		connect_pol->marker = malloc(1);
#endif
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Connect to SAMR database */

NTSTATUS cli_samr_connect4(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			   uint32 access_mask, POLICY_HND *connect_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CONNECT4 q;
	SAMR_R_CONNECT4 r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_connect4 to %s\n", cli->desthost));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_connect4(&q, cli->desthost, access_mask);

	if (!samr_io_q_connect4("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CONNECT4, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_connect4("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*connect_pol = r.connect_pol;
#ifdef __INSURE__
		connect_pol->marker = malloc(1);
#endif
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Close SAMR handle */

NTSTATUS cli_samr_close(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                        POLICY_HND *connect_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CLOSE_HND q;
	SAMR_R_CLOSE_HND r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_close\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_close_hnd(&q, connect_pol);

	if (!samr_io_q_close_hnd("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CLOSE_HND, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_close_hnd("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
#ifdef __INSURE__
		SAFE_FREE(connect_pol->marker);
#endif
		*connect_pol = r.pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Open handle on a domain */

NTSTATUS cli_samr_open_domain(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                              POLICY_HND *connect_pol, uint32 access_mask, 
                              const DOM_SID *domain_sid, POLICY_HND *domain_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_OPEN_DOMAIN q;
	SAMR_R_OPEN_DOMAIN r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_open_domain with sid %s\n", sid_string_static(domain_sid) ));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_open_domain(&q, connect_pol, access_mask, domain_sid);

	if (!samr_io_q_open_domain("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_OPEN_DOMAIN, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_open_domain("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*domain_pol = r.domain_pol;
#ifdef __INSURE__
		domain_pol->marker = malloc(1);
#endif
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Open handle on a user */

NTSTATUS cli_samr_open_user(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *domain_pol, uint32 access_mask, 
                            uint32 user_rid, POLICY_HND *user_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_OPEN_USER q;
	SAMR_R_OPEN_USER r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_open_user with rid 0x%x\n", user_rid ));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_open_user(&q, domain_pol, access_mask, user_rid);

	if (!samr_io_q_open_user("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_OPEN_USER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_open_user("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*user_pol = r.user_pol;
#ifdef __INSURE__
		user_pol->marker = malloc(1);
#endif
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Open handle on a group */

NTSTATUS cli_samr_open_group(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                             POLICY_HND *domain_pol, uint32 access_mask, 
                             uint32 group_rid, POLICY_HND *group_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_OPEN_GROUP q;
	SAMR_R_OPEN_GROUP r;
	NTSTATUS result =  NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_open_group with rid 0x%x\n", group_rid ));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_open_group(&q, domain_pol, access_mask, group_rid);

	if (!samr_io_q_open_group("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_OPEN_GROUP, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_open_group("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*group_pol = r.pol;
#ifdef __INSURE__
		group_pol->marker = malloc(1);
#endif
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Create domain group */

NTSTATUS cli_samr_create_dom_group(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *domain_pol,
				   const char *group_name,
				   uint32 access_mask, POLICY_HND *group_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CREATE_DOM_GROUP q;
	SAMR_R_CREATE_DOM_GROUP r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_create_dom_group\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_create_dom_group(&q, domain_pol, group_name, access_mask);

	if (!samr_io_q_create_dom_group("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CREATE_DOM_GROUP, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_create_dom_group("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (NT_STATUS_IS_OK(result))
		*group_pol = r.pol;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Add a domain group member */

NTSTATUS cli_samr_add_groupmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			       POLICY_HND *group_pol, uint32 rid)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_ADD_GROUPMEM q;
	SAMR_R_ADD_GROUPMEM r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_add_groupmem\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_add_groupmem(&q, group_pol, rid);

	if (!samr_io_q_add_groupmem("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_ADD_GROUPMEM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_add_groupmem("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Delete a domain group member */

NTSTATUS cli_samr_del_groupmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			       POLICY_HND *group_pol, uint32 rid)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_DEL_GROUPMEM q;
	SAMR_R_DEL_GROUPMEM r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_del_groupmem\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_del_groupmem(&q, group_pol, rid);

	if (!samr_io_q_del_groupmem("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_DEL_GROUPMEM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_del_groupmem("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query user info */

NTSTATUS cli_samr_query_userinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                 POLICY_HND *user_pol, uint16 switch_value, 
                                 SAM_USERINFO_CTR **ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_USERINFO q;
	SAMR_R_QUERY_USERINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_userinfo\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_userinfo(&q, user_pol, switch_value);

	if (!samr_io_q_query_userinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_USERINFO, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_query_userinfo("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;
	*ctr = r.ctr;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Set group info */

NTSTATUS cli_samr_set_groupinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				POLICY_HND *group_pol, GROUP_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_SET_GROUPINFO q;
	SAMR_R_SET_GROUPINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_set_groupinfo\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_set_groupinfo(&q, group_pol, ctr);

	if (!samr_io_q_set_groupinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_SET_GROUPINFO, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_set_groupinfo("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query group info */

NTSTATUS cli_samr_query_groupinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                  POLICY_HND *group_pol, uint32 info_level, 
                                  GROUP_INFO_CTR **ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_GROUPINFO q;
	SAMR_R_QUERY_GROUPINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_groupinfo\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_groupinfo(&q, group_pol, info_level);

	if (!samr_io_q_query_groupinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_GROUPINFO, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_query_groupinfo("", &r, &rbuf, 0))
		goto done;

	*ctr = r.ctr;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query user groups */

NTSTATUS cli_samr_query_usergroups(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                   POLICY_HND *user_pol, uint32 *num_groups, 
                                   DOM_GID **gid)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_USERGROUPS q;
	SAMR_R_QUERY_USERGROUPS r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_usergroups\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_usergroups(&q, user_pol);

	if (!samr_io_q_query_usergroups("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_USERGROUPS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_query_usergroups("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*num_groups = r.num_entries;
		*gid = r.gid;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Set alias info */

NTSTATUS cli_samr_set_aliasinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				POLICY_HND *alias_pol, ALIAS_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_SET_ALIASINFO q;
	SAMR_R_SET_ALIASINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_set_aliasinfo\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_set_aliasinfo(&q, alias_pol, ctr);

	if (!samr_io_q_set_aliasinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_SET_ALIASINFO, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_set_aliasinfo("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query user aliases */

NTSTATUS cli_samr_query_useraliases(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                   POLICY_HND *user_pol, uint32 num_sids, DOM_SID2 *sid,
				   uint32 *num_aliases, uint32 **als_rids)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_USERALIASES q;
	SAMR_R_QUERY_USERALIASES r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	unsigned int ptr=1;
	
	DEBUG(10,("cli_samr_query_useraliases\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_useraliases(&q, user_pol, num_sids, &ptr, sid);

	if (!samr_io_q_query_useraliases("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_USERALIASES, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_query_useraliases("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*num_aliases = r.num_entries;
		*als_rids = r.rid;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query user groups */

NTSTATUS cli_samr_query_groupmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                 POLICY_HND *group_pol, uint32 *num_mem, 
                                 uint32 **rid, uint32 **attr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_GROUPMEM q;
	SAMR_R_QUERY_GROUPMEM r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_groupmem\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_groupmem(&q, group_pol);

	if (!samr_io_q_query_groupmem("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_GROUPMEM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_query_groupmem("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*num_mem = r.num_entries;
		*rid = r.rid;
		*attr = r.attr;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/**
 * Enumerate domain users
 *
 * @param cli client state structure
 * @param mem_ctx talloc context
 * @param pol opened domain policy handle
 * @param start_idx starting index of enumeration, returns context for
                    next enumeration
 * @param acb_mask account control bit mask (to enumerate some particular
 *                 kind of accounts)
 * @param size max acceptable size of response
 * @param dom_users returned array of domain user names
 * @param rids returned array of domain user RIDs
 * @param num_dom_users numer returned entries
 * 
 * @return NTSTATUS returned in rpc response
 **/
NTSTATUS cli_samr_enum_dom_users(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                 POLICY_HND *pol, uint32 *start_idx, uint16 acb_mask,
                                 uint32 size, char ***dom_users, uint32 **rids,
                                 uint32 *num_dom_users)
{
	prs_struct qbuf;
	prs_struct rbuf;
	SAMR_Q_ENUM_DOM_USERS q;
	SAMR_R_ENUM_DOM_USERS r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;
	
	DEBUG(10,("cli_samr_enum_dom_users starting at index %u\n", (unsigned int)*start_idx));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);
	
	/* always init this */
	*num_dom_users = 0;
	
	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	/* Fill query structure with parameters */

	init_samr_q_enum_dom_users(&q, pol, *start_idx, acb_mask, 0, size);
	
	if (!samr_io_q_enum_dom_users("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_ENUM_DOM_USERS, &qbuf, &rbuf)) {
		goto done;
	}

	/* unpack received stream */

	if(!samr_io_r_enum_dom_users("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!NT_STATUS_IS_OK(result) &&
	    NT_STATUS_V(result) != NT_STATUS_V(STATUS_MORE_ENTRIES))
		goto done;
	
	*start_idx = r.next_idx;
	*num_dom_users = r.num_entries2;

	if (r.num_entries2) {
		/* allocate memory needed to return received data */	
		*rids = (uint32*)talloc(mem_ctx, sizeof(uint32) * r.num_entries2);
		if (!*rids) {
			DEBUG(0, ("Error in cli_samr_enum_dom_users(): out of memory\n"));
			return NT_STATUS_NO_MEMORY;
		}
		
		*dom_users = (char**)talloc(mem_ctx, sizeof(char*) * r.num_entries2);
		if (!*dom_users) {
			DEBUG(0, ("Error in cli_samr_enum_dom_users(): out of memory\n"));
			return NT_STATUS_NO_MEMORY;
		}
		
		/* fill output buffers with rpc response */
		for (i = 0; i < r.num_entries2; i++) {
			fstring conv_buf;
			
			(*rids)[i] = r.sam[i].rid;
			unistr2_to_ascii(conv_buf, &(r.uni_acct_name[i]), sizeof(conv_buf) - 1);
			(*dom_users)[i] = talloc_strdup(mem_ctx, conv_buf);
		}
	}
	
done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
	
	return result;
}

/* Enumerate domain groups */

NTSTATUS cli_samr_enum_dom_groups(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                  POLICY_HND *pol, uint32 *start_idx, 
                                  uint32 size, struct acct_info **dom_groups,
                                  uint32 *num_dom_groups)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_ENUM_DOM_GROUPS q;
	SAMR_R_ENUM_DOM_GROUPS r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 name_idx, i;

	DEBUG(10,("cli_samr_enum_dom_groups starting at index %u\n", (unsigned int)*start_idx));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_enum_dom_groups(&q, pol, *start_idx, size);

	if (!samr_io_q_enum_dom_groups("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_ENUM_DOM_GROUPS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_enum_dom_groups("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (!NT_STATUS_IS_OK(result) &&
	    NT_STATUS_V(result) != NT_STATUS_V(STATUS_MORE_ENTRIES))
		goto done;

	*num_dom_groups = r.num_entries2;

	if (*num_dom_groups == 0)
		goto done;

	if (!((*dom_groups) = (struct acct_info *)
	      talloc(mem_ctx, sizeof(struct acct_info) * *num_dom_groups))) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	memset(*dom_groups, 0, sizeof(struct acct_info) * (*num_dom_groups));

	name_idx = 0;

	for (i = 0; i < *num_dom_groups; i++) {

		(*dom_groups)[i].rid = r.sam[i].rid;

		if (r.sam[i].hdr_name.buffer) {
			unistr2_to_ascii((*dom_groups)[i].acct_name,
					 &r.uni_grp_name[name_idx],
					 sizeof(fstring) - 1);
			name_idx++;
		}

		*start_idx = r.next_idx;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Enumerate domain groups */

NTSTATUS cli_samr_enum_als_groups(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                  POLICY_HND *pol, uint32 *start_idx, 
                                  uint32 size, struct acct_info **dom_aliases,
                                  uint32 *num_dom_aliases)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_ENUM_DOM_ALIASES q;
	SAMR_R_ENUM_DOM_ALIASES r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 name_idx, i;

	DEBUG(10,("cli_samr_enum_als_groups starting at index %u\n", (unsigned int)*start_idx));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_enum_dom_aliases(&q, pol, *start_idx, size);

	if (!samr_io_q_enum_dom_aliases("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_ENUM_DOM_ALIASES, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_enum_dom_aliases("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	result = r.status;

	if (!NT_STATUS_IS_OK(result) &&
	    NT_STATUS_V(result) != NT_STATUS_V(STATUS_MORE_ENTRIES)) {
		goto done;
	}

	*num_dom_aliases = r.num_entries2;

	if (*num_dom_aliases == 0)
		goto done;

	if (!((*dom_aliases) = (struct acct_info *)
	      talloc(mem_ctx, sizeof(struct acct_info) * *num_dom_aliases))) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	memset(*dom_aliases, 0, sizeof(struct acct_info) * *num_dom_aliases);

	name_idx = 0;

	for (i = 0; i < *num_dom_aliases; i++) {

		(*dom_aliases)[i].rid = r.sam[i].rid;

		if (r.sam[i].hdr_name.buffer) {
			unistr2_to_ascii((*dom_aliases)[i].acct_name,
					 &r.uni_grp_name[name_idx],
					 sizeof(fstring) - 1);
			name_idx++;
		}

		*start_idx = r.next_idx;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query alias members */

NTSTATUS cli_samr_query_aliasmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                 POLICY_HND *alias_pol, uint32 *num_mem, 
                                 DOM_SID **sids)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_ALIASMEM q;
	SAMR_R_QUERY_ALIASMEM r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 i;

	DEBUG(10,("cli_samr_query_aliasmem\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_aliasmem(&q, alias_pol);

	if (!samr_io_q_query_aliasmem("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_ALIASMEM, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_query_aliasmem("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	*num_mem = r.num_sids;

	if (*num_mem == 0) {
		*sids = NULL;
		result = NT_STATUS_OK;
		goto done;
	}

	if (!(*sids = talloc(mem_ctx, sizeof(DOM_SID) * *num_mem))) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	for (i = 0; i < *num_mem; i++) {
		(*sids)[i] = r.sid[i].sid;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Open handle on an alias */

NTSTATUS cli_samr_open_alias(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                             POLICY_HND *domain_pol, uint32 access_mask, 
                             uint32 alias_rid, POLICY_HND *alias_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_OPEN_ALIAS q;
	SAMR_R_OPEN_ALIAS r;
	NTSTATUS result;

	DEBUG(10,("cli_samr_open_alias with rid 0x%x\n", alias_rid));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_open_alias(&q, domain_pol, access_mask, alias_rid);

	if (!samr_io_q_open_alias("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_OPEN_ALIAS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_open_alias("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*alias_pol = r.pol;
#ifdef __INSURE__
		alias_pol->marker = malloc(1);
#endif
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Create an alias */

NTSTATUS cli_samr_create_dom_alias(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				   POLICY_HND *domain_pol, const char *name,
				   POLICY_HND *alias_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CREATE_DOM_ALIAS q;
	SAMR_R_CREATE_DOM_ALIAS r;
	NTSTATUS result;

	DEBUG(10,("cli_samr_create_dom_alias named %s\n", name));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_create_dom_alias(&q, domain_pol, name);

	if (!samr_io_q_create_dom_alias("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CREATE_DOM_ALIAS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_create_dom_alias("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if (NT_STATUS_IS_OK(result = r.status)) {
		*alias_pol = r.alias_pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Add an alias member */

NTSTATUS cli_samr_add_aliasmem(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			       POLICY_HND *alias_pol, DOM_SID *member)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_ADD_ALIASMEM q;
	SAMR_R_ADD_ALIASMEM r;
	NTSTATUS result;

	DEBUG(10,("cli_samr_add_aliasmem"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_add_aliasmem(&q, alias_pol, member);

	if (!samr_io_q_add_aliasmem("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_ADD_ALIASMEM, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_add_aliasmem("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Delete an alias member */

NTSTATUS cli_samr_del_aliasmem(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			       POLICY_HND *alias_pol, DOM_SID *member)
{
	prs_struct qbuf, rbuf;
 	SAMR_Q_DEL_ALIASMEM q;
 	SAMR_R_DEL_ALIASMEM r;
 	NTSTATUS result;

 	DEBUG(10,("cli_samr_del_aliasmem"));

 	ZERO_STRUCT(q);
 	ZERO_STRUCT(r);

 	/* Initialise parse structures */

 	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
 	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

 	/* Marshall data and send request */

 	init_samr_q_del_aliasmem(&q, alias_pol, member);

	if (!samr_io_q_del_aliasmem("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_DEL_ALIASMEM, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_del_aliasmem("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query alias info */

NTSTATUS cli_samr_query_alias_info(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *alias_pol, uint16 switch_value,
				   ALIAS_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_ALIASINFO q;
	SAMR_R_QUERY_ALIASINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_dom_info\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_aliasinfo(&q, alias_pol, switch_value);

	if (!samr_io_q_query_aliasinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_ALIASINFO, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_query_aliasinfo("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	*ctr = r.ctr;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query domain info */

NTSTATUS cli_samr_query_dom_info(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                 POLICY_HND *domain_pol, uint16 switch_value,
                                 SAM_UNK_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_DOMAIN_INFO q;
	SAMR_R_QUERY_DOMAIN_INFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_dom_info\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_dom_info(&q, domain_pol, switch_value);

	if (!samr_io_q_query_dom_info("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_DOMAIN_INFO, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	r.ctr = ctr;

	if (!samr_io_r_query_dom_info("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* User change password */

NTSTATUS cli_samr_chgpasswd_user(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				 const char *username, 
				 const char *newpassword, 
				 const char *oldpassword )
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CHGPASSWD_USER q;
	SAMR_R_CHGPASSWD_USER r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	uchar new_nt_password[516];
	uchar new_lm_password[516];
	uchar old_nt_hash[16];
	uchar old_lanman_hash[16];
	uchar old_nt_hash_enc[16];
	uchar old_lanman_hash_enc[16];

	uchar new_nt_hash[16];
	uchar new_lanman_hash[16];

	DEBUG(10,("cli_samr_query_dom_info\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash(oldpassword, old_nt_hash);
	E_md4hash(newpassword, new_nt_hash);

	if (lp_client_lanman_auth() 
	    && E_deshash(newpassword, new_lanman_hash) 
	    && E_deshash(oldpassword, old_lanman_hash)) {
		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14) */

		encode_pw_buffer(new_lm_password, newpassword, STR_UNICODE);

		SamOEMhash( new_lm_password, old_nt_hash, 516);
		E_old_pw_hash( new_nt_hash, old_lanman_hash, old_lanman_hash_enc);
	} else {
		ZERO_STRUCT(new_lm_password);
		ZERO_STRUCT(old_lanman_hash_enc);
	}

	encode_pw_buffer(new_nt_password, newpassword, STR_UNICODE);
	
	SamOEMhash( new_nt_password, old_nt_hash, 516);
	E_old_pw_hash( new_nt_hash, old_nt_hash, old_nt_hash_enc);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_chgpasswd_user(&q, cli->srv_name_slash, username, 
				   new_nt_password, 
				   old_nt_hash_enc, 
				   new_lm_password,
				   old_lanman_hash_enc);

	if (!samr_io_q_chgpasswd_user("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CHGPASSWD_USER, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_chgpasswd_user("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* This function returns the bizzare set of (max_entries, max_size) required
   for the QueryDisplayInfo RPC to actually work against a domain controller
   with large (10k and higher) numbers of users.  These values were 
   obtained by inspection using ethereal and NT4 running User Manager. */

void get_query_dispinfo_params(int loop_count, uint32 *max_entries,
			       uint32 *max_size)
{
	switch(loop_count) {
	case 0:
		*max_entries = 512;
		*max_size = 16383;
		break;
	case 1:
		*max_entries = 1024;
		*max_size = 32766;
		break;
	case 2:
		*max_entries = 2048;
		*max_size = 65532;
		break;
	case 3:
		*max_entries = 4096;
		*max_size = 131064;
		break;
	default:              /* loop_count >= 4 */
		*max_entries = 4096;
		*max_size = 131071;
		break;
	}
}		     

/* Query display info */

NTSTATUS cli_samr_query_dispinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                 POLICY_HND *domain_pol, uint32 *start_idx,
                                 uint16 switch_value, uint32 *num_entries,
                                 uint32 max_entries, uint32 max_size,
				 SAM_DISPINFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_DISPINFO q;
	SAMR_R_QUERY_DISPINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_dispinfo for start_idx = %u\n", *start_idx));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	*num_entries = 0;

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_dispinfo(&q, domain_pol, switch_value,
				   *start_idx, max_entries, max_size);

	if (!samr_io_q_query_dispinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_DISPINFO, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	r.ctr = ctr;

	if (!samr_io_r_query_dispinfo("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

        result = r.status;

	if (!NT_STATUS_IS_OK(result) &&
	    NT_STATUS_V(result) != NT_STATUS_V(STATUS_MORE_ENTRIES)) {
		goto done;
	}

	*num_entries = r.num_entries;
	*start_idx += r.num_entries;  /* No next_idx in this structure! */

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Lookup rids.  Note that NT4 seems to crash if more than ~1000 rids are
   looked up in one packet. */

NTSTATUS cli_samr_lookup_rids(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                              POLICY_HND *domain_pol, uint32 flags,
                              uint32 num_rids, uint32 *rids, 
                              uint32 *num_names, char ***names,
                              uint32 **name_types)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_LOOKUP_RIDS q;
	SAMR_R_LOOKUP_RIDS r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 i;

	DEBUG(10,("cli_samr_lookup_rids\n"));

        if (num_rids > 1000) {
                DEBUG(2, ("cli_samr_lookup_rids: warning: NT4 can crash if "
                          "more than ~1000 rids are looked up at once.\n"));
        }

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_lookup_rids(mem_ctx, &q, domain_pol, flags,
				num_rids, rids);

	if (!samr_io_q_lookup_rids("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_LOOKUP_RIDS, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_lookup_rids("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	if (r.num_names1 == 0) {
		*num_names = 0;
		*names = NULL;
		goto done;
	}

	*num_names = r.num_names1;
	*names = talloc(mem_ctx, sizeof(char *) * r.num_names1);
	*name_types = talloc(mem_ctx, sizeof(uint32) * r.num_names1);

	for (i = 0; i < r.num_names1; i++) {
		fstring tmp;

		unistr2_to_ascii(tmp, &r.uni_name[i], sizeof(tmp) - 1);
		(*names)[i] = talloc_strdup(mem_ctx, tmp);
		(*name_types)[i] = r.type[i];
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Lookup names */

NTSTATUS cli_samr_lookup_names(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                               POLICY_HND *domain_pol, uint32 flags,
                               uint32 num_names, const char **names,
                               uint32 *num_rids, uint32 **rids,
                               uint32 **rid_types)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_LOOKUP_NAMES q;
	SAMR_R_LOOKUP_NAMES r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 i;

	DEBUG(10,("cli_samr_lookup_names\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_lookup_names(mem_ctx, &q, domain_pol, flags,
				 num_names, names);

	if (!samr_io_q_lookup_names("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_LOOKUP_NAMES, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_lookup_names("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	if (r.num_rids1 == 0) {
		*num_rids = 0;
		goto done;
	}

	*num_rids = r.num_rids1;
	*rids = talloc(mem_ctx, sizeof(uint32) * r.num_rids1);
	*rid_types = talloc(mem_ctx, sizeof(uint32) * r.num_rids1);

	for (i = 0; i < r.num_rids1; i++) {
		(*rids)[i] = r.rids[i];
		(*rid_types)[i] = r.types[i];
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Create a domain user */

NTSTATUS cli_samr_create_dom_user(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                  POLICY_HND *domain_pol, const char *acct_name,
                                  uint32 acb_info, uint32 unknown, 
                                  POLICY_HND *user_pol, uint32 *rid)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CREATE_USER q;
	SAMR_R_CREATE_USER r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_create_dom_user %s\n", acct_name));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_create_user(&q, domain_pol, acct_name, acb_info, unknown);

	if (!samr_io_q_create_user("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CREATE_USER, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_create_user("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

	if (user_pol)
		*user_pol = r.user_pol;

	if (rid)
		*rid = r.user_rid;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Set userinfo */

NTSTATUS cli_samr_set_userinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                               POLICY_HND *user_pol, uint16 switch_value,
                               DATA_BLOB *sess_key, SAM_USERINFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_SET_USERINFO q;
	SAMR_R_SET_USERINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_set_userinfo\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	if (!sess_key->length) {
		DEBUG(1, ("No user session key\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	q.ctr = ctr;

	init_samr_q_set_userinfo(&q, user_pol, sess_key, switch_value, 
				 ctr->info.id);

	if (!samr_io_q_set_userinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_SET_USERINFO, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_set_userinfo("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Set userinfo2 */

NTSTATUS cli_samr_set_userinfo2(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                POLICY_HND *user_pol, uint16 switch_value,
                                DATA_BLOB *sess_key, SAM_USERINFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_SET_USERINFO2 q;
	SAMR_R_SET_USERINFO2 r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_set_userinfo2\n"));

	if (!sess_key->length) {
		DEBUG(1, ("No user session key\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_set_userinfo2(&q, user_pol, sess_key, switch_value, ctr);

	if (!samr_io_q_set_userinfo2("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_SET_USERINFO2, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_set_userinfo2("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (!NT_STATUS_IS_OK(result = r.status)) {
		goto done;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Delete domain group */

NTSTATUS cli_samr_delete_dom_group(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                  POLICY_HND *group_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_DELETE_DOM_GROUP q;
	SAMR_R_DELETE_DOM_GROUP r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_delete_dom_group\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_delete_dom_group(&q, group_pol);

	if (!samr_io_q_delete_dom_group("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_DELETE_DOM_GROUP, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_delete_dom_group("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Delete domain alias */

NTSTATUS cli_samr_delete_dom_alias(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                  POLICY_HND *alias_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_DELETE_DOM_ALIAS q;
	SAMR_R_DELETE_DOM_ALIAS r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_delete_dom_alias\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_delete_dom_alias(&q, alias_pol);

	if (!samr_io_q_delete_dom_alias("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_DELETE_DOM_ALIAS, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_delete_dom_alias("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Delete domain user */

NTSTATUS cli_samr_delete_dom_user(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                  POLICY_HND *user_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_DELETE_DOM_USER q;
	SAMR_R_DELETE_DOM_USER r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_delete_dom_user\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_delete_dom_user(&q, user_pol);

	if (!samr_io_q_delete_dom_user("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_DELETE_DOM_USER, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_delete_dom_user("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query user security object */

NTSTATUS cli_samr_query_sec_obj(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                 POLICY_HND *user_pol, uint16 switch_value, 
                                 TALLOC_CTX *ctx, SEC_DESC_BUF **sec_desc_buf)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_SEC_OBJ q;
	SAMR_R_QUERY_SEC_OBJ r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_query_sec_obj\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_query_sec_obj(&q, user_pol, switch_value);

	if (!samr_io_q_query_sec_obj("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_SEC_OBJECT, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_query_sec_obj("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	result = r.status;
	*sec_desc_buf=dup_sec_desc_buf(ctx, r.buf);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Get domain password info */

NTSTATUS cli_samr_get_dom_pwinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 uint16 *unk_0, uint16 *unk_1, uint16 *unk_2)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_GET_DOM_PWINFO q;
	SAMR_R_GET_DOM_PWINFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_get_dom_pwinfo\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_get_dom_pwinfo(&q, cli->desthost);

	if (!samr_io_q_get_dom_pwinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_GET_DOM_PWINFO, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_get_dom_pwinfo("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (NT_STATUS_IS_OK(result)) {
		if (unk_0)
			*unk_0 = r.unk_0;
		if (unk_1)
			*unk_1 = r.unk_1;
		if (unk_2)
			*unk_2 = r.unk_2;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Lookup Domain Name */

NTSTATUS cli_samr_lookup_domain(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				POLICY_HND *user_pol, char *domain_name, 
				DOM_SID *sid)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_LOOKUP_DOMAIN q;
	SAMR_R_LOOKUP_DOMAIN r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(10,("cli_samr_lookup_domain\n"));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_samr_q_lookup_domain(&q, user_pol, domain_name);

	if (!samr_io_q_lookup_domain("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_LOOKUP_DOMAIN, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!samr_io_r_lookup_domain("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (NT_STATUS_IS_OK(result))
		sid_copy(sid, &r.dom_sid.sid);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}
