/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client
   Copyright (C) Tim Potter                             2000,
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

/* Opens a SMB connection to the SAMR pipe */

struct cli_state *cli_samr_initialise(struct cli_state *cli, char *system_name,
				      struct ntuser_creds *creds)
{
	struct in_addr dest_ip;
	struct nmb_name calling, called;
	fstring dest_host;
	extern pstring global_myname;
	struct ntuser_creds anon;

	/* Initialise cli_state information */

	if (!cli_initialise(cli)) {
		return NULL;
	}

	if (!creds) {
		ZERO_STRUCT(anon);
		anon.pwd.null_pwd = 1;
		creds = &anon;
	}

	cli_init_creds(cli, creds);

	/* Establish a SMB connection */

	if (!resolve_srv_name(system_name, dest_host, &dest_ip)) {
		return NULL;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(cli, dest_host, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		return NULL;
	}

	/* Open a NT session thingy */

	if (!cli_nt_session_open(cli, PIPE_SAMR)) {
		cli_shutdown(cli);
		return NULL;
	}

	return cli;
}

/* Shut down a SMB connection to the SAMR pipe */

void cli_samr_shutdown(struct cli_state *cli)
{
	if (cli->fd != -1) cli_ulogoff(cli);
	cli_shutdown(cli);
}

/* Connect to SAMR database */

uint32 cli_samr_connect(struct cli_state *cli, char *srv_name,
			uint32 access_mask, POLICY_HND *connect_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CONNECT q;
	SAMR_R_CONNECT r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, True);

	/* Marshall data and send request */

	init_samr_q_connect(&q, srv_name, access_mask);

	if (!samr_io_q_connect("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CONNECT, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_connect("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
		*connect_pol = r.connect_pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Close SAMR handle */

uint32 cli_samr_close(struct cli_state *cli, POLICY_HND *connect_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_CLOSE_HND q;
	SAMR_R_CLOSE_HND r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, True);

	/* Marshall data and send request */

	init_samr_q_close_hnd(&q, connect_pol);

	if (!samr_io_q_close_hnd("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_CLOSE_HND, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_close_hnd("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
		*connect_pol = r.pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Open handle on a domain */

uint32 cli_samr_open_domain(struct cli_state *cli, POLICY_HND *connect_pol,
			    uint32 access_mask, DOM_SID *domain_sid,
			    POLICY_HND *domain_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_OPEN_DOMAIN q;
	SAMR_R_OPEN_DOMAIN r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, True);

	/* Marshall data and send request */

	init_samr_q_open_domain(&q, connect_pol, access_mask, domain_sid);

	if (!samr_io_q_open_domain("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_OPEN_DOMAIN, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_open_domain("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
		*domain_pol = r.domain_pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Open handle on a user */

uint32 cli_samr_open_user(struct cli_state *cli, POLICY_HND *domain_pol,
			  uint32 access_mask, uint32 user_rid,
			  POLICY_HND *user_pol)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_OPEN_USER q;
	SAMR_R_OPEN_USER r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, True);

	/* Marshall data and send request */

	init_samr_q_open_user(&q, domain_pol, access_mask, user_rid);

	if (!samr_io_q_open_user("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_OPEN_USER, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!samr_io_r_open_user("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
		*user_pol = r.user_pol;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Query user info */

uint32 cli_samr_query_userinfo(struct cli_state *cli, POLICY_HND *user_pol, 
			       uint16 switch_value, SAM_USERINFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_QUERY_USERINFO q;
	SAMR_R_QUERY_USERINFO r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, True);

	/* Marshall data and send request */

	init_samr_q_query_userinfo(&q, user_pol, switch_value);

	if (!samr_io_q_query_userinfo("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SAMR_QUERY_USERINFO, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	r.ctr = ctr;

	if (!samr_io_r_query_userinfo("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}
