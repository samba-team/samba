/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   
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

/* Opens a SMB connection to the netdfs pipe */

struct cli_state *cli_dfs_initialise(struct cli_state *cli, char *system_name,
				     struct ntuser_creds *creds)
{
        return cli_pipe_initialise(cli, system_name, PIPE_NETDFS, creds);
}

/* Query DFS support */

NTSTATUS cli_dfs_exist(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                       BOOL *dfs_exists)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_EXIST q;
	DFS_R_DFS_EXIST r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_dfs_q_dfs_exist(&q);

	if (!dfs_io_q_dfs_exist("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, DFS_EXIST, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!dfs_io_r_dfs_exist("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return result */

	*dfs_exists = (r.status != 0);

	result = NT_STATUS_OK;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_dfs_add(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                     char *entrypath, char *servername, char *sharename,
                     char *comment, uint32 flags)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_ADD q;
	DFS_R_DFS_ADD r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_dfs_q_dfs_add(&q, entrypath, servername, sharename, comment,
			   flags);

	if (!dfs_io_q_dfs_add("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, DFS_ADD, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!dfs_io_r_dfs_add("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return result */

        result = werror_to_ntstatus(r.status);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_dfs_remove(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                        char *entrypath, char *servername, char *sharename)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_REMOVE q;
	DFS_R_DFS_REMOVE r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_dfs_q_dfs_remove(&q, entrypath, servername, sharename);

	if (!dfs_io_q_dfs_remove("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, DFS_REMOVE, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!dfs_io_r_dfs_remove("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return result */

	result = werror_to_ntstatus(r.status);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_dfs_get_info(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                          char *entrypath, char *servername, char *sharename,
                          uint32 info_level, DFS_INFO_CTR *ctr)

{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_GET_INFO q;
	DFS_R_DFS_GET_INFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_dfs_q_dfs_get_info(&q, entrypath, servername, sharename,
				info_level);

	if (!dfs_io_q_dfs_get_info("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, DFS_GET_INFO, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!dfs_io_r_dfs_get_info("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return result */

	result = werror_to_ntstatus(r.status);
	*ctr = r.ctr;
	
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Enumerate dfs shares */

NTSTATUS cli_dfs_enum(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                      uint32 info_level, DFS_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_ENUM q;
	DFS_R_DFS_ENUM r;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_dfs_q_dfs_enum(&q, info_level, ctr);

	if (!dfs_io_q_dfs_enum("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, DFS_ENUM, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */
	
	r.ctr = ctr;

	if (!dfs_io_r_dfs_enum("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return result */

	result = werror_to_ntstatus(r.status);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}
