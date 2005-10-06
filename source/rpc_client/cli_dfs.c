/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   Copyright (C) Jeremy Allison				2005.
   
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

/* Query DFS support */

NTSTATUS rpccli_dfs_exist(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                       BOOL *dfs_exists)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_EXIST q;
	DFS_R_DFS_EXIST r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

        init_dfs_q_dfs_exist(&q);

	CLI_DO_RPC( cli, mem_ctx, PI_NETDFS, DFS_EXIST,
		q, r,
		qbuf, rbuf,
		dfs_io_q_dfs_exist,
		dfs_io_r_dfs_exist,
		NT_STATUS_UNSUCCESSFUL);

	/* Return result */

	*dfs_exists = (r.status != 0);

	result = NT_STATUS_OK;

	return result;
}

NTSTATUS rpccli_dfs_add(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                     const char *entrypath, const char *servername, 
		     const char *sharename, const char *comment, uint32 flags)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_ADD q;
	DFS_R_DFS_ADD r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

        init_dfs_q_dfs_add(&q, entrypath, servername, sharename, comment,
			   flags);

	CLI_DO_RPC( cli, mem_ctx, PI_NETDFS, DFS_ADD,
		q, r,
		qbuf, rbuf,
		dfs_io_q_dfs_add,
		dfs_io_r_dfs_add,
		NT_STATUS_UNSUCCESSFUL);

	/* Return result */

        result = werror_to_ntstatus(r.status);

	return result;
}

NTSTATUS rpccli_dfs_remove(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                        const char *entrypath, const char *servername, 
			const char *sharename)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_REMOVE q;
	DFS_R_DFS_REMOVE r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

        init_dfs_q_dfs_remove(&q, entrypath, servername, sharename);

	CLI_DO_RPC( cli, mem_ctx, PI_NETDFS, DFS_REMOVE,
		q, r,
		qbuf, rbuf,
		dfs_io_q_dfs_remove,
		dfs_io_r_dfs_remove,
		NT_STATUS_UNSUCCESSFUL);

	/* Return result */

	result = werror_to_ntstatus(r.status);

	return result;
}

NTSTATUS rpccli_dfs_get_info(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                          const char *entrypath, const char *servername, 
			  const char *sharename, uint32 info_level, 
			  DFS_INFO_CTR *ctr)

{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_GET_INFO q;
	DFS_R_DFS_GET_INFO r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

        init_dfs_q_dfs_get_info(&q, entrypath, servername, sharename,
				info_level);

	CLI_DO_RPC( cli, mem_ctx, PI_NETDFS, DFS_GET_INFO,
		q, r,
		qbuf, rbuf,
		dfs_io_q_dfs_get_info,
		dfs_io_r_dfs_get_info,
		NT_STATUS_UNSUCCESSFUL);

	/* Return result */

	result = werror_to_ntstatus(r.status);
	*ctr = r.ctr;
	
	return result;
}

/* Enumerate dfs shares */

NTSTATUS rpccli_dfs_enum(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                      uint32 info_level, DFS_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	DFS_Q_DFS_ENUM q;
	DFS_R_DFS_ENUM r;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

        init_dfs_q_dfs_enum(&q, info_level, ctr);

	r.ctr = ctr;

	CLI_DO_RPC( cli, mem_ctx, PI_NETDFS, DFS_ENUM,
		q, r,
		qbuf, rbuf,
		dfs_io_q_dfs_enum,
		dfs_io_r_dfs_enum,
		NT_STATUS_UNSUCCESSFUL);

	/* Return result */

	result = werror_to_ntstatus(r.status);

	return result;
}
