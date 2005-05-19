/* 
   Unix SMB/CIFS implementation.

   RPC pipe client

   Copyright (C) Volker Lendecke 2005
   
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

NTSTATUS rpccli_unixinfo_uid2sid(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx, uid_t uid, DOM_SID *sid)
{
	prs_struct qbuf, rbuf;
	UNIXINFO_Q_UID_TO_SID q;
	UNIXINFO_R_UID_TO_SID r;
	NTSTATUS result = NT_STATUS_NET_WRITE_FAULT;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	if (!prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!prs_init(&rbuf, 0, mem_ctx, UNMARSHALL)) {
		prs_mem_free(&qbuf);
		return NT_STATUS_NO_MEMORY;
	}

	/* Marshall data and send request */
	{
		UINT64_S uid64;
		uid64.high = 0;
		uid64.low = uid;
		init_q_unixinfo_uid_to_sid(&q, uid64);
	}

	if (!unixinfo_io_q_unixinfo_uid_to_sid("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req_int(cli, UNIXINFO_UID_TO_SID, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!unixinfo_io_r_unixinfo_uid_to_sid("", &r, &rbuf, 0))
		goto done;

	if (NT_STATUS_IS_OK(r.status) && (sid != NULL)) {
		sid_copy(sid, &r.sid);
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_unixinfo_uid2sid(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      uid_t uid, DOM_SID *sid)
{
	return rpccli_unixinfo_uid2sid(&cli->pipes[PI_UNIXINFO], mem_ctx,
				       uid, sid);
}

NTSTATUS rpccli_unixinfo_sid2uid(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const DOM_SID *sid, uid_t *uid)
{
	prs_struct qbuf, rbuf;
	UNIXINFO_Q_SID_TO_UID q;
	UNIXINFO_R_SID_TO_UID r;
	NTSTATUS result = NT_STATUS_NET_WRITE_FAULT;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	if (!prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!prs_init(&rbuf, 0, mem_ctx, UNMARSHALL)) {
		prs_mem_free(&qbuf);
		return NT_STATUS_NO_MEMORY;
	}

	/* Marshall data and send request */
	init_q_unixinfo_sid_to_uid(&q, sid);

	if (!unixinfo_io_q_unixinfo_sid_to_uid("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req_int(cli, UNIXINFO_SID_TO_UID, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!unixinfo_io_r_unixinfo_sid_to_uid("", &r, &rbuf, 0))
		goto done;

	if (NT_STATUS_IS_OK(r.status)) {
		if (r.uid.high != 0) {
			/* 64-Bit uid's not yet handled */
			goto done;
		}
		if (uid != NULL) {
			*uid = r.uid.low;
		}
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_unixinfo_sid2uid(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      const DOM_SID *sid, uid_t *uid)
{
	return rpccli_unixinfo_sid2uid(&cli->pipes[PI_UNIXINFO], mem_ctx,
				       sid, uid);
}

NTSTATUS rpccli_unixinfo_gid2sid(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx, gid_t gid, DOM_SID *sid)
{
	prs_struct qbuf, rbuf;
	UNIXINFO_Q_GID_TO_SID q;
	UNIXINFO_R_GID_TO_SID r;
	NTSTATUS result = NT_STATUS_NET_WRITE_FAULT;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	if (!prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!prs_init(&rbuf, 0, mem_ctx, UNMARSHALL)) {
		prs_mem_free(&qbuf);
		return NT_STATUS_NO_MEMORY;
	}

	/* Marshall data and send request */
	{
		UINT64_S gid64;
		gid64.high = 0;
		gid64.low = gid;
		init_q_unixinfo_gid_to_sid(&q, gid64);
	}

	if (!unixinfo_io_q_unixinfo_gid_to_sid("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req_int(cli, UNIXINFO_GID_TO_SID, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!unixinfo_io_r_unixinfo_gid_to_sid("", &r, &rbuf, 0))
		goto done;

	if (NT_STATUS_IS_OK(r.status) && (sid != NULL)) {
		sid_copy(sid, &r.sid);
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_unixinfo_gid2sid(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      gid_t gid, DOM_SID *sid)
{
	return rpccli_unixinfo_gid2sid(&cli->pipes[PI_UNIXINFO], mem_ctx, gid,
				       sid);
}

NTSTATUS rpccli_unixinfo_sid2gid(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const DOM_SID *sid, gid_t *gid)
{
	prs_struct qbuf, rbuf;
	UNIXINFO_Q_SID_TO_GID q;
	UNIXINFO_R_SID_TO_GID r;
	NTSTATUS result = NT_STATUS_NET_WRITE_FAULT;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	if (!prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!prs_init(&rbuf, 0, mem_ctx, UNMARSHALL)) {
		prs_mem_free(&qbuf);
		return NT_STATUS_NO_MEMORY;
	}

	/* Marshall data and send request */
	init_q_unixinfo_sid_to_gid(&q, sid);

	if (!unixinfo_io_q_unixinfo_sid_to_gid("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req_int(cli, UNIXINFO_SID_TO_GID, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!unixinfo_io_r_unixinfo_sid_to_gid("", &r, &rbuf, 0))
		goto done;

	if (NT_STATUS_IS_OK(r.status)) {
		if (r.gid.high != 0) {
			/* 64-Bit gid's not yet handled */
			goto done;
		}
		if (gid != NULL) {
			*gid = r.gid.low;
		}
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_unixinfo_sid2gid(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      const DOM_SID *sid, gid_t *gid)
{
	return rpccli_unixinfo_sid2gid(&cli->pipes[PI_UNIXINFO], mem_ctx, sid,
				       gid);
}

NTSTATUS rpccli_unixinfo_getpwuid(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  int count, uid_t *uids,
				  struct unixinfo_getpwuid **info)
{
	prs_struct qbuf, rbuf;
	UNIXINFO_Q_GETPWUID q;
	UNIXINFO_R_GETPWUID r;
	NTSTATUS result = NT_STATUS_NET_WRITE_FAULT;
	int i;
	UINT64_S *uids64;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	if (!prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!prs_init(&rbuf, 0, mem_ctx, UNMARSHALL)) {
		prs_mem_free(&qbuf);
		return NT_STATUS_NO_MEMORY;
	}

	/* Marshall data and send request */

	uids64 = SMB_MALLOC_ARRAY(UINT64_S, count);
	if (uids64 == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<count; i++) {
		uids64[i].high = 0;
		uids64[i].low = uids[i];
	}

	init_q_unixinfo_getpwuid(&q, count, uids64);

	if (!unixinfo_io_q_unixinfo_getpwuid("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req_int(cli, UNIXINFO_GETPWUID, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!unixinfo_io_r_unixinfo_getpwuid("", &r, &rbuf, 0))
		goto done;

	if (!NT_STATUS_IS_OK(r.status)) {
		result = r.status;
		*info = NULL;
		goto done;
	}

	if (r.count != count) {
		DEBUG(0, ("Expected array size %d, got %d\n",
			  count, r.count));
		goto done;
	}

	*info = TALLOC_ARRAY(mem_ctx, struct unixinfo_getpwuid, count);
	if (*info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<count; i++) {
		(*info)[i].status = r.info[i].status;
		(*info)[i].homedir = talloc_strdup(mem_ctx, r.info[i].homedir);
		(*info)[i].shell = talloc_strdup(mem_ctx, r.info[i].shell);
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_unixinfo_getpwuid(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			       int count, uid_t *uids,
			       struct unixinfo_getpwuid **info)
{
	return rpccli_unixinfo_getpwuid(&cli->pipes[PI_UNIXINFO], mem_ctx,
					count, uids, info);
}

