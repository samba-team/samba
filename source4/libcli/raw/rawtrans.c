/* 
   Unix SMB/CIFS implementation.
   raw trans/trans2/nttrans operations

   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
#include <tevent.h>
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "../libcli/smb/smbXcli_base.h"

static void smb_raw_trans_backend_done(struct tevent_req *subreq);

static struct smbcli_request *smb_raw_trans_backend_send(struct smbcli_tree *tree,
						         struct smb_trans2 *parms,
						         uint8_t command)
{
	struct smbcli_request *req;
	uint8_t additional_flags;
	uint8_t clear_flags;
	uint16_t additional_flags2;
	uint16_t clear_flags2;
	uint32_t pid;
	struct smbXcli_tcon *tcon = NULL;
	struct smbXcli_session *session = NULL;
	const char *pipe_name = NULL;
	uint8_t s;
	uint32_t timeout_msec;
	uint32_t tmp;

	tmp = parms->in.params.length + parms->in.data.length;

	req = smbcli_request_setup(tree, command, parms->in.setup_count, tmp);
	if (req == NULL) {
		return NULL;
	}

	additional_flags = CVAL(req->out.hdr, HDR_FLG);
	additional_flags2 = SVAL(req->out.hdr, HDR_FLG2);
	pid  = SVAL(req->out.hdr, HDR_PID);
	pid |= SVAL(req->out.hdr, HDR_PIDHIGH)<<16;

	if (req->session) {
		session = req->session->smbXcli;
	}

	if (req->tree) {
		tcon = req->tree->smbXcli;
	}

	clear_flags = ~additional_flags;
	clear_flags2 = ~additional_flags2;

	timeout_msec = req->transport->options.request_timeout * 1000;

	for (s=0; s < parms->in.setup_count; s++) {
		SSVAL(req->out.vwv, VWV(s), parms->in.setup[s]);
	}

	memcpy(req->out.data,
	       parms->in.params.data,
	       parms->in.params.length);
	memcpy(req->out.data + parms->in.params.length,
	       parms->in.data.data,
	       parms->in.data.length);

	if (command == SMBtrans && parms->in.trans_name) {
		pipe_name = parms->in.trans_name;
	}

	req->subreqs[0] = smb1cli_trans_send(req,
					     req->transport->ev,
					     req->transport->conn,
					     command,
					     additional_flags,
					     clear_flags,
					     additional_flags2,
					     clear_flags2,
					     timeout_msec,
					     pid,
					     tcon,
					     session,
					     pipe_name,
					     0xFFFF, /* fid */
					     0, /* function */
					     parms->in.flags,
					     (uint16_t *)req->out.vwv,
					     parms->in.setup_count,
					     parms->in.max_setup,
					     req->out.data,
					     parms->in.params.length,
					     parms->in.max_param,
					     req->out.data+
					     parms->in.params.length,
					     parms->in.data.length,
					     parms->in.max_data);
	if (req->subreqs[0] == NULL) {
		talloc_free(req);
		return NULL;
	}
	tevent_req_set_callback(req->subreqs[0],
				smb_raw_trans_backend_done,
				req);

	return req;
}

static void smb_raw_trans_backend_done(struct tevent_req *subreq)
{
	struct smbcli_request *req =
		tevent_req_callback_data(subreq,
		struct smbcli_request);
	struct smbcli_transport *transport = req->transport;
	uint16_t *setup = NULL;
	uint8_t num_setup = 0;
	uint8_t s;
	uint8_t *param = NULL;
	uint32_t num_param = 0;
	uint8_t *data = NULL;
	uint32_t num_data = 0;

	req->status = smb1cli_trans_recv(req->subreqs[0], req,
					 &req->flags2,
					 &setup,
					 0, /* min_setup */
					 &num_setup,
					 &param,
					 0, /* min_param */
					 &num_param,
					 &data,
					 0, /* min_data */
					 &num_data);
	TALLOC_FREE(req->subreqs[0]);
	if (NT_STATUS_IS_ERR(req->status)) {
		req->state = SMBCLI_REQUEST_ERROR;
		transport->error.e.nt_status = req->status;
		transport->error.etype = ETYPE_SMB;
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}

	req->trans2.out.setup_count = num_setup;
	req->trans2.out.setup = talloc_array(req, uint16_t, num_setup);
	if (req->trans2.out.setup == NULL) {
		req->state = SMBCLI_REQUEST_ERROR;
		req->status = NT_STATUS_NO_MEMORY;
		transport->error.e.nt_status = req->status;
		transport->error.etype = ETYPE_SMB;
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}
	for (s = 0; s < num_setup; s++) {
		req->trans2.out.setup[s] = SVAL(setup, VWV(s));
	}

	req->trans2.out.params.data = param;
	req->trans2.out.params.length = num_param;

	req->trans2.out.data.data = data;
	req->trans2.out.data.length = num_data;

	transport->error.e.nt_status = req->status;
	if (NT_STATUS_IS_OK(req->status)) {
		transport->error.etype = ETYPE_NONE;
	} else {
		transport->error.etype = ETYPE_SMB;
	}

	req->state = SMBCLI_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

static NTSTATUS smb_raw_trans_backend_recv(struct smbcli_request *req,
					   TALLOC_CTX *mem_ctx,
					   struct smb_trans2 *parms)
{
	if (!smbcli_request_receive(req) ||
	    smbcli_request_is_error(req)) {
		goto failed;
	}

	parms->out = req->trans2.out;
	talloc_steal(mem_ctx, parms->out.setup);
	talloc_steal(mem_ctx, parms->out.params.data);
	talloc_steal(mem_ctx, parms->out.data.data);

failed:
	return smbcli_request_destroy(req);
}

_PUBLIC_ struct smbcli_request *smb_raw_trans_send(struct smbcli_tree *tree,
				       struct smb_trans2 *parms)
{
	return smb_raw_trans_backend_send(tree, parms, SMBtrans);
}

_PUBLIC_ NTSTATUS smb_raw_trans_recv(struct smbcli_request *req,
			     TALLOC_CTX *mem_ctx,
			     struct smb_trans2 *parms)
{
	return smb_raw_trans_backend_recv(req, mem_ctx, parms);
}

_PUBLIC_ NTSTATUS smb_raw_trans(struct smbcli_tree *tree,
		       TALLOC_CTX *mem_ctx,
		       struct smb_trans2 *parms)
{
	struct smbcli_request *req;
	req = smb_raw_trans_send(tree, parms);
	if (!req) return NT_STATUS_UNSUCCESSFUL;
	return smb_raw_trans_recv(req, mem_ctx, parms);
}

struct smbcli_request *smb_raw_trans2_send(struct smbcli_tree *tree,
				       struct smb_trans2 *parms)
{
	return smb_raw_trans_backend_send(tree, parms, SMBtrans2);
}

NTSTATUS smb_raw_trans2_recv(struct smbcli_request *req,
			     TALLOC_CTX *mem_ctx,
			     struct smb_trans2 *parms)
{
	return smb_raw_trans_backend_recv(req, mem_ctx, parms);
}

NTSTATUS smb_raw_trans2(struct smbcli_tree *tree,
			TALLOC_CTX *mem_ctx,
			struct smb_trans2 *parms)
{
	struct smbcli_request *req;
	req = smb_raw_trans2_send(tree, parms);
	if (!req) return NT_STATUS_UNSUCCESSFUL;
	return smb_raw_trans2_recv(req, mem_ctx, parms);
}

static void smb_raw_nttrans_done(struct tevent_req *subreq);

struct smbcli_request *smb_raw_nttrans_send(struct smbcli_tree *tree,
					    struct smb_nttrans *parms)
{
	struct smbcli_request *req;
	uint8_t additional_flags;
	uint8_t clear_flags;
	uint16_t additional_flags2;
	uint16_t clear_flags2;
	uint32_t pid;
	struct smbXcli_tcon *tcon = NULL;
	struct smbXcli_session *session = NULL;
	uint32_t timeout_msec;
	uint32_t tmp;

	tmp = parms->in.params.length + parms->in.data.length;

	req = smbcli_request_setup(tree, SMBnttrans, parms->in.setup_count, tmp);
	if (req == NULL) {
		return NULL;
	}

	additional_flags = CVAL(req->out.hdr, HDR_FLG);
	additional_flags2 = SVAL(req->out.hdr, HDR_FLG2);
	pid  = SVAL(req->out.hdr, HDR_PID);
	pid |= SVAL(req->out.hdr, HDR_PIDHIGH)<<16;

	if (req->session) {
		session = req->session->smbXcli;
	}

	if (req->tree) {
		tcon = req->tree->smbXcli;
	}

	clear_flags = ~additional_flags;
	clear_flags2 = ~additional_flags2;

	timeout_msec = req->transport->options.request_timeout * 1000;

	memcpy(req->out.vwv,
	       parms->in.setup,
	       parms->in.setup_count * 2);

	memcpy(req->out.data,
	       parms->in.params.data,
	       parms->in.params.length);
	memcpy(req->out.data + parms->in.params.length,
	       parms->in.data.data,
	       parms->in.data.length);

	req->subreqs[0] = smb1cli_trans_send(req,
					     req->transport->ev,
					     req->transport->conn,
					     SMBnttrans,
					     additional_flags,
					     clear_flags,
					     additional_flags2,
					     clear_flags2,
					     timeout_msec,
					     pid,
					     tcon,
					     session,
					     NULL, /* pipe_name */
					     0xFFFF, /* fid */
					     parms->in.function,
					     0, /* flags */
					     (uint16_t *)req->out.vwv,
					     parms->in.setup_count,
					     parms->in.max_setup,
					     req->out.data,
					     parms->in.params.length,
					     parms->in.max_param,
					     req->out.data+
					     parms->in.params.length,
					     parms->in.data.length,
					     parms->in.max_data);
	if (req->subreqs[0] == NULL) {
		talloc_free(req);
		return NULL;
	}
	tevent_req_set_callback(req->subreqs[0],
				smb_raw_nttrans_done,
				req);

	return req;
}

static void smb_raw_nttrans_done(struct tevent_req *subreq)
{
	struct smbcli_request *req =
		tevent_req_callback_data(subreq,
		struct smbcli_request);
	struct smbcli_transport *transport = req->transport;
	uint16_t *setup = NULL;
	uint8_t num_setup = 0;
	uint8_t *param = NULL;
	uint32_t num_param = 0;
	uint8_t *data = NULL;
	uint32_t num_data = 0;

	req->status = smb1cli_trans_recv(req->subreqs[0], req,
					 &req->flags2,
					 &setup,
					 0, /* min_setup */
					 &num_setup,
					 &param,
					 0, /* min_param */
					 &num_param,
					 &data,
					 0, /* min_data */
					 &num_data);
	TALLOC_FREE(req->subreqs[0]);
	if (NT_STATUS_IS_ERR(req->status)) {
		req->state = SMBCLI_REQUEST_ERROR;
		transport->error.e.nt_status = req->status;
		transport->error.etype = ETYPE_SMB;
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}

	req->nttrans.out.setup_count = num_setup;
	req->nttrans.out.setup = (uint8_t *)setup;

	req->nttrans.out.params.data = param;
	req->nttrans.out.params.length = num_param;

	req->nttrans.out.data.data = data;
	req->nttrans.out.data.length = num_data;

	transport->error.e.nt_status = req->status;
	if (NT_STATUS_IS_OK(req->status)) {
		transport->error.etype = ETYPE_NONE;
	} else {
		transport->error.etype = ETYPE_SMB;
	}

	req->state = SMBCLI_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

NTSTATUS smb_raw_nttrans_recv(struct smbcli_request *req,
			      TALLOC_CTX *mem_ctx,
			      struct smb_nttrans *parms)
{
	if (!smbcli_request_receive(req) ||
	    smbcli_request_is_error(req)) {
		goto failed;
	}

	parms->out = req->nttrans.out;
	talloc_steal(mem_ctx, parms->out.setup);
	talloc_steal(mem_ctx, parms->out.params.data);
	talloc_steal(mem_ctx, parms->out.data.data);

failed:
	return smbcli_request_destroy(req);
}

/****************************************************************************
  receive a SMB nttrans response allocating the necessary memory
  ****************************************************************************/
NTSTATUS smb_raw_nttrans(struct smbcli_tree *tree,
			 TALLOC_CTX *mem_ctx,
			 struct smb_nttrans *parms)
{
	struct smbcli_request *req;

	req = smb_raw_nttrans_send(tree, parms);
	if (!req) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return smb_raw_nttrans_recv(req, mem_ctx, parms);
}
