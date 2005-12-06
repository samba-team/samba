/* 
   Unix SMB2 implementation.
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "smb_server/smb_server.h"
#include "smb_server/smb2/smb2_server.h"

static NTSTATUS smb2srv_tcon_backend(struct smb2srv_request *req, struct smb2_tree_connect *io)
{
	struct smbsrv_tcon *tcon;

	tcon = smbsrv_tcon_new(req->smb_conn);
	NT_STATUS_HAVE_NO_MEMORY(tcon);

	/* TODO: do real tree connect */

	io->out.unknown1	= 0;
	io->out.unknown2	= 0;
	io->out.unknown3	= 0;
	io->out.access_mask	= 0;

	io->out.tid		= tcon->tid;

	req->tcon = tcon;
	return NT_STATUS_OK;
}

static void smb2srv_tcon_send(struct smb2srv_request *req, struct smb2_tree_connect *io)
{
	NTSTATUS status;

	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	status = smb2srv_setup_reply(req, 0x10, 0);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SBVAL(req->out.hdr, SMB2_HDR_TID,    io->out.tid);

	SSVAL(req->out.body, 0x02, io->out.unknown1);
	SIVAL(req->out.body, 0x04, io->out.unknown2);
	SIVAL(req->out.body, 0x08, io->out.unknown3);
	SIVAL(req->out.body, 0x0C, io->out.access_mask);

	smb2srv_send_reply(req);
}

void smb2srv_tcon_recv(struct smb2srv_request *req)
{
	struct smb2_tree_connect *io;
	NTSTATUS status;

	if (req->in.body_size < 0x08) {
		smb2srv_send_error(req,  NT_STATUS_FOOBAR);
		return;
	}

	io = talloc(req, struct smb2_tree_connect);
	if (!io) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(NT_STATUS_NO_MEMORY));
		talloc_free(req);
		return;
	}

	io->in.unknown1 = SVAL(req->in.body, 0x02);
	status = smb2_pull_o16s16_string(&req->in, io, req->in.body+0x04, &io->in.path);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	req->status = smb2srv_tcon_backend(req, io);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_tcon_send(req, io);
}

static NTSTATUS smb2srv_tdis_backend(struct smb2srv_request *req)
{
	/* TODO: call ntvfs backends to close file of this tcon */
	talloc_free(req->tcon);
	req->tcon = NULL;
	return NT_STATUS_OK;
}

static void smb2srv_tdis_send(struct smb2srv_request *req)
{
	NTSTATUS status;

	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	status = smb2srv_setup_reply(req, 0x04, 0);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SSVAL(req->out.body, 0x02, 0);

	smb2srv_send_reply(req);
}

void smb2srv_tdis_recv(struct smb2srv_request *req)
{
	uint16_t _pad;

	if (req->in.body_size < 0x04) {
		smb2srv_send_error(req,  NT_STATUS_FOOBAR);
		return;
	}

	_pad	= SVAL(req->in.body, 0x02);

	req->status = smb2srv_tdis_backend(req);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_tdis_send(req);
}
