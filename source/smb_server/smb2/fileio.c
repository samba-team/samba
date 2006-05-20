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
#include "smb_server/service_smb_proto.h"
#include "smb_server/smb2/smb2_server.h"
#include "ntvfs/ntvfs.h"

static void smb2srv_create_send(struct ntvfs_request *ntvfs)
{
	struct smb2srv_request *req;
	union smb_open *io;

	SMB2SRV_CHECK_ASYNC_STATUS(io, union smb_open);
	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x58, True, io->smb2.out.blob.length));

	SSVAL(req->out.body,	0x02,	io->smb2.out.oplock_flags);
	SIVAL(req->out.body,	0x04,	io->smb2.out.create_action);
	SBVAL(req->out.body,	0x08,	io->smb2.out.create_time);
	SBVAL(req->out.body,	0x10,	io->smb2.out.access_time);
	SBVAL(req->out.body,	0x18,	io->smb2.out.write_time);
	SBVAL(req->out.body,	0x20,	io->smb2.out.change_time);
	SBVAL(req->out.body,	0x28,	io->smb2.out.alloc_size);
	SBVAL(req->out.body,	0x30,	io->smb2.out.size);
	SIVAL(req->out.body,	0x38,	io->smb2.out.file_attr);
	SIVAL(req->out.body,	0x3C,	io->smb2.out._pad);
	smb2srv_push_handle(req->out.body, 0x40,io->smb2.out.file.ntvfs);
	SMB2SRV_CHECK(smb2_push_o16s16_blob(&req->out, 0x50, io->smb2.out.blob));

	smb2srv_send_reply(req);
}

void smb2srv_create_recv(struct smb2srv_request *req)
{
	union smb_open *io;
	DATA_BLOB blob;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x38, True);
	SMB2SRV_TALLOC_IO_PTR(io, union smb_open);
	SMB2SRV_SETUP_NTVFS_REQUEST(smb2srv_create_send, NTVFS_ASYNC_STATE_MAY_ASYNC);

	io->smb2.level			= RAW_OPEN_SMB2;
	io->smb2.in.oplock_flags	= SVAL(req->in.body, 0x02);
	io->smb2.in.impersonation	= IVAL(req->in.body, 0x04);
	io->smb2.in.unknown3[0]		= IVAL(req->in.body, 0x08);
	io->smb2.in.unknown3[1]		= IVAL(req->in.body, 0x0C);
	io->smb2.in.unknown3[2]		= IVAL(req->in.body, 0x10);
	io->smb2.in.unknown3[3]		= IVAL(req->in.body, 0x14);
	io->smb2.in.access_mask		= IVAL(req->in.body, 0x18);
	io->smb2.in.file_attr		= IVAL(req->in.body, 0x1C);
	io->smb2.in.share_access	= IVAL(req->in.body, 0x20);
	io->smb2.in.open_disposition	= IVAL(req->in.body, 0x24);
	io->smb2.in.create_options	= IVAL(req->in.body, 0x28);
	SMB2SRV_CHECK(smb2_pull_o16s16_string(&req->in, io, req->in.body+0x2C, &io->smb2.in.fname));
	SMB2SRV_CHECK(smb2_pull_o32s32_blob(&req->in, io, req->in.body+0x30, &blob));
	/* TODO: parse the blob */
	ZERO_STRUCT(io->smb2.in.eas);

	SMB2SRV_CALL_NTVFS_BACKEND(ntvfs_open(req->ntvfs, io));
}

void smb2srv_close_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_flush_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_read_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_write_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_lock_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_ioctl_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_cancel_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_find_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_notify_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_getinfo_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_setinfo_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_break_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}
