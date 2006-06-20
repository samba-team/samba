/* 
   Unix SMB2 implementation.
   
   Copyright (C) Stefan Metzmacher	2006
   
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

static void smb2srv_getinfo_send(struct ntvfs_request *ntvfs)
{
	struct smb2srv_request *req;
	struct smb2_getinfo *info;

	SMB2SRV_CHECK_ASYNC_STATUS(info, struct smb2_getinfo);
	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x08, True, 0));

	/* TODO: this is maybe a o16s32_blob */
	SMB2SRV_CHECK(smb2_push_o16s16_blob(&req->out, 0x02, info->out.blob));
	SSVAL(req->out.body,	0x06,	0);

	smb2srv_send_reply(req);
}

static NTSTATUS smb2srv_getinfo_backend(struct ntvfs_request *ntvfs, struct smb2_getinfo *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

void smb2srv_getinfo_recv(struct smb2srv_request *req)
{
	struct smb2_getinfo *info;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x30, True);
	SMB2SRV_TALLOC_IO_PTR(info, struct smb2_getinfo);
	SMB2SRV_SETUP_NTVFS_REQUEST(smb2srv_getinfo_send, NTVFS_ASYNC_STATE_MAY_ASYNC);

	info->in.level			= SVAL(req->in.body, 0x02);
	info->in.max_response_size	= IVAL(req->in.body, 0x04);
	info->in.unknown1		= IVAL(req->in.body, 0x08);
	info->in.unknown2		= IVAL(req->in.body, 0x0C);
	info->in.flags			= IVAL(req->in.body, 0x10);
	info->in.flags2			= IVAL(req->in.body, 0x14);
	info->in.file.ntvfs		= smb2srv_pull_handle(req, req->in.body, 0x18);

	SMB2SRV_CHECK_FILE_HANDLE(info->in.file.ntvfs);
	SMB2SRV_CALL_NTVFS_BACKEND(smb2srv_getinfo_backend(req->ntvfs, info));
}

void smb2srv_setinfo_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_break_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}
