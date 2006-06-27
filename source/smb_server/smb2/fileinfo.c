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
#include "librpc/gen_ndr/ndr_security.h"

struct smb2srv_getinfo_op {
	struct smb2srv_request *req;
	struct smb2_getinfo *info;
	void *io_ptr;
	NTSTATUS (*send_fn)(struct smb2srv_getinfo_op *op);
};

static void smb2srv_getinfo_send(struct ntvfs_request *ntvfs)
{
	struct smb2srv_getinfo_op *op;
	struct smb2srv_request *req;

	/*
	 * SMB2 uses NT_STATUS_INVALID_INFO_CLASS
	 * so we need to translated it here
	 */
	if (NT_STATUS_EQUAL(NT_STATUS_INVALID_LEVEL, ntvfs->async_states->status)) {
		ntvfs->async_states->status = NT_STATUS_INVALID_INFO_CLASS;
	}

	SMB2SRV_CHECK_ASYNC_STATUS(op, struct smb2srv_getinfo_op);

	ZERO_STRUCT(op->info->out);
	if (op->send_fn) {
		SMB2SRV_CHECK(op->send_fn(op));
	}

	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x08, True, 0));

	/* TODO: this is maybe a o16s32_blob */
	SMB2SRV_CHECK(smb2_push_o16s16_blob(&req->out, 0x02, op->info->out.blob));
	SSVAL(req->out.body,	0x06,	0);

	smb2srv_send_reply(req);
}

static NTSTATUS smb2srv_getinfo_file_send(struct smb2srv_getinfo_op *op)
{
	union smb_fileinfo *io = talloc_get_type(op->io_ptr, union smb_fileinfo);
	NTSTATUS status;

	status = smbsrv_push_passthru_fileinfo(op->req,
					       &op->info->out.blob,
					       io->generic.level, io,
					       STR_UNICODE);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_getinfo_file(struct smb2srv_getinfo_op *op, uint8_t smb2_level)
{
	union smb_fileinfo *io;

	io = talloc(op, union smb_fileinfo);
	NT_STATUS_HAVE_NO_MEMORY(io);

	switch (op->info->in.level) {
	case RAW_FILEINFO_SMB2_ALL_EAS:
		io->all_eas.level		= op->info->in.level;
		io->all_eas.in.file.ntvfs	= op->info->in.file.ntvfs;
		io->all_eas.in.continue_flags	= op->info->in.flags2;
		break;

	case RAW_FILEINFO_SMB2_ALL_INFORMATION:
		io->all_info2.level		= op->info->in.level;
		io->all_info2.in.file.ntvfs	= op->info->in.file.ntvfs;
		break;

	default:
		/* the rest directly maps to the passthru levels */
		io->generic.level		= smb2_level + 1000;
		io->generic.in.file.ntvfs	= op->info->in.file.ntvfs;
		break;
	}

	op->io_ptr	= io;
	op->send_fn	= smb2srv_getinfo_file_send;

	return ntvfs_qfileinfo(op->req->ntvfs, io);
}

static NTSTATUS smb2srv_getinfo_fs_send(struct smb2srv_getinfo_op *op)
{
	union smb_fsinfo *io = talloc_get_type(op->io_ptr, union smb_fsinfo);
	NTSTATUS status;

	status = smbsrv_push_passthru_fsinfo(op->req,
					     &op->info->out.blob,
					     io->generic.level, io,
					     STR_UNICODE);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_getinfo_fs(struct smb2srv_getinfo_op *op, uint8_t smb2_level)
{
	union smb_fsinfo *io;

	io = talloc(op, union smb_fsinfo);
	NT_STATUS_HAVE_NO_MEMORY(io);

	/* the rest directly maps to the passthru levels */
	io->generic.level	= smb2_level + 1000;

	/* TODO: allow qfsinfo only the share root directory handle */

	op->io_ptr	= io;
	op->send_fn	= smb2srv_getinfo_fs_send;

	return ntvfs_fsinfo(op->req->ntvfs, io);
}

static NTSTATUS smb2srv_getinfo_security_send(struct smb2srv_getinfo_op *op)
{
	union smb_fileinfo *io = talloc_get_type(op->io_ptr, union smb_fileinfo);
	NTSTATUS status;

	status = ndr_push_struct_blob(&op->info->out.blob, op->req,
				      io->query_secdesc.out.sd,
				      (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_getinfo_security(struct smb2srv_getinfo_op *op, uint8_t smb2_level)
{
	union smb_fileinfo *io;

	switch (smb2_level) {
	case 0x00:
		io = talloc(op, union smb_fileinfo);
		NT_STATUS_HAVE_NO_MEMORY(io);

		io->query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		io->query_secdesc.in.file.ntvfs		= op->info->in.file.ntvfs;
		io->query_secdesc.in.secinfo_flags	= op->info->in.flags;

		op->io_ptr	= io;
		op->send_fn	= smb2srv_getinfo_security_send;

		return ntvfs_qfileinfo(op->req->ntvfs, io);
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

static NTSTATUS smb2srv_getinfo_backend(struct smb2srv_getinfo_op *op)
{
	uint8_t smb2_class;
	uint8_t smb2_level;

	smb2_class = 0xFF & op->info->in.level;
	smb2_level = 0xFF & (op->info->in.level>>8);

	switch (smb2_class) {
	case SMB2_GETINFO_FILE:
		return smb2srv_getinfo_file(op, smb2_level);

	case SMB2_GETINFO_FS:
		return smb2srv_getinfo_fs(op, smb2_level);

	case SMB2_GETINFO_SECURITY:
		return smb2srv_getinfo_security(op, smb2_level);
	}

	return NT_STATUS_FOOBAR;
}

void smb2srv_getinfo_recv(struct smb2srv_request *req)
{
	struct smb2_getinfo *info;
	struct smb2srv_getinfo_op *op;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x28, True);
	SMB2SRV_TALLOC_IO_PTR(info, struct smb2_getinfo);
	/* this overwrites req->io_ptr !*/
	SMB2SRV_TALLOC_IO_PTR(op, struct smb2srv_getinfo_op);
	op->req		= req;
	op->info	= info;
	op->io_ptr	= NULL;
	op->send_fn	= NULL;
	SMB2SRV_SETUP_NTVFS_REQUEST(smb2srv_getinfo_send, NTVFS_ASYNC_STATE_MAY_ASYNC);

	info->in.level			= SVAL(req->in.body, 0x02);
	info->in.max_response_size	= IVAL(req->in.body, 0x04);
	info->in.unknown1		= IVAL(req->in.body, 0x08);
	info->in.unknown2		= IVAL(req->in.body, 0x0C);
	info->in.flags			= IVAL(req->in.body, 0x10);
	info->in.flags2			= IVAL(req->in.body, 0x14);
	info->in.file.ntvfs		= smb2srv_pull_handle(req, req->in.body, 0x18);

	SMB2SRV_CHECK_FILE_HANDLE(info->in.file.ntvfs);
	SMB2SRV_CALL_NTVFS_BACKEND(smb2srv_getinfo_backend(op));
}

struct smb2srv_setinfo_op {
	struct smb2srv_request *req;
	struct smb2_setinfo *info;
};

static void smb2srv_setinfo_send(struct ntvfs_request *ntvfs)
{
	struct smb2srv_setinfo_op *op;
	struct smb2srv_request *req;

	/*
	 * SMB2 uses NT_STATUS_INVALID_INFO_CLASS
	 * so we need to translated it here
	 */
	if (NT_STATUS_EQUAL(NT_STATUS_INVALID_LEVEL, ntvfs->async_states->status)) {
		ntvfs->async_states->status = NT_STATUS_INVALID_INFO_CLASS;
	}

	SMB2SRV_CHECK_ASYNC_STATUS(op, struct smb2srv_setinfo_op);

	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x02, False, 0));

	smb2srv_send_reply(req);
}

static NTSTATUS smb2srv_setinfo_backend(struct smb2srv_setinfo_op *op)
{
	uint8_t smb2_class;
	/*uint8_t smb2_level;*/

	smb2_class = 0xFF & op->info->in.level;
	/*smb2_level = 0xFF & (op->info->in.level>>8);*/

	switch (smb2_class) {
	case SMB2_GETINFO_FILE:
		return NT_STATUS_NOT_IMPLEMENTED;

	case SMB2_GETINFO_FS:
		return NT_STATUS_NOT_IMPLEMENTED;

	case SMB2_GETINFO_SECURITY:
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_FOOBAR;
}

void smb2srv_setinfo_recv(struct smb2srv_request *req)
{
	struct smb2_setinfo *info;
	struct smb2srv_setinfo_op *op;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x20, True);
	SMB2SRV_TALLOC_IO_PTR(info, struct smb2_setinfo);
	/* this overwrites req->io_ptr !*/
	SMB2SRV_TALLOC_IO_PTR(op, struct smb2srv_setinfo_op);
	op->req		= req;
	op->info	= info;
	SMB2SRV_SETUP_NTVFS_REQUEST(smb2srv_setinfo_send, NTVFS_ASYNC_STATE_MAY_ASYNC);

	info->in.level			= SVAL(req->in.body, 0x02);
	SMB2SRV_CHECK(smb2_pull_s32o32_blob(&req->in, info, req->in.body+0x04, &info->in.blob));
	info->in.flags			= IVAL(req->in.body, 0x0C);
	info->in.file.ntvfs		= smb2srv_pull_handle(req, req->in.body, 0x10);

	SMB2SRV_CHECK_FILE_HANDLE(info->in.file.ntvfs);
	SMB2SRV_CALL_NTVFS_BACKEND(smb2srv_setinfo_backend(op));
}
