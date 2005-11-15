/* 
   Unix SMB/CIFS implementation.

   SMB2 client getinfo calls

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

/*
  send a getinfo request
*/
struct smb2_request *smb2_getinfo_send(struct smb2_tree *tree, struct smb2_getinfo *io)
{
	struct smb2_request *req;

	req = smb2_request_init_tree(tree, SMB2_OP_GETINFO, 0x28);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x00, io->in.buffer_code);
	SSVAL(req->out.body, 0x02, io->in.level);
	SIVAL(req->out.body, 0x04, io->in.max_response_size);
	SIVAL(req->out.body, 0x08, io->in.unknown1);
	SIVAL(req->out.body, 0x0C, io->in.flags);
	SIVAL(req->out.body, 0x10, io->in.unknown3);
	SIVAL(req->out.body, 0x14, io->in.unknown4);
	smb2_put_handle(req->out.body+0x18, &io->in.handle);

	smb2_transport_send(req);

	return req;
}


/*
  recv a getinfo reply
*/
NTSTATUS smb2_getinfo_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx,
			   struct smb2_getinfo *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 0x08) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	SMB2_CHECK_BUFFER_CODE(req, 0x09);

	status = smb2_pull_ofs_blob(&req->in, mem_ctx, req->in.body+0x02, &io->out.blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return smb2_request_destroy(req);
}

/*
  sync getinfo request
*/
NTSTATUS smb2_getinfo(struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
		      struct smb2_getinfo *io)
{
	struct smb2_request *req = smb2_getinfo_send(tree, io);
	return smb2_getinfo_recv(req, mem_ctx, io);
}


/*
  parse a returned getinfo data blob
*/
NTSTATUS smb2_getinfo_parse(TALLOC_CTX *mem_ctx, 
			    uint16_t level,
			    DATA_BLOB blob,
			    union smb2_fileinfo *io)
{
	switch (level) {
	case SMB2_GETINFO_FILE_BASIC_INFO:
		if (blob.length != 0x28) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->basic_info.create_time = smbcli_pull_nttime(blob.data, 0x00);
		io->basic_info.access_time = smbcli_pull_nttime(blob.data, 0x08);
		io->basic_info.write_time  = smbcli_pull_nttime(blob.data, 0x10);
		io->basic_info.change_time = smbcli_pull_nttime(blob.data, 0x18);
		io->basic_info.file_attr   = IVAL(blob.data, 0x20);
		io->basic_info.unknown     = IVAL(blob.data, 0x24);
		break;

	case SMB2_GETINFO_FILE_SIZE_INFO:
		if (blob.length != 0x18) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->size_info.alloc_size     = BVAL(blob.data, 0x00);
		io->size_info.size           = BVAL(blob.data, 0x08);
		io->size_info.nlink          = IVAL(blob.data, 0x10);
		io->size_info.delete_pending = CVAL(blob.data, 0x14);
		io->size_info.directory      = CVAL(blob.data, 0x15);
		break;

	case SMB2_GETINFO_FILE_ID:
		if (blob.length != 0x8) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->file_id.file_id = BVAL(blob.data, 0x00);
		break;

	case SMB2_GETINFO_FILE_EA_SIZE:
		if (blob.length != 0x4) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->ea_size.ea_size = IVAL(blob.data, 0x00);
		break;

	case SMB2_GETINFO_FILE_ACCESS_INFO:
		if (blob.length != 0x4) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->access_info.access_mask = IVAL(blob.data, 0x00);
		break;

	case SMB2_GETINFO_FILE_0E:
		if (blob.length != 0x8) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->unknown0e.unknown1     = IVAL(blob.data, 0x00);
		io->unknown0e.unknown2     = IVAL(blob.data, 0x04);
		break;

	case SMB2_GETINFO_FILE_ALL_EAS:
		return ea_pull_list(&blob, mem_ctx, 
				    &io->all_eas.eas.num_eas,
				    &io->all_eas.eas.eas);

	case SMB2_GETINFO_FILE_10:
		if (blob.length != 0x4) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->unknown10.unknown     = IVAL(blob.data, 0x00);
		break;

	case SMB2_GETINFO_FILE_11:
		if (blob.length != 0x4) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->unknown11.unknown     = IVAL(blob.data, 0x00);
		break;

	case SMB2_GETINFO_FILE_ALL_INFO: {
		uint32_t nlen;
		ssize_t size;
		void *vstr;
		if (blob.length < 0x64) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->all_info.create_time    = smbcli_pull_nttime(blob.data, 0x00);
		io->all_info.access_time    = smbcli_pull_nttime(blob.data, 0x08);
		io->all_info.write_time     = smbcli_pull_nttime(blob.data, 0x10);
		io->all_info.change_time    = smbcli_pull_nttime(blob.data, 0x18);
		io->all_info.file_attr      = IVAL(blob.data, 0x20);
		io->all_info.alloc_size     = BVAL(blob.data, 0x28);
		io->all_info.size           = BVAL(blob.data, 0x30);
		io->all_info.nlink          = IVAL(blob.data, 0x38);
		io->all_info.delete_pending = CVAL(blob.data, 0x3C);
		io->all_info.directory      = CVAL(blob.data, 0x3D);
		io->all_info.file_id        = BVAL(blob.data, 0x40);
		io->all_info.ea_size        = IVAL(blob.data, 0x48);
		io->all_info.access_mask    = IVAL(blob.data, 0x4C);
		io->all_info.unknown5       = BVAL(blob.data, 0x50);
		io->all_info.unknown6       = BVAL(blob.data, 0x58);
		nlen                        = IVAL(blob.data, 0x60);
		if (nlen > blob.length - 0x64) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		size = convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX, 
					     blob.data+0x64, nlen, &vstr);
		if (size == -1) {
			return NT_STATUS_ILLEGAL_CHARACTER;
		}
		io->all_info.fname = vstr;
		break;
	}

	case SMB2_GETINFO_FILE_SHORT_INFO: {
		uint32_t nlen;
		ssize_t size;
		void *vstr;
		if (blob.length < 0x04) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		nlen                     = IVAL(blob.data, 0x00);
		if (nlen > blob.length - 0x04) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		size = convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX, 
					     blob.data+0x04, nlen, &vstr);
		if (size == -1) {
			return NT_STATUS_ILLEGAL_CHARACTER;
		}
		io->short_info.short_name = vstr;
		break;
	}

	case SMB2_GETINFO_FILE_STREAM_INFO:
		return smbcli_parse_stream_info(blob, mem_ctx, &io->stream_info);

	case SMB2_GETINFO_FILE_EOF_INFO:
		if (blob.length != 0x10) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->eof_info.size     = BVAL(blob.data, 0x00);
		io->eof_info.unknown  = BVAL(blob.data, 0x08);
		break;

	case SMB2_GETINFO_FILE_STANDARD_INFO:
		if (blob.length != 0x38) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->standard_info.create_time = smbcli_pull_nttime(blob.data, 0x00);
		io->standard_info.access_time = smbcli_pull_nttime(blob.data, 0x08);
		io->standard_info.write_time  = smbcli_pull_nttime(blob.data, 0x10);
		io->standard_info.change_time = smbcli_pull_nttime(blob.data, 0x18);
		io->standard_info.alloc_size  = BVAL(blob.data, 0x20);
		io->standard_info.size        = BVAL(blob.data, 0x28);
		io->standard_info.file_attr   = IVAL(blob.data, 0x30);
		io->standard_info.unknown     = IVAL(blob.data, 0x34);
		break;

	case SMB2_GETINFO_FILE_ATTRIB_INFO:
		if (blob.length != 0x08) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		io->attrib_info.file_attr   = IVAL(blob.data, 0x00);
		io->attrib_info.unknown     = IVAL(blob.data, 0x04);
		break;

	case SMB2_GETINFO_SECURITY: {
		struct ndr_pull *ndr;
		NTSTATUS status;
		ndr = ndr_pull_init_blob(&blob, mem_ctx);
		if (!ndr) {
			return NT_STATUS_NO_MEMORY;
		}
		io->security.sd = talloc(mem_ctx, struct security_descriptor);
		if (io->security.sd == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = ndr_pull_security_descriptor(ndr, NDR_SCALARS|NDR_BUFFERS, io->security.sd);
		talloc_free(ndr);
		return status;
	}
		
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	return NT_STATUS_OK;
}


/*
  recv a getinfo reply and parse the level info
*/
NTSTATUS smb2_getinfo_level_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx,
				 uint16_t level, union smb2_fileinfo *io)
{
	struct smb2_getinfo b;
	NTSTATUS status;

	status = smb2_getinfo_recv(req, mem_ctx, &b);
	NT_STATUS_NOT_OK_RETURN(status);

	status = smb2_getinfo_parse(mem_ctx, level, b.out.blob, io);
	data_blob_free(&b.out.blob);

	return status;
}

/*
  level specific getinfo call
*/
NTSTATUS smb2_getinfo_level(struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
			    struct smb2_handle handle,
			    uint16_t level, union smb2_fileinfo *io)
{
	struct smb2_getinfo b;
	struct smb2_request *req;

	ZERO_STRUCT(b);
	b.in.buffer_code       = 0x29;
	b.in.max_response_size = 0x10000;
	b.in.handle            = handle;
	b.in.level             = level;

	req = smb2_getinfo_send(tree, &b);
	
	return smb2_getinfo_level_recv(req, mem_ctx, level, io);
}
