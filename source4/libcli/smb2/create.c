/* 
   Unix SMB/CIFS implementation.

   SMB2 client tree handling

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

/*
  add a blob to a smb2_create attribute blob
*/
NTSTATUS smb2_create_blob_add(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, 
			      const char *tag,
			      DATA_BLOB add, bool last)
{
	uint32_t ofs = blob->length;
	size_t tag_length = strlen(tag);
	uint8_t pad = smb2_padding_size(add.length+tag_length, 8);
	if (!data_blob_realloc(mem_ctx, blob, 
			       blob->length + 0x14 + tag_length + add.length + pad))
		return NT_STATUS_NO_MEMORY;
	
	if (last) {
		SIVAL(blob->data, ofs+0x00, 0);
	} else {
		SIVAL(blob->data, ofs+0x00, 0x14 + tag_length + add.length + pad);
	}
	SSVAL(blob->data, ofs+0x04, 0x10); /* offset of tag */
	SIVAL(blob->data, ofs+0x06, tag_length); /* tag length */
	SSVAL(blob->data, ofs+0x0A, 0x14 + tag_length); /* offset of data */
	SIVAL(blob->data, ofs+0x0C, add.length);
	memcpy(blob->data+ofs+0x10, tag, tag_length);
	SIVAL(blob->data, ofs+0x10+tag_length, 0); /* pad? */
	memcpy(blob->data+ofs+0x14+tag_length, add.data, add.length);
	memset(blob->data+ofs+0x14+tag_length+add.length, 0, pad);

	return NT_STATUS_OK;
}

/*
  send a create request
*/
struct smb2_request *smb2_create_send(struct smb2_tree *tree, struct smb2_create *io)
{
	struct smb2_request *req;
	NTSTATUS status;
	DATA_BLOB blob = data_blob(NULL, 0);

	req = smb2_request_init_tree(tree, SMB2_OP_CREATE, 0x38, true, 0);
	if (req == NULL) return NULL;

	SCVAL(req->out.body, 0x02, io->in.security_flags);
	SCVAL(req->out.body, 0x03, io->in.oplock_level);
	SIVAL(req->out.body, 0x04, io->in.impersonation_level);
	SBVAL(req->out.body, 0x08, io->in.create_flags);
	SBVAL(req->out.body, 0x10, io->in.reserved);
	SIVAL(req->out.body, 0x18, io->in.desired_access);
	SIVAL(req->out.body, 0x1C, io->in.file_attributes);
	SIVAL(req->out.body, 0x20, io->in.share_access);
	SIVAL(req->out.body, 0x24, io->in.create_disposition);
	SIVAL(req->out.body, 0x28, io->in.create_options);

	status = smb2_push_o16s16_string(&req->out, 0x2C, io->in.fname);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	if (io->in.eas.num_eas != 0) {
		DATA_BLOB b = data_blob_talloc(req, NULL, 
					       ea_list_size_chained(io->in.eas.num_eas, io->in.eas.eas));
		ea_put_list_chained(b.data, io->in.eas.num_eas, io->in.eas.eas);
		status = smb2_create_blob_add(req, &blob, SMB2_CREATE_TAG_EXTA, b, false);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
		data_blob_free(&b);
	}

	/* an empty MxAc tag seems to be used to ask the server to
	   return the maximum access mask allowed on the file */
	status = smb2_create_blob_add(req, &blob, SMB2_CREATE_TAG_MXAC, 
				      data_blob(NULL, 0), true);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}
	status = smb2_push_o32s32_blob(&req->out, 0x30, blob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	smb2_transport_send(req);

	return req;
}


/*
  recv a create reply
*/
NTSTATUS smb2_create_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, struct smb2_create *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    !smb2_request_is_ok(req)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x58, true);

	io->out.oplock_level   = CVAL(req->in.body, 0x02);
	io->out.reserved       = CVAL(req->in.body, 0x03);
	io->out.create_action  = IVAL(req->in.body, 0x04);
	io->out.create_time    = smbcli_pull_nttime(req->in.body, 0x08);
	io->out.access_time    = smbcli_pull_nttime(req->in.body, 0x10);
	io->out.write_time     = smbcli_pull_nttime(req->in.body, 0x18);
	io->out.change_time    = smbcli_pull_nttime(req->in.body, 0x20);
	io->out.alloc_size     = BVAL(req->in.body, 0x28);
	io->out.size           = BVAL(req->in.body, 0x30);
	io->out.file_attr      = IVAL(req->in.body, 0x38);
	io->out.reserved2      = IVAL(req->in.body, 0x3C);
	smb2_pull_handle(req->in.body+0x40, &io->out.file.handle);
	status = smb2_pull_o32s32_blob(&req->in, mem_ctx, req->in.body+0x50, &io->out.blob);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	return smb2_request_destroy(req);
}

/*
  sync create request
*/
NTSTATUS smb2_create(struct smb2_tree *tree, TALLOC_CTX *mem_ctx, struct smb2_create *io)
{
	struct smb2_request *req = smb2_create_send(tree, io);
	return smb2_create_recv(req, mem_ctx, io);
}
