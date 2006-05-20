/* 
   Unix SMB/CIFS implementation.

   SMB2 client tree handling

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

#define CREATE_TAG_EXTA 0x41747845 /* "ExtA" */
#define CREATE_TAG_MXAC 0x6341784D /* "MxAc" */

/*
  add a blob to a smb2_create attribute blob
*/
static NTSTATUS smb2_create_blob_add(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, 
				     uint32_t tag,
				     DATA_BLOB add, BOOL last)
{
	NTSTATUS status;
	uint32_t ofs = blob->length;
	uint8_t pad = smb2_padding_size(add.length, 8);
	status = data_blob_realloc(mem_ctx, blob, blob->length + 0x18 + add.length + pad);
	NT_STATUS_NOT_OK_RETURN(status);
	
	if (last) {
		SIVAL(blob->data, ofs+0x00, 0);
	} else {
		SIVAL(blob->data, ofs+0x00, 0x18 + add.length + pad);
	}
	SSVAL(blob->data, ofs+0x04, 0x10); /* offset of tag */
	SIVAL(blob->data, ofs+0x06, 0x04); /* tag length */
	SSVAL(blob->data, ofs+0x0A, 0x18); /* offset of data */
	SIVAL(blob->data, ofs+0x0C, add.length);
	SIVAL(blob->data, ofs+0x10, tag);
	SIVAL(blob->data, ofs+0x14, 0); /* pad? */
	memcpy(blob->data+ofs+0x18, add.data, add.length);
	memset(blob->data+ofs+0x18+add.length, 0, pad);

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

	req = smb2_request_init_tree(tree, SMB2_OP_CREATE, 0x38, True, 0);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x02, io->in.oplock_flags);
	SIVAL(req->out.body, 0x04, io->in.impersonation);
	SIVAL(req->out.body, 0x08, io->in.unknown3[0]);
	SIVAL(req->out.body, 0x0C, io->in.unknown3[1]);
	SIVAL(req->out.body, 0x10, io->in.unknown3[2]);
	SIVAL(req->out.body, 0x14, io->in.unknown3[3]);
	SIVAL(req->out.body, 0x18, io->in.access_mask);
	SIVAL(req->out.body, 0x1C, io->in.file_attr);
	SIVAL(req->out.body, 0x20, io->in.share_access);
	SIVAL(req->out.body, 0x24, io->in.open_disposition);
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
		status = smb2_create_blob_add(req, &blob, CREATE_TAG_EXTA, b, False);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
		data_blob_free(&b);
	}

	/* an empty MxAc tag seems to be used to ask the server to
	   return the maximum access mask allowed on the file */
	status = smb2_create_blob_add(req, &blob, CREATE_TAG_MXAC, data_blob(NULL, 0), True);

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

	SMB2_CHECK_PACKET_RECV(req, 0x58, True);

	io->out.oplock_flags   = SVAL(req->in.body, 0x02);
	io->out.create_action  = IVAL(req->in.body, 0x04);
	io->out.create_time    = smbcli_pull_nttime(req->in.body, 0x08);
	io->out.access_time    = smbcli_pull_nttime(req->in.body, 0x10);
	io->out.write_time     = smbcli_pull_nttime(req->in.body, 0x18);
	io->out.change_time    = smbcli_pull_nttime(req->in.body, 0x20);
	io->out.alloc_size     = BVAL(req->in.body, 0x28);
	io->out.size           = BVAL(req->in.body, 0x30);
	io->out.file_attr      = IVAL(req->in.body, 0x38);
	io->out._pad           = IVAL(req->in.body, 0x3C);
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
