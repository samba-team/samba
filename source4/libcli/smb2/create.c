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
#include "librpc/gen_ndr/ndr_security.h"


/*
  parse a set of SMB2 create blobs
*/
NTSTATUS smb2_create_blob_parse(TALLOC_CTX *mem_ctx, const DATA_BLOB buffer,
				struct smb2_create_blobs *blobs)
{
	const uint8_t *data = buffer.data;
	uint32_t remaining = buffer.length;

	while (remaining > 0) {
		uint32_t next;
		uint32_t name_offset, name_length;
		uint32_t reserved, data_offset;
		uint32_t data_length;
		char *tag;
		DATA_BLOB b;
		NTSTATUS status;

		if (remaining < 16) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		next        = IVAL(data, 0);
		name_offset = SVAL(data, 4);
		name_length = SVAL(data, 6);
		reserved    = SVAL(data, 8);
		data_offset = SVAL(data, 10);
		data_length = IVAL(data, 12);

		if ((next & 0x7) != 0 ||
		    next > remaining ||
		    name_offset < 16 ||
		    name_offset > remaining ||
		    name_length != 4 || /* windows enforces this */
		    name_offset + name_length > remaining ||
		    data_offset < name_offset + name_length ||
		    data_offset > remaining ||
		    data_offset + (uint64_t)data_length > remaining) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		tag = talloc_strndup(mem_ctx, (const char *)data + name_offset, name_length);
		if (tag == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		b = data_blob_const(data+data_offset, data_length);
		status = smb2_create_blob_add(mem_ctx, blobs, tag, b);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		talloc_free(tag);

		if (next == 0) break;

		remaining -= next;
		data += next;

		if (remaining < 16) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	return NT_STATUS_OK;
}


/*
  add a blob to a smb2_create attribute blob
*/
static NTSTATUS smb2_create_blob_push_one(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
					  const struct smb2_create_blob *blob,
					  bool last)
{
	uint32_t ofs = buffer->length;
	size_t tag_length = strlen(blob->tag);
	uint8_t pad = smb2_padding_size(blob->data.length+tag_length, 4);

	if (!data_blob_realloc(mem_ctx, buffer,
			       buffer->length + 0x14 + tag_length + blob->data.length + pad))
		return NT_STATUS_NO_MEMORY;

	if (last) {
		SIVAL(buffer->data, ofs+0x00, 0);
	} else {
		SIVAL(buffer->data, ofs+0x00, 0x14 + tag_length + blob->data.length + pad);
	}
	SSVAL(buffer->data, ofs+0x04, 0x10); /* offset of tag */
	SIVAL(buffer->data, ofs+0x06, tag_length); /* tag length */
	SSVAL(buffer->data, ofs+0x0A, 0x14 + tag_length); /* offset of data */
	SIVAL(buffer->data, ofs+0x0C, blob->data.length);
	memcpy(buffer->data+ofs+0x10, blob->tag, tag_length);
	SIVAL(buffer->data, ofs+0x10+tag_length, 0); /* pad? */
	memcpy(buffer->data+ofs+0x14+tag_length, blob->data.data, blob->data.length);
	memset(buffer->data+ofs+0x14+tag_length+blob->data.length, 0, pad);

	return NT_STATUS_OK;
}


/*
  create a buffer of a set of create blobs
*/
NTSTATUS smb2_create_blob_push(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
			       const struct smb2_create_blobs blobs)
{
	int i;
	NTSTATUS status;

	*buffer = data_blob(NULL, 0);
	for (i=0; i < blobs.num_blobs; i++) {
		bool last = false;
		const struct smb2_create_blob *c;

		if ((i + 1) == blobs.num_blobs) {
			last = true;
		}

		c = &blobs.blobs[i];
		status = smb2_create_blob_push_one(mem_ctx, buffer, c, last);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	return NT_STATUS_OK;
}


NTSTATUS smb2_create_blob_add(TALLOC_CTX *mem_ctx, struct smb2_create_blobs *b,
			      const char *tag, DATA_BLOB data)
{
	struct smb2_create_blob *array;

	array = talloc_realloc(mem_ctx, b->blobs,
			       struct smb2_create_blob,
			       b->num_blobs + 1);
	NT_STATUS_HAVE_NO_MEMORY(array);
	b->blobs = array;

	b->blobs[b->num_blobs].tag = talloc_strdup(b->blobs, tag);
	NT_STATUS_HAVE_NO_MEMORY(b->blobs[b->num_blobs].tag);

	if (data.data) {
		b->blobs[b->num_blobs].data = data_blob_talloc(b->blobs,
							       data.data,
							       data.length);
		NT_STATUS_HAVE_NO_MEMORY(b->blobs[b->num_blobs].data.data);
	} else {
		b->blobs[b->num_blobs].data = data_blob(NULL, 0);
	}

	b->num_blobs += 1;

	return NT_STATUS_OK;
}

/*
  send a create request
*/
struct smb2_request *smb2_create_send(struct smb2_tree *tree, struct smb2_create *io)
{
	struct smb2_request *req;
	NTSTATUS status;
	DATA_BLOB blob;
	struct smb2_create_blobs blobs;
	int i;

	ZERO_STRUCT(blobs);

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

	/* now add all the optional blobs */
	if (io->in.eas.num_eas != 0) {
		DATA_BLOB b = data_blob_talloc(req, NULL, 
					       ea_list_size_chained(io->in.eas.num_eas, io->in.eas.eas, 4));
		ea_put_list_chained(b.data, io->in.eas.num_eas, io->in.eas.eas, 4);
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_EXTA, b);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
		data_blob_free(&b);
	}

	/* an empty MxAc tag seems to be used to ask the server to
	   return the maximum access mask allowed on the file */
	if (io->in.query_maximal_access) {
		/* TODO: MS-SMB2 2.2.13.2.5 says this can contain a timestamp? What to do
		   with that if it doesn't match? */
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_MXAC, data_blob(NULL, 0));
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	if (io->in.alloc_size != 0) {
		uint8_t data[8];
		SBVAL(data, 0, io->in.alloc_size);
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_ALSI, data_blob_const(data, 8));
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	if (io->in.durable_open) {
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_DHNQ, data_blob_talloc_zero(req, 16));
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	if (io->in.durable_handle) {
		uint8_t data[16];
		smb2_push_handle(data, io->in.durable_handle);
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_DHNC, data_blob_const(data, 16));
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	if (io->in.timewarp) {
		uint8_t data[8];
		SBVAL(data, 0, io->in.timewarp);		
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_TWRP, data_blob_const(data, 8));
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	if (io->in.sec_desc) {
		enum ndr_err_code ndr_err;
		DATA_BLOB sd_blob;
		ndr_err = ndr_push_struct_blob(&sd_blob, req, NULL,
					       io->in.sec_desc,
					       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(req);
			return NULL;
		}
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_SECD, sd_blob);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	if (io->in.query_on_disk_id) {
		status = smb2_create_blob_add(req, &blobs,
					      SMB2_CREATE_TAG_QFID, data_blob(NULL, 0));
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}

	/* and any custom blobs */
	for (i=0;i<io->in.blobs.num_blobs;i++) {
		status = smb2_create_blob_add(req, &blobs,
					      io->in.blobs.blobs[i].tag, 
					      io->in.blobs.blobs[i].data);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(req);
			return NULL;
		}
	}


	status = smb2_create_blob_push(req, &blob, blobs);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	status = smb2_push_o32s32_blob(&req->out, 0x30, blob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	data_blob_free(&blob);

	smb2_transport_send(req);

	return req;
}


/*
  recv a create reply
*/
NTSTATUS smb2_create_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, struct smb2_create *io)
{
	NTSTATUS status;
	DATA_BLOB blob;
	int i;

	if (!smb2_request_receive(req) || 
	    !smb2_request_is_ok(req)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x58, true);
	ZERO_STRUCT(io->out);
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
	status = smb2_pull_o32s32_blob(&req->in, mem_ctx, req->in.body+0x50, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	status = smb2_create_blob_parse(mem_ctx, blob, &io->out.blobs);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	/* pull out the parsed blobs */
	for (i=0;i<io->out.blobs.num_blobs;i++) {
		if (strcmp(io->out.blobs.blobs[i].tag, SMB2_CREATE_TAG_MXAC) == 0) {
			/* TODO: this also contains a status field in
			   first 4 bytes */
			if (io->out.blobs.blobs[i].data.length != 8) {
				smb2_request_destroy(req);
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}
			io->out.maximal_access = IVAL(io->out.blobs.blobs[i].data.data, 4);
		}
		if (strcmp(io->out.blobs.blobs[i].tag, SMB2_CREATE_TAG_QFID) == 0) {
			if (io->out.blobs.blobs[i].data.length != 32) {
				smb2_request_destroy(req);
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}
			memcpy(io->out.on_disk_id, io->out.blobs.blobs[i].data.data, 32);
		}
	}

	data_blob_free(&blob);

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
