/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2014

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
#include "../libcli/smb/smb_common.h"
#include "libcli/smb/smb2_negotiate_context.h"

static size_t smb2_negotiate_context_padding(uint32_t offset, size_t n)
{
	if ((offset & (n-1)) == 0) return 0;
	return n - (offset & (n-1));
}

/*
  parse a set of SMB2 create contexts
*/
NTSTATUS smb2_negotiate_context_parse(TALLOC_CTX *mem_ctx, const DATA_BLOB buffer,
				      struct smb2_negotiate_contexts *contexts)
{
	const uint8_t *data = buffer.data;
	uint32_t remaining = buffer.length;

	while (true) {
		uint16_t data_length;
		uint16_t type;
		NTSTATUS status;
		size_t pad;
		uint32_t next_offset;

		if (remaining < 8) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		type        = SVAL(data, 0x00);
		data_length = SVAL(data, 0x02);
#if 0
		reserved    = IVAL(data, 0x04);
#endif

		next_offset = 0x08 + data_length;
		if (remaining < next_offset) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = smb2_negotiate_context_add(
			mem_ctx, contexts, type, data+0x08, data_length);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		remaining -= next_offset;
		data += next_offset;

		if (remaining == 0) {
			break;
		}

		pad = smb2_negotiate_context_padding(next_offset, 8);
		if (remaining < pad) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		remaining -= pad;
		data += pad;
	}

	return NT_STATUS_OK;
}

/*
  add a context to a smb2_negotiate attribute context
*/
static NTSTATUS smb2_negotiate_context_push_one(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
					  const struct smb2_negotiate_context *context,
					  bool last)
{
	uint32_t ofs = buffer->length;
	size_t next_offset = 0;
	size_t next_pad = 0;
	bool ok;

	if (context->data.length > UINT16_MAX) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	next_offset = 0x08 + context->data.length;
	if (!last) {
		next_pad = smb2_negotiate_context_padding(next_offset, 8);
	}

	ok = data_blob_realloc(mem_ctx, buffer,
			       buffer->length + next_offset + next_pad);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	SSVAL(buffer->data, ofs+0x00, context->type);
	SIVAL(buffer->data, ofs+0x02, context->data.length);
	SIVAL(buffer->data, ofs+0x04, 0);
	memcpy(buffer->data+ofs+0x08, context->data.data, context->data.length);
	if (next_pad > 0) {
		memset(buffer->data+ofs+next_offset, 0, next_pad);
	}

	return NT_STATUS_OK;
}

/*
  create a buffer of a set of create contexts
*/
NTSTATUS smb2_negotiate_context_push(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
				     const struct smb2_negotiate_contexts contexts)
{
	uint32_t i;
	NTSTATUS status;

	*buffer = data_blob(NULL, 0);
	for (i=0; i < contexts.num_contexts; i++) {
		bool last = false;
		const struct smb2_negotiate_context *c;

		if ((i + 1) == contexts.num_contexts) {
			last = true;
		}

		c = &contexts.contexts[i];
		status = smb2_negotiate_context_push_one(mem_ctx, buffer, c, last);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	return NT_STATUS_OK;
}

NTSTATUS smb2_negotiate_context_add(TALLOC_CTX *mem_ctx,
				    struct smb2_negotiate_contexts *c,
				    uint16_t type,
				    const uint8_t *buf,
				    size_t buflen)
{
	struct smb2_negotiate_context *array;

	array = talloc_realloc(mem_ctx, c->contexts,
			       struct smb2_negotiate_context,
			       c->num_contexts + 1);
	NT_STATUS_HAVE_NO_MEMORY(array);
	c->contexts = array;

	c->contexts[c->num_contexts].type = type;

	if (buf != NULL) {
		c->contexts[c->num_contexts].data = data_blob_talloc(
			c->contexts, buf, buflen);
		NT_STATUS_HAVE_NO_MEMORY(c->contexts[c->num_contexts].data.data);
	} else {
		c->contexts[c->num_contexts].data = data_blob_null;
	}

	c->num_contexts += 1;

	return NT_STATUS_OK;
}

/*
 * return the first blob with the given tag
 */
struct smb2_negotiate_context *smb2_negotiate_context_find(const struct smb2_negotiate_contexts *c,
							   uint16_t type)
{
	uint32_t i;

	for (i=0; i < c->num_contexts; i++) {
		if (c->contexts[i].type ==  type) {
			return &c->contexts[i];
		}
	}

	return NULL;
}
