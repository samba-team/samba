/* 
   Unix SMB/CIFS implementation.
   DCE/RPC over named pipes support (glue between dcerpc and smb servers)

   Copyright (C) Jelmer Vernooij 2005

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
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "rpc_server/dcerpc_server.h"
#include "ntvfs/ipc/ipc.h"

static NTSTATUS echo_pipe_open (void *context_data, const char *path, struct auth_session_info *session_info, struct stream_connection *srv_conn, TALLOC_CTX *mem_ctx, void **private_data)
{
	*private_data = talloc_zero(mem_ctx, DATA_BLOB);

	return NT_STATUS_OK;
}

static NTSTATUS echo_pipe_trans(void *private_data, DATA_BLOB *in, DATA_BLOB *out)
{
	memcpy(out->data, in->data, MIN(out->length,in->length));

	return NT_STATUS_OK;
}

static NTSTATUS echo_pipe_write(void *private_data, DATA_BLOB *out)
{
	DATA_BLOB *cache = private_data;
	return data_blob_append(cache, cache, out->data, out->length);
}

static NTSTATUS echo_pipe_read(void *private_data, DATA_BLOB *in)
{
	uint8_t *newdata;
	DATA_BLOB *cache = private_data;
	uint32_t numread = MIN(in->length, cache->length);

	memcpy(in->data, cache->data, numread);

	cache->length -= numread;
	newdata = talloc_memdup(cache, cache+numread, cache->length);
	if (newdata == NULL)
		return NT_STATUS_NO_MEMORY;

	talloc_free(cache->data);
	cache->data = newdata;

	return NT_STATUS_OK;
}

const struct named_pipe_ops echo_pipe_ops = {
	.open = echo_pipe_open,
	.write = echo_pipe_write,
	.read = echo_pipe_read,
	.trans = echo_pipe_trans
};

NTSTATUS np_echo_init(void)
{
	return named_pipe_listen("\\PIPE\\NPECHO", &echo_pipe_ops, NULL);
}
