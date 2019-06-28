/*
   Unix SMB/CIFS implementation.

   Samba internal messaging functions (send).

   Copyright (C) Andrew Tridgell 2004

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
#include "messaging/messaging.h"
#include "messaging/irpc.h"
#include "lib/messaging/messages_dgm.h"
#include "lib/messaging/messages_dgm_ref.h"
#include "../source3/lib/messages_util.h"
#include "messaging/messaging_internal.h"
#include "lib/util/server_id_db.h"
#include "cluster/cluster.h"
#include "../lib/util/unix_privs.h"

/*
 * This file is for functions that can be called from auth_log without
 * depending on all of dcerpc and so cause dep loops.
 */

/*
  return a list of server ids for a server name
*/
NTSTATUS irpc_servers_byname(struct imessaging_context *msg_ctx,
			     TALLOC_CTX *mem_ctx, const char *name,
			     unsigned *num_servers,
			     struct server_id **servers)
{
	int ret;

	ret = server_id_db_lookup(msg_ctx->names, name, mem_ctx,
				  num_servers, servers);
	if (ret != 0) {
		return map_nt_error_from_unix_common(ret);
	}
	return NT_STATUS_OK;
}

/*
  Send a message to a particular server
*/
NTSTATUS imessaging_send(struct imessaging_context *msg, struct server_id server,
			uint32_t msg_type, const DATA_BLOB *data)
{
	uint8_t hdr[MESSAGE_HDR_LENGTH];
	struct iovec iov[2];
	int num_iov, ret;
	pid_t pid;
	void *priv;

	if (!cluster_node_equal(&msg->server_id, &server)) {
		/* No cluster in source4... */
		return NT_STATUS_OK;
	}

	message_hdr_put(hdr, msg_type, msg->server_id, server);

	iov[0] = (struct iovec) { .iov_base = &hdr, .iov_len = sizeof(hdr) };
	num_iov = 1;

	if (data != NULL) {
		iov[1] = (struct iovec) { .iov_base = data->data,
					  .iov_len = data->length };
		num_iov += 1;
	}

	pid = server.pid;
	if (pid == 0) {
		pid = getpid();
	}

	ret = messaging_dgm_send(pid, iov, num_iov, NULL, 0);

	if (ret == EACCES) {
		priv = root_privileges();
		ret = messaging_dgm_send(pid, iov, num_iov, NULL, 0);
		TALLOC_FREE(priv);
	}

	if (ret != 0) {
		return map_nt_error_from_unix_common(ret);
	}
	return NT_STATUS_OK;
}

/*
  Send a message to a particular server, with the message containing a single pointer
*/
NTSTATUS imessaging_send_ptr(struct imessaging_context *msg, struct server_id server,
			    uint32_t msg_type, void *ptr)
{
	DATA_BLOB blob;

	blob.data = (uint8_t *)&ptr;
	blob.length = sizeof(void *);

	return imessaging_send(msg, server, msg_type, &blob);
}
