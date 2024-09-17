/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Stefan Metzmacher 2011-2012
 * Copyright (C) Michael Adam 2012
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SMBXSRV_SESSION_H__
#define __SMBXSRV_SESSION_H__

#include "replace.h"
#include <tevent.h>
#include "libcli/util/ntstatus.h"
#include "lib/util/time.h"

struct messaging_context;
struct smbXsrv_client;
struct smbXsrv_connection;
struct smbXsrv_session;
struct smbXsrv_session_global0;
struct smbXsrv_channel_global0;
struct smbXsrv_session_auth0;

NTSTATUS smbXsrv_session_global_init(struct messaging_context *msg_ctx);
NTSTATUS smbXsrv_session_create(struct smbXsrv_connection *conn,
				NTTIME now,
				struct smbXsrv_session **_session);
NTSTATUS smbXsrv_session_add_channel(struct smbXsrv_session *session,
				     struct smbXsrv_connection *conn,
				     NTTIME now,
				     struct smbXsrv_channel_global0 **_c);
NTSTATUS smbXsrv_session_remove_channel(struct smbXsrv_session *session,
					struct smbXsrv_connection *xconn);
NTSTATUS smbXsrv_session_disconnect_xconn(struct smbXsrv_connection *xconn);
NTSTATUS smbXsrv_session_update(struct smbXsrv_session *session);
NTSTATUS smbXsrv_session_find_channel(const struct smbXsrv_session *session,
				      const struct smbXsrv_connection *conn,
				      struct smbXsrv_channel_global0 **_c);
NTSTATUS smbXsrv_session_find_auth(const struct smbXsrv_session *session,
				   const struct smbXsrv_connection *conn,
				   NTTIME now,
				   struct smbXsrv_session_auth0 **_a);
NTSTATUS smbXsrv_session_create_auth(struct smbXsrv_session *session,
				     struct smbXsrv_connection *conn,
				     NTTIME now,
				     uint8_t in_flags,
				     uint8_t in_security_mode,
				     struct smbXsrv_session_auth0 **_a);
struct tevent_req *smb2srv_session_shutdown_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXsrv_session *session,
	struct smbd_smb2_request *current_req);
NTSTATUS smb2srv_session_shutdown_recv(struct tevent_req *req);
NTSTATUS smbXsrv_session_logoff(struct smbXsrv_session *session);
NTSTATUS smbXsrv_session_logoff_all(struct smbXsrv_client *client);
NTSTATUS smb1srv_session_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb1srv_session_lookup(struct smbXsrv_connection *conn,
				uint16_t vuid,
				NTTIME now,
				struct smbXsrv_session **session);
NTSTATUS smbXsrv_session_info_lookup(struct smbXsrv_client *client,
				     uint64_t session_wire_id,
				     struct auth_session_info **si);
NTSTATUS smb2srv_session_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb2srv_session_lookup_conn(struct smbXsrv_connection *conn,
				     uint64_t session_id,
				     NTTIME now,
				     struct smbXsrv_session **session);
NTSTATUS smb2srv_session_lookup_client(struct smbXsrv_client *client,
				       uint64_t session_id,
				       NTTIME now,
				       struct smbXsrv_session **session);
NTSTATUS smb2srv_session_lookup_global(struct smbXsrv_client *client,
				       uint64_t session_wire_id,
				       TALLOC_CTX *mem_ctx,
				       struct smbXsrv_session **session);
NTSTATUS get_valid_smbXsrv_session(struct smbXsrv_client *client,
				   uint64_t session_wire_id,
				   struct smbXsrv_session **session);
NTSTATUS smbXsrv_session_local_traverse(
	struct smbXsrv_client *client,
	int (*caller_cb)(struct smbXsrv_session *session, void *caller_data),
	void *caller_data);
NTSTATUS smbXsrv_session_global_traverse(
	int (*fn)(struct smbXsrv_session_global0 *, void *),
	void *private_data);
struct tevent_req *smb2srv_session_close_previous_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXsrv_connection *conn,
	struct auth_session_info *session_info,
	uint64_t previous_session_id,
	uint64_t current_session_id);
NTSTATUS smb2srv_session_close_previous_recv(struct tevent_req *req);

void smbXsrv_wait_for_handle_lease_break(
				struct tevent_req *req,
				struct tevent_context *ev,
				struct smbXsrv_client *client,
				struct tevent_queue *wait_queue,
				bool (*fsp_cmp_fn)(struct files_struct *fsp,
						   void *private_data),
				void *fsp_cmp_private_data);

#endif
