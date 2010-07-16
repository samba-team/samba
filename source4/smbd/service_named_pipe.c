/*
   Unix SMB/CIFS implementation.

   helper functions for NAMED PIPE servers

   Copyright (C) Stefan (metze) Metzmacher	2008

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
#include <tevent.h>
#include "smbd/service.h"
#include "param/param.h"
#include "auth/auth.h"
#include "auth/session.h"
#include "auth/auth_sam_reply.h"
#include "lib/socket/socket.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/util/tstream.h"
#include "librpc/gen_ndr/ndr_named_pipe_auth.h"
#include "system/passwd.h"
#include "system/network.h"
#include "libcli/raw/smb.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "libcli/security/dom_sid.h"
#include "libcli/named_pipe_auth/npa_tstream.h"

struct named_pipe_socket {
	const char *pipe_name;
	const char *pipe_path;
	const struct stream_server_ops *ops;
	void *private_data;
};

static void named_pipe_accept_done(struct tevent_req *subreq);

static void named_pipe_accept(struct stream_connection *conn)
{
	struct tstream_context *plain_tstream;
	int fd;
	struct tevent_req *subreq;
	int ret;

	/* Let tstream take over fd operations */

	fd = socket_get_fd(conn->socket);
	socket_set_flags(conn->socket, SOCKET_FLAG_NOCLOSE);
	TALLOC_FREE(conn->event.fde);
	TALLOC_FREE(conn->socket);

	ret = tstream_bsd_existing_socket(conn, fd, &plain_tstream);
	if (ret != 0) {
		stream_terminate_connection(conn,
				"named_pipe_accept: out of memory");
		return;
	}

	subreq = tstream_npa_accept_existing_send(conn, conn->event.ctx,
						  plain_tstream,
						  FILE_TYPE_MESSAGE_MODE_PIPE,
						  0xff | 0x0400 | 0x0100,
						  4096);
	if (subreq == NULL) {
		stream_terminate_connection(conn,
			"named_pipe_accept: "
			"no memory for tstream_npa_accept_existing_send");
		return;
	}
	tevent_req_set_callback(subreq, named_pipe_accept_done, conn);
}

static void named_pipe_accept_done(struct tevent_req *subreq)
{
	struct stream_connection *conn = tevent_req_callback_data(subreq,
						struct stream_connection);
	struct named_pipe_socket *pipe_sock =
				talloc_get_type(conn->private_data,
						struct named_pipe_socket);
	struct tsocket_address *client;
	char *client_name;
	struct tsocket_address *server;
	char *server_name;
	struct netr_SamInfo3 *info3;
	DATA_BLOB session_key;
	DATA_BLOB delegated_creds;

	union netr_Validation val;
	struct auth_serversupplied_info *server_info;
	struct auth_context *auth_context;
	uint32_t session_flags = 0;
	struct dom_sid *anonymous_sid;
	const char *reason = NULL;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	int error;
	int ret;

	tmp_ctx = talloc_new(conn);
	if (!tmp_ctx) {
		reason = "Out of memory!\n";
		goto out;
	}

	ret = tstream_npa_accept_existing_recv(subreq, &error, tmp_ctx,
						&conn->tstream,
						&client,
						&client_name,
						&server,
						&server_name,
						&info3,
						&session_key,
						&delegated_creds);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		reason = talloc_asprintf(conn,
					 "tstream_npa_accept_existing_recv()"
					 " failed: %s", strerror(error));
		goto out;
	}

	DEBUG(10, ("Accepted npa connection from %s. "
		   "Client: %s (%s). Server: %s (%s)\n",
		   tsocket_address_string(conn->remote_address, tmp_ctx),
		   client_name, tsocket_address_string(client, tmp_ctx),
		   server_name, tsocket_address_string(server, tmp_ctx)));

	if (info3) {
		val.sam3 = info3;

		status = make_server_info_netlogon_validation(conn,
					val.sam3->base.account_name.string,
					3, &val, &server_info);
		if (!NT_STATUS_IS_OK(status)) {
			reason = talloc_asprintf(conn,
					"make_server_info_netlogon_validation "
					"returned: %s", nt_errstr(status));
			goto out;
		}

		status = auth_context_create(conn, conn->event.ctx,
					     conn->msg_ctx, conn->lp_ctx,
					     &auth_context);
		if (!NT_STATUS_IS_OK(status)) {
			reason = talloc_asprintf(conn,
					"auth_context_create returned: %s",
					nt_errstr(status));
			goto out;
		}

		anonymous_sid = dom_sid_parse_talloc(auth_context,
						     SID_NT_ANONYMOUS);
		if (anonymous_sid == NULL) {
			talloc_free(auth_context);
			reason = "Failed to parse Anonymous SID ";
			goto out;
		}

		session_flags = AUTH_SESSION_INFO_DEFAULT_GROUPS;
		if (!dom_sid_equal(anonymous_sid, server_info->account_sid)) {
			session_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
		}


		/* setup the session_info on the connection */
		status = auth_context->generate_session_info(conn,
							     auth_context,
							     server_info,
							     session_flags,
							     &conn->session_info);
		talloc_free(auth_context);
		if (!NT_STATUS_IS_OK(status)) {
			reason = talloc_asprintf(conn,
					"auth_generate_session_info "
					"returned: %s", nt_errstr(status));
			goto out;
		}
	}

	if (session_key.length) {
		conn->session_info->session_key = session_key;
		talloc_steal(conn->session_info, session_key.data);
	}

	if (delegated_creds.length) {
		struct cli_credentials *creds;
		OM_uint32 minor_status;
		gss_buffer_desc cred_token;
		gss_cred_id_t cred_handle;
		const char *error_string;

		DEBUG(10, ("Delegated credentials supplied by client\n"));

		cred_token.value = delegated_creds.data;
		cred_token.length = delegated_creds.length;

		ret = gss_import_cred(&minor_status,
				      &cred_token,
				      &cred_handle);
		if (ret != GSS_S_COMPLETE) {
			reason = "Internal error in gss_import_cred()";
			goto out;
		}

		creds = cli_credentials_init(conn->session_info);
		if (!creds) {
			reason = "Out of memory in cli_credentials_init()";
			goto out;
		}
		conn->session_info->credentials = creds;

		cli_credentials_set_conf(creds, conn->lp_ctx);
		/* Just so we don't segfault trying to get at a username */
		cli_credentials_set_anonymous(creds);

		ret = cli_credentials_set_client_gss_creds(creds,
							   conn->event.ctx,
							   conn->lp_ctx,
							   cred_handle,
							   CRED_SPECIFIED,
							   &error_string);
		if (ret) {
			reason = talloc_asprintf(conn,
						 "Failed to set pipe forwarded"
						 "creds: %s\n", error_string);
			goto out;
		}

		/* This credential handle isn't useful for password
		 * authentication, so ensure nobody tries to do that */
		cli_credentials_set_kerberos_state(creds,
						   CRED_MUST_USE_KERBEROS);

	}

	/*
	 * hand over to the real pipe implementation,
	 * now that we have setup the transport session_info
	 */
	conn->ops = pipe_sock->ops;
	conn->private_data = pipe_sock->private_data;
	conn->ops->accept_connection(conn);

	DEBUG(10, ("named pipe connection [%s] established\n",
		   conn->ops->name));

	talloc_free(tmp_ctx);
	return;

out:
	talloc_free(tmp_ctx);
	if (!reason) {
		reason = "Internal error";
	}
	stream_terminate_connection(conn, reason);
}

/*
  called when a pipe socket becomes readable
*/
static void named_pipe_recv(struct stream_connection *conn, uint16_t flags)
{
	stream_terminate_connection(conn, "named_pipe_recv: called");
}

/*
  called when a pipe socket becomes writable
*/
static void named_pipe_send(struct stream_connection *conn, uint16_t flags)
{
	stream_terminate_connection(conn, "named_pipe_send: called");
}

static const struct stream_server_ops named_pipe_stream_ops = {
	.name			= "named_pipe",
	.accept_connection	= named_pipe_accept,
	.recv_handler		= named_pipe_recv,
	.send_handler		= named_pipe_send,
};

NTSTATUS tstream_setup_named_pipe(struct tevent_context *event_context,
				  struct loadparm_context *lp_ctx,
				  const struct model_ops *model_ops,
				  const struct stream_server_ops *stream_ops,
				  const char *pipe_name,
				  void *private_data)
{
	char *dirname;
	struct named_pipe_socket *pipe_sock;
	NTSTATUS status = NT_STATUS_NO_MEMORY;;

	pipe_sock = talloc(event_context, struct named_pipe_socket);
	if (pipe_sock == NULL) {
		goto fail;
	}

	/* remember the details about the pipe */
	pipe_sock->pipe_name	= talloc_strdup(pipe_sock, pipe_name);
	if (pipe_sock->pipe_name == NULL) {
		goto fail;
	}

	dirname = talloc_asprintf(pipe_sock, "%s/np", lpcfg_ncalrpc_dir(lp_ctx));
	if (dirname == NULL) {
		goto fail;
	}

	if (!directory_create_or_exist(dirname, geteuid(), 0700)) {
		status = map_nt_error_from_unix(errno);
		DEBUG(0,(__location__ ": Failed to create stream pipe directory %s - %s\n",
			 dirname, nt_errstr(status)));
		goto fail;
	}

	if (strncmp(pipe_name, "\\pipe\\", 6) == 0) {
		pipe_name += 6;
	}

	pipe_sock->pipe_path = talloc_asprintf(pipe_sock, "%s/%s", dirname,
					       pipe_name);
	if (pipe_sock->pipe_path == NULL) {
		goto fail;
	}

	talloc_free(dirname);

	pipe_sock->ops = stream_ops;
	pipe_sock->private_data	= private_data;

	status = stream_setup_socket(event_context,
				     lp_ctx,
				     model_ops,
				     &named_pipe_stream_ops,
				     "unix",
				     pipe_sock->pipe_path,
				     NULL,
				     NULL,
				     pipe_sock);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	return NT_STATUS_OK;

 fail:
	talloc_free(pipe_sock);
	return status;
}
