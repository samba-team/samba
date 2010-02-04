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

struct named_pipe_socket {
	const char *pipe_name;
	const char *pipe_path;
	const struct stream_server_ops *ops;
	void *private_data;
};

struct named_pipe_connection {
	struct stream_connection *connection;
	const struct named_pipe_socket *pipe_sock;
	struct tstream_context *tstream;
};

static void named_pipe_terminate_connection(struct named_pipe_connection *pipe_conn, const char *reason)
{
	stream_terminate_connection(pipe_conn->connection, reason);
}

static NTSTATUS named_pipe_full_request(void *private_data, DATA_BLOB blob, size_t *size)
{
	if (blob.length < 8) {
		return STATUS_MORE_ENTRIES;
	}

	if (memcmp(NAMED_PIPE_AUTH_MAGIC, &blob.data[4], 4) != 0) {
		DEBUG(0,("named_pipe_full_request: wrong protocol\n"));
		*size = blob.length;
		/* the error will be handled in named_pipe_recv_auth_request */
		return NT_STATUS_OK;
	}

	*size = 4 + RIVAL(blob.data, 0);
	if (*size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}

static void named_pipe_auth_request(struct tevent_req *subreq);

static void named_pipe_accept(struct stream_connection *conn)
{
	struct named_pipe_socket *pipe_sock = talloc_get_type(conn->private_data,
						struct named_pipe_socket);
	struct named_pipe_connection *pipe_conn;
	struct tevent_req *subreq;
	int rc, fd;

	pipe_conn = talloc_zero(conn, struct named_pipe_connection);
	if (pipe_conn == NULL) {
		stream_terminate_connection(conn,
				"named_pipe_accept: out of memory");
		return;
	}

	TALLOC_FREE(conn->event.fde);

	/*
	 * We have to duplicate the fd, cause it gets closed when the tstream
	 * is freed and you shouldn't work a fd the tstream is based on.
	 */
	fd = dup(socket_get_fd(conn->socket));
	if (fd == -1) {
		char *reason;

		reason = talloc_asprintf(conn,
					 "named_pipe_accept: failed to duplicate the file descriptor - %s",
					 strerror(errno));
		if (reason == NULL) {
			reason = strerror(errno);
		}
		stream_terminate_connection(conn, reason);
	}
	rc = tstream_bsd_existing_socket(pipe_conn,
					 fd,
					 &pipe_conn->tstream);
	if (rc < 0) {
		stream_terminate_connection(conn,
				"named_pipe_accept: out of memory");
		return;
	}

	pipe_conn->connection = conn;
	pipe_conn->pipe_sock = pipe_sock;
	conn->private_data = pipe_conn;

	/*
	 * The named pipe pdu's have the length as 8 byte (initial_read_size),
	 * named_pipe_full_request provides the pdu length then.
	 */
	subreq = tstream_read_pdu_blob_send(pipe_conn,
					    pipe_conn->connection->event.ctx,
					    pipe_conn->tstream,
					    8, /* initial_read_size */
					    named_pipe_full_request,
					    pipe_conn);
	if (subreq == NULL) {
		named_pipe_terminate_connection(pipe_conn,
				"named_pipe_accept: "
				"no memory for tstream_read_pdu_blob_send");
		return;
	}
	tevent_req_set_callback(subreq, named_pipe_auth_request, pipe_conn);
}

struct named_pipe_call {
	struct named_pipe_connection *pipe_conn;
	DATA_BLOB in;
	DATA_BLOB out;
	struct iovec out_iov[1];
	NTSTATUS status;
};

static void named_pipe_handover_connection(struct tevent_req *subreq);

static void named_pipe_auth_request(struct tevent_req *subreq)
{
	struct named_pipe_connection *pipe_conn = tevent_req_callback_data(subreq,
				      struct named_pipe_connection);
	struct stream_connection *conn = pipe_conn->connection;
	struct named_pipe_call *call;
	enum ndr_err_code ndr_err;
	union netr_Validation val;
	struct auth_serversupplied_info *server_info;
	struct named_pipe_auth_req pipe_request;
	struct named_pipe_auth_rep pipe_reply;
	NTSTATUS status;

	call = talloc(pipe_conn, struct named_pipe_call);
	if (call == NULL) {
		named_pipe_terminate_connection(pipe_conn,
				"named_pipe_auth_request: "
				"no memory for named_pipe_call");
		return;
	}
	call->pipe_conn = pipe_conn;

	status = tstream_read_pdu_blob_recv(subreq,
					    call,
					    &call->in);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "named_pipe_call_loop: "
					 "tstream_read_pdu_blob_recv() - %s",
					 nt_errstr(status));
		if (reason == NULL) {
			reason = nt_errstr(status);
		}

		named_pipe_terminate_connection(pipe_conn, reason);
		return;
	}

	DEBUG(10,("Received named_pipe packet of length %lu from %s\n",
		 (long) call->in.length,
		 tsocket_address_string(pipe_conn->connection->remote_address, call)));
	dump_data(11, call->in.data, call->in.length);

	/*
	 * TODO: check it's a root (uid == 0) pipe
	 */

	ZERO_STRUCT(pipe_reply);
	pipe_reply.level = 0;
	pipe_reply.status = NT_STATUS_INTERNAL_ERROR;

	/* parse the passed credentials */
	ndr_err = ndr_pull_struct_blob_all(
			&call->in,
			pipe_conn,
			lp_iconv_convenience(conn->lp_ctx),
			&pipe_request,
			(ndr_pull_flags_fn_t) ndr_pull_named_pipe_auth_req);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		pipe_reply.status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(2, ("Could not unmarshall named_pipe_auth_req: %s\n",
			  nt_errstr(pipe_reply.status)));
		goto reply;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(named_pipe_auth_req, &pipe_request);
	}

	if (strcmp(NAMED_PIPE_AUTH_MAGIC, pipe_request.magic) != 0) {
		DEBUG(2, ("named_pipe_auth_req: invalid magic '%s' != %s\n",
			  pipe_request.magic, NAMED_PIPE_AUTH_MAGIC));
		pipe_reply.status = NT_STATUS_INVALID_PARAMETER;
		goto reply;
	}

	switch (pipe_request.level) {
	case 0:
		/*
		 * anon connection, we don't create a session info
		 * and leave it NULL
		 */
		pipe_reply.level = 0;
		pipe_reply.status = NT_STATUS_OK;
		break;
	case 1:
		val.sam3 = &pipe_request.info.info1;

		pipe_reply.level = 1;
		pipe_reply.status = make_server_info_netlogon_validation(pipe_conn,
									 "TODO",
									 3, &val,
									 &server_info);
		if (!NT_STATUS_IS_OK(pipe_reply.status)) {
			DEBUG(2, ("make_server_info_netlogon_validation returned "
				  "%s\n", nt_errstr(pipe_reply.status)));
			goto reply;
		}

		/* setup the session_info on the connection */
		pipe_reply.status = auth_generate_session_info(conn,
							       conn->event.ctx,
							       conn->lp_ctx,
							       server_info,
							       &conn->session_info);
		if (!NT_STATUS_IS_OK(pipe_reply.status)) {
			DEBUG(2, ("auth_generate_session_info failed: %s\n",
				  nt_errstr(pipe_reply.status)));
			goto reply;
		}

		break;
	case 2:
		pipe_reply.level = 2;
		pipe_reply.info.info2.file_type = FILE_TYPE_MESSAGE_MODE_PIPE;
		pipe_reply.info.info2.device_state = 0xff | 0x0400 | 0x0100;
		pipe_reply.info.info2.allocation_size = 4096;

		if (pipe_request.info.info2.sam_info3 == NULL) {
			/*
			 * anon connection, we don't create a session info
			 * and leave it NULL
			 */
			pipe_reply.status = NT_STATUS_OK;
			break;
		}

		val.sam3 = pipe_request.info.info2.sam_info3;

		pipe_reply.status = make_server_info_netlogon_validation(pipe_conn,
						val.sam3->base.account_name.string,
						3, &val, &server_info);
		if (!NT_STATUS_IS_OK(pipe_reply.status)) {
			DEBUG(2, ("make_server_info_netlogon_validation returned "
				  "%s\n", nt_errstr(pipe_reply.status)));
			goto reply;
		}

		/* setup the session_info on the connection */
		pipe_reply.status = auth_generate_session_info(conn,
							conn->event.ctx,
							conn->lp_ctx,
							server_info,
							&conn->session_info);
		if (!NT_STATUS_IS_OK(pipe_reply.status)) {
			DEBUG(2, ("auth_generate_session_info failed: %s\n",
				  nt_errstr(pipe_reply.status)));
			goto reply;
		}

		conn->session_info->session_key = data_blob_const(pipe_request.info.info2.session_key,
							pipe_request.info.info2.session_key_length);
		talloc_steal(conn->session_info, pipe_request.info.info2.session_key);

		break;
	case 3:
		pipe_reply.level = 3;
		pipe_reply.info.info3.file_type = FILE_TYPE_MESSAGE_MODE_PIPE;
		pipe_reply.info.info3.device_state = 0xff | 0x0400 | 0x0100;
		pipe_reply.info.info3.allocation_size = 4096;

		if (pipe_request.info.info3.sam_info3 == NULL) {
			/*
			 * anon connection, we don't create a session info
			 * and leave it NULL
			 */
			pipe_reply.status = NT_STATUS_OK;
			break;
		}

		val.sam3 = pipe_request.info.info3.sam_info3;

		pipe_reply.status = make_server_info_netlogon_validation(pipe_conn,
						val.sam3->base.account_name.string,
						3, &val, &server_info);
		if (!NT_STATUS_IS_OK(pipe_reply.status)) {
			DEBUG(2, ("make_server_info_netlogon_validation returned "
				  "%s\n", nt_errstr(pipe_reply.status)));
			goto reply;
		}

		/* setup the session_info on the connection */
		pipe_reply.status = auth_generate_session_info(conn,
							       conn->event.ctx,
							       conn->lp_ctx,
							       server_info,
							       &conn->session_info);
		if (!NT_STATUS_IS_OK(pipe_reply.status)) {
			DEBUG(2, ("auth_generate_session_info failed: %s\n",
				  nt_errstr(pipe_reply.status)));
			goto reply;
		}

		if (pipe_request.info.info3.gssapi_delegated_creds_length) {
			OM_uint32 minor_status;
			gss_buffer_desc cred_token;
			gss_cred_id_t cred_handle;
			int ret;
			const char *error_string;

			DEBUG(10, ("named_pipe_auth: delegated credentials supplied by client\n"));

			cred_token.value = pipe_request.info.info3.gssapi_delegated_creds;
			cred_token.length = pipe_request.info.info3.gssapi_delegated_creds_length;

			ret = gss_import_cred(&minor_status,
					       &cred_token,
					       &cred_handle);
			if (ret != GSS_S_COMPLETE) {
				pipe_reply.status = NT_STATUS_INTERNAL_ERROR;
				goto reply;
			}

			conn->session_info->credentials = cli_credentials_init(conn->session_info);
			if (conn->session_info->credentials == NULL) {
				pipe_reply.status = NT_STATUS_NO_MEMORY;
				goto reply;
			}

			cli_credentials_set_conf(conn->session_info->credentials,
						 conn->lp_ctx);
			/* Just so we don't segfault trying to get at a username */
			cli_credentials_set_anonymous(conn->session_info->credentials);

			ret = cli_credentials_set_client_gss_creds(conn->session_info->credentials,
								   conn->event.ctx,
								   conn->lp_ctx,
								   cred_handle,
								   CRED_SPECIFIED, &error_string);
			if (ret) {
				pipe_reply.status = NT_STATUS_INTERNAL_ERROR;
				DEBUG(2, ("Failed to set pipe forwarded creds: %s\n", error_string));
				goto reply;
			}

			/* This credential handle isn't useful for password authentication, so ensure nobody tries to do that */
			cli_credentials_set_kerberos_state(conn->session_info->credentials,
							   CRED_MUST_USE_KERBEROS);
		}

		conn->session_info->session_key = data_blob_const(pipe_request.info.info3.session_key,
							pipe_request.info.info3.session_key_length);
		talloc_steal(conn->session_info, pipe_request.info.info3.session_key);

		break;
	default:
		DEBUG(0, ("named_pipe_auth_req: unknown level %u\n",
			  pipe_request.level));
		pipe_reply.level = 0;
		pipe_reply.status = NT_STATUS_INVALID_LEVEL;
		goto reply;
	}

reply:
	/* create the output */
	ndr_err = ndr_push_struct_blob(&call->out, pipe_conn,
			lp_iconv_convenience(conn->lp_ctx),
			&pipe_reply,
			(ndr_push_flags_fn_t)ndr_push_named_pipe_auth_rep);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		const char *reason;
		status = ndr_map_error2ntstatus(ndr_err);

		reason = talloc_asprintf(pipe_conn, "named_pipe_auth_request: could not marshall named_pipe_auth_rep: %s\n",
					 nt_errstr(status));
		if (reason == NULL) {
			reason = "named_pipe_auth_request: could not marshall named_pipe_auth_rep";
		}
		named_pipe_terminate_connection(pipe_conn, reason);
		return;
	}

	DEBUG(10,("named_pipe_auth_request: named_pipe_auth reply[%u]\n",
		  (unsigned) call->out.length));
	dump_data(11, call->out.data, call->out.length);
	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(named_pipe_auth_rep, &pipe_reply);
	}

	call->status = pipe_reply.status;

	call->out_iov[0].iov_base = call->out.data;
	call->out_iov[0].iov_len = call->out.length;

	subreq = tstream_writev_send(call,
				     pipe_conn->connection->event.ctx,
				     pipe_conn->tstream,
				     call->out_iov, 1);
	if (subreq == NULL) {
		named_pipe_terminate_connection(pipe_conn, "named_pipe_auth_request: "
				"no memory for tstream_writev_send");
		return;
	}

	tevent_req_set_callback(subreq, named_pipe_handover_connection, call);
}

static void named_pipe_handover_connection(struct tevent_req *subreq)
{
	struct named_pipe_call *call = tevent_req_callback_data(subreq,
			struct named_pipe_call);
	struct named_pipe_connection *pipe_conn = call->pipe_conn;
	struct stream_connection *conn = pipe_conn->connection;
	int sys_errno;
	int rc;

	rc = tstream_writev_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (rc == -1) {
		const char *reason;

		reason = talloc_asprintf(call, "named_pipe_handover_connection: "
					 "tstream_writev_recv() - %d:%s",
					 sys_errno, strerror(sys_errno));
		if (reason == NULL) {
			reason = "named_pipe_handover_connection: "
				 "tstream_writev_recv() failed";
		}

		named_pipe_terminate_connection(pipe_conn, reason);
		return;
	}

	if (!NT_STATUS_IS_OK(call->status)) {
		const char *reason;

		reason = talloc_asprintf(call, "named_pipe_handover_connection: "
					"reply status - %s", nt_errstr(call->status));
		if (reason == NULL) {
			reason = nt_errstr(call->status);
		}

		named_pipe_terminate_connection(pipe_conn, reason);
		return;
	}

	/*
	 * remove the named_pipe layer together with its packet layer
	 */
	conn->ops		= pipe_conn->pipe_sock->ops;
	conn->private_data	= pipe_conn->pipe_sock->private_data;
	talloc_unlink(conn, pipe_conn);

	conn->event.fde = tevent_add_fd(conn->event.ctx,
					conn,
					socket_get_fd(conn->socket),
					TEVENT_FD_READ,
					stream_io_handler_fde,
					conn);
	if (conn->event.fde == NULL) {
		named_pipe_terminate_connection(pipe_conn, "named_pipe_handover_connection: "
				"setting up the stream_io_handler_fde failed");
		return;
	}

	/*
	 * hand over to the real pipe implementation,
	 * now that we have setup the transport session_info
	 */
	conn->ops->accept_connection(conn);

	DEBUG(10,("named_pipe_handover_connection[%s]: succeeded\n",
	      conn->ops->name));

	/* we don't have to free call here as the connection got closed */
}

/*
  called when a pipe socket becomes readable
*/
static void named_pipe_recv(struct stream_connection *conn, uint16_t flags)
{
	struct named_pipe_connection *pipe_conn = talloc_get_type(
		conn->private_data, struct named_pipe_connection);

	named_pipe_terminate_connection(pipe_conn,
					"named_pipe_recv: called");
}

/*
  called when a pipe socket becomes writable
*/
static void named_pipe_send(struct stream_connection *conn, uint16_t flags)
{
	struct named_pipe_connection *pipe_conn = talloc_get_type(
		conn->private_data, struct named_pipe_connection);

	named_pipe_terminate_connection(pipe_conn,
					"named_pipe_send: called");
}

static const struct stream_server_ops named_pipe_stream_ops = {
	.name			= "named_pipe",
	.accept_connection	= named_pipe_accept,
	.recv_handler		= named_pipe_recv,
	.send_handler		= named_pipe_send,
};

NTSTATUS stream_setup_named_pipe(struct tevent_context *event_context,
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

	dirname = talloc_asprintf(pipe_sock, "%s/np", lp_ncalrpc_dir(lp_ctx));
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

	pipe_sock->ops		= stream_ops;
	pipe_sock->private_data	= talloc_reference(pipe_sock, private_data);

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
