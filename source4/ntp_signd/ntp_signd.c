/* 
   Unix SMB/CIFS implementation.

   NTP packet signing server

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Stefan Metzmacher	2005

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
#include "smbd/service_task.h"
#include "smbd/service.h"
#include "smbd/service_stream.h"
#include "smbd/process_model.h"
#include "lib/stream/packet.h"
#include "librpc/gen_ndr/ndr_ntp_signd.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"

/*
  top level context structure for the ntp_signd server
*/
struct ntp_signd_server {
	struct task_server *task;
	struct ldb_context *samdb;
};

/*
  state of an open connection
*/
struct ntp_signd_connection {
	/* stream connection we belong to */
	struct stream_connection *conn;

	/* the ntp_signd_server the connection belongs to */
	struct ntp_signd_server *ntp_signd;

	struct packet_context *packet;
};

static void ntp_signd_terminate_connection(struct ntp_signd_connection *ntp_signdconn, const char *reason)
{
	stream_terminate_connection(ntp_signdconn->conn, reason);
}

/*
  receive a full packet on a NTP_SIGND connection
*/
static NTSTATUS ntp_signd_recv(void *private, DATA_BLOB blob)
{
	struct ntp_signd_connection *ntp_signdconn = talloc_get_type(private, 
							     struct ntp_signd_connection);
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *tmp_ctx = talloc_new(ntp_signdconn);
	DATA_BLOB input, reply;
	const struct dom_sid *domain_sid;
	struct dom_sid *sid;
	struct sign_request sign_request;
	enum ndr_err_code ndr_err;
	struct ldb_result *res;
	const char *attrs[] = { "unicodePwd", NULL };
	int ret;

	talloc_steal(tmp_ctx, blob.data);

	input = data_blob_const(blob.data + 4, blob.length - 4); 

	ndr_err = ndr_pull_struct_blob_all(&input, tmp_ctx, 
					   lp_iconv_convenience(ntp_signdconn->ntp_signd->task->lp_ctx),
					   &sign_request,
					   (ndr_pull_flags_fn_t)ndr_pull_sign_request);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1,("failed to parse ntp signing request\n"));
		dump_data(1, input.data, input.length);
		return ndr_map_error2ntstatus(ndr_err);
	}

	domain_sid = samdb_domain_sid(ntp_signdconn->ntp_signd->samdb);
	if (!domain_sid) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	sid = dom_sid_add_rid(tmp_ctx, domain_sid, sign_request.key_id & 0x7FFFFFFF);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Sign packet */
	ret = ldb_search_exp_fmt(ntp_signdconn->ntp_signd->samdb, tmp_ctx,
				 &res, samdb_base_dn(ntp_signdconn->ntp_signd->samdb),
				 LDB_SCOPE_SUBTREE, attrs, "(&(objectSid=%s)(objectClass=computer))",
				 dom_sid_string(tmp_ctx, sid));
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (res->count != 1) {
		return NT_STATUS_NO_SUCH_USER;
	}

	/* Sign the NTP response with the unicodePwd */

	/* Place it into the packet for the wire */

	blob = data_blob_talloc(ntp_signdconn, NULL, reply.length + 4);
	if (!blob.data) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	RSIVAL(blob.data, 0, reply.length);
	memcpy(blob.data + 4, reply.data, reply.length);	

	status = packet_send(ntp_signdconn->packet, blob);

	/* the call isn't needed any more */
	talloc_free(tmp_ctx);
	return status;
}

/*
  receive some data on a NTP_SIGND connection
*/
static void ntp_signd_recv_handler(struct stream_connection *conn, uint16_t flags)
{
	struct ntp_signd_connection *ntp_signdconn = talloc_get_type(conn->private, 
							     struct ntp_signd_connection);
	packet_recv(ntp_signdconn->packet);
}

/*
  called on a tcp recv error
*/
static void ntp_signd_recv_error(void *private, NTSTATUS status)
{
	struct ntp_signd_connection *ntp_signdconn = talloc_get_type(private, struct ntp_signd_connection);
	ntp_signd_terminate_connection(ntp_signdconn, nt_errstr(status));
}

/*
  called when we can write to a connection
*/
static void ntp_signd_send(struct stream_connection *conn, uint16_t flags)
{
	struct ntp_signd_connection *ntp_signdconn = talloc_get_type(conn->private, 
							     struct ntp_signd_connection);
	packet_queue_run(ntp_signdconn->packet);
}

/*
  called when we get a new connection
*/
static void ntp_signd_accept(struct stream_connection *conn)
{
	struct ntp_signd_server *ntp_signd = talloc_get_type(conn->private, struct ntp_signd_server);
	struct ntp_signd_connection *ntp_signdconn;

	ntp_signdconn = talloc_zero(conn, struct ntp_signd_connection);
	if (!ntp_signdconn) {
		stream_terminate_connection(conn, "ntp_signd_accept: out of memory");
		return;
	}
	ntp_signdconn->conn	 = conn;
	ntp_signdconn->ntp_signd	 = ntp_signd;
	conn->private    = ntp_signdconn;

	ntp_signdconn->packet = packet_init(ntp_signdconn);
	if (ntp_signdconn->packet == NULL) {
		ntp_signd_terminate_connection(ntp_signdconn, "ntp_signd_accept: out of memory");
		return;
	}
	packet_set_private(ntp_signdconn->packet, ntp_signdconn);
	packet_set_socket(ntp_signdconn->packet, conn->socket);
	packet_set_callback(ntp_signdconn->packet, ntp_signd_recv);
	packet_set_full_request(ntp_signdconn->packet, packet_full_request_u32);
	packet_set_error_handler(ntp_signdconn->packet, ntp_signd_recv_error);
	packet_set_event_context(ntp_signdconn->packet, conn->event.ctx);
	packet_set_fde(ntp_signdconn->packet, conn->event.fde);
	packet_set_serialise(ntp_signdconn->packet);
}

static const struct stream_server_ops ntp_signd_stream_ops = {
	.name			= "ntp_signd",
	.accept_connection	= ntp_signd_accept,
	.recv_handler		= ntp_signd_recv_handler,
	.send_handler		= ntp_signd_send
};

/*
  startup the ntp_signd task
*/
static void ntp_signd_task_init(struct task_server *task)
{
	struct ntp_signd_server *ntp_signd;
	NTSTATUS status;

	const struct model_ops *model_ops;

	const char *address = "/tmp/ux_demo";

	/* within the ntp_signd task we want to be a single process, so
	   ask for the single process model ops and pass these to the
	   stream_setup_socket() call. */
	model_ops = process_model_byname("single");
	if (!model_ops) {
		DEBUG(0,("Can't find 'single' process model_ops\n"));
		return;
	}

	task_server_set_title(task, "task[ntp_signd]");

	ntp_signd = talloc(task, struct ntp_signd_server);
	if (ntp_signd == NULL) {
		task_server_terminate(task, "ntp_signd: out of memory");
		return;
	}

	ntp_signd->task = task;

	ntp_signd->samdb = samdb_connect(ntp_signd, task->event_ctx, task->lp_ctx, anonymous_session(ntp_signd, task->event_ctx, task->lp_ctx));
	if (ntp_signd->samdb == NULL) {
		task_server_terminate(task, "ntp_signd failed to open samdb");
		return;
	}

	status = stream_setup_socket(ntp_signd->task->event_ctx, 
				     ntp_signd->task->lp_ctx,
				     model_ops, 
				     &ntp_signd_stream_ops, 
				     "unix", address, NULL,
				     lp_socket_options(ntp_signd->task->lp_ctx), 
				     ntp_signd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s - %s\n",
			 address, nt_errstr(status)));
		return;
	}

}


/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_ntp_signd_init(void)
{
	return register_server_service("ntp_signd", ntp_signd_task_init);
}
