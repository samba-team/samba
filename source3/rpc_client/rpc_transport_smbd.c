/*
 *  Unix SMB/CIFS implementation.
 *  RPC client transport over named pipes to a child smbd
 *  Copyright (C) Volker Lendecke 2009
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_CLI

/**
 * struct rpc_cli_smbd_conn represents a forked smbd. This structure should
 * exist only once per process which does the rpc calls.
 *
 * RPC pipe handles can be attached to this smbd connection with
 * rpc_pipe_open_local().
 *
 * For this to work right, we can not use rpc_transport_np directly, because
 * the child smbd wants to write its DEBUG output somewhere. We redirect the
 * child's output to rpc_cli_smbd_conn->stdout_fd. While the RPC calls are
 * active, we have an event context available and attach a fd event to the
 * stdout_df.
 */

struct rpc_cli_smbd_conn {
	/**
	 * The smb connection to handle the named pipe traffic over
	 */
	struct cli_state *cli;

	/**
	 * Attached to stdout in the forked smbd, this is where smbd will
	 * print its DEBUG.
	 */
	int stdout_fd;

	/**
	 * Custom callback provided by the owner of the
	 * rpc_cli_smbd_conn. Here we send the smbd DEBUG output. Can be NULL.
	 */
	struct {
		void (*fn)(char *buf, size_t len, void *priv);
		void *priv;
	} stdout_callback ;
};

/**
 * Event handler to be called whenever the forked smbd prints debugging
 * output.
 */

static void rpc_cli_smbd_stdout_reader(struct event_context *ev,
				       struct fd_event *fde,
				       uint16_t flags, void *priv)
{
	struct rpc_cli_smbd_conn *conn = talloc_get_type_abort(
		priv, struct rpc_cli_smbd_conn);
	char buf[1024];
	ssize_t nread;

	if ((flags & EVENT_FD_READ) == 0) {
		return;
	}

	nread = read(conn->stdout_fd, buf, sizeof(buf)-1);
	if (nread < 0) {
		DEBUG(0, ("Could not read from smbd stdout: %s\n",
			  strerror(errno)));
		TALLOC_FREE(fde);
		return;
	}
	if (nread == 0) {
		DEBUG(0, ("EOF from smbd stdout\n"));
		TALLOC_FREE(fde);
		return;
	}
	buf[nread] = '\0';

	if (conn->stdout_callback.fn != NULL) {
		conn->stdout_callback.fn(buf, nread,
					 conn->stdout_callback.priv);
	}
}

/**
 * struct rpc_transport_smbd_state is the link from a struct rpc_pipe_client
 * to the rpc_cli_smbd_conn. We use a named pipe transport as a subtransport.
 */

struct rpc_transport_smbd_state {
	struct rpc_cli_smbd_conn *conn;
	struct rpc_cli_transport *sub_transp;
};

static int rpc_cli_smbd_conn_destructor(struct rpc_cli_smbd_conn *conn)
{
	if (conn->cli != NULL) {
		cli_shutdown(conn->cli);
		conn->cli = NULL;
	}
	if (conn->stdout_fd != -1) {
		close(conn->stdout_fd);
		conn->stdout_fd = -1;
	}
	return 0;
}

/*
 * Do the negprot/sesssetup/tcon to an anonymous ipc$ connection
 */

struct get_anon_ipc_state {
	struct event_context *ev;
	struct cli_state *cli;
};

static void get_anon_ipc_negprot_done(struct async_req *subreq);
static void get_anon_ipc_sesssetup_done(struct async_req *subreq);
static void get_anon_ipc_tcon_done(struct async_req *subreq);

static struct async_req *get_anon_ipc_send(TALLOC_CTX *mem_ctx,
					   struct event_context *ev,
					   struct cli_state *cli)
{
	struct async_req *result, *subreq;
	struct get_anon_ipc_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct get_anon_ipc_state)) {
		return NULL;
	}

	state->ev = ev;
	state->cli = cli;

	subreq = cli_negprot_send(state, ev, cli);
	if (subreq == NULL) {
		goto fail;
	}
	subreq->async.fn = get_anon_ipc_negprot_done;
	subreq->async.priv = result;
	return result;
 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void get_anon_ipc_negprot_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct get_anon_ipc_state *state = talloc_get_type_abort(
		req->private_data, struct get_anon_ipc_state);
	NTSTATUS status;

	status = cli_negprot_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}

	subreq = cli_session_setup_guest_send(state, state->ev, state->cli);
	if (async_req_nomem(subreq, req)) {
		return;
	}
	subreq->async.fn = get_anon_ipc_sesssetup_done;
	subreq->async.priv = req;
}

static void get_anon_ipc_sesssetup_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct get_anon_ipc_state *state = talloc_get_type_abort(
		req->private_data, struct get_anon_ipc_state);
	NTSTATUS status;

	status = cli_session_setup_guest_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}

	subreq = cli_tcon_andx_send(state, state->ev, state->cli,
				    "IPC$", "IPC", NULL, 0);
	if (async_req_nomem(subreq, req)) {
		return;
	}
	subreq->async.fn = get_anon_ipc_tcon_done;
	subreq->async.priv = req;
}

static void get_anon_ipc_tcon_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	NTSTATUS status;

	status = cli_tcon_andx_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}
	async_req_done(req);
}

static NTSTATUS get_anon_ipc_recv(struct async_req *req)
{
	return async_req_simple_recv_ntstatus(req);
}

struct rpc_cli_smbd_conn_init_state {
	struct event_context *ev;
	struct rpc_cli_smbd_conn *conn;
};

static void rpc_cli_smbd_conn_init_done(struct async_req *subreq);

struct async_req *rpc_cli_smbd_conn_init_send(TALLOC_CTX *mem_ctx,
					      struct event_context *ev,
					      void (*stdout_callback)(char *buf,
								      size_t len,
								      void *priv),
					      void *priv)
{
	struct async_req *result, *subreq;
	struct rpc_cli_smbd_conn_init_state *state;
	int smb_sock[2];
	int stdout_pipe[2];
	NTSTATUS status;
	pid_t pid;
	int ret;

	smb_sock[0] = smb_sock[1] = stdout_pipe[0] = stdout_pipe[1] = -1;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct rpc_cli_smbd_conn_init_state)) {
		return NULL;
	}
	state->ev = ev;

	state->conn = talloc(state, struct rpc_cli_smbd_conn);
	if (state->conn == NULL) {
		goto nomem;
	}

	state->conn->cli = cli_initialise();
	if (state->conn->cli == NULL) {
		goto nomem;
	}
	state->conn->stdout_fd = -1;
	state->conn->stdout_callback.fn = stdout_callback;
	state->conn->stdout_callback.priv = priv;
	talloc_set_destructor(state->conn, rpc_cli_smbd_conn_destructor);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, smb_sock);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		goto post_status;
	}
	ret = pipe(stdout_pipe);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		goto post_status;
	}

	pid = sys_fork();
	if (pid == -1) {
		status = map_nt_error_from_unix(errno);
		goto post_status;
	}
	if (pid == 0) {
		char *smbd_cmd;

		close(smb_sock[0]);
		close(stdout_pipe[0]);
		close(0);
		if (dup(smb_sock[1]) == -1) {
			exit(1);
		}
		close(smb_sock[1]);
		close(1);
		if (dup(stdout_pipe[1]) == -1) {
			exit(1);
		}
		close(stdout_pipe[1]);

		smbd_cmd = getenv("SMB_PATH");

		if ((smbd_cmd == NULL)
		    && (asprintf(&smbd_cmd, "%s/smbd", get_dyn_SBINDIR())
			== -1)) {
			printf("no memory");
			exit(1);
		}
		if (asprintf(&smbd_cmd, "%s -F -S -d %d", smbd_cmd,
			     DEBUGLEVEL) == -1) {
			printf("no memory");
			exit(1);
		}

		exit(system(smbd_cmd));
	}

	state->conn->cli->fd = smb_sock[0];
	smb_sock[0] = -1;
	close(smb_sock[1]);
	smb_sock[1] = -1;

	state->conn->stdout_fd = stdout_pipe[0];
	stdout_pipe[0] = -1;
	close(stdout_pipe[1]);
	stdout_pipe[1] = -1;

	subreq = get_anon_ipc_send(state, ev, state->conn->cli);
	if (subreq == NULL) {
		goto nomem;
	}

	if (event_add_fd(ev, state, state->conn->stdout_fd, EVENT_FD_READ,
			 rpc_cli_smbd_stdout_reader, state->conn) == NULL) {
		goto nomem;
	}

	subreq->async.fn = rpc_cli_smbd_conn_init_done;
	subreq->async.priv = result;
	return result;

 nomem:
	status = NT_STATUS_NO_MEMORY;
 post_status:
	if (smb_sock[0] != -1) {
		close(smb_sock[0]);
	}
	if (smb_sock[1] != -1) {
		close(smb_sock[1]);
	}
	if (stdout_pipe[0] != -1) {
		close(stdout_pipe[0]);
	}
	if (stdout_pipe[1] != -1) {
		close(stdout_pipe[1]);
	}
	if (async_post_ntstatus(result, ev, status)) {
		return result;
	}
	TALLOC_FREE(result);
	return NULL;
}

static void rpc_cli_smbd_conn_init_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	NTSTATUS status;

	status = get_anon_ipc_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}
	async_req_done(req);
}

NTSTATUS rpc_cli_smbd_conn_init_recv(struct async_req *req,
				     TALLOC_CTX *mem_ctx,
				     struct rpc_cli_smbd_conn **pconn)
{
	struct rpc_cli_smbd_conn_init_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_cli_smbd_conn_init_state);
	NTSTATUS status;

	if (async_req_is_nterror(req, &status)) {
		return status;
	}
	*pconn = talloc_move(mem_ctx, &state->conn);
	return NT_STATUS_OK;
}

NTSTATUS rpc_cli_smbd_conn_init(TALLOC_CTX *mem_ctx,
				struct rpc_cli_smbd_conn **pconn,
				void (*stdout_callback)(char *buf,
							size_t len,
							void *priv),
				void *priv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct async_req *req;
	NTSTATUS status;

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = rpc_cli_smbd_conn_init_send(frame, ev, stdout_callback, priv);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	while (req->state < ASYNC_REQ_DONE) {
		event_loop_once(ev);
	}

	status = rpc_cli_smbd_conn_init_recv(req, mem_ctx, pconn);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct rpc_smbd_write_state {
	struct rpc_cli_transport *sub_transp;
	ssize_t written;
};

static void rpc_smbd_write_done(struct async_req *subreq);

static struct async_req *rpc_smbd_write_send(TALLOC_CTX *mem_ctx,
					     struct event_context *ev,
					     const uint8_t *data, size_t size,
					     void *priv)
{
	struct rpc_transport_smbd_state *transp = talloc_get_type_abort(
		priv, struct rpc_transport_smbd_state);
	struct async_req *result, *subreq;
	struct rpc_smbd_write_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct rpc_smbd_write_state)) {
		return NULL;
	}
	state->sub_transp = transp->sub_transp;

	subreq = transp->sub_transp->write_send(state, ev, data, size,
						transp->sub_transp->priv);
	if (subreq == NULL) {
		goto fail;
	}

	if (event_add_fd(ev, state, transp->conn->stdout_fd, EVENT_FD_READ,
			 rpc_cli_smbd_stdout_reader, transp->conn) == NULL) {
		goto fail;
	}

	subreq->async.fn = rpc_smbd_write_done;
	subreq->async.priv = result;
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void rpc_smbd_write_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct rpc_smbd_write_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_smbd_write_state);
	NTSTATUS status;

	status = state->sub_transp->write_recv(subreq, &state->written);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}
	async_req_done(req);
}

static NTSTATUS rpc_smbd_write_recv(struct async_req *req, ssize_t *pwritten)
{
	struct rpc_smbd_write_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_smbd_write_state);
	NTSTATUS status;

	if (async_req_is_nterror(req, &status)) {
		return status;
	}
	*pwritten = state->written;
	return NT_STATUS_OK;
}

struct rpc_smbd_read_state {
	struct rpc_cli_transport *sub_transp;
	ssize_t received;
};

static void rpc_smbd_read_done(struct async_req *subreq);

static struct async_req *rpc_smbd_read_send(TALLOC_CTX *mem_ctx,
					    struct event_context *ev,
					    uint8_t *data, size_t size,
					    void *priv)
{
	struct rpc_transport_smbd_state *transp = talloc_get_type_abort(
		priv, struct rpc_transport_smbd_state);
	struct async_req *result, *subreq;
	struct rpc_smbd_read_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct rpc_smbd_read_state)) {
		return NULL;
	}
	state->sub_transp = transp->sub_transp;

	subreq = transp->sub_transp->read_send(state, ev, data, size,
						transp->sub_transp->priv);
	if (subreq == NULL) {
		goto fail;
	}

	if (event_add_fd(ev, state, transp->conn->stdout_fd, EVENT_FD_READ,
			 rpc_cli_smbd_stdout_reader, transp->conn) == NULL) {
		goto fail;
	}

	subreq->async.fn = rpc_smbd_read_done;
	subreq->async.priv = result;
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void rpc_smbd_read_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct rpc_smbd_read_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_smbd_read_state);
	NTSTATUS status;

	status = state->sub_transp->read_recv(subreq, &state->received);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}
	async_req_done(req);
}

static NTSTATUS rpc_smbd_read_recv(struct async_req *req, ssize_t *preceived)
{
	struct rpc_smbd_read_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_smbd_read_state);
	NTSTATUS status;

	if (async_req_is_nterror(req, &status)) {
		return status;
	}
	*preceived = state->received;
	return NT_STATUS_OK;
}

struct rpc_transport_smbd_init_state {
	struct rpc_cli_transport *transport;
	struct rpc_transport_smbd_state *transport_smbd;
};

static void rpc_transport_smbd_init_done(struct async_req *subreq);

struct async_req *rpc_transport_smbd_init_send(TALLOC_CTX *mem_ctx,
					       struct event_context *ev,
					       struct rpc_cli_smbd_conn *conn,
					       const struct ndr_syntax_id *abstract_syntax)
{
	struct async_req *result, *subreq;
	struct rpc_transport_smbd_init_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct rpc_transport_smbd_init_state)) {
		return NULL;
	}

	state->transport = talloc(state, struct rpc_cli_transport);
	if (state->transport == NULL) {
		goto fail;
	}
	state->transport_smbd = talloc(state->transport,
				       struct rpc_transport_smbd_state);
	if (state->transport_smbd == NULL) {
		goto fail;
	}
	state->transport_smbd->conn = conn;
	state->transport->priv = state->transport_smbd;

	if (event_add_fd(ev, state, conn->stdout_fd, EVENT_FD_READ,
			 rpc_cli_smbd_stdout_reader, conn) == NULL) {
		goto fail;
	}

	subreq = rpc_transport_np_init_send(state, ev, conn->cli,
					    abstract_syntax);
	if (subreq == NULL) {
		goto fail;
	}
	subreq->async.fn = rpc_transport_smbd_init_done;
	subreq->async.priv = result;
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void rpc_transport_smbd_init_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct rpc_transport_smbd_init_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_transport_smbd_init_state);
	NTSTATUS status;

	status = rpc_transport_np_init_recv(
		subreq, state->transport_smbd,
		&state->transport_smbd->sub_transp);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_nterror(req, status);
		return;
	}
	async_req_done(req);
}

NTSTATUS rpc_transport_smbd_init_recv(struct async_req *req,
				      TALLOC_CTX *mem_ctx,
				      struct rpc_cli_transport **presult)
{
	struct rpc_transport_smbd_init_state *state = talloc_get_type_abort(
		req->private_data, struct rpc_transport_smbd_init_state);
	NTSTATUS status;

	if (async_req_is_nterror(req, &status)) {
		return status;
	}

	state->transport->write_send = rpc_smbd_write_send;
	state->transport->write_recv = rpc_smbd_write_recv;
	state->transport->read_send = rpc_smbd_read_send;
	state->transport->read_recv = rpc_smbd_read_recv;
	state->transport->trans_send = NULL;
	state->transport->trans_recv = NULL;

	*presult = talloc_move(mem_ctx, &state->transport);
	return NT_STATUS_OK;
}

NTSTATUS rpc_transport_smbd_init(TALLOC_CTX *mem_ctx,
				 struct rpc_cli_smbd_conn *conn,
				 const struct ndr_syntax_id *abstract_syntax,
				 struct rpc_cli_transport **presult)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct async_req *req;
	NTSTATUS status;

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = rpc_transport_smbd_init_send(frame, ev, conn, abstract_syntax);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	while (req->state < ASYNC_REQ_DONE) {
		event_loop_once(ev);
	}

	status = rpc_transport_smbd_init_recv(req, mem_ctx, presult);
 fail:
	TALLOC_FREE(frame);
	return status;
}
