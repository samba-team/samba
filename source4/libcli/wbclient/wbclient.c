/*
   Unix SMB/CIFS implementation.

   Winbind client library.

   Copyright (C) 2008 Kai Blin  <kai@samba.org>

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
#include "lib/util/tevent_unix.h"
#include "libcli/wbclient/wbclient.h"
#include "nsswitch/wb_reqtrans.h"
#include "system/network.h"
#include "libcli/util/error.h"
#include "libcli/security/dom_sid.h"

/**
 * Initialize the wbclient context, talloc_free() when done.
 *
 * \param mem_ctx talloc context to allocate memory from
 * \param msg_ctx message context to use
 * \param
 */
struct wbc_context *wbc_init(TALLOC_CTX *mem_ctx,
			     struct imessaging_context *msg_ctx,
			     struct tevent_context *event_ctx)
{
	struct wbc_context *ctx;

	ctx = talloc(mem_ctx, struct wbc_context);
	if (ctx == NULL) return NULL;

	ctx->event_ctx = event_ctx;

	ctx->irpc_handle = irpc_binding_handle_by_name(ctx, msg_ctx,
						       "winbind_server",
						       &ndr_table_winbind);
	if (ctx->irpc_handle == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	return ctx;
}

struct wbc_idmap_state {
	struct composite_context *ctx;
	struct winbind_get_idmap *req;
	struct id_map *ids;
};

static void sids_to_xids_recv_ids(struct tevent_req *subreq);

struct composite_context *wbc_sids_to_xids_send(struct wbc_context *wbc_ctx,
						TALLOC_CTX *mem_ctx,
						uint32_t count,
						struct id_map *ids)
{
	struct composite_context *ctx;
	struct wbc_idmap_state *state;
	struct tevent_req *subreq;

	DEBUG(5, ("wbc_sids_to_xids called\n"));

	ctx = composite_create(mem_ctx, wbc_ctx->event_ctx);
	if (ctx == NULL) return NULL;

	state = talloc(ctx, struct wbc_idmap_state);
	if (composite_nomem(state, ctx)) return ctx;
	ctx->private_data = state;

	state->req = talloc(state, struct winbind_get_idmap);
	if (composite_nomem(state->req, ctx)) return ctx;

	state->req->in.count = count;
	state->req->in.level = WINBIND_IDMAP_LEVEL_SIDS_TO_XIDS;
	state->req->in.ids = ids;
	state->ctx = ctx;

	subreq = dcerpc_winbind_get_idmap_r_send(state,
						 wbc_ctx->event_ctx,
						 wbc_ctx->irpc_handle,
						 state->req);
	if (composite_nomem(subreq, ctx)) return ctx;

	tevent_req_set_callback(subreq, sids_to_xids_recv_ids, state);

	return ctx;
}

static void sids_to_xids_recv_ids(struct tevent_req *subreq)
{
	struct wbc_idmap_state *state =
		tevent_req_callback_data(subreq,
		struct wbc_idmap_state);

	state->ctx->status = dcerpc_winbind_get_idmap_r_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(state->ctx)) return;

	state->ids = state->req->out.ids;
	composite_done(state->ctx);
}

NTSTATUS wbc_sids_to_xids_recv(struct composite_context *ctx,
			       struct id_map **ids)
{
	NTSTATUS status = composite_wait(ctx);
		DEBUG(5, ("wbc_sids_to_xids_recv called\n"));
	if (NT_STATUS_IS_OK(status)) {
		struct wbc_idmap_state *state =	talloc_get_type_abort(
							ctx->private_data,
							struct wbc_idmap_state);
		*ids = state->ids;
	}

	return status;
}

static void xids_to_sids_recv_ids(struct tevent_req *subreq);

struct composite_context *wbc_xids_to_sids_send(struct wbc_context *wbc_ctx,
						TALLOC_CTX *mem_ctx,
						uint32_t count,
						struct id_map *ids)
{
	struct composite_context *ctx;
	struct wbc_idmap_state *state;
	struct tevent_req *subreq;

	DEBUG(5, ("wbc_xids_to_sids called\n"));

	ctx = composite_create(mem_ctx, wbc_ctx->event_ctx);
	if (ctx == NULL) return NULL;

	state = talloc(ctx, struct wbc_idmap_state);
	if (composite_nomem(state, ctx)) return ctx;
	ctx->private_data = state;

	state->req = talloc(state, struct winbind_get_idmap);
	if (composite_nomem(state->req, ctx)) return ctx;

	state->req->in.count = count;
	state->req->in.level = WINBIND_IDMAP_LEVEL_XIDS_TO_SIDS;
	state->req->in.ids = ids;
	state->ctx = ctx;

	subreq = dcerpc_winbind_get_idmap_r_send(state,
						 wbc_ctx->event_ctx,
						 wbc_ctx->irpc_handle,
						 state->req);
	if (composite_nomem(subreq, ctx)) return ctx;

	tevent_req_set_callback(subreq, xids_to_sids_recv_ids, state);

	return ctx;
}

static void xids_to_sids_recv_ids(struct tevent_req *subreq)
{
	struct wbc_idmap_state *state =
		tevent_req_callback_data(subreq,
		struct wbc_idmap_state);

	state->ctx->status = dcerpc_winbind_get_idmap_r_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(state->ctx)) return;

	state->ids = state->req->out.ids;
	composite_done(state->ctx);
}

NTSTATUS wbc_xids_to_sids_recv(struct composite_context *ctx,
			       struct id_map **ids)
{
	NTSTATUS status = composite_wait(ctx);
		DEBUG(5, ("wbc_xids_to_sids_recv called\n"));
	if (NT_STATUS_IS_OK(status)) {
		struct wbc_idmap_state *state =	talloc_get_type_abort(
							ctx->private_data,
							struct wbc_idmap_state);
		*ids = state->ids;
	}

	return status;
}

static int wb_simple_trans(struct tevent_context *ev, int fd,
			   struct winbindd_request *wb_req,
			   TALLOC_CTX *mem_ctx,
			   struct winbindd_response **resp, int *err)
{
	struct tevent_req *req;
	bool polled;
	int ret;

	req = wb_simple_trans_send(ev, ev, NULL, fd, wb_req);
	if (req == NULL) {
		*err = ENOMEM;
		return -1;
	}

	polled = tevent_req_poll(req, ev);
	if (!polled) {
		*err = errno;
		DEBUG(10, ("tevent_req_poll returned %s\n",
			   strerror(*err)));
		return -1;
	}

	ret = wb_simple_trans_recv(req, mem_ctx, resp, err);
	TALLOC_FREE(req);
	return ret;
}

static const char *winbindd_socket_dir(void)
{
#ifdef SOCKET_WRAPPER
	const char *env_dir;

	env_dir = getenv(WINBINDD_SOCKET_DIR_ENVVAR);
	if (env_dir) {
		return env_dir;
	}
#endif

	return WINBINDD_SOCKET_DIR;
}

static int winbindd_pipe_sock(void)
{
	struct sockaddr_un sunaddr = {};
	int ret, fd;
	char *path;

	ret = asprintf(&path, "%s/%s", winbindd_socket_dir(),
		       WINBINDD_SOCKET_NAME);
	if (ret == -1) {
		errno = ENOMEM;
		return -1;
	}
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path));
	free(path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}

	ret = connect(fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (ret == -1) {
		int err = errno;
		close(fd);
		errno = err;
		return -1;
	}

	return fd;
}

NTSTATUS wbc_sids_to_xids(struct tevent_context *ev, struct id_map *ids,
			  uint32_t count)
{
	TALLOC_CTX *mem_ctx;
	struct winbindd_request req = {};
	struct winbindd_response *resp;
	uint32_t i;
	int fd, ret, err;
	char *sids, *p;
	size_t sidslen;

	fd = winbindd_pipe_sock();
	if (fd == -1) {
		return map_nt_error_from_unix_common(errno);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		close(fd);
		return NT_STATUS_NO_MEMORY;
	}

	sidslen = count * (DOM_SID_STR_BUFLEN + 1);

	sids = talloc_array(mem_ctx, char, sidslen);
	if (sids == NULL) {
		close(fd);
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	p = sids;
	for (i=0; i<count; i++) {
		p += dom_sid_string_buf(ids[i].sid, p, sidslen - (p - sids));
		*p++ = '\n';
	}
	*p++ = '\0';

	DEBUG(10, ("sids=\n%s", sids));

	req.length = sizeof(struct winbindd_request);
	req.cmd = WINBINDD_SIDS_TO_XIDS;
	req.pid = getpid();
	req.extra_data.data = sids;
	req.extra_len = sidslen;

	ret = wb_simple_trans(ev, fd, &req, mem_ctx, &resp, &err);
	if (ret == -1) {
		return map_nt_error_from_unix_common(err);
	}

	close(fd);

	p = resp->extra_data.data;

	for (i=0; i<count; i++) {
		struct unixid *id = &ids[i].xid;
		char *q;

		switch (p[0]) {
		case 'U':
			id->type = ID_TYPE_UID;
			id->id = strtoul(p+1, &q, 10);
			break;
		case 'G':
			id->type = ID_TYPE_GID;
			id->id = strtoul(p+1, &q, 10);
			break;
		case 'B':
			id->type = ID_TYPE_BOTH;
			id->id = strtoul(p+1, &q, 10);
			break;
		default:
			id->type = ID_TYPE_NOT_SPECIFIED;
			id->id = UINT32_MAX;
			q = strchr(p, '\n');
			break;
		};
		ids[i].status = ID_MAPPED;

		if (q == NULL || q[0] != '\n') {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
		p = q+1;
	}

	return NT_STATUS_OK;
}

struct wbc_id_to_sid_state {
	struct winbindd_request wbreq;
	struct dom_sid sid;
};

static void wbc_id_to_sid_done(struct tevent_req *subreq);

static struct tevent_req *wbc_id_to_sid_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     int fd, const struct unixid *id)
{
	struct tevent_req *req, *subreq;
	struct wbc_id_to_sid_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_id_to_sid_state);
	if (req == NULL) {
		return NULL;
	}

	switch(id->type) {
	case ID_TYPE_UID:
		state->wbreq.cmd = WINBINDD_UID_TO_SID;
		state->wbreq.data.uid = id->id;
		break;
	case ID_TYPE_GID:
		state->wbreq.cmd = WINBINDD_GID_TO_SID;
		state->wbreq.data.gid = id->id;
		break;
	default:
		tevent_req_error(req, ENOENT);
		return tevent_req_post(req, ev);
	}

	subreq = wb_simple_trans_send(state, ev, NULL, fd, &state->wbreq);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wbc_id_to_sid_done, req);
	return req;
}

static void wbc_id_to_sid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wbc_id_to_sid_state *state = tevent_req_data(
		req, struct wbc_id_to_sid_state);
	struct winbindd_response *wbresp;
	int ret, err;

	ret = wb_simple_trans_recv(subreq, state, &wbresp, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	if ((wbresp->result != WINBINDD_OK) ||
	    !dom_sid_parse(wbresp->data.sid.sid, &state->sid)) {
		tevent_req_error(req, ENOENT);
		return;
	}
	tevent_req_done(req);
}

static int wbc_id_to_sid_recv(struct tevent_req *req, struct dom_sid *sid)
{
	struct wbc_id_to_sid_state *state = tevent_req_data(
		req, struct wbc_id_to_sid_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	sid_copy(sid, &state->sid);
	return 0;
}

struct wbc_ids_to_sids_state {
	struct tevent_context *ev;
	int fd;
	struct id_map *ids;
	uint32_t count;
	uint32_t idx;
};

static void wbc_ids_to_sids_done(struct tevent_req *subreq);

static struct tevent_req *wbc_ids_to_sids_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	int fd, struct id_map *ids, uint32_t count)
{
	struct tevent_req *req, *subreq;
	struct wbc_ids_to_sids_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wbc_ids_to_sids_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fd = fd;
	state->ids = ids;
	state->count = count;

	if (count == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = wbc_id_to_sid_send(state, state->ev, state->fd,
				    &state->ids[state->idx].xid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wbc_ids_to_sids_done, req);
	return req;
}

static void wbc_ids_to_sids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wbc_ids_to_sids_state *state = tevent_req_data(
		req, struct wbc_ids_to_sids_state);
	struct id_map *id;
	struct dom_sid sid;
	int ret;

	ret = wbc_id_to_sid_recv(subreq, &sid);
	TALLOC_FREE(subreq);

	id = &state->ids[state->idx];
	if (ret == 0) {
		id->status = ID_MAPPED;
		id->sid = dom_sid_dup(state->ids, &sid);
		if (id->sid == NULL) {
			tevent_req_error(req, ENOMEM);
			return;
		}
	} else {
		id->status = ID_UNMAPPED;
		id->sid = NULL;
	}

	state->idx += 1;
	if (state->idx == state->count) {
		tevent_req_done(req);
		return;
	}

	subreq = wbc_id_to_sid_send(state, state->ev, state->fd,
				    &state->ids[state->idx].xid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wbc_ids_to_sids_done, req);
}

static int wbc_ids_to_sids_recv(struct tevent_req *req)
{
	int err;
	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

NTSTATUS wbc_xids_to_sids(struct tevent_context *ev, struct id_map *ids,
			  uint32_t count)
{
	struct tevent_req *req;
	NTSTATUS status;
	bool polled;
	int ret, fd;

	DEBUG(5, ("wbc_xids_to_sids called: %u ids\n", (unsigned)count));

	fd = winbindd_pipe_sock();
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(10, ("winbindd_pipe_sock returned %s\n",
			   strerror(errno)));
		return status;
	}

	req = wbc_ids_to_sids_send(ev, ev, fd, ids, count);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	polled = tevent_req_poll(req, ev);
	if (!polled) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(10, ("tevent_req_poll returned %s\n",
			   strerror(errno)));
		goto done;
	}

	ret = wbc_ids_to_sids_recv(req);
	TALLOC_FREE(req);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(ret);
		DEBUG(10, ("tevent_req_poll returned %s\n",
			   strerror(ret)));
	} else {
		status = NT_STATUS_OK;
	}

done:
	close(fd);
	return status;
}
