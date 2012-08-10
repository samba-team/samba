/*
   Unix SMB/CIFS implementation.
   Samba3 message channels
   Copyright (C) Volker Lendecke 2012

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
#include "msg_channel.h"
#include "ctdb_conn.h"
#include "lib/util/tevent_unix.h"

struct msg_channel {
	struct ctdb_msg_channel *ctdb_channel;
	struct messaging_context *msg;
	uint32_t msg_type;

	struct tevent_req *pending_req;
	struct tevent_context *ev;

	struct messaging_rec **msgs;
};

struct msg_channel_init_state {
	struct msg_channel *channel;
};

static void msg_channel_init_got_ctdb(struct tevent_req *subreq);
static void msg_channel_init_got_msg(struct messaging_context *msg,
			       void *priv, uint32_t msg_type,
			       struct server_id server_id, DATA_BLOB *data);
static void msg_channel_trigger(struct tevent_context *ev,
				struct tevent_immediate *im,
				void *priv);
static int msg_channel_destructor(struct msg_channel *s);

struct tevent_req *msg_channel_init_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct messaging_context *msg,
				    uint32_t msg_type)
{
	struct tevent_req *req, *subreq;
	struct msg_channel_init_state *state;
	struct server_id pid;

	req = tevent_req_create(mem_ctx, &state,
				struct msg_channel_init_state);
	if (req == NULL) {
		return NULL;
	}

	state->channel = talloc_zero(state, struct msg_channel);
	if (tevent_req_nomem(state->channel, req)) {
		return tevent_req_post(req, ev);
	}
	state->channel->msg = msg;
	state->channel->msg_type = msg_type;

	pid = messaging_server_id(msg);
	subreq = ctdb_msg_channel_init_send(state, ev, lp_ctdbd_socket(),
					    pid.pid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_channel_init_got_ctdb, req);
	return req;
}

static void msg_channel_init_got_ctdb(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_channel_init_state *state = tevent_req_data(
		req, struct msg_channel_init_state);
	struct msg_channel *s = state->channel;
	NTSTATUS status;
	int ret;

	ret = ctdb_msg_channel_init_recv(subreq, s, &s->ctdb_channel);
	TALLOC_FREE(subreq);

	if (ret == ENOSYS) {
		s->ctdb_channel = NULL;
		ret = 0;
	}

	if (tevent_req_error(req, ret)) {
		return;
	}
	status = messaging_register(s->msg, s, s->msg_type,
				    msg_channel_init_got_msg);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, map_errno_from_nt_status(status));
		return;
	}
	talloc_set_destructor(s, msg_channel_destructor);
	tevent_req_done(req);
}

static int msg_channel_destructor(struct msg_channel *s)
{
	messaging_deregister(s->msg, s->msg_type, s);
	return 0;
}

int msg_channel_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct msg_channel **pchannel)
{
	struct msg_channel_init_state *state = tevent_req_data(
		req, struct msg_channel_init_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*pchannel = talloc_move(mem_ctx, &state->channel);
	return 0;
}

int msg_channel_init(TALLOC_CTX *mem_ctx, struct messaging_context *msg,
		     uint32_t msgtype, struct msg_channel **pchannel)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	int err = ENOMEM;
	bool ok;

	ev = tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = msg_channel_init_send(frame, ev, msg, msgtype);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll(req, ev);
	if (!ok) {
		err = errno;
		goto fail;
	}
	err = msg_channel_init_recv(req, mem_ctx, pchannel);
fail:
	TALLOC_FREE(frame);
	return err;
}

static void msg_channel_init_got_msg(struct messaging_context *msg,
				     void *priv, uint32_t msg_type,
				     struct server_id server_id,
				     DATA_BLOB *data)
{
	struct msg_channel *s = talloc_get_type_abort(
		priv, struct msg_channel);
	struct messaging_rec *rec;
	struct messaging_rec **msgs;
	size_t num_msgs;
	struct tevent_immediate *im;

	rec = talloc(s, struct messaging_rec);
	if (rec == NULL) {
		goto fail;
	}
	rec->msg_version = 1;
	rec->msg_type = msg_type;
	rec->dest = server_id;
	rec->src = messaging_server_id(msg);
	rec->buf.data = (uint8_t *)talloc_memdup(rec, data->data,
						 data->length);
	if (rec->buf.data == NULL) {
		goto fail;
	}
	rec->buf.length = data->length;

	num_msgs = talloc_array_length(s->msgs);
	msgs = talloc_realloc(s, s->msgs, struct messaging_rec *, num_msgs+1);
	if (msgs == NULL) {
		goto fail;
	}
	s->msgs = msgs;
	s->msgs[num_msgs] = talloc_move(s->msgs, &rec);

	if (s->pending_req == NULL) {
		return;
	}

	im = tevent_create_immediate(s);
	if (im == NULL) {
		goto fail;
	}
	tevent_schedule_immediate(im, s->ev, msg_channel_trigger, s);
	return;
fail:
	TALLOC_FREE(rec);
}

struct msg_read_state {
	struct tevent_context *ev;
	struct tevent_req *req;
	struct msg_channel *channel;
	struct messaging_rec *rec;
};

static int msg_read_state_destructor(struct msg_read_state *s);
static void msg_read_got_ctdb(struct tevent_req *subreq);

struct tevent_req *msg_read_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct msg_channel *channel)
{
	struct tevent_req *req;
	struct tevent_immediate *im;
	struct msg_read_state *state;
	void *msg_tdb_event;
	size_t num_msgs;

	req = tevent_req_create(mem_ctx, &state, struct msg_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->req = req;
	state->channel = channel;

	if (channel->pending_req != NULL) {
		tevent_req_error(req, EBUSY);
		return tevent_req_post(req, ev);
	}
	channel->pending_req = req;
	channel->ev = ev;
	talloc_set_destructor(state, msg_read_state_destructor);

	num_msgs = talloc_array_length(channel->msgs);
	if (num_msgs != 0) {
		im = tevent_create_immediate(channel->ev);
		if (tevent_req_nomem(im, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_schedule_immediate(im, channel->ev, msg_channel_trigger,
					  channel);
		return req;
	}

	msg_tdb_event = messaging_tdb_event(state, channel->msg, ev);
	if (tevent_req_nomem(msg_tdb_event, req)) {
		return tevent_req_post(req, ev);

	}
	if (channel->ctdb_channel != NULL) {
		struct tevent_req *subreq;

		subreq = ctdb_msg_read_send(state, ev,
					    channel->ctdb_channel);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, msg_read_got_ctdb, req);
	}
	return req;
}

static int msg_read_state_destructor(struct msg_read_state *s)
{
	assert(s->channel->pending_req == s->req);
	s->channel->pending_req = NULL;
	return 0;
}

static void msg_channel_trigger(struct tevent_context *ev,
			       struct tevent_immediate *im,
			       void *priv)
{
	struct msg_channel *channel;
	struct tevent_req *req;
	struct msg_read_state *state;
	size_t num_msgs;

	channel = talloc_get_type_abort(priv, struct msg_channel);
	req = channel->pending_req;
	state = tevent_req_data(req, struct msg_read_state);

	talloc_set_destructor(state, NULL);
	msg_read_state_destructor(state);

	num_msgs = talloc_array_length(channel->msgs);
	assert(num_msgs > 0);

	state->rec = talloc_move(state, &channel->msgs[0]);

	memmove(channel->msgs, channel->msgs+1,
		sizeof(struct messaging_rec *) * (num_msgs-1));
	channel->msgs = talloc_realloc(
		channel, channel->msgs, struct messaging_rec *, num_msgs - 1);

	tevent_req_done(req);
}

static void msg_read_got_ctdb(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_read_state *state = tevent_req_data(
		req, struct msg_read_state);
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	int ret;

	ret = ctdb_msg_read_recv(subreq, talloc_tos(),
				 &blob.data, &blob.length);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	state->rec = talloc(state, struct messaging_rec);
	if (tevent_req_nomem(state->rec, req)) {
		return;
	}

	ndr_err = ndr_pull_struct_blob(
		&blob, state->rec, state->rec,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_rec);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("ndr_pull_struct_blob failed: %s\n",
			  ndr_errstr(ndr_err)));
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return;
	}
	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(messaging_rec, state->rec);
	}
	if (state->rec->msg_type == state->channel->msg_type) {
		tevent_req_done(req);
		return;
	}
	/*
	 * Got some unexpected msg type, wait for the next one
	 */
	subreq = ctdb_msg_read_send(state, state->ev,
				    state->channel->ctdb_channel);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, msg_read_got_ctdb, req);
}

int msg_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		  struct messaging_rec **prec)
{
	struct msg_read_state *state = tevent_req_data(
		req, struct msg_read_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*prec = talloc_move(mem_ctx, &state->rec);
	return 0;
}
