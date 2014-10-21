/*
   Unix SMB/CIFS implementation.
   Samba3 ctdb connection handling
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
#include "lib/util/tevent_unix.h"
#include "ctdb_conn.h"

#include <tdb.h>

#include <ctdb_protocol.h>

#include "lib/async_req/async_sock.h"

struct ctdb_conn {
	int fd;
	struct tevent_queue *outqueue;
};

struct ctdb_conn_init_state {
	struct sockaddr_un addr;
	struct ctdb_conn *conn;
};

/*
 * use the callbacks of async_connect_send to make sure
 * we are connecting to CTDB as root
 */
static void before_connect_cb(void *private_data) {
	become_root();
}

static void after_connect_cb(void *private_data) {
	unbecome_root();
}

static void ctdb_conn_init_done(struct tevent_req *subreq);
static int ctdb_conn_destructor(struct ctdb_conn *conn);

struct tevent_req *ctdb_conn_init_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       const char *sock)
{
	struct tevent_req *req, *subreq;
	struct ctdb_conn_init_state *state;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_conn_init_state);
	if (req == NULL) {
		return NULL;
	}

	if (!lp_clustering()) {
		tevent_req_error(req, ENOSYS);
		return tevent_req_post(req, ev);
	}

	if (strlen(sock) >= sizeof(state->addr.sun_path)) {
		tevent_req_error(req, ENAMETOOLONG);
		return tevent_req_post(req, ev);
	}

	state->conn = talloc(state, struct ctdb_conn);
	if (tevent_req_nomem(state->conn, req)) {
		return tevent_req_post(req, ev);
	}

	state->conn->outqueue = tevent_queue_create(
		state->conn, "ctdb outqueue");
	if (tevent_req_nomem(state->conn->outqueue, req)) {
		return tevent_req_post(req, ev);
	}

	state->conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (state->conn->fd == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state->conn, ctdb_conn_destructor);

	state->addr.sun_family = AF_UNIX;
	strncpy(state->addr.sun_path, sock, sizeof(state->addr.sun_path));

	subreq = async_connect_send(state, ev, state->conn->fd,
				    (struct sockaddr *)&state->addr,
				    sizeof(state->addr), before_connect_cb,
				    after_connect_cb, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_conn_init_done, req);
	return req;
}

static int ctdb_conn_destructor(struct ctdb_conn *c)
{
	if (c->fd != -1) {
		close(c->fd);
		c->fd = -1;
	}
	return 0;
}

static void ctdb_conn_init_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret, err;

	ret = async_connect_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

int ctdb_conn_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			struct ctdb_conn **pconn)
{
	struct ctdb_conn_init_state *state = tevent_req_data(
		req, struct ctdb_conn_init_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*pconn = talloc_move(mem_ctx, &state->conn);

	return 0;
}

struct ctdb_conn_control_state {
	struct tevent_context *ev;
	struct ctdb_conn *conn;
	struct ctdb_req_control req;
	struct iovec iov[2];
	struct ctdb_reply_control *reply;
};

static void ctdb_conn_control_written(struct tevent_req *subreq);
static void ctdb_conn_control_done(struct tevent_req *subreq);
static ssize_t ctdb_packet_more(uint8_t *buf, size_t buflen, void *p);

struct tevent_req *ctdb_conn_control_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_conn *conn,
					  uint32_t vnn, uint32_t opcode,
					  uint64_t srvid, uint32_t flags,
					  uint8_t *data, size_t datalen)
{
	struct tevent_req *req, *subreq;
	struct ctdb_conn_control_state *state;
	struct ctdb_req_header *hdr;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_conn_control_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->conn = conn;

	hdr = &state->req.hdr;
	hdr->length = offsetof(struct ctdb_req_control, data) + datalen;
	hdr->ctdb_magic    = CTDB_MAGIC;
	hdr->ctdb_version  = CTDB_PROTOCOL;
	hdr->operation     = CTDB_REQ_CONTROL;
	hdr->reqid         = 1; /* FIXME */
	hdr->destnode      = vnn;
	state->req.opcode  = opcode;
	state->req.srvid   = srvid;
	state->req.datalen = datalen;
	state->req.flags   = flags;

	state->iov[0].iov_base = &state->req;
	state->iov[0].iov_len = offsetof(struct ctdb_req_control, data);
	state->iov[1].iov_base = data;
	state->iov[1].iov_len = datalen;

	subreq = writev_send(state, ev, conn->outqueue, conn->fd, false,
			     state->iov, 2);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_conn_control_written, req);
	return req;
}

static void ctdb_conn_control_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_control_state *state = tevent_req_data(
		req, struct ctdb_conn_control_state);
	ssize_t written;
	int err;

	written = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (written == -1) {
		tevent_req_error(req, err);
		return;
	}
	subreq = read_packet_send(
		state, state->ev, state->conn->fd, sizeof(uint32_t),
		ctdb_packet_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_control_done, req);
}

static ssize_t ctdb_packet_more(uint8_t *buf, size_t buflen, void *p)
{
	uint32_t len;

	if (buflen > sizeof(uint32_t)) {
		/* Been here, done */
		return 0;
	}
	memcpy(&len, buf, sizeof(len));

	if (len < sizeof(uint32_t)) {
		return -1;
	}

	return (len - sizeof(uint32_t));
}

static void ctdb_conn_control_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_control_state *state = tevent_req_data(
		req, struct ctdb_conn_control_state);
	ssize_t nread;
	uint8_t *buf;
	int err;

	nread = read_packet_recv(subreq, state, &buf, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		tevent_req_error(req, err);
		return;
	}
	state->reply = (struct ctdb_reply_control *)buf;
	tevent_req_done(req);
}

int ctdb_conn_control_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct ctdb_reply_control **preply)
{
	struct ctdb_conn_control_state *state = tevent_req_data(
		req, struct ctdb_conn_control_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	if (preply != NULL) {
		*preply = talloc_move(mem_ctx, &state->reply);
	}
	return 0;
}

struct ctdb_conn_msg_write_state {
	struct ctdb_req_message ctdb_msg;
	struct iovec iov[2];
};

static void ctdb_conn_msg_write_done(struct tevent_req *subreq);

struct tevent_req *ctdb_conn_msg_write_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_conn *conn,
					    uint32_t vnn, uint64_t srvid,
					    uint8_t *msg, size_t msg_len)
{
	struct tevent_req *req, *subreq;
	struct ctdb_conn_msg_write_state *state;
	struct ctdb_req_header *h;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_conn_msg_write_state);
	if (req == NULL) {
		return NULL;
	}

	h = &state->ctdb_msg.hdr;

	h->length = offsetof(struct ctdb_req_message, data) + msg_len;
	h->ctdb_magic = CTDB_MAGIC;
	h->ctdb_version = CTDB_PROTOCOL;
	h->generation = 1;
	h->operation  = CTDB_REQ_MESSAGE;
	h->destnode   = vnn;
	h->srcnode    = CTDB_CURRENT_NODE;
	h->reqid      = 0;
	state->ctdb_msg.srvid   = srvid;
	state->ctdb_msg.datalen = msg_len;

	state->iov[0].iov_base = &state->ctdb_msg;
	state->iov[0].iov_len = offsetof(struct ctdb_req_message, data);
	state->iov[1].iov_base = msg;
	state->iov[1].iov_len = msg_len;

	subreq = writev_send(state, ev, conn->outqueue, conn->fd, false,
			     state->iov, 2);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_conn_msg_write_done, req);
	return req;
}

static void ctdb_conn_msg_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	ssize_t written;
	int err;

	written = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (written == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

int ctdb_conn_msg_write_recv(struct tevent_req *req)
{
	int err;
	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

struct ctdb_msg_channel {
	struct ctdb_conn *conn;
};

struct ctdb_msg_channel_init_state {
	struct tevent_context *ev;
	struct ctdb_conn *conn;
	uint64_t srvid;
	struct ctdb_msg_channel *channel;
};

static void ctdb_msg_channel_init_connected(struct tevent_req *subreq);
static void ctdb_msg_channel_init_registered_srvid(struct tevent_req *subreq);

struct tevent_req *ctdb_msg_channel_init_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *sock, uint64_t srvid)
{
	struct tevent_req *req, *subreq;
	struct ctdb_msg_channel_init_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_msg_channel_init_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->srvid = srvid;

	subreq = ctdb_conn_init_send(state, ev, sock);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_msg_channel_init_connected, req);
	return req;
}

static void ctdb_msg_channel_init_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_msg_channel_init_state *state = tevent_req_data(
		req, struct ctdb_msg_channel_init_state);
	int ret;

	ret = ctdb_conn_init_recv(subreq, state, &state->conn);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	subreq = ctdb_conn_control_send(state, state->ev, state->conn,
					CTDB_CURRENT_NODE,
					CTDB_CONTROL_REGISTER_SRVID,
					state->srvid, 0, NULL, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(
		subreq, ctdb_msg_channel_init_registered_srvid,	req);
}

static void ctdb_msg_channel_init_registered_srvid(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_msg_channel_init_state *state = tevent_req_data(
		req, struct ctdb_msg_channel_init_state);
	struct ctdb_reply_control *reply;
	int ret;

	ret = ctdb_conn_control_recv(subreq, talloc_tos(), &reply);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	if (reply->status != 0) {
		tevent_req_error(req, EIO);
		return;
	}
	state->channel = talloc(state, struct ctdb_msg_channel);
	if (tevent_req_nomem(state->channel, req)) {
		return;
	}
	state->channel->conn = talloc_move(state->channel, &state->conn);
	tevent_req_done(req);
}

int ctdb_msg_channel_init_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       struct ctdb_msg_channel **pchannel)
{
	struct ctdb_msg_channel_init_state *state = tevent_req_data(
		req, struct ctdb_msg_channel_init_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*pchannel = talloc_move(mem_ctx, &state->channel);
	return 0;
}

struct ctdb_msg_read_state {
	size_t buflen;
	uint8_t *buf;
};

static void ctdb_msg_channel_got_msg(struct tevent_req *subreq);

struct tevent_req *ctdb_msg_read_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct ctdb_msg_channel *channel)
{
	struct tevent_req *req, *subreq;
	struct ctdb_msg_read_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_msg_read_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = read_packet_send(state, ev, channel->conn->fd,
		sizeof(uint32_t), ctdb_packet_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_msg_channel_got_msg, req);
	return req;
}

static void ctdb_msg_channel_got_msg(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_msg_read_state *state = tevent_req_data(
		req, struct ctdb_msg_read_state);
	ssize_t nread;
	uint8_t *buf;
	int err;

	nread = read_packet_recv(subreq, state, &buf, &err);
	if (nread == -1) {
		tevent_req_error(req, err);
		return;
	}
	state->buflen = nread;
	state->buf = buf;
	tevent_req_done(req);
}

int ctdb_msg_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		       uint8_t **pmsg, size_t *pmsg_len)
{
	struct ctdb_msg_read_state *state = tevent_req_data(
		req, struct ctdb_msg_read_state);
	struct ctdb_req_header *hdr;
	struct ctdb_req_message *msg;
	uint8_t *buf;
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}

	hdr = (struct ctdb_req_header *)state->buf;
	if (hdr->length != state->buflen) {
		DEBUG(10, ("Got invalid header length\n"));
		return EIO;
	}
	if (hdr->operation != CTDB_REQ_MESSAGE) {
		DEBUG(10, ("Expected %d (CTDB_REQ_MESSAGE), got %d\n",
			   CTDB_REQ_MESSAGE, (int)hdr->operation));
		return EIO;
	}
	if (hdr->length < offsetof(struct ctdb_req_message, data)) {
		DEBUG(10, ("Got short msg, len=%d\n", (int)hdr->length));
		return EIO;
	}

	msg = (struct ctdb_req_message *)hdr;
	if (msg->datalen >
	    hdr->length - offsetof(struct ctdb_req_message, data)) {
		DEBUG(10, ("Got invalid datalen %d\n", (int)msg->datalen));
		return EIO;
	}

	buf = (uint8_t *)talloc_memdup(mem_ctx, msg->data, msg->datalen);
	if (buf == NULL) {
		return ENOMEM;
	}
	*pmsg = buf;
	*pmsg_len = msg->datalen;
	return 0;
}
