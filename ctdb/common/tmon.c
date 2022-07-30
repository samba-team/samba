/*
   Trivial FD monitoring

   Copyright (C) Martin Schwenke & Amitay Isaacs, DataDirect Networks  2022

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include <ctype.h>

#include "lib/util/blocking.h"
#include "lib/util/sys_rw.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/util.h"
#include "lib/util/smb_strtox.h"

#include "lib/async_req/async_sock.h"

#include "common/tmon.h"


enum tmon_message_type {
	TMON_MSG_EXIT = 1,
	TMON_MSG_ERRNO,
	TMON_MSG_PING,
	TMON_MSG_ASCII,
	TMON_MSG_CUSTOM,
};

struct tmon_pkt {
	enum tmon_message_type type;
	uint16_t val;
};

struct tmon_buf {
	uint8_t data[4];
};

static void tmon_packet_push(struct tmon_pkt *pkt,
			     struct tmon_buf *buf)
{
	uint16_t type_n, val_n;

	type_n = htons(pkt->type);
	val_n = htons(pkt->val);
	memcpy(&buf->data[0], &type_n, 2);
	memcpy(&buf->data[2], &val_n, 2);
}

static void tmon_packet_pull(struct tmon_buf *buf,
			     struct tmon_pkt *pkt)
{
	uint16_t type_n, val_n;

	memcpy(&type_n, &buf->data[0], 2);
	memcpy(&val_n, &buf->data[2], 2);

	pkt->type = ntohs(type_n);
	pkt->val = ntohs(val_n);
}

static int tmon_packet_write(int fd, struct tmon_pkt *pkt)
{
	struct tmon_buf buf;
	ssize_t n;

	tmon_packet_push(pkt, &buf);

	n = sys_write(fd, &buf.data[0], sizeof(buf.data));
	if (n == -1) {
		return errno;
	}
	return 0;
}

bool tmon_set_exit(struct tmon_pkt *pkt)
{
	*pkt = (struct tmon_pkt) {
		.type = TMON_MSG_EXIT,
	};

	return true;
}

bool tmon_set_errno(struct tmon_pkt *pkt, int err)
{
	if (err <= 0 || err > UINT16_MAX) {
		return false;
	}

	*pkt = (struct tmon_pkt) {
		.type = TMON_MSG_ERRNO,
		.val = (uint16_t)err,
	};

	return true;
}

bool tmon_set_ping(struct tmon_pkt *pkt)
{
	*pkt = (struct tmon_pkt) {
		.type = TMON_MSG_PING,
	};

	return true;
}

bool tmon_set_ascii(struct tmon_pkt *pkt, char c)
{
	if (!isascii(c)) {
		return false;
	}

	*pkt = (struct tmon_pkt) {
		.type = TMON_MSG_ASCII,
		.val = (uint16_t)c,
	};

	return true;
}

bool tmon_set_custom(struct tmon_pkt *pkt, uint16_t val)
{
	*pkt = (struct tmon_pkt) {
		.type = TMON_MSG_CUSTOM,
		.val = val,
	};

	return true;
}

static bool tmon_parse_exit(struct tmon_pkt *pkt)
{
	if (pkt->type != TMON_MSG_EXIT) {
		return false;
	}
	if (pkt->val != 0) {
		return false;
	}

	return true;
}

static bool tmon_parse_errno(struct tmon_pkt *pkt, int *err)
{
	if (pkt->type != TMON_MSG_ERRNO) {
		return false;
	}
	*err= (int)pkt->val;

	return true;
}

bool tmon_parse_ping(struct tmon_pkt *pkt)
{
	if (pkt->type != TMON_MSG_PING) {
		return false;
	}
	if (pkt->val != 0) {
		return false;
	}

	return true;
}

bool tmon_parse_ascii(struct tmon_pkt *pkt, char *c)
{
	if (pkt->type != TMON_MSG_ASCII) {
		return false;
	}
	if (!isascii((int)pkt->val)) {
		return false;
	}
	*c = (char)pkt->val;

	return true;
}

bool tmon_parse_custom(struct tmon_pkt *pkt, uint16_t *val)
{
	if (pkt->type != TMON_MSG_CUSTOM) {
		return false;
	}
	*val = pkt->val;

	return true;
}

struct tmon_state {
	int fd;
	int direction;
	struct tevent_context *ev;
	bool monitor_close;
	unsigned long write_interval;
	unsigned long read_timeout;
	struct tmon_actions actions;
	struct tevent_timer *timer;
	void *private_data;
};

static void tmon_readable(struct tevent_req *subreq);
static bool tmon_set_timeout(struct tevent_req *req,
			     struct tevent_context *ev);
static void tmon_timedout(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval now,
			  void *private_data);
static void tmon_write_loop(struct tevent_req *subreq);

struct tevent_req *tmon_send(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev,
			     int fd,
			     int direction,
			     unsigned long read_timeout,
			     unsigned long write_interval,
			     struct tmon_actions *actions,
			     void *private_data)
{
	struct tevent_req *req, *subreq;
	struct tmon_state *state;
	bool status;

	req = tevent_req_create(mem_ctx, &state, struct tmon_state);
	if (req == NULL) {
		return NULL;
	}

	if (actions != NULL) {
		/* If FD isn't readable then read actions are invalid */
		if (!(direction & TMON_FD_READ) &&
		    (actions->timeout_callback != NULL ||
		     actions->read_callback != NULL ||
		     read_timeout != 0)) {
			tevent_req_error(req, EINVAL);
			return tevent_req_post(req, ev);
		}
		/* If FD isn't writeable then write actions are invalid */
		if (!(direction & TMON_FD_WRITE) &&
		    (actions->write_callback != NULL ||
		     write_interval != 0)) {
			tevent_req_error(req, EINVAL);
			return tevent_req_post(req, ev);
		}
		/* Can't specify write interval without a callback */
		if (state->write_interval != 0 &&
		    state->actions.write_callback == NULL) {
			tevent_req_error(req, EINVAL);
			return tevent_req_post(req, ev);
		}
	}

	state->fd = fd;
	state->direction = direction;
	state->ev = ev;
	state->write_interval = write_interval;
	state->read_timeout = read_timeout;
	state->private_data = private_data;

	if (actions != NULL) {
		state->actions = *actions;
	}

	status = set_close_on_exec(fd);
	if (!status) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	if (direction & TMON_FD_READ) {
		subreq = wait_for_read_send(state, ev, fd, true);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, tmon_readable, req);
	}

	if (state->read_timeout != 0) {
		status = tmon_set_timeout(req, state->ev);
		if (!status) {
			tevent_req_error(req, ENOMEM);
			return tevent_req_post(req, ev);
		}
	}

	if (state->write_interval != 0) {
		subreq = tevent_wakeup_send(
			state,
			state->ev,
			tevent_timeval_current_ofs(state->write_interval, 0));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, state->ev);
		}
		tevent_req_set_callback(subreq, tmon_write_loop, req);
	}

	return req;
}

static void tmon_readable(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tmon_state *state = tevent_req_data( req, struct tmon_state);
	struct tmon_buf buf;
	struct tmon_pkt pkt;
	ssize_t nread;
	bool status;
	int err;
	int ret;

	status = wait_for_read_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (!status) {
		if (ret == EPIPE && state->actions.close_callback != NULL) {
			ret = state->actions.close_callback(state->private_data);
			if (ret == TMON_STATUS_EXIT) {
				ret = 0;
			}
		}
		if (ret == 0) {
			tevent_req_done(req);
		} else {
			tevent_req_error(req, ret);
		}
		return;
	}

	nread = sys_read(state->fd, buf.data, sizeof(buf.data));
	if (nread == -1) {
		tevent_req_error(req, errno);
		return;
	}
	if (nread == 0) {
		/* Can't happen, treat like EPIPE, above */
		tevent_req_error(req, EPIPE);
		return;
	}
	if (nread != sizeof(buf.data)) {
		tevent_req_error(req, EPROTO);
		return;
	}

	tmon_packet_pull(&buf, &pkt);

	switch (pkt.type) {
	case TMON_MSG_EXIT:
		status = tmon_parse_exit(&pkt);
		if (!status) {
			tevent_req_error(req, EPROTO);
			return;
		}
		tevent_req_done(req);
		return;
	case TMON_MSG_ERRNO:
		status = tmon_parse_errno(&pkt, &err);
		if (!status) {
			err = EPROTO;
		}
		tevent_req_error(req, err);
		return;
	default:
		break;
	}

	if (state->actions.read_callback == NULL) {
		/* Shouldn't happen, other end should not write */
		tevent_req_error(req, EIO);
		return;
	}
	ret = state->actions.read_callback(state->private_data, &pkt);
	if (ret == TMON_STATUS_EXIT) {
		tevent_req_done(req);
		return;
	}
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = wait_for_read_send(state, state->ev, state->fd, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tmon_readable, req);

	/* Reset read timeout */
	if (state->read_timeout != 0) {
		status = tmon_set_timeout(req, state->ev);
		if (!status) {
			tevent_req_error(req, ENOMEM);
			return;
		}
	}
}

static bool tmon_set_timeout(struct tevent_req *req,
			     struct tevent_context *ev)
{
	struct tmon_state *state = tevent_req_data(
		req, struct tmon_state);
	struct timeval endtime =
		tevent_timeval_current_ofs(state->read_timeout, 0);

	TALLOC_FREE(state->timer);

	state->timer = tevent_add_timer(ev, req, endtime, tmon_timedout, req);
	if (tevent_req_nomem(state->timer, req)) {
		return false;
	}

	return true;
}

static void tmon_timedout(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval now,
			  void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct tmon_state *state = tevent_req_data(req, struct tmon_state);
	int ret;

	TALLOC_FREE(state->timer);

	if (state->actions.timeout_callback != NULL) {
		ret = state->actions.timeout_callback(state->private_data);
		if (ret == TMON_STATUS_EXIT) {
			ret = 0;
		}
	} else {
		ret = ETIMEDOUT;
	}

	if (ret == 0) {
		tevent_req_done(req);
	} else {
		tevent_req_error(req, ret);
	}
}

static void tmon_write_loop(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tmon_state *state = tevent_req_data(
		req, struct tmon_state);
	struct tmon_pkt pkt;
	int ret;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!status) {
		/* Ignore error */
	}

	ret = state->actions.write_callback(state->private_data, &pkt);
	if (ret == TMON_STATUS_EXIT) {
		tevent_req_done(req);
		return;
	}
	if (ret == TMON_STATUS_SKIP) {
		goto done;
	}
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	status = tmon_write(req, &pkt);
	if (!status) {
		return;
	}

done:
	subreq = tevent_wakeup_send(
		state,
		state->ev,
		tevent_timeval_current_ofs(state->write_interval, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tmon_write_loop, req);
}

bool tmon_write(struct tevent_req *req, struct tmon_pkt *pkt)
{
	struct tmon_state *state = tevent_req_data(
		req, struct tmon_state);
	int ret;

	if (state->fd == -1) {
		return false;
	}

	if (!(state->direction & TMON_FD_WRITE)) {
		tevent_req_error(req, EINVAL);
		return false;
	}

	ret = tmon_packet_write(state->fd, pkt);
	if (ret != 0) {
		if (ret == EPIPE && state->actions.close_callback != NULL) {
			ret = state->actions.close_callback(state->private_data);
			if (ret == TMON_STATUS_EXIT) {
				ret = 0;
			}
		}

		if (ret == 0) {
			tevent_req_done(req);
		} else {
			tevent_req_error(req, ret);
		}
		state->fd = -1;
		return false;
	}

	return true;
}

bool tmon_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static int ping_writer(void *private_data, struct tmon_pkt *pkt)
{
	tmon_set_ping(pkt);

	return 0;
}

static int ping_reader(void *private_data, struct tmon_pkt *pkt)
{
	bool status;

	/* Only expect pings */
	status = tmon_parse_ping(pkt);
	if (!status) {
		return EPROTO;
	}

	return 0;
}

struct tevent_req *tmon_ping_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  int fd,
				  int direction,
				  unsigned long timeout,
				  unsigned long interval)
{
	struct tevent_req *req;
	struct tmon_actions actions = {
		.write_callback = NULL,
	};

	if ((direction & TMON_FD_WRITE) && interval != 0) {
		actions.write_callback = ping_writer;
	}
	if ((direction & TMON_FD_READ) && timeout != 0) {
		actions.read_callback = ping_reader;
	}

	req = tmon_send(mem_ctx,
			ev,
			fd,
			direction,
			timeout,
			interval,
			&actions,
			NULL);
	return req;
}

bool tmon_ping_recv(struct tevent_req *req, int *perr)
{
	bool status;

	status = tmon_recv(req, perr);

	return status;
}
