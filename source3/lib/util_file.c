/*
 * Unix SMB/CIFS implementation.
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "lib/util_file.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/sys_popen.h"
#include "lib/async_req/async_sock.h"
#include "lib/util/tevent_unix.h"

struct file_ploadv_state {
	struct tevent_context *ev;
	size_t maxsize;
	int fd;
	uint8_t *buf;
};

static int file_ploadv_state_destructor(struct file_ploadv_state *s);
static void file_ploadv_readable(struct tevent_req *subreq);

struct tevent_req *file_ploadv_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   char * const argl[], size_t maxsize)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct file_ploadv_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct file_ploadv_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->maxsize = maxsize;

	state->fd = sys_popenv(argl);
	if (state->fd == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state, file_ploadv_state_destructor);

	subreq = wait_for_read_send(state, state->ev, state->fd, false);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, file_ploadv_readable, req);
	return req;
}

static int file_ploadv_state_destructor(struct file_ploadv_state *s)
{
	if (s->fd != -1) {
		sys_pclose(s->fd);
		s->fd = -1;
	}
	return 0;
}

static void file_ploadv_readable(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct file_ploadv_state *state = tevent_req_data(
		req, struct file_ploadv_state);
	uint8_t buf[1024];
	uint8_t *tmp;
	ssize_t nread;
	size_t bufsize;
	int err;
	bool ok;

	ok = wait_for_read_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, err);
		return;
	}

	nread = sys_read(state->fd, buf, sizeof(buf));
	if (nread == -1) {
		tevent_req_error(req, errno);
		return;
	}
	if (nread == 0) {
		tevent_req_done(req);
		return;
	}

	bufsize = talloc_get_size(state->buf);

	if (((bufsize + nread) < bufsize) ||
	    ((bufsize + nread + 1) < bufsize)) {
		/* overflow */
		tevent_req_error(req, EMSGSIZE);
		return;
	}

	if ((state->maxsize != 0) && ((bufsize + nread) > state->maxsize)) {
		tevent_req_error(req, EMSGSIZE);
		return;
	}

	tmp = talloc_realloc(state, state->buf, uint8_t, bufsize + nread + 1);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	state->buf = tmp;

	memcpy(state->buf + bufsize, buf, nread);
	state->buf[bufsize+nread] = '\0';

	subreq = wait_for_read_send(state, state->ev, state->fd, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, file_ploadv_readable, req);
}

int file_ploadv_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		    uint8_t **buf)
{
	struct file_ploadv_state *state = tevent_req_data(
		req, struct file_ploadv_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*buf = talloc_move(mem_ctx, &state->buf);

	tevent_req_received(req);

	return 0;
}


/**
 Load a pipe into memory and return an array of pointers to lines in the data
 must be freed with TALLOC_FREE.
**/

char **file_lines_ploadv(TALLOC_CTX *mem_ctx,
			char * const argl[],
			int *numlines)
{
	char *p = NULL;
	size_t size;

	p = file_ploadv(argl, &size);
	if (!p) {
		return NULL;
	}

	return file_lines_parse(p, size, numlines, mem_ctx);
}
