/*
   A client based on unix domain socket

   Copyright (C) Amitay Isaacs  2017

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
#include "system/filesys.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

#include "common/logging.h"
#include "common/reqid.h"
#include "common/comm.h"
#include "common/sock_client.h"

struct sock_client_context {
	struct sock_client_proto_funcs *funcs;
	void *private_data;

	void (*disconnect_callback)(void *private_data);
	void *disconnect_data;

	int fd;
	struct comm_context *comm;
	struct reqid_context *idr;
};

/*
 * connect to a unix domain socket
 */

static int socket_connect(const char *sockpath)
{
	struct sockaddr_un addr;
	size_t len;
	int fd, ret;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		D_ERR("socket path too long: %s\n", sockpath);
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		D_ERR("socket create failed - %s\n", sockpath);
		return -1;
	}

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		D_ERR("socket connect failed - %s\n", sockpath);
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Socket client
 */

static int sock_client_context_destructor(struct sock_client_context *sockc);
static void sock_client_read_handler(uint8_t *buf, size_t buflen,
				     void *private_data);
static void sock_client_dead_handler(void *private_data);

static void sock_client_msg_reply(struct sock_client_context *sockc,
				  uint8_t *buf, size_t buflen);

int sock_client_setup(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      const char *sockpath,
		      struct sock_client_proto_funcs *funcs,
		      void *private_data,
		      struct sock_client_context **result)
{
	struct sock_client_context *sockc;
	int ret;

	if (sockpath == NULL) {
		return EINVAL;
	}

	if (funcs == NULL || funcs->request_push == NULL ||
	    funcs->reply_pull == NULL || funcs->reply_reqid == NULL) {
		return EINVAL;
	}

	sockc = talloc_zero(mem_ctx, struct sock_client_context);
	if (sockc == NULL) {
		return ENOMEM;
	}

	sockc->funcs = funcs;
	sockc->private_data = private_data;

	sockc->fd = socket_connect(sockpath);
	if (sockc->fd == -1) {
		talloc_free(sockc);
		return EIO;
	}

	ret = comm_setup(sockc, ev, sockc->fd,
			 sock_client_read_handler, sockc,
			 sock_client_dead_handler, sockc,
			 &sockc->comm);
	if (ret != 0) {
		D_ERR("comm_setup() failed, ret=%d\n", ret);
		close(sockc->fd);
		talloc_free(sockc);
		return ret;
	}

	ret = reqid_init(sockc, INT_MAX-200, &sockc->idr);
	if (ret != 0) {
		D_ERR("reqid_init() failed, ret=%d\n", ret);
		close(sockc->fd);
		talloc_free(sockc);
		return ret;
	}

	talloc_set_destructor(sockc, sock_client_context_destructor);

	*result = sockc;
	return 0;
}

static int sock_client_context_destructor(struct sock_client_context *sockc)
{
	TALLOC_FREE(sockc->comm);
	if (sockc->fd != -1) {
		close(sockc->fd);
		sockc->fd = -1;
	}
	return 0;
}


static void sock_client_read_handler(uint8_t *buf, size_t buflen,
				     void *private_data)
{
	struct sock_client_context *sockc = talloc_get_type_abort(
		private_data, struct sock_client_context);

	sock_client_msg_reply(sockc, buf, buflen);
}

static void sock_client_dead_handler(void *private_data)
{
	struct sock_client_context *sockc = talloc_get_type_abort(
		private_data, struct sock_client_context);

	if (sockc->disconnect_callback != NULL) {
		sockc->disconnect_callback(sockc->disconnect_data);
		talloc_free(sockc);
		return;
	}

	D_NOTICE("connection to daemon closed, exiting\n");
	exit(1);
}

void sock_client_set_disconnect_callback(struct sock_client_context *sockc,
					 sock_client_callback_func_t callback,
					 void *private_data)
{
	sockc->disconnect_callback = callback;
	sockc->disconnect_data = private_data;
}


struct sock_client_msg_state {
	struct sock_client_context *sockc;
	uint32_t reqid;
	struct tevent_req *req;
	void *reply;
};

static int sock_client_msg_state_destructor(
				struct sock_client_msg_state *state);
static void sock_client_msg_done(struct tevent_req *subreq);

struct tevent_req *sock_client_msg_send(TALLOC_CTX *mem_ctx,
				        struct tevent_context *ev,
					struct sock_client_context *sockc,
					struct timeval timeout,
					void *request)
{
	struct tevent_req *req, *subreq;
	struct sock_client_msg_state *state;
	uint8_t *buf;
	size_t buflen;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct sock_client_msg_state);
	if (req == NULL) {
		return NULL;
	}

	state->sockc = sockc;

	state->reqid = reqid_new(sockc->idr, state);
	if (state->reqid == REQID_INVALID) {
		talloc_free(req);
		return NULL;
	}

	state->req = req;

	talloc_set_destructor(state, sock_client_msg_state_destructor);

	ret = sockc->funcs->request_push(request, state->reqid, state,
					 &buf, &buflen, sockc->private_data);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	subreq = comm_write_send(state, ev, sockc->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, sock_client_msg_done, req);

	if (! timeval_is_zero(&timeout)) {
		if (!tevent_req_set_endtime(req, ev, timeout)) {
			return tevent_req_post(req, ev);
		}
	}

	return req;
}

static int sock_client_msg_state_destructor(
				struct sock_client_msg_state *state)
{
	reqid_remove(state->sockc->idr, state->reqid);
	return 0;
}

static void sock_client_msg_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	/* wait for the reply or timeout */
}

static void sock_client_msg_reply(struct sock_client_context *sockc,
				  uint8_t *buf, size_t buflen)
{
	struct sock_client_msg_state *state;
	uint32_t reqid;
	int ret;

	ret = sockc->funcs->reply_reqid(buf, buflen, &reqid,
					sockc->private_data);
	if (ret != 0) {
		D_WARNING("Invalid packet received, ret=%d\n", ret);
		return;
	}

	state = reqid_find(sockc->idr, reqid, struct sock_client_msg_state);
	if (state == NULL) {
		return;
	}

	if (reqid != state->reqid) {
		return;
	}

	ret = sockc->funcs->reply_pull(buf, buflen, state, &state->reply,
				       sockc->private_data);
	if (ret != 0) {
		tevent_req_error(state->req, ret);
		return;
	}

	tevent_req_done(state->req);
}

bool sock_client_msg_recv(struct tevent_req *req, int *perr,
			  TALLOC_CTX *mem_ctx, void *reply)
{
	struct sock_client_msg_state *state = tevent_req_data(
		req, struct sock_client_msg_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*(void **)reply = talloc_steal(mem_ctx, state->reply);
	}

	return true;
}
