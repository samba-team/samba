/*
   CTDB client code

   Copyright (C) Amitay Isaacs  2015

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
#include "system/network.h"
#include "system/filesys.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "common/reqid.h"
#include "common/srvid.h"
#include "common/comm.h"
#include "common/logging.h"

#include "lib/util/tevent_unix.h"
#include "lib/util/debug.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"

#include "client/client_private.h"
#include "client/client.h"

static int ctdb_client_connect(struct ctdb_client_context *client,
			       struct tevent_context *ev,
			       const char *sockpath);

static int ctdb_client_context_destructor(struct ctdb_client_context *client);

int ctdb_client_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     const char *sockpath, struct ctdb_client_context **out)
{
	struct ctdb_client_context *client;
	int ret;

	client = talloc_zero(mem_ctx, struct ctdb_client_context);
	if (client == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " memory allocation error\n"));
		return ENOMEM;
	}

	ret = reqid_init(client, INT_MAX-200, &client->idr);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("reqid_init() failed, ret=%d\n", ret));
		talloc_free(client);
		return ret;
	}

	ret = srvid_init(client, &client->srv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("srvid_init() failed, ret=%d\n", ret));
		talloc_free(client);
		return ret;
	}

	client->fd = -1;
	client->pnn = CTDB_UNKNOWN_PNN;

	ret = ctdb_client_connect(client, ev, sockpath);
	if (ret != 0) {
		talloc_free(client);
		return ret;
	}

	talloc_set_destructor(client, ctdb_client_context_destructor);

	*out = client;
	return 0;
}

static int ctdb_client_context_destructor(struct ctdb_client_context *client)
{
	if (client->fd != -1) {
		close(client->fd);
		client->fd = -1;
	}
	return 0;
}

static void client_read_handler(uint8_t *buf, size_t buflen,
				void *private_data);
static void client_dead_handler(void *private_data);

static int ctdb_client_connect(struct ctdb_client_context *client,
			       struct tevent_context *ev, const char *sockpath)
{
	struct sockaddr_un addr;
	size_t len;
	int fd, ret;

	if (sockpath == NULL) {
		DEBUG(DEBUG_ERR, ("socket path cannot be NULL\n"));
		return EINVAL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if (len != strlen(sockpath)) {
		DEBUG(DEBUG_ERR, ("socket path too long, len=%zu\n",
				  strlen(sockpath)));
		return ENAMETOOLONG;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		ret = errno;
		DEBUG(DEBUG_ERR, ("socket() failed, errno=%d\n", ret));
		return ret;
	}

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		ret = errno;
		DEBUG(DEBUG_ERR, ("connect() failed, errno=%d\n", ret));
		close(fd);
		return ret;
	}
	client->fd = fd;

	ret = comm_setup(client, ev, fd, client_read_handler, client,
			 client_dead_handler, client, &client->comm);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("comm_setup() failed, ret=%d\n", ret));
		close(fd);
		client->fd = -1;
		return ret;
	}

	ret = ctdb_ctrl_get_pnn(client, ev, client, CTDB_CURRENT_NODE,
				tevent_timeval_zero(), &client->pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("failed to get current node pnn\n"));
		close(fd);
		client->fd = -1;
		TALLOC_FREE(client->comm);
		return ret;
	}

	return 0;
}

static void client_read_handler(uint8_t *buf, size_t buflen,
				void *private_data)
{
	struct ctdb_client_context *client = talloc_get_type_abort(
		private_data, struct ctdb_client_context);
	struct ctdb_req_header hdr;
	int ret;

	ret = ctdb_req_header_pull(discard_const(buf), buflen, &hdr);
	if (ret != 0) {
		DEBUG(DEBUG_WARNING, ("invalid header, ret=%d\n", ret));
		return;
	}

	if (buflen != hdr.length) {
		DEBUG(DEBUG_WARNING, ("packet size mismatch %zu != %d\n",
				      buflen, hdr.length));
		return;
	}

	ret = ctdb_req_header_verify(&hdr, 0);
	if (ret != 0) {
		DEBUG(DEBUG_WARNING, ("invalid header, ret=%d\n", ret));
		return;
	}

	switch (hdr.operation) {
	case CTDB_REPLY_CALL:
		ctdb_client_reply_call(client, buf, buflen, hdr.reqid);
		break;

	case CTDB_REQ_MESSAGE:
		ctdb_client_req_message(client, buf, buflen, hdr.reqid);
		break;

	case CTDB_REPLY_CONTROL:
		ctdb_client_reply_control(client, buf, buflen, hdr.reqid);
		break;

	default:
		break;
	}
}

static void client_dead_handler(void *private_data)
{
	struct ctdb_client_context *client = talloc_get_type_abort(
		private_data, struct ctdb_client_context);
	ctdb_client_callback_func_t callback = client->callback;
	void *callback_data = client->private_data;

	talloc_free(client);
	if (callback != NULL) {
		callback(callback_data);
		return;
	}

	DEBUG(DEBUG_NOTICE, ("connection to daemon closed, exiting\n"));
	exit(1);
}

void ctdb_client_set_disconnect_callback(struct ctdb_client_context *client,
					 ctdb_client_callback_func_t callback,
					 void *private_data)
{
	client->callback = callback;
	client->private_data = private_data;
}

uint32_t ctdb_client_pnn(struct ctdb_client_context *client)
{
	return client->pnn;
}

void ctdb_client_wait(struct tevent_context *ev, bool *done)
{
	while (! (*done)) {
		tevent_loop_once(ev);
	}
}

struct ctdb_recovery_wait_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
};

static void ctdb_recovery_wait_retry(struct tevent_req *subreq);

struct tevent_req *ctdb_recovery_wait_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client)
{
	struct tevent_req *req, *subreq;
	struct ctdb_recovery_wait_state *state;
	int recmode;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_recovery_wait_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;

	ret = ctdb_ctrl_get_recmode(client, ev, client, client->pnn,
				    tevent_timeval_zero(), &recmode);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	if (recmode == CTDB_RECOVERY_NORMAL) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_recovery_wait_retry, req);

	return req;
}

static void ctdb_recovery_wait_retry(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_recovery_wait_state *state = tevent_req_data(
		req, struct ctdb_recovery_wait_state);
	int ret, recmode;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	ret = ctdb_ctrl_get_recmode(state, state->ev, state->client,
				    ctdb_client_pnn(state->client),
				    tevent_timeval_zero(), &recmode);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	if (recmode == CTDB_RECOVERY_NORMAL) {
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_recovery_wait_retry, req);
}

bool ctdb_recovery_wait_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}
