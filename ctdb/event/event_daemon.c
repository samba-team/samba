/*
   CTDB event daemon

   Copyright (C) Amitay Isaacs  2018

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

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"

#include "common/logging.h"
#include "common/path.h"
#include "common/sock_daemon.h"

#include "event/event_private.h"

struct event_daemon_state {
	TALLOC_CTX *mem_ctx;
	char *socket;
	char *pidfile;
	struct tevent_context *ev;
	struct event_config *config;
	struct sock_daemon_context *sockd;
	struct event_context *eventd;
};

static int event_daemon_startup(void *private_data)
{
	struct event_daemon_state *e_state = talloc_get_type_abort(
		private_data, struct event_daemon_state);
	int ret;

	ret = event_context_init(e_state,
				 e_state->ev,
				 e_state->config,
				 &e_state->eventd);
	if (ret != 0) {
		D_ERR("Failed to initialize event context\n");
		return ret;
	}

	return 0;
}

static int event_daemon_reconfigure(void *private_data)
{
	struct event_daemon_state *e_state = talloc_get_type_abort(
		private_data, struct event_daemon_state);
	int ret;

	ret = event_config_reload(e_state->config);
	if (ret != 0) {
		D_WARNING("Configuration reload failed\n");
	}

	return 0;
}

static void event_daemon_shutdown(void *private_data)
{
	struct event_daemon_state *e_state = talloc_get_type_abort(
		private_data, struct event_daemon_state);

	TALLOC_FREE(e_state->eventd);
}

static bool event_client_connect(struct sock_client_context *client,
				 pid_t pid,
				 void *private_data)
{
	struct event_daemon_state *e_state = talloc_get_type_abort(
		private_data, struct event_daemon_state);
	int ret;

	ret = eventd_client_add(e_state->eventd, client);
	if (ret != 0) {
		D_ERR("Failed to register client, ret=%d\n", ret);
		return false;
	}

	return true;
}

static void event_client_disconnect(struct sock_client_context *client,
				    void *private_data)
{
	struct event_daemon_state *e_state = talloc_get_type_abort(
		private_data, struct event_daemon_state);

	eventd_client_del(e_state->eventd, client);
}

struct event_client_state {
	struct tevent_context *ev;
	struct event_context *eventd;
	struct sock_client_context *client;
	uint8_t *buf;
	size_t buflen;
};

static void event_client_request_done(struct tevent_req *subreq);
static void event_client_reply_done(struct tevent_req *subreq);

static struct tevent_req *event_client_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct sock_client_context *client,
					    uint8_t *buf,
					    size_t buflen,
					    void *private_data)
{
	struct event_daemon_state *e_state = talloc_get_type_abort(
		private_data, struct event_daemon_state);
	struct tevent_req *req, *subreq;
	struct event_client_state *state;

	req = tevent_req_create(mem_ctx, &state, struct event_client_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->eventd = e_state->eventd;
	state->client = client;

	subreq = event_pkt_send(state, ev, e_state->eventd, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, event_client_request_done, req);

	return req;
}

static void event_client_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct event_client_state *state = tevent_req_data(
		req, struct event_client_state);
	int ret = 0;
	bool ok;

	ok = event_pkt_recv(subreq, &ret, state, &state->buf, &state->buflen);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ret);
		return;
	}

	ok = eventd_client_exists(state->eventd, state->client);
	if (!ok) {
		/* Client has already disconnected */
		talloc_free(state->buf);
		tevent_req_done(req);
		return;
	}

	subreq = sock_socket_write_send(state,
					state->ev,
					state->client,
					state->buf,
					state->buflen);
	if (tevent_req_nomem(subreq, req)) {
		talloc_free(state->buf);
		return;
	}
	tevent_req_set_callback(subreq, event_client_reply_done, req);
}

static void event_client_reply_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct event_client_state *state = tevent_req_data(
		req, struct event_client_state);
	int ret = 0;
	bool ok;

	talloc_free(state->buf);

	ok = sock_socket_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (!ok) {
		D_ERR("Sending reply failed\n");
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool event_client_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static struct {
	int pid;
	int startup_fd;
} options = {
	.pid = -1,
	.startup_fd = -1,
};

struct poptOption cmdline_options[] = {
	POPT_AUTOHELP
	{ "pid", 'P', POPT_ARG_INT, &options.pid, 0,
		"pid to wait for", "PID" },
	{ "startup-fd", 'S', POPT_ARG_INT, &options.startup_fd, 0,
		"file descriptor to notify of successful start", "FD" },
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	poptContext pc;
	struct event_daemon_state *e_state;
	struct sock_daemon_funcs daemon_funcs;
	struct sock_socket_funcs socket_funcs;
	const char *log_location = "file:";
	const char *log_level = "NOTICE";
	const char *t;
	int interactive = 0;
	int opt, ret;
	bool ok;

	pc = poptGetContext(argv[0],
			    argc,
			    argv,
			    cmdline_options,
			    0);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		D_ERR("Invalid options %s: %s\n",
		      poptBadOption(pc, 0),
		      poptStrerror(opt));
		exit(1);
	}

	t = getenv("CTDB_INTERACTIVE");
	if (t != NULL) {
		interactive = 1;
	}

	e_state = talloc_zero(NULL, struct event_daemon_state);
	if (e_state == NULL) {
		D_ERR("Memory allocation error\n");
		ret = 1;
		goto fail;
	}

	e_state->mem_ctx = talloc_new(e_state);
	if (e_state->mem_ctx == NULL) {
		D_ERR("Memory allocation error\n");
		ret = 1;
		goto fail;
	}

	e_state->socket = path_socket(e_state, "eventd");
	if (e_state->socket == NULL) {
		D_ERR("Memory allocation error\n");
		ret = 1;
		goto fail;
	}

	e_state->pidfile = path_pidfile(e_state, "eventd");
	if (e_state->pidfile == NULL) {
		D_ERR("Memory allocation error\n");
		ret = 1;
		goto fail;
	}

	ret = event_config_init(e_state, &e_state->config);
	if (ret != 0) {
		D_ERR("Failed to initialize event config\n");
		goto fail;
	}

	e_state->ev = tevent_context_init(e_state->mem_ctx);
	if (e_state->ev == NULL) {
		D_ERR("Failed to initialize tevent\n");
		ret = 1;
		goto fail;
	}

	daemon_funcs = (struct sock_daemon_funcs) {
		.startup = event_daemon_startup,
		.reconfigure = event_daemon_reconfigure,
		.shutdown = event_daemon_shutdown,
	};

	if (interactive == 0) {
		log_location = event_config_log_location(e_state->config);
		log_level = event_config_log_level(e_state->config);
	}

	ret = sock_daemon_setup(e_state->mem_ctx,
				"ctdb-eventd",
				log_location,
				log_level,
				&daemon_funcs,
				e_state,
				&e_state->sockd);
	if (ret != 0) {
		D_ERR("Failed to setup sock daemon\n");
		goto fail;
	}

	socket_funcs = (struct sock_socket_funcs) {
		.connect = event_client_connect,
		.disconnect = event_client_disconnect,
		.read_send = event_client_send,
		.read_recv = event_client_recv,
	};

	ret = sock_daemon_add_unix(e_state->sockd,
				   e_state->socket,
				   &socket_funcs,
				   e_state);
	if (ret != 0) {
		D_ERR("Failed to setup socket %s\n", e_state->socket);
		goto fail;
	}

	if (options.startup_fd != -1) {
		ok = sock_daemon_set_startup_fd(e_state->sockd,
						options.startup_fd);
		if (!ok) {
			goto fail;
		}
	}

	ret = sock_daemon_run(e_state->ev,
			      e_state->sockd,
			      e_state->pidfile,
			      false,
			      false,
			      options.pid);
	if (ret == EINTR) {
		ret = 0;
	}

	if (t != NULL) {
		talloc_report_full(e_state->mem_ctx, stderr);
	}

fail:
	talloc_free(e_state);
	(void)poptFreeContext(pc);
	exit(ret);
}
