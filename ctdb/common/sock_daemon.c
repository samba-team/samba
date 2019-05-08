/*
   A server based on unix domain socket

   Copyright (C) Amitay Isaacs  2016

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
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/async_req/async_sock.h"
#include "lib/util/debug.h"
#include "lib/util/blocking.h"
#include "lib/util/dlinklist.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/become_daemon.h"
#include "lib/util/sys_rw.h"

#include "common/logging.h"
#include "common/reqid.h"
#include "common/comm.h"
#include "common/pidfile.h"
#include "common/system.h"
#include "common/sock_daemon.h"

struct sock_socket {
	struct sock_socket *prev, *next;

	const char *sockpath;
	struct sock_socket_funcs *funcs;
	void *private_data;

	int fd;
	struct tevent_req *req;
};

struct sock_client {
	struct sock_client *prev, *next;

	struct tevent_req *req;
	struct sock_client_context *client_ctx;
};

struct sock_client_context {
	struct tevent_context *ev;
	struct sock_socket *sock;
	int fd;
	struct comm_context *comm;

	struct sock_client *client;
};

struct sock_daemon_context {
	struct sock_daemon_funcs *funcs;
	void *private_data;

	struct pidfile_context *pid_ctx;
	struct sock_socket *socket_list;
	int startup_fd;
};

/*
 * Process a single client
 */

static void sock_client_read_handler(uint8_t *buf, size_t buflen,
				     void *private_data);
static void sock_client_read_done(struct tevent_req *subreq);
static void sock_client_dead_handler(void *private_data);
static int sock_client_context_destructor(
				struct sock_client_context *client_ctx);

static int sock_client_context_init(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct sock_socket *sock,
				    int client_fd,
				    struct sock_client *client,
				    struct sock_client_context **result)
{
	struct sock_client_context *client_ctx;
	int ret;

	client_ctx = talloc_zero(mem_ctx, struct sock_client_context);
	if (client_ctx == NULL) {
		return ENOMEM;
	}

	client_ctx->ev = ev;
	client_ctx->sock = sock;
	client_ctx->fd = client_fd;
	client_ctx->client = client;

	ret = comm_setup(client_ctx, ev, client_fd,
			 sock_client_read_handler, client_ctx,
			 sock_client_dead_handler, client_ctx,
			 &client_ctx->comm);
	if (ret != 0) {
		talloc_free(client_ctx);
		return ret;
	}

	if (sock->funcs->connect != NULL) {
		pid_t pid;
		bool status;

		(void) ctdb_get_peer_pid(client_fd, &pid);

		status = sock->funcs->connect(client_ctx,
					      pid,
					      sock->private_data);
		if (! status) {
			talloc_free(client_ctx);
			close(client_fd);
			return 0;
		}
	}

	talloc_set_destructor(client_ctx, sock_client_context_destructor);

	*result = client_ctx;
	return 0;
}

static void sock_client_read_handler(uint8_t *buf, size_t buflen,
				     void *private_data)
{
	struct sock_client_context *client_ctx = talloc_get_type_abort(
		private_data, struct sock_client_context);
	struct sock_socket *sock = client_ctx->sock;
	struct tevent_req *subreq;

	subreq = sock->funcs->read_send(client_ctx, client_ctx->ev,
					client_ctx, buf, buflen,
					sock->private_data);
	if (subreq == NULL) {
		talloc_free(client_ctx);
		return;
	}
	tevent_req_set_callback(subreq, sock_client_read_done, client_ctx);
}

static void sock_client_read_done(struct tevent_req *subreq)
{
	struct sock_client_context *client_ctx = tevent_req_callback_data(
		subreq, struct sock_client_context);
	struct sock_socket *sock = client_ctx->sock;
	int ret;
	bool status;

	status = sock->funcs->read_recv(subreq, &ret);
	if (! status) {
		D_ERR("client read failed with ret=%d\n", ret);
		talloc_free(client_ctx);
	}
}

static void sock_client_dead_handler(void *private_data)
{
	struct sock_client_context *client_ctx = talloc_get_type_abort(
		private_data, struct sock_client_context);
	struct sock_socket *sock = client_ctx->sock;

	if (sock->funcs->disconnect != NULL) {
		sock->funcs->disconnect(client_ctx, sock->private_data);
	}

	talloc_free(client_ctx);
}

static int sock_client_context_destructor(
				struct sock_client_context *client_ctx)
{
	TALLOC_FREE(client_ctx->client);
	TALLOC_FREE(client_ctx->comm);
	if (client_ctx->fd != -1) {
		close(client_ctx->fd);
		client_ctx->fd = -1;
	}

	return 0;
}

/*
 * Process a single listening socket
 */

static int socket_setup(const char *sockpath, bool remove_before_use)
{
	struct sockaddr_un addr;
	size_t len;
	int ret, fd;

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

	ret = set_blocking(fd, false);
	if (ret != 0) {
		D_ERR("socket set nonblocking failed - %s\n", sockpath);
		close(fd);
		return -1;
	}

	if (remove_before_use) {
		unlink(sockpath);
	}

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		D_ERR("socket bind failed - %s\n", sockpath);
		close(fd);
		return -1;
	}

	ret = listen(fd, 10);
	if (ret != 0) {
		D_ERR("socket listen failed - %s\n", sockpath);
		close(fd);
		return -1;
	}

	D_NOTICE("listening on %s\n", sockpath);

	return fd;
}

static int sock_socket_destructor(struct sock_socket *sock);

static int sock_socket_init(TALLOC_CTX *mem_ctx, const char *sockpath,
			    struct sock_socket_funcs *funcs,
			    void *private_data,
			    struct sock_socket **result)
{
	struct sock_socket *sock;

	if (funcs == NULL) {
		return EINVAL;
	}
	if (funcs->read_send == NULL || funcs->read_recv == NULL) {
		return EINVAL;
	}

	sock = talloc_zero(mem_ctx, struct sock_socket);
	if (sock == NULL) {
		return ENOMEM;
	}

	sock->sockpath = talloc_strdup(sock, sockpath);
	if (sock->sockpath == NULL) {
		talloc_free(sock);
		return ENOMEM;
	}
	sock->funcs = funcs;
	sock->private_data = private_data;
	sock->fd = -1;

	talloc_set_destructor(sock, sock_socket_destructor);

	*result = sock;
	return 0;
}

static int sock_socket_destructor(struct sock_socket *sock)
{
	TALLOC_FREE(sock->req);

	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}

	unlink(sock->sockpath);
	return 0;
}


struct sock_socket_start_state {
	struct tevent_context *ev;
	struct sock_socket *sock;

	struct sock_client *client_list;
};

static int sock_socket_start_state_destructor(
				struct sock_socket_start_state *state);
static void sock_socket_start_new_client(struct tevent_req *subreq);
static int sock_socket_start_client_destructor(struct sock_client *client);

static struct tevent_req *sock_socket_start_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct sock_socket *sock,
						 bool remove_before_use)
{
	struct tevent_req *req, *subreq;
	struct sock_socket_start_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct sock_socket_start_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->sock = sock;

	sock->fd = socket_setup(sock->sockpath, remove_before_use);
	if (sock->fd == -1) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	talloc_set_destructor(state, sock_socket_start_state_destructor);

	subreq = accept_send(state, ev, sock->fd);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, sock_socket_start_new_client, req);

	sock->req = req;

	return req;
}

static int sock_socket_start_state_destructor(
				struct sock_socket_start_state *state)
{
	struct sock_client *client;

	while ((client = state->client_list) != NULL) {
		talloc_free(client);
	}

	return 0;
}

static void sock_socket_start_new_client(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_socket_start_state *state = tevent_req_data(
		req, struct sock_socket_start_state);
	struct sock_client *client;
	int client_fd, ret;

	client_fd = accept_recv(subreq, NULL, NULL, &ret);
	TALLOC_FREE(subreq);
	if (client_fd == -1) {
		D_ERR("failed to accept new connection\n");
	}

	subreq = accept_send(state, state->ev, state->sock->fd);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, sock_socket_start_new_client, req);

	if (client_fd == -1) {
		return;
	}

	client = talloc_zero(state, struct sock_client);
	if (tevent_req_nomem(client, req)) {
		close(client_fd);
		return;
	}

	client->req = req;

	ret = sock_client_context_init(client, state->ev, state->sock,
				       client_fd, client, &client->client_ctx);
	if (ret != 0) {
		talloc_free(client);
		return;
	}

	talloc_set_destructor(client, sock_socket_start_client_destructor);
	DLIST_ADD(state->client_list, client);
}

static int sock_socket_start_client_destructor(struct sock_client *client)
{
	struct sock_socket_start_state *state = tevent_req_data(
		client->req, struct sock_socket_start_state);

	DLIST_REMOVE(state->client_list, client);
	TALLOC_FREE(client->client_ctx);

	return 0;
}

static bool sock_socket_start_recv(struct tevent_req *req, int *perr,
				   TALLOC_CTX *mem_ctx, const char **sockpath)
{
	struct sock_socket_start_state *state = tevent_req_data(
		req, struct sock_socket_start_state);
	int ret;

	state->sock->req = NULL;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (sockpath != NULL) {
		*sockpath = talloc_steal(mem_ctx, state->sock->sockpath);
	}

	return true;
}

/*
 * Send message to a client
 */

struct tevent_req *sock_socket_write_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct sock_client_context *client_ctx,
					 uint8_t *buf, size_t buflen)
{
	struct tevent_req *req;

	req = comm_write_send(mem_ctx, ev, client_ctx->comm, buf, buflen);

	return req;
}

bool sock_socket_write_recv(struct tevent_req *req, int *perr)
{
	int ret;
	bool status;

	status = comm_write_recv(req, &ret);
	if (! status) {
		if (perr != NULL) {
			*perr = ret;
		}
	}

	return status;
}

/*
 * Socket daemon
 */

int sock_daemon_setup(TALLOC_CTX *mem_ctx, const char *daemon_name,
		      const char *logging, const char *debug_level,
		      struct sock_daemon_funcs *funcs,
		      void *private_data,
		      struct sock_daemon_context **out)
{
	struct sock_daemon_context *sockd;
	int ret;

	sockd = talloc_zero(mem_ctx, struct sock_daemon_context);
	if (sockd == NULL) {
		return ENOMEM;
	}

	sockd->funcs = funcs;
	sockd->private_data = private_data;
	sockd->startup_fd = -1;

	ret = logging_init(sockd, logging, debug_level, daemon_name);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to initialize logging, logging=%s, debug=%s\n",
			logging, debug_level);
		return ret;
	}

	*out = sockd;
	return 0;
}

int sock_daemon_add_unix(struct sock_daemon_context *sockd,
			 const char *sockpath,
			 struct sock_socket_funcs *funcs,
			 void *private_data)
{
	struct sock_socket *sock;
	int ret;

	ret = sock_socket_init(sockd, sockpath, funcs, private_data, &sock);
	if (ret != 0) {
		return ret;
	}


	DLIST_ADD(sockd->socket_list, sock);
	return 0;
}

bool sock_daemon_set_startup_fd(struct sock_daemon_context *sockd, int fd)
{
	if (! set_close_on_exec(fd)) {
		D_ERR("Failed to set close-on-exec on startup fd\n");
		return false;
	}

	sockd->startup_fd = fd;
	return true;
}

/*
 * Run socket daemon
 */

struct sock_daemon_run_state {
	struct tevent_context *ev;
	struct sock_daemon_context *sockd;
	pid_t pid_watch;

	int fd;
	int exit_code;
};

static void sock_daemon_run_started(struct tevent_req *subreq);
static void sock_daemon_run_startup_done(struct tevent_req *subreq);
static void sock_daemon_run_signal_handler(struct tevent_context *ev,
					   struct tevent_signal *se,
					   int signum, int count, void *siginfo,
					   void *private_data);
static void sock_daemon_run_reconfigure(struct tevent_req *req);
static void sock_daemon_run_reconfigure_done(struct tevent_req *subreq);
static void sock_daemon_run_shutdown(struct tevent_req *req);
static void sock_daemon_run_shutdown_done(struct tevent_req *subreq);
static void sock_daemon_run_exit(struct tevent_req *req);
static bool sock_daemon_run_socket_listen(struct tevent_req *req);
static void sock_daemon_run_socket_fail(struct tevent_req *subreq);
static void sock_daemon_run_watch_pid(struct tevent_req *subreq);
static void sock_daemon_run_wait(struct tevent_req *req);
static void sock_daemon_run_wait_done(struct tevent_req *subreq);
static void sock_daemon_startup_notify(struct sock_daemon_context *sockd);

struct tevent_req *sock_daemon_run_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct sock_daemon_context *sockd,
					const char *pidfile,
					bool do_fork, bool create_session,
					pid_t pid_watch)
{
	struct tevent_req *req, *subreq;
	struct sock_daemon_run_state *state;
	struct tevent_signal *se;

	req = tevent_req_create(mem_ctx, &state,
				struct sock_daemon_run_state);
	if (req == NULL) {
		return NULL;
	}

	become_daemon(do_fork, !create_session, false);

	if (pidfile != NULL) {
		int ret = pidfile_context_create(sockd, pidfile,
						 &sockd->pid_ctx);
		if (ret != 0) {
			tevent_req_error(req, EEXIST);
			return tevent_req_post(req, ev);
		}
	}

	state->ev = ev;
	state->sockd = sockd;
	state->pid_watch = pid_watch;
	state->fd  = -1;

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(0, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, sock_daemon_run_started, req);

	se = tevent_add_signal(ev, state, SIGHUP, 0,
			       sock_daemon_run_signal_handler, req);
	if (tevent_req_nomem(se, req)) {
		return tevent_req_post(req, ev);
	}

	se = tevent_add_signal(ev, state, SIGUSR1, 0,
			       sock_daemon_run_signal_handler, req);
	if (tevent_req_nomem(se, req)) {
		return tevent_req_post(req, ev);
	}

	se = tevent_add_signal(ev, state, SIGINT, 0,
			       sock_daemon_run_signal_handler, req);
	if (tevent_req_nomem(se, req)) {
		return tevent_req_post(req, ev);
	}

	se = tevent_add_signal(ev, state, SIGTERM, 0,
			       sock_daemon_run_signal_handler, req);
	if (tevent_req_nomem(se, req)) {
		return tevent_req_post(req, ev);
	}

	if (pid_watch > 1) {
		subreq = tevent_wakeup_send(state, ev,
					    tevent_timeval_current_ofs(1,0));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, sock_daemon_run_watch_pid,
					req);
	}

	return req;
}

static void sock_daemon_run_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	D_NOTICE("daemon started, pid=%u\n", getpid());

	if (sockd->funcs != NULL && sockd->funcs->startup_send != NULL &&
	    sockd->funcs->startup_recv != NULL) {
		subreq = sockd->funcs->startup_send(state, state->ev,
						    sockd->private_data);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, sock_daemon_run_startup_done,
					req);
		return;
	}

	if (sockd->funcs != NULL && sockd->funcs->startup != NULL) {
		int ret;

		ret = sockd->funcs->startup(sockd->private_data);
		if (ret != 0) {
			D_ERR("startup failed, ret=%d\n", ret);
			tevent_req_error(req, EIO);
			return;
		}

		D_NOTICE("startup completed successfully\n");
	}

	status = sock_daemon_run_socket_listen(req);
	if (! status) {
		return;
	}
	sock_daemon_run_wait(req);

	sock_daemon_startup_notify(sockd);
}

static void sock_daemon_run_startup_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;
	int ret;
	bool status;

	status = sockd->funcs->startup_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("startup failed, ret=%d\n", ret);
		tevent_req_error(req, EIO);
		return;
	}

	D_NOTICE("startup completed successfully\n");

	status = sock_daemon_run_socket_listen(req);
	if (! status) {
		return;
	}
	sock_daemon_run_wait(req);

	sock_daemon_startup_notify(sockd);
}

static void sock_daemon_run_signal_handler(struct tevent_context *ev,
					   struct tevent_signal *se,
					   int signum, int count, void *siginfo,
					   void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);

	D_NOTICE("Received signal %d\n", signum);

	if (signum == SIGHUP || signum == SIGUSR1) {
		sock_daemon_run_reconfigure(req);
		return;
	}

	if (signum == SIGINT || signum == SIGTERM) {
		state->exit_code = EINTR;
		sock_daemon_run_shutdown(req);
	}
}

static void sock_daemon_run_reconfigure(struct tevent_req *req)
{
	struct tevent_req *subreq;
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;

	if (sockd->funcs != NULL && sockd->funcs->reconfigure_send != NULL &&
	    sockd->funcs->reconfigure_recv != NULL) {
		subreq = sockd->funcs->reconfigure_send(state, state->ev,
							sockd->private_data);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					sock_daemon_run_reconfigure_done, req);
		return;
	}

	if (sockd->funcs != NULL && sockd->funcs->reconfigure != NULL) {
		int ret;

		ret = sockd->funcs->reconfigure(sockd->private_data);
		if (ret != 0) {
			D_ERR("reconfigure failed, ret=%d\n", ret);
			return;
		}

		D_NOTICE("reconfigure completed successfully\n");
	}
}

static void sock_daemon_run_reconfigure_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;
	int ret;
	bool status;

	status = sockd->funcs->reconfigure_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("reconfigure failed, ret=%d\n", ret);
		return;
	}

	D_NOTICE("reconfigure completed successfully\n");
}

static void sock_daemon_run_shutdown(struct tevent_req *req)
{
	struct tevent_req *subreq;
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;
	struct sock_socket *sock;

	D_NOTICE("Shutting down\n");

	while ((sock = sockd->socket_list) != NULL) {
		DLIST_REMOVE(sockd->socket_list, sock);
		TALLOC_FREE(sock);
	}

	if (sockd->funcs != NULL && sockd->funcs->shutdown_send != NULL &&
	    sockd->funcs->shutdown_recv != NULL) {
		subreq = sockd->funcs->shutdown_send(state, state->ev,
						     sockd->private_data);
		if (subreq == NULL) {
			sock_daemon_run_exit(req);
			return;
		}
		tevent_req_set_callback(subreq, sock_daemon_run_shutdown_done,
						req);
		return;
	}

	if (sockd->funcs != NULL && sockd->funcs->shutdown != NULL) {
		sockd->funcs->shutdown(sockd->private_data);
	}

	sock_daemon_run_exit(req);
}

static void sock_daemon_run_shutdown_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;

	sockd->funcs->shutdown_recv(subreq);
	TALLOC_FREE(subreq);

	sock_daemon_run_exit(req);
}

static void sock_daemon_run_exit(struct tevent_req *req)
{
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;

	TALLOC_FREE(sockd->pid_ctx);

	if (state->exit_code == 0) {
		tevent_req_done(req);
	} else {
		tevent_req_error(req, state->exit_code);
	}
}

static bool sock_daemon_run_socket_listen(struct tevent_req *req)
{
	struct tevent_req *subreq;
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;
	struct sock_socket *sock;
	bool remove_before_use = false;

	if (sockd->pid_ctx != NULL) {
		remove_before_use = true;
	}
	for (sock = sockd->socket_list; sock != NULL; sock = sock->next) {
		subreq = sock_socket_start_send(state, state->ev, sock,
						remove_before_use);
		if (tevent_req_nomem(subreq, req)) {
			return false;
		}
		tevent_req_set_callback(subreq, sock_daemon_run_socket_fail,
					req);
	}

	return true;
}

static void sock_daemon_run_socket_fail(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	const char *sockpath = "INVALID";
	int ret = 0;
	bool status;

	status = sock_socket_start_recv(subreq, &ret, state, &sockpath);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("socket %s closed unexpectedly\n", sockpath);
		state->exit_code = ret;
	} else {
		state->exit_code = 0;
	}

	sock_daemon_run_shutdown(req);
}

static void sock_daemon_run_watch_pid(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	int ret;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	ret = kill(state->pid_watch, 0);
	if (ret == -1) {
		if (errno == ESRCH) {
			D_ERR("PID %d gone away, exiting\n", state->pid_watch);
			state->exit_code = ESRCH;
			sock_daemon_run_shutdown(req);
			return;
		} else {
			D_ERR("Failed to check PID status %d, ret=%d\n",
			      state->pid_watch, errno);
		}
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, sock_daemon_run_watch_pid, req);
}

static void sock_daemon_run_wait(struct tevent_req *req)
{
	struct tevent_req *subreq;
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;

	if (sockd->funcs != NULL && sockd->funcs->wait_send != NULL &&
	    sockd->funcs->wait_recv != NULL) {
		subreq = sockd->funcs->wait_send(state, state->ev,
						 sockd->private_data);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, sock_daemon_run_wait_done,
					req);
	}
}

static void sock_daemon_run_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_daemon_run_state *state = tevent_req_data(
		req, struct sock_daemon_run_state);
	struct sock_daemon_context *sockd = state->sockd;
	int ret = 0;
	bool status;

	status = sockd->funcs->wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		state->exit_code = ret;
	} else {
		state->exit_code = 0;
	}

	sock_daemon_run_shutdown(req);
}

static void sock_daemon_startup_notify(struct sock_daemon_context *sockd)
{
	if (sockd->startup_fd != -1) {
		unsigned int zero = 0;
		ssize_t num;

		num = sys_write(sockd->startup_fd, &zero, sizeof(zero));
		if (num != sizeof(zero)) {
			D_WARNING("Failed to write zero to pipe FD\n");
		}
	}
}

bool sock_daemon_run_recv(struct tevent_req *req, int *perr)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	return true;
}

int sock_daemon_run(struct tevent_context *ev,
		    struct sock_daemon_context *sockd,
		    const char *pidfile,
		    bool do_fork, bool create_session,
		    pid_t pid_watch)
{
	struct tevent_req *req;
	int ret;
	bool status;

	req = sock_daemon_run_send(ev, ev, sockd,
				   pidfile, do_fork, create_session, pid_watch);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = sock_daemon_run_recv(req, &ret);
	TALLOC_FREE(req);
	if (! status) {
		return ret;
	}

	return 0;
}
