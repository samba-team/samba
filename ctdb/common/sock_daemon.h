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

#ifndef __CTDB_SOCK_DAEMON_H__
#define __CTDB_SOCK_DAEMON_H__

#include <talloc.h>
#include <tevent.h>

#include "common/logging.h"

/**
 * @file sock_daemon.h
 *
 * @brief A framework for a server based on unix-domain sockets.
 *
 * This abstraction allows one to build simple servers that communicate using
 * unix-domain sockets.  It takes care of the common boilerplate.
 */

/**
 * @brief The abstract socket daemon context
 */
struct sock_daemon_context;

/**
 * @brief The abstract socket client context
 */
struct sock_client_context;

/**
 * @brief The callback routines called during daemon life cycle
 *
 * startup() is called when the daemon starts running
 *	either via sock_daemon_run() or via sock_daemon_run_send()
 *	startup() should return 0 for success, non-zero value on failure
 *	On failure, sock_daemon_run() will return error.
 *
 * startup_send()/startup_recv() is the async version of startup()
 *
 * reconfigure() is called when the daemon receives SIGUSR1 or SIGHUP
 *	reconfigure() should return 0 for success, non-zero value on failure
 *	On failure, sock_daemon_run() will continue to run.
 *
 * reconfigure_send()/reconfigure_recv() is the async version of reconfigure()
 *
 * shutdown() is called when process receives SIGINT or SIGTERM or
 *             when wait computation has finished
 *
 * shutdown_send()/shutdown_recv() is the async version of shutdown()
 *
 * Please note that only one (sync or async) version of these functions
 * will be called.  If both versions are defined, then only async function
 * will be called.
 *
 * wait_send() starts the async computation to keep running the daemon
 * wait_recv() ends the async computation to keep running the daemon
 *
 * If wait_send()/wait_recv() is NULL, then daemon will keep running forever.
 * If wait_send() returns req, then when req is over, daemon will shutdown.
 */
struct sock_daemon_funcs {
	int (*startup)(void *private_data);

	struct tevent_req * (*startup_send)(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    void *private_data);
	bool (*startup_recv)(struct tevent_req *req, int *perr);

	int (*reconfigure)(void *private_data);

	struct tevent_req * (*reconfigure_send)(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						void *private_data);
	bool (*reconfigure_recv)(struct tevent_req *req, int *perr);

	void (*shutdown)(void *private_data);

	struct tevent_req * (*shutdown_send)(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     void *private_data);
	void (*shutdown_recv)(struct tevent_req *req);

	struct tevent_req * (*wait_send)(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 void *private_data);
	bool (*wait_recv)(struct tevent_req *req, int *perr);
};

/**
 * @brief The callback routines called for an unix-domain socket
 *
 * connect() is called when there is a new connection
 *
 * @param[in] client The new socket client context
 * @param[in] pid The pid of the new client process, or -1 if unknown
 * @param[in] private_data Private data set with the socket
 * @return true if connection should be accepted, false otherwise
 *
 *
 * disconnect() is called  when client closes connection
 *
 * @param[in] client The socket client context
 * @param[in] private_data Private data associated with the socket
 *
 *
 * read_send() starts the async computation to process data on the socket
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client The socket client context
 * @param[in] buf Data received from the client
 * @param[in] buflen Length of the data
 * @param[i] private_data Private data associatedwith the socket
 * @return new tevent reques, or NULL on failure
 *
 *
 * read_recv() ends the async computation to process data on the socket
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 *
 */
struct sock_socket_funcs {
	bool (*connect)(struct sock_client_context *client,
			pid_t pid,
			void *private_data);
	void (*disconnect)(struct sock_client_context *client,
			   void *private_data);

	struct tevent_req * (*read_send)(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct sock_client_context *client,
					 uint8_t *buf, size_t buflen,
					 void *private_data);
	bool (*read_recv)(struct tevent_req *req, int *perr);
};

/**
 * @brief Async computation to send data to the client
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client The socket client context
 * @param[in] buf Data to be sent to the client
 * @param[in] buflen Length of the data
 * @return new tevent request, or NULL on failure
 */
struct tevent_req *sock_socket_write_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct sock_client_context *client,
					  uint8_t *buf, size_t buflen);

/**
 * @brief Async computation end to send data to client
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool sock_socket_write_recv(struct tevent_req *req, int *perr);

/**
 * @brief Create a new socket daemon
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] daemon_name Name of the daemon, used for logging
 * @param[in] logging Logging setup string
 * @param[in] debug_level Debug level to log at
 * @param[in] funcs Socket daemon callback routines
 * @param[in] private_data Private data associated with callback routines
 * @param[out] result New socket daemon context
 * @return 0 on success, errno on failure
 */
int sock_daemon_setup(TALLOC_CTX *mem_ctx, const char *daemon_name,
		      const char *logging, const char *debug_level,
		      struct sock_daemon_funcs *funcs,
		      void *private_data,
		      struct sock_daemon_context **result);

/**
 * @brief Create and listen to the unix domain socket
 *
 * @param[in] sockd Socket daemon context
 * @param[in] sockpath Unix domain socket path
 * @param[in] funcs socket callback routines
 * @param[in] private_data Private data associated with callback routines
 * @return 0 on success, errno on failure
 */
int sock_daemon_add_unix(struct sock_daemon_context *sockd,
			 const char *sockpath,
			 struct sock_socket_funcs *funcs,
			 void *private_data);

/**
 * @brief Set file descriptor for indicating startup success
 *
 * On successful completion, 0 (unsigned int) will be written to the fd.
 *
 * @param[in] sockd Socket daemon context
 * @param[in] fd File descriptor
 * @return true on success, false on error
 */
bool sock_daemon_set_startup_fd(struct sock_daemon_context *sockd, int fd);

/**
 * @brief Async computation start to run a socket daemon
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] sockd The socket daemon context
 * @param[in] pidfile PID file to create, NULL if no PID file required
 * @param[in] do_fork Whether the daemon should fork on startup
 * @param[in] create_session Whether the daemon should create a new session
 * @param[in] pid_watch PID to watch. If PID goes away, shutdown.
 * @return new tevent request, NULL on failure
 */
struct tevent_req *sock_daemon_run_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct sock_daemon_context *sockd,
					const char *pidfile,
					bool do_fork, bool create_session,
					pid_t pid_watch);

/**
 * @brief Async computation end to run a socket daemon
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool sock_daemon_run_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync way to start a daemon
 *
 * @param[in] ev Tevent context
 * @param[in] sockd The socket daemon context
 * @param[in] pidfile PID file to create, NULL if no PID file required
 * @param[in] do_fork Whether the daemon should fork on startup
 * @param[in] create_session Whether the daemon should create a new session
 * @param[in] pid_watch PID to watch. If PID goes away, shutdown.
 * @return 0 on success, errno on failure
 *
 * This call will return only on shutdown of the daemon
 */
int sock_daemon_run(struct tevent_context *ev,
		    struct sock_daemon_context *sockd,
		    const char *pidfile,
		    bool do_fork, bool create_session,
		    pid_t pid_watch);

#endif /* __CTDB_SOCK_DAEMON_H__ */
