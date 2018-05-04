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

#ifndef __CTDB_SOCK_CLIENT_H__
#define __CTDB_SOCK_CLIENT_H__

#include <talloc.h>
#include <tevent.h>

/**
 * @file sock_client.h
 *
 * @brief A framework for a client based on unix-domain sockets.
 *
 * This abstraction allows one to build clients that communicate using
 * unix-domain sockets.  It takes care of the common boilerplate.
 */

/**
 * @brief The abstract socket daemon context
 */
struct sock_client_context;

/**
 * @brief callback function
 *
 * This function can be registered to be called in case daemon goes away.
 */
typedef void (*sock_client_callback_func_t)(void *private_data);

/**
 * @brief Protocol marshalling functions
 *
 * The typical protocol packet will have a header and a payload.
 * Header will contain at least 2 fields: length and reqid
 *
 * request_push() is called when the request packet needs to be marshalled
 *
 * reply_pull() is called to unmarshall data into a reply packet
 *
 * reply_reqid() is called to extract request id from a reply packet
 */
struct sock_client_proto_funcs {
	int (*request_push)(void *request, uint32_t reqid,
			    TALLOC_CTX *mem_ctx,
			    uint8_t **buf, size_t *buflen,
			    void *private_data);

	int (*reply_pull)(uint8_t *buf, size_t buflen,
			  TALLOC_CTX *mem_ctx, void **reply,
			  void *private_data);

	int (*reply_reqid)(uint8_t *buf, size_t buflen,
			   uint32_t *reqid, void *private_data);
};

/**
 * @brief Create a new socket client
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] sockpath Unix domain socket path
 * @param[in] funcs Protocol marshalling functions
 * @param[in] private_data Private data for protocol functions
 * @param[out] result New socket client context
 * @return 0 on success, errno on failure
 */
int sock_client_setup(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      const char *sockpath,
		      struct sock_client_proto_funcs *funcs,
		      void *private_data,
		      struct sock_client_context **result);

/**
 * @brief Register a callback in case of client disconnection
 *
 * @param[in] sockc Socket client context
 * @param[in] callback Callback function
 * @param[in] private_data Private data for callback function
 */
void sock_client_set_disconnect_callback(struct sock_client_context *sockc,
					 sock_client_callback_func_t callback,
					 void *private_data);

/**
 * @brief Async computation to send data to the daemon
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] sockc The socket client context
 * @param[in] timeout How long to wait for
 * @param[in] request Requeset packet to be sent
 * @return new tevent request, or NULL on failure
 */
struct tevent_req *sock_client_msg_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct sock_client_context *sockc,
					struct timeval timeout,
					void *request);

/**
 * @brief Async computation end to send data to the daemon
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc memory context
 * @param[out] reply Reply received from server
 * @return true on success, false on failure
 */
bool sock_client_msg_recv(struct tevent_req *req, int *perr,
			  TALLOC_CTX *mem_ctx, void *reply);

#endif /* __CTDB_SOCK_CLIENT_H__ */
