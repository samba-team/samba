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

#ifndef __CTDB_CLIENT_H__
#define __CTDB_CLIENT_H__

#include <talloc.h>
#include <tevent.h>

#include "protocol/protocol.h"
#include "common/srvid.h"

/**
 * @file client.h
 *
 * @brief Client api to talk to ctdb daemon
 *
 * This API allows one to connect to ctdb daemon, perform various database
 * operations, send controls to ctdb daemon and send messages to other ctdb
 * clients.
 */

/**
 * @brief The abstract context that holds client connection to ctdb daemon
 */
struct ctdb_client_context;

/**
 * @brief The abstract context that holds a tunnel endpoint
 */
struct ctdb_tunnel_context;

/**
 * @brief The abstract context that represents a clustered database
 */
struct ctdb_db_context;

/**
 * @brief The abstract context that represents a record from a distributed
 * database
 */
struct ctdb_record_handle;

/**
 * @brief The abstract context that represents a transaction on a replicated
 * database
 */
struct ctdb_transaction_handle;

/**
 * @brief Client callback function
 *
 * This function can be registered to be invoked in case of ctdb daemon going
 * away.
 */
typedef void (*ctdb_client_callback_func_t)(void *private_data);

/**
 * @brief Tunnel callback function
 *
 * This function is registered when a tunnel endpoint is set up.  When the
 * tunnel endpoint receives a message, this function is invoked.
 */
typedef void (*ctdb_tunnel_callback_func_t)(struct ctdb_tunnel_context *tctx,
					    uint32_t srcnode, uint32_t reqid,
					    uint8_t *buf, size_t buflen,
					    void *private_data);

/**
 * @brief Async computation start to initialize a connection to ctdb daemon
 *
 * This returns a ctdb client context.  Freeing this context will free the
 * connection to ctdb daemon and any memory associated with it.
 *
 * If the connection to ctdb daemon is lost, the client will terminate
 * automatically as the library will call exit().  If the client code
 * wants to perform cleanup or wants to re-establish a new connection,
 * the client should register a disconnect callback function.
 *
 * @see ctdb_client_set_disconnect_callback
 *
 * When a disconnect callback function is registered, client library will
 * not call exit().  It is the responsibility of the client code to take
 * appropriate action.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] sockpath Path to ctdb daemon unix domain socket
 * @return new tevent request, NULL on failure
 */
struct tevent_req *ctdb_client_init_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 const char *sockpath);

/**
 * @brief Async computation end to initialize a connection to ctdb daemon
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc memory context
 * @param[out] result The new ctdb client context
 * @return true on success, false on failure
 */
bool ctdb_client_init_recv(struct tevent_req *req, int *perr,
			   TALLOC_CTX *mem_ctx,
			   struct ctdb_client_context **result);

/**
 * @brief Sync wrapper to initialize ctdb connection
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] sockpath Path to ctdb daemon unix domain socket
 * @param[out] result The new ctdb client context
 * @return 0 on succcess, errno on failure
 */
int ctdb_client_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     const char *sockpath,
		     struct ctdb_client_context **result);

/**
 * @brief Register a callback in case of client disconnection
 *
 * This allows client code to know if the connection to ctdb daemon is lost.
 * This is useful if the client wants to re-establish a new connection to ctdb
 * daemon.
 *
 * @param[in] client Client connection context
 * @param[in] func Callback function
 * @param[in] private_data private data for callback function
 */
void ctdb_client_set_disconnect_callback(struct ctdb_client_context *client,
					 ctdb_client_callback_func_t func,
					 void *private_data);

/**
 * @brief Get the node number of the current node
 *
 * @param[in] client Client connection context
 * return node number on success, CTDB_UNKNOWN_PNN on error
 */
uint32_t ctdb_client_pnn(struct ctdb_client_context *client);

/**
 * @brief Client event loop waiting for a flag
 *
 * This can used to wait for asynchronous computations to complete.
 * When this function is called, it will run tevent event loop and wait
 * till the done flag is set to true.  This function will block and will
 * not return as long as the done flag is false.
 *
 * @param[in] ev Tevent context
 * @param[in] done Boolean flag to indicate when to stop waiting
 */
void ctdb_client_wait(struct tevent_context *ev, bool *done);

/**
 * @brief Client event loop waiting for a flag with timeout
 *
 * This can be used to wait for asynchronous computations to complete.
 * When this function is called, it will run tevent event loop and wait
 * till the done flag is set to true or if the timeout occurs.
 *
 * This function will return when either
 *  - done flag is set to true, or
 *  - timeout has occurred.
 *
 * @param[in] ev Tevent context
 * @param[in] done Boolean flag to indicate when to stop waiting
 * @param[in] timeout How long to wait
 * @return 0 on success, ETIMEDOUT on timeout, and errno on failure
 */
int ctdb_client_wait_timeout(struct tevent_context *ev, bool *done,
			     struct timeval timeout);

/**
 * @brief Async computation start to wait till recovery is completed
 *
 * CTDB daemon does not perform many operations while in recovery (especially
 * database operations).  This computation allows one to wait till ctdb daemon has
 * finished recovery.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @return new tevent request, or NULL on failure
 */
struct tevent_req *ctdb_recovery_wait_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client);

/**
 * @brief Async computation end to wait till recovery is completed
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_recovery_wait_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper for ctdb_recovery_wait computation
 *
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @return true on success, false on failure
 */
bool ctdb_recovery_wait(struct tevent_context *ev,
			struct ctdb_client_context *client);

/**
 * @brief Async computation start to migrate a database record
 *
 * This sends a request to ctdb daemon to migrate a database record to
 * the local node.  CTDB daemon will locate the data master for the record
 * and will migrate record (and the data master) to the current node.
 *
 * @see ctdb_fetch_lock_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev  Tevent context
 * @param[in] client Client connection context
 * @param[in] request CTDB request data
 * @return a new tevent req, or NULL on failure
 */
struct tevent_req *ctdb_client_call_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_req_call *request);

/**
 * @brief Async computation end to migrate a database record
 *
 * @param[in] req Tevent request
 * @param[in] mem_ctx Talloc memory context
 * @param[out] reply CTDB reply data
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_client_call_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct ctdb_reply_call **reply, int *perr);


/**
 * @brief Async computation start to send a message to remote client(s)
 *
 * This sends a message to ctdb clients on a remote node.  All the
 * messages are associated with a specific SRVID.  All the clients on the
 * remote node listening to that SRVID, will get the message.
 *
 * Clients can register and deregister for messages for a SRVID using
 * ctdb_client_set_message_handler() and ctdb_client_remove_message_handler().
 *
 * @see ctdb_client_set_message_handler_send,
 *      ctdb_client_remove_message_handler_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] destnode Remote node id
 * @param[in] message Message to send
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_client_message_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct ctdb_req_message *message);

/**
 * @brief Async computation end to send a message to remote client(s)
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_client_message_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper to send a message to client(s) on remote node
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] destnode Node id
 * @param[in] message Message to send
 */
int ctdb_client_message(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode, struct ctdb_req_message *message);

/**
 * @brief Async computation start to send a message to multiple nodes
 *
 * This sends a message to ctdb clients on multiple remote nodes.  All the
 * messages are associated with a specific SRVID.  All the clients on remote
 * nodes listening to that SRVID, will get the message.
 *
 * Clients can register and deregister for messages for a SRVID using
 * ctdb_client_set_message_handler() and ctdb_client_remove_message_handler().
 *
 * @see ctdb_client_set_message_handler_send,
 *      ctdb_client_remove_message_handler_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] pnn_list List of node ids
 * @param[in] count Number of node ids
 * @param[in] message Message to send
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_client_message_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct ctdb_req_message *message);

/**
 * @brief Async computation end to send a message to multiple nodes
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc memory context
 * @param[out] perr_list The status from each node id
 * @return true on success, false on failure
 *
 * If perr_list is not NULL, then the status (0 on success, errno on failure)
 * of sending message to each of the node in the specified node list.  The
 * perr_list is an array of the same size as of pnn_list.
 */
bool ctdb_client_message_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list);

/**
 * @brief Sync wrapper to send a message to multiple nodes
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] pnn_list List of node ids
 * @param[in] count Number of node ids
 * @param[in] message Message to send
 * @param[out] perr_list The status from each node id
 * @return 0 on success, errno on failure
 */
int ctdb_client_message_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct ctdb_req_message *message,
			      int **perr_list);

/**
 * @brief Async computation start to receive messages for a SRVID
 *
 * This computation informs ctdb that the client is interested in all messages
 * for a specific SRVID.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] srvid SRVID
 * @param[in] handler Callback function to call when a message is received
 * @param[in] private_data Private data for callback
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_client_set_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					srvid_handler_fn handler,
					void *private_data);

/**
 * @brief Async computation end to receive messages for a SRVID
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_client_set_message_handler_recv(struct tevent_req *req, int *perr);

/**
 * Sync wrapper to receive messages for a SRVID
 *
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] srvid SRVID
 * @param[in] handler Callback function to call when a message is received
 * @param[in] private_data Private data for callback
 * @return 0 on success, errno on failure
 */
int ctdb_client_set_message_handler(struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    uint64_t srvid, srvid_handler_fn handler,
				    void *private_data);

/**
 * @brief Async computation start to stop receiving messages for a SRVID
 *
 * This computation informs ctdb that the client is no longer interested in
 * messages for a specific SRVID.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] srvid SRVID
 * @param[in] private_data Private data used to register callback
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_client_remove_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					void *private_data);

/**
 * @brief Async computation end to stop receiving messages for a SRVID
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_client_remove_message_handler_recv(struct tevent_req *req,
					     int *perr);

/**
 * Sync wrapper to stop receiving messages for a SRVID
 *
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] srvid SRVID
 * @param[in] private_data Private data used to register callback
 * @return 0 on success, errno on failure
 */
int ctdb_client_remove_message_handler(struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       uint64_t srvid, void *private_data);

/**
 * @brief Async computation start to send a control to ctdb daemon
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] destnode Node id
 * @param[in] timeout How long to wait
 * @param[in] request Control request
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_client_control_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct timeval timeout,
					    struct ctdb_req_control *request);

/**
 * @brief Async computation end to send a control to ctdb daemon
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc memory context
 * @param[out] preply Control reply
 * @return true on success, false on failure
 */
bool ctdb_client_control_recv(struct tevent_req *req, int *perr,
			      TALLOC_CTX *mem_ctx,
			      struct ctdb_reply_control **preply);

/**
 * @brief Sync wrapper to send a control to ctdb daemon
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] destnode Node id
 * @param[in] timeout How long to wait
 * @param[in] request Control request
 * @param[out] preply Control reply
 * @return 0 on success, errno on failure
 */
int ctdb_client_control(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode,
			struct timeval timeout,
			struct ctdb_req_control *request,
			struct ctdb_reply_control **preply);

/**
 * @brief Async computation start to send a control to multiple nodes
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] pnn_list List of node ids
 * @param[in] count Number of node ids
 * @param[in] timeout How long to wait
 * @param[in] request Control request
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_client_control_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct timeval timeout,
				struct ctdb_req_control *request);

/**
 * @brief Async computation end to send a control to multiple nodes
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc memory context
 * @param[out] perr_list Status from each node
 * @param[out] preply Control reply from each node
 * @return true on success, false on failure
 */
bool ctdb_client_control_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list,
				    struct ctdb_reply_control ***preply);

/**
 * @brief Sync wrapper to send a control to multiple nodes
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] pnn_list List of node ids
 * @param[in] count Number of node ids
 * @param[in] timeout How long to wait
 * @param[in] request Control request
 * @param[out] perr_list Status from each node
 * @param[out] preply Control reply from each node
 * @return 0 on success, errno on failure
 */
int ctdb_client_control_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct timeval timeout,
			      struct ctdb_req_control *request,
			      int **perr_list,
			      struct ctdb_reply_control ***preply);

/**
 * @brief Check err_list for errors
 *
 * This is a convenience function to parse the err_list returned from
 * functions that send requests to multiple nodes.
 *
 * If status from any of the node is non-zero, then return first non-zero
 * status.
 *
 * If status from all the nodes is 0, then return 0.
 *
 * @param[in] pnn_list List of node ids
 * @param[in] count Number of node ids
 * @param[in] err_list Status from each node
 * @param[out] pnn Node id in case of failure
 * @return 0 if no failures, status from first failure
 */
int ctdb_client_control_multi_error(uint32_t *pnn_list, int count,
				    int *err_list, uint32_t *pnn);

/**
 * @brief Async computation start to setup a tunnel endpoint
 *
 * This computation sets up a tunnel endpoint corresponding to a tunnel_id.
 * A tunnel is a ctdb transport to deliver new protocol between endpoints.
 *
 * For two endpoints to communicate using new protocol,
 * 1. Set up tunnel endpoints
 * 2. Send requests
 * 3. Send replies
 * 4. Destroy tunnel endpoints
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] tunnel_id Unique tunnel id
 * @param[in] callback Callback function to call when a message is received
 * @param[in] private_data Private data for callback
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_tunnel_setup_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_client_context *client,
					  uint64_t tunnel_id,
					  ctdb_tunnel_callback_func_t callback,
					  void *private_data);

/**
 * @brief Async computation end to setup a tunnel
 *
 * @param[in] req Tevent request
 * @param[in] perr errno in case of failure
 * @param[out] result A new tunnel context
 * @return true on success, false on failure
 *
 * Tunnel context should never be freed by user.
 */
bool ctdb_tunnel_setup_recv(struct tevent_req *req, int *perr,
			    struct ctdb_tunnel_context **result);

/**
 * @brief Sync wrapper for ctdb_tunnel_setup computation
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] tunnel_id Unique tunnel id
 * @param[in] callback Callback function to call when a message is received
 * @param[in] private_data Private data for callback
 * @param[out] result A new tunnel context
 * @return 0 on success, errno on failure
 */
int ctdb_tunnel_setup(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client, uint64_t tunnel_id,
		      ctdb_tunnel_callback_func_t callback, void *private_data,
		      struct ctdb_tunnel_context **result);

/**
 * @brief Async computation start to destroy a tunnel endpoint
 *
 * This computation destroys the tunnel endpoint.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] tctx Tunnel context
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_tunnel_destroy_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_tunnel_context *tctx);

/**
 * @brief Async computation end to destroy a tunnel endpoint
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_tunnel_destroy_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper for ctdb_tunnel_destroy computation
 *
 * @param[in] ev Tevent context
 * @param[in] tctx Tunnel context
 * @return 0 on success, errno on failure
 */
int ctdb_tunnel_destroy(struct tevent_context *ev,
			struct ctdb_tunnel_context *tctx);

/**
 * @brief Async computation start to send a request via a tunnel
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] tctx Tunnel context
 * @param[in] destnode PNN of destination
 * @param[in] timeout How long to wait
 * @param[in] buf Message to send
 * @param[in] buflen Size of the message to send
 * @param[in] wait_for_reply Whether to wait for reply
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_tunnel_request_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_tunnel_context *tctx,
					    uint32_t destnode,
					    struct timeval timeout,
					    uint8_t *buf, size_t buflen,
					    bool wait_for_reply);

/**
 * @brief Async computation end to send a request via a tunnel
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc context
 * @param[out] buf Reply data if expected
 * @param[out] buflen Size of reply data if expected
 * @return true on success, false on failure
 */
bool ctdb_tunnel_request_recv(struct tevent_req *req, int *perr,
			      TALLOC_CTX *mem_ctx, uint8_t **buf,
			      size_t *buflen);

/**
 * @brief Sync wrapper for ctdb_tunnel_request computation
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] tctx Tunnel context
 * @param[in] destnode PNN of destination
 * @param[in] timeout How long to wait
 * @param[in] buf Message to send
 * @param[in] buflen Size of the message to send
 * @param[in] wait_for_reply Whether to wait for reply
 * @return 0 on success, errno on failure
 */
int ctdb_tunnel_request(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_tunnel_context *tctx, uint32_t destnode,
			struct timeval timeout, uint8_t *buf, size_t buflen,
			bool wait_for_reply);

/**
 * @brief Async computation start to send a reply via a tunnel
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] tctx Tunnel context
 * @param[in] destnode PNN of destination
 * @param[in] reqid Request id
 * @param[in] timeout How long to wait
 * @param[in] buf Reply data
 * @param[in] buflen Size of reply data
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_tunnel_reply_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_tunnel_context *tctx,
					  uint32_t destnode, uint32_t reqid,
					  struct timeval timeout,
					  uint8_t *buf, size_t buflen);

/**
 * @brief Async computation end to send a reply via a tunnel
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_tunnel_reply_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper for ctdb_tunnel_reply computation
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] tctx Tunnel context
 * @param[in] destnode PNN of destination
 * @param[in] reqid Request id
 * @param[in] timeout How long to wait
 * @param[in] buf Reply data
 * @param[in] buflen Size of reply data
 * @return 0 on success, errno on failure
 */
int ctdb_tunnel_reply(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_tunnel_context *tctx, uint32_t destnode,
		      uint32_t reqid, struct timeval timeout,
		      uint8_t *buf, size_t buflen);

/**
 * @brief Async computation start to attach a database
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in[ client Client connection context
 * @param[in] timeout How long to wait
 * @param[in] db_name Name of the database
 * @param[in] db_flags Database flags
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_attach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout,
				    const char *db_name, uint8_t db_flags);

/**
 * @brief Async computation end to attach a database
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[out] result New database context
 * @return true on success, false on failure
 */
bool ctdb_attach_recv(struct tevent_req *req, int *perr,
		      struct ctdb_db_context **result);

/**
 * @brief Sync wrapper to attach a database
 *
 * @param[in] ev Tevent context
 * @param[in[ client Client connection context
 * @param[in] timeout How long to wait
 * @param[in] db_name Name of the database
 * @param[in] db_flags Database flags
 * @param[out] result New database context
 * @return 0 on success, errno on failure
 */
int ctdb_attach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout,
		const char *db_name, uint8_t db_flags,
		struct ctdb_db_context **result);

/**
 * @brief Async computation start to detach a database
 *
 * Only volatile databases can be detached at runtime.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in[ client Client connection context
 * @param[in] timeout How long to wait
 * @param[in] db_id Database id
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_detach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout, uint32_t db_id);

/**
 * @brief Async computation end to detach a database
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_detach_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper to detach a database
 *
 * Only volatile databases can be detached at runtime.
 *
 * @param[in] ev Tevent context
 * @param[in[ client Client connection context
 * @param[in] timeout How long to wait
 * @param[in] db_id Database id
 * @return 0 on success, errno on failure
 */
int ctdb_detach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout, uint32_t db_id);


/**
 * @brief Get database id from database context
 *
 * @param[in] db Database context
 * @return database id
 */
uint32_t ctdb_db_id(struct ctdb_db_context *db);

/**
 * @brief Traverse a database locally on the node
 *
 * This function traverses a database locally on the node and for each record
 * calls the parser function.  If the parser function returns 1, the traverse
 * will terminate.  If parser function returns 0, the traverse will continue
 * till all records in database are parsed.
 *
 * This is useful for replicated databases, since each node has exactly the
 * same records.
 *
 * @param[in] db Database context
 * @param[in] readonly Is the traversal for reading or updating
 * @param[in] extract_header Whether to extract ltdb header from record data
 * @param[in] parser Record parsing function
 * @param[in] private_data Private data for parser function
 * @return 0 on success, non-zero return value from parser function
 */
int ctdb_db_traverse_local(struct ctdb_db_context *db, bool readonly,
			   bool extract_header,
			   ctdb_rec_parser_func_t parser, void *private_data);

/**
 * @brief Async computation start to a cluster-wide database traverse
 *
 * This function traverses a database on all the nodes and for each record
 * calls the parser function.  If the parser function returns 1, the traverse
 * will terminate.  If parser function returns 0, the traverse will continue
 * till all records all on nodes are parsed.
 *
 * This is useful for distributed databases as the records are distributed
 * among the cluster nodes.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] db Database context
 * @param[in] destnode Node id
 * @param[in] timeout How long to wait
 * @param[in] parser Record parser function
 * @param[in] private_data Private data for parser
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_db_traverse_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 uint32_t destnode,
					 struct timeval timeout,
					 ctdb_rec_parser_func_t parser,
					 void *private_data);

/**
 * @brief Async computation end to a cluster-wide database traverse
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_db_traverse_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper for a cluster-wide database traverse
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] db Database context
 * @param[in] destnode Node id
 * @param[in] timeout How long to wait
 * @param[in] parser Record parser function
 * @param[in] private_data Private data for parser
 * @return 0 on success, errno on failure or non-zero status from parser
 */
int ctdb_db_traverse(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     struct ctdb_db_context *db,
		     uint32_t destnode, struct timeval timeout,
		     ctdb_rec_parser_func_t parser, void *private_data);

/**
 * @brief Fetch a record from a local database
 *
 * This function is primarily for internal use.
 * Clients should use ctdb_fetch_lock() instead.
 *
 * @param[in] db Database context
 * @param[in] key Record key
 * @param[out] header Record header
 * @param[in] mem_ctx Talloc memory context
 * @param[out] data Record data
 */
int ctdb_ltdb_fetch(struct ctdb_db_context *db, TDB_DATA key,
		    struct ctdb_ltdb_header *header,
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);

/**
 * @brief Async computation start to fetch a locked record
 *
 * This function is used to fetch a record from a distributed database.
 *
 * If the record is already available on the local node, then lock the
 * record and return the record handle.
 *
 * If the record is not available on the local node, send a CTDB request to
 * migrate the record.  Once the record is migrated to the local node, lock
 * the record and return the record handle.
 *
 * At the end of the computation, a record handle is returned which holds
 * the record lock.  When the record handle is freed, the record is unlocked.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client context
 * @param[in] db Database context
 * @param[in] key Record key
 * @param[in] readonly Whether to request readonly copy of the record
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_fetch_lock_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					struct ctdb_db_context *db,
					TDB_DATA key, bool readonly);

/**
 * @brief Async computation end to fetch a locked record
 *
 * @param[in] req Tevent request
 * @param[out] header Record header
 * @param[in] mem_ctx Talloc memory context
 * @param[out] data Record data
 * @param[out] perr errno in case of failure
 * @return a new record handle, NULL on failure
 */
struct ctdb_record_handle *ctdb_fetch_lock_recv(struct tevent_req *req,
						struct ctdb_ltdb_header *header,
						TALLOC_CTX *mem_ctx,
						TDB_DATA *data, int *perr);

/**
 * @brief Sync wrapper to fetch a locked record
 *
 * @see ctdb_fetch_lock_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client context
 * @param[in] db Database context
 * @param[in] key Record key
 * @param[in] readonly Whether to request readonly copy of the record
 * @param[out] header Record header
 * @param[out] data Record data
 * return 0 on success, errno on failure
 */
int ctdb_fetch_lock(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    struct ctdb_client_context *client,
		    struct ctdb_db_context *db, TDB_DATA key, bool readonly,
		    struct ctdb_record_handle **out,
		    struct ctdb_ltdb_header *header, TDB_DATA *data);

/**
 * @brief Update a locked record
 *
 * This function is used to update a record in a distributed database.
 *
 * This function should NOT be used to store null data, instead use
 * ctdb_delete_record().
 *
 * @param[in] h Record handle
 * @param[in] data New record data
 * @return 0 on success, errno on failure
 */
int ctdb_store_record(struct ctdb_record_handle *h, TDB_DATA data);

/**
 * @brief Async computation start to delete a locked record
 *
 * This function is used to delete a record in a distributed database
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] h Record handle
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_delete_record_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_record_handle *h);

/**
 * @brief Async computation end to delete a locked record
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_delete_record_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper to delete a locked record
 *
 * @see ctdb_delete_record_send
 *
 * @param[in] h Record handle
 * @return 0 on success, errno on failure
 */
int ctdb_delete_record(struct ctdb_record_handle *h);

/**
 * @brief Async computation start to get a global database lock
 *
 * Functions related to global locks are primarily used internally for
 * implementing transaction api.
 *
 * Clients should use transaction api directly.
 * @see ctdb_transaction_start_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client context
 * @param[in] db Database context for g_lock.tdb
 * @param[in] keyname Record key
 * @param[in] sid Server id
 * @param[in] readonly Lock type
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_g_lock_lock_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 const char *keyname,
					 struct ctdb_server_id *sid,
					 bool readonly);

/**
 * @brief Async computation end to get a global database lock
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_g_lock_lock_recv(struct tevent_req *req, int *perr);

/**
 * @brief Async computation start to release a global database lock
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] db Database context
 * @param[in] keyname Record key
 * @param[in] sid Server id
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_g_lock_unlock_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   struct ctdb_db_context *db,
					   const char *keyname,
					   struct ctdb_server_id sid);

/**
 * @brief Async computation end to release a global database lock
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_g_lock_unlock_recv(struct tevent_req *req, int *perr);

/**
 * @brief Async computation start to start a transaction
 *
 * This function is used to start a transaction on a replicated database.
 *
 * To perform any updates on a replicated database
 * - start transaction
 * - fetch record (ctdb_transaction_fetch_record)
 * - store record (ctdb_transaction_store_record)
 * - delete record (ctdb_transaction_delete_record)
 * - commit transaction (ctdb_transaction_commit_send), or
 * - cancel transaction (ctdb_transaction_cancel_send)
 *
 * Starting a transaction will return a transaction handle.  This is used
 * for updating records under a transaction.  This handle is automatically
 * freed once the transacion is committed or cancelled.
 *
 * Clients should NOT free the transaction handle.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] timeout How long to wait
 * @param[in] db Database context
 * @param[in] readonly Is transaction readonly
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_transaction_start_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct ctdb_client_context *client,
					       struct timeval timeout,
					       struct ctdb_db_context *db,
					       bool readonly);

/**
 * @brief Async computation end to start a transaction
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return a new transaction handle on success, NULL on failure
 */
struct ctdb_transaction_handle *ctdb_transaction_start_recv(
					struct tevent_req *req,
					int *perr);

/**
 * @brief Sync wrapper to start a transaction
 *
 * @see ctdb_transaction_start_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] timeout How long to wait
 * @param[in] db Database context
 * @param[in] readonly Is transaction readonly
 * @param[out] result a new transaction handle
 * @return 0 on success, errno on failure
 */
int ctdb_transaction_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   struct timeval timeout,
			   struct ctdb_db_context *db, bool readonly,
			   struct ctdb_transaction_handle **result);

/**
 * @brief Fetch a record under a transaction
 *
 * @see ctdb_transaction_start_send
 *
 * @param[in] h Transaction handle
 * @param[in] key Record key
 * @param[in] mem_ctx Talloc memory context
 * @param[out] data Record data
 * @return 0 on success, errno on failure
 */
int ctdb_transaction_fetch_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key,
				  TALLOC_CTX *mem_ctx, TDB_DATA *data);

/**
 * @brief Store a record under a transaction
 *
 * @see ctdb_transaction_start_send
 *
 * @param[in] h Transaction handle
 * @param[in] key Record key
 * @param[in] data New record data
 * @return 0 on success, errno on failure
 */
int ctdb_transaction_store_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key, TDB_DATA data);

/**
 * @brief Delete a record under a transaction
 *
 * @see ctdb_transaction_start_send
 *
 * @param[in] h Transaction handle
 * @param[in] key Record key
 * @return 0 on success, errno on failure
 */
int ctdb_transaction_delete_record(struct ctdb_transaction_handle *h,
				   TDB_DATA key);

/**
 * @brief Async computation start to commit a transaction
 *
 * @see ctdb_transaction_start_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] timeout How long to wait
 * @param[in] h Transaction handle
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_transaction_commit_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h);

/**
 * @brief Async computation end to commit a transaction
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_transaction_commit_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper to commit a transaction
 *
 * @see ctdb_transaction_commit_send
 *
 * @param[in] h Transaction handle
 * @return 0 on success, errno on failure
 */
int ctdb_transaction_commit(struct ctdb_transaction_handle *h);

/**
 * @brief Async computation start to cancel a transaction
 *
 * @see ctdb_transaction_start_send
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] timeout How long to wait
 * @param[in] h Transaction handle
 * @return a new tevent req on success, NULL on failure
 */
struct tevent_req *ctdb_transaction_cancel_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h);

/**
 * @brief Async computation end to cancel a transaction
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool ctdb_transaction_cancel_recv(struct tevent_req *req, int *perr);

/**
 * @brief Sync wrapper to cancel a transaction
 *
 * @see ctdb_transaction_cancel_send
 *
 * @param[in] h Transaction handle
 * @return 0 on success, errno on failure
 */
int ctdb_transaction_cancel(struct ctdb_transaction_handle *h);

/**
 * @brief Utility function to extract a list of node ids from nodemap
 *
 * @param[in] nodemap Node map
 * @param[in] flags_mask Flags to match on
 * @param[in] exclude_pnn Node id to exclude from the list
 * @param[in] mem_ctx Talloc memory context
 * @param[out] pnn_list List of node ids
 * @return number of node ids on success, -1 on failure
 */
int list_of_nodes(struct ctdb_node_map *nodemap,
		  uint32_t flags_mask, uint32_t exclude_pnn,
		  TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

/**
 * @brief Utility function to extract a list of node ids for active nodes
 *
 * @param[in] nodemap Node map
 * @param[in] exclude_pnn Node id to exclude from the list
 * @param[in] mem_ctx Talloc memory context
 * @param[out] pnn_list List of node ids
 * @return number of node ids on success, -1 on failure
 */
int list_of_active_nodes(struct ctdb_node_map *nodemap, uint32_t exclude_pnn,
			 TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

/**
 * @brief Utility function to extract a list of node ids for connected nodes
 *
 * @param[in] nodemap Node map
 * @param[in] exclude_pnn Node id to exclude from the list
 * @param[in] mem_ctx Talloc memory context
 * @param[out] pnn_list List of node ids
 * @return number of node ids on success, -1 on failure
 */
int list_of_connected_nodes(struct ctdb_node_map *nodemap,
			    uint32_t exclude_pnn,
			    TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

/**
 * @brief Construct a new server id
 *
 * @param[in] client Client connection context
 * @param[in] task_id Task id
 * @return a new server id
 */
struct ctdb_server_id ctdb_client_get_server_id(
				struct ctdb_client_context *client,
				uint32_t task_id);

/**
 * @brief Check if two server ids are the same
 *
 * @param[in] sid1 Server id 1
 * @param[in] sid2 Server id 2
 * @return true if the server ids are same, false otherwise
 */
bool ctdb_server_id_equal(struct ctdb_server_id *sid1,
			  struct ctdb_server_id *sid2);

/**
 * @brief Check if the process with server id exists
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] client Client connection context
 * @param[in] sid Server id
 * @param[out] exists Boolean flag to indicate if the process exists
 * @return 0 on success, errno on failure
 */
int ctdb_server_id_exists(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  struct ctdb_server_id *sid, bool *exists);

#endif /* __CTDB_CLIENT_H__ */
