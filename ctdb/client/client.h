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

struct ctdb_client_context;
struct ctdb_db_context;
struct ctdb_record_handle;

typedef void (*ctdb_client_callback_func_t)(void *private_data);

/* from client/client_connect.c */

int ctdb_client_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     const char *sockpath, struct ctdb_client_context **ret);

void ctdb_client_set_disconnect_callback(struct ctdb_client_context *client,
					 ctdb_client_callback_func_t func,
					 void *private_data);

uint32_t ctdb_client_pnn(struct ctdb_client_context *client);

void ctdb_client_wait(struct tevent_context *ev, bool *done);

int ctdb_client_wait_timeout(struct tevent_context *ev, bool *done,
			     struct timeval timeout);

struct tevent_req *ctdb_recovery_wait_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client);

bool ctdb_recovery_wait_recv(struct tevent_req *req, int *perr);

bool ctdb_recovery_wait(struct tevent_context *ev,
			struct ctdb_client_context *client);

/* from client/client_call.c */

struct tevent_req *ctdb_client_call_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_req_call *request);

bool ctdb_client_call_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct ctdb_reply_call **reply, int *perr);


/* from client/client_message.c */

struct tevent_req *ctdb_client_message_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct ctdb_req_message *message);

bool ctdb_client_message_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_client_message_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct ctdb_req_message *message);

bool ctdb_client_message_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list);

int ctdb_client_message(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode, struct ctdb_req_message *message);

int ctdb_client_message_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct ctdb_req_message *message,
			      int **perr_list);

struct tevent_req *ctdb_client_set_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					srvid_handler_fn handler,
					void *private_data);
bool ctdb_client_set_message_handler_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_client_remove_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					void *private_data);
bool ctdb_client_remove_message_handler_recv(struct tevent_req *req,
					     int *perr);

int ctdb_client_set_message_handler(struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    uint64_t srvid, srvid_handler_fn handler,
				    void *private_data);

int ctdb_client_remove_message_handler(struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       uint64_t srvid, void *private_data);

/* from client/client_control.c */

struct tevent_req *ctdb_client_control_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct timeval timeout,
					    struct ctdb_req_control *request);

bool ctdb_client_control_recv(struct tevent_req *req, int *perr,
			      TALLOC_CTX *mem_ctx,
			      struct ctdb_reply_control **preply);

struct tevent_req *ctdb_client_control_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct timeval timeout,
				struct ctdb_req_control *request);

bool ctdb_client_control_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list,
				    struct ctdb_reply_control ***preply);

int ctdb_client_control_multi_error(uint32_t *pnn_list, int count,
				    int *err_list, uint32_t *pnn);

int ctdb_client_control(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode,
			struct timeval timeout,
			struct ctdb_req_control *c,
			struct ctdb_reply_control **preply);

int ctdb_client_control_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct timeval timeout,
			      struct ctdb_req_control *request,
			      int **perr,
			      struct ctdb_reply_control ***preply);

/* from client/client_db.c */

struct tevent_req *ctdb_attach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout,
				    const char *db_name, uint8_t db_flags);

bool ctdb_attach_recv(struct tevent_req *req, int *perr,
		      struct ctdb_db_context **out);

int ctdb_attach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout,
		const char *db_name, uint8_t db_flags,
		struct ctdb_db_context **out);

struct tevent_req *ctdb_detach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout, uint32_t db_id);

bool ctdb_detach_recv(struct tevent_req *req, int *perr);

int ctdb_detach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout, uint32_t db_id);

uint32_t ctdb_db_id(struct ctdb_db_context *db);

int ctdb_db_traverse_local(struct ctdb_db_context *db, bool readonly,
			   bool extract_header,
			   ctdb_rec_parser_func_t parser, void *private_data);

struct tevent_req *ctdb_db_traverse_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 uint32_t destnode,
					 struct timeval timeout,
					 ctdb_rec_parser_func_t parser,
					 void *private_data);

bool ctdb_db_traverse_recv(struct tevent_req *req, int *perr);

int ctdb_db_traverse(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     struct ctdb_db_context *db,
		     uint32_t destnode, struct timeval timeout,
		     ctdb_rec_parser_func_t parser, void *private_data);

int ctdb_ltdb_fetch(struct ctdb_db_context *db, TDB_DATA key,
		    struct ctdb_ltdb_header *header,
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);

struct tevent_req *ctdb_fetch_lock_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					struct ctdb_db_context *db,
					TDB_DATA key, bool readonly);

struct ctdb_record_handle *ctdb_fetch_lock_recv(struct tevent_req *req,
						struct ctdb_ltdb_header *header,
						TALLOC_CTX *mem_ctx,
						TDB_DATA *data, int *perr);

int ctdb_fetch_lock(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    struct ctdb_client_context *client,
		    struct ctdb_db_context *db, TDB_DATA key, bool readonly,
		    struct ctdb_record_handle **out,
		    struct ctdb_ltdb_header *header, TDB_DATA *data);

int ctdb_store_record(struct ctdb_record_handle *h, TDB_DATA data);

struct tevent_req *ctdb_delete_record_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_record_handle *h);

bool ctdb_delete_record_recv(struct tevent_req *req, int *perr);

int ctdb_delete_record(struct ctdb_record_handle *h);

struct tevent_req *ctdb_g_lock_lock_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 const char *keyname,
					 struct ctdb_server_id *sid,
					 bool readonly);

bool ctdb_g_lock_lock_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_g_lock_unlock_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   struct ctdb_db_context *db,
					   const char *keyname,
					   struct ctdb_server_id sid);

bool ctdb_g_lock_unlock_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_transaction_start_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct ctdb_client_context *client,
					       struct timeval timeout,
					       struct ctdb_db_context *db,
					       bool readonly);

struct ctdb_transaction_handle *ctdb_transaction_start_recv(
					struct tevent_req *req,
					int *perr);

int ctdb_transaction_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   struct timeval timeout,
			   struct ctdb_db_context *db, bool readonly,
			   struct ctdb_transaction_handle **out);

int ctdb_transaction_fetch_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key,
				  TALLOC_CTX *mem_ctx, TDB_DATA *data);

int ctdb_transaction_store_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key, TDB_DATA data);

int ctdb_transaction_delete_record(struct ctdb_transaction_handle *h,
				   TDB_DATA key);

struct tevent_req *ctdb_transaction_commit_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h);

bool ctdb_transaction_commit_recv(struct tevent_req *req, int *perr);

int ctdb_transaction_commit(struct ctdb_transaction_handle *h);

struct tevent_req *ctdb_transaction_cancel_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h);

bool ctdb_transaction_cancel_recv(struct tevent_req *req, int *perr);

int ctdb_transaction_cancel(struct ctdb_transaction_handle *h);

/* from client/client_util.c */

int list_of_nodes(struct ctdb_node_map *nodemap,
		  uint32_t flags_mask, uint32_t exclude_pnn,
		  TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

int list_of_active_nodes(struct ctdb_node_map *nodemap, uint32_t exclude_pnn,
			 TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

int list_of_connected_nodes(struct ctdb_node_map *nodemap,
			    uint32_t exclude_pnn,
			    TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

struct ctdb_server_id ctdb_client_get_server_id(
				struct ctdb_client_context *client,
				uint32_t task_id);

bool ctdb_server_id_equal(struct ctdb_server_id *sid1,
			  struct ctdb_server_id *sid2);

int ctdb_server_id_exists(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  struct ctdb_server_id *sid, bool *exists);

#endif /* __CTDB_CLIENT_H__ */
