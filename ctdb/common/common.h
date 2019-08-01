/*
   ctdb database library

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

#ifndef __CTDB_COMMON_H__
#define __CTDB_COMMON_H__

#include "lib/util/attr.h"

/* From common/ctdb_io.c */

typedef void (*ctdb_queue_cb_fn_t)(uint8_t *data, size_t length,
				   void *private_data);

uint32_t ctdb_queue_length(struct ctdb_queue *queue);

int ctdb_queue_send(struct ctdb_queue *queue, uint8_t *data, uint32_t length);

int ctdb_queue_set_fd(struct ctdb_queue *queue, int fd);

struct ctdb_queue *ctdb_queue_setup(struct ctdb_context *ctdb,
				    TALLOC_CTX *mem_ctx, int fd, int alignment,
				    ctdb_queue_cb_fn_t callback,
				    void *private_data, const char *fmt, ...)
				    PRINTF_ATTRIBUTE(7,8);

/* From common/ctdb_ltdb.c */

int ctdb_db_tdb_flags(uint8_t db_flags, bool with_valgrind, bool with_mutex);

struct ctdb_db_context *ctdb_db_handle(struct ctdb_context *ctdb,
				       const char *name);

bool ctdb_db_persistent(struct ctdb_db_context *ctdb_db);
bool ctdb_db_replicated(struct ctdb_db_context *ctdb_db);
bool ctdb_db_volatile(struct ctdb_db_context *ctdb_db);

bool ctdb_db_readonly(struct ctdb_db_context *ctdb_db);
void ctdb_db_set_readonly(struct ctdb_db_context *ctdb_db);
void ctdb_db_reset_readonly(struct ctdb_db_context *ctdb_db);

bool ctdb_db_sticky(struct ctdb_db_context *ctdb_db);
void ctdb_db_set_sticky(struct ctdb_db_context *ctdb_db);

uint32_t ctdb_lmaster(struct ctdb_context *ctdb, const TDB_DATA *key);

int ctdb_ltdb_fetch(struct ctdb_db_context *ctdb_db,
		    TDB_DATA key, struct ctdb_ltdb_header *header,
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);

int ctdb_ltdb_store(struct ctdb_db_context *ctdb_db, TDB_DATA key,
		    struct ctdb_ltdb_header *header, TDB_DATA data);

int ctdb_ltdb_lock(struct ctdb_db_context *ctdb_db, TDB_DATA key);

int ctdb_ltdb_unlock(struct ctdb_db_context *ctdb_db, TDB_DATA key);

int ctdb_ltdb_delete(struct ctdb_db_context *ctdb_db, TDB_DATA key);

int ctdb_trackingdb_add_pnn(struct ctdb_context *ctdb, TDB_DATA *data, uint32_t pnn);

typedef void (*ctdb_trackingdb_cb)(struct ctdb_context *ctdb, uint32_t pnn,
				   void *private_data);

void ctdb_trackingdb_traverse(struct ctdb_context *ctdb, TDB_DATA data,
			      ctdb_trackingdb_cb cb, void *private_data);

int ctdb_null_func(struct ctdb_call_info *call);

int ctdb_fetch_func(struct ctdb_call_info *call);

int ctdb_fetch_with_header_func(struct ctdb_call_info *call);

/* from common/ctdb_util.c */

const char *ctdb_errstr(struct ctdb_context *ctdb);

void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...)
		    PRINTF_ATTRIBUTE(2,3);

void ctdb_fatal(struct ctdb_context *ctdb, const char *msg) _NORETURN_;

void ctdb_die(struct ctdb_context *ctdb, const char *msg) _NORETURN_;

bool ctdb_set_helper(const char *type, char *helper, size_t size,
		     const char *envvar,
		     const char *dir, const char *file);

int ctdb_parse_address(TALLOC_CTX *mem_ctx, const char *str,
		       ctdb_sock_addr *address);

bool ctdb_same_address(ctdb_sock_addr *a1, ctdb_sock_addr *a2);

uint32_t ctdb_hash(const TDB_DATA *key);

struct ctdb_rec_data_old *ctdb_marshall_record(TALLOC_CTX *mem_ctx,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data);

struct ctdb_marshall_buffer *ctdb_marshall_add(TALLOC_CTX *mem_ctx,
					       struct ctdb_marshall_buffer *m,
					       uint32_t db_id,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data);

TDB_DATA ctdb_marshall_finish(struct ctdb_marshall_buffer *m);

struct ctdb_rec_data_old *ctdb_marshall_loop_next(
					struct ctdb_marshall_buffer *m,
					struct ctdb_rec_data_old *r,
					uint32_t *reqid,
					struct ctdb_ltdb_header *header,
					TDB_DATA *key, TDB_DATA *data);

void ctdb_canonicalize_ip(const ctdb_sock_addr *ip, ctdb_sock_addr *cip);

bool ctdb_same_ip(const ctdb_sock_addr *tip1, const ctdb_sock_addr *tip2);

bool ctdb_same_sockaddr(const ctdb_sock_addr *ip1, const ctdb_sock_addr *ip2);

char *ctdb_addr_to_str(ctdb_sock_addr *addr);

unsigned ctdb_addr_to_port(ctdb_sock_addr *addr);

struct ctdb_node_map_old *ctdb_read_nodes_file(TALLOC_CTX *mem_ctx,
					       const char *nlist);

struct ctdb_node_map_old *ctdb_node_list_to_map(struct ctdb_node **nodes,
						uint32_t num_nodes,
						TALLOC_CTX *mem_ctx);

const char *runstate_to_string(enum ctdb_runstate runstate);

enum ctdb_runstate runstate_from_string(const char *label);

void ctdb_set_runstate(struct ctdb_context *ctdb, enum ctdb_runstate runstate);

uint32_t *ctdb_key_to_idkey(TALLOC_CTX *mem_ctx, TDB_DATA key);

#endif /* __CTDB_COMMON_H__ */
