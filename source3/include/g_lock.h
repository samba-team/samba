/*
   Unix SMB/CIFS implementation.
   global locks based on dbwrap and messaging
   Copyright (C) 2009 by Volker Lendecke

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _G_LOCK_H_
#define _G_LOCK_H_

#include "dbwrap/dbwrap.h"

struct g_lock_ctx;
struct messaging_context;

enum g_lock_type {
	G_LOCK_READ,
	G_LOCK_WRITE,
	G_LOCK_UPGRADE,
	G_LOCK_DOWNGRADE,
};

struct g_lock_ctx *g_lock_ctx_init_backend(
	TALLOC_CTX *mem_ctx,
	struct messaging_context *msg,
	struct db_context **backend);
void g_lock_set_lock_order(struct g_lock_ctx *ctx,
			   enum dbwrap_lock_order lock_order);
struct g_lock_ctx *g_lock_ctx_init(TALLOC_CTX *mem_ctx,
				   struct messaging_context *msg);

struct tevent_req *g_lock_lock_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct g_lock_ctx *ctx,
				    TDB_DATA key,
				    enum g_lock_type type);
NTSTATUS g_lock_lock_recv(struct tevent_req *req);
NTSTATUS g_lock_lock(struct g_lock_ctx *ctx, TDB_DATA key,
		     enum g_lock_type lock_type, struct timeval timeout);
NTSTATUS g_lock_unlock(struct g_lock_ctx *ctx, TDB_DATA key);

NTSTATUS g_lock_writev_data(
	struct g_lock_ctx *ctx,
	TDB_DATA key,
	const TDB_DATA *dbufs,
	size_t num_dbufs);
NTSTATUS g_lock_write_data(struct g_lock_ctx *ctx, TDB_DATA key,
			   const uint8_t *buf, size_t buflen);

int g_lock_locks(struct g_lock_ctx *ctx,
		 int (*fn)(TDB_DATA key, void *private_data),
		 void *private_data);
struct tevent_req *g_lock_dump_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct g_lock_ctx *ctx,
	TDB_DATA key,
	void (*fn)(struct server_id exclusive,
		   size_t num_shared,
		   struct server_id *shared,
		   const uint8_t *data,
		   size_t datalen,
		   void *private_data),
	void *private_data);
NTSTATUS g_lock_dump_recv(struct tevent_req *req);
NTSTATUS g_lock_dump(struct g_lock_ctx *ctx,
		     TDB_DATA key,
		     void (*fn)(struct server_id exclusive,
				size_t num_shared,
				struct server_id *shared,
				const uint8_t *data,
				size_t datalen,
				void *private_data),
		     void *private_data);
int g_lock_seqnum(struct g_lock_ctx *ctx);

struct tevent_req *g_lock_watch_data_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct g_lock_ctx *ctx,
	TDB_DATA key,
	struct server_id blocker);
NTSTATUS g_lock_watch_data_recv(
	struct tevent_req *req,
	bool *blockerdead,
	struct server_id *blocker);
void g_lock_wake_watchers(struct g_lock_ctx *ctx, TDB_DATA key);

#endif
