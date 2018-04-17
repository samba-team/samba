/* 
   Unix SMB/CIFS implementation.

   local (dummy) clustering operations

   Copyright (C) Andrew Tridgell 2006
   
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

#include "includes.h"
#include "cluster/cluster.h"
#include "cluster/cluster_private.h"
#include "dbwrap/dbwrap.h"
#include "system/filesys.h"
#include "param/param.h"
#include "librpc/gen_ndr/server_id.h"

/*
  server a server_id for the local node
*/
static struct server_id local_id(struct cluster_ops *ops, uint64_t pid, uint32_t task_id)
{
	struct server_id server_id;
	ZERO_STRUCT(server_id);
	server_id.pid = pid;
	server_id.task_id = task_id;
	server_id.vnn = NONCLUSTER_VNN;
	/* This is because we are not in the s3 serverid database */
	server_id.unique_id = SERVERID_UNIQUE_ID_NOT_TO_VERIFY;
	return server_id;
}


/*
  open a tmp tdb for the local node. By using smbd_tmp_path() we don't need
  TDB_CLEAR_IF_FIRST as the tmp path is wiped at startup
*/
static struct db_context *local_db_tmp_open(struct cluster_ops *ops,
					    TALLOC_CTX *mem_ctx,
					    struct loadparm_context *lp_ctx,
					    const char *dbbase, int flags)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	char *path, *dbname;
	struct db_context *db;
	int hash_size, tdb_flags;

	dbname = talloc_asprintf(mem_ctx, "%s.tdb", dbbase);

	path = smbd_tmp_path(tmp_ctx, lp_ctx, dbname);

	hash_size = lpcfg_tdb_hash_size(lp_ctx, path);
	tdb_flags = lpcfg_tdb_flags(lp_ctx, flags);

	db = dbwrap_local_open(
		mem_ctx,
		path,
		hash_size,
		tdb_flags,
		O_RDWR|O_CREAT,
		0600,
		DBWRAP_LOCK_ORDER_NONE,
		DBWRAP_FLAG_NONE);
	talloc_free(tmp_ctx);
	return db;
}

/*
  dummy backend handle function
*/
static void *local_backend_handle(struct cluster_ops *ops)
{
	return NULL;
}

/*
  dummy message init function - not needed as all messages are local
*/
static NTSTATUS local_message_init(struct cluster_ops *ops,
				   struct imessaging_context *msg,
				   struct server_id server,
				   cluster_message_fn_t handler)
{
	return NT_STATUS_OK;
}

/*
  dummy message send
*/
static NTSTATUS local_message_send(struct cluster_ops *ops,
				   struct server_id server, DATA_BLOB *data)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static struct cluster_ops cluster_local_ops = {
	.cluster_id           = local_id,
	.cluster_db_tmp_open  = local_db_tmp_open,
	.backend_handle       = local_backend_handle,
	.message_init         = local_message_init,
	.message_send         = local_message_send,
	.private_data         = NULL
};

void cluster_local_init(void)
{
	cluster_set_ops(&cluster_local_ops);
}

