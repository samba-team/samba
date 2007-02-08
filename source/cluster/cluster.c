/* 
   Unix SMB/CIFS implementation.

   core clustering code

   Copyright (C) Andrew Tridgell 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "cluster/cluster.h"
#include "cluster/cluster_private.h"

static struct cluster_ops *ops;

/* set cluster operations */
void cluster_set_ops(struct cluster_ops *new_ops)
{
	ops = new_ops;
}

/*
  an ugly way of getting at the backend handle (eg. ctdb context) via the cluster API
*/
void *cluster_backend_handle(void)
{
	return ops->backend_handle(ops);
}

/* by default use the local ops */
static void cluster_init(void)
{
	if (ops == NULL) cluster_local_init();
}

/*
  server a server_id for the local node
*/
struct server_id cluster_id(uint32_t id)
{
	cluster_init();
	return ops->cluster_id(ops, id);
}


/*
  return a server_id as a string
*/
const char *cluster_id_string(TALLOC_CTX *mem_ctx, struct server_id id)
{
	cluster_init();
	return ops->cluster_id_string(ops, mem_ctx, id);
}


/*
  open a temporary tdb in a cluster friendly manner
*/
struct tdb_wrap *cluster_tdb_tmp_open(TALLOC_CTX *mem_ctx, const char *dbname, int flags)
{
	cluster_init();
	return ops->cluster_tdb_tmp_open(ops, mem_ctx, dbname, flags);
}


/*
  register a callback function for a messaging endpoint
*/
NTSTATUS cluster_message_init(struct messaging_context *msg, struct server_id server,
			      cluster_message_fn_t handler)
{
	cluster_init();
	return ops->message_init(ops, msg, server, handler);
}

/*
  send a message to another node in the cluster
*/
NTSTATUS cluster_message_send(struct server_id server, uint32_t msg_type, DATA_BLOB *data)
{
	cluster_init();
	return ops->message_send(ops, server, msg_type, data);
}
