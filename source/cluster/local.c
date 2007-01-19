/* 
   Unix SMB/CIFS implementation.

   local (dummy) clustering operations

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

/*
  server a server_id for the local node
*/
static struct server_id local_id(struct cluster_ops *ops, uint32_t id)
{
	struct server_id server_id;
	ZERO_STRUCT(server_id);
	server_id.id = id;
	return server_id;
}


/*
  return a server_id as a string
*/
static const char *local_id_string(struct cluster_ops *ops,
				   TALLOC_CTX *mem_ctx, struct server_id id)
{
	return talloc_asprintf(mem_ctx, "%u.%u", id.node, id.id);
}

static struct cluster_ops cluster_local_ops = {
	.cluster_id        = local_id,
	.cluster_id_string = local_id_string,
	.private           = NULL
};

void cluster_local_init(void)
{
	cluster_set_ops(&cluster_local_ops);
}

