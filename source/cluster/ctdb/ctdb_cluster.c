/* 
   Unix SMB/CIFS implementation.

   ctdb clustering hooks

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
#include "lib/events/events.h"
#include "cluster/cluster.h"
#include "system/filesys.h"
#include "cluster/cluster_private.h"
#include "lib/tdb/include/tdb.h"
#include "include/ctdb.h"
#include "db_wrap.h"
#include "lib/util/dlinklist.h"

/* a linked list of messaging handlers, allowing incoming messages
   to be directed to the right messaging context */
struct cluster_messaging_list {
	struct cluster_messaging_list *next, *prev;
	struct cluster_state *state;
	struct messaging_context *msg;
	struct server_id server;
	cluster_message_fn_t handler;
};

struct cluster_state {
	struct ctdb_context *ctdb;
	struct cluster_messaging_list *list;
};



/*
  return a server_id for a ctdb node
*/
static struct server_id ctdb_id(struct cluster_ops *ops, uint32_t id)
{
	struct cluster_state *state = ops->private;
	struct ctdb_context *ctdb = state->ctdb;
	struct server_id server_id;
	server_id.node = ctdb_get_vnn(ctdb);
	server_id.id = id;
	return server_id;
}


/*
  return a server_id as a string
*/
static const char *ctdb_id_string(struct cluster_ops *ops, 
				  TALLOC_CTX *mem_ctx, struct server_id id)
{
	return talloc_asprintf(mem_ctx, "%u.%u", id.node, id.id);
}

/*
  this is an interim method for subsystems that have not yet been
  converted to use the ctdb api. It opens a shared database in the
  cluster temporary area, using TDB_CLEAR_IF_FIRST which relies on
  correct operation of fcntl locks on the shared fileystem.
*/
static struct tdb_wrap *ctdb_tdb_tmp_open(struct cluster_ops *ops,
					  TALLOC_CTX *mem_ctx, const char *dbname, 
					  int flags)
{
	const char *dir = lp_parm_string(-1, "ctdb", "shared data");
	char *path;
	struct tdb_wrap *w;
	if (dir == NULL) {
		DEBUG(0,("ERROR: You must set 'ctdb:shared data' to a cluster shared path\n"));
		return NULL;
	}
	path = talloc_asprintf(mem_ctx, "%s/%s", dir, dbname);
	w = tdb_wrap_open(mem_ctx, path, 0,  
			  flags | TDB_CLEAR_IF_FIRST,
			  O_RDWR|O_CREAT, 0600);
	talloc_free(path);
	return w;
}

/*
  get at the ctdb handle
*/
static void *ctdb_backend_handle(struct cluster_ops *ops)
{
	struct cluster_state *state = ops->private;
	return (void *)state->ctdb;
}

struct ctdb_handler_state {
	struct cluster_state *state;
	cluster_message_fn_t handler;
	struct messaging_context *msg;
};

/*
  dispatch incoming ctdb messages
*/
static void ctdb_message_handler(struct ctdb_context *ctdb, uint64_t srvid, 
				 TDB_DATA data, void *private)
{
	struct ctdb_handler_state *s = talloc_get_type(private, 
						       struct ctdb_handler_state);
	DATA_BLOB blob;
	blob.data = data.dptr;
	blob.length = data.dsize;
	s->handler(s->msg, blob);
}

static int ctdb_handler_destructor(struct ctdb_handler_state *s)
{
	/* XXX - tell ctdb to de-register the message handler */
	return 0;
}

/*
  setup a handler for ctdb messages
*/
static NTSTATUS ctdb_message_init(struct cluster_ops *ops,
				  struct messaging_context *msg, 
				  struct server_id server,
				  cluster_message_fn_t handler)
{
	struct cluster_state *state = ops->private;
	struct ctdb_handler_state *h;
	int ret;

	h = talloc(msg, struct ctdb_handler_state);
	NT_STATUS_HAVE_NO_MEMORY(h);

	h->state = state;
	h->handler = handler;
	h->msg = msg;

	talloc_set_destructor(h, ctdb_handler_destructor);

	/* setup a message handler */
	ret = ctdb_set_message_handler(state->ctdb, server.id, 
				       ctdb_message_handler, h);
        if (ret == -1) {
                DEBUG(0,("ctdb_set_message_handler failed - %s\n", 
			 ctdb_errstr(state->ctdb)));
		exit(1);
        }

	return NT_STATUS_OK;
}

/*
  send a ctdb message to another node
*/
static NTSTATUS ctdb_message_send(struct cluster_ops *ops,
				  struct server_id server, DATA_BLOB *data)
{
	struct cluster_state *state = ops->private;
	struct ctdb_context *ctdb = state->ctdb;
	TDB_DATA tdata;
	int ret;

	tdata.dptr = data->data;
	tdata.dsize = data->length;

	ret = ctdb_send_message(ctdb, server.node, server.id, tdata);
	if (ret != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	return NT_STATUS_OK;
}

static struct cluster_ops cluster_ctdb_ops = {
	.cluster_id           = ctdb_id,
	.cluster_id_string    = ctdb_id_string,
	.cluster_tdb_tmp_open = ctdb_tdb_tmp_open,
	.backend_handle       = ctdb_backend_handle,
	.message_init         = ctdb_message_init,
	.message_send         = ctdb_message_send,
	.private           = NULL
};

/* initialise ctdb */
void cluster_ctdb_init(struct event_context *ev, const char *model)
{
	struct cluster_state *state;

	if (!lp_parm_bool(-1, "ctdb", "enable", False)) {
		return;
	}

	state = talloc(ev, struct cluster_state);
	if (state == NULL) goto failed;

	state->ctdb = ctdb_init(ev);
	if (state->ctdb == NULL) goto failed;

	state->list = NULL;

	cluster_ctdb_ops.private = state;

	cluster_set_ops(&cluster_ctdb_ops);

	/* nasty hack for now ... */
	{
		void brl_ctdb_init_ops(void);
		brl_ctdb_init_ops();
	}

	return;
	
failed:
	DEBUG(0,("cluster_ctdb_init failed\n"));
	talloc_free(state);
}
