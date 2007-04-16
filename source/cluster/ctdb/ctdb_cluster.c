/* 
   Unix SMB/CIFS implementation.

   ctdb clustering hooks

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

/*
  dispatch incoming ctdb messages
*/
static void ctdb_message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
				 TDB_DATA data, void *private)
{
	struct cluster_state *state = talloc_get_type(private, struct cluster_state);
	struct cluster_messaging_list *m;
	for (m=state->list;m;m=m->next) {
		if (srvid == m->server.id) {
			DATA_BLOB bdata;
			bdata.data   = data.dptr;
			bdata.length = data.dsize;
			m->handler(m->msg, bdata);
		}
	}
}

/*
  destroy a element of messaging list (when messaging context goes away)
*/
static int cluster_messaging_destructor(struct cluster_messaging_list *m)
{
	DLIST_REMOVE(m->state->list, m);
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
	struct cluster_messaging_list *m;
	int ret;

	/* setup messaging handler */
	ret = ctdb_set_message_handler(state->ctdb, ctdb_message_handler, 
				       server.id, state);
        if (ret == -1) {
                DEBUG(0,("ctdb_set_message_handler failed - %s\n", 
			 ctdb_errstr(state->ctdb)));
		exit(1);
        }

	m = talloc(msg, struct cluster_messaging_list);
	NT_STATUS_HAVE_NO_MEMORY(m);
	
	m->state   = state;
	m->msg     = msg;
	m->server  = server;
	m->handler = handler;
	DLIST_ADD(state->list, m);

	talloc_set_destructor(m, cluster_messaging_destructor);

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
void cluster_ctdb_init(struct event_context *ev)
{
	const char *nlist;
	const char *address;
	const char *transport;
	struct cluster_state *state;
	int ret, lacount, i;
	const char *db_list[] = { "brlock", "opendb" };

	nlist = lp_parm_string(-1, "ctdb", "nlist");
	if (nlist == NULL) return;

	address = lp_parm_string(-1, "ctdb", "address");
	if (address == NULL) return;

	transport = lp_parm_string(-1, "ctdb", "transport");
	if (transport == NULL) {
		transport = "tcp";
	}

	state = talloc(ev, struct cluster_state);
	if (state == NULL) goto failed;

	state->ctdb = ctdb_init(ev);
	if (state->ctdb == NULL) goto failed;

	state->list = NULL;

	cluster_ctdb_ops.private = state;

	ret = ctdb_set_transport(state->ctdb, transport);
	if (ret == -1) {
		DEBUG(0,("ctdb_set_transport failed - %s\n",
			 ctdb_errstr(state->ctdb)));
		goto failed;
	}

	if (lp_parm_bool(-1, "ctdb", "selfconnect", False)) {
		DEBUG(0,("Enabling ctdb selfconnect\n"));
		ctdb_set_flags(state->ctdb, CTDB_FLAG_SELF_CONNECT);
	}

	lacount = lp_parm_int(-1, "ctdb", "maxlacount", -1);
	if (lacount != -1) {
		ctdb_set_max_lacount(state->ctdb, lacount);
	}

	/* tell ctdb what address to listen on */
        ret = ctdb_set_address(state->ctdb, address);
        if (ret == -1) {
                DEBUG(0,("ctdb_set_address failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
        }

        /* tell ctdb what nodes are available */
        ret = ctdb_set_nlist(state->ctdb, nlist);
        if (ret == -1) {
                DEBUG(0,("ctdb_set_nlist failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
        }

	/* attach all the databases we will need */
	for (i=0;i<ARRAY_SIZE(db_list);i++) {
		struct ctdb_db_context *ctdb_db;
		ctdb_db = ctdb_attach(state->ctdb, db_list[i], TDB_INTERNAL, 
				      O_RDWR|O_CREAT|O_TRUNC, 0666);
		if (ctdb_db == NULL) goto failed;
	}

	/* start the protocol running */
	ret = ctdb_start(state->ctdb);
        if (ret == -1) {
                DEBUG(0,("ctdb_start failed - %s\n", ctdb_errstr(state->ctdb)));
		goto failed;
        }

	/* wait until all nodes are connected (should not be needed
	   outide of test code) */
	ctdb_connect_wait(state->ctdb);

	cluster_set_ops(&cluster_ctdb_ops);

	return;
	
failed:
	DEBUG(0,("cluster_ctdb_init failed\n"));
	talloc_free(state);
}
