/* 
   ctdb recovery daemon

   Copyright (C) Ronnie Sahlberg  2007

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

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/time.h"
#include "system/network.h"
#include "system/wait.h"
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "dlinklist.h"


struct ban_state {
	struct ctdb_recoverd *rec;
	uint32_t banned_node;
};

/*
  private state of recovery daemon
 */
struct ctdb_recoverd {
	struct ctdb_context *ctdb;
	uint32_t recmaster;
	uint32_t num_active;
	uint32_t num_connected;
	struct ctdb_node_map *nodemap;
	uint32_t last_culprit;
	uint32_t culprit_counter;
	struct timeval first_recover_time;
	struct ban_state **banned_nodes;
	struct timeval priority_time;
	bool need_takeover_run;
	bool need_recovery;
	uint32_t node_flags;
	struct timed_event *send_election_te;
	struct timed_event *election_timeout;
	struct vacuum_info *vacuum_info;
};

#define CONTROL_TIMEOUT() timeval_current_ofs(ctdb->tunable.recover_timeout, 0)
#define MONITOR_TIMEOUT() timeval_current_ofs(ctdb->tunable.recover_interval, 0)


/*
  unban a node
 */
static void ctdb_unban_node(struct ctdb_recoverd *rec, uint32_t pnn)
{
	struct ctdb_context *ctdb = rec->ctdb;

	DEBUG(DEBUG_NOTICE,("Unbanning node %u\n", pnn));

	if (!ctdb_validate_pnn(ctdb, pnn)) {
		DEBUG(DEBUG_ERR,("Bad pnn %u in ctdb_unban_node\n", pnn));
		return;
	}

	/* If we are unbanning a different node then just pass the ban info on */
	if (pnn != ctdb->pnn) {
		TDB_DATA data;
		int ret;
		
		DEBUG(DEBUG_NOTICE,("Unanning remote node %u. Passing the ban request on to the remote node.\n", pnn));

		data.dptr = (uint8_t *)&pnn;
		data.dsize = sizeof(uint32_t);

		ret = ctdb_send_message(ctdb, pnn, CTDB_SRVID_UNBAN_NODE, data);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to unban node %u\n", pnn));
			return;
		}

		return;
	}

	/* make sure we remember we are no longer banned in case 
	   there is an election */
	rec->node_flags &= ~NODE_FLAGS_BANNED;

	DEBUG(DEBUG_INFO,("Clearing ban flag on node %u\n", pnn));
	ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), pnn, 0, NODE_FLAGS_BANNED);

	if (rec->banned_nodes[pnn] == NULL) {
		DEBUG(DEBUG_INFO,("No ban recorded for this node. ctdb_unban_node() request ignored\n"));
		return;
	}

	talloc_free(rec->banned_nodes[pnn]);
	rec->banned_nodes[pnn] = NULL;
}


/*
  called when a ban has timed out
 */
static void ctdb_ban_timeout(struct event_context *ev, struct timed_event *te, struct timeval t, void *p)
{
	struct ban_state *state = talloc_get_type(p, struct ban_state);
	struct ctdb_recoverd *rec = state->rec;
	uint32_t pnn = state->banned_node;

	DEBUG(DEBUG_NOTICE,("Ban timeout. Node %u is now unbanned\n", pnn));
	ctdb_unban_node(rec, pnn);
}

/*
  ban a node for a period of time
 */
static void ctdb_ban_node(struct ctdb_recoverd *rec, uint32_t pnn, uint32_t ban_time)
{
	struct ctdb_context *ctdb = rec->ctdb;

	DEBUG(DEBUG_NOTICE,("Banning node %u for %u seconds\n", pnn, ban_time));

	if (!ctdb_validate_pnn(ctdb, pnn)) {
		DEBUG(DEBUG_ERR,("Bad pnn %u in ctdb_ban_node\n", pnn));
		return;
	}

	if (0 == ctdb->tunable.enable_bans) {
		DEBUG(DEBUG_INFO,("Bans are disabled - ignoring ban of node %u\n", pnn));
		return;
	}

	/* If we are banning a different node then just pass the ban info on */
	if (pnn != ctdb->pnn) {
		struct ctdb_ban_info b;
		TDB_DATA data;
		int ret;
		
		DEBUG(DEBUG_NOTICE,("Banning remote node %u for %u seconds. Passing the ban request on to the remote node.\n", pnn, ban_time));

		b.pnn = pnn;
		b.ban_time = ban_time;

		data.dptr = (uint8_t *)&b;
		data.dsize = sizeof(b);

		ret = ctdb_send_message(ctdb, pnn, CTDB_SRVID_BAN_NODE, data);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to ban node %u\n", pnn));
			return;
		}

		return;
	}

	DEBUG(DEBUG_NOTICE,("self ban - lowering our election priority\n"));
	ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), pnn, NODE_FLAGS_BANNED, 0);

	/* banning ourselves - lower our election priority */
	rec->priority_time = timeval_current();

	/* make sure we remember we are banned in case there is an 
	   election */
	rec->node_flags |= NODE_FLAGS_BANNED;

	if (rec->banned_nodes[pnn] != NULL) {
		DEBUG(DEBUG_NOTICE,("Re-banning an already banned node. Remove previous ban and set a new ban.\n"));		
		talloc_free(rec->banned_nodes[pnn]);
		rec->banned_nodes[pnn] = NULL;
	}

	rec->banned_nodes[pnn] = talloc(rec->banned_nodes, struct ban_state);
	CTDB_NO_MEMORY_FATAL(ctdb, rec->banned_nodes[pnn]);

	rec->banned_nodes[pnn]->rec = rec;
	rec->banned_nodes[pnn]->banned_node = pnn;

	if (ban_time != 0) {
		event_add_timed(ctdb->ev, rec->banned_nodes[pnn], 
				timeval_current_ofs(ban_time, 0),
				ctdb_ban_timeout, rec->banned_nodes[pnn]);
	}
}

enum monitor_result { MONITOR_OK, MONITOR_RECOVERY_NEEDED, MONITOR_ELECTION_NEEDED, MONITOR_FAILED};


/*
  run the "recovered" eventscript on all nodes
 */
static int run_recovered_eventscript(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, const char *caller)
{
	TALLOC_CTX *tmp_ctx;
	uint32_t *nodes;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_END_RECOVERY,
					nodes,
					CONTROL_TIMEOUT(), false, tdb_null,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to run the 'recovered' event when called from %s\n", caller));

		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  remember the trouble maker
 */
static void ctdb_set_culprit(struct ctdb_recoverd *rec, uint32_t culprit)
{
	struct ctdb_context *ctdb = rec->ctdb;

	if (rec->last_culprit != culprit ||
	    timeval_elapsed(&rec->first_recover_time) > ctdb->tunable.recovery_grace_period) {
		DEBUG(DEBUG_NOTICE,("New recovery culprit %u\n", culprit));
		/* either a new node is the culprit, or we've decided to forgive them */
		rec->last_culprit = culprit;
		rec->first_recover_time = timeval_current();
		rec->culprit_counter = 0;
	}
	rec->culprit_counter++;
}


/* this callback is called for every node that failed to execute the
   start recovery event
*/
static void startrecovery_fail_callback(struct ctdb_context *ctdb, uint32_t node_pnn, int32_t res, TDB_DATA outdata, void *callback_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(callback_data, struct ctdb_recoverd);

	DEBUG(DEBUG_ERR, (__location__ " Node %u failed the startrecovery event. Setting it as recovery fail culprit\n", node_pnn));

	ctdb_set_culprit(rec, node_pnn);
}

/*
  run the "startrecovery" eventscript on all nodes
 */
static int run_startrecovery_eventscript(struct ctdb_recoverd *rec, struct ctdb_node_map *nodemap)
{
	TALLOC_CTX *tmp_ctx;
	uint32_t *nodes;
	struct ctdb_context *ctdb = rec->ctdb;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_START_RECOVERY,
					nodes,
					CONTROL_TIMEOUT(), false, tdb_null,
					NULL,
					startrecovery_fail_callback,
					rec) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to run the 'startrecovery' event. Recovery failed.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

static void async_getcap_callback(struct ctdb_context *ctdb, uint32_t node_pnn, int32_t res, TDB_DATA outdata, void *callback_data)
{
	if ( (outdata.dsize != sizeof(uint32_t)) || (outdata.dptr == NULL) ) {
		DEBUG(DEBUG_ERR, (__location__ " Invalid lenght/pointer for getcap callback : %u %p\n",  (unsigned)outdata.dsize, outdata.dptr));
		return;
	}
	if (node_pnn < ctdb->num_nodes) {
		ctdb->nodes[node_pnn]->capabilities = *((uint32_t *)outdata.dptr);
	}
}

/*
  update the node capabilities for all connected nodes
 */
static int update_capabilities(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap)
{
	uint32_t *nodes;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_GET_CAPABILITIES,
					nodes, CONTROL_TIMEOUT(),
					false, tdb_null,
					async_getcap_callback, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to read node capabilities.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  change recovery mode on all nodes
 */
static int set_recovery_mode(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, uint32_t rec_mode)
{
	TDB_DATA data;
	uint32_t *nodes;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	/* freeze all nodes */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (rec_mode == CTDB_RECOVERY_ACTIVE) {
		if (ctdb_client_async_control(ctdb, CTDB_CONTROL_FREEZE,
						nodes, CONTROL_TIMEOUT(),
						false, tdb_null,
						NULL, NULL,
						NULL) != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to freeze nodes. Recovery failed.\n"));
			talloc_free(tmp_ctx);
			return -1;
		}
	}


	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&rec_mode;

	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_SET_RECMODE,
					nodes, CONTROL_TIMEOUT(),
					false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery mode. Recovery failed.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  change recovery master on all node
 */
static int set_recovery_master(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, uint32_t pnn)
{
	TDB_DATA data;
	TALLOC_CTX *tmp_ctx;
	uint32_t *nodes;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&pnn;

	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_SET_RECMASTER,
					nodes,
					CONTROL_TIMEOUT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recmaster. Recovery failed.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}


/*
  ensure all other nodes have attached to any databases that we have
 */
static int create_missing_remote_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
					   uint32_t pnn, struct ctdb_dbid_map *dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, db, ret;
	struct ctdb_dbid_map *remote_dbmap;

	/* verify that all other nodes have all our databases */
	for (j=0; j<nodemap->num; j++) {
		/* we dont need to ourself ourselves */
		if (nodemap->nodes[j].pnn == pnn) {
			continue;
		}
		/* dont check nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					 mem_ctx, &remote_dbmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to get dbids from node %u\n", pnn));
			return -1;
		}

		/* step through all local databases */
		for (db=0; db<dbmap->num;db++) {
			const char *name;


			for (i=0;i<remote_dbmap->num;i++) {
				if (dbmap->dbs[db].dbid == remote_dbmap->dbs[i].dbid) {
					break;
				}
			}
			/* the remote node already have this database */
			if (i!=remote_dbmap->num) {
				continue;
			}
			/* ok so we need to create this database */
			ctdb_ctrl_getdbname(ctdb, CONTROL_TIMEOUT(), pnn, dbmap->dbs[db].dbid, 
					    mem_ctx, &name);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Unable to get dbname from node %u\n", pnn));
				return -1;
			}
			ctdb_ctrl_createdb(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					   mem_ctx, name, dbmap->dbs[db].persistent);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Unable to create remote db:%s\n", name));
				return -1;
			}
		}
	}

	return 0;
}


/*
  ensure we are attached to any databases that anyone else is attached to
 */
static int create_missing_local_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
					  uint32_t pnn, struct ctdb_dbid_map **dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, db, ret;
	struct ctdb_dbid_map *remote_dbmap;

	/* verify that we have all database any other node has */
	for (j=0; j<nodemap->num; j++) {
		/* we dont need to ourself ourselves */
		if (nodemap->nodes[j].pnn == pnn) {
			continue;
		}
		/* dont check nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					 mem_ctx, &remote_dbmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to get dbids from node %u\n", pnn));
			return -1;
		}

		/* step through all databases on the remote node */
		for (db=0; db<remote_dbmap->num;db++) {
			const char *name;

			for (i=0;i<(*dbmap)->num;i++) {
				if (remote_dbmap->dbs[db].dbid == (*dbmap)->dbs[i].dbid) {
					break;
				}
			}
			/* we already have this db locally */
			if (i!=(*dbmap)->num) {
				continue;
			}
			/* ok so we need to create this database and
			   rebuild dbmap
			 */
			ctdb_ctrl_getdbname(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					    remote_dbmap->dbs[db].dbid, mem_ctx, &name);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Unable to get dbname from node %u\n", 
					  nodemap->nodes[j].pnn));
				return -1;
			}
			ctdb_ctrl_createdb(ctdb, CONTROL_TIMEOUT(), pnn, mem_ctx, name, 
					   remote_dbmap->dbs[db].persistent);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Unable to create local db:%s\n", name));
				return -1;
			}
			ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), pnn, mem_ctx, dbmap);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Unable to reread dbmap on node %u\n", pnn));
				return -1;
			}
		}
	}

	return 0;
}


/*
  pull the remote database contents from one node into the recdb
 */
static int pull_one_remote_database(struct ctdb_context *ctdb, uint32_t srcnode, 
				    struct tdb_wrap *recdb, uint32_t dbid)
{
	int ret;
	TDB_DATA outdata;
	struct ctdb_marshall_buffer *reply;
	struct ctdb_rec_data *rec;
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(recdb);

	ret = ctdb_ctrl_pulldb(ctdb, srcnode, dbid, CTDB_LMASTER_ANY, tmp_ctx,
			       CONTROL_TIMEOUT(), &outdata);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to copy db from node %u\n", srcnode));
		talloc_free(tmp_ctx);
		return -1;
	}

	reply = (struct ctdb_marshall_buffer *)outdata.dptr;

	if (outdata.dsize < offsetof(struct ctdb_marshall_buffer, data)) {
		DEBUG(DEBUG_ERR,(__location__ " invalid data in pulldb reply\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	
	rec = (struct ctdb_rec_data *)&reply->data[0];
	
	for (i=0;
	     i<reply->count;
	     rec = (struct ctdb_rec_data *)(rec->length + (uint8_t *)rec), i++) {
		TDB_DATA key, data;
		struct ctdb_ltdb_header *hdr;
		TDB_DATA existing;
		
		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;
		
		hdr = (struct ctdb_ltdb_header *)data.dptr;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record\n"));
			talloc_free(tmp_ctx);
			return -1;
		}

		/* fetch the existing record, if any */
		existing = tdb_fetch(recdb->tdb, key);
		
		if (existing.dptr != NULL) {
			struct ctdb_ltdb_header header;
			if (existing.dsize < sizeof(struct ctdb_ltdb_header)) {
				DEBUG(DEBUG_CRIT,(__location__ " Bad record size %u from node %u\n", 
					 (unsigned)existing.dsize, srcnode));
				free(existing.dptr);
				talloc_free(tmp_ctx);
				return -1;
			}
			header = *(struct ctdb_ltdb_header *)existing.dptr;
			free(existing.dptr);
			if (!(header.rsn < hdr->rsn ||
			      (header.dmaster != ctdb->recovery_master && header.rsn == hdr->rsn))) {
				continue;
			}
		}
		
		if (tdb_store(recdb->tdb, key, data, TDB_REPLACE) != 0) {
			DEBUG(DEBUG_CRIT,(__location__ " Failed to store record\n"));
			talloc_free(tmp_ctx);
			return -1;				
		}
	}

	talloc_free(tmp_ctx);

	return 0;
}

/*
  pull all the remote database contents into the recdb
 */
static int pull_remote_database(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
				struct tdb_wrap *recdb, uint32_t dbid)
{
	int j;

	/* pull all records from all other nodes across onto this node
	   (this merges based on rsn)
	*/
	for (j=0; j<nodemap->num; j++) {
		/* dont merge from nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (pull_one_remote_database(ctdb, nodemap->nodes[j].pnn, recdb, dbid) != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to pull remote database from node %u\n", 
				 nodemap->nodes[j].pnn));
			return -1;
		}
	}
	
	return 0;
}


/*
  update flags on all active nodes
 */
static int update_flags_on_all_nodes(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, uint32_t pnn, uint32_t flags)
{
	int ret;

	ret = ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), pnn, flags, ~flags);
		if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to update nodeflags on remote nodes\n"));
		return -1;
	}

	return 0;
}

/*
  ensure all nodes have the same vnnmap we do
 */
static int update_vnnmap_on_all_nodes(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
				      uint32_t pnn, struct ctdb_vnn_map *vnnmap, TALLOC_CTX *mem_ctx)
{
	int j, ret;

	/* push the new vnn map out to all the nodes */
	for (j=0; j<nodemap->num; j++) {
		/* dont push to nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_setvnnmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, mem_ctx, vnnmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to set vnnmap for node %u\n", pnn));
			return -1;
		}
	}

	return 0;
}


/*
  handler for when the admin bans a node
*/
static void ban_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(private_data, struct ctdb_recoverd);
	struct ctdb_ban_info *b = (struct ctdb_ban_info *)data.dptr;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);

	if (data.dsize != sizeof(*b)) {
		DEBUG(DEBUG_ERR,("Bad data in ban_handler\n"));
		talloc_free(mem_ctx);
		return;
	}

	if (b->pnn != ctdb->pnn) {
		DEBUG(DEBUG_ERR,("Got a ban request for pnn:%u but our pnn is %u. Ignoring ban request\n", b->pnn, ctdb->pnn));
		return;
	}

	DEBUG(DEBUG_NOTICE,("Node %u has been banned for %u seconds\n", 
		 b->pnn, b->ban_time));

	ctdb_ban_node(rec, b->pnn, b->ban_time);
	talloc_free(mem_ctx);
}

/*
  handler for when the admin unbans a node
*/
static void unban_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			  TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(private_data, struct ctdb_recoverd);
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);
	uint32_t pnn;

	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR,("Bad data in unban_handler\n"));
		talloc_free(mem_ctx);
		return;
	}
	pnn = *(uint32_t *)data.dptr;

	if (pnn != ctdb->pnn) {
		DEBUG(DEBUG_ERR,("Got an unban request for pnn:%u but our pnn is %u. Ignoring unban request\n", pnn, ctdb->pnn));
		return;
	}

	DEBUG(DEBUG_NOTICE,("Node %u has been unbanned.\n", pnn));
	ctdb_unban_node(rec, pnn);
	talloc_free(mem_ctx);
}


struct vacuum_info {
	struct vacuum_info *next, *prev;
	struct ctdb_recoverd *rec;
	uint32_t srcnode;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_marshall_buffer *recs;
	struct ctdb_rec_data *r;
};

static void vacuum_fetch_next(struct vacuum_info *v);

/*
  called when a vacuum fetch has completed - just free it and do the next one
 */
static void vacuum_fetch_callback(struct ctdb_client_call_state *state)
{
	struct vacuum_info *v = talloc_get_type(state->async.private_data, struct vacuum_info);
	talloc_free(state);
	vacuum_fetch_next(v);
}


/*
  process the next element from the vacuum list
*/
static void vacuum_fetch_next(struct vacuum_info *v)
{
	struct ctdb_call call;
	struct ctdb_rec_data *r;

	while (v->recs->count) {
		struct ctdb_client_call_state *state;
		TDB_DATA data;
		struct ctdb_ltdb_header *hdr;

		ZERO_STRUCT(call);
		call.call_id = CTDB_NULL_FUNC;
		call.flags = CTDB_IMMEDIATE_MIGRATION;

		r = v->r;
		v->r = (struct ctdb_rec_data *)(r->length + (uint8_t *)r);
		v->recs->count--;

		call.key.dptr = &r->data[0];
		call.key.dsize = r->keylen;

		/* ensure we don't block this daemon - just skip a record if we can't get
		   the chainlock */
		if (tdb_chainlock_nonblock(v->ctdb_db->ltdb->tdb, call.key) != 0) {
			continue;
		}

		data = tdb_fetch(v->ctdb_db->ltdb->tdb, call.key);
		if (data.dptr == NULL) {
			tdb_chainunlock(v->ctdb_db->ltdb->tdb, call.key);
			continue;
		}

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			free(data.dptr);
			tdb_chainunlock(v->ctdb_db->ltdb->tdb, call.key);
			continue;
		}
		
		hdr = (struct ctdb_ltdb_header *)data.dptr;
		if (hdr->dmaster == v->rec->ctdb->pnn) {
			/* its already local */
			free(data.dptr);
			tdb_chainunlock(v->ctdb_db->ltdb->tdb, call.key);
			continue;
		}

		free(data.dptr);

		state = ctdb_call_send(v->ctdb_db, &call);
		tdb_chainunlock(v->ctdb_db->ltdb->tdb, call.key);
		if (state == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to setup vacuum fetch call\n"));
			talloc_free(v);
			return;
		}
		state->async.fn = vacuum_fetch_callback;
		state->async.private_data = v;
		return;
	}

	talloc_free(v);
}


/*
  destroy a vacuum info structure
 */
static int vacuum_info_destructor(struct vacuum_info *v)
{
	DLIST_REMOVE(v->rec->vacuum_info, v);
	return 0;
}


/*
  handler for vacuum fetch
*/
static void vacuum_fetch_handler(struct ctdb_context *ctdb, uint64_t srvid, 
				 TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(private_data, struct ctdb_recoverd);
	struct ctdb_marshall_buffer *recs;
	int ret, i;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	const char *name;
	struct ctdb_dbid_map *dbmap=NULL;
	bool persistent = false;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_rec_data *r;
	uint32_t srcnode;
	struct vacuum_info *v;

	recs = (struct ctdb_marshall_buffer *)data.dptr;
	r = (struct ctdb_rec_data *)&recs->data[0];

	if (recs->count == 0) {
		talloc_free(tmp_ctx);
		return;
	}

	srcnode = r->reqid;

	for (v=rec->vacuum_info;v;v=v->next) {
		if (srcnode == v->srcnode && recs->db_id == v->ctdb_db->db_id) {
			/* we're already working on records from this node */
			talloc_free(tmp_ctx);
			return;
		}
	}

	/* work out if the database is persistent */
	ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, tmp_ctx, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get dbids from local node\n"));
		talloc_free(tmp_ctx);
		return;
	}

	for (i=0;i<dbmap->num;i++) {
		if (dbmap->dbs[i].dbid == recs->db_id) {
			persistent = dbmap->dbs[i].persistent;
			break;
		}
	}
	if (i == dbmap->num) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to find db_id 0x%x on local node\n", recs->db_id));
		talloc_free(tmp_ctx);
		return;		
	}

	/* find the name of this database */
	if (ctdb_ctrl_getdbname(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, recs->db_id, tmp_ctx, &name) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get name of db 0x%x\n", recs->db_id));
		talloc_free(tmp_ctx);
		return;
	}

	/* attach to it */
	ctdb_db = ctdb_attach(ctdb, name, persistent, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to attach to database '%s'\n", name));
		talloc_free(tmp_ctx);
		return;
	}

	v = talloc_zero(rec, struct vacuum_info);
	if (v == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Out of memory\n"));
		talloc_free(tmp_ctx);
		return;
	}

	v->rec = rec;
	v->srcnode = srcnode;
	v->ctdb_db = ctdb_db;
	v->recs = talloc_memdup(v, recs, data.dsize);
	if (v->recs == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Out of memory\n"));
		talloc_free(v);
		talloc_free(tmp_ctx);
		return;		
	}
	v->r = 	(struct ctdb_rec_data *)&v->recs->data[0];

	DLIST_ADD(rec->vacuum_info, v);

	talloc_set_destructor(v, vacuum_info_destructor);

	vacuum_fetch_next(v);
	talloc_free(tmp_ctx);
}


/*
  called when ctdb_wait_timeout should finish
 */
static void ctdb_wait_handler(struct event_context *ev, struct timed_event *te, 
			      struct timeval yt, void *p)
{
	uint32_t *timed_out = (uint32_t *)p;
	(*timed_out) = 1;
}

/*
  wait for a given number of seconds
 */
static void ctdb_wait_timeout(struct ctdb_context *ctdb, uint32_t secs)
{
	uint32_t timed_out = 0;
	event_add_timed(ctdb->ev, ctdb, timeval_current_ofs(secs, 0), ctdb_wait_handler, &timed_out);
	while (!timed_out) {
		event_loop_once(ctdb->ev);
	}
}

/*
  called when an election times out (ends)
 */
static void ctdb_election_timeout(struct event_context *ev, struct timed_event *te, 
				  struct timeval t, void *p)
{
	struct ctdb_recoverd *rec = talloc_get_type(p, struct ctdb_recoverd);
	rec->election_timeout = NULL;
}


/*
  wait for an election to finish. It finished election_timeout seconds after
  the last election packet is received
 */
static void ctdb_wait_election(struct ctdb_recoverd *rec)
{
	struct ctdb_context *ctdb = rec->ctdb;
	while (rec->election_timeout) {
		event_loop_once(ctdb->ev);
	}
}

/*
  Update our local flags from all remote connected nodes. 
  This is only run when we are or we belive we are the recovery master
 */
static int update_local_flags(struct ctdb_recoverd *rec, struct ctdb_node_map *nodemap)
{
	int j;
	struct ctdb_context *ctdb = rec->ctdb;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);

	/* get the nodemap for all active remote nodes and verify
	   they are the same as for this node
	 */
	for (j=0; j<nodemap->num; j++) {
		struct ctdb_node_map *remote_nodemap=NULL;
		int ret;

		if (nodemap->nodes[j].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}
		if (nodemap->nodes[j].pnn == ctdb->pnn) {
			continue;
		}

		ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					   mem_ctx, &remote_nodemap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to get nodemap from remote node %u\n", 
				  nodemap->nodes[j].pnn));
			ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
			talloc_free(mem_ctx);
			return MONITOR_FAILED;
		}
		if (nodemap->nodes[j].flags != remote_nodemap->nodes[j].flags) {
			int ban_changed = (nodemap->nodes[j].flags ^ remote_nodemap->nodes[j].flags) & NODE_FLAGS_BANNED;

			if (ban_changed) {
				DEBUG(DEBUG_NOTICE,("Remote node %u had different BANNED flags 0x%x, local had 0x%x - trigger a re-election\n",
				nodemap->nodes[j].pnn,
				remote_nodemap->nodes[j].flags,
				nodemap->nodes[j].flags));
			}

			/* We should tell our daemon about this so it
			   updates its flags or else we will log the same 
			   message again in the next iteration of recovery.
			   Since we are the recovery master we can just as
			   well update the flags on all nodes.
			*/
			ret = ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, nodemap->nodes[j].flags, ~nodemap->nodes[j].flags);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Unable to update nodeflags on remote nodes\n"));
				return -1;
			}

			/* Update our local copy of the flags in the recovery
			   daemon.
			*/
			DEBUG(DEBUG_NOTICE,("Remote node %u had flags 0x%x, local had 0x%x - updating local\n",
				 nodemap->nodes[j].pnn, remote_nodemap->nodes[j].flags,
				 nodemap->nodes[j].flags));
			nodemap->nodes[j].flags = remote_nodemap->nodes[j].flags;

			/* If the BANNED flag has changed for the node
			   this is a good reason to do a new election.
			 */
			if (ban_changed) {
				talloc_free(mem_ctx);
				return MONITOR_ELECTION_NEEDED;
			}

		}
		talloc_free(remote_nodemap);
	}
	talloc_free(mem_ctx);
	return MONITOR_OK;
}


/* Create a new random generation ip. 
   The generation id can not be the INVALID_GENERATION id
*/
static uint32_t new_generation(void)
{
	uint32_t generation;

	while (1) {
		generation = random();

		if (generation != INVALID_GENERATION) {
			break;
		}
	}

	return generation;
}


/*
  create a temporary working database
 */
static struct tdb_wrap *create_recdb(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx)
{
	char *name;
	struct tdb_wrap *recdb;
	unsigned tdb_flags;

	/* open up the temporary recovery database */
	name = talloc_asprintf(mem_ctx, "%s/recdb.tdb", ctdb->db_directory);
	if (name == NULL) {
		return NULL;
	}
	unlink(name);

	tdb_flags = TDB_NOLOCK;
	if (!ctdb->do_setsched) {
		tdb_flags |= TDB_NOMMAP;
	}

	recdb = tdb_wrap_open(mem_ctx, name, ctdb->tunable.database_hash_size, 
			      tdb_flags, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (recdb == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to create temp recovery database '%s'\n", name));
	}

	talloc_free(name);

	return recdb;
}


/* 
   a traverse function for pulling all relevent records from recdb
 */
struct recdb_data {
	struct ctdb_context *ctdb;
	struct ctdb_marshall_buffer *recdata;
	uint32_t len;
	bool failed;
};

static int traverse_recdb(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct recdb_data *params = (struct recdb_data *)p;
	struct ctdb_rec_data *rec;
	struct ctdb_ltdb_header *hdr;

	/* skip empty records */
	if (data.dsize <= sizeof(struct ctdb_ltdb_header)) {
		return 0;
	}

	/* update the dmaster field to point to us */
	hdr = (struct ctdb_ltdb_header *)data.dptr;
	hdr->dmaster = params->ctdb->pnn;

	/* add the record to the blob ready to send to the nodes */
	rec = ctdb_marshall_record(params->recdata, 0, key, NULL, data);
	if (rec == NULL) {
		params->failed = true;
		return -1;
	}
	params->recdata = talloc_realloc_size(NULL, params->recdata, rec->length + params->len);
	if (params->recdata == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to expand recdata to %u (%u records)\n", 
			 rec->length + params->len, params->recdata->count));
		params->failed = true;
		return -1;
	}
	params->recdata->count++;
	memcpy(params->len+(uint8_t *)params->recdata, rec, rec->length);
	params->len += rec->length;
	talloc_free(rec);

	return 0;
}

/*
  push the recdb database out to all nodes
 */
static int push_recdb_database(struct ctdb_context *ctdb, uint32_t dbid,
			       struct tdb_wrap *recdb, struct ctdb_node_map *nodemap)
{
	struct recdb_data params;
	struct ctdb_marshall_buffer *recdata;
	TDB_DATA outdata;
	TALLOC_CTX *tmp_ctx;
	uint32_t *nodes;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	recdata = talloc_zero(recdb, struct ctdb_marshall_buffer);
	CTDB_NO_MEMORY(ctdb, recdata);

	recdata->db_id = dbid;

	params.ctdb = ctdb;
	params.recdata = recdata;
	params.len = offsetof(struct ctdb_marshall_buffer, data);
	params.failed = false;

	if (tdb_traverse_read(recdb->tdb, traverse_recdb, &params) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to traverse recdb database\n"));
		talloc_free(params.recdata);
		talloc_free(tmp_ctx);
		return -1;
	}

	if (params.failed) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to traverse recdb database\n"));
		talloc_free(params.recdata);
		talloc_free(tmp_ctx);
		return -1;		
	}

	recdata = params.recdata;

	outdata.dptr = (void *)recdata;
	outdata.dsize = params.len;

	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_PUSH_DB,
					nodes,
					CONTROL_TIMEOUT(), false, outdata,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to push recdb records to nodes for db 0x%x\n", dbid));
		talloc_free(recdata);
		talloc_free(tmp_ctx);
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - pushed remote database 0x%x of size %u\n", 
		  dbid, recdata->count));

	talloc_free(recdata);
	talloc_free(tmp_ctx);

	return 0;
}


/*
  go through a full recovery on one database 
 */
static int recover_database(struct ctdb_recoverd *rec, 
			    TALLOC_CTX *mem_ctx,
			    uint32_t dbid,
			    uint32_t pnn, 
			    struct ctdb_node_map *nodemap,
			    uint32_t transaction_id)
{
	struct tdb_wrap *recdb;
	int ret;
	struct ctdb_context *ctdb = rec->ctdb;
	TDB_DATA data;
	struct ctdb_control_wipe_database w;
	uint32_t *nodes;

	recdb = create_recdb(ctdb, mem_ctx);
	if (recdb == NULL) {
		return -1;
	}

	/* pull all remote databases onto the recdb */
	ret = pull_remote_database(ctdb, nodemap, recdb, dbid);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to pull remote database 0x%x\n", dbid));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - pulled remote database 0x%x\n", dbid));

	/* wipe all the remote databases. This is safe as we are in a transaction */
	w.db_id = dbid;
	w.transaction_id = transaction_id;

	data.dptr = (void *)&w;
	data.dsize = sizeof(w);

	nodes = list_of_active_nodes(ctdb, nodemap, recdb, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_WIPE_DATABASE,
					nodes,
					CONTROL_TIMEOUT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to wipe database. Recovery failed.\n"));
		talloc_free(recdb);
		return -1;
	}
	
	/* push out the correct database. This sets the dmaster and skips 
	   the empty records */
	ret = push_recdb_database(ctdb, dbid, recdb, nodemap);
	if (ret != 0) {
		talloc_free(recdb);
		return -1;
	}

	/* all done with this database */
	talloc_free(recdb);

	return 0;
}

/*
  reload the nodes file 
*/
static void reload_nodes_file(struct ctdb_context *ctdb)
{
	ctdb->nodes = NULL;
	ctdb_load_nodes_file(ctdb);
}

	
/*
  we are the recmaster, and recovery is needed - start a recovery run
 */
static int do_recovery(struct ctdb_recoverd *rec, 
		       TALLOC_CTX *mem_ctx, uint32_t pnn,
		       struct ctdb_node_map *nodemap, struct ctdb_vnn_map *vnnmap,
		       int32_t culprit)
{
	struct ctdb_context *ctdb = rec->ctdb;
	int i, j, ret;
	uint32_t generation;
	struct ctdb_dbid_map *dbmap;
	TDB_DATA data;
	uint32_t *nodes;

	DEBUG(DEBUG_NOTICE, (__location__ " Starting do_recovery\n"));

	if (ctdb->num_nodes != nodemap->num) {
		DEBUG(DEBUG_ERR, (__location__ " ctdb->num_nodes (%d) != nodemap->num (%d) reloading nodes file\n", ctdb->num_nodes, nodemap->num));
		reload_nodes_file(ctdb);
		return -1;
	}

	/* if recovery fails, force it again */
	rec->need_recovery = true;

	if (culprit != -1) {
		ctdb_set_culprit(rec, culprit);
	}

	if (rec->culprit_counter > 2*nodemap->num) {
		DEBUG(DEBUG_NOTICE,("Node %u has caused %u recoveries in %.0f seconds - banning it for %u seconds\n",
			 culprit, rec->culprit_counter, timeval_elapsed(&rec->first_recover_time),
			 ctdb->tunable.recovery_ban_period));
		ctdb_ban_node(rec, culprit, ctdb->tunable.recovery_ban_period);
	}

	if (!ctdb_recovery_lock(ctdb, true)) {
		ctdb_set_culprit(rec, pnn);
		DEBUG(DEBUG_ERR,("Unable to get recovery lock - aborting recovery\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery initiated due to problem with node %u\n", culprit));

	/* get a list of all databases */
	ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), pnn, mem_ctx, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get dbids from node :%u\n", pnn));
		return -1;
	}

	/* we do the db creation before we set the recovery mode, so the freeze happens
	   on all databases we will be dealing with. */

	/* verify that we have all the databases any other node has */
	ret = create_missing_local_databases(ctdb, nodemap, pnn, &dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to create missing local databases\n"));
		return -1;
	}

	/* verify that all other nodes have all our databases */
	ret = create_missing_remote_databases(ctdb, nodemap, pnn, dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to create missing remote databases\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - created remote databases\n"));


	/* set recovery mode to active on all nodes */
	ret = set_recovery_mode(ctdb, nodemap, CTDB_RECOVERY_ACTIVE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery mode to active on cluster\n"));
		return -1;
	}

	/* execute the "startrecovery" event script on all nodes */
	ret = run_startrecovery_eventscript(rec, nodemap);
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to run the 'startrecovery' event on cluster\n"));
		return -1;
	}

	/* pick a new generation number */
	generation = new_generation();

	/* change the vnnmap on this node to use the new generation 
	   number but not on any other nodes.
	   this guarantees that if we abort the recovery prematurely
	   for some reason (a node stops responding?)
	   that we can just return immediately and we will reenter
	   recovery shortly again.
	   I.e. we deliberately leave the cluster with an inconsistent
	   generation id to allow us to abort recovery at any stage and
	   just restart it from scratch.
	 */
	vnnmap->generation = generation;
	ret = ctdb_ctrl_setvnnmap(ctdb, CONTROL_TIMEOUT(), pnn, mem_ctx, vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set vnnmap for node %u\n", pnn));
		return -1;
	}

	data.dptr = (void *)&generation;
	data.dsize = sizeof(uint32_t);

	nodes = list_of_active_nodes(ctdb, nodemap, mem_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_TRANSACTION_START,
					nodes,
					CONTROL_TIMEOUT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to start transactions. Recovery failed.\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE,(__location__ " started transactions on all nodes\n"));

	for (i=0;i<dbmap->num;i++) {
		if (recover_database(rec, mem_ctx, dbmap->dbs[i].dbid, pnn, nodemap, generation) != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to recover database 0x%x\n", dbmap->dbs[i].dbid));
			return -1;
		}
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - starting database commits\n"));

	/* commit all the changes */
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_TRANSACTION_COMMIT,
					nodes,
					CONTROL_TIMEOUT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to commit recovery changes. Recovery failed.\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - committed databases\n"));
	

	/* update the capabilities for all nodes */
	ret = update_capabilities(ctdb, nodemap);
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to update node capabilities.\n"));
		return -1;
	}

	/* build a new vnn map with all the currently active and
	   unbanned nodes */
	generation = new_generation();
	vnnmap = talloc(mem_ctx, struct ctdb_vnn_map);
	CTDB_NO_MEMORY(ctdb, vnnmap);
	vnnmap->generation = generation;
	vnnmap->size = 0;
	vnnmap->map = talloc_zero_array(vnnmap, uint32_t, vnnmap->size);
	CTDB_NO_MEMORY(ctdb, vnnmap->map);
	for (i=j=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (!(ctdb->nodes[i]->capabilities & CTDB_CAP_LMASTER)) {
			/* this node can not be an lmaster */
			DEBUG(DEBUG_DEBUG, ("Node %d cant be a LMASTER, skipping it\n", i));
			continue;
		}

		vnnmap->size++;
		vnnmap->map = talloc_realloc(vnnmap, vnnmap->map, uint32_t, vnnmap->size);
		CTDB_NO_MEMORY(ctdb, vnnmap->map);
		vnnmap->map[j++] = nodemap->nodes[i].pnn;

	}
	if (vnnmap->size == 0) {
		DEBUG(DEBUG_NOTICE, ("No suitable lmasters found. Adding local node (recmaster) anyway.\n"));
		vnnmap->size++;
		vnnmap->map = talloc_realloc(vnnmap, vnnmap->map, uint32_t, vnnmap->size);
		CTDB_NO_MEMORY(ctdb, vnnmap->map);
		vnnmap->map[0] = pnn;
	}	

	/* update to the new vnnmap on all nodes */
	ret = update_vnnmap_on_all_nodes(ctdb, nodemap, pnn, vnnmap, mem_ctx);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to update vnnmap on all nodes\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - updated vnnmap\n"));

	/* update recmaster to point to us for all nodes */
	ret = set_recovery_master(ctdb, nodemap, pnn);
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery master\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - updated recmaster\n"));

	/*
	  update all nodes to have the same flags that we have
	 */
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		ret = update_flags_on_all_nodes(ctdb, nodemap, i, nodemap->nodes[i].flags);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to update flags on all nodes for node %d\n", i));
			return -1;
		}
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - updated flags\n"));

	/* disable recovery mode */
	ret = set_recovery_mode(ctdb, nodemap, CTDB_RECOVERY_NORMAL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery mode to normal on cluster\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - disabled recovery mode\n"));

	/*
	  tell nodes to takeover their public IPs
	 */
	rec->need_takeover_run = false;
	ret = ctdb_takeover_run(ctdb, nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to setup public takeover addresses\n"));
		return -1;
	}
	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - takeip finished\n"));

	/* execute the "recovered" event script on all nodes */
	ret = run_recovered_eventscript(ctdb, nodemap, "do_recovery");
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to run the 'recovered' event on cluster. Recovery process failed.\n"));
		return -1;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - finished the recovered event\n"));

	/* send a message to all clients telling them that the cluster 
	   has been reconfigured */
	ctdb_send_message(ctdb, CTDB_BROADCAST_CONNECTED, CTDB_SRVID_RECONFIGURE, tdb_null);

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery complete\n"));

	rec->need_recovery = false;

	/* We just finished a recovery successfully. 
	   We now wait for rerecovery_timeout before we allow 
	   another recovery to take place.
	*/
	DEBUG(DEBUG_NOTICE, (__location__ " New recoveries supressed for the rerecovery timeout\n"));
	ctdb_wait_timeout(ctdb, ctdb->tunable.rerecovery_timeout);
	DEBUG(DEBUG_NOTICE, (__location__ " Rerecovery timeout elapsed. Recovery reactivated.\n"));

	return 0;
}


/*
  elections are won by first checking the number of connected nodes, then
  the priority time, then the pnn
 */
struct election_message {
	uint32_t num_connected;
	struct timeval priority_time;
	uint32_t pnn;
	uint32_t node_flags;
};

/*
  form this nodes election data
 */
static void ctdb_election_data(struct ctdb_recoverd *rec, struct election_message *em)
{
	int ret, i;
	struct ctdb_node_map *nodemap;
	struct ctdb_context *ctdb = rec->ctdb;

	ZERO_STRUCTP(em);

	em->pnn = rec->ctdb->pnn;
	em->priority_time = rec->priority_time;
	em->node_flags = rec->node_flags;

	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, rec, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " unable to get election data\n"));
		return;
	}

	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED)) {
			em->num_connected++;
		}
	}

	/* we shouldnt try to win this election if we cant be a recmaster */
	if ((ctdb->capabilities & CTDB_CAP_RECMASTER) == 0) {
		em->num_connected = 0;
		em->priority_time = timeval_current();
	}

	talloc_free(nodemap);
}

/*
  see if the given election data wins
 */
static bool ctdb_election_win(struct ctdb_recoverd *rec, struct election_message *em)
{
	struct election_message myem;
	int cmp = 0;

	ctdb_election_data(rec, &myem);

	/* we cant win if we dont have the recmaster capability */
	if ((rec->ctdb->capabilities & CTDB_CAP_RECMASTER) == 0) {
		return false;
	}

	/* we cant win if we are banned */
	if (rec->node_flags & NODE_FLAGS_BANNED) {
		return false;
	}	

	/* we will automatically win if the other node is banned */
	if (em->node_flags & NODE_FLAGS_BANNED) {
		return true;
	}

	/* try to use the most connected node */
	if (cmp == 0) {
		cmp = (int)myem.num_connected - (int)em->num_connected;
	}

	/* then the longest running node */
	if (cmp == 0) {
		cmp = timeval_compare(&em->priority_time, &myem.priority_time);
	}

	if (cmp == 0) {
		cmp = (int)myem.pnn - (int)em->pnn;
	}

	return cmp > 0;
}

/*
  send out an election request
 */
static int send_election_request(struct ctdb_recoverd *rec, uint32_t pnn, bool update_recmaster)
{
	int ret;
	TDB_DATA election_data;
	struct election_message emsg;
	uint64_t srvid;
	struct ctdb_context *ctdb = rec->ctdb;

	srvid = CTDB_SRVID_RECOVERY;

	ctdb_election_data(rec, &emsg);

	election_data.dsize = sizeof(struct election_message);
	election_data.dptr  = (unsigned char *)&emsg;


	/* send an election message to all active nodes */
	ctdb_send_message(ctdb, CTDB_BROADCAST_ALL, srvid, election_data);


	/* A new node that is already frozen has entered the cluster.
	   The existing nodes are not frozen and dont need to be frozen
	   until the election has ended and we start the actual recovery
	*/
	if (update_recmaster == true) {
		/* first we assume we will win the election and set 
		   recoverymaster to be ourself on the current node
		 */
		ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(), pnn, pnn);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " failed to send recmaster election request\n"));
			return -1;
		}
	}


	return 0;
}

/*
  this function will unban all nodes in the cluster
*/
static void unban_all_nodes(struct ctdb_context *ctdb)
{
	int ret, i;
	struct ctdb_node_map *nodemap;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " failed to get nodemap to unban all nodes\n"));
		return;
	}

	for (i=0;i<nodemap->num;i++) {
		if ( (!(nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED))
		  && (nodemap->nodes[i].flags & NODE_FLAGS_BANNED) ) {
			ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[i].pnn, 0, NODE_FLAGS_BANNED);
		}
	}

	talloc_free(tmp_ctx);
}


/*
  we think we are winning the election - send a broadcast election request
 */
static void election_send_request(struct event_context *ev, struct timed_event *te, struct timeval t, void *p)
{
	struct ctdb_recoverd *rec = talloc_get_type(p, struct ctdb_recoverd);
	int ret;

	ret = send_election_request(rec, ctdb_get_pnn(rec->ctdb), false);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send election request!\n"));
	}

	talloc_free(rec->send_election_te);
	rec->send_election_te = NULL;
}

/*
  handler for memory dumps
*/
static void mem_dump_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA *dump;
	int ret;
	struct rd_memdump_reply *rd;

	if (data.dsize != sizeof(struct rd_memdump_reply)) {
		DEBUG(DEBUG_ERR, (__location__ " Wrong size of return address.\n"));
		talloc_free(tmp_ctx);
		return;
	}
	rd = (struct rd_memdump_reply *)data.dptr;

	dump = talloc_zero(tmp_ctx, TDB_DATA);
	if (dump == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to allocate memory for memdump\n"));
		talloc_free(tmp_ctx);
		return;
	}
	ret = ctdb_dump_memory(ctdb, dump);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " ctdb_dump_memory() failed\n"));
		talloc_free(tmp_ctx);
		return;
	}

DEBUG(DEBUG_ERR, ("recovery master memory dump\n"));		

	ret = ctdb_send_message(ctdb, rd->pnn, rd->srvid, *dump);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send rd memdump reply message\n"));
		talloc_free(tmp_ctx);
		return;
	}

	talloc_free(tmp_ctx);
}

/*
  handler for recovery master elections
*/
static void election_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(private_data, struct ctdb_recoverd);
	int ret;
	struct election_message *em = (struct election_message *)data.dptr;
	TALLOC_CTX *mem_ctx;

	/* we got an election packet - update the timeout for the election */
	talloc_free(rec->election_timeout);
	rec->election_timeout = event_add_timed(ctdb->ev, ctdb, 
						timeval_current_ofs(ctdb->tunable.election_timeout, 0), 
						ctdb_election_timeout, rec);

	mem_ctx = talloc_new(ctdb);

	/* someone called an election. check their election data
	   and if we disagree and we would rather be the elected node, 
	   send a new election message to all other nodes
	 */
	if (ctdb_election_win(rec, em)) {
		if (!rec->send_election_te) {
			rec->send_election_te = event_add_timed(ctdb->ev, rec, 
								timeval_current_ofs(0, 500000),
								election_send_request, rec);
		}
		talloc_free(mem_ctx);
		/*unban_all_nodes(ctdb);*/
		return;
	}
	
	/* we didn't win */
	talloc_free(rec->send_election_te);
	rec->send_election_te = NULL;

	/* release the recmaster lock */
	if (em->pnn != ctdb->pnn &&
	    ctdb->recovery_lock_fd != -1) {
		close(ctdb->recovery_lock_fd);
		ctdb->recovery_lock_fd = -1;
		unban_all_nodes(ctdb);
	}

	/* ok, let that guy become recmaster then */
	ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(), ctdb_get_pnn(ctdb), em->pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " failed to send recmaster election request"));
		talloc_free(mem_ctx);
		return;
	}

	/* release any bans */
	rec->last_culprit = (uint32_t)-1;
	talloc_free(rec->banned_nodes);
	rec->banned_nodes = talloc_zero_array(rec, struct ban_state *, ctdb->num_nodes);
	CTDB_NO_MEMORY_FATAL(ctdb, rec->banned_nodes);

	talloc_free(mem_ctx);
	return;
}


/*
  force the start of the election process
 */
static void force_election(struct ctdb_recoverd *rec, uint32_t pnn, 
			   struct ctdb_node_map *nodemap)
{
	int ret;
	struct ctdb_context *ctdb = rec->ctdb;

	/* set all nodes to recovery mode to stop all internode traffic */
	ret = set_recovery_mode(ctdb, nodemap, CTDB_RECOVERY_ACTIVE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery mode to active on cluster\n"));
		return;
	}

	talloc_free(rec->election_timeout);
	rec->election_timeout = event_add_timed(ctdb->ev, ctdb, 
						timeval_current_ofs(ctdb->tunable.election_timeout, 0), 
						ctdb_election_timeout, rec);

	ret = send_election_request(rec, pnn, true);
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " failed to initiate recmaster election"));
		return;
	}

	/* wait for a few seconds to collect all responses */
	ctdb_wait_election(rec);
}



/*
  handler for when a node changes its flags
*/
static void monitor_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			    TDB_DATA data, void *private_data)
{
	int ret;
	struct ctdb_node_flag_change *c = (struct ctdb_node_flag_change *)data.dptr;
	struct ctdb_node_map *nodemap=NULL;
	TALLOC_CTX *tmp_ctx;
	uint32_t changed_flags;
	int i;
	struct ctdb_recoverd *rec = talloc_get_type(private_data, struct ctdb_recoverd);

	if (data.dsize != sizeof(*c)) {
		DEBUG(DEBUG_ERR,(__location__ "Invalid data in ctdb_node_flag_change\n"));
		return;
	}

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY_VOID(ctdb, tmp_ctx);

	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ "ctdb_ctrl_getnodemap failed in monitor_handler\n"));
		talloc_free(tmp_ctx);
		return;		
	}


	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].pnn == c->pnn) break;
	}

	if (i == nodemap->num) {
		DEBUG(DEBUG_CRIT,(__location__ "Flag change for non-existant node %u\n", c->pnn));
		talloc_free(tmp_ctx);
		return;
	}

	changed_flags = c->old_flags ^ c->new_flags;

	if (nodemap->nodes[i].flags != c->new_flags) {
		DEBUG(DEBUG_NOTICE,("Node %u has changed flags - now 0x%x  was 0x%x\n", c->pnn, c->new_flags, c->old_flags));
	}

	nodemap->nodes[i].flags = c->new_flags;

	ret = ctdb_ctrl_getrecmaster(ctdb, tmp_ctx, CONTROL_TIMEOUT(), 
				     CTDB_CURRENT_NODE, &ctdb->recovery_master);

	if (ret == 0) {
		ret = ctdb_ctrl_getrecmode(ctdb, tmp_ctx, CONTROL_TIMEOUT(), 
					   CTDB_CURRENT_NODE, &ctdb->recovery_mode);
	}
	
	if (ret == 0 &&
	    ctdb->recovery_master == ctdb->pnn &&
	    ctdb->recovery_mode == CTDB_RECOVERY_NORMAL) {
		/* Only do the takeover run if the perm disabled or unhealthy
		   flags changed since these will cause an ip failover but not
		   a recovery.
		   If the node became disconnected or banned this will also
		   lead to an ip address failover but that is handled 
		   during recovery
		*/
		if (changed_flags & NODE_FLAGS_DISABLED) {
			rec->need_takeover_run = true;
		}
	}

	talloc_free(tmp_ctx);
}

/*
  handler for when we need to push out flag changes ot all other nodes
*/
static void push_flags_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			    TDB_DATA data, void *private_data)
{
	int ret;
	struct ctdb_node_flag_change *c = (struct ctdb_node_flag_change *)data.dptr;

	ret = ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), c->pnn, c->new_flags, ~c->new_flags);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to update nodeflags on remote nodes\n"));
	}
}


struct verify_recmode_normal_data {
	uint32_t count;
	enum monitor_result status;
};

static void verify_recmode_normal_callback(struct ctdb_client_control_state *state)
{
	struct verify_recmode_normal_data *rmdata = talloc_get_type(state->async.private_data, struct verify_recmode_normal_data);


	/* one more node has responded with recmode data*/
	rmdata->count--;

	/* if we failed to get the recmode, then return an error and let
	   the main loop try again.
	*/
	if (state->state != CTDB_CONTROL_DONE) {
		if (rmdata->status == MONITOR_OK) {
			rmdata->status = MONITOR_FAILED;
		}
		return;
	}

	/* if we got a response, then the recmode will be stored in the
	   status field
	*/
	if (state->status != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_NOTICE, (__location__ " Node:%u was in recovery mode. Restart recovery process\n", state->c->hdr.destnode));
		rmdata->status = MONITOR_RECOVERY_NEEDED;
	}

	return;
}


/* verify that all nodes are in normal recovery mode */
static enum monitor_result verify_recmode(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap)
{
	struct verify_recmode_normal_data *rmdata;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);
	struct ctdb_client_control_state *state;
	enum monitor_result status;
	int j;
	
	rmdata = talloc(mem_ctx, struct verify_recmode_normal_data);
	CTDB_NO_MEMORY_FATAL(ctdb, rmdata);
	rmdata->count  = 0;
	rmdata->status = MONITOR_OK;

	/* loop over all active nodes and send an async getrecmode call to 
	   them*/
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		state = ctdb_ctrl_getrecmode_send(ctdb, mem_ctx, 
					CONTROL_TIMEOUT(), 
					nodemap->nodes[j].pnn);
		if (state == NULL) {
			/* we failed to send the control, treat this as 
			   an error and try again next iteration
			*/			
			DEBUG(DEBUG_ERR,("Failed to call ctdb_ctrl_getrecmode_send during monitoring\n"));
			talloc_free(mem_ctx);
			return MONITOR_FAILED;
		}

		/* set up the callback functions */
		state->async.fn = verify_recmode_normal_callback;
		state->async.private_data = rmdata;

		/* one more control to wait for to complete */
		rmdata->count++;
	}


	/* now wait for up to the maximum number of seconds allowed
	   or until all nodes we expect a response from has replied
	*/
	while (rmdata->count > 0) {
		event_loop_once(ctdb->ev);
	}

	status = rmdata->status;
	talloc_free(mem_ctx);
	return status;
}


struct verify_recmaster_data {
	struct ctdb_recoverd *rec;
	uint32_t count;
	uint32_t pnn;
	enum monitor_result status;
};

static void verify_recmaster_callback(struct ctdb_client_control_state *state)
{
	struct verify_recmaster_data *rmdata = talloc_get_type(state->async.private_data, struct verify_recmaster_data);


	/* one more node has responded with recmaster data*/
	rmdata->count--;

	/* if we failed to get the recmaster, then return an error and let
	   the main loop try again.
	*/
	if (state->state != CTDB_CONTROL_DONE) {
		if (rmdata->status == MONITOR_OK) {
			rmdata->status = MONITOR_FAILED;
		}
		return;
	}

	/* if we got a response, then the recmaster will be stored in the
	   status field
	*/
	if (state->status != rmdata->pnn) {
		DEBUG(DEBUG_ERR,("Node %d does not agree we are the recmaster. Need a new recmaster election\n", state->c->hdr.destnode));
		ctdb_set_culprit(rmdata->rec, state->c->hdr.destnode);
		rmdata->status = MONITOR_ELECTION_NEEDED;
	}

	return;
}


/* verify that all nodes agree that we are the recmaster */
static enum monitor_result verify_recmaster(struct ctdb_recoverd *rec, struct ctdb_node_map *nodemap, uint32_t pnn)
{
	struct ctdb_context *ctdb = rec->ctdb;
	struct verify_recmaster_data *rmdata;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);
	struct ctdb_client_control_state *state;
	enum monitor_result status;
	int j;
	
	rmdata = talloc(mem_ctx, struct verify_recmaster_data);
	CTDB_NO_MEMORY_FATAL(ctdb, rmdata);
	rmdata->rec    = rec;
	rmdata->count  = 0;
	rmdata->pnn    = pnn;
	rmdata->status = MONITOR_OK;

	/* loop over all active nodes and send an async getrecmaster call to 
	   them*/
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		state = ctdb_ctrl_getrecmaster_send(ctdb, mem_ctx, 
					CONTROL_TIMEOUT(),
					nodemap->nodes[j].pnn);
		if (state == NULL) {
			/* we failed to send the control, treat this as 
			   an error and try again next iteration
			*/			
			DEBUG(DEBUG_ERR,("Failed to call ctdb_ctrl_getrecmaster_send during monitoring\n"));
			talloc_free(mem_ctx);
			return MONITOR_FAILED;
		}

		/* set up the callback functions */
		state->async.fn = verify_recmaster_callback;
		state->async.private_data = rmdata;

		/* one more control to wait for to complete */
		rmdata->count++;
	}


	/* now wait for up to the maximum number of seconds allowed
	   or until all nodes we expect a response from has replied
	*/
	while (rmdata->count > 0) {
		event_loop_once(ctdb->ev);
	}

	status = rmdata->status;
	talloc_free(mem_ctx);
	return status;
}


/* called to check that the allocation of public ip addresses is ok.
*/
static int verify_ip_allocation(struct ctdb_context *ctdb, uint32_t pnn)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_all_public_ips *ips = NULL;
	struct ctdb_uptime *uptime1 = NULL;
	struct ctdb_uptime *uptime2 = NULL;
	int ret, j;

	ret = ctdb_ctrl_uptime(ctdb, mem_ctx, CONTROL_TIMEOUT(),
				CTDB_CURRENT_NODE, &uptime1);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get uptime from local node %u\n", pnn));
		talloc_free(mem_ctx);
		return -1;
	}

	/* read the ip allocation from the local node */
	ret = ctdb_ctrl_get_public_ips(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, mem_ctx, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get public ips from local node %u\n", pnn));
		talloc_free(mem_ctx);
		return -1;
	}

	ret = ctdb_ctrl_uptime(ctdb, mem_ctx, CONTROL_TIMEOUT(),
				CTDB_CURRENT_NODE, &uptime2);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get uptime from local node %u\n", pnn));
		talloc_free(mem_ctx);
		return -1;
	}

	/* skip the check if the startrecovery time has changed */
	if (timeval_compare(&uptime1->last_recovery_started,
			    &uptime2->last_recovery_started) != 0) {
		DEBUG(DEBUG_NOTICE, (__location__ " last recovery time changed while we read the public ip list. skipping public ip address check\n"));
		talloc_free(mem_ctx);
		return 0;
	}

	/* skip the check if the endrecovery time has changed */
	if (timeval_compare(&uptime1->last_recovery_finished,
			    &uptime2->last_recovery_finished) != 0) {
		DEBUG(DEBUG_NOTICE, (__location__ " last recovery time changed while we read the public ip list. skipping public ip address check\n"));
		talloc_free(mem_ctx);
		return 0;
	}

	/* skip the check if we have started but not finished recovery */
	if (timeval_compare(&uptime1->last_recovery_finished,
			    &uptime1->last_recovery_started) != 1) {
		DEBUG(DEBUG_NOTICE, (__location__ " in the middle of recovery. skipping public ip address check\n"));
		talloc_free(mem_ctx);

		return 0;
	}

	/* verify that we have the ip addresses we should have
	   and we dont have ones we shouldnt have.
	   if we find an inconsistency we set recmode to
	   active on the local node and wait for the recmaster
	   to do a full blown recovery
	*/
	for (j=0; j<ips->num; j++) {
		if (ips->ips[j].pnn == pnn) {
			if (!ctdb_sys_have_ip(&ips->ips[j].addr)) {
				DEBUG(DEBUG_CRIT,("Public address '%s' is missing and we should serve this ip\n",
					ctdb_addr_to_str(&ips->ips[j].addr)));
				ret = ctdb_ctrl_freeze(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE);
				if (ret != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to freeze node due to public ip address mismatches\n"));

					talloc_free(mem_ctx);
					return -1;
				}
				ret = ctdb_ctrl_setrecmode(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, CTDB_RECOVERY_ACTIVE);
				if (ret != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to activate recovery mode due to public ip address mismatches\n"));

					talloc_free(mem_ctx);
					return -1;
				}
			}
		} else {
			if (ctdb_sys_have_ip(&ips->ips[j].addr)) {
				DEBUG(DEBUG_CRIT,("We are still serving a public address '%s' that we should not be serving.\n", 
					ctdb_addr_to_str(&ips->ips[j].addr)));

				ret = ctdb_ctrl_freeze(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE);
				if (ret != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to freeze node due to public ip address mismatches\n"));

					talloc_free(mem_ctx);
					return -1;
				}
				ret = ctdb_ctrl_setrecmode(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, CTDB_RECOVERY_ACTIVE);
				if (ret != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to activate recovery mode due to public ip address mismatches\n"));

					talloc_free(mem_ctx);
					return -1;
				}
			}
		}
	}

	talloc_free(mem_ctx);
	return 0;
}


static void async_getnodemap_callback(struct ctdb_context *ctdb, uint32_t node_pnn, int32_t res, TDB_DATA outdata, void *callback_data)
{
	struct ctdb_node_map **remote_nodemaps = callback_data;

	if (node_pnn >= ctdb->num_nodes) {
		DEBUG(DEBUG_ERR,(__location__ " pnn from invalid node\n"));
		return;
	}

	remote_nodemaps[node_pnn] = (struct ctdb_node_map *)talloc_steal(remote_nodemaps, outdata.dptr);

}

static int get_remote_nodemaps(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
	struct ctdb_node_map *nodemap,
	struct ctdb_node_map **remote_nodemaps)
{
	uint32_t *nodes;

	nodes = list_of_active_nodes(ctdb, nodemap, mem_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_GET_NODEMAP,
					nodes,
					CONTROL_TIMEOUT(), false, tdb_null,
					async_getnodemap_callback,
					NULL,
					remote_nodemaps) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to pull all remote nodemaps\n"));

		return -1;
	}

	return 0;
}

/*
  the main monitoring loop
 */
static void monitor_cluster(struct ctdb_context *ctdb)
{
	uint32_t pnn;
	TALLOC_CTX *mem_ctx=NULL;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_node_map *recmaster_nodemap=NULL;
	struct ctdb_node_map **remote_nodemaps=NULL;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_vnn_map *remote_vnnmap=NULL;
	int32_t debug_level;
	int i, j, ret;
	struct ctdb_recoverd *rec;
	char c;

	DEBUG(DEBUG_NOTICE,("monitor_cluster starting\n"));

	rec = talloc_zero(ctdb, struct ctdb_recoverd);
	CTDB_NO_MEMORY_FATAL(ctdb, rec);

	rec->ctdb = ctdb;
	rec->banned_nodes = talloc_zero_array(rec, struct ban_state *, ctdb->num_nodes);
	CTDB_NO_MEMORY_FATAL(ctdb, rec->banned_nodes);

	rec->priority_time = timeval_current();

	/* register a message port for sending memory dumps */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_MEM_DUMP, mem_dump_handler, rec);

	/* register a message port for recovery elections */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_RECOVERY, election_handler, rec);

	/* when nodes are disabled/enabled */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_SET_NODE_FLAGS, monitor_handler, rec);

	/* when we are asked to puch out a flag change */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_PUSH_NODE_FLAGS, push_flags_handler, rec);

	/* when nodes are banned */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_BAN_NODE, ban_handler, rec);

	/* and one for when nodes are unbanned */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_UNBAN_NODE, unban_handler, rec);

	/* register a message port for vacuum fetch */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_VACUUM_FETCH, vacuum_fetch_handler, rec);

again:
	if (mem_ctx) {
		talloc_free(mem_ctx);
		mem_ctx = NULL;
	}
	mem_ctx = talloc_new(ctdb);
	if (!mem_ctx) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to create temporary context\n"));
		exit(-1);
	}

	/* we only check for recovery once every second */
	ctdb_wait_timeout(ctdb, ctdb->tunable.recover_interval);

	/* verify that the main daemon is still running */
	if (kill(ctdb->ctdbd_pid, 0) != 0) {
		DEBUG(DEBUG_CRIT,("CTDB daemon is no longer available. Shutting down recovery daemon\n"));
		exit(-1);
	}

	/* ping the local daemon to tell it we are alive */
	ctdb_ctrl_recd_ping(ctdb);

	if (rec->election_timeout) {
		/* an election is in progress */
		goto again;
	}

	/* read the debug level from the parent and update locally */
	ret = ctdb_ctrl_get_debuglevel(ctdb, CTDB_CURRENT_NODE, &debug_level);
	if (ret !=0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to read debuglevel from parent\n"));
		goto again;
	}
	LogLevel = debug_level;


	/* We must check if we need to ban a node here but we want to do this
	   as early as possible so we dont wait until we have pulled the node
	   map from the local node. thats why we have the hardcoded value 20
	*/
	if (rec->culprit_counter > 20) {
		DEBUG(DEBUG_NOTICE,("Node %u has caused %u failures in %.0f seconds - banning it for %u seconds\n",
			 rec->last_culprit, rec->culprit_counter, timeval_elapsed(&rec->first_recover_time),
			 ctdb->tunable.recovery_ban_period));
		ctdb_ban_node(rec, rec->last_culprit, ctdb->tunable.recovery_ban_period);
	}

	/* get relevant tunables */
	ret = ctdb_ctrl_get_all_tunables(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, &ctdb->tunable);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to get tunables - retrying\n"));
		goto again;
	}

	pnn = ctdb_ctrl_getpnn(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE);
	if (pnn == (uint32_t)-1) {
		DEBUG(DEBUG_ERR,("Failed to get local pnn - retrying\n"));
		goto again;
	}

	/* get the vnnmap */
	ret = ctdb_ctrl_getvnnmap(ctdb, CONTROL_TIMEOUT(), pnn, mem_ctx, &vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get vnnmap from node %u\n", pnn));
		goto again;
	}


	/* get number of nodes */
	if (rec->nodemap) {
		talloc_free(rec->nodemap);
		rec->nodemap = NULL;
		nodemap=NULL;
	}
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), pnn, rec, &rec->nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get nodemap from node %u\n", pnn));
		goto again;
	}
	nodemap = rec->nodemap;

	/* check which node is the recovery master */
	ret = ctdb_ctrl_getrecmaster(ctdb, mem_ctx, CONTROL_TIMEOUT(), pnn, &rec->recmaster);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get recmaster from node %u\n", pnn));
		goto again;
	}

	if (rec->recmaster == (uint32_t)-1) {
		DEBUG(DEBUG_NOTICE,(__location__ " Initial recovery master set - forcing election\n"));
		force_election(rec, pnn, nodemap);
		goto again;
	}
	
	/* check that we (recovery daemon) and the local ctdb daemon
	   agrees on whether we are banned or not
	*/
	if (nodemap->nodes[pnn].flags & NODE_FLAGS_BANNED) {
		if (rec->banned_nodes[pnn] == NULL) {
			if (rec->recmaster == pnn) {
				DEBUG(DEBUG_NOTICE,("Local ctdb daemon on recmaster thinks this node is BANNED but the recovery master disagrees. Unbanning the node\n"));

				ctdb_unban_node(rec, pnn);
			} else {
				DEBUG(DEBUG_NOTICE,("Local ctdb daemon on non-recmaster thinks this node is BANNED but the recovery master disagrees. Re-banning the node\n"));
				ctdb_ban_node(rec, pnn, ctdb->tunable.recovery_ban_period);
				ctdb_set_culprit(rec, pnn);
			}
			goto again;
		}
	} else {
		if (rec->banned_nodes[pnn] != NULL) {
			if (rec->recmaster == pnn) {
				DEBUG(DEBUG_NOTICE,("Local ctdb daemon on recmaster does not think this node is BANNED but the recovery master disagrees. Unbanning the node\n"));

				ctdb_unban_node(rec, pnn);
			} else {
				DEBUG(DEBUG_NOTICE,("Local ctdb daemon on non-recmaster does not think this node is BANNED but the recovery master disagrees. Re-banning the node\n"));

				ctdb_ban_node(rec, pnn, ctdb->tunable.recovery_ban_period);
				ctdb_set_culprit(rec, pnn);
			}
			goto again;
		}
	}

	/* remember our own node flags */
	rec->node_flags = nodemap->nodes[pnn].flags;

	/* count how many active nodes there are */
	rec->num_active    = 0;
	rec->num_connected = 0;
	for (i=0; i<nodemap->num; i++) {
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE)) {
			rec->num_active++;
		}
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED)) {
			rec->num_connected++;
		}
	}


	/* verify that the recmaster node is still active */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].pnn==rec->recmaster) {
			break;
		}
	}

	if (j == nodemap->num) {
		DEBUG(DEBUG_ERR, ("Recmaster node %u not in list. Force reelection\n", rec->recmaster));
		force_election(rec, pnn, nodemap);
		goto again;
	}

	/* if recovery master is disconnected we must elect a new recmaster */
	if (nodemap->nodes[j].flags & NODE_FLAGS_DISCONNECTED) {
		DEBUG(DEBUG_NOTICE, ("Recmaster node %u is disconnected. Force reelection\n", nodemap->nodes[j].pnn));
		force_election(rec, pnn, nodemap);
		goto again;
	}

	/* grap the nodemap from the recovery master to check if it is banned */
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
				   mem_ctx, &recmaster_nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get nodemap from recovery master %u\n", 
			  nodemap->nodes[j].pnn));
		goto again;
	}


	if (recmaster_nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
		DEBUG(DEBUG_NOTICE, ("Recmaster node %u no longer available. Force reelection\n", nodemap->nodes[j].pnn));
		force_election(rec, pnn, nodemap);
		goto again;
	}


	/* verify that we have all ip addresses we should have and we dont
	 * have addresses we shouldnt have.
	 */ 
	if (ctdb->do_checkpublicip) {
		if (verify_ip_allocation(ctdb, pnn) != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Public IPs were inconsistent.\n"));
			goto again;
		}
	}


	/* if we are not the recmaster then we do not need to check
	   if recovery is needed
	 */
	if (pnn != rec->recmaster) {
		goto again;
	}


	/* ensure our local copies of flags are right */
	ret = update_local_flags(rec, nodemap);
	if (ret == MONITOR_ELECTION_NEEDED) {
		DEBUG(DEBUG_NOTICE,("update_local_flags() called for a re-election.\n"));
		force_election(rec, pnn, nodemap);
		goto again;
	}
	if (ret != MONITOR_OK) {
		DEBUG(DEBUG_ERR,("Unable to update local flags\n"));
		goto again;
	}

	/* update the list of public ips that a node can handle for
	   all connected nodes
	*/
	if (ctdb->num_nodes != nodemap->num) {
		DEBUG(DEBUG_ERR, (__location__ " ctdb->num_nodes (%d) != nodemap->num (%d) reloading nodes file\n", ctdb->num_nodes, nodemap->num));
		reload_nodes_file(ctdb);
		goto again;
	}
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		/* release any existing data */
		if (ctdb->nodes[j]->public_ips) {
			talloc_free(ctdb->nodes[j]->public_ips);
			ctdb->nodes[j]->public_ips = NULL;
		}
		/* grab a new shiny list of public ips from the node */
		if (ctdb_ctrl_get_public_ips(ctdb, CONTROL_TIMEOUT(),
			ctdb->nodes[j]->pnn, 
			ctdb->nodes,
			&ctdb->nodes[j]->public_ips)) {
			DEBUG(DEBUG_ERR,("Failed to read public ips from node : %u\n", 
				ctdb->nodes[j]->pnn));
			goto again;
		}
	}


	/* verify that all active nodes agree that we are the recmaster */
	switch (verify_recmaster(rec, nodemap, pnn)) {
	case MONITOR_RECOVERY_NEEDED:
		/* can not happen */
		goto again;
	case MONITOR_ELECTION_NEEDED:
		force_election(rec, pnn, nodemap);
		goto again;
	case MONITOR_OK:
		break;
	case MONITOR_FAILED:
		goto again;
	}


	if (rec->need_recovery) {
		/* a previous recovery didn't finish */
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, -1);
		goto again;		
	}

	/* verify that all active nodes are in normal mode 
	   and not in recovery mode 
	 */
	switch (verify_recmode(ctdb, nodemap)) {
	case MONITOR_RECOVERY_NEEDED:
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, ctdb->pnn);
		goto again;
	case MONITOR_FAILED:
		goto again;
	case MONITOR_ELECTION_NEEDED:
		/* can not happen */
	case MONITOR_OK:
		break;
	}


	/* we should have the reclock - check its not stale */
	if (ctdb->recovery_lock_fd == -1) {
		DEBUG(DEBUG_CRIT,("recovery master doesn't have the recovery lock\n"));
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, ctdb->pnn);
		goto again;
	}

	if (pread(ctdb->recovery_lock_fd, &c, 1, 0) == -1) {
		DEBUG(DEBUG_CRIT,("failed read from recovery_lock_fd - %s\n", strerror(errno)));
		close(ctdb->recovery_lock_fd);
		ctdb->recovery_lock_fd = -1;
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, ctdb->pnn);
		goto again;
	}


	/* get the nodemap for all active remote nodes
	 */
	remote_nodemaps = talloc_array(mem_ctx, struct ctdb_node_map *, nodemap->num);
	if (remote_nodemaps == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " failed to allocate remote nodemap array\n"));
		goto again;
	}
	for(i=0; i<nodemap->num; i++) {
		remote_nodemaps[i] = NULL;
	}
	if (get_remote_nodemaps(ctdb, mem_ctx, nodemap, remote_nodemaps) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to read remote nodemaps\n"));
		goto again;
	} 

	/* verify that all other nodes have the same nodemap as we have
	*/
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		if (remote_nodemaps[j] == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Did not get a remote nodemap for node %d, restarting monitoring\n", j));
			goto again;
		}

 		/* if the nodes disagree on how many nodes there are
		   then this is a good reason to try recovery
		 */
		if (remote_nodemaps[j]->num != nodemap->num) {
			DEBUG(DEBUG_ERR, (__location__ " Remote node:%u has different node count. %u vs %u of the local node\n",
				  nodemap->nodes[j].pnn, remote_nodemaps[j]->num, nodemap->num));
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, nodemap->nodes[j].pnn);
			goto again;
		}

		/* if the nodes disagree on which nodes exist and are
		   active, then that is also a good reason to do recovery
		 */
		for (i=0;i<nodemap->num;i++) {
			if (remote_nodemaps[j]->nodes[i].pnn != nodemap->nodes[i].pnn) {
				DEBUG(DEBUG_ERR, (__location__ " Remote node:%u has different nodemap pnn for %d (%u vs %u).\n", 
					  nodemap->nodes[j].pnn, i, 
					  remote_nodemaps[j]->nodes[i].pnn, nodemap->nodes[i].pnn));
				do_recovery(rec, mem_ctx, pnn, nodemap, 
					    vnnmap, nodemap->nodes[j].pnn);
				goto again;
			}
		}

		/* verify the flags are consistent
		*/
		for (i=0; i<nodemap->num; i++) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
				continue;
			}
			
			if (nodemap->nodes[i].flags != remote_nodemaps[j]->nodes[i].flags) {
				DEBUG(DEBUG_ERR, (__location__ " Remote node:%u has different flags for node %u. It has 0x%02x vs our 0x%02x\n", 
				  nodemap->nodes[j].pnn, 
				  nodemap->nodes[i].pnn, 
				  remote_nodemaps[j]->nodes[i].flags,
				  nodemap->nodes[j].flags));
				if (i == j) {
					DEBUG(DEBUG_ERR,("Use flags 0x%02x from remote node %d for cluster update of its own flags\n", remote_nodemaps[j]->nodes[i].flags, j));
					update_flags_on_all_nodes(ctdb, nodemap, nodemap->nodes[i].pnn, remote_nodemaps[j]->nodes[i].flags);
					do_recovery(rec, mem_ctx, pnn, nodemap, 
						    vnnmap, nodemap->nodes[j].pnn);
					goto again;
				} else {
					DEBUG(DEBUG_ERR,("Use flags 0x%02x from local recmaster node for cluster update of node %d flags\n", nodemap->nodes[i].flags, i));
					update_flags_on_all_nodes(ctdb, nodemap, nodemap->nodes[i].pnn, nodemap->nodes[i].flags);
					do_recovery(rec, mem_ctx, pnn, nodemap, 
						    vnnmap, nodemap->nodes[j].pnn);
					goto again;
				}
			}
		}
	}


	/* there better be the same number of lmasters in the vnn map
	   as there are active nodes or we will have to do a recovery
	 */
	if (vnnmap->size != rec->num_active) {
		DEBUG(DEBUG_ERR, (__location__ " The vnnmap count is different from the number of active nodes. %u vs %u\n", 
			  vnnmap->size, rec->num_active));
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, ctdb->pnn);
		goto again;
	}

	/* verify that all active nodes in the nodemap also exist in 
	   the vnnmap.
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[j].pnn == pnn) {
			continue;
		}

		for (i=0; i<vnnmap->size; i++) {
			if (vnnmap->map[i] == nodemap->nodes[j].pnn) {
				break;
			}
		}
		if (i == vnnmap->size) {
			DEBUG(DEBUG_ERR, (__location__ " Node %u is active in the nodemap but did not exist in the vnnmap\n", 
				  nodemap->nodes[j].pnn));
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, nodemap->nodes[j].pnn);
			goto again;
		}
	}

	
	/* verify that all other nodes have the same vnnmap
	   and are from the same generation
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[j].pnn == pnn) {
			continue;
		}

		ret = ctdb_ctrl_getvnnmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					  mem_ctx, &remote_vnnmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to get vnnmap from remote node %u\n", 
				  nodemap->nodes[j].pnn));
			goto again;
		}

		/* verify the vnnmap generation is the same */
		if (vnnmap->generation != remote_vnnmap->generation) {
			DEBUG(DEBUG_ERR, (__location__ " Remote node %u has different generation of vnnmap. %u vs %u (ours)\n", 
				  nodemap->nodes[j].pnn, remote_vnnmap->generation, vnnmap->generation));
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, nodemap->nodes[j].pnn);
			goto again;
		}

		/* verify the vnnmap size is the same */
		if (vnnmap->size != remote_vnnmap->size) {
			DEBUG(DEBUG_ERR, (__location__ " Remote node %u has different size of vnnmap. %u vs %u (ours)\n", 
				  nodemap->nodes[j].pnn, remote_vnnmap->size, vnnmap->size));
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap, nodemap->nodes[j].pnn);
			goto again;
		}

		/* verify the vnnmap is the same */
		for (i=0;i<vnnmap->size;i++) {
			if (remote_vnnmap->map[i] != vnnmap->map[i]) {
				DEBUG(DEBUG_ERR, (__location__ " Remote node %u has different vnnmap.\n", 
					  nodemap->nodes[j].pnn));
				do_recovery(rec, mem_ctx, pnn, nodemap, 
					    vnnmap, nodemap->nodes[j].pnn);
				goto again;
			}
		}
	}

	/* we might need to change who has what IP assigned */
	if (rec->need_takeover_run) {
		rec->need_takeover_run = false;

		/* execute the "startrecovery" event script on all nodes */
		ret = run_startrecovery_eventscript(rec, nodemap);
		if (ret!=0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to run the 'startrecovery' event on cluster\n"));
			do_recovery(rec, mem_ctx, pnn, nodemap, 
				    vnnmap, ctdb->pnn);
		}

		ret = ctdb_takeover_run(ctdb, nodemap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to setup public takeover addresses - starting recovery\n"));
			do_recovery(rec, mem_ctx, pnn, nodemap, 
				    vnnmap, ctdb->pnn);
		}

		/* execute the "recovered" event script on all nodes */
		ret = run_recovered_eventscript(ctdb, nodemap, "monitor_cluster");
#if 0
// we cant check whether the event completed successfully
// since this script WILL fail if the node is in recovery mode
// and if that race happens, the code here would just cause a second
// cascading recovery.
		if (ret!=0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to run the 'recovered' event on cluster. Update of public ips failed.\n"));
			do_recovery(rec, mem_ctx, pnn, nodemap, 
				    vnnmap, ctdb->pnn);
		}
#endif
	}


	goto again;

}

/*
  event handler for when the main ctdbd dies
 */
static void ctdb_recoverd_parent(struct event_context *ev, struct fd_event *fde, 
				 uint16_t flags, void *private_data)
{
	DEBUG(DEBUG_ALERT,("recovery daemon parent died - exiting\n"));
	_exit(1);
}

/*
  called regularly to verify that the recovery daemon is still running
 */
static void ctdb_check_recd(struct event_context *ev, struct timed_event *te, 
			      struct timeval yt, void *p)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);

	if (kill(ctdb->recoverd_pid, 0) != 0) {
		DEBUG(DEBUG_ERR,("Recovery daemon (pid:%d) is no longer running. Shutting down main daemon\n", (int)ctdb->recoverd_pid));

		ctdb_stop_recoverd(ctdb);
		ctdb_stop_keepalive(ctdb);
		ctdb_stop_monitoring(ctdb);
		ctdb_release_all_ips(ctdb);
		if (ctdb->methods != NULL) {
			ctdb->methods->shutdown(ctdb);
		}
		ctdb_event_script(ctdb, "shutdown");

		exit(10);	
	}

	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(30, 0),
			ctdb_check_recd, ctdb);
}

static void recd_sig_child_handler(struct event_context *ev,
	struct signal_event *se, int signum, int count,
	void *dont_care, 
	void *private_data)
{
//	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int status;
	pid_t pid = -1;

	while (pid != 0) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) {
			DEBUG(DEBUG_ERR, (__location__ " waitpid() returned error. errno:%d\n", errno));
			return;
		}
		if (pid > 0) {
			DEBUG(DEBUG_DEBUG, ("RECD SIGCHLD from %d\n", (int)pid));
		}
	}
}

/*
  startup the recovery daemon as a child of the main ctdb daemon
 */
int ctdb_start_recoverd(struct ctdb_context *ctdb)
{
	int fd[2];
	struct signal_event *se;

	if (pipe(fd) != 0) {
		return -1;
	}

	ctdb->ctdbd_pid = getpid();

	ctdb->recoverd_pid = fork();
	if (ctdb->recoverd_pid == -1) {
		return -1;
	}
	
	if (ctdb->recoverd_pid != 0) {
		close(fd[0]);
		event_add_timed(ctdb->ev, ctdb, 
				timeval_current_ofs(30, 0),
				ctdb_check_recd, ctdb);
		return 0;
	}

	close(fd[1]);

	srandom(getpid() ^ time(NULL));

	if (switch_from_server_to_client(ctdb) != 0) {
		DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch recovery daemon into client mode. shutting down.\n"));
		exit(1);
	}

	event_add_fd(ctdb->ev, ctdb, fd[0], EVENT_FD_READ|EVENT_FD_AUTOCLOSE, 
		     ctdb_recoverd_parent, &fd[0]);	

	/* set up a handler to pick up sigchld */
	se = event_add_signal(ctdb->ev, ctdb,
				     SIGCHLD, 0,
				     recd_sig_child_handler,
				     ctdb);
	if (se == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to set up signal handler for SIGCHLD in recovery daemon\n"));
		exit(1);
	}

	monitor_cluster(ctdb);

	DEBUG(DEBUG_ALERT,("ERROR: ctdb_recoverd finished!?\n"));
	return -1;
}

/*
  shutdown the recovery daemon
 */
void ctdb_stop_recoverd(struct ctdb_context *ctdb)
{
	if (ctdb->recoverd_pid == 0) {
		return;
	}

	DEBUG(DEBUG_NOTICE,("Shutting down recovery daemon\n"));
	kill(ctdb->recoverd_pid, SIGTERM);
}
