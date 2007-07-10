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
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"


struct ban_state {
	struct ctdb_recoverd *rec;
	uint32_t banned_node;
};

/*
  private state of recovery daemon
 */
struct ctdb_recoverd {
	struct ctdb_context *ctdb;
	uint32_t last_culprit;
	uint32_t culprit_counter;
	struct timeval first_recover_time;
	struct ban_state **banned_nodes;
	struct timeval priority_time;
};

#define CONTROL_TIMEOUT() timeval_current_ofs(ctdb->tunable.recover_timeout, 0)
#define MONITOR_TIMEOUT() timeval_current_ofs(ctdb->tunable.recover_interval, 0)

/*
  unban a node
 */
static void ctdb_unban_node(struct ctdb_recoverd *rec, uint32_t vnn)
{
	struct ctdb_context *ctdb = rec->ctdb;

	if (!ctdb_validate_vnn(ctdb, vnn)) {
		DEBUG(0,("Bad vnn %u in ctdb_ban_node\n", vnn));
		return;
	}

	if (rec->banned_nodes[vnn] == NULL) {
		return;
	}

	ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), vnn, 0, NODE_FLAGS_BANNED);

	talloc_free(rec->banned_nodes[vnn]);
	rec->banned_nodes[vnn] = NULL;
}


/*
  called when a ban has timed out
 */
static void ctdb_ban_timeout(struct event_context *ev, struct timed_event *te, struct timeval t, void *p)
{
	struct ban_state *state = talloc_get_type(p, struct ban_state);
	struct ctdb_recoverd *rec = state->rec;
	uint32_t vnn = state->banned_node;

	DEBUG(0,("Node %u is now unbanned\n", vnn));
	ctdb_unban_node(rec, vnn);
}

/*
  ban a node for a period of time
 */
static void ctdb_ban_node(struct ctdb_recoverd *rec, uint32_t vnn, uint32_t ban_time)
{
	struct ctdb_context *ctdb = rec->ctdb;

	if (!ctdb_validate_vnn(ctdb, vnn)) {
		DEBUG(0,("Bad vnn %u in ctdb_ban_node\n", vnn));
		return;
	}

	if (vnn == ctdb->vnn) {
		DEBUG(0,("self ban - lowering our election priority\n"));
		/* banning ourselves - lower our election priority */
		rec->priority_time = timeval_current();
	}

	ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), vnn, NODE_FLAGS_BANNED, 0);

	rec->banned_nodes[vnn] = talloc(rec, struct ban_state);
	CTDB_NO_MEMORY_FATAL(ctdb, rec->banned_nodes[vnn]);

	rec->banned_nodes[vnn]->rec = rec;
	rec->banned_nodes[vnn]->banned_node = vnn;

	if (ban_time != 0) {
		event_add_timed(ctdb->ev, rec->banned_nodes[vnn], 
				timeval_current_ofs(ban_time, 0),
				ctdb_ban_timeout, rec->banned_nodes[vnn]);
	}
}


/*
  change recovery mode on all nodes
 */
static int set_recovery_mode(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, uint32_t rec_mode)
{
	int j, ret;

	/* start the freeze process immediately on all nodes */
	ctdb_control(ctdb, CTDB_BROADCAST_CONNECTED, 0, 
		     CTDB_CONTROL_FREEZE, CTDB_CTRL_FLAG_NOREPLY, tdb_null, 
		     NULL, NULL, NULL, NULL, NULL);

	/* set recovery mode to active on all nodes */
	for (j=0; j<nodemap->num; j++) {
		/* dont change it for nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		if (rec_mode == CTDB_RECOVERY_ACTIVE) {
			ret = ctdb_ctrl_freeze(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to freeze node %u\n", nodemap->nodes[j].vnn));
				return -1;
			}
		}

		ret = ctdb_ctrl_setrecmode(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, rec_mode);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to set recmode on node %u\n", nodemap->nodes[j].vnn));
			return -1;
		}

		if (rec_mode == CTDB_RECOVERY_NORMAL) {
			ret = ctdb_ctrl_thaw(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to thaw node %u\n", nodemap->nodes[j].vnn));
				return -1;
			}
		}
	}

	return 0;
}

/*
  change recovery master on all node
 */
static int set_recovery_master(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, uint32_t vnn)
{
	int j, ret;

	/* set recovery master to vnn on all nodes */
	for (j=0; j<nodemap->num; j++) {
		/* dont change it for nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, vnn);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to set recmaster on node %u\n", nodemap->nodes[j].vnn));
			return -1;
		}
	}

	return 0;
}


/*
  ensure all other nodes have attached to any databases that we have
 */
static int create_missing_remote_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
					   uint32_t vnn, struct ctdb_dbid_map *dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, db, ret;
	struct ctdb_dbid_map *remote_dbmap;

	/* verify that all other nodes have all our databases */
	for (j=0; j<nodemap->num; j++) {
		/* we dont need to ourself ourselves */
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}
		/* dont check nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, 
					 mem_ctx, &remote_dbmap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to get dbids from node %u\n", vnn));
			return -1;
		}

		/* step through all local databases */
		for (db=0; db<dbmap->num;db++) {
			const char *name;


			for (i=0;i<remote_dbmap->num;i++) {
				if (dbmap->dbids[db] == remote_dbmap->dbids[i]) {
					break;
				}
			}
			/* the remote node already have this database */
			if (i!=remote_dbmap->num) {
				continue;
			}
			/* ok so we need to create this database */
			ctdb_ctrl_getdbname(ctdb, CONTROL_TIMEOUT(), vnn, dbmap->dbids[db], mem_ctx, &name);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to get dbname from node %u\n", vnn));
				return -1;
			}
			ctdb_ctrl_createdb(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, mem_ctx, name);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to create remote db:%s\n", name));
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
					  uint32_t vnn, struct ctdb_dbid_map **dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, db, ret;
	struct ctdb_dbid_map *remote_dbmap;

	/* verify that we have all database any other node has */
	for (j=0; j<nodemap->num; j++) {
		/* we dont need to ourself ourselves */
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}
		/* dont check nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, 
					 mem_ctx, &remote_dbmap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to get dbids from node %u\n", vnn));
			return -1;
		}

		/* step through all databases on the remote node */
		for (db=0; db<remote_dbmap->num;db++) {
			const char *name;

			for (i=0;i<(*dbmap)->num;i++) {
				if (remote_dbmap->dbids[db] == (*dbmap)->dbids[i]) {
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
			ctdb_ctrl_getdbname(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, 
					    remote_dbmap->dbids[db], mem_ctx, &name);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to get dbname from node %u\n", 
					  nodemap->nodes[j].vnn));
				return -1;
			}
			ctdb_ctrl_createdb(ctdb, CONTROL_TIMEOUT(), vnn, mem_ctx, name);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to create local db:%s\n", name));
				return -1;
			}
			ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), vnn, mem_ctx, dbmap);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to reread dbmap on node %u\n", vnn));
				return -1;
			}
		}
	}

	return 0;
}


/*
  pull all the remote database contents into ours
 */
static int pull_all_remote_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
				     uint32_t vnn, struct ctdb_dbid_map *dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, ret;

	/* pull all records from all other nodes across onto this node
	   (this merges based on rsn)
	*/
	for (i=0;i<dbmap->num;i++) {
		for (j=0; j<nodemap->num; j++) {
			/* we dont need to merge with ourselves */
			if (nodemap->nodes[j].vnn == vnn) {
				continue;
			}
			/* dont merge from nodes that are unavailable */
			if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
				continue;
			}
			ret = ctdb_ctrl_copydb(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, 
					       vnn, dbmap->dbids[i], CTDB_LMASTER_ANY, mem_ctx);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to copy db from node %u to node %u\n", 
					  nodemap->nodes[j].vnn, vnn));
				return -1;
			}
		}
	}

	return 0;
}


/*
  change the dmaster on all databases to point to us
 */
static int update_dmaster_on_all_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
					   uint32_t vnn, struct ctdb_dbid_map *dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, ret;

	/* update dmaster to point to this node for all databases/nodes */
	for (i=0;i<dbmap->num;i++) {
		for (j=0; j<nodemap->num; j++) {
			/* dont repoint nodes that are unavailable */
			if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
				continue;
			}
			ret = ctdb_ctrl_setdmaster(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, ctdb, dbmap->dbids[i], vnn);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to set dmaster for node %u db:0x%08x\n", nodemap->nodes[j].vnn, dbmap->dbids[i]));
				return -1;
			}
		}
	}

	return 0;
}


/*
  update flags on all active nodes
 */
static int update_flags_on_all_nodes(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap)
{
	int i;
	for (i=0;i<nodemap->num;i++) {
		struct ctdb_node_flag_change c;
		TDB_DATA data;

		c.vnn = nodemap->nodes[i].vnn;
		c.flags = nodemap->nodes[i].flags;

		data.dptr = (uint8_t *)&c;
		data.dsize = sizeof(c);

		ctdb_send_message(ctdb, CTDB_BROADCAST_CONNECTED,
				  CTDB_SRVID_NODE_FLAGS_CHANGED, data);

	}
	return 0;
}

/*
  vacuum one database
 */
static int vacuum_db(struct ctdb_context *ctdb, uint32_t db_id, struct ctdb_node_map *nodemap)
{
	uint64_t max_rsn;
	int ret, i;

	/* find max rsn on our local node for this db */
	ret = ctdb_ctrl_get_max_rsn(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, db_id, &max_rsn);
	if (ret != 0) {
		return -1;
	}

	/* set rsn on non-empty records to max_rsn+1 */
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		ret = ctdb_ctrl_set_rsn_nonempty(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[i].vnn,
						 db_id, max_rsn+1);
		if (ret != 0) {
			DEBUG(0,(__location__ " Failed to set rsn on node %u to %llu\n",
				 nodemap->nodes[i].vnn, (unsigned long long)max_rsn+1));
			return -1;
		}
	}

	/* delete records with rsn < max_rsn+1 on all nodes */
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		ret = ctdb_ctrl_delete_low_rsn(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[i].vnn,
						 db_id, max_rsn+1);
		if (ret != 0) {
			DEBUG(0,(__location__ " Failed to delete records on node %u with rsn below %llu\n",
				 nodemap->nodes[i].vnn, (unsigned long long)max_rsn+1));
			return -1;
		}
	}


	return 0;
}


/*
  vacuum all attached databases
 */
static int vacuum_all_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
				struct ctdb_dbid_map *dbmap)
{
	int i;

	/* update dmaster to point to this node for all databases/nodes */
	for (i=0;i<dbmap->num;i++) {
		if (vacuum_db(ctdb, dbmap->dbids[i], nodemap) != 0) {
			return -1;
		}
	}
	return 0;
}


/*
  push out all our database contents to all other nodes
 */
static int push_all_local_databases(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
				    uint32_t vnn, struct ctdb_dbid_map *dbmap, TALLOC_CTX *mem_ctx)
{
	int i, j, ret;

	/* push all records out to the nodes again */
	for (i=0;i<dbmap->num;i++) {
		for (j=0; j<nodemap->num; j++) {
			/* we dont need to push to ourselves */
			if (nodemap->nodes[j].vnn == vnn) {
				continue;
			}
			/* dont push to nodes that are unavailable */
			if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
				continue;
			}
			ret = ctdb_ctrl_copydb(ctdb, CONTROL_TIMEOUT(), vnn, nodemap->nodes[j].vnn, 
					       dbmap->dbids[i], CTDB_LMASTER_ANY, mem_ctx);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to copy db from node %u to node %u\n", 
					  vnn, nodemap->nodes[j].vnn));
				return -1;
			}
		}
	}

	return 0;
}


/*
  ensure all nodes have the same vnnmap we do
 */
static int update_vnnmap_on_all_nodes(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap, 
				      uint32_t vnn, struct ctdb_vnn_map *vnnmap, TALLOC_CTX *mem_ctx)
{
	int j, ret;

	/* push the new vnn map out to all the nodes */
	for (j=0; j<nodemap->num; j++) {
		/* dont push to nodes that are unavailable */
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_setvnnmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, mem_ctx, vnnmap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to set vnnmap for node %u\n", vnn));
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
	uint32_t recmaster;
	int ret;

	if (data.dsize != sizeof(*b)) {
		DEBUG(0,("Bad data in ban_handler\n"));
		return;
	}

	ret = ctdb_ctrl_getrecmaster(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, &recmaster);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to find the recmaster\n"));
		return;
	}

	if (recmaster != ctdb->vnn) {
		DEBUG(0,("We are not the recmaster - ignoring ban request\n"));
		return;
	}

	DEBUG(0,("Node %u has been banned for %u seconds by the administrator\n", 
		 b->vnn, b->ban_time));
	ctdb_ban_node(rec, b->vnn, b->ban_time);
}

/*
  handler for when the admin unbans a node
*/
static void unban_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			  TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(private_data, struct ctdb_recoverd);
	uint32_t vnn;
	int ret;
	uint32_t recmaster;

	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Bad data in unban_handler\n"));
		return;
	}
	vnn = *(uint32_t *)data.dptr;

	ret = ctdb_ctrl_getrecmaster(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, &recmaster);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to find the recmaster\n"));
		return;
	}

	if (recmaster != ctdb->vnn) {
		DEBUG(0,("We are not the recmaster - ignoring unban request\n"));
		return;
	}

	DEBUG(0,("Node %u has been unbanned by the administrator\n", vnn));
	ctdb_unban_node(rec, vnn);
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
  we are the recmaster, and recovery is needed - start a recovery run
 */
static int do_recovery(struct ctdb_recoverd *rec, 
		       TALLOC_CTX *mem_ctx, uint32_t vnn, uint32_t num_active,
		       struct ctdb_node_map *nodemap, struct ctdb_vnn_map *vnnmap,
		       uint32_t culprit)
{
	struct ctdb_context *ctdb = rec->ctdb;
	int i, j, ret;
	uint32_t generation;
	struct ctdb_dbid_map *dbmap;

	if (rec->last_culprit != culprit ||
	    timeval_elapsed(&rec->first_recover_time) > ctdb->tunable.recovery_grace_period) {
		/* either a new node is the culprit, or we've decide to forgive them */
		rec->last_culprit = culprit;
		rec->first_recover_time = timeval_current();
		rec->culprit_counter = 0;
	}
	rec->culprit_counter++;

	if (rec->culprit_counter > 2*nodemap->num) {
		DEBUG(0,("Node %u has caused %u recoveries in %.0f seconds - banning it for %u seconds\n",
			 culprit, rec->culprit_counter, timeval_elapsed(&rec->first_recover_time),
			 ctdb->tunable.recovery_ban_period));
		ctdb_ban_node(rec, culprit, ctdb->tunable.recovery_ban_period);
	}

	if (!ctdb_recovery_lock(ctdb, true)) {
		DEBUG(0,("Unable to get recovery lock - aborting recovery\n"));
		return -1;
	}

	/* set recovery mode to active on all nodes */
	ret = set_recovery_mode(ctdb, nodemap, CTDB_RECOVERY_ACTIVE);
	if (ret!=0) {
		DEBUG(0, (__location__ " Unable to set recovery mode to active on cluster\n"));
		return -1;
	}

	DEBUG(0, (__location__ " Recovery initiated due to problem with node %u\n", culprit));

	/* pick a new generation number */
	generation = random();

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
	ret = ctdb_ctrl_setvnnmap(ctdb, CONTROL_TIMEOUT(), vnn, mem_ctx, vnnmap);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to set vnnmap for node %u\n", vnn));
		return -1;
	}

	/* get a list of all databases */
	ret = ctdb_ctrl_getdbmap(ctdb, CONTROL_TIMEOUT(), vnn, mem_ctx, &dbmap);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to get dbids from node :%u\n", vnn));
		return -1;
	}



	/* verify that all other nodes have all our databases */
	ret = create_missing_remote_databases(ctdb, nodemap, vnn, dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to create missing remote databases\n"));
		return -1;
	}

	/* verify that we have all the databases any other node has */
	ret = create_missing_local_databases(ctdb, nodemap, vnn, &dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to create missing local databases\n"));
		return -1;
	}



	/* verify that all other nodes have all our databases */
	ret = create_missing_remote_databases(ctdb, nodemap, vnn, dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to create missing remote databases\n"));
		return -1;
	}


	DEBUG(1, (__location__ " Recovery - created remote databases\n"));

	/* pull all remote databases onto the local node */
	ret = pull_all_remote_databases(ctdb, nodemap, vnn, dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to pull remote databases\n"));
		return -1;
	}

	DEBUG(1, (__location__ " Recovery - pulled remote databases\n"));

	/* push all local databases to the remote nodes */
	ret = push_all_local_databases(ctdb, nodemap, vnn, dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to push local databases\n"));
		return -1;
	}

	DEBUG(1, (__location__ " Recovery - pushed remote databases\n"));

	/* build a new vnn map with all the currently active and
	   unbanned nodes */
	generation = random();
	vnnmap = talloc(mem_ctx, struct ctdb_vnn_map);
	CTDB_NO_MEMORY(ctdb, vnnmap);
	vnnmap->generation = generation;
	vnnmap->size = num_active;
	vnnmap->map = talloc_zero_array(vnnmap, uint32_t, vnnmap->size);
	for (i=j=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE)) {
			vnnmap->map[j++] = nodemap->nodes[i].vnn;
		}
	}



	/* update to the new vnnmap on all nodes */
	ret = update_vnnmap_on_all_nodes(ctdb, nodemap, vnn, vnnmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to update vnnmap on all nodes\n"));
		return -1;
	}

	DEBUG(1, (__location__ " Recovery - updated vnnmap\n"));

	/* update recmaster to point to us for all nodes */
	ret = set_recovery_master(ctdb, nodemap, vnn);
	if (ret!=0) {
		DEBUG(0, (__location__ " Unable to set recovery master\n"));
		return -1;
	}

	DEBUG(1, (__location__ " Recovery - updated recmaster\n"));

	/* repoint all local and remote database records to the local
	   node as being dmaster
	 */
	ret = update_dmaster_on_all_databases(ctdb, nodemap, vnn, dbmap, mem_ctx);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to update dmaster on all databases\n"));
		return -1;
	}

	DEBUG(1, (__location__ " Recovery - updated dmaster on all databases\n"));

	/*
	  update all nodes to have the same flags that we have
	 */
	ret = update_flags_on_all_nodes(ctdb, nodemap);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to update flags on all nodes\n"));
		return -1;
	}
	
	DEBUG(1, (__location__ " Recovery - updated flags\n"));

	/*
	  run a vacuum operation on empty records
	 */
	ret = vacuum_all_databases(ctdb, nodemap, dbmap);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to vacuum all databases\n"));
		return -1;
	}

	DEBUG(1, (__location__ " Recovery - vacuumed all databases\n"));

	/*
	  if enabled, tell nodes to takeover their public IPs
	 */
	if (ctdb->takeover.enabled) {
		ret = ctdb_takeover_run(ctdb, nodemap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to setup public takeover addresses\n"));
			return -1;
		}
		DEBUG(1, (__location__ " Recovery - done takeover\n"));
	}


	/* disable recovery mode */
	ret = set_recovery_mode(ctdb, nodemap, CTDB_RECOVERY_NORMAL);
	if (ret!=0) {
		DEBUG(0, (__location__ " Unable to set recovery mode to normal on cluster\n"));
		return -1;
	}

	/* send a message to all clients telling them that the cluster 
	   has been reconfigured */
	ctdb_send_message(ctdb, CTDB_BROADCAST_ALL, CTDB_SRVID_RECONFIGURE, tdb_null);

	DEBUG(0, (__location__ " Recovery complete\n"));

	/* We just finished a recovery successfully. 
	   We now wait for rerecovery_timeout before we allow 
	   another recovery to take place.
	*/
	DEBUG(0, (__location__ " New recoveries supressed for the rerecovery timeout\n"));
	ctdb_wait_timeout(ctdb, ctdb->tunable.rerecovery_timeout);
	DEBUG(0, (__location__ " Rerecovery timeout elapsed. Recovery reactivated.\n"));

	return 0;
}


/*
  elections are won by first checking the number of connected nodes, then
  the priority time, then the vnn
 */
struct election_message {
	uint32_t num_connected;
	struct timeval priority_time;
	uint32_t vnn;
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

	em->vnn = rec->ctdb->vnn;
	em->priority_time = rec->priority_time;

	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, rec, &nodemap);
	if (ret != 0) {
		return;
	}

	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED)) {
			em->num_connected++;
		}
	}
	talloc_free(nodemap);
}

/*
  see if the given election data wins
 */
static bool ctdb_election_win(struct ctdb_recoverd *rec, struct election_message *em)
{
	struct election_message myem;
	int cmp;

	ctdb_election_data(rec, &myem);

	/* try to use the most connected node */
	cmp = (int)myem.num_connected - (int)em->num_connected;

	/* then the longest running node */
	if (cmp == 0) {
		cmp = timeval_compare(&em->priority_time, &myem.priority_time);
	}

	if (cmp == 0) {
		cmp = (int)myem.vnn - (int)em->vnn;
	}

	return cmp > 0;
}

/*
  send out an election request
 */
static int send_election_request(struct ctdb_recoverd *rec, TALLOC_CTX *mem_ctx, uint32_t vnn)
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


	/* first we assume we will win the election and set 
	   recoverymaster to be ourself on the current node
	 */
	ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(), vnn, vnn);
	if (ret != 0) {
		DEBUG(0, (__location__ " failed to send recmaster election request\n"));
		return -1;
	}


	/* send an election message to all active nodes */
	ctdb_send_message(ctdb, CTDB_BROADCAST_ALL, srvid, election_data);

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
		DEBUG(0,(__location__ " failed to get nodemap to unban all nodes\n"));
		return;
	}

	for (i=0;i<nodemap->num;i++) {
		if ( (!(nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED))
		  && (nodemap->nodes[i].flags & NODE_FLAGS_BANNED) ) {
			ctdb_ctrl_modflags(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[i].vnn, 0, NODE_FLAGS_BANNED);
		}
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

	mem_ctx = talloc_new(ctdb);

	/* someone called an election. check their election data
	   and if we disagree and we would rather be the elected node, 
	   send a new election message to all other nodes
	 */
	if (ctdb_election_win(rec, em)) {
		ret = send_election_request(rec, mem_ctx, ctdb_get_vnn(ctdb));
		if (ret!=0) {
			DEBUG(0, (__location__ " failed to initiate recmaster election"));
		}
		talloc_free(mem_ctx);
		/*unban_all_nodes(ctdb);*/
		return;
	}

	/* release the recmaster lock */
	if (em->vnn != ctdb->vnn &&
	    ctdb->recovery_lock_fd != -1) {
		close(ctdb->recovery_lock_fd);
		ctdb->recovery_lock_fd = -1;
		unban_all_nodes(ctdb);
	}

	/* ok, let that guy become recmaster then */
	ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(), ctdb_get_vnn(ctdb), em->vnn);
	if (ret != 0) {
		DEBUG(0, (__location__ " failed to send recmaster election request"));
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
static void force_election(struct ctdb_recoverd *rec, TALLOC_CTX *mem_ctx, uint32_t vnn, 
			   struct ctdb_node_map *nodemap)
{
	int ret;
	struct ctdb_context *ctdb = rec->ctdb;

	/* set all nodes to recovery mode to stop all internode traffic */
	ret = set_recovery_mode(ctdb, nodemap, CTDB_RECOVERY_ACTIVE);
	if (ret!=0) {
		DEBUG(0, (__location__ " Unable to set recovery mode to active on cluster\n"));
		return;
	}
	
	ret = send_election_request(rec, mem_ctx, vnn);
	if (ret!=0) {
		DEBUG(0, (__location__ " failed to initiate recmaster election"));
		return;
	}

	/* wait for a few seconds to collect all responses */
	ctdb_wait_timeout(ctdb, ctdb->tunable.election_timeout);
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
	int i;

	if (data.dsize != sizeof(*c)) {
		DEBUG(0,(__location__ "Invalid data in ctdb_node_flag_change\n"));
		return;
	}

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY_VOID(ctdb, tmp_ctx);

	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);

	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].vnn == c->vnn) break;
	}

	if (i == nodemap->num) {
		DEBUG(0,(__location__ "Flag change for non-existant node %u\n", c->vnn));
		talloc_free(tmp_ctx);
		return;
	}

	/* Dont let messages from remote nodes change the DISCONNECTED flag. 
	   This flag is handled locally based on whether the local node
	   can communicate with the node or not.
	*/
	c->flags &= ~NODE_FLAGS_DISCONNECTED;
	if (nodemap->nodes[i].flags&NODE_FLAGS_DISCONNECTED) {
		c->flags |= NODE_FLAGS_DISCONNECTED;
	}

	if (nodemap->nodes[i].flags != c->flags) {
		DEBUG(0,("Node %u has changed flags - now 0x%x\n", c->vnn, c->flags));
	}

	nodemap->nodes[i].flags = c->flags;

	ret = ctdb_ctrl_getrecmaster(ctdb, CONTROL_TIMEOUT(), 
				     CTDB_CURRENT_NODE, &ctdb->recovery_master);

	if (ret == 0) {
		ret = ctdb_ctrl_getrecmode(ctdb, CONTROL_TIMEOUT(), 
					   CTDB_CURRENT_NODE, &ctdb->recovery_mode);
	}
	
	if (ret == 0 &&
	    ctdb->recovery_master == ctdb->vnn &&
	    ctdb->recovery_mode == CTDB_RECOVERY_NORMAL &&
	    ctdb->takeover.enabled) {
		ret = ctdb_takeover_run(ctdb, nodemap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to setup public takeover addresses\n"));
		}
	}

	talloc_free(tmp_ctx);
}



/*
  the main monitoring loop
 */
static void monitor_cluster(struct ctdb_context *ctdb)
{
	uint32_t vnn, num_active, recmode, recmaster;
	TALLOC_CTX *mem_ctx=NULL;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_node_map *remote_nodemap=NULL;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_vnn_map *remote_vnnmap=NULL;
	int i, j, ret;
	bool need_takeover_run;
	struct ctdb_recoverd *rec;

	rec = talloc_zero(ctdb, struct ctdb_recoverd);
	CTDB_NO_MEMORY_FATAL(ctdb, rec);

	rec->ctdb = ctdb;
	rec->banned_nodes = talloc_zero_array(rec, struct ban_state *, ctdb->num_nodes);
	CTDB_NO_MEMORY_FATAL(ctdb, rec->banned_nodes);

	rec->priority_time = timeval_current();

	/* register a message port for recovery elections */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_RECOVERY, election_handler, rec);

	/* and one for when nodes are disabled/enabled */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_NODE_FLAGS_CHANGED, monitor_handler, rec);

	/* and one for when nodes are banned */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_BAN_NODE, ban_handler, rec);

	/* and one for when nodes are unbanned */
	ctdb_set_message_handler(ctdb, CTDB_SRVID_UNBAN_NODE, unban_handler, rec);
	
again:
	need_takeover_run = false;

	if (mem_ctx) {
		talloc_free(mem_ctx);
		mem_ctx = NULL;
	}
	mem_ctx = talloc_new(ctdb);
	if (!mem_ctx) {
		DEBUG(0,("Failed to create temporary context\n"));
		exit(-1);
	}

	/* we only check for recovery once every second */
	ctdb_wait_timeout(ctdb, ctdb->tunable.recover_interval);

	/* get relevant tunables */
	ret = ctdb_ctrl_get_all_tunables(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, &ctdb->tunable);
	if (ret != 0) {
		DEBUG(0,("Failed to get tunables - retrying\n"));
		goto again;
	}

	vnn = ctdb_ctrl_getvnn(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE);
	if (vnn == (uint32_t)-1) {
		DEBUG(0,("Failed to get local vnn - retrying\n"));
		goto again;
	}

	/* get the vnnmap */
	ret = ctdb_ctrl_getvnnmap(ctdb, CONTROL_TIMEOUT(), vnn, mem_ctx, &vnnmap);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to get vnnmap from node %u\n", vnn));
		goto again;
	}


	/* get number of nodes */
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), vnn, mem_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to get nodemap from node %u\n", vnn));
		goto again;
	}


	/* count how many active nodes there are */
	num_active = 0;
	for (i=0; i<nodemap->num; i++) {
		if (rec->banned_nodes[nodemap->nodes[i].vnn] != NULL) {
			nodemap->nodes[i].flags |= NODE_FLAGS_BANNED;
		} else {
			nodemap->nodes[i].flags &= ~NODE_FLAGS_BANNED;
		}
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE)) {
			num_active++;
		}
	}


	/* check which node is the recovery master */
	ret = ctdb_ctrl_getrecmaster(ctdb, CONTROL_TIMEOUT(), vnn, &recmaster);
	if (ret != 0) {
		DEBUG(0, (__location__ " Unable to get recmaster from node %u\n", vnn));
		goto again;
	}

	if (recmaster == (uint32_t)-1) {
		DEBUG(0,(__location__ " Initial recovery master set - forcing election\n"));
		force_election(rec, mem_ctx, vnn, nodemap);
		goto again;
	}
	
	/* verify that the recmaster node is still active */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].vnn==recmaster) {
			break;
		}
	}

	if (j == nodemap->num) {
		DEBUG(0, ("Recmaster node %u not in list. Force reelection\n", recmaster));
		force_election(rec, mem_ctx, vnn, nodemap);
		goto again;
	}

	if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
		DEBUG(0, ("Recmaster node %u no longer available. Force reelection\n", nodemap->nodes[j].vnn));
		force_election(rec, mem_ctx, vnn, nodemap);
		goto again;
	}
	

	/* if we are not the recmaster then we do not need to check
	   if recovery is needed
	 */
	if (vnn!=recmaster) {
		goto again;
	}


	/* verify that all active nodes agree that we are the recmaster */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		ret = ctdb_ctrl_getrecmaster(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, &recmaster);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to get recmaster from node %u\n", vnn));
			goto again;
		}

		if (recmaster!=vnn) {
			DEBUG(0, ("Node %u does not agree we are the recmaster. Force reelection\n", 
				  nodemap->nodes[j].vnn));
			force_election(rec, mem_ctx, vnn, nodemap);
			goto again;
		}
	}


	/* verify that all active nodes are in normal mode 
	   and not in recovery mode 
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		ret = ctdb_ctrl_getrecmode(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, &recmode);
		if (ret != 0) {
			DEBUG(0, ("Unable to get recmode from node %u\n", vnn));
			goto again;
		}
		if (recmode != CTDB_RECOVERY_NORMAL) {
			DEBUG(0, (__location__ " Node:%u was in recovery mode. Restart recovery process\n", 
				  nodemap->nodes[j].vnn));
			do_recovery(rec, mem_ctx, vnn, num_active, nodemap, vnnmap, nodemap->nodes[j].vnn);
			goto again;
		}
	}


	/* get the nodemap for all active remote nodes and verify
	   they are the same as for this node
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, 
					   mem_ctx, &remote_nodemap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to get nodemap from remote node %u\n", 
				  nodemap->nodes[j].vnn));
			goto again;
		}

		/* if the nodes disagree on how many nodes there are
		   then this is a good reason to try recovery
		 */
		if (remote_nodemap->num != nodemap->num) {
			DEBUG(0, (__location__ " Remote node:%u has different node count. %u vs %u of the local node\n",
				  nodemap->nodes[j].vnn, remote_nodemap->num, nodemap->num));
			do_recovery(rec, mem_ctx, vnn, num_active, nodemap, vnnmap, nodemap->nodes[j].vnn);
			goto again;
		}

		/* if the nodes disagree on which nodes exist and are
		   active, then that is also a good reason to do recovery
		 */
		for (i=0;i<nodemap->num;i++) {
			if (remote_nodemap->nodes[i].vnn != nodemap->nodes[i].vnn) {
				DEBUG(0, (__location__ " Remote node:%u has different nodemap vnn for %d (%u vs %u).\n", 
					  nodemap->nodes[j].vnn, i, 
					  remote_nodemap->nodes[i].vnn, nodemap->nodes[i].vnn));
				do_recovery(rec, mem_ctx, vnn, num_active, nodemap, 
					    vnnmap, nodemap->nodes[j].vnn);
				goto again;
			}
			if ((remote_nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) != 
			    (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE)) {
				DEBUG(0, (__location__ " Remote node:%u has different nodemap flag for %d (0x%x vs 0x%x)\n", 
					  nodemap->nodes[j].vnn, i,
					  remote_nodemap->nodes[i].flags, nodemap->nodes[i].flags));
				do_recovery(rec, mem_ctx, vnn, num_active, nodemap, 
					    vnnmap, nodemap->nodes[j].vnn);
				goto again;
			}
		}

		/* update our nodemap flags according to the other
		   server - this gets the NODE_FLAGS_DISABLED
		   flag. Note that the remote node is authoritative
		   for its flags (except CONNECTED, which we know
		   matches in this code) */
		if (nodemap->nodes[j].flags != remote_nodemap->nodes[j].flags) {
			nodemap->nodes[j].flags = remote_nodemap->nodes[j].flags;
			need_takeover_run = true;
		}
	}


	/* there better be the same number of lmasters in the vnn map
	   as there are active nodes or we will have to do a recovery
	 */
	if (vnnmap->size != num_active) {
		DEBUG(0, (__location__ " The vnnmap count is different from the number of active nodes. %u vs %u\n", 
			  vnnmap->size, num_active));
		do_recovery(rec, mem_ctx, vnn, num_active, nodemap, vnnmap, ctdb->vnn);
		goto again;
	}

	/* verify that all active nodes in the nodemap also exist in 
	   the vnnmap.
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		for (i=0; i<vnnmap->size; i++) {
			if (vnnmap->map[i] == nodemap->nodes[j].vnn) {
				break;
			}
		}
		if (i == vnnmap->size) {
			DEBUG(0, (__location__ " Node %u is active in the nodemap but did not exist in the vnnmap\n", 
				  nodemap->nodes[j].vnn));
			do_recovery(rec, mem_ctx, vnn, num_active, nodemap, vnnmap, nodemap->nodes[j].vnn);
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
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		ret = ctdb_ctrl_getvnnmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].vnn, 
					  mem_ctx, &remote_vnnmap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to get vnnmap from remote node %u\n", 
				  nodemap->nodes[j].vnn));
			goto again;
		}

		/* verify the vnnmap generation is the same */
		if (vnnmap->generation != remote_vnnmap->generation) {
			DEBUG(0, (__location__ " Remote node %u has different generation of vnnmap. %u vs %u (ours)\n", 
				  nodemap->nodes[j].vnn, remote_vnnmap->generation, vnnmap->generation));
			do_recovery(rec, mem_ctx, vnn, num_active, nodemap, vnnmap, nodemap->nodes[j].vnn);
			goto again;
		}

		/* verify the vnnmap size is the same */
		if (vnnmap->size != remote_vnnmap->size) {
			DEBUG(0, (__location__ " Remote node %u has different size of vnnmap. %u vs %u (ours)\n", 
				  nodemap->nodes[j].vnn, remote_vnnmap->size, vnnmap->size));
			do_recovery(rec, mem_ctx, vnn, num_active, nodemap, vnnmap, nodemap->nodes[j].vnn);
			goto again;
		}

		/* verify the vnnmap is the same */
		for (i=0;i<vnnmap->size;i++) {
			if (remote_vnnmap->map[i] != vnnmap->map[i]) {
				DEBUG(0, (__location__ " Remote node %u has different vnnmap.\n", 
					  nodemap->nodes[j].vnn));
				do_recovery(rec, mem_ctx, vnn, num_active, nodemap, 
					    vnnmap, nodemap->nodes[j].vnn);
				goto again;
			}
		}
	}

	/* we might need to change who has what IP assigned */
	if (need_takeover_run && ctdb->takeover.enabled) {
		ret = ctdb_takeover_run(ctdb, nodemap);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to setup public takeover addresses\n"));
		}
	}

	goto again;

}

/*
  event handler for when the main ctdbd dies
 */
static void ctdb_recoverd_parent(struct event_context *ev, struct fd_event *fde, 
				 uint16_t flags, void *private_data)
{
	DEBUG(0,("recovery daemon parent died - exiting\n"));
	_exit(1);
}



/*
  startup the recovery daemon as a child of the main ctdb daemon
 */
int ctdb_start_recoverd(struct ctdb_context *ctdb)
{
	int ret;
	int fd[2];
	pid_t child;

	if (pipe(fd) != 0) {
		return -1;
	}

	child = fork();
	if (child == -1) {
		return -1;
	}
	
	if (child != 0) {
		close(fd[0]);
		return 0;
	}

	close(fd[1]);

	/* shutdown the transport */
	ctdb->methods->shutdown(ctdb);

	/* get a new event context */
	talloc_free(ctdb->ev);
	ctdb->ev = event_context_init(ctdb);

	event_add_fd(ctdb->ev, ctdb, fd[0], EVENT_FD_READ|EVENT_FD_AUTOCLOSE, 
		     ctdb_recoverd_parent, &fd[0]);	

	close(ctdb->daemon.sd);
	ctdb->daemon.sd = -1;

	srandom(getpid() ^ time(NULL));

	/* initialise ctdb */
	ret = ctdb_socket_connect(ctdb);
	if (ret != 0) {
		DEBUG(0, (__location__ " Failed to init ctdb\n"));
		exit(1);
	}

	monitor_cluster(ctdb);

	DEBUG(0,("ERROR: ctdb_recoverd finished!?\n"));
	return -1;
}
