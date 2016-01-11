/* 
   ctdb recovery code

   Copyright (C) Andrew Tridgell  2007
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
#include "replace.h"
#include "system/time.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/util_process.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

int 
ctdb_control_getvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_vnn_map_wire *map;
	size_t len;

	CHECK_CONTROL_DATA_SIZE(0);

	len = offsetof(struct ctdb_vnn_map_wire, map) + sizeof(uint32_t)*ctdb->vnn_map->size;
	map = talloc_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, map);

	map->generation = ctdb->vnn_map->generation;
	map->size = ctdb->vnn_map->size;
	memcpy(map->map, ctdb->vnn_map->map, sizeof(uint32_t)*map->size);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)map;

	return 0;
}

int
ctdb_control_setvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_vnn_map_wire *map = (struct ctdb_vnn_map_wire *)indata.dptr;

	if (ctdb->recovery_mode != CTDB_RECOVERY_ACTIVE) {
		DEBUG(DEBUG_ERR, ("Attempt to set vnnmap when not in recovery\n"));
		return -1;
	}

	talloc_free(ctdb->vnn_map);

	ctdb->vnn_map = talloc(ctdb, struct ctdb_vnn_map);
	CTDB_NO_MEMORY(ctdb, ctdb->vnn_map);

	ctdb->vnn_map->generation = map->generation;
	ctdb->vnn_map->size       = map->size;
	ctdb->vnn_map->map = talloc_array(ctdb->vnn_map, uint32_t, map->size);
	CTDB_NO_MEMORY(ctdb, ctdb->vnn_map->map);

	memcpy(ctdb->vnn_map->map, map->map, sizeof(uint32_t)*map->size);

	return 0;
}

int 
ctdb_control_getdbmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	uint32_t i, len;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_dbid_map_old *dbid_map;

	CHECK_CONTROL_DATA_SIZE(0);

	len = 0;
	for(ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next){
		len++;
	}


	outdata->dsize = offsetof(struct ctdb_dbid_map_old, dbs) + sizeof(dbid_map->dbs[0])*len;
	outdata->dptr  = (unsigned char *)talloc_zero_size(outdata, outdata->dsize);
	if (!outdata->dptr) {
		DEBUG(DEBUG_ALERT, (__location__ " Failed to allocate dbmap array\n"));
		exit(1);
	}

	dbid_map = (struct ctdb_dbid_map_old *)outdata->dptr;
	dbid_map->num = len;
	for (i=0,ctdb_db=ctdb->db_list;ctdb_db;i++,ctdb_db=ctdb_db->next){
		dbid_map->dbs[i].db_id       = ctdb_db->db_id;
		if (ctdb_db->persistent != 0) {
			dbid_map->dbs[i].flags |= CTDB_DB_FLAGS_PERSISTENT;
		}
		if (ctdb_db->readonly != 0) {
			dbid_map->dbs[i].flags |= CTDB_DB_FLAGS_READONLY;
		}
		if (ctdb_db->sticky != 0) {
			dbid_map->dbs[i].flags |= CTDB_DB_FLAGS_STICKY;
		}
	}

	return 0;
}

int
ctdb_control_getnodemap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	CHECK_CONTROL_DATA_SIZE(0);

	outdata->dptr  = (unsigned char *)ctdb_node_list_to_map(ctdb->nodes,
								ctdb->num_nodes,
								outdata);
	if (outdata->dptr == NULL) {
		return -1;
	}

	outdata->dsize = talloc_get_size(outdata->dptr);

	return 0;
}

/*
  reload the nodes file
*/
int
ctdb_control_reload_nodes_file(struct ctdb_context *ctdb, uint32_t opcode)
{
	int i, num_nodes;
	TALLOC_CTX *tmp_ctx;
	struct ctdb_node **nodes;

	tmp_ctx = talloc_new(ctdb);

	/* steal the old nodes file for a while */
	talloc_steal(tmp_ctx, ctdb->nodes);
	nodes = ctdb->nodes;
	ctdb->nodes = NULL;
	num_nodes = ctdb->num_nodes;
	ctdb->num_nodes = 0;

	/* load the new nodes file */
	ctdb_load_nodes_file(ctdb);

	for (i=0; i<ctdb->num_nodes; i++) {
		/* keep any identical pre-existing nodes and connections */
		if ((i < num_nodes) && ctdb_same_address(&ctdb->nodes[i]->address, &nodes[i]->address)) {
			talloc_free(ctdb->nodes[i]);
			ctdb->nodes[i] = talloc_steal(ctdb->nodes, nodes[i]);
			continue;
		}

		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		/* any new or different nodes must be added */
		if (ctdb->methods->add_node(ctdb->nodes[i]) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " methods->add_node failed at %d\n", i));
			ctdb_fatal(ctdb, "failed to add node. shutting down\n");
		}
		if (ctdb->methods->connect_node(ctdb->nodes[i]) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " methods->add_connect failed at %d\n", i));
			ctdb_fatal(ctdb, "failed to connect to node. shutting down\n");
		}
	}

	/* tell the recovery daemon to reaload the nodes file too */
	ctdb_daemon_send_message(ctdb, ctdb->pnn, CTDB_SRVID_RELOAD_NODES, tdb_null);

	talloc_free(tmp_ctx);

	return 0;
}

/* 
   a traverse function for pulling all relevent records from pulldb
 */
struct pulldb_data {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_marshall_buffer *pulldata;
	uint32_t len;
	uint32_t allocated_len;
	bool failed;
};

static int traverse_pulldb(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct pulldb_data *params = (struct pulldb_data *)p;
	struct ctdb_rec_data_old *rec;
	struct ctdb_context *ctdb = params->ctdb;
	struct ctdb_db_context *ctdb_db = params->ctdb_db;

	/* add the record to the blob */
	rec = ctdb_marshall_record(params->pulldata, 0, key, NULL, data);
	if (rec == NULL) {
		params->failed = true;
		return -1;
	}
	if (params->len + rec->length >= params->allocated_len) {
		params->allocated_len = rec->length + params->len + ctdb->tunable.pulldb_preallocation_size;
		params->pulldata = talloc_realloc_size(NULL, params->pulldata, params->allocated_len);
	}
	if (params->pulldata == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to expand pulldb_data to %u\n", rec->length + params->len));
		ctdb_fatal(params->ctdb, "failed to allocate memory for recovery. shutting down\n");
	}
	params->pulldata->count++;
	memcpy(params->len+(uint8_t *)params->pulldata, rec, rec->length);
	params->len += rec->length;

	if (ctdb->tunable.db_record_size_warn != 0 && rec->length > ctdb->tunable.db_record_size_warn) {
		DEBUG(DEBUG_ERR,("Data record in %s is big. Record size is %d bytes\n", ctdb_db->db_name, (int)rec->length));
	}

	talloc_free(rec);

	return 0;
}

/*
  pull a bunch of records from a ltdb, filtering by lmaster
 */
int32_t ctdb_control_pull_db(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_pulldb *pull;
	struct ctdb_db_context *ctdb_db;
	struct pulldb_data params;
	struct ctdb_marshall_buffer *reply;

	pull = (struct ctdb_pulldb *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, pull->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", pull->db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_pull_db when not frozen\n"));
		return -1;
	}

	reply = talloc_zero(outdata, struct ctdb_marshall_buffer);
	CTDB_NO_MEMORY(ctdb, reply);

	reply->db_id = pull->db_id;

	params.ctdb = ctdb;
	params.ctdb_db = ctdb_db;
	params.pulldata = reply;
	params.len = offsetof(struct ctdb_marshall_buffer, data);
	params.allocated_len = params.len;
	params.failed = false;

	if (ctdb_db->unhealthy_reason) {
		/* this is just a warning, as the tdb should be empty anyway */
		DEBUG(DEBUG_WARNING,("db(%s) unhealty in ctdb_control_pull_db: %s\n",
				     ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	if (ctdb_lockdb_mark(ctdb_db) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get lock on entire db - failing\n"));
		return -1;
	}

	if (tdb_traverse_read(ctdb_db->ltdb->tdb, traverse_pulldb, &params) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get traverse db '%s'\n", ctdb_db->db_name));
		ctdb_lockdb_unmark(ctdb_db);
		talloc_free(params.pulldata);
		return -1;
	}

	ctdb_lockdb_unmark(ctdb_db);

	outdata->dptr = (uint8_t *)params.pulldata;
	outdata->dsize = params.len;

	if (ctdb->tunable.db_record_count_warn != 0 && params.pulldata->count > ctdb->tunable.db_record_count_warn) {
		DEBUG(DEBUG_ERR,("Database %s is big. Contains %d records\n", ctdb_db->db_name, params.pulldata->count));
	}
	if (ctdb->tunable.db_size_warn != 0 && outdata->dsize > ctdb->tunable.db_size_warn) {
		DEBUG(DEBUG_ERR,("Database %s is big. Contains %d bytes\n", ctdb_db->db_name, (int)outdata->dsize));
	}


	return 0;
}

/*
  push a bunch of records into a ltdb, filtering by rsn
 */
int32_t ctdb_control_push_db(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_marshall_buffer *reply = (struct ctdb_marshall_buffer *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	int i, ret;
	struct ctdb_rec_data_old *rec;

	if (indata.dsize < offsetof(struct ctdb_marshall_buffer, data)) {
		DEBUG(DEBUG_ERR,(__location__ " invalid data in pulldb reply\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, reply->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", reply->db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_push_db when not frozen\n"));
		return -1;
	}

	if (ctdb_lockdb_mark(ctdb_db) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get lock on entire db - failing\n"));
		return -1;
	}

	rec = (struct ctdb_rec_data_old *)&reply->data[0];

	DEBUG(DEBUG_INFO,("starting push of %u records for dbid 0x%x\n",
		 reply->count, reply->db_id));

	for (i=0;i<reply->count;i++) {
		TDB_DATA key, data;
		struct ctdb_ltdb_header *hdr;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record\n"));
			goto failed;
		}
		hdr = (struct ctdb_ltdb_header *)data.dptr;
		/* strip off any read only record flags. All readonly records
		   are revoked implicitely by a recovery
		*/
		hdr->flags &= ~CTDB_REC_RO_FLAGS;

		data.dptr += sizeof(*hdr);
		data.dsize -= sizeof(*hdr);

		ret = ctdb_ltdb_store(ctdb_db, key, hdr, data);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " Unable to store record\n"));
			goto failed;
		}

		rec = (struct ctdb_rec_data_old *)(rec->length + (uint8_t *)rec);
	}	    

	DEBUG(DEBUG_DEBUG,("finished push of %u records for dbid 0x%x\n",
		 reply->count, reply->db_id));

	if (ctdb_db->readonly) {
		DEBUG(DEBUG_CRIT,("Clearing the tracking database for dbid 0x%x\n",
				  ctdb_db->db_id));
		if (tdb_wipe_all(ctdb_db->rottdb) != 0) {
			DEBUG(DEBUG_ERR,("Failed to wipe tracking database for 0x%x. Dropping read-only delegation support\n", ctdb_db->db_id));
			ctdb_db->readonly = false;
			tdb_close(ctdb_db->rottdb);
			ctdb_db->rottdb = NULL;
			ctdb_db->readonly = false;
		}
		while (ctdb_db->revokechild_active != NULL) {
			talloc_free(ctdb_db->revokechild_active);
		}
	}

	ctdb_lockdb_unmark(ctdb_db);
	return 0;

failed:
	ctdb_lockdb_unmark(ctdb_db);
	return -1;
}

struct ctdb_set_recmode_state {
	struct ctdb_context *ctdb;
	struct ctdb_req_control_old *c;
	uint32_t recmode;
	int fd[2];
	struct tevent_timer *te;
	struct tevent_fd *fde;
	pid_t child;
	struct timeval start_time;
};

/*
  called if our set_recmode child times out. this would happen if
  ctdb_recovery_lock() would block.
 */
static void ctdb_set_recmode_timeout(struct tevent_context *ev,
				     struct tevent_timer *te,
				     struct timeval t, void *private_data)
{
	struct ctdb_set_recmode_state *state = talloc_get_type(private_data, 
					   struct ctdb_set_recmode_state);

	/* we consider this a success, not a failure, as we failed to
	   set the recovery lock which is what we wanted.  This can be
	   caused by the cluster filesystem being very slow to
	   arbitrate locks immediately after a node failure.	   
	 */
	DEBUG(DEBUG_ERR,(__location__ " set_recmode child process hung/timedout CFS slow to grant locks? (allowing recmode set anyway)\n"));
	state->ctdb->recovery_mode = state->recmode;
	ctdb_request_control_reply(state->ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
}


/* when we free the recmode state we must kill any child process.
*/
static int set_recmode_destructor(struct ctdb_set_recmode_state *state)
{
	double l = timeval_elapsed(&state->start_time);

	CTDB_UPDATE_RECLOCK_LATENCY(state->ctdb, "daemon reclock", reclock.ctdbd, l);

	if (state->fd[0] != -1) {
		state->fd[0] = -1;
	}
	if (state->fd[1] != -1) {
		state->fd[1] = -1;
	}
	ctdb_kill(state->ctdb, state->child, SIGKILL);
	return 0;
}

/* this is called when the client process has completed ctdb_recovery_lock()
   and has written data back to us through the pipe.
*/
static void set_recmode_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags, void *private_data)
{
	struct ctdb_set_recmode_state *state= talloc_get_type(private_data, 
					     struct ctdb_set_recmode_state);
	char c = 0;
	int ret;

	/* we got a response from our child process so we can abort the
	   timeout.
	*/
	talloc_free(state->te);
	state->te = NULL;


	/* If, as expected, the child was unable to take the recovery
	 * lock then it will have written 0 into the pipe, so
	 * continue.  However, any other value (e.g. 1) indicates that
	 * it was able to take the recovery lock when it should have
	 * been held by the recovery daemon on the recovery master.
	*/
	ret = sys_read(state->fd[0], &c, 1);
	if (ret != 1 || c != 0) {
		ctdb_request_control_reply(
			state->ctdb, state->c, NULL, -1,
			"Took recovery lock from daemon during recovery - probably a cluster filesystem lock coherence problem");
		talloc_free(state);
		return;
	}

	state->ctdb->recovery_mode = state->recmode;

	/* release any deferred attach calls from clients */
	if (state->recmode == CTDB_RECOVERY_NORMAL) {
		ctdb_process_deferred_attach(state->ctdb);
	}

	ctdb_request_control_reply(state->ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
	return;
}

static void
ctdb_drop_all_ips_event(struct tevent_context *ev, struct tevent_timer *te,
			struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);

	DEBUG(DEBUG_ERR,(__location__ " Been in recovery mode for too long. Dropping all IPS\n"));
	talloc_free(ctdb->release_ips_ctx);
	ctdb->release_ips_ctx = NULL;

	ctdb_release_all_ips(ctdb);
}

/*
 * Set up an event to drop all public ips if we remain in recovery for too
 * long
 */
int ctdb_deferred_drop_all_ips(struct ctdb_context *ctdb)
{
	if (ctdb->release_ips_ctx != NULL) {
		talloc_free(ctdb->release_ips_ctx);
	}
	ctdb->release_ips_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, ctdb->release_ips_ctx);

	tevent_add_timer(ctdb->ev, ctdb->release_ips_ctx,
			 timeval_current_ofs(ctdb->tunable.recovery_drop_all_ips, 0),
			 ctdb_drop_all_ips_event, ctdb);
	return 0;
}

/*
  set the recovery mode
 */
int32_t ctdb_control_set_recmode(struct ctdb_context *ctdb, 
				 struct ctdb_req_control_old *c,
				 TDB_DATA indata, bool *async_reply,
				 const char **errormsg)
{
	uint32_t recmode = *(uint32_t *)indata.dptr;
	int i, ret;
	struct ctdb_set_recmode_state *state;
	pid_t parent = getpid();
	struct ctdb_db_context *ctdb_db;

	/* if we enter recovery but stay in recovery for too long
	   we will eventually drop all our ip addresses
	*/
	if (recmode == CTDB_RECOVERY_NORMAL) {
		talloc_free(ctdb->release_ips_ctx);
		ctdb->release_ips_ctx = NULL;
	} else {
		if (ctdb_deferred_drop_all_ips(ctdb) != 0) {
			DEBUG(DEBUG_ERR,("Failed to set up deferred drop all ips\n"));
		}
	}

	if (recmode != ctdb->recovery_mode) {
		DEBUG(DEBUG_NOTICE,(__location__ " Recovery mode set to %s\n", 
			 recmode==CTDB_RECOVERY_NORMAL?"NORMAL":"ACTIVE"));
	}

	if (recmode != CTDB_RECOVERY_NORMAL ||
	    ctdb->recovery_mode != CTDB_RECOVERY_ACTIVE) {
		ctdb->recovery_mode = recmode;
		return 0;
	}

	/* some special handling when ending recovery mode */

	for (ctdb_db = ctdb->db_list; ctdb_db != NULL; ctdb_db = ctdb_db->next) {
		if (ctdb_db->generation != ctdb->vnn_map->generation) {
			DEBUG(DEBUG_ERR,
			      ("Inconsistent DB generation %u for %s\n",
			       ctdb_db->generation, ctdb_db->db_name));
			DEBUG(DEBUG_ERR, ("Recovery mode set to ACTIVE\n"));
			return -1;
		}
	}

	/* force the databases to thaw */
	for (i=1; i<=NUM_DB_PRIORITIES; i++) {
		if (ctdb_db_prio_frozen(ctdb, i)) {
			ctdb_control_thaw(ctdb, i, false);
		}
	}

	/* release any deferred attach calls from clients */
	if (recmode == CTDB_RECOVERY_NORMAL) {
		ctdb_process_deferred_attach(ctdb);
	}

	if (ctdb->recovery_lock_file == NULL) {
		/* Not using recovery lock file */
		ctdb->recovery_mode = recmode;
		return 0;
	}

	state = talloc(ctdb, struct ctdb_set_recmode_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->start_time = timeval_current();
	state->fd[0] = -1;
	state->fd[1] = -1;

	/* For the rest of what needs to be done, we need to do this in
	   a child process since 
	   1, the call to ctdb_recovery_lock() can block if the cluster
	      filesystem is in the process of recovery.
	*/
	ret = pipe(state->fd);
	if (ret != 0) {
		talloc_free(state);
		DEBUG(DEBUG_CRIT,(__location__ " Failed to open pipe for set_recmode child\n"));
		return -1;
	}

	state->child = ctdb_fork(ctdb);
	if (state->child == (pid_t)-1) {
		close(state->fd[0]);
		close(state->fd[1]);
		talloc_free(state);
		return -1;
	}

	if (state->child == 0) {
		char cc = 0;
		close(state->fd[0]);

		prctl_set_comment("ctdb_recmode");
		debug_extra = talloc_asprintf(NULL, "set_recmode:");
		/* Daemon should not be able to get the recover lock,
		 * as it should be held by the recovery master */
		if (ctdb_recovery_lock(ctdb)) {
			DEBUG(DEBUG_ERR,
			      ("ERROR: Daemon able to take recovery lock on \"%s\" during recovery\n",
			       ctdb->recovery_lock_file));
			ctdb_recovery_unlock(ctdb);
			cc = 1;
		}

		sys_write(state->fd[1], &cc, 1);
		/* make sure we die when our parent dies */
		while (ctdb_kill(ctdb, parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
			sys_write(state->fd[1], &cc, 1);
		}
		_exit(0);
	}
	close(state->fd[1]);
	set_close_on_exec(state->fd[0]);

	state->fd[1] = -1;

	talloc_set_destructor(state, set_recmode_destructor);

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d for setrecmode\n", state->fd[0]));

	state->te = tevent_add_timer(ctdb->ev, state, timeval_current_ofs(5, 0),
				     ctdb_set_recmode_timeout, state);

	state->fde = tevent_add_fd(ctdb->ev, state, state->fd[0], TEVENT_FD_READ,
				   set_recmode_handler, (void *)state);

	if (state->fde == NULL) {
		talloc_free(state);
		return -1;
	}
	tevent_fd_set_auto_close(state->fde);

	state->ctdb    = ctdb;
	state->recmode = recmode;
	state->c       = talloc_steal(state, c);

	*async_reply = true;

	return 0;
}


bool ctdb_recovery_have_lock(struct ctdb_context *ctdb)
{
	return ctdb->recovery_lock_fd != -1;
}

/*
  try and get the recovery lock in shared storage - should only work
  on the recovery master recovery daemon. Anywhere else is a bug
 */
bool ctdb_recovery_lock(struct ctdb_context *ctdb)
{
	struct flock lock;

	ctdb->recovery_lock_fd = open(ctdb->recovery_lock_file,
				      O_RDWR|O_CREAT, 0600);
	if (ctdb->recovery_lock_fd == -1) {
		DEBUG(DEBUG_ERR,
		      ("ctdb_recovery_lock: Unable to open %s - (%s)\n",
		       ctdb->recovery_lock_file, strerror(errno)));
		return false;
	}

	set_close_on_exec(ctdb->recovery_lock_fd);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 1;
	lock.l_pid = 0;

	if (fcntl(ctdb->recovery_lock_fd, F_SETLK, &lock) != 0) {
		int saved_errno = errno;
		close(ctdb->recovery_lock_fd);
		ctdb->recovery_lock_fd = -1;
		/* Fail silently on these errors, since they indicate
		 * lock contention, but log an error for any other
		 * failure. */
		if (saved_errno != EACCES &&
		    saved_errno != EAGAIN) {
			DEBUG(DEBUG_ERR,("ctdb_recovery_lock: Failed to get "
					 "recovery lock on '%s' - (%s)\n",
					 ctdb->recovery_lock_file,
					 strerror(saved_errno)));
		}
		return false;
	}

	return true;
}

void ctdb_recovery_unlock(struct ctdb_context *ctdb)
{
	if (ctdb->recovery_lock_fd != -1) {
		DEBUG(DEBUG_NOTICE, ("Releasing recovery lock\n"));
		close(ctdb->recovery_lock_fd);
		ctdb->recovery_lock_fd = -1;
	}
}

/*
  delete a record as part of the vacuum process
  only delete if we are not lmaster or dmaster, and our rsn is <= the provided rsn
  use non-blocking locks

  return 0 if the record was successfully deleted (i.e. it does not exist
  when the function returns)
  or !0 is the record still exists in the tdb after returning.
 */
static int delete_tdb_record(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, struct ctdb_rec_data_old *rec)
{
	TDB_DATA key, data, data2;
	struct ctdb_ltdb_header *hdr, *hdr2;
	
	/* these are really internal tdb functions - but we need them here for
	   non-blocking lock of the freelist */
	int tdb_lock_nonblock(struct tdb_context *tdb, int list, int ltype);
	int tdb_unlock(struct tdb_context *tdb, int list, int ltype);


	key.dsize = rec->keylen;
	key.dptr  = &rec->data[0];
	data.dsize = rec->datalen;
	data.dptr = &rec->data[rec->keylen];

	if (ctdb_lmaster(ctdb, &key) == ctdb->pnn) {
		DEBUG(DEBUG_INFO,(__location__ " Called delete on record where we are lmaster\n"));
		return -1;
	}

	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		DEBUG(DEBUG_ERR,(__location__ " Bad record size\n"));
		return -1;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	/* use a non-blocking lock */
	if (tdb_chainlock_nonblock(ctdb_db->ltdb->tdb, key) != 0) {
		return -1;
	}

	data2 = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (data2.dptr == NULL) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		return 0;
	}

	if (data2.dsize < sizeof(struct ctdb_ltdb_header)) {
		if (tdb_lock_nonblock(ctdb_db->ltdb->tdb, -1, F_WRLCK) == 0) {
			if (tdb_delete(ctdb_db->ltdb->tdb, key) != 0) {
				DEBUG(DEBUG_CRIT,(__location__ " Failed to delete corrupt record\n"));
			}
			tdb_unlock(ctdb_db->ltdb->tdb, -1, F_WRLCK);
			DEBUG(DEBUG_CRIT,(__location__ " Deleted corrupt record\n"));
		}
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		free(data2.dptr);
		return 0;
	}
	
	hdr2 = (struct ctdb_ltdb_header *)data2.dptr;

	if (hdr2->rsn > hdr->rsn) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DEBUG(DEBUG_INFO,(__location__ " Skipping record with rsn=%llu - called with rsn=%llu\n",
			 (unsigned long long)hdr2->rsn, (unsigned long long)hdr->rsn));
		free(data2.dptr);
		return -1;
	}

	/* do not allow deleting record that have readonly flags set. */
	if (hdr->flags & CTDB_REC_RO_FLAGS) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DEBUG(DEBUG_INFO,(__location__ " Skipping record with readonly flags set\n"));
		free(data2.dptr);
		return -1;
	}
	if (hdr2->flags & CTDB_REC_RO_FLAGS) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DEBUG(DEBUG_INFO,(__location__ " Skipping record with readonly flags set\n"));
		free(data2.dptr);
		return -1;
	}

	if (hdr2->dmaster == ctdb->pnn) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DEBUG(DEBUG_INFO,(__location__ " Attempted delete record where we are the dmaster\n"));
		free(data2.dptr);
		return -1;
	}

	if (tdb_lock_nonblock(ctdb_db->ltdb->tdb, -1, F_WRLCK) != 0) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		free(data2.dptr);
		return -1;
	}

	if (tdb_delete(ctdb_db->ltdb->tdb, key) != 0) {
		tdb_unlock(ctdb_db->ltdb->tdb, -1, F_WRLCK);
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DEBUG(DEBUG_INFO,(__location__ " Failed to delete record\n"));
		free(data2.dptr);
		return -1;
	}

	tdb_unlock(ctdb_db->ltdb->tdb, -1, F_WRLCK);
	tdb_chainunlock(ctdb_db->ltdb->tdb, key);
	free(data2.dptr);
	return 0;
}



struct recovery_callback_state {
	struct ctdb_req_control_old *c;
};


/*
  called when the 'recovered' event script has finished
 */
static void ctdb_end_recovery_callback(struct ctdb_context *ctdb, int status, void *p)
{
	struct recovery_callback_state *state = talloc_get_type(p, struct recovery_callback_state);

	ctdb_enable_monitoring(ctdb);
	CTDB_INCREMENT_STAT(ctdb, num_recoveries);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " recovered event script failed (status %d)\n", status));
		if (status == -ETIME) {
			ctdb_ban_self(ctdb);
		}
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	talloc_free(state);

	gettimeofday(&ctdb->last_recovery_finished, NULL);

	if (ctdb->runstate == CTDB_RUNSTATE_FIRST_RECOVERY) {
		ctdb_set_runstate(ctdb, CTDB_RUNSTATE_STARTUP);
	}
}

/*
  recovery has finished
 */
int32_t ctdb_control_end_recovery(struct ctdb_context *ctdb, 
				struct ctdb_req_control_old *c,
				bool *async_reply)
{
	int ret;
	struct recovery_callback_state *state;

	DEBUG(DEBUG_NOTICE,("Recovery has finished\n"));

	ctdb_persistent_finish_trans3_commits(ctdb);

	state = talloc(ctdb, struct recovery_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c    = c;

	ctdb_disable_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, state,
					 ctdb_end_recovery_callback, 
					 state, 
					 CTDB_EVENT_RECOVERED, "%s", "");

	if (ret != 0) {
		ctdb_enable_monitoring(ctdb);

		DEBUG(DEBUG_ERR,(__location__ " Failed to end recovery\n"));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	state->c    = talloc_steal(state, c);
	*async_reply = true;
	return 0;
}

/*
  called when the 'startrecovery' event script has finished
 */
static void ctdb_start_recovery_callback(struct ctdb_context *ctdb, int status, void *p)
{
	struct recovery_callback_state *state = talloc_get_type(p, struct recovery_callback_state);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " startrecovery event script failed (status %d)\n", status));
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	talloc_free(state);
}

/*
  run the startrecovery eventscript
 */
int32_t ctdb_control_start_recovery(struct ctdb_context *ctdb, 
				struct ctdb_req_control_old *c,
				bool *async_reply)
{
	int ret;
	struct recovery_callback_state *state;

	DEBUG(DEBUG_NOTICE,(__location__ " startrecovery eventscript has been invoked\n"));
	gettimeofday(&ctdb->last_recovery_started, NULL);

	state = talloc(ctdb, struct recovery_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c    = talloc_steal(state, c);

	ctdb_disable_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, state,
					 ctdb_start_recovery_callback, 
					 state,
					 CTDB_EVENT_START_RECOVERY,
					 "%s", "");

	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to start recovery\n"));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	*async_reply = true;
	return 0;
}

/*
 try to delete all these records as part of the vacuuming process
 and return the records we failed to delete
*/
int32_t ctdb_control_try_delete_records(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_marshall_buffer *reply = (struct ctdb_marshall_buffer *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	int i;
	struct ctdb_rec_data_old *rec;
	struct ctdb_marshall_buffer *records;

	if (indata.dsize < offsetof(struct ctdb_marshall_buffer, data)) {
		DEBUG(DEBUG_ERR,(__location__ " invalid data in try_delete_records\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, reply->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", reply->db_id));
		return -1;
	}


	DEBUG(DEBUG_DEBUG,("starting try_delete_records of %u records for dbid 0x%x\n",
		 reply->count, reply->db_id));


	/* create a blob to send back the records we couldnt delete */	
	records = (struct ctdb_marshall_buffer *)
			talloc_zero_size(outdata, 
				    offsetof(struct ctdb_marshall_buffer, data));
	if (records == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}
	records->db_id = ctdb_db->db_id;


	rec = (struct ctdb_rec_data_old *)&reply->data[0];
	for (i=0;i<reply->count;i++) {
		TDB_DATA key, data;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record in indata\n"));
			return -1;
		}

		/* If we cant delete the record we must add it to the reply
		   so the lmaster knows it may not purge this record
		*/
		if (delete_tdb_record(ctdb, ctdb_db, rec) != 0) {
			size_t old_size;
			struct ctdb_ltdb_header *hdr;

			hdr = (struct ctdb_ltdb_header *)data.dptr;
			data.dptr += sizeof(*hdr);
			data.dsize -= sizeof(*hdr);

			DEBUG(DEBUG_INFO, (__location__ " Failed to vacuum delete record with hash 0x%08x\n", ctdb_hash(&key)));

			old_size = talloc_get_size(records);
			records = talloc_realloc_size(outdata, records, old_size + rec->length);
			if (records == NULL) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to expand\n"));
				return -1;
			}
			records->count++;
			memcpy(old_size+(uint8_t *)records, rec, rec->length);
		} 

		rec = (struct ctdb_rec_data_old *)(rec->length + (uint8_t *)rec);
	}	    


	*outdata = ctdb_marshall_finish(records);

	return 0;
}

/**
 * Store a record as part of the vacuum process:
 * This is called from the RECEIVE_RECORD control which
 * the lmaster uses to send the current empty copy
 * to all nodes for storing, before it lets the other
 * nodes delete the records in the second phase with
 * the TRY_DELETE_RECORDS control.
 *
 * Only store if we are not lmaster or dmaster, and our
 * rsn is <= the provided rsn. Use non-blocking locks.
 *
 * return 0 if the record was successfully stored.
 * return !0 if the record still exists in the tdb after returning.
 */
static int store_tdb_record(struct ctdb_context *ctdb,
			    struct ctdb_db_context *ctdb_db,
			    struct ctdb_rec_data_old *rec)
{
	TDB_DATA key, data, data2;
	struct ctdb_ltdb_header *hdr, *hdr2;
	int ret;

	key.dsize = rec->keylen;
	key.dptr = &rec->data[0];
	data.dsize = rec->datalen;
	data.dptr = &rec->data[rec->keylen];

	if (ctdb_lmaster(ctdb, &key) == ctdb->pnn) {
		DEBUG(DEBUG_INFO, (__location__ " Called store_tdb_record "
				   "where we are lmaster\n"));
		return -1;
	}

	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		DEBUG(DEBUG_ERR, (__location__ " Bad record size\n"));
		return -1;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	/* use a non-blocking lock */
	if (tdb_chainlock_nonblock(ctdb_db->ltdb->tdb, key) != 0) {
		DEBUG(DEBUG_INFO, (__location__ " Failed to lock chain in non-blocking mode\n"));
		return -1;
	}

	data2 = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (data2.dptr == NULL || data2.dsize < sizeof(struct ctdb_ltdb_header)) {
		if (tdb_store(ctdb_db->ltdb->tdb, key, data, 0) == -1) {
			DEBUG(DEBUG_ERR, (__location__ "Failed to store record\n"));
			ret = -1;
			goto done;
		}
		DEBUG(DEBUG_INFO, (__location__ " Stored record\n"));
		ret = 0;
		goto done;
	}

	hdr2 = (struct ctdb_ltdb_header *)data2.dptr;

	if (hdr2->rsn > hdr->rsn) {
		DEBUG(DEBUG_INFO, (__location__ " Skipping record with "
				   "rsn=%llu - called with rsn=%llu\n",
				   (unsigned long long)hdr2->rsn,
				   (unsigned long long)hdr->rsn));
		ret = -1;
		goto done;
	}

	/* do not allow vacuuming of records that have readonly flags set. */
	if (hdr->flags & CTDB_REC_RO_FLAGS) {
		DEBUG(DEBUG_INFO,(__location__ " Skipping record with readonly "
				  "flags set\n"));
		ret = -1;
		goto done;
	}
	if (hdr2->flags & CTDB_REC_RO_FLAGS) {
		DEBUG(DEBUG_INFO,(__location__ " Skipping record with readonly "
				  "flags set\n"));
		ret = -1;
		goto done;
	}

	if (hdr2->dmaster == ctdb->pnn) {
		DEBUG(DEBUG_INFO, (__location__ " Attempted to store record "
				   "where we are the dmaster\n"));
		ret = -1;
		goto done;
	}

	if (tdb_store(ctdb_db->ltdb->tdb, key, data, 0) != 0) {
		DEBUG(DEBUG_INFO,(__location__ " Failed to store record\n"));
		ret = -1;
		goto done;
	}

	ret = 0;

done:
	tdb_chainunlock(ctdb_db->ltdb->tdb, key);
	free(data2.dptr);
	return  ret;
}



/**
 * Try to store all these records as part of the vacuuming process
 * and return the records we failed to store.
 */
int32_t ctdb_control_receive_records(struct ctdb_context *ctdb,
				     TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_marshall_buffer *reply = (struct ctdb_marshall_buffer *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	int i;
	struct ctdb_rec_data_old *rec;
	struct ctdb_marshall_buffer *records;

	if (indata.dsize < offsetof(struct ctdb_marshall_buffer, data)) {
		DEBUG(DEBUG_ERR,
		      (__location__ " invalid data in receive_records\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, reply->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR, (__location__ " Unknown db 0x%08x\n",
				  reply->db_id));
		return -1;
	}

	DEBUG(DEBUG_DEBUG, ("starting receive_records of %u records for "
			    "dbid 0x%x\n", reply->count, reply->db_id));

	/* create a blob to send back the records we could not store */
	records = (struct ctdb_marshall_buffer *)
			talloc_zero_size(outdata,
				offsetof(struct ctdb_marshall_buffer, data));
	if (records == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Out of memory\n"));
		return -1;
	}
	records->db_id = ctdb_db->db_id;

	rec = (struct ctdb_rec_data_old *)&reply->data[0];
	for (i=0; i<reply->count; i++) {
		TDB_DATA key, data;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT, (__location__ " bad ltdb record "
					   "in indata\n"));
			return -1;
		}

		/*
		 * If we can not store the record we must add it to the reply
		 * so the lmaster knows it may not purge this record.
		 */
		if (store_tdb_record(ctdb, ctdb_db, rec) != 0) {
			size_t old_size;
			struct ctdb_ltdb_header *hdr;

			hdr = (struct ctdb_ltdb_header *)data.dptr;
			data.dptr += sizeof(*hdr);
			data.dsize -= sizeof(*hdr);

			DEBUG(DEBUG_INFO, (__location__ " Failed to store "
					   "record with hash 0x%08x in vacuum "
					   "via RECEIVE_RECORDS\n",
					   ctdb_hash(&key)));

			old_size = talloc_get_size(records);
			records = talloc_realloc_size(outdata, records,
						      old_size + rec->length);
			if (records == NULL) {
				DEBUG(DEBUG_ERR, (__location__ " Failed to "
						  "expand\n"));
				return -1;
			}
			records->count++;
			memcpy(old_size+(uint8_t *)records, rec, rec->length);
		}

		rec = (struct ctdb_rec_data_old *)(rec->length + (uint8_t *)rec);
	}

	*outdata = ctdb_marshall_finish(records);

	return 0;
}


/*
  report capabilities
 */
int32_t ctdb_control_get_capabilities(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	uint32_t *capabilities = NULL;

	capabilities = talloc(outdata, uint32_t);
	CTDB_NO_MEMORY(ctdb, capabilities);
	*capabilities = ctdb->capabilities;

	outdata->dsize = sizeof(uint32_t);
	outdata->dptr = (uint8_t *)capabilities;

	return 0;	
}

/* The recovery daemon will ping us at regular intervals.
   If we havent been pinged for a while we assume the recovery
   daemon is inoperable and we restart.
*/
static void ctdb_recd_ping_timeout(struct tevent_context *ev,
				   struct tevent_timer *te,
				   struct timeval t, void *p)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);
	uint32_t *count = talloc_get_type(ctdb->recd_ping_count, uint32_t);

	DEBUG(DEBUG_ERR, ("Recovery daemon ping timeout. Count : %u\n", *count));

	if (*count < ctdb->tunable.recd_ping_failcount) {
		(*count)++;
		tevent_add_timer(ctdb->ev, ctdb->recd_ping_count,
				 timeval_current_ofs(ctdb->tunable.recd_ping_timeout, 0),
				 ctdb_recd_ping_timeout, ctdb);
		return;
	}

	DEBUG(DEBUG_ERR, ("Final timeout for recovery daemon ping. Restarting recovery daemon. (This can be caused if the cluster filesystem has hung)\n"));

	ctdb_stop_recoverd(ctdb);
	ctdb_start_recoverd(ctdb);
}

int32_t ctdb_control_recd_ping(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->recd_ping_count);

	ctdb->recd_ping_count = talloc_zero(ctdb, uint32_t);
	CTDB_NO_MEMORY(ctdb, ctdb->recd_ping_count);

	if (ctdb->tunable.recd_ping_timeout != 0) {
		tevent_add_timer(ctdb->ev, ctdb->recd_ping_count,
				 timeval_current_ofs(ctdb->tunable.recd_ping_timeout, 0),
				 ctdb_recd_ping_timeout, ctdb);
	}

	return 0;
}



int32_t ctdb_control_set_recmaster(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata)
{
	uint32_t new_recmaster;

	CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
	new_recmaster = ((uint32_t *)(&indata.dptr[0]))[0];

	if (ctdb->pnn != new_recmaster && ctdb->recovery_master == ctdb->pnn) {
		DEBUG(DEBUG_NOTICE,
		      ("This node (%u) is no longer the recovery master\n", ctdb->pnn));
	}

	if (ctdb->pnn == new_recmaster && ctdb->recovery_master != new_recmaster) {
		DEBUG(DEBUG_NOTICE,
		      ("This node (%u) is now the recovery master\n", ctdb->pnn));
	}

	ctdb->recovery_master = new_recmaster;
	return 0;
}


int32_t ctdb_control_stop_node(struct ctdb_context *ctdb)
{
	DEBUG(DEBUG_NOTICE, ("Stopping node\n"));
	ctdb_disable_monitoring(ctdb);
	ctdb->nodes[ctdb->pnn]->flags |= NODE_FLAGS_STOPPED;

	return 0;
}

int32_t ctdb_control_continue_node(struct ctdb_context *ctdb)
{
	DEBUG(DEBUG_NOTICE, ("Continue node\n"));
	ctdb->nodes[ctdb->pnn]->flags &= ~NODE_FLAGS_STOPPED;

	return 0;
}

