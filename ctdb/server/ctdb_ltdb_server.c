/* 
   ctdb ltdb code - server side

   Copyright (C) Andrew Tridgell  2007

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
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "system/time.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "lib/util/dlinklist.h"
#include <ctype.h>

#define PERSISTENT_HEALTH_TDB "persistent_health.tdb"

/*
  this is the dummy null procedure that all databases support
*/
static int ctdb_null_func(struct ctdb_call_info *call)
{
	return 0;
}

/*
  this is a plain fetch procedure that all databases support
*/
static int ctdb_fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
}



struct lock_fetch_state {
	struct ctdb_context *ctdb;
	void (*recv_pkt)(void *, struct ctdb_req_header *);
	void *recv_context;
	struct ctdb_req_header *hdr;
	uint32_t generation;
	bool ignore_generation;
};

/*
  called when we should retry the operation
 */
static void lock_fetch_callback(void *p)
{
	struct lock_fetch_state *state = talloc_get_type(p, struct lock_fetch_state);
	if (!state->ignore_generation &&
	    state->generation != state->ctdb->vnn_map->generation) {
		DEBUG(DEBUG_NOTICE,("Discarding previous generation lockwait packet\n"));
		talloc_free(state->hdr);
		return;
	}
	state->recv_pkt(state->recv_context, state->hdr);
	DEBUG(DEBUG_INFO,(__location__ " PACKET REQUEUED\n"));
}


/*
  do a non-blocking ltdb_lock, deferring this ctdb request until we
  have the chainlock

  It does the following:

   1) tries to get the chainlock. If it succeeds, then it returns 0

   2) if it fails to get a chainlock immediately then it sets up a
   non-blocking chainlock via ctdb_lockwait, and when it gets the
   chainlock it re-submits this ctdb request to the main packet
   receive function

   This effectively queues all ctdb requests that cannot be
   immediately satisfied until it can get the lock. This means that
   the main ctdb daemon will not block waiting for a chainlock held by
   a client

   There are 3 possible return values:

       0:    means that it got the lock immediately.
      -1:    means that it failed to get the lock, and won't retry
      -2:    means that it failed to get the lock immediately, but will retry
 */
int ctdb_ltdb_lock_requeue(struct ctdb_db_context *ctdb_db, 
			   TDB_DATA key, struct ctdb_req_header *hdr,
			   void (*recv_pkt)(void *, struct ctdb_req_header *),
			   void *recv_context, bool ignore_generation)
{
	int ret;
	struct tdb_context *tdb = ctdb_db->ltdb->tdb;
	struct lockwait_handle *h;
	struct lock_fetch_state *state;
	
	ret = tdb_chainlock_nonblock(tdb, key);

	if (ret != 0 &&
	    !(errno == EACCES || errno == EAGAIN || errno == EDEADLK)) {
		/* a hard failure - don't try again */
		return -1;
	}

	/* when torturing, ensure we test the contended path */
	if ((ctdb_db->ctdb->flags & CTDB_FLAG_TORTURE) &&
	    random() % 5 == 0) {
		ret = -1;
		tdb_chainunlock(tdb, key);
	}

	/* first the non-contended path */
	if (ret == 0) {
		return 0;
	}

	state = talloc(hdr, struct lock_fetch_state);
	state->ctdb = ctdb_db->ctdb;
	state->hdr = hdr;
	state->recv_pkt = recv_pkt;
	state->recv_context = recv_context;
	state->generation = ctdb_db->ctdb->vnn_map->generation;
	state->ignore_generation = ignore_generation;

	/* now the contended path */
	h = ctdb_lockwait(ctdb_db, key, lock_fetch_callback, state);
	if (h == NULL) {
		tdb_chainunlock(tdb, key);
		return -1;
	}

	/* we need to move the packet off the temporary context in ctdb_input_pkt(),
	   so it won't be freed yet */
	talloc_steal(state, hdr);
	talloc_steal(state, h);

	/* now tell the caller than we will retry asynchronously */
	return -2;
}

/*
  a varient of ctdb_ltdb_lock_requeue that also fetches the record
 */
int ctdb_ltdb_lock_fetch_requeue(struct ctdb_db_context *ctdb_db, 
				 TDB_DATA key, struct ctdb_ltdb_header *header, 
				 struct ctdb_req_header *hdr, TDB_DATA *data,
				 void (*recv_pkt)(void *, struct ctdb_req_header *),
				 void *recv_context, bool ignore_generation)
{
	int ret;

	ret = ctdb_ltdb_lock_requeue(ctdb_db, key, hdr, recv_pkt, 
				     recv_context, ignore_generation);
	if (ret == 0) {
		ret = ctdb_ltdb_fetch(ctdb_db, key, header, hdr, data);
		if (ret != 0) {
			ctdb_ltdb_unlock(ctdb_db, key);
		}
	}
	return ret;
}


/*
  paraoid check to see if the db is empty
 */
static void ctdb_check_db_empty(struct ctdb_db_context *ctdb_db)
{
	struct tdb_context *tdb = ctdb_db->ltdb->tdb;
	int count = tdb_traverse_read(tdb, NULL, NULL);
	if (count != 0) {
		DEBUG(DEBUG_ALERT,(__location__ " tdb '%s' not empty on attach! aborting\n",
			 ctdb_db->db_path));
		ctdb_fatal(ctdb_db->ctdb, "database not empty on attach");
	}
}

int ctdb_load_persistent_health(struct ctdb_context *ctdb,
				struct ctdb_db_context *ctdb_db)
{
	struct tdb_context *tdb = ctdb->db_persistent_health->tdb;
	char *old;
	char *reason = NULL;
	TDB_DATA key;
	TDB_DATA val;

	key.dptr = discard_const_p(uint8_t, ctdb_db->db_name);
	key.dsize = strlen(ctdb_db->db_name);

	old = ctdb_db->unhealthy_reason;
	ctdb_db->unhealthy_reason = NULL;

	val = tdb_fetch(tdb, key);
	if (val.dsize > 0) {
		reason = talloc_strndup(ctdb_db,
					(const char *)val.dptr,
					val.dsize);
		if (reason == NULL) {
			DEBUG(DEBUG_ALERT,(__location__ " talloc_strndup(%d) failed\n",
					   (int)val.dsize));
			ctdb_db->unhealthy_reason = old;
			free(val.dptr);
			return -1;
		}
	}

	if (val.dptr) {
		free(val.dptr);
	}

	talloc_free(old);
	ctdb_db->unhealthy_reason = reason;
	return 0;
}

int ctdb_update_persistent_health(struct ctdb_context *ctdb,
				  struct ctdb_db_context *ctdb_db,
				  const char *given_reason,/* NULL means healthy */
				  int num_healthy_nodes)
{
	struct tdb_context *tdb = ctdb->db_persistent_health->tdb;
	int ret;
	TDB_DATA key;
	TDB_DATA val;
	char *new_reason = NULL;
	char *old_reason = NULL;

	ret = tdb_transaction_start(tdb);
	if (ret != 0) {
		DEBUG(DEBUG_ALERT,(__location__ " tdb_transaction_start('%s') failed: %d - %s\n",
				   tdb_name(tdb), ret, tdb_errorstr(tdb)));
		return -1;
	}

	ret = ctdb_load_persistent_health(ctdb, ctdb_db);
	if (ret != 0) {
		DEBUG(DEBUG_ALERT,(__location__ " ctdb_load_persistent_health('%s') failed: %d\n",
				   ctdb_db->db_name, ret));
		return -1;
	}
	old_reason = ctdb_db->unhealthy_reason;

	key.dptr = discard_const_p(uint8_t, ctdb_db->db_name);
	key.dsize = strlen(ctdb_db->db_name);

	if (given_reason) {
		new_reason = talloc_strdup(ctdb_db, given_reason);
		if (new_reason == NULL) {
			DEBUG(DEBUG_ALERT,(__location__ " talloc_strdup(%s) failed\n",
					  given_reason));
			return -1;
		}
	} else if (old_reason && num_healthy_nodes == 0) {
		/*
		 * If the reason indicates ok, but there where no healthy nodes
		 * available, that it means, we have not recovered valid content
		 * of the db. So if there's an old reason, prefix it with
		 * "NO-HEALTHY-NODES - "
		 */
		const char *prefix;

#define _TMP_PREFIX "NO-HEALTHY-NODES - "
		ret = strncmp(_TMP_PREFIX, old_reason, strlen(_TMP_PREFIX));
		if (ret != 0) {
			prefix = _TMP_PREFIX;
		} else {
			prefix = "";
		}
		new_reason = talloc_asprintf(ctdb_db, "%s%s",
					 prefix, old_reason);
		if (new_reason == NULL) {
			DEBUG(DEBUG_ALERT,(__location__ " talloc_asprintf(%s%s) failed\n",
					  prefix, old_reason));
			return -1;
		}
#undef _TMP_PREFIX
	}

	if (new_reason) {
		val.dptr = discard_const_p(uint8_t, new_reason);
		val.dsize = strlen(new_reason);

		ret = tdb_store(tdb, key, val, TDB_REPLACE);
		if (ret != 0) {
			tdb_transaction_cancel(tdb);
			DEBUG(DEBUG_ALERT,(__location__ " tdb_store('%s', %s, %s) failed: %d - %s\n",
					   tdb_name(tdb), ctdb_db->db_name, new_reason,
					   ret, tdb_errorstr(tdb)));
			talloc_free(new_reason);
			return -1;
		}
		DEBUG(DEBUG_ALERT,("Updated db health for db(%s) to: %s\n",
				   ctdb_db->db_name, new_reason));
	} else if (old_reason) {
		ret = tdb_delete(tdb, key);
		if (ret != 0) {
			tdb_transaction_cancel(tdb);
			DEBUG(DEBUG_ALERT,(__location__ " tdb_delete('%s', %s) failed: %d - %s\n",
					   tdb_name(tdb), ctdb_db->db_name,
					   ret, tdb_errorstr(tdb)));
			talloc_free(new_reason);
			return -1;
		}
		DEBUG(DEBUG_NOTICE,("Updated db health for db(%s): OK\n",
				   ctdb_db->db_name));
	}

	ret = tdb_transaction_commit(tdb);
	if (ret != TDB_SUCCESS) {
		DEBUG(DEBUG_ALERT,(__location__ " tdb_transaction_commit('%s') failed: %d - %s\n",
				   tdb_name(tdb), ret, tdb_errorstr(tdb)));
		talloc_free(new_reason);
		return -1;
	}

	talloc_free(old_reason);
	ctdb_db->unhealthy_reason = new_reason;

	return 0;
}

static int ctdb_backup_corrupted_tdb(struct ctdb_context *ctdb,
				     struct ctdb_db_context *ctdb_db)
{
	time_t now = time(NULL);
	char *new_path;
	char *new_reason;
	int ret;
	struct tm *tm;

	tm = gmtime(&now);

	/* formatted like: foo.tdb.0.corrupted.20091204160825.0Z */
	new_path = talloc_asprintf(ctdb_db, "%s.corrupted."
				   "%04u%02u%02u%02u%02u%02u.0Z",
				   ctdb_db->db_path,
				   tm->tm_year+1900, tm->tm_mon+1,
				   tm->tm_mday, tm->tm_hour, tm->tm_min,
				   tm->tm_sec);
	if (new_path == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " talloc_asprintf() failed\n"));
		return -1;
	}

	new_reason = talloc_asprintf(ctdb_db,
				     "ERROR - Backup of corrupted TDB in '%s'",
				     new_path);
	if (new_reason == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " talloc_asprintf() failed\n"));
		return -1;
	}
	ret = ctdb_update_persistent_health(ctdb, ctdb_db, new_reason, 0);
	talloc_free(new_reason);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,(__location__
				 ": ctdb_backup_corrupted_tdb(%s) not implemented yet\n",
				 ctdb_db->db_path));
		return -1;
	}

	ret = rename(ctdb_db->db_path, new_path);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,(__location__
				  ": ctdb_backup_corrupted_tdb(%s) rename to %s failed: %d - %s\n",
				  ctdb_db->db_path, new_path,
				  errno, strerror(errno)));
		talloc_free(new_path);
		return -1;
	}

	DEBUG(DEBUG_CRIT,(__location__
			 ": ctdb_backup_corrupted_tdb(%s) renamed to %s\n",
			 ctdb_db->db_path, new_path));
	talloc_free(new_path);
	return 0;
}

int ctdb_recheck_persistent_health(struct ctdb_context *ctdb)
{
	struct ctdb_db_context *ctdb_db;
	int ret;
	int ok = 0;
	int fail = 0;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (!ctdb_db->persistent) {
			continue;
		}

		ret = ctdb_load_persistent_health(ctdb, ctdb_db);
		if (ret != 0) {
			DEBUG(DEBUG_ALERT,(__location__
					   " load persistent health for '%s' failed\n",
					   ctdb_db->db_path));
			return -1;
		}

		if (ctdb_db->unhealthy_reason == NULL) {
			ok++;
			DEBUG(DEBUG_INFO,(__location__
				   " persistent db '%s' healthy\n",
				   ctdb_db->db_path));
			continue;
		}

		fail++;
		DEBUG(DEBUG_ALERT,(__location__
				   " persistent db '%s' unhealthy: %s\n",
				   ctdb_db->db_path,
				   ctdb_db->unhealthy_reason));
	}
	DEBUG((fail!=0)?DEBUG_ALERT:DEBUG_NOTICE,
	      ("ctdb_recheck_presistent_health: OK[%d] FAIL[%d]\n",
	       ok, fail));

	if (fail != 0) {
		return -1;
	}

	return 0;
}


/*
  mark a database - as healthy
 */
int32_t ctdb_control_db_set_healthy(struct ctdb_context *ctdb, TDB_DATA indata)
{
	uint32_t db_id = *(uint32_t *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	int ret;
	bool may_recover = false;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%x\n", db_id));
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		may_recover = true;
	}

	ret = ctdb_update_persistent_health(ctdb, ctdb_db, NULL, 1);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__
				 " ctdb_update_persistent_health(%s) failed\n",
				 ctdb_db->db_name));
		return -1;
	}

	if (may_recover && !ctdb->done_startup) {
		DEBUG(DEBUG_ERR, (__location__ " db %s become healthy  - force recovery for startup\n",
				  ctdb_db->db_name));
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	}

	return 0;
}

int32_t ctdb_control_db_get_health(struct ctdb_context *ctdb,
				   TDB_DATA indata,
				   TDB_DATA *outdata)
{
	uint32_t db_id = *(uint32_t *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	int ret;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%x\n", db_id));
		return -1;
	}

	ret = ctdb_load_persistent_health(ctdb, ctdb_db);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__
				 " ctdb_load_persistent_health(%s) failed\n",
				 ctdb_db->db_name));
		return -1;
	}

	*outdata = tdb_null;
	if (ctdb_db->unhealthy_reason) {
		outdata->dptr = (uint8_t *)ctdb_db->unhealthy_reason;
		outdata->dsize = strlen(ctdb_db->unhealthy_reason)+1;
	}

	return 0;
}

/*
  attach to a database, handling both persistent and non-persistent databases
  return 0 on success, -1 on failure
 */
static int ctdb_local_attach(struct ctdb_context *ctdb, const char *db_name,
			     bool persistent, const char *unhealthy_reason)
{
	struct ctdb_db_context *ctdb_db, *tmp_db;
	int ret;
	struct TDB_DATA key;
	unsigned tdb_flags;
	int mode = 0600;
	int remaining_tries = 0;

	ctdb_db = talloc_zero(ctdb, struct ctdb_db_context);
	CTDB_NO_MEMORY(ctdb, ctdb_db);

	ctdb_db->priority = 1;
	ctdb_db->ctdb = ctdb;
	ctdb_db->db_name = talloc_strdup(ctdb_db, db_name);
	CTDB_NO_MEMORY(ctdb, ctdb_db->db_name);

	key.dsize = strlen(db_name)+1;
	key.dptr  = discard_const(db_name);
	ctdb_db->db_id = ctdb_hash(&key);
	ctdb_db->persistent = persistent;

	/* check for hash collisions */
	for (tmp_db=ctdb->db_list;tmp_db;tmp_db=tmp_db->next) {
		if (tmp_db->db_id == ctdb_db->db_id) {
			DEBUG(DEBUG_CRIT,("db_id 0x%x hash collision. name1='%s' name2='%s'\n",
				 tmp_db->db_id, db_name, tmp_db->db_name));
			talloc_free(ctdb_db);
			return -1;
		}
	}

	if (persistent) {
		if (unhealthy_reason) {
			ret = ctdb_update_persistent_health(ctdb, ctdb_db,
							    unhealthy_reason, 0);
			if (ret != 0) {
				DEBUG(DEBUG_ALERT,(__location__ " ctdb_update_persistent_health('%s','%s') failed: %d\n",
						   ctdb_db->db_name, unhealthy_reason, ret));
				talloc_free(ctdb_db);
				return -1;
			}
		}

		if (ctdb->max_persistent_check_errors > 0) {
			remaining_tries = 1;
		}
		if (ctdb->done_startup) {
			remaining_tries = 0;
		}

		ret = ctdb_load_persistent_health(ctdb, ctdb_db);
		if (ret != 0) {
			DEBUG(DEBUG_ALERT,(__location__ " ctdb_load_persistent_health('%s') failed: %d\n",
				   ctdb_db->db_name, ret));
			talloc_free(ctdb_db);
			return -1;
		}
	}

	if (ctdb_db->unhealthy_reason && remaining_tries == 0) {
		DEBUG(DEBUG_ALERT,(__location__ "ERROR: tdb %s is marked as unhealthy: %s\n",
				   ctdb_db->db_name, ctdb_db->unhealthy_reason));
		talloc_free(ctdb_db);
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		/* this is just a warning, but we want that in the log file! */
		DEBUG(DEBUG_ALERT,(__location__ "Warning: tdb %s is marked as unhealthy: %s\n",
				   ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	/* open the database */
	ctdb_db->db_path = talloc_asprintf(ctdb_db, "%s/%s.%u", 
					   persistent?ctdb->db_directory_persistent:ctdb->db_directory, 
					   db_name, ctdb->pnn);

	tdb_flags = persistent? TDB_DEFAULT : TDB_CLEAR_IF_FIRST | TDB_NOSYNC;
	if (!ctdb->do_setsched) {
		tdb_flags |= TDB_NOMMAP;
	}
	tdb_flags |= TDB_DISALLOW_NESTING;

again:
	ctdb_db->ltdb = tdb_wrap_open(ctdb, ctdb_db->db_path, 
				      ctdb->tunable.database_hash_size, 
				      tdb_flags, 
				      O_CREAT|O_RDWR, mode);
	if (ctdb_db->ltdb == NULL) {
		struct stat st;
		int saved_errno = errno;

		if (!persistent) {
			DEBUG(DEBUG_CRIT,("Failed to open tdb '%s': %d - %s\n",
					  ctdb_db->db_path,
					  saved_errno,
					  strerror(saved_errno)));
			talloc_free(ctdb_db);
			return -1;
		}

		if (remaining_tries == 0) {
			DEBUG(DEBUG_CRIT,(__location__
					  "Failed to open persistent tdb '%s': %d - %s\n",
					  ctdb_db->db_path,
					  saved_errno,
					  strerror(saved_errno)));
			talloc_free(ctdb_db);
			return -1;
		}

		ret = stat(ctdb_db->db_path, &st);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT,(__location__
					  "Failed to open persistent tdb '%s': %d - %s\n",
					  ctdb_db->db_path,
					  saved_errno,
					  strerror(saved_errno)));
			talloc_free(ctdb_db);
			return -1;
		}

		ret = ctdb_backup_corrupted_tdb(ctdb, ctdb_db);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT,(__location__
					  "Failed to open persistent tdb '%s': %d - %s\n",
					  ctdb_db->db_path,
					  saved_errno,
					  strerror(saved_errno)));
			talloc_free(ctdb_db);
			return -1;
		}

		remaining_tries--;
		mode = st.st_mode;
		goto again;
	}

	if (!persistent) {
		ctdb_check_db_empty(ctdb_db);
	} else {
		ret = tdb_check(ctdb_db->ltdb->tdb, NULL, NULL);
		if (ret != 0) {
			int fd;
			struct stat st;

			DEBUG(DEBUG_CRIT,("tdb_check(%s) failed: %d - %s\n",
					  ctdb_db->db_path, ret,
					  tdb_errorstr(ctdb_db->ltdb->tdb)));
			if (remaining_tries == 0) {
				talloc_free(ctdb_db);
				return -1;
			}

			fd = tdb_fd(ctdb_db->ltdb->tdb);
			ret = fstat(fd, &st);
			if (ret != 0) {
				DEBUG(DEBUG_CRIT,(__location__
						  "Failed to fstat() persistent tdb '%s': %d - %s\n",
						  ctdb_db->db_path,
						  errno,
						  strerror(errno)));
				talloc_free(ctdb_db);
				return -1;
			}

			/* close the TDB */
			talloc_free(ctdb_db->ltdb);
			ctdb_db->ltdb = NULL;

			ret = ctdb_backup_corrupted_tdb(ctdb, ctdb_db);
			if (ret != 0) {
				DEBUG(DEBUG_CRIT,("Failed to backup corrupted tdb '%s'\n",
						  ctdb_db->db_path));
				talloc_free(ctdb_db);
				return -1;
			}

			remaining_tries--;
			mode = st.st_mode;
			goto again;
		}
	}

	DLIST_ADD(ctdb->db_list, ctdb_db);

	/* setting this can help some high churn databases */
	tdb_set_max_dead(ctdb_db->ltdb->tdb, ctdb->tunable.database_max_dead);

	/* 
	   all databases support the "null" function. we need this in
	   order to do forced migration of records
	*/
	ret = ctdb_daemon_set_call(ctdb, ctdb_db->db_id, ctdb_null_func, CTDB_NULL_FUNC);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,("Failed to setup null function for '%s'\n", ctdb_db->db_name));
		talloc_free(ctdb_db);
		return -1;
	}

	/* 
	   all databases support the "fetch" function. we need this
	   for efficient Samba3 ctdb fetch
	*/
	ret = ctdb_daemon_set_call(ctdb, ctdb_db->db_id, ctdb_fetch_func, CTDB_FETCH_FUNC);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,("Failed to setup fetch function for '%s'\n", ctdb_db->db_name));
		talloc_free(ctdb_db);
		return -1;
	}

	ret = ctdb_vacuum_init(ctdb_db);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,("Failed to setup vacuuming for "
				  "database '%s'\n", ctdb_db->db_name));
		talloc_free(ctdb_db);
		return -1;
	}


	DEBUG(DEBUG_INFO,("Attached to database '%s'\n", ctdb_db->db_path));
	
	/* success */
	return 0;
}


/*
  a client has asked to attach a new database
 */
int32_t ctdb_control_db_attach(struct ctdb_context *ctdb, TDB_DATA indata,
			       TDB_DATA *outdata, uint64_t tdb_flags, 
			       bool persistent)
{
	const char *db_name = (const char *)indata.dptr;
	struct ctdb_db_context *db;
	struct ctdb_node *node = ctdb->nodes[ctdb->pnn];

	/* the client can optionally pass additional tdb flags, but we
	   only allow a subset of those on the database in ctdb. Note
	   that tdb_flags is passed in via the (otherwise unused)
	   srvid to the attach control */
	tdb_flags &= TDB_NOSYNC;

	/* If the node is inactive it is not part of the cluster
	   and we should not allow clients to attach to any
	   databases
	*/
	if (node->flags & NODE_FLAGS_INACTIVE) {
		DEBUG(DEBUG_ERR,("DB Attach to database %s refused since node is inactive (disconnected or banned)\n", db_name));
		return -1;
	}


	/* see if we already have this name */
	db = ctdb_db_handle(ctdb, db_name);
	if (db) {
		outdata->dptr  = (uint8_t *)&db->db_id;
		outdata->dsize = sizeof(db->db_id);
		tdb_add_flags(db->ltdb->tdb, tdb_flags);
		return 0;
	}

	if (ctdb_local_attach(ctdb, db_name, persistent, NULL) != 0) {
		return -1;
	}

	db = ctdb_db_handle(ctdb, db_name);
	if (!db) {
		DEBUG(DEBUG_ERR,("Failed to find db handle for name '%s'\n", db_name));
		return -1;
	}

	/* remember the flags the client has specified */
	tdb_add_flags(db->ltdb->tdb, tdb_flags);

	outdata->dptr  = (uint8_t *)&db->db_id;
	outdata->dsize = sizeof(db->db_id);

	/* tell all the other nodes about this database */
	ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL, 0,
				 persistent?CTDB_CONTROL_DB_ATTACH_PERSISTENT:
						CTDB_CONTROL_DB_ATTACH,
				 0, CTDB_CTRL_FLAG_NOREPLY,
				 indata, NULL, NULL);

	/* success */
	return 0;
}


/*
  attach to all existing persistent databases
 */
static int ctdb_attach_persistent(struct ctdb_context *ctdb,
				  const char *unhealthy_reason)
{
	DIR *d;
	struct dirent *de;

	/* open the persistent db directory and scan it for files */
	d = opendir(ctdb->db_directory_persistent);
	if (d == NULL) {
		return 0;
	}

	while ((de=readdir(d))) {
		char *p, *s, *q;
		size_t len = strlen(de->d_name);
		uint32_t node;
		int invalid_name = 0;
		
		s = talloc_strdup(ctdb, de->d_name);
		CTDB_NO_MEMORY(ctdb, s);

		/* only accept names ending in .tdb */
		p = strstr(s, ".tdb.");
		if (len < 7 || p == NULL) {
			talloc_free(s);
			continue;
		}

		/* only accept names ending with .tdb. and any number of digits */
		q = p+5;
		while (*q != 0 && invalid_name == 0) {
			if (!isdigit(*q++)) {
				invalid_name = 1;
			}
		}
		if (invalid_name == 1 || sscanf(p+5, "%u", &node) != 1 || node != ctdb->pnn) {
			DEBUG(DEBUG_ERR,("Ignoring persistent database '%s'\n", de->d_name));
			talloc_free(s);
			continue;
		}
		p[4] = 0;

		if (ctdb_local_attach(ctdb, s, true, unhealthy_reason) != 0) {
			DEBUG(DEBUG_ERR,("Failed to attach to persistent database '%s'\n", de->d_name));
			closedir(d);
			talloc_free(s);
			return -1;
		}

		DEBUG(DEBUG_INFO,("Attached to persistent database %s\n", s));

		talloc_free(s);
	}
	closedir(d);
	return 0;
}

int ctdb_attach_databases(struct ctdb_context *ctdb)
{
	int ret;
	char *persistent_health_path = NULL;
	char *unhealthy_reason = NULL;
	bool first_try = true;

	if (ctdb->db_directory == NULL) {
		ctdb->db_directory = VARDIR "/ctdb";
	}
	if (ctdb->db_directory_persistent == NULL) {
		ctdb->db_directory_persistent = VARDIR "/ctdb/persistent";
	}
	if (ctdb->db_directory_state == NULL) {
		ctdb->db_directory_state = VARDIR "/ctdb/state";
	}

	/* make sure the db directory exists */
	ret = mkdir(ctdb->db_directory, 0700);
	if (ret == -1 && errno != EEXIST) {
		DEBUG(DEBUG_CRIT,(__location__ " Unable to create ctdb directory '%s'\n",
			 ctdb->db_directory));
		return -1;
	}

	/* make sure the persistent db directory exists */
	ret = mkdir(ctdb->db_directory_persistent, 0700);
	if (ret == -1 && errno != EEXIST) {
		DEBUG(DEBUG_CRIT,(__location__ " Unable to create ctdb persistent directory '%s'\n",
			 ctdb->db_directory_persistent));
		return -1;
	}

	/* make sure the internal state db directory exists */
	ret = mkdir(ctdb->db_directory_state, 0700);
	if (ret == -1 && errno != EEXIST) {
		DEBUG(DEBUG_CRIT,(__location__ " Unable to create ctdb state directory '%s'\n",
			 ctdb->db_directory_state));
		return -1;
	}

	persistent_health_path = talloc_asprintf(ctdb, "%s/%s.%u",
						 ctdb->db_directory_state,
						 PERSISTENT_HEALTH_TDB,
						 ctdb->pnn);
	if (persistent_health_path == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " talloc_asprintf() failed\n"));
		return -1;
	}

again:

	ctdb->db_persistent_health = tdb_wrap_open(ctdb, persistent_health_path,
						   0, TDB_DISALLOW_NESTING,
						   O_CREAT | O_RDWR, 0600);
	if (ctdb->db_persistent_health == NULL) {
		struct tdb_wrap *tdb;

		if (!first_try) {
			DEBUG(DEBUG_CRIT,("Failed to open tdb '%s': %d - %s\n",
					  persistent_health_path,
					  errno,
					  strerror(errno)));
			talloc_free(persistent_health_path);
			talloc_free(unhealthy_reason);
			return -1;
		}
		first_try = false;

		unhealthy_reason = talloc_asprintf(ctdb, "WARNING - '%s' %s - %s",
						   persistent_health_path,
						   "was cleared after a failure",
						   "manual verification needed");
		if (unhealthy_reason == NULL) {
			DEBUG(DEBUG_CRIT,(__location__ " talloc_asprintf() failed\n"));
			talloc_free(persistent_health_path);
			return -1;
		}

		DEBUG(DEBUG_CRIT,("Failed to open tdb '%s' - retrying after CLEAR_IF_FIRST\n",
				  persistent_health_path));
		tdb = tdb_wrap_open(ctdb, persistent_health_path,
				    0, TDB_CLEAR_IF_FIRST | TDB_DISALLOW_NESTING,
				    O_CREAT | O_RDWR, 0600);
		if (tdb) {
			DEBUG(DEBUG_CRIT,("Failed to open tdb '%s' - with CLEAR_IF_FIRST: %d - %s\n",
					  persistent_health_path,
					  errno,
					  strerror(errno)));
			talloc_free(persistent_health_path);
			talloc_free(unhealthy_reason);
			return -1;
		}

		talloc_free(tdb);
		goto again;
	}
	ret = tdb_check(ctdb->db_persistent_health->tdb, NULL, NULL);
	if (ret != 0) {
		struct tdb_wrap *tdb;

		talloc_free(ctdb->db_persistent_health);
		ctdb->db_persistent_health = NULL;

		if (!first_try) {
			DEBUG(DEBUG_CRIT,("tdb_check('%s') failed\n",
					  persistent_health_path));
			talloc_free(persistent_health_path);
			talloc_free(unhealthy_reason);
			return -1;
		}
		first_try = false;

		unhealthy_reason = talloc_asprintf(ctdb, "WARNING - '%s' %s - %s",
						   persistent_health_path,
						   "was cleared after a failure",
						   "manual verification needed");
		if (unhealthy_reason == NULL) {
			DEBUG(DEBUG_CRIT,(__location__ " talloc_asprintf() failed\n"));
			talloc_free(persistent_health_path);
			return -1;
		}

		DEBUG(DEBUG_CRIT,("tdb_check('%s') failed - retrying after CLEAR_IF_FIRST\n",
				  persistent_health_path));
		tdb = tdb_wrap_open(ctdb, persistent_health_path,
				    0, TDB_CLEAR_IF_FIRST | TDB_DISALLOW_NESTING,
				    O_CREAT | O_RDWR, 0600);
		if (tdb) {
			DEBUG(DEBUG_CRIT,("Failed to open tdb '%s' - with CLEAR_IF_FIRST: %d - %s\n",
					  persistent_health_path,
					  errno,
					  strerror(errno)));
			talloc_free(persistent_health_path);
			talloc_free(unhealthy_reason);
			return -1;
		}

		talloc_free(tdb);
		goto again;
	}
	talloc_free(persistent_health_path);

	ret = ctdb_attach_persistent(ctdb, unhealthy_reason);
	talloc_free(unhealthy_reason);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

/*
  called when a broadcast seqnum update comes in
 */
int32_t ctdb_ltdb_update_seqnum(struct ctdb_context *ctdb, uint32_t db_id, uint32_t srcnode)
{
	struct ctdb_db_context *ctdb_db;
	if (srcnode == ctdb->pnn) {
		/* don't update ourselves! */
		return 0;
	}

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,("Unknown db_id 0x%x in ctdb_ltdb_update_seqnum\n", db_id));
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		DEBUG(DEBUG_ERR,("db(%s) unhealty in ctdb_ltdb_update_seqnum: %s\n",
				 ctdb_db->db_name, ctdb_db->unhealthy_reason));
		return -1;
	}

	tdb_increment_seqnum_nonblock(ctdb_db->ltdb->tdb);
	ctdb_db->seqnum = tdb_get_seqnum(ctdb_db->ltdb->tdb);
	return 0;
}

/*
  timer to check for seqnum changes in a ltdb and propogate them
 */
static void ctdb_ltdb_seqnum_check(struct event_context *ev, struct timed_event *te, 
				   struct timeval t, void *p)
{
	struct ctdb_db_context *ctdb_db = talloc_get_type(p, struct ctdb_db_context);
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	uint32_t new_seqnum = tdb_get_seqnum(ctdb_db->ltdb->tdb);
	if (new_seqnum != ctdb_db->seqnum) {
		/* something has changed - propogate it */
		TDB_DATA data;
		data.dptr = (uint8_t *)&ctdb_db->db_id;
		data.dsize = sizeof(uint32_t);
		ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_VNNMAP, 0,
					 CTDB_CONTROL_UPDATE_SEQNUM, 0, CTDB_CTRL_FLAG_NOREPLY,
					 data, NULL, NULL);		
	}
	ctdb_db->seqnum = new_seqnum;

	/* setup a new timer */
	ctdb_db->seqnum_update =
		event_add_timed(ctdb->ev, ctdb_db, 
				timeval_current_ofs(ctdb->tunable.seqnum_interval/1000, (ctdb->tunable.seqnum_interval%1000)*1000),
				ctdb_ltdb_seqnum_check, ctdb_db);
}

/*
  enable seqnum handling on this db
 */
int32_t ctdb_ltdb_enable_seqnum(struct ctdb_context *ctdb, uint32_t db_id)
{
	struct ctdb_db_context *ctdb_db;
	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,("Unknown db_id 0x%x in ctdb_ltdb_enable_seqnum\n", db_id));
		return -1;
	}

	if (ctdb_db->seqnum_update == NULL) {
		ctdb_db->seqnum_update =
			event_add_timed(ctdb->ev, ctdb_db, 
					timeval_current_ofs(ctdb->tunable.seqnum_interval/1000, (ctdb->tunable.seqnum_interval%1000)*1000),
					ctdb_ltdb_seqnum_check, ctdb_db);
	}

	tdb_enable_seqnum(ctdb_db->ltdb->tdb);
	ctdb_db->seqnum = tdb_get_seqnum(ctdb_db->ltdb->tdb);
	return 0;
}

int32_t ctdb_control_set_db_priority(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_db_priority *db_prio = (struct ctdb_db_priority *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, db_prio->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,("Unknown db_id 0x%x in ctdb_set_db_priority\n", db_prio->db_id));
		return -1;
	}

	if ((db_prio->priority<1) || (db_prio->priority>NUM_DB_PRIORITIES)) {
		DEBUG(DEBUG_ERR,("Trying to set invalid priority : %u\n", db_prio->priority));
		return -1;
	}

	ctdb_db->priority = db_prio->priority;
	DEBUG(DEBUG_INFO,("Setting DB priority to %u for db 0x%08x\n", db_prio->priority, db_prio->db_id));

	return 0;
}


