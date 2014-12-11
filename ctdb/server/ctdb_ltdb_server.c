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
#include "tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "system/time.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include <ctype.h>

#define PERSISTENT_HEALTH_TDB "persistent_health.tdb"

/**
 * write a record to a normal database
 *
 * This is the server-variant of the ctdb_ltdb_store function.
 * It contains logic to determine whether a record should be
 * stored or deleted. It also sends SCHEDULE_FOR_DELETION
 * controls to the local ctdb daemon if apporpriate.
 */
static int ctdb_ltdb_store_server(struct ctdb_db_context *ctdb_db,
				  TDB_DATA key,
				  struct ctdb_ltdb_header *header,
				  TDB_DATA data)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	TDB_DATA rec;
	int ret;
	bool seqnum_suppressed = false;
	bool keep = false;
	bool schedule_for_deletion = false;
	bool remove_from_delete_queue = false;
	uint32_t lmaster;

	if (ctdb->flags & CTDB_FLAG_TORTURE) {
		struct ctdb_ltdb_header *h2;
		rec = tdb_fetch(ctdb_db->ltdb->tdb, key);
		h2 = (struct ctdb_ltdb_header *)rec.dptr;
		if (rec.dptr && rec.dsize >= sizeof(h2) && h2->rsn > header->rsn) {
			DEBUG(DEBUG_CRIT,("RSN regression! %llu %llu\n",
				 (unsigned long long)h2->rsn, (unsigned long long)header->rsn));
		}
		if (rec.dptr) free(rec.dptr);
	}

	if (ctdb->vnn_map == NULL) {
		/*
		 * Called from a client: always store the record
		 * Also don't call ctdb_lmaster since it uses the vnn_map!
		 */
		keep = true;
		goto store;
	}

	lmaster = ctdb_lmaster(ctdb_db->ctdb, &key);

	/*
	 * If we migrate an empty record off to another node
	 * and the record has not been migrated with data,
	 * delete the record instead of storing the empty record.
	 */
	if (data.dsize != 0) {
		keep = true;
	} else if (header->flags & CTDB_REC_RO_FLAGS) {
		keep = true;
	} else if (ctdb_db->persistent) {
		keep = true;
	} else if (header->flags & CTDB_REC_FLAG_AUTOMATIC) {
		/*
		 * The record is not created by the client but
		 * automatically by the ctdb_ltdb_fetch logic that
		 * creates a record with an initial header in the
		 * ltdb before trying to migrate the record from
		 * the current lmaster. Keep it instead of trying
		 * to delete the non-existing record...
		 */
		keep = true;
		schedule_for_deletion = true;
	} else if (header->flags & CTDB_REC_FLAG_MIGRATED_WITH_DATA) {
		keep = true;
	} else if (ctdb_db->ctdb->pnn == lmaster) {
		/*
		 * If we are lmaster, then we usually keep the record.
		 * But if we retrieve the dmaster role by a VACUUM_MIGRATE
		 * and the record is empty and has never been migrated
		 * with data, then we should delete it instead of storing it.
		 * This is part of the vacuuming process.
		 *
		 * The reason that we usually need to store even empty records
		 * on the lmaster is that a client operating directly on the
		 * lmaster (== dmaster) expects the local copy of the record to
		 * exist after successful ctdb migrate call. If the record does
		 * not exist, the client goes into a migrate loop and eventually
		 * fails. So storing the empty record makes sure that we do not
		 * need to change the client code.
		 */
		if ((header->flags & CTDB_REC_FLAG_VACUUM_MIGRATED) &&
		    (ctdb_db->ctdb->pnn == header->dmaster)) {
			keep = true;
			schedule_for_deletion = true;
		}
		if (!(header->flags & CTDB_REC_FLAG_VACUUM_MIGRATED)) {
			keep = true;
		} else if (ctdb_db->ctdb->pnn != header->dmaster) {
			keep = true;
		}
	} else if (ctdb_db->ctdb->pnn == header->dmaster) {
		keep = true;
	}

	if (keep) {
		if (!ctdb_db->persistent &&
		    (ctdb_db->ctdb->pnn == header->dmaster) &&
		    !(header->flags & CTDB_REC_RO_FLAGS))
		{
			header->rsn++;

			if (data.dsize == 0) {
				schedule_for_deletion = true;
			}
		}
		remove_from_delete_queue = !schedule_for_deletion;
	}

store:
	/*
	 * The VACUUM_MIGRATED flag is only set temporarily for
	 * the above logic when the record was retrieved by a
	 * VACUUM_MIGRATE call and should not be stored in the
	 * database.
	 *
	 * The VACUUM_MIGRATE call is triggered by a vacuum fetch,
	 * and there are two cases in which the corresponding record
	 * is stored in the local database:
	 * 1. The record has been migrated with data in the past
	 *    (the MIGRATED_WITH_DATA record flag is set).
	 * 2. The record has been filled with data again since it
	 *    had been submitted in the VACUUM_FETCH message to the
	 *    lmaster.
	 * For such records it is important to not store the
	 * VACUUM_MIGRATED flag in the database.
	 */
	header->flags &= ~CTDB_REC_FLAG_VACUUM_MIGRATED;

	/*
	 * Similarly, clear the AUTOMATIC flag which should not enter
	 * the local database copy since this would require client
	 * modifications to clear the flag when the client stores
	 * the record.
	 */
	header->flags &= ~CTDB_REC_FLAG_AUTOMATIC;

	rec.dsize = sizeof(*header) + data.dsize;
	rec.dptr = talloc_size(ctdb, rec.dsize);
	CTDB_NO_MEMORY(ctdb, rec.dptr);

	memcpy(rec.dptr, header, sizeof(*header));
	memcpy(rec.dptr + sizeof(*header), data.dptr, data.dsize);

	/* Databases with seqnum updates enabled only get their seqnum
	   changes when/if we modify the data */
	if (ctdb_db->seqnum_update != NULL) {
		TDB_DATA old;
		old = tdb_fetch(ctdb_db->ltdb->tdb, key);

		if ( (old.dsize == rec.dsize)
		&& !memcmp(old.dptr+sizeof(struct ctdb_ltdb_header),
			  rec.dptr+sizeof(struct ctdb_ltdb_header),
			  rec.dsize-sizeof(struct ctdb_ltdb_header)) ) {
			tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_SEQNUM);
			seqnum_suppressed = true;
		}
		if (old.dptr) free(old.dptr);
	}

	DEBUG(DEBUG_DEBUG, (__location__ " db[%s]: %s record: hash[0x%08x]\n",
			    ctdb_db->db_name,
			    keep?"storing":"deleting",
			    ctdb_hash(&key)));

	if (keep) {
		ret = tdb_store(ctdb_db->ltdb->tdb, key, rec, TDB_REPLACE);
	} else {
		ret = tdb_delete(ctdb_db->ltdb->tdb, key);
	}

	if (ret != 0) {
		int lvl = DEBUG_ERR;

		if (keep == false &&
		    tdb_error(ctdb_db->ltdb->tdb) == TDB_ERR_NOEXIST)
		{
			lvl = DEBUG_DEBUG;
		}

		DEBUG(lvl, (__location__ " db[%s]: Failed to %s record: "
			    "%d - %s\n",
			    ctdb_db->db_name,
			    keep?"store":"delete", ret,
			    tdb_errorstr(ctdb_db->ltdb->tdb)));

		schedule_for_deletion = false;
		remove_from_delete_queue = false;
	}
	if (seqnum_suppressed) {
		tdb_add_flags(ctdb_db->ltdb->tdb, TDB_SEQNUM);
	}

	talloc_free(rec.dptr);

	if (schedule_for_deletion) {
		int ret2;
		ret2 = ctdb_local_schedule_for_deletion(ctdb_db, header, key);
		if (ret2 != 0) {
			DEBUG(DEBUG_ERR, (__location__ " ctdb_local_schedule_for_deletion failed.\n"));
		}
	}

	if (remove_from_delete_queue) {
		ctdb_local_remove_from_delete_queue(ctdb_db, header, key);
	}

	return ret;
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
static void lock_fetch_callback(void *p, bool locked)
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
   non-blocking chainlock via ctdb_lock_record, and when it gets the
   chainlock it re-submits this ctdb request to the main packet
   receive function.

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
	struct lock_request *lreq;
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
	lreq = ctdb_lock_record(state, ctdb_db, key, true, lock_fetch_callback, state);
	if (lreq == NULL) {
		return -1;
	}

	/* we need to move the packet off the temporary context in ctdb_input_pkt(),
	   so it won't be freed yet */
	talloc_steal(state, hdr);

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
			int uret;
			uret = ctdb_ltdb_unlock(ctdb_db, key);
			if (uret != 0) {
				DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", uret));
			}
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

	if (may_recover && ctdb->runstate == CTDB_RUNSTATE_STARTUP) {
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


int ctdb_set_db_readonly(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db)
{
	char *ropath;

	if (ctdb_db->readonly) {
		return 0;
	}

	if (ctdb_db->persistent) {
		DEBUG(DEBUG_ERR,("Persistent databases do not support readonly property\n"));
		return -1;
	}

	ropath = talloc_asprintf(ctdb_db, "%s.RO", ctdb_db->db_path);
	if (ropath == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to asprintf the tracking database\n"));
		return -1;
	}
	ctdb_db->rottdb = tdb_open(ropath, 
			      ctdb->tunable.database_hash_size, 
			      TDB_NOLOCK|TDB_CLEAR_IF_FIRST|TDB_NOSYNC,
			      O_CREAT|O_RDWR, 0);
	if (ctdb_db->rottdb == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to open/create the tracking database '%s'\n", ropath));
		talloc_free(ropath);
		return -1;
	}

	DEBUG(DEBUG_NOTICE,("OPENED tracking database : '%s'\n", ropath));

	ctdb_db->readonly = true;

	DEBUG(DEBUG_NOTICE, ("Readonly property set on DB %s\n", ctdb_db->db_name));

	talloc_free(ropath);
	return 0;
}

/*
  attach to a database, handling both persistent and non-persistent databases
  return 0 on success, -1 on failure
 */
static int ctdb_local_attach(struct ctdb_context *ctdb, const char *db_name,
			     bool persistent, const char *unhealthy_reason,
			     bool jenkinshash, bool mutexes)
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

	if (!ctdb_db->persistent) {
		ctdb_db->delete_queue = trbt_create(ctdb_db, 0);
		if (ctdb_db->delete_queue == NULL) {
			CTDB_NO_MEMORY(ctdb, ctdb_db->delete_queue);
		}

		ctdb_db->ctdb_ltdb_store_fn = ctdb_ltdb_store_server;
	}

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
		if (ctdb->runstate == CTDB_RUNSTATE_RUNNING) {
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
	if (ctdb->valgrinding) {
		tdb_flags |= TDB_NOMMAP;
	}
	tdb_flags |= TDB_DISALLOW_NESTING;
	if (jenkinshash) {
		tdb_flags |= TDB_INCOMPATIBLE_HASH;
	}
#ifdef TDB_MUTEX_LOCKING
	if (ctdb->tunable.mutex_enabled && mutexes &&
	    tdb_runtime_check_for_robust_mutexes()) {
		tdb_flags |= (TDB_MUTEX_LOCKING | TDB_CLEAR_IF_FIRST);
	}
#endif

again:
	ctdb_db->ltdb = tdb_wrap_open(ctdb_db, ctdb_db->db_path,
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

	/* set up a rb tree we can use to track which records we have a 
	   fetch-lock in-flight for so we can defer any additional calls
	   for the same record.
	 */
	ctdb_db->deferred_fetch = trbt_create(ctdb_db, 0);
	if (ctdb_db->deferred_fetch == NULL) {
		DEBUG(DEBUG_ERR,("Failed to create deferred fetch rb tree for ctdb database\n"));
		talloc_free(ctdb_db);
		return -1;
	}

	ctdb_db->defer_dmaster = trbt_create(ctdb_db, 0);
	if (ctdb_db->defer_dmaster == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to create defer dmaster rb tree for %s\n",
				  ctdb_db->db_name));
		talloc_free(ctdb_db);
		return -1;
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

	/* 
	   all databases support the "fetch_with_header" function. we need this
	   for efficient readonly record fetches
	*/
	ret = ctdb_daemon_set_call(ctdb, ctdb_db->db_id, ctdb_fetch_with_header_func, CTDB_FETCH_WITH_HEADER_FUNC);
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


	DEBUG(DEBUG_NOTICE,("Attached to database '%s' with flags 0x%x\n",
			    ctdb_db->db_path, tdb_flags));

	/* success */
	return 0;
}


struct ctdb_deferred_attach_context {
	struct ctdb_deferred_attach_context *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_req_control *c;
};


static int ctdb_deferred_attach_destructor(struct ctdb_deferred_attach_context *da_ctx)
{
	DLIST_REMOVE(da_ctx->ctdb->deferred_attach, da_ctx);

	return 0;
}

static void ctdb_deferred_attach_timeout(struct event_context *ev, struct timed_event *te, struct timeval t, void *private_data)
{
	struct ctdb_deferred_attach_context *da_ctx = talloc_get_type(private_data, struct ctdb_deferred_attach_context);
	struct ctdb_context *ctdb = da_ctx->ctdb;

	ctdb_request_control_reply(ctdb, da_ctx->c, NULL, -1, NULL);
	talloc_free(da_ctx);
}

static void ctdb_deferred_attach_callback(struct event_context *ev, struct timed_event *te, struct timeval t, void *private_data)
{
	struct ctdb_deferred_attach_context *da_ctx = talloc_get_type(private_data, struct ctdb_deferred_attach_context);
	struct ctdb_context *ctdb = da_ctx->ctdb;

	/* This talloc-steals the packet ->c */
	ctdb_input_pkt(ctdb, (struct ctdb_req_header *)da_ctx->c);
	talloc_free(da_ctx);
}

int ctdb_process_deferred_attach(struct ctdb_context *ctdb)
{
	struct ctdb_deferred_attach_context *da_ctx;

	/* call it from the main event loop as soon as the current event 
	   finishes.
	 */
	while ((da_ctx = ctdb->deferred_attach) != NULL) {
		DLIST_REMOVE(ctdb->deferred_attach, da_ctx);
		event_add_timed(ctdb->ev, da_ctx, timeval_current_ofs(1,0), ctdb_deferred_attach_callback, da_ctx);
	}

	return 0;
}

/*
  a client has asked to attach a new database
 */
int32_t ctdb_control_db_attach(struct ctdb_context *ctdb, TDB_DATA indata,
			       TDB_DATA *outdata, uint64_t tdb_flags, 
			       bool persistent, uint32_t client_id,
			       struct ctdb_req_control *c,
			       bool *async_reply)
{
	const char *db_name = (const char *)indata.dptr;
	struct ctdb_db_context *db;
	struct ctdb_node *node = ctdb->nodes[ctdb->pnn];
	struct ctdb_client *client = NULL;
	bool with_jenkinshash, with_mutexes;

	if (ctdb->tunable.allow_client_db_attach == 0) {
		DEBUG(DEBUG_ERR, ("DB Attach to database %s denied by tunable "
				  "AllowClientDBAccess == 0\n", db_name));
		return -1;
	}

	/* dont allow any local clients to attach while we are in recovery mode
	 * except for the recovery daemon.
	 * allow all attach from the network since these are always from remote
	 * recovery daemons.
	 */
	if (client_id != 0) {
		client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	}
	if (client != NULL) {
		/* If the node is inactive it is not part of the cluster
		   and we should not allow clients to attach to any
		   databases
		*/
		if (node->flags & NODE_FLAGS_INACTIVE) {
			DEBUG(DEBUG_ERR,("DB Attach to database %s refused since node is inactive (flags=0x%x)\n", db_name, node->flags));
			return -1;
		}

		if (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE &&
		    client->pid != ctdb->recoverd_pid &&
		    ctdb->runstate < CTDB_RUNSTATE_RUNNING) {
			struct ctdb_deferred_attach_context *da_ctx = talloc(client, struct ctdb_deferred_attach_context);

			if (da_ctx == NULL) {
				DEBUG(DEBUG_ERR,("DB Attach to database %s deferral for client with pid:%d failed due to OOM.\n", db_name, client->pid));
				return -1;
			}

			da_ctx->ctdb = ctdb;
			da_ctx->c = talloc_steal(da_ctx, c);
			talloc_set_destructor(da_ctx, ctdb_deferred_attach_destructor);
			DLIST_ADD(ctdb->deferred_attach, da_ctx);

			event_add_timed(ctdb->ev, da_ctx, timeval_current_ofs(ctdb->tunable.deferred_attach_timeout, 0), ctdb_deferred_attach_timeout, da_ctx);

			DEBUG(DEBUG_ERR,("DB Attach to database %s deferred for client with pid:%d since node is in recovery mode.\n", db_name, client->pid));
			*async_reply = true;
			return 0;
		}
	}

	/* the client can optionally pass additional tdb flags, but we
	   only allow a subset of those on the database in ctdb. Note
	   that tdb_flags is passed in via the (otherwise unused)
	   srvid to the attach control */
#ifdef TDB_MUTEX_LOCKING
	tdb_flags &= (TDB_NOSYNC|TDB_INCOMPATIBLE_HASH|TDB_MUTEX_LOCKING|TDB_CLEAR_IF_FIRST);
#else
	tdb_flags &= (TDB_NOSYNC|TDB_INCOMPATIBLE_HASH);
#endif

	/* see if we already have this name */
	db = ctdb_db_handle(ctdb, db_name);
	if (db) {
		if (db->persistent != persistent) {
			DEBUG(DEBUG_ERR, ("ERROR: DB Attach %spersistent to %spersistent "
					  "database %s\n", persistent ? "" : "non-",
					  db-> persistent ? "" : "non-", db_name));
			return -1;
		}
		outdata->dptr  = (uint8_t *)&db->db_id;
		outdata->dsize = sizeof(db->db_id);
		tdb_add_flags(db->ltdb->tdb, tdb_flags);
		return 0;
	}

	with_jenkinshash = (tdb_flags & TDB_INCOMPATIBLE_HASH) ? true : false;
#ifdef TDB_MUTEX_LOCKING
	with_mutexes = (tdb_flags & TDB_MUTEX_LOCKING) ? true : false;
#else
	with_mutexes = false;
#endif

	if (ctdb_local_attach(ctdb, db_name, persistent, NULL,
			      with_jenkinshash, with_mutexes) != 0) {
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

	/* Try to ensure it's locked in mem */
	lockdown_memory(ctdb->valgrinding);

	/* tell all the other nodes about this database */
	ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL, tdb_flags,
				 persistent?CTDB_CONTROL_DB_ATTACH_PERSISTENT:
						CTDB_CONTROL_DB_ATTACH,
				 0, CTDB_CTRL_FLAG_NOREPLY,
				 indata, NULL, NULL);

	/* success */
	return 0;
}

/*
 * a client has asked to detach from a database
 */
int32_t ctdb_control_db_detach(struct ctdb_context *ctdb, TDB_DATA indata,
			       uint32_t client_id)
{
	uint32_t db_id;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_client *client = NULL;

	db_id = *(uint32_t *)indata.dptr;
	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR, ("Invalid dbid 0x%08x in DB detach\n",
				  db_id));
		return -1;
	}

	if (ctdb->tunable.allow_client_db_attach == 1) {
		DEBUG(DEBUG_ERR, ("DB detach from database %s denied. "
				  "Clients are allowed access to databases "
				  "(AllowClientDBAccess == 1)\n",
				  ctdb_db->db_name));
		return -1;
	}

	if (ctdb_db->persistent) {
		DEBUG(DEBUG_ERR, ("DB detach from persistent database %s "
				  "denied\n", ctdb_db->db_name));
		return -1;
	}

	/* Cannot detach from database when in recovery */
	if (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE) {
		DEBUG(DEBUG_ERR, ("DB detach denied while in recovery\n"));
		return -1;
	}

	/* If a control comes from a client, then broadcast it to all nodes.
	 * Do the actual detach only if the control comes from other daemons.
	 */
	if (client_id != 0) {
		client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
		if (client != NULL) {
			/* forward the control to all the nodes */
			ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL, 0,
						 CTDB_CONTROL_DB_DETACH, 0,
						 CTDB_CTRL_FLAG_NOREPLY,
						 indata, NULL, NULL);
			return 0;
		}
		DEBUG(DEBUG_ERR, ("Client has gone away. Failing DB detach "
				  "for database '%s'\n", ctdb_db->db_name));
		return -1;
	}

	/* Detach database from recoverd */
	if (ctdb_daemon_send_message(ctdb, ctdb->pnn,
				     CTDB_SRVID_DETACH_DATABASE,
				     indata) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to detach DB from recoverd\n"));
		return -1;
	}

	/* Disable vacuuming and drop all vacuuming data */
	talloc_free(ctdb_db->vacuum_handle);
	talloc_free(ctdb_db->delete_queue);

	/* Terminate any deferred fetch */
	talloc_free(ctdb_db->deferred_fetch);

	/* Terminate any traverses */
	while (ctdb_db->traverse) {
		talloc_free(ctdb_db->traverse);
	}

	/* Terminate any revokes */
	while (ctdb_db->revokechild_active) {
		talloc_free(ctdb_db->revokechild_active);
	}

	/* Free readonly tracking database */
	if (ctdb_db->readonly) {
		talloc_free(ctdb_db->rottdb);
	}

	DLIST_REMOVE(ctdb->db_list, ctdb_db);

	DEBUG(DEBUG_NOTICE, ("Detached from database '%s'\n",
			     ctdb_db->db_name));
	talloc_free(ctdb_db);

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
		if (s == NULL) {
			closedir(d);
			CTDB_NO_MEMORY(ctdb, s);
		}

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

		if (ctdb_local_attach(ctdb, s, true, unhealthy_reason, false, false) != 0) {
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

int32_t ctdb_control_set_db_priority(struct ctdb_context *ctdb, TDB_DATA indata,
				     uint32_t client_id)
{
	struct ctdb_db_priority *db_prio = (struct ctdb_db_priority *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, db_prio->db_id);
	if (!ctdb_db) {
		if (!(ctdb->nodes[ctdb->pnn]->flags & NODE_FLAGS_INACTIVE)) {
			DEBUG(DEBUG_ERR,("Unknown db_id 0x%x in ctdb_set_db_priority\n",
					 db_prio->db_id));
		}
		return 0;
	}

	if ((db_prio->priority<1) || (db_prio->priority>NUM_DB_PRIORITIES)) {
		DEBUG(DEBUG_ERR,("Trying to set invalid priority : %u\n", db_prio->priority));
		return 0;
	}

	ctdb_db->priority = db_prio->priority;
	DEBUG(DEBUG_INFO,("Setting DB priority to %u for db 0x%08x\n", db_prio->priority, db_prio->db_id));

	if (client_id != 0) {
		/* Broadcast the update to the rest of the cluster */
		ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL, 0,
					 CTDB_CONTROL_SET_DB_PRIORITY, 0,
					 CTDB_CTRL_FLAG_NOREPLY, indata,
					 NULL, NULL);
	}
	return 0;
}


int ctdb_set_db_sticky(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->sticky) {
		return 0;
	}

	if (ctdb_db->persistent) {
		DEBUG(DEBUG_ERR,("Trying to set persistent database with sticky property\n"));
		return -1;
	}

	ctdb_db->sticky_records = trbt_create(ctdb_db, 0);

	ctdb_db->sticky = true;

	DEBUG(DEBUG_NOTICE,("set db sticky %s\n", ctdb_db->db_name));

	return 0;
}

int32_t ctdb_control_get_db_statistics(struct ctdb_context *ctdb,
				uint32_t db_id,
				TDB_DATA *outdata)
{
	struct ctdb_db_context *ctdb_db;
	struct ctdb_db_statistics *stats;
	int i;
	int len;
	char *ptr;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,("Unknown db_id 0x%x in get_db_statistics\n", db_id));
		return -1;
	}

	len = offsetof(struct ctdb_db_statistics, hot_keys_wire);
	for (i = 0; i < MAX_HOT_KEYS; i++) {
		len += ctdb_db->statistics.hot_keys[i].key.dsize;
	}

	stats = talloc_size(outdata, len);
	if (stats == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate db statistics structure\n"));
		return -1;
	}

	*stats = ctdb_db->statistics;

	stats->num_hot_keys = MAX_HOT_KEYS;

	ptr = &stats->hot_keys_wire[0];
	for (i = 0; i < MAX_HOT_KEYS; i++) {
		memcpy(ptr, ctdb_db->statistics.hot_keys[i].key.dptr,
		       ctdb_db->statistics.hot_keys[i].key.dsize);
		ptr += ctdb_db->statistics.hot_keys[i].key.dsize;
	}

	outdata->dptr  = (uint8_t *)stats;
	outdata->dsize = len;

	return 0;
}
