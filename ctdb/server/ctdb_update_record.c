/* 
   implementation of the update record control

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
#include "system/network.h"
#include "system/time.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/util_process.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

struct ctdb_persistent_write_state {
	struct ctdb_db_context *ctdb_db;
	struct ctdb_marshall_buffer *m;
	struct ctdb_req_control_old *c;
	uint32_t flags;
};

/* don't create/update records that does not exist locally */
#define UPDATE_FLAGS_REPLACE_ONLY	1

/*
  called from a child process to write the data
 */
static int ctdb_persistent_store(struct ctdb_persistent_write_state *state)
{
	unsigned int i;
	int ret;
	struct ctdb_rec_data_old *rec = NULL;
	struct ctdb_marshall_buffer *m = state->m;

	ret = tdb_transaction_start(state->ctdb_db->ltdb->tdb);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("Failed to start transaction for db_id 0x%08x in ctdb_persistent_store\n",
				 state->ctdb_db->db_id));
		return -1;
	}

	for (i=0;i<m->count;i++) {
		struct ctdb_ltdb_header oldheader;
		struct ctdb_ltdb_header header;
		TDB_DATA key, data, olddata;
		TALLOC_CTX *tmp_ctx = talloc_new(state);

		rec = ctdb_marshall_loop_next(m, rec, NULL, &header, &key, &data);

		if (rec == NULL) {
			D_ERR("Failed to get next record %u for db_id 0x%08x "
			      "in ctdb_persistent_store\n",
			      i,
			      state->ctdb_db->db_id);
			talloc_free(tmp_ctx);
			goto failed;
		}

		/* we must check if the record exists or not because
		   ctdb_ltdb_fetch will unconditionally create a record
		 */
		if (state->flags & UPDATE_FLAGS_REPLACE_ONLY) {
			TDB_DATA trec;
			trec = tdb_fetch(state->ctdb_db->ltdb->tdb, key);
			if (trec.dsize == 0) {
				talloc_free(tmp_ctx);
				continue;
			}
			free(trec.dptr);
		}

		/* fetch the old header and ensure the rsn is less than the new rsn */
		ret = ctdb_ltdb_fetch(state->ctdb_db, key, &oldheader, tmp_ctx, &olddata);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to fetch old record for db_id 0x%08x in ctdb_persistent_store\n",
					 state->ctdb_db->db_id));
			talloc_free(tmp_ctx);
			goto failed;
		}

		if (oldheader.rsn >= header.rsn &&
		    (olddata.dsize != data.dsize ||
		     memcmp(olddata.dptr, data.dptr, data.dsize) != 0)) {
			DEBUG(DEBUG_CRIT,("existing header for db_id 0x%08x has larger RSN %llu than new RSN %llu in ctdb_persistent_store\n",
					  state->ctdb_db->db_id,
					  (unsigned long long)oldheader.rsn, (unsigned long long)header.rsn));
			talloc_free(tmp_ctx);
			goto failed;
		}

		talloc_free(tmp_ctx);

		ret = ctdb_ltdb_store(state->ctdb_db, key, &header, data);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT,("Failed to store record for db_id 0x%08x in ctdb_persistent_store\n",
					  state->ctdb_db->db_id));
			goto failed;
		}
	}

	ret = tdb_transaction_commit(state->ctdb_db->ltdb->tdb);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("Failed to commit transaction for db_id 0x%08x in ctdb_persistent_store\n",
				 state->ctdb_db->db_id));
		return -1;
	}

	return 0;

failed:
	tdb_transaction_cancel(state->ctdb_db->ltdb->tdb);
	return -1;
}


/*
  called when we the child has completed the persistent write
  on our behalf
 */
static void ctdb_persistent_write_callback(int status, void *private_data)
{
	struct ctdb_persistent_write_state *state = talloc_get_type(private_data,
								   struct ctdb_persistent_write_state);


	ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, status, NULL);

	talloc_free(state);
}

/*
  called if our lockwait child times out
 */
static void ctdb_persistent_lock_timeout(struct tevent_context *ev,
					 struct tevent_timer *te,
					 struct timeval t, void *private_data)
{
	struct ctdb_persistent_write_state *state = talloc_get_type(private_data,
								   struct ctdb_persistent_write_state);
	ctdb_request_control_reply(state->ctdb_db->ctdb, state->c, NULL, -1, "timeout in ctdb_persistent_lock");
	talloc_free(state);
}

struct childwrite_handle {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct tevent_fd *fde;
	int fd[2];
	pid_t child;
	void *private_data;
	void (*callback)(int, void *);
	struct timeval start_time;
};

static int childwrite_destructor(struct childwrite_handle *h)
{
	CTDB_DECREMENT_STAT(h->ctdb, pending_childwrite_calls);
	ctdb_kill(h->ctdb, h->child, SIGKILL);
	return 0;
}

/* called when the child process has finished writing the record to the
   database
*/
static void childwrite_handler(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags, void *private_data)
{
	struct childwrite_handle *h = talloc_get_type(private_data,
						     struct childwrite_handle);
	void *p = h->private_data;
	void (*callback)(int, void *) = h->callback;
	pid_t child = h->child;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	int ret;
	char c;

	CTDB_UPDATE_LATENCY(h->ctdb, h->ctdb_db, "persistent", childwrite_latency, h->start_time);
	CTDB_DECREMENT_STAT(h->ctdb, pending_childwrite_calls);

	/* the handle needs to go away when the context is gone - when
	   the handle goes away this implicitly closes the pipe, which
	   kills the child */
	talloc_steal(tmp_ctx, h);

	talloc_set_destructor(h, NULL);

	ret = sys_read(h->fd[0], &c, 1);
	if (ret < 1) {
		DEBUG(DEBUG_ERR, (__location__ " Read returned %d. Childwrite failed\n", ret));
		c = 1;
	}

	callback(c, p);

	ctdb_kill(h->ctdb, child, SIGKILL);
	talloc_free(tmp_ctx);
}

/* this creates a child process which will take out a tdb transaction
   and write the record to the database.
*/
static struct childwrite_handle *ctdb_childwrite(
				struct ctdb_db_context *ctdb_db,
				void (*callback)(int, void *private_data),
				struct ctdb_persistent_write_state *state)
{
	struct childwrite_handle *result;
	int ret;
	pid_t parent = getpid();

	CTDB_INCREMENT_STAT(ctdb_db->ctdb, childwrite_calls);
	CTDB_INCREMENT_STAT(ctdb_db->ctdb, pending_childwrite_calls);

	if (!(result = talloc_zero(state, struct childwrite_handle))) {
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_childwrite_calls);
		return NULL;
	}

	ret = pipe(result->fd);

	if (ret != 0) {
		talloc_free(result);
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_childwrite_calls);
		return NULL;
	}

	result->child = ctdb_fork(ctdb_db->ctdb);

	if (result->child == (pid_t)-1) {
		close(result->fd[0]);
		close(result->fd[1]);
		talloc_free(result);
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_childwrite_calls);
		return NULL;
	}

	result->callback = callback;
	result->private_data = state;
	result->ctdb = ctdb_db->ctdb;
	result->ctdb_db = ctdb_db;

	if (result->child == 0) {
		char c = 0;

		close(result->fd[0]);
		prctl_set_comment("ctdb_write_persistent");
		ret = ctdb_persistent_store(state);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to write persistent data\n"));
			c = 1;
		}

		sys_write(result->fd[1], &c, 1);

		ctdb_wait_for_process_to_exit(parent);
		_exit(0);
	}

	close(result->fd[1]);
	set_close_on_exec(result->fd[0]);

	talloc_set_destructor(result, childwrite_destructor);

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d for ctdb_childwrite\n", result->fd[0]));

	result->fde = tevent_add_fd(ctdb_db->ctdb->ev, result, result->fd[0],
				    TEVENT_FD_READ, childwrite_handler,
				    (void *)result);
	if (result->fde == NULL) {
		talloc_free(result);
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_childwrite_calls);
		return NULL;
	}
	tevent_fd_set_auto_close(result->fde);

	result->start_time = timeval_current();

	return result;
}

/*
   update a record on this node if the new record has a higher rsn than the
   current record
 */
int32_t ctdb_control_update_record(struct ctdb_context *ctdb,
				   struct ctdb_req_control_old *c, TDB_DATA recdata,
				   bool *async_reply)
{
	struct ctdb_db_context *ctdb_db;
	struct ctdb_persistent_write_state *state;
	struct childwrite_handle *handle;
	struct ctdb_marshall_buffer *m = (struct ctdb_marshall_buffer *)recdata.dptr;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_INFO,("rejecting ctdb_control_update_record when recovery active\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, m->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unknown database 0x%08x in ctdb_control_update_record\n", m->db_id));
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		DEBUG(DEBUG_ERR,("db(%s) unhealty in ctdb_control_update_record: %s\n",
				 ctdb_db->db_name, ctdb_db->unhealthy_reason));
		return -1;
	}

	state = talloc(ctdb, struct ctdb_persistent_write_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb_db = ctdb_db;
	state->c       = c;
	state->m       = m;
	state->flags   = 0;
	if (ctdb_db_volatile(ctdb_db)) {
		state->flags   = UPDATE_FLAGS_REPLACE_ONLY;
	}

	/* create a child process to take out a transaction and
	   write the data.
	*/
	handle = ctdb_childwrite(ctdb_db, ctdb_persistent_write_callback, state);
	if (handle == NULL) {
		DEBUG(DEBUG_ERR,("Failed to setup childwrite handler in ctdb_control_update_record\n"));
		talloc_free(state);
		return -1;
	}

	/* we need to wait for the replies */
	*async_reply = true;

	/* need to keep the control structure around */
	talloc_steal(state, c);

	/* but we won't wait forever */
	tevent_add_timer(ctdb->ev, state,
			 timeval_current_ofs(ctdb->tunable.control_timeout, 0),
			 ctdb_persistent_lock_timeout, state);

	return 0;
}

