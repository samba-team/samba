/* 
   ctdb_call protocol code

   Copyright (C) Andrew Tridgell  2006

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
/*
  see http://wiki.samba.org/index.php/Samba_%26_Clustering for
  protocol design and packet details
*/
#include "includes.h"
#include "tdb.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"

struct ctdb_sticky_record {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	TDB_CONTEXT *pindown;
};

/*
  find the ctdb_db from a db index
 */
 struct ctdb_db_context *find_ctdb_db(struct ctdb_context *ctdb, uint32_t id)
{
	struct ctdb_db_context *ctdb_db;

	for (ctdb_db=ctdb->db_list; ctdb_db; ctdb_db=ctdb_db->next) {
		if (ctdb_db->db_id == id) {
			break;
		}
	}
	return ctdb_db;
}

/*
  a varient of input packet that can be used in lock requeue
*/
static void ctdb_call_input_pkt(void *p, struct ctdb_req_header *hdr)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);
	ctdb_input_pkt(ctdb, hdr);
}


/*
  send an error reply
*/
static void ctdb_send_error(struct ctdb_context *ctdb, 
			    struct ctdb_req_header *hdr, uint32_t status,
			    const char *fmt, ...) PRINTF_ATTRIBUTE(4,5);
static void ctdb_send_error(struct ctdb_context *ctdb, 
			    struct ctdb_req_header *hdr, uint32_t status,
			    const char *fmt, ...)
{
	va_list ap;
	struct ctdb_reply_error *r;
	char *msg;
	int msglen, len;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Failed to send error. Transport is DOWN\n"));
		return;
	}

	va_start(ap, fmt);
	msg = talloc_vasprintf(ctdb, fmt, ap);
	if (msg == NULL) {
		ctdb_fatal(ctdb, "Unable to allocate error in ctdb_send_error\n");
	}
	va_end(ap);

	msglen = strlen(msg)+1;
	len = offsetof(struct ctdb_reply_error, msg);
	r = ctdb_transport_allocate(ctdb, msg, CTDB_REPLY_ERROR, len + msglen, 
				    struct ctdb_reply_error);
	CTDB_NO_MEMORY_FATAL(ctdb, r);

	r->hdr.destnode  = hdr->srcnode;
	r->hdr.reqid     = hdr->reqid;
	r->status        = status;
	r->msglen        = msglen;
	memcpy(&r->msg[0], msg, msglen);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(msg);
}


/**
 * send a redirect reply
 *
 * The logic behind this function is this:
 *
 * A client wants to grab a record and sends a CTDB_REQ_CALL packet
 * to its local ctdb (ctdb_request_call). If the node is not itself
 * the record's DMASTER, it first redirects the packet to  the
 * record's LMASTER. The LMASTER then redirects the call packet to
 * the current DMASTER. Note that this works because of this: When
 * a record is migrated off a node, then the new DMASTER is stored
 * in the record's copy on the former DMASTER.
 */
static void ctdb_call_send_redirect(struct ctdb_context *ctdb,
				    struct ctdb_db_context *ctdb_db,
				    TDB_DATA key,
				    struct ctdb_req_call *c, 
				    struct ctdb_ltdb_header *header)
{
	uint32_t lmaster = ctdb_lmaster(ctdb, &key);

	c->hdr.destnode = lmaster;
	if (ctdb->pnn == lmaster) {
		c->hdr.destnode = header->dmaster;
	}
	c->hopcount++;

	if (c->hopcount%100 > 95) {
		DEBUG(DEBUG_WARNING,("High hopcount %d dbid:%s "
			"key:0x%08x reqid=%08x pnn:%d src:%d lmaster:%d "
			"header->dmaster:%d dst:%d\n",
			c->hopcount, ctdb_db->db_name, ctdb_hash(&key),
			c->hdr.reqid, ctdb->pnn, c->hdr.srcnode, lmaster,
			header->dmaster, c->hdr.destnode));
	}

	ctdb_queue_packet(ctdb, &c->hdr);
}


/*
  send a dmaster reply

  caller must have the chainlock before calling this routine. Caller must be
  the lmaster
*/
static void ctdb_send_dmaster_reply(struct ctdb_db_context *ctdb_db,
				    struct ctdb_ltdb_header *header,
				    TDB_DATA key, TDB_DATA data,
				    uint32_t new_dmaster,
				    uint32_t reqid)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_reply_dmaster *r;
	int ret, len;
	TALLOC_CTX *tmp_ctx;

	if (ctdb->pnn != ctdb_lmaster(ctdb, &key)) {
		DEBUG(DEBUG_ALERT,(__location__ " Caller is not lmaster!\n"));
		return;
	}

	header->dmaster = new_dmaster;
	ret = ctdb_ltdb_store(ctdb_db, key, header, data);
	if (ret != 0) {
		ctdb_fatal(ctdb, "ctdb_send_dmaster_reply unable to update dmaster");
		return;
	}

	if (ctdb->methods == NULL) {
		ctdb_fatal(ctdb, "ctdb_send_dmaster_reply cant update dmaster since transport is down");
		return;
	}

	/* put the packet on a temporary context, allowing us to safely free
	   it below even if ctdb_reply_dmaster() has freed it already */
	tmp_ctx = talloc_new(ctdb);

	/* send the CTDB_REPLY_DMASTER */
	len = offsetof(struct ctdb_reply_dmaster, data) + key.dsize + data.dsize + sizeof(uint32_t);
	r = ctdb_transport_allocate(ctdb, tmp_ctx, CTDB_REPLY_DMASTER, len,
				    struct ctdb_reply_dmaster);
	CTDB_NO_MEMORY_FATAL(ctdb, r);

	r->hdr.destnode  = new_dmaster;
	r->hdr.reqid     = reqid;
	r->rsn           = header->rsn;
	r->keylen        = key.dsize;
	r->datalen       = data.dsize;
	r->db_id         = ctdb_db->db_id;
	memcpy(&r->data[0], key.dptr, key.dsize);
	memcpy(&r->data[key.dsize], data.dptr, data.dsize);
	memcpy(&r->data[key.dsize+data.dsize], &header->flags, sizeof(uint32_t));

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(tmp_ctx);
}

/*
  send a dmaster request (give another node the dmaster for a record)

  This is always sent to the lmaster, which ensures that the lmaster
  always knows who the dmaster is. The lmaster will then send a
  CTDB_REPLY_DMASTER to the new dmaster
*/
static void ctdb_call_send_dmaster(struct ctdb_db_context *ctdb_db, 
				   struct ctdb_req_call *c, 
				   struct ctdb_ltdb_header *header,
				   TDB_DATA *key, TDB_DATA *data)
{
	struct ctdb_req_dmaster *r;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int len;
	uint32_t lmaster = ctdb_lmaster(ctdb, key);

	if (ctdb->methods == NULL) {
		ctdb_fatal(ctdb, "Failed ctdb_call_send_dmaster since transport is down");
		return;
	}

	if (data->dsize != 0) {
		header->flags |= CTDB_REC_FLAG_MIGRATED_WITH_DATA;
	}

	if (lmaster == ctdb->pnn) {
		ctdb_send_dmaster_reply(ctdb_db, header, *key, *data, 
					c->hdr.srcnode, c->hdr.reqid);
		return;
	}
	
	len = offsetof(struct ctdb_req_dmaster, data) + key->dsize + data->dsize
			+ sizeof(uint32_t);
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_DMASTER, len, 
				    struct ctdb_req_dmaster);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	r->hdr.destnode  = lmaster;
	r->hdr.reqid     = c->hdr.reqid;
	r->db_id         = c->db_id;
	r->rsn           = header->rsn;
	r->dmaster       = c->hdr.srcnode;
	r->keylen        = key->dsize;
	r->datalen       = data->dsize;
	memcpy(&r->data[0], key->dptr, key->dsize);
	memcpy(&r->data[key->dsize], data->dptr, data->dsize);
	memcpy(&r->data[key->dsize + data->dsize], &header->flags, sizeof(uint32_t));

	header->dmaster = c->hdr.srcnode;
	if (ctdb_ltdb_store(ctdb_db, *key, header, *data) != 0) {
		ctdb_fatal(ctdb, "Failed to store record in ctdb_call_send_dmaster");
	}
	
	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
}

static void ctdb_sticky_pindown_timeout(struct event_context *ev, struct timed_event *te, 
				       struct timeval t, void *private_data)
{
	struct ctdb_sticky_record *sr = talloc_get_type(private_data, 
						       struct ctdb_sticky_record);

	DEBUG(DEBUG_ERR,("Pindown timeout db:%s  unstick record\n", sr->ctdb_db->db_name));
	if (sr->pindown != NULL) {
		talloc_free(sr->pindown);
		sr->pindown = NULL;
	}
}

static int
ctdb_set_sticky_pindown(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	uint32_t *k;
	struct ctdb_sticky_record *sr;

	k = ctdb_key_to_idkey(tmp_ctx, key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for sticky record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	sr = trbt_lookuparray32(ctdb_db->sticky_records, k[0], &k[0]);
	if (sr == NULL) {
		talloc_free(tmp_ctx);
		return 0;
	}

	talloc_free(tmp_ctx);

	if (sr->pindown == NULL) {
		DEBUG(DEBUG_ERR,("Pinning down record in %s for %d ms\n", ctdb_db->db_name, ctdb->tunable.sticky_pindown));
		sr->pindown = talloc_new(sr);
		if (sr->pindown == NULL) {
			DEBUG(DEBUG_ERR,("Failed to allocate pindown context for sticky record\n"));
			return -1;
		}
		event_add_timed(ctdb->ev, sr->pindown, timeval_current_ofs(ctdb->tunable.sticky_pindown / 1000, (ctdb->tunable.sticky_pindown * 1000) % 1000000), ctdb_sticky_pindown_timeout, sr);
	}

	return 0;
}

/*
  called when a CTDB_REPLY_DMASTER packet comes in, or when the lmaster
  gets a CTDB_REQUEST_DMASTER for itself. We become the dmaster.

  must be called with the chainlock held. This function releases the chainlock
*/
static void ctdb_become_dmaster(struct ctdb_db_context *ctdb_db,
				struct ctdb_req_header *hdr,
				TDB_DATA key, TDB_DATA data,
				uint64_t rsn, uint32_t record_flags)
{
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_ltdb_header header;
	int ret;

	DEBUG(DEBUG_DEBUG,("pnn %u dmaster response %08x\n", ctdb->pnn, ctdb_hash(&key)));

	ZERO_STRUCT(header);
	header.rsn = rsn;
	header.dmaster = ctdb->pnn;
	header.flags = record_flags;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);

	if (state) {
		if (state->call->flags & CTDB_CALL_FLAG_VACUUM_MIGRATION) {
			/*
			 * We temporarily add the VACUUM_MIGRATED flag to
			 * the record flags, so that ctdb_ltdb_store can
			 * decide whether the record should be stored or
			 * deleted.
			 */
			header.flags |= CTDB_REC_FLAG_VACUUM_MIGRATED;
		}
	}

	if (ctdb_ltdb_store(ctdb_db, key, &header, data) != 0) {
		ctdb_fatal(ctdb, "ctdb_reply_dmaster store failed\n");

		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}
		return;
	}

	/* we just became DMASTER and this database is "sticky",
	   see if the record is flagged as "hot" and set up a pin-down
	   context to stop migrations for a little while if so
	*/
	if (ctdb_db->sticky) {
		ctdb_set_sticky_pindown(ctdb, ctdb_db, key);
	}

	if (state == NULL) {
		DEBUG(DEBUG_ERR,("pnn %u Invalid reqid %u in ctdb_become_dmaster from node %u\n",
			 ctdb->pnn, hdr->reqid, hdr->srcnode));

		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}
		return;
	}

	if (key.dsize != state->call->key.dsize || memcmp(key.dptr, state->call->key.dptr, key.dsize)) {
		DEBUG(DEBUG_ERR, ("Got bogus DMASTER packet reqid:%u from node %u. Key does not match key held in matching idr.\n", hdr->reqid, hdr->srcnode));

		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(DEBUG_ERR, ("Dropped orphan in ctdb_become_dmaster with reqid:%u\n from node %u", hdr->reqid, hdr->srcnode));

		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}
		return;
	}

	ctdb_call_local(ctdb_db, state->call, &header, state, &data, true);

	ret = ctdb_ltdb_unlock(ctdb_db, state->call->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
	}

	state->state = CTDB_CALL_DONE;
	if (state->async.fn) {
		state->async.fn(state);
	}
}

struct dmaster_defer_call {
	struct dmaster_defer_call *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_req_header *hdr;
};

struct dmaster_defer_queue {
	struct ctdb_context *ctdb;
	uint32_t generation;
	struct dmaster_defer_call *deferred_calls;
};

static void dmaster_defer_reprocess(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval t,
				    void *private_data)
{
	struct dmaster_defer_call *call = talloc_get_type(
		private_data, struct dmaster_defer_call);

	ctdb_input_pkt(call->ctdb, call->hdr);
	talloc_free(call);
}

static int dmaster_defer_queue_destructor(struct dmaster_defer_queue *ddq)
{
	/* Ignore requests, if database recovery happens in-between. */
	if (ddq->generation != ddq->ctdb->vnn_map->generation) {
		return 0;
	}

	while (ddq->deferred_calls != NULL) {
		struct dmaster_defer_call *call = ddq->deferred_calls;

		DLIST_REMOVE(ddq->deferred_calls, call);

		talloc_steal(call->ctdb, call);
		tevent_add_timer(call->ctdb->ev, call, timeval_zero(),
				 dmaster_defer_reprocess, call);
	}
	return 0;
}

static void *insert_ddq_callback(void *parm, void *data)
{
	if (data) {
		talloc_free(data);
	}
	return parm;
}

/**
 * This function is used to reigster a key in database that needs to be updated.
 * Any requests for that key should get deferred till this is completed.
 */
static int dmaster_defer_setup(struct ctdb_db_context *ctdb_db,
			       struct ctdb_req_header *hdr,
			       TDB_DATA key)
{
	uint32_t *k;
	struct dmaster_defer_queue *ddq;

	k = ctdb_key_to_idkey(hdr, key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate key for dmaster defer setup\n"));
		return -1;
	}

	/* Already exists */
	ddq = trbt_lookuparray32(ctdb_db->defer_dmaster, k[0], k);
	if (ddq != NULL) {
		talloc_free(k);
		return 0;
	}

	ddq = talloc(hdr, struct dmaster_defer_queue);
	if (ddq == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate dmaster defer queue\n"));
		talloc_free(k);
		return -1;
	}
	ddq->ctdb = ctdb_db->ctdb;
	ddq->generation = hdr->generation;
	ddq->deferred_calls = NULL;

	trbt_insertarray32_callback(ctdb_db->defer_dmaster, k[0], k,
				    insert_ddq_callback, ddq);
	talloc_set_destructor(ddq, dmaster_defer_queue_destructor);

	talloc_free(k);
	return 0;
}

static int dmaster_defer_add(struct ctdb_db_context *ctdb_db,
			     struct ctdb_req_header *hdr,
			     TDB_DATA key)
{
	struct dmaster_defer_queue *ddq;
	struct dmaster_defer_call *call;
	uint32_t *k;

	k = ctdb_key_to_idkey(hdr, key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate key for dmaster defer add\n"));
		return -1;
	}

	ddq = trbt_lookuparray32(ctdb_db->defer_dmaster, k[0], k);
	if (ddq == NULL) {
		talloc_free(k);
		return -1;
	}

	talloc_free(k);

	if (ddq->generation != hdr->generation) {
		talloc_set_destructor(ddq, NULL);
		talloc_free(ddq);
		return -1;
	}

	call = talloc(ddq, struct dmaster_defer_call);
	if (call == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate dmaster defer call\n"));
		return -1;
	}

	call->ctdb = ctdb_db->ctdb;
	call->hdr = talloc_steal(call, hdr);

	DLIST_ADD_END(ddq->deferred_calls, call, NULL);

	return 0;
}

/*
  called when a CTDB_REQ_DMASTER packet comes in

  this comes into the lmaster for a record when the current dmaster
  wants to give up the dmaster role and give it to someone else
*/
void ctdb_request_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_dmaster *c = (struct ctdb_req_dmaster *)hdr;
	TDB_DATA key, data, data2;
	struct ctdb_ltdb_header header;
	struct ctdb_db_context *ctdb_db;
	uint32_t record_flags = 0;
	size_t len;
	int ret;

	key.dptr = c->data;
	key.dsize = c->keylen;
	data.dptr = c->data + c->keylen;
	data.dsize = c->datalen;
	len = offsetof(struct ctdb_req_dmaster, data) + key.dsize + data.dsize
			+ sizeof(uint32_t);
	if (len <= c->hdr.length) {
		memcpy(&record_flags, &c->data[c->keylen + c->datalen],
		       sizeof(record_flags));
	}

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (!ctdb_db) {
		ctdb_send_error(ctdb, hdr, -1,
				"Unknown database in request. db_id==0x%08x",
				c->db_id);
		return;
	}

	dmaster_defer_setup(ctdb_db, hdr, key);

	/* fetch the current record */
	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, key, &header, hdr, &data2,
					   ctdb_call_input_pkt, ctdb, false);
	if (ret == -1) {
		ctdb_fatal(ctdb, "ctdb_req_dmaster failed to fetch record");
		return;
	}
	if (ret == -2) {
		DEBUG(DEBUG_INFO,(__location__ " deferring ctdb_request_dmaster\n"));
		return;
	}

	if (ctdb_lmaster(ctdb, &key) != ctdb->pnn) {
		DEBUG(DEBUG_ALERT,("pnn %u dmaster request to non-lmaster lmaster=%u gen=%u curgen=%u\n",
			 ctdb->pnn, ctdb_lmaster(ctdb, &key), 
			 hdr->generation, ctdb->vnn_map->generation));
		ctdb_fatal(ctdb, "ctdb_req_dmaster to non-lmaster");
	}

	DEBUG(DEBUG_DEBUG,("pnn %u dmaster request on %08x for %u from %u\n", 
		 ctdb->pnn, ctdb_hash(&key), c->dmaster, c->hdr.srcnode));

	/* its a protocol error if the sending node is not the current dmaster */
	if (header.dmaster != hdr->srcnode) {
		DEBUG(DEBUG_ALERT,("pnn %u dmaster request for new-dmaster %u from non-master %u real-dmaster=%u key %08x dbid 0x%08x gen=%u curgen=%u c->rsn=%llu header.rsn=%llu reqid=%u keyval=0x%08x\n",
			 ctdb->pnn, c->dmaster, hdr->srcnode, header.dmaster, ctdb_hash(&key),
			 ctdb_db->db_id, hdr->generation, ctdb->vnn_map->generation,
			 (unsigned long long)c->rsn, (unsigned long long)header.rsn, c->hdr.reqid,
			 (key.dsize >= 4)?(*(uint32_t *)key.dptr):0));
		if (header.rsn != 0 || header.dmaster != ctdb->pnn) {
			DEBUG(DEBUG_ERR,("ctdb_req_dmaster from non-master. Force a recovery.\n"));

			ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
			ctdb_ltdb_unlock(ctdb_db, key);
			return;
		}
	}

	if (header.rsn > c->rsn) {
		DEBUG(DEBUG_ALERT,("pnn %u dmaster request with older RSN new-dmaster %u from %u real-dmaster=%u key %08x dbid 0x%08x gen=%u curgen=%u c->rsn=%llu header.rsn=%llu reqid=%u\n",
			 ctdb->pnn, c->dmaster, hdr->srcnode, header.dmaster, ctdb_hash(&key),
			 ctdb_db->db_id, hdr->generation, ctdb->vnn_map->generation,
			 (unsigned long long)c->rsn, (unsigned long long)header.rsn, c->hdr.reqid));
	}

	/* use the rsn from the sending node */
	header.rsn = c->rsn;

	/* store the record flags from the sending node */
	header.flags = record_flags;

	/* check if the new dmaster is the lmaster, in which case we
	   skip the dmaster reply */
	if (c->dmaster == ctdb->pnn) {
		ctdb_become_dmaster(ctdb_db, hdr, key, data, c->rsn, record_flags);
	} else {
		ctdb_send_dmaster_reply(ctdb_db, &header, key, data, c->dmaster, hdr->reqid);

		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}
	}
}

static void ctdb_sticky_record_timeout(struct event_context *ev, struct timed_event *te, 
				       struct timeval t, void *private_data)
{
	struct ctdb_sticky_record *sr = talloc_get_type(private_data, 
						       struct ctdb_sticky_record);
	talloc_free(sr);
}

static void *ctdb_make_sticky_record_callback(void *parm, void *data)
{
        if (data) {
		DEBUG(DEBUG_ERR,("Already have sticky record registered. Free old %p and create new %p\n", data, parm));
                talloc_free(data);
        }
        return parm;
}

static int
ctdb_make_record_sticky(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	uint32_t *k;
	struct ctdb_sticky_record *sr;

	k = ctdb_key_to_idkey(tmp_ctx, key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for sticky record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	sr = trbt_lookuparray32(ctdb_db->sticky_records, k[0], &k[0]);
	if (sr != NULL) {
		talloc_free(tmp_ctx);
		return 0;
	}

	sr = talloc(ctdb_db->sticky_records, struct ctdb_sticky_record);
	if (sr == NULL) {
		talloc_free(tmp_ctx);
		DEBUG(DEBUG_ERR,("Failed to allocate sticky record structure\n"));
		return -1;
	}

	sr->ctdb    = ctdb;
	sr->ctdb_db = ctdb_db;
	sr->pindown = NULL;

	DEBUG(DEBUG_ERR,("Make record sticky for %d seconds in db %s key:0x%08x.\n",
			 ctdb->tunable.sticky_duration,
			 ctdb_db->db_name, ctdb_hash(&key)));

	trbt_insertarray32_callback(ctdb_db->sticky_records, k[0], &k[0], ctdb_make_sticky_record_callback, sr);

	event_add_timed(ctdb->ev, sr, timeval_current_ofs(ctdb->tunable.sticky_duration, 0), ctdb_sticky_record_timeout, sr);

	talloc_free(tmp_ctx);
	return 0;
}

struct pinned_down_requeue_handle {
	struct ctdb_context *ctdb;
	struct ctdb_req_header *hdr;
};

struct pinned_down_deferred_call {
	struct ctdb_context *ctdb;
	struct ctdb_req_header *hdr;
};

static void pinned_down_requeue(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct pinned_down_requeue_handle *handle = talloc_get_type(private_data, struct pinned_down_requeue_handle);
	struct ctdb_context *ctdb = handle->ctdb;

	talloc_steal(ctdb, handle->hdr);
	ctdb_call_input_pkt(ctdb, handle->hdr);

	talloc_free(handle);
}

static int pinned_down_destructor(struct pinned_down_deferred_call *pinned_down)
{
	struct ctdb_context *ctdb = pinned_down->ctdb;
	struct pinned_down_requeue_handle *handle = talloc(ctdb, struct pinned_down_requeue_handle);

	handle->ctdb = pinned_down->ctdb;
	handle->hdr  = pinned_down->hdr;
	talloc_steal(handle, handle->hdr);

	event_add_timed(ctdb->ev, handle, timeval_zero(), pinned_down_requeue, handle);

	return 0;
}

static int
ctdb_defer_pinned_down_request(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_req_header *hdr)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	uint32_t *k;
	struct ctdb_sticky_record *sr;
	struct pinned_down_deferred_call *pinned_down;

	k = ctdb_key_to_idkey(tmp_ctx, key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for sticky record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	sr = trbt_lookuparray32(ctdb_db->sticky_records, k[0], &k[0]);
	if (sr == NULL) {
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);

	if (sr->pindown == NULL) {
		return -1;
	}
	
	pinned_down = talloc(sr->pindown, struct pinned_down_deferred_call);
	if (pinned_down == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate structure for deferred pinned down request\n"));
		return -1;
	}

	pinned_down->ctdb = ctdb;
	pinned_down->hdr  = hdr;

	talloc_set_destructor(pinned_down, pinned_down_destructor);
	talloc_steal(pinned_down, hdr);

	return 0;
}

static void
ctdb_update_db_stat_hot_keys(struct ctdb_db_context *ctdb_db, TDB_DATA key, int hopcount)
{
	int i, id;

	/* smallest value is always at index 0 */
	if (hopcount <= ctdb_db->statistics.hot_keys[0].count) {
		return;
	}

	/* see if we already know this key */
	for (i = 0; i < MAX_HOT_KEYS; i++) {
		if (key.dsize != ctdb_db->statistics.hot_keys[i].key.dsize) {
			continue;
		}
		if (memcmp(key.dptr, ctdb_db->statistics.hot_keys[i].key.dptr, key.dsize)) {
			continue;
		}
		/* found an entry for this key */
		if (hopcount <= ctdb_db->statistics.hot_keys[i].count) {
			return;
		}
		ctdb_db->statistics.hot_keys[i].count = hopcount;
		goto sort_keys;
	}

	if (ctdb_db->statistics.num_hot_keys < MAX_HOT_KEYS) {
		id = ctdb_db->statistics.num_hot_keys;
		ctdb_db->statistics.num_hot_keys++;
	} else {
		id = 0;
	}

	if (ctdb_db->statistics.hot_keys[id].key.dptr != NULL) {
		talloc_free(ctdb_db->statistics.hot_keys[id].key.dptr);
	}
	ctdb_db->statistics.hot_keys[id].key.dsize = key.dsize;
	ctdb_db->statistics.hot_keys[id].key.dptr  = talloc_memdup(ctdb_db, key.dptr, key.dsize);
	ctdb_db->statistics.hot_keys[id].count = hopcount;
	DEBUG(DEBUG_NOTICE,("Updated hot key database=%s key=0x%08x id=%d hop_count=%d\n",
			    ctdb_db->db_name, ctdb_hash(&key), id, hopcount));

sort_keys:
	for (i = 1; i < MAX_HOT_KEYS; i++) {
		if (ctdb_db->statistics.hot_keys[i].count == 0) {
			continue;
		}
		if (ctdb_db->statistics.hot_keys[i].count < ctdb_db->statistics.hot_keys[0].count) {
			hopcount = ctdb_db->statistics.hot_keys[i].count;
			ctdb_db->statistics.hot_keys[i].count = ctdb_db->statistics.hot_keys[0].count;
			ctdb_db->statistics.hot_keys[0].count = hopcount;

			key = ctdb_db->statistics.hot_keys[i].key;
			ctdb_db->statistics.hot_keys[i].key = ctdb_db->statistics.hot_keys[0].key;
			ctdb_db->statistics.hot_keys[0].key = key;
		}
	}
}

/*
  called when a CTDB_REQ_CALL packet comes in
*/
void ctdb_request_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_call *c = (struct ctdb_req_call *)hdr;
	TDB_DATA data;
	struct ctdb_reply_call *r;
	int ret, len;
	struct ctdb_ltdb_header header;
	struct ctdb_call *call;
	struct ctdb_db_context *ctdb_db;
	int tmp_count, bucket;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Failed ctdb_request_call. Transport is DOWN\n"));
		return;
	}


	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (!ctdb_db) {
		ctdb_send_error(ctdb, hdr, -1,
				"Unknown database in request. db_id==0x%08x",
				c->db_id);
		return;
	}

	call = talloc(hdr, struct ctdb_call);
	CTDB_NO_MEMORY_FATAL(ctdb, call);

	call->call_id  = c->callid;
	call->key.dptr = c->data;
	call->key.dsize = c->keylen;
	call->call_data.dptr = c->data + c->keylen;
	call->call_data.dsize = c->calldatalen;
	call->reply_data.dptr  = NULL;
	call->reply_data.dsize = 0;


	/* If this record is pinned down we should defer the
	   request until the pindown times out
	*/
	if (ctdb_db->sticky) {
		if (ctdb_defer_pinned_down_request(ctdb, ctdb_db, call->key, hdr) == 0) {
			DEBUG(DEBUG_WARNING,
			      ("Defer request for pinned down record in %s\n", ctdb_db->db_name));
			talloc_free(call);
			return;
		}
	}

	if (dmaster_defer_add(ctdb_db, hdr, call->key) == 0) {
		talloc_free(call);
		return;
	}

	/* determine if we are the dmaster for this key. This also
	   fetches the record data (if any), thus avoiding a 2nd fetch of the data 
	   if the call will be answered locally */

	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, call->key, &header, hdr, &data,
					   ctdb_call_input_pkt, ctdb, false);
	if (ret == -1) {
		ctdb_send_error(ctdb, hdr, ret, "ltdb fetch failed in ctdb_request_call");
		talloc_free(call);
		return;
	}
	if (ret == -2) {
		DEBUG(DEBUG_INFO,(__location__ " deferred ctdb_request_call\n"));
		talloc_free(call);
		return;
	}

	/* Dont do READONLY if we dont have a tracking database */
	if ((c->flags & CTDB_WANT_READONLY) && !ctdb_db->readonly) {
		c->flags &= ~CTDB_WANT_READONLY;
	}

	if (header.flags & CTDB_REC_RO_REVOKE_COMPLETE) {
		header.flags &= ~CTDB_REC_RO_FLAGS;
		CTDB_INCREMENT_STAT(ctdb, total_ro_revokes);
		CTDB_INCREMENT_DB_STAT(ctdb_db, db_ro_revokes);
		if (ctdb_ltdb_store(ctdb_db, call->key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to write header with cleared REVOKE flag");
		}
		/* and clear out the tracking data */
		if (tdb_delete(ctdb_db->rottdb, call->key) != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to clear out trackingdb record\n"));
		}
	}

	/* if we are revoking, we must defer all other calls until the revoke
	 * had completed.
	 */
	if (header.flags & CTDB_REC_RO_REVOKING_READONLY) {
		talloc_free(data.dptr);
		ret = ctdb_ltdb_unlock(ctdb_db, call->key);

		if (ctdb_add_revoke_deferred_call(ctdb, ctdb_db, call->key, hdr, ctdb_call_input_pkt, ctdb) != 0) {
			ctdb_fatal(ctdb, "Failed to add deferred call for revoke child");
		}
		talloc_free(call);
		return;
	}

	/*
	 * If we are not the dmaster and are not hosting any delegations,
	 * then we redirect the request to the node than can answer it
	 * (the lmaster or the dmaster).
	 */
	if ((header.dmaster != ctdb->pnn) 
	    && (!(header.flags & CTDB_REC_RO_HAVE_DELEGATIONS)) ) {
		talloc_free(data.dptr);
		ctdb_call_send_redirect(ctdb, ctdb_db, call->key, c, &header);

		ret = ctdb_ltdb_unlock(ctdb_db, call->key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}
		talloc_free(call);
		return;
	}

	if ( (!(c->flags & CTDB_WANT_READONLY))
	&& (header.flags & (CTDB_REC_RO_HAVE_DELEGATIONS|CTDB_REC_RO_HAVE_READONLY)) ) {
		header.flags   |= CTDB_REC_RO_REVOKING_READONLY;
		if (ctdb_ltdb_store(ctdb_db, call->key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to store record with HAVE_DELEGATIONS set");
		}
		ret = ctdb_ltdb_unlock(ctdb_db, call->key);

		if (ctdb_start_revoke_ro_record(ctdb, ctdb_db, call->key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to start record revoke");
		}
		talloc_free(data.dptr);

		if (ctdb_add_revoke_deferred_call(ctdb, ctdb_db, call->key, hdr, ctdb_call_input_pkt, ctdb) != 0) {
			ctdb_fatal(ctdb, "Failed to add deferred call for revoke child");
		}
		talloc_free(call);

		return;
	}		

	/* If this is the first request for delegation. bump rsn and set
	 * the delegations flag
	 */
	if ((c->flags & CTDB_WANT_READONLY)
	&&  (c->callid == CTDB_FETCH_WITH_HEADER_FUNC)
	&&  (!(header.flags & CTDB_REC_RO_HAVE_DELEGATIONS))) {
		header.rsn     += 3;
		header.flags   |= CTDB_REC_RO_HAVE_DELEGATIONS;
		if (ctdb_ltdb_store(ctdb_db, call->key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to store record with HAVE_DELEGATIONS set");
		}
	}
	if ((c->flags & CTDB_WANT_READONLY) 
	&&  (call->call_id == CTDB_FETCH_WITH_HEADER_FUNC)) {
		TDB_DATA tdata;

		tdata = tdb_fetch(ctdb_db->rottdb, call->key);
		if (ctdb_trackingdb_add_pnn(ctdb, &tdata, c->hdr.srcnode) != 0) {
			ctdb_fatal(ctdb, "Failed to add node to trackingdb");
		}
		if (tdb_store(ctdb_db->rottdb, call->key, tdata, TDB_REPLACE) != 0) {
			ctdb_fatal(ctdb, "Failed to store trackingdb data");
		}
		free(tdata.dptr);

		ret = ctdb_ltdb_unlock(ctdb_db, call->key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}

		len = offsetof(struct ctdb_reply_call, data) + data.dsize + sizeof(struct ctdb_ltdb_header);
		r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REPLY_CALL, len, 
					    struct ctdb_reply_call);
		CTDB_NO_MEMORY_FATAL(ctdb, r);
		r->hdr.destnode  = c->hdr.srcnode;
		r->hdr.reqid     = c->hdr.reqid;
		r->status        = 0;
		r->datalen       = data.dsize + sizeof(struct ctdb_ltdb_header);
		header.rsn      -= 2;
		header.flags   |= CTDB_REC_RO_HAVE_READONLY;
		header.flags   &= ~CTDB_REC_RO_HAVE_DELEGATIONS;
		memcpy(&r->data[0], &header, sizeof(struct ctdb_ltdb_header));

		if (data.dsize) {
			memcpy(&r->data[sizeof(struct ctdb_ltdb_header)], data.dptr, data.dsize);
		}

		ctdb_queue_packet(ctdb, &r->hdr);
		CTDB_INCREMENT_STAT(ctdb, total_ro_delegations);
		CTDB_INCREMENT_DB_STAT(ctdb_db, db_ro_delegations);

		talloc_free(r);
		talloc_free(call);
		return;
	}

	CTDB_UPDATE_STAT(ctdb, max_hop_count, c->hopcount);
	tmp_count = c->hopcount;
	bucket = 0;
	while (tmp_count) {
		tmp_count >>= 2;
		bucket++;
	}
	if (bucket >= MAX_COUNT_BUCKETS) {
		bucket = MAX_COUNT_BUCKETS - 1;
	}
	CTDB_INCREMENT_STAT(ctdb, hop_count_bucket[bucket]);
	CTDB_INCREMENT_DB_STAT(ctdb_db, hop_count_bucket[bucket]);
	ctdb_update_db_stat_hot_keys(ctdb_db, call->key, c->hopcount);

	/* If this database supports sticky records, then check if the
	   hopcount is big. If it is it means the record is hot and we
	   should make it sticky.
	*/
	if (ctdb_db->sticky && c->hopcount >= ctdb->tunable.hopcount_make_sticky) {
		ctdb_make_record_sticky(ctdb, ctdb_db, call->key);
	}


	/* Try if possible to migrate the record off to the caller node.
	 * From the clients perspective a fetch of the data is just as 
	 * expensive as a migration.
	 */
	if (c->hdr.srcnode != ctdb->pnn) {
		if (ctdb_db->persistent_state) {
			DEBUG(DEBUG_INFO, (__location__ " refusing migration"
			      " of key %s while transaction is active\n",
			      (char *)call->key.dptr));
		} else {
			DEBUG(DEBUG_DEBUG,("pnn %u starting migration of %08x to %u\n",
				 ctdb->pnn, ctdb_hash(&(call->key)), c->hdr.srcnode));
			ctdb_call_send_dmaster(ctdb_db, c, &header, &(call->key), &data);
			talloc_free(data.dptr);

			ret = ctdb_ltdb_unlock(ctdb_db, call->key);
			if (ret != 0) {
				DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
			}
		}
		talloc_free(call);
		return;
	}

	ret = ctdb_call_local(ctdb_db, call, &header, hdr, &data, true);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_call_local failed\n"));
		call->status = -1;
	}

	ret = ctdb_ltdb_unlock(ctdb_db, call->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
	}

	len = offsetof(struct ctdb_reply_call, data) + call->reply_data.dsize;
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REPLY_CALL, len, 
				    struct ctdb_reply_call);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	r->hdr.destnode  = hdr->srcnode;
	r->hdr.reqid     = hdr->reqid;
	r->status        = call->status;
	r->datalen       = call->reply_data.dsize;
	if (call->reply_data.dsize) {
		memcpy(&r->data[0], call->reply_data.dptr, call->reply_data.dsize);
	}

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
	talloc_free(call);
}

/**
 * called when a CTDB_REPLY_CALL packet comes in
 *
 * This packet comes in response to a CTDB_REQ_CALL request packet. It
 * contains any reply data from the call
 */
void ctdb_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_call *c = (struct ctdb_reply_call *)hdr;
	struct ctdb_call_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " reqid %u not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(DEBUG_ERR, ("Dropped orphaned call reply with reqid:%u\n",hdr->reqid));
		return;
	}


	/* read only delegation processing */
	/* If we got a FETCH_WITH_HEADER we should check if this is a ro
	 * delegation since we may need to update the record header
	 */
	if (state->c->callid == CTDB_FETCH_WITH_HEADER_FUNC) {
		struct ctdb_db_context *ctdb_db = state->ctdb_db;
		struct ctdb_ltdb_header *header = (struct ctdb_ltdb_header *)&c->data[0];
		struct ctdb_ltdb_header oldheader;
		TDB_DATA key, data, olddata;
		int ret;

		if (!(header->flags & CTDB_REC_RO_HAVE_READONLY)) {
			goto finished_ro;
			return;
		}

		key.dsize = state->c->keylen;
		key.dptr  = state->c->data;
		ret = ctdb_ltdb_lock_requeue(ctdb_db, key, hdr,
				     ctdb_call_input_pkt, ctdb, false);
		if (ret == -2) {
			return;
		}
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to get lock in ctdb_reply_call\n"));
			return;
		}

		ret = ctdb_ltdb_fetch(ctdb_db, key, &oldheader, state, &olddata);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Failed to fetch old record in ctdb_reply_call\n"));
			ctdb_ltdb_unlock(ctdb_db, key);
			goto finished_ro;
		}			

		if (header->rsn <= oldheader.rsn) {
			ctdb_ltdb_unlock(ctdb_db, key);
			goto finished_ro;
		}

		if (c->datalen < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_ERR,(__location__ " Got FETCH_WITH_HEADER reply with too little data: %d bytes\n", c->datalen));
			ctdb_ltdb_unlock(ctdb_db, key);
			goto finished_ro;
		}

		data.dsize = c->datalen - sizeof(struct ctdb_ltdb_header);
		data.dptr  = &c->data[sizeof(struct ctdb_ltdb_header)];
		ret = ctdb_ltdb_store(ctdb_db, key, header, data);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Failed to store new record in ctdb_reply_call\n"));
			ctdb_ltdb_unlock(ctdb_db, key);
			goto finished_ro;
		}			

		ctdb_ltdb_unlock(ctdb_db, key);
	}
finished_ro:

	state->call->reply_data.dptr = c->data;
	state->call->reply_data.dsize = c->datalen;
	state->call->status = c->status;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;
	if (state->async.fn) {
		state->async.fn(state);
	}
}


/**
 * called when a CTDB_REPLY_DMASTER packet comes in
 *
 * This packet comes in from the lmaster in response to a CTDB_REQ_CALL
 * request packet. It means that the current dmaster wants to give us
 * the dmaster role.
 */
void ctdb_reply_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_dmaster *c = (struct ctdb_reply_dmaster *)hdr;
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key, data;
	uint32_t record_flags = 0;
	size_t len;
	int ret;

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unknown db_id 0x%x in ctdb_reply_dmaster\n", c->db_id));
		return;
	}
	
	key.dptr = c->data;
	key.dsize = c->keylen;
	data.dptr = &c->data[key.dsize];
	data.dsize = c->datalen;
	len = offsetof(struct ctdb_reply_dmaster, data) + key.dsize + data.dsize
		+ sizeof(uint32_t);
	if (len <= c->hdr.length) {
		memcpy(&record_flags, &c->data[c->keylen + c->datalen],
		       sizeof(record_flags));
	}

	dmaster_defer_setup(ctdb_db, hdr, key);

	ret = ctdb_ltdb_lock_requeue(ctdb_db, key, hdr,
				     ctdb_call_input_pkt, ctdb, false);
	if (ret == -2) {
		return;
	}
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get lock in ctdb_reply_dmaster\n"));
		return;
	}

	ctdb_become_dmaster(ctdb_db, hdr, key, data, c->rsn, record_flags);
}


/*
  called when a CTDB_REPLY_ERROR packet comes in
*/
void ctdb_reply_error(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_error *c = (struct ctdb_reply_error *)hdr;
	struct ctdb_call_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR,("pnn %u Invalid reqid %u in ctdb_reply_error\n",
			 ctdb->pnn, hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(DEBUG_ERR, ("Dropped orphaned error reply with reqid:%u\n",hdr->reqid));
		return;
	}

	talloc_steal(state, c);

	state->state  = CTDB_CALL_ERROR;
	state->errmsg = (char *)c->msg;
	if (state->async.fn) {
		state->async.fn(state);
	}
}


/*
  destroy a ctdb_call
*/
static int ctdb_call_destructor(struct ctdb_call_state *state)
{
	DLIST_REMOVE(state->ctdb_db->ctdb->pending_calls, state);
	ctdb_reqid_remove(state->ctdb_db->ctdb, state->reqid);
	return 0;
}


/*
  called when a ctdb_call needs to be resent after a reconfigure event
*/
static void ctdb_call_resend(struct ctdb_call_state *state)
{
	struct ctdb_context *ctdb = state->ctdb_db->ctdb;

	state->generation = ctdb->vnn_map->generation;

	/* use a new reqid, in case the old reply does eventually come in */
	ctdb_reqid_remove(ctdb, state->reqid);
	state->reqid = ctdb_reqid_new(ctdb, state);
	state->c->hdr.reqid = state->reqid;

	/* update the generation count for this request, so its valid with the new vnn_map */
	state->c->hdr.generation = state->generation;

	/* send the packet to ourselves, it will be redirected appropriately */
	state->c->hdr.destnode = ctdb->pnn;

	ctdb_queue_packet(ctdb, &state->c->hdr);
	DEBUG(DEBUG_NOTICE,("resent ctdb_call\n"));
}

/*
  resend all pending calls on recovery
 */
void ctdb_call_resend_all(struct ctdb_context *ctdb)
{
	struct ctdb_call_state *state, *next;
	for (state=ctdb->pending_calls;state;state=next) {
		next = state->next;
		ctdb_call_resend(state);
	}
}

/*
  this allows the caller to setup a async.fn 
*/
static void call_local_trigger(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct ctdb_call_state *state = talloc_get_type(private_data, struct ctdb_call_state);
	if (state->async.fn) {
		state->async.fn(state);
	}
}	


/*
  construct an event driven local ctdb_call

  this is used so that locally processed ctdb_call requests are processed
  in an event driven manner
*/
struct ctdb_call_state *ctdb_call_local_send(struct ctdb_db_context *ctdb_db, 
					     struct ctdb_call *call,
					     struct ctdb_ltdb_header *header,
					     TDB_DATA *data)
{
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int ret;

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	CTDB_NO_MEMORY_NULL(ctdb, state);

	talloc_steal(state, data->dptr);

	state->state = CTDB_CALL_DONE;
	state->call  = talloc(state, struct ctdb_call);
	CTDB_NO_MEMORY_NULL(ctdb, state->call);
	*(state->call) = *call;
	state->ctdb_db = ctdb_db;

	ret = ctdb_call_local(ctdb_db, state->call, header, state, data, true);
	if (ret != 0) {
		DEBUG(DEBUG_DEBUG,("ctdb_call_local() failed, ignoring return code %d\n", ret));
	}

	event_add_timed(ctdb->ev, state, timeval_zero(), call_local_trigger, state);

	return state;
}


/*
  make a remote ctdb call - async send. Called in daemon context.

  This constructs a ctdb_call request and queues it for processing. 
  This call never blocks.
*/
struct ctdb_call_state *ctdb_daemon_call_send_remote(struct ctdb_db_context *ctdb_db, 
						     struct ctdb_call *call, 
						     struct ctdb_ltdb_header *header)
{
	uint32_t len;
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Failed send packet. Transport is down\n"));
		return NULL;
	}

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	CTDB_NO_MEMORY_NULL(ctdb, state);
	state->call = talloc(state, struct ctdb_call);
	CTDB_NO_MEMORY_NULL(ctdb, state->call);

	state->reqid = ctdb_reqid_new(ctdb, state);
	state->ctdb_db = ctdb_db;
	talloc_set_destructor(state, ctdb_call_destructor);

	len = offsetof(struct ctdb_req_call, data) + call->key.dsize + call->call_data.dsize;
	state->c = ctdb_transport_allocate(ctdb, state, CTDB_REQ_CALL, len, 
					   struct ctdb_req_call);
	CTDB_NO_MEMORY_NULL(ctdb, state->c);
	state->c->hdr.destnode  = header->dmaster;

	/* this limits us to 16k outstanding messages - not unreasonable */
	state->c->hdr.reqid     = state->reqid;
	state->c->flags         = call->flags;
	state->c->db_id         = ctdb_db->db_id;
	state->c->callid        = call->call_id;
	state->c->hopcount      = 0;
	state->c->keylen        = call->key.dsize;
	state->c->calldatalen   = call->call_data.dsize;
	memcpy(&state->c->data[0], call->key.dptr, call->key.dsize);
	memcpy(&state->c->data[call->key.dsize], 
	       call->call_data.dptr, call->call_data.dsize);
	*(state->call)              = *call;
	state->call->call_data.dptr = &state->c->data[call->key.dsize];
	state->call->key.dptr       = &state->c->data[0];

	state->state  = CTDB_CALL_WAIT;
	state->generation = ctdb->vnn_map->generation;

	DLIST_ADD(ctdb->pending_calls, state);

	ctdb_queue_packet(ctdb, &state->c->hdr);

	return state;
}

/*
  make a remote ctdb call - async recv - called in daemon context

  This is called when the program wants to wait for a ctdb_call to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdb_daemon_call_recv(struct ctdb_call_state *state, struct ctdb_call *call)
{
	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->ctdb_db->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		ctdb_set_error(state->ctdb_db->ctdb, "%s", state->errmsg);
		talloc_free(state);
		return -1;
	}

	if (state->call->reply_data.dsize) {
		call->reply_data.dptr = talloc_memdup(call,
						      state->call->reply_data.dptr,
						      state->call->reply_data.dsize);
		call->reply_data.dsize = state->call->reply_data.dsize;
	} else {
		call->reply_data.dptr = NULL;
		call->reply_data.dsize = 0;
	}
	call->status = state->call->status;
	talloc_free(state);
	return 0;
}


/* 
   send a keepalive packet to the other node
*/
void ctdb_send_keepalive(struct ctdb_context *ctdb, uint32_t destnode)
{
	struct ctdb_req_keepalive *r;
	
	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Failed to send keepalive. Transport is DOWN\n"));
		return;
	}

	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_KEEPALIVE,
				    sizeof(struct ctdb_req_keepalive), 
				    struct ctdb_req_keepalive);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	r->hdr.destnode  = destnode;
	r->hdr.reqid     = 0;
	
	CTDB_INCREMENT_STAT(ctdb, keepalive_packets_sent);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
}



struct revokechild_deferred_call {
	struct ctdb_context *ctdb;
	struct ctdb_req_header *hdr;
	deferred_requeue_fn fn;
	void *ctx;
};

struct revokechild_handle {
	struct revokechild_handle *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct fd_event *fde;
	int status;
	int fd[2];
	pid_t child;
	TDB_DATA key;
};

struct revokechild_requeue_handle {
	struct ctdb_context *ctdb;
	struct ctdb_req_header *hdr;
	deferred_requeue_fn fn;
	void *ctx;
};

static void deferred_call_requeue(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct revokechild_requeue_handle *requeue_handle = talloc_get_type(private_data, struct revokechild_requeue_handle);

	requeue_handle->fn(requeue_handle->ctx, requeue_handle->hdr);
	talloc_free(requeue_handle);
}

static int deferred_call_destructor(struct revokechild_deferred_call *deferred_call)
{
	struct ctdb_context *ctdb = deferred_call->ctdb;
	struct revokechild_requeue_handle *requeue_handle = talloc(ctdb, struct revokechild_requeue_handle);
	struct ctdb_req_call *c = (struct ctdb_req_call *)deferred_call->hdr;

	requeue_handle->ctdb = ctdb;
	requeue_handle->hdr  = deferred_call->hdr;
	requeue_handle->fn   = deferred_call->fn;
	requeue_handle->ctx  = deferred_call->ctx;
	talloc_steal(requeue_handle, requeue_handle->hdr);

	/* when revoking, any READONLY requests have 1 second grace to let read/write finish first */
	event_add_timed(ctdb->ev, requeue_handle, timeval_current_ofs(c->flags & CTDB_WANT_READONLY ? 1 : 0, 0), deferred_call_requeue, requeue_handle);

	return 0;
}


static int revokechild_destructor(struct revokechild_handle *rc)
{
	if (rc->fde != NULL) {
		talloc_free(rc->fde);
	}

	if (rc->fd[0] != -1) {
		close(rc->fd[0]);
	}
	if (rc->fd[1] != -1) {
		close(rc->fd[1]);
	}
	ctdb_kill(rc->ctdb, rc->child, SIGKILL);

	DLIST_REMOVE(rc->ctdb_db->revokechild_active, rc);
	return 0;
}

static void revokechild_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct revokechild_handle *rc = talloc_get_type(private_data, 
						     struct revokechild_handle);
	int ret;
	char c;

	ret = sys_read(rc->fd[0], &c, 1);
	if (ret != 1) {
		DEBUG(DEBUG_ERR,("Failed to read status from revokechild. errno:%d\n", errno));
		rc->status = -1;
		talloc_free(rc);
		return;
	}
	if (c != 0) {
		DEBUG(DEBUG_ERR,("revokechild returned failure. status:%d\n", c));
		rc->status = -1;
		talloc_free(rc);
		return;
	}

	talloc_free(rc);
}

struct ctdb_revoke_state {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	struct ctdb_ltdb_header *header;
	TDB_DATA data;
	int count;
	int status;
	int finished;
};

static void update_record_cb(struct ctdb_client_control_state *state)
{
	struct ctdb_revoke_state *revoke_state;
	int ret;
	int32_t res;

	if (state == NULL) {
		return;
	}
	revoke_state = state->async.private_data;

	state->async.fn = NULL;
        ret = ctdb_control_recv(state->ctdb, state, state, NULL, &res, NULL);
        if ((ret != 0) || (res != 0)) {
		DEBUG(DEBUG_ERR,("Recv for revoke update record failed ret:%d res:%d\n", ret, res));
		revoke_state->status = -1;
	}

	revoke_state->count--;
	if (revoke_state->count <= 0) {
		revoke_state->finished = 1;
	}
}

static void revoke_send_cb(struct ctdb_context *ctdb, uint32_t pnn, void *private_data)
{
	struct ctdb_revoke_state *revoke_state = private_data;
	struct ctdb_client_control_state *state;

	state = ctdb_ctrl_updaterecord_send(ctdb, revoke_state, timeval_current_ofs(ctdb->tunable.control_timeout,0), pnn, revoke_state->ctdb_db, revoke_state->key, revoke_state->header, revoke_state->data);
	if (state == NULL) {
		DEBUG(DEBUG_ERR,("Failure to send update record to revoke readonly delegation\n"));
		revoke_state->status = -1;
		return;
	}
	state->async.fn           = update_record_cb;
	state->async.private_data = revoke_state;

	revoke_state->count++;

}

static void ctdb_revoke_timeout_handler(struct event_context *ev, struct timed_event *te, 
			      struct timeval yt, void *private_data)
{
	struct ctdb_revoke_state *state = private_data;

	DEBUG(DEBUG_ERR,("Timed out waiting for revoke to finish\n"));
	state->finished = 1;
	state->status   = -1;
}

static int ctdb_revoke_all_delegations(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA tdata, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data)
{
	struct ctdb_revoke_state *state = talloc_zero(ctdb, struct ctdb_revoke_state);
	struct ctdb_ltdb_header new_header;
	TDB_DATA new_data;

	state->ctdb_db = ctdb_db;
	state->key     = key;
	state->header  = header;
	state->data    = data;
 
	ctdb_trackingdb_traverse(ctdb, tdata, revoke_send_cb, state);

	event_add_timed(ctdb->ev, state, timeval_current_ofs(ctdb->tunable.control_timeout, 0), ctdb_revoke_timeout_handler, state);

	while (state->finished == 0) {
		event_loop_once(ctdb->ev);
	}

	if (ctdb_ltdb_lock(ctdb_db, key) != 0) {
		DEBUG(DEBUG_ERR,("Failed to chainlock the database in revokechild\n"));
		talloc_free(state);
		return -1;
	}
	if (ctdb_ltdb_fetch(ctdb_db, key, &new_header, state, &new_data) != 0) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(DEBUG_ERR,("Failed for fetch tdb record in revokechild\n"));
		talloc_free(state);
		return -1;
	}
	header->rsn++;
	if (new_header.rsn > header->rsn) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(DEBUG_ERR,("RSN too high in tdb record in revokechild\n"));
		talloc_free(state);
		return -1;
	}
	if ( (new_header.flags & (CTDB_REC_RO_REVOKING_READONLY|CTDB_REC_RO_HAVE_DELEGATIONS)) != (CTDB_REC_RO_REVOKING_READONLY|CTDB_REC_RO_HAVE_DELEGATIONS) ) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(DEBUG_ERR,("Flags are wrong in tdb record in revokechild\n"));
		talloc_free(state);
		return -1;
	}

	/*
	 * If revoke on all nodes succeed, revoke is complete.  Otherwise,
	 * remove CTDB_REC_RO_REVOKING_READONLY flag and retry.
	 */
	if (state->status == 0) {
		new_header.rsn++;
		new_header.flags |= CTDB_REC_RO_REVOKE_COMPLETE;
	} else {
		DEBUG(DEBUG_NOTICE, ("Revoke all delegations failed, retrying.\n"));
		new_header.flags &= ~CTDB_REC_RO_REVOKING_READONLY;
	}
	if (ctdb_ltdb_store(ctdb_db, key, &new_header, new_data) != 0) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(DEBUG_ERR,("Failed to write new record in revokechild\n"));
		talloc_free(state);
		return -1;
	}
	ctdb_ltdb_unlock(ctdb_db, key);

	talloc_free(state);
	return 0;
}


int ctdb_start_revoke_ro_record(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data)
{
	TDB_DATA tdata;
	struct revokechild_handle *rc;
	pid_t parent = getpid();
	int ret;

	header->flags &= ~(CTDB_REC_RO_REVOKING_READONLY|CTDB_REC_RO_HAVE_DELEGATIONS|CTDB_REC_RO_HAVE_READONLY);
	header->flags |= CTDB_REC_FLAG_MIGRATED_WITH_DATA;
	header->rsn   -= 1;

	if ((rc = talloc_zero(ctdb_db, struct revokechild_handle)) == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate revokechild_handle\n"));
		return -1;
	}

	tdata = tdb_fetch(ctdb_db->rottdb, key);
	if (tdata.dsize > 0) {
		uint8_t *tmp;

		tmp = tdata.dptr;
		tdata.dptr = talloc_memdup(rc, tdata.dptr, tdata.dsize);
		free(tmp);
	}

	rc->status    = 0;
	rc->ctdb      = ctdb;
	rc->ctdb_db   = ctdb_db;
	rc->fd[0]     = -1;
	rc->fd[1]     = -1;

	talloc_set_destructor(rc, revokechild_destructor);

	rc->key.dsize = key.dsize;
	rc->key.dptr  = talloc_memdup(rc, key.dptr, key.dsize);
	if (rc->key.dptr == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for revokechild_handle\n"));
		talloc_free(rc);
		return -1;
	}

	ret = pipe(rc->fd);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for revokechild_handle\n"));
		talloc_free(rc);
		return -1;
	}


	rc->child = ctdb_fork(ctdb);
	if (rc->child == (pid_t)-1) {
		DEBUG(DEBUG_ERR,("Failed to fork child for revokechild\n"));
		talloc_free(rc);
		return -1;
	}

	if (rc->child == 0) {
		char c = 0;
		close(rc->fd[0]);
		debug_extra = talloc_asprintf(NULL, "revokechild-%s:", ctdb_db->db_name);

		ctdb_set_process_name("ctdb_revokechild");
		if (switch_from_server_to_client(ctdb, "revokechild-%s", ctdb_db->db_name) != 0) {
			DEBUG(DEBUG_ERR,("Failed to switch from server to client for revokechild process\n"));
			c = 1;
			goto child_finished;
		}

		c = ctdb_revoke_all_delegations(ctdb, ctdb_db, tdata, key, header, data);

child_finished:
		sys_write(rc->fd[1], &c, 1);
		/* make sure we die when our parent dies */
		while (ctdb_kill(ctdb, parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	close(rc->fd[1]);
	rc->fd[1] = -1;
	set_close_on_exec(rc->fd[0]);

	/* This is an active revokechild child process */
	DLIST_ADD_END(ctdb_db->revokechild_active, rc, NULL);

	rc->fde = event_add_fd(ctdb->ev, rc, rc->fd[0],
				   EVENT_FD_READ, revokechild_handler,
				   (void *)rc);
	if (rc->fde == NULL) {
		DEBUG(DEBUG_ERR,("Failed to set up fd event for revokechild process\n"));
		talloc_free(rc);
	}
	tevent_fd_set_auto_close(rc->fde);

	return 0;
}

int ctdb_add_revoke_deferred_call(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_req_header *hdr, deferred_requeue_fn fn, void *call_context)
{
	struct revokechild_handle *rc;
	struct revokechild_deferred_call *deferred_call;

	for (rc = ctdb_db->revokechild_active; rc; rc = rc->next) {
		if (rc->key.dsize == 0) {
			continue;
		}
		if (rc->key.dsize != key.dsize) {
			continue;
		}
		if (!memcmp(rc->key.dptr, key.dptr, key.dsize)) {
			break;
		}
	}

	if (rc == NULL) {
		DEBUG(DEBUG_ERR,("Failed to add deferred call to revoke list. revoke structure not found\n"));
		return -1;
	}

	deferred_call = talloc(rc, struct revokechild_deferred_call);
	if (deferred_call == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate deferred call structure for revoking record\n"));
		return -1;
	}

	deferred_call->ctdb = ctdb;
	deferred_call->hdr  = hdr;
	deferred_call->fn   = fn;
	deferred_call->ctx  = call_context;

	talloc_set_destructor(deferred_call, deferred_call_destructor);
	talloc_steal(deferred_call, hdr);

	return 0;
}
