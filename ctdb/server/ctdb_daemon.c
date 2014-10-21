/* 
   ctdb daemon code

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

#include "includes.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "tdb.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_version.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include <sys/socket.h>

struct ctdb_client_pid_list {
	struct ctdb_client_pid_list *next, *prev;
	struct ctdb_context *ctdb;
	pid_t pid;
	struct ctdb_client *client;
};

const char *ctdbd_pidfile = NULL;

static void daemon_incoming_packet(void *, struct ctdb_req_header *);

static void print_exit_message(void)
{
	if (debug_extra != NULL && debug_extra[0] != '\0') {
		DEBUG(DEBUG_NOTICE,("CTDB %s shutting down\n", debug_extra));
	} else {
		DEBUG(DEBUG_NOTICE,("CTDB daemon shutting down\n"));

		/* Wait a second to allow pending log messages to be flushed */
		sleep(1);
	}
}



static void ctdb_time_tick(struct event_context *ev, struct timed_event *te, 
				  struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);

	if (getpid() != ctdb->ctdbd_pid) {
		return;
	}

	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(1, 0), 
			ctdb_time_tick, ctdb);
}

/* Used to trigger a dummy event once per second, to make
 * detection of hangs more reliable.
 */
static void ctdb_start_time_tickd(struct ctdb_context *ctdb)
{
	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(1, 0), 
			ctdb_time_tick, ctdb);
}

static void ctdb_start_periodic_events(struct ctdb_context *ctdb)
{
	/* start monitoring for connected/disconnected nodes */
	ctdb_start_keepalive(ctdb);

	/* start periodic update of tcp tickle lists */
       	ctdb_start_tcp_tickle_update(ctdb);

	/* start listening for recovery daemon pings */
	ctdb_control_recd_ping(ctdb);

	/* start listening to timer ticks */
	ctdb_start_time_tickd(ctdb);
}

static void ignore_signal(int signum)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signum);
	sigaction(signum, &act, NULL);
}


/*
  send a packet to a client
 */
static int daemon_queue_send(struct ctdb_client *client, struct ctdb_req_header *hdr)
{
	CTDB_INCREMENT_STAT(client->ctdb, client_packets_sent);
	if (hdr->operation == CTDB_REQ_MESSAGE) {
		if (ctdb_queue_length(client->queue) > client->ctdb->tunable.max_queue_depth_drop_msg) {
			DEBUG(DEBUG_ERR,("CTDB_REQ_MESSAGE queue full - killing client connection.\n"));
			talloc_free(client);
			return -1;
		}
	}
	return ctdb_queue_send(client->queue, (uint8_t *)hdr, hdr->length);
}

/*
  message handler for when we are in daemon mode. This redirects the message
  to the right client
 */
static void daemon_message_handler(struct ctdb_context *ctdb, uint64_t srvid, 
				    TDB_DATA data, void *private_data)
{
	struct ctdb_client *client = talloc_get_type(private_data, struct ctdb_client);
	struct ctdb_req_message *r;
	int len;

	/* construct a message to send to the client containing the data */
	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdbd_allocate_pkt(ctdb, ctdb, CTDB_REQ_MESSAGE, 
			       len, struct ctdb_req_message);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	talloc_set_name_const(r, "req_message packet");

	r->srvid         = srvid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);

	daemon_queue_send(client, &r->hdr);

	talloc_free(r);
}

/*
  this is called when the ctdb daemon received a ctdb request to 
  set the srvid from the client
 */
int daemon_register_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	int res;
	if (client == NULL) {
		DEBUG(DEBUG_ERR,("Bad client_id in daemon_request_register_message_handler\n"));
		return -1;
	}
	res = ctdb_register_message_handler(ctdb, client, srvid, daemon_message_handler, client);
	if (res != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to register handler %llu in daemon\n", 
			 (unsigned long long)srvid));
	} else {
		DEBUG(DEBUG_INFO,(__location__ " Registered message handler for srvid=%llu\n", 
			 (unsigned long long)srvid));
	}

	return res;
}

/*
  this is called when the ctdb daemon received a ctdb request to 
  remove a srvid from the client
 */
int daemon_deregister_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	if (client == NULL) {
		DEBUG(DEBUG_ERR,("Bad client_id in daemon_request_deregister_message_handler\n"));
		return -1;
	}
	return ctdb_deregister_message_handler(ctdb, srvid, client);
}

int daemon_check_srvids(struct ctdb_context *ctdb, TDB_DATA indata,
			TDB_DATA *outdata)
{
	uint64_t *ids;
	int i, num_ids;
	uint8_t *results;

	if ((indata.dsize % sizeof(uint64_t)) != 0) {
		DEBUG(DEBUG_ERR, ("Bad indata in daemon_check_srvids, "
				  "size=%d\n", (int)indata.dsize));
		return -1;
	}

	ids = (uint64_t *)indata.dptr;
	num_ids = indata.dsize / 8;

	results = talloc_zero_array(outdata, uint8_t, (num_ids+7)/8);
	if (results == NULL) {
		DEBUG(DEBUG_ERR, ("talloc failed in daemon_check_srvids\n"));
		return -1;
	}
	for (i=0; i<num_ids; i++) {
		if (ctdb_check_message_handler(ctdb, ids[i])) {
			results[i/8] |= (1 << (i%8));
		}
	}
	outdata->dptr = (uint8_t *)results;
	outdata->dsize = talloc_get_size(results);
	return 0;
}

/*
  destroy a ctdb_client
*/
static int ctdb_client_destructor(struct ctdb_client *client)
{
	struct ctdb_db_context *ctdb_db;

	ctdb_takeover_client_destructor_hook(client);
	ctdb_reqid_remove(client->ctdb, client->client_id);
	client->ctdb->num_clients--;

	if (client->num_persistent_updates != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Client disconnecting with %u persistent updates in flight. Starting recovery\n", client->num_persistent_updates));
		client->ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	}
	ctdb_db = find_ctdb_db(client->ctdb, client->db_id);
	if (ctdb_db) {
		DEBUG(DEBUG_ERR, (__location__ " client exit while transaction "
				  "commit active. Forcing recovery.\n"));
		client->ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;

		/*
		 * trans3 transaction state:
		 *
		 * The destructor sets the pointer to NULL.
		 */
		talloc_free(ctdb_db->persistent_state);
	}

	return 0;
}


/*
  this is called when the ctdb daemon received a ctdb request message
  from a local client over the unix domain socket
 */
static void daemon_request_message_from_client(struct ctdb_client *client, 
					       struct ctdb_req_message *c)
{
	TDB_DATA data;
	int res;

	if (c->hdr.destnode == CTDB_CURRENT_NODE) {
		c->hdr.destnode = ctdb_get_pnn(client->ctdb);
	}

	/* maybe the message is for another client on this node */
	if (ctdb_get_pnn(client->ctdb)==c->hdr.destnode) {
		ctdb_request_message(client->ctdb, (struct ctdb_req_header *)c);
		return;
	}

	/* its for a remote node */
	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	res = ctdb_daemon_send_message(client->ctdb, c->hdr.destnode,
				       c->srvid, data);
	if (res != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to send message to remote node %u\n",
			 c->hdr.destnode));
	}
}


struct daemon_call_state {
	struct ctdb_client *client;
	uint32_t reqid;
	struct ctdb_call *call;
	struct timeval start_time;

	/* readonly request ? */
	uint32_t readonly_fetch;
	uint32_t client_callid;
};

/* 
   complete a call from a client 
*/
static void daemon_call_from_client_callback(struct ctdb_call_state *state)
{
	struct daemon_call_state *dstate = talloc_get_type(state->async.private_data, 
							   struct daemon_call_state);
	struct ctdb_reply_call *r;
	int res;
	uint32_t length;
	struct ctdb_client *client = dstate->client;
	struct ctdb_db_context *ctdb_db = state->ctdb_db;

	talloc_steal(client, dstate);
	talloc_steal(dstate, dstate->call);

	res = ctdb_daemon_call_recv(state, dstate->call);
	if (res != 0) {
		DEBUG(DEBUG_ERR, (__location__ " ctdbd_call_recv() returned error\n"));
		CTDB_DECREMENT_STAT(client->ctdb, pending_calls);

		CTDB_UPDATE_LATENCY(client->ctdb, ctdb_db, "call_from_client_cb 1", call_latency, dstate->start_time);
		return;
	}

	length = offsetof(struct ctdb_reply_call, data) + dstate->call->reply_data.dsize;
	/* If the client asked for readonly FETCH, we remapped this to 
	   FETCH_WITH_HEADER when calling the daemon. So we must
	   strip the extra header off the reply data before passing
	   it back to the client.
	*/
	if (dstate->readonly_fetch
	&& dstate->client_callid == CTDB_FETCH_FUNC) {
		length -= sizeof(struct ctdb_ltdb_header);
	}

	r = ctdbd_allocate_pkt(client->ctdb, dstate, CTDB_REPLY_CALL, 
			       length, struct ctdb_reply_call);
	if (r == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to allocate reply_call in ctdb daemon\n"));
		CTDB_DECREMENT_STAT(client->ctdb, pending_calls);
		CTDB_UPDATE_LATENCY(client->ctdb, ctdb_db, "call_from_client_cb 2", call_latency, dstate->start_time);
		return;
	}
	r->hdr.reqid        = dstate->reqid;
	r->status           = dstate->call->status;

	if (dstate->readonly_fetch
	&& dstate->client_callid == CTDB_FETCH_FUNC) {
		/* client only asked for a FETCH so we must strip off
		   the extra ctdb_ltdb header
		*/
		r->datalen          = dstate->call->reply_data.dsize - sizeof(struct ctdb_ltdb_header);
		memcpy(&r->data[0], dstate->call->reply_data.dptr + sizeof(struct ctdb_ltdb_header), r->datalen);
	} else {
		r->datalen          = dstate->call->reply_data.dsize;
		memcpy(&r->data[0], dstate->call->reply_data.dptr, r->datalen);
	}

	res = daemon_queue_send(client, &r->hdr);
	if (res == -1) {
		/* client is dead - return immediately */
		return;
	}
	if (res != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to queue packet from daemon to client\n"));
	}
	CTDB_UPDATE_LATENCY(client->ctdb, ctdb_db, "call_from_client_cb 3", call_latency, dstate->start_time);
	CTDB_DECREMENT_STAT(client->ctdb, pending_calls);
	talloc_free(dstate);
}

struct ctdb_daemon_packet_wrap {
	struct ctdb_context *ctdb;
	uint32_t client_id;
};

/*
  a wrapper to catch disconnected clients
 */
static void daemon_incoming_packet_wrap(void *p, struct ctdb_req_header *hdr)
{
	struct ctdb_client *client;
	struct ctdb_daemon_packet_wrap *w = talloc_get_type(p, 
							    struct ctdb_daemon_packet_wrap);
	if (w == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Bad packet type '%s'\n", talloc_get_name(p)));
		return;
	}

	client = ctdb_reqid_find(w->ctdb, w->client_id, struct ctdb_client);
	if (client == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Packet for disconnected client %u\n",
			 w->client_id));
		talloc_free(w);
		return;
	}
	talloc_free(w);

	/* process it */
	daemon_incoming_packet(client, hdr);	
}

struct ctdb_deferred_fetch_call {
	struct ctdb_deferred_fetch_call *next, *prev;
	struct ctdb_req_call *c;
	struct ctdb_daemon_packet_wrap *w;
};

struct ctdb_deferred_fetch_queue {
	struct ctdb_deferred_fetch_call *deferred_calls;
};

struct ctdb_deferred_requeue {
	struct ctdb_deferred_fetch_call *dfc;
	struct ctdb_client *client;
};

/* called from a timer event and starts reprocessing the deferred call.*/
static void reprocess_deferred_call(struct event_context *ev, struct timed_event *te, 
				       struct timeval t, void *private_data)
{
	struct ctdb_deferred_requeue *dfr = (struct ctdb_deferred_requeue *)private_data;
	struct ctdb_client *client = dfr->client;

	talloc_steal(client, dfr->dfc->c);
	daemon_incoming_packet(client, (struct ctdb_req_header *)dfr->dfc->c);
	talloc_free(dfr);
}

/* the referral context is destroyed either after a timeout or when the initial
   fetch-lock has finished.
   at this stage, immediately start reprocessing the queued up deferred
   calls so they get reprocessed immediately (and since we are dmaster at
   this stage, trigger the waiting smbd processes to pick up and aquire the
   record right away.
*/
static int deferred_fetch_queue_destructor(struct ctdb_deferred_fetch_queue *dfq)
{

	/* need to reprocess the packets from the queue explicitely instead of
	   just using a normal destructor since we want, need, to
	   call the clients in the same oder as the requests queued up
	*/
	while (dfq->deferred_calls != NULL) {
		struct ctdb_client *client;
		struct ctdb_deferred_fetch_call *dfc = dfq->deferred_calls;
		struct ctdb_deferred_requeue *dfr;

		DLIST_REMOVE(dfq->deferred_calls, dfc);

		client = ctdb_reqid_find(dfc->w->ctdb, dfc->w->client_id, struct ctdb_client);
		if (client == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Packet for disconnected client %u\n",
				 dfc->w->client_id));
			continue;
		}

		/* process it by pushing it back onto the eventloop */
		dfr = talloc(client, struct ctdb_deferred_requeue);
		if (dfr == NULL) {
			DEBUG(DEBUG_ERR,("Failed to allocate deferred fetch requeue structure\n"));
			continue;
		}

		dfr->dfc    = talloc_steal(dfr, dfc);
		dfr->client = client;

		event_add_timed(dfc->w->ctdb->ev, client, timeval_zero(), reprocess_deferred_call, dfr);
	}

	return 0;
}

/* insert the new deferral context into the rb tree.
   there should never be a pre-existing context here, but check for it
   warn and destroy the previous context if there is already a deferral context
   for this key.
*/
static void *insert_dfq_callback(void *parm, void *data)
{
        if (data) {
		DEBUG(DEBUG_ERR,("Already have DFQ registered. Free old %p and create new %p\n", data, parm));
                talloc_free(data);
        }
        return parm;
}

/* if the original fetch-lock did not complete within a reasonable time,
   free the context and context for all deferred requests to cause them to be
   re-inserted into the event system.
*/
static void dfq_timeout(struct event_context *ev, struct timed_event *te, 
				  struct timeval t, void *private_data)
{
	talloc_free(private_data);
}

/* This function is used in the local daemon to register a KEY in a database
   for being "fetched"
   While the remote fetch is in-flight, any futher attempts to re-fetch the
   same record will be deferred until the fetch completes.
*/
static int setup_deferred_fetch_locks(struct ctdb_db_context *ctdb_db, struct ctdb_call *call)
{
	uint32_t *k;
	struct ctdb_deferred_fetch_queue *dfq;

	k = ctdb_key_to_idkey(call, call->key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for deferred fetch\n"));
		return -1;
	}

	dfq  = talloc(call, struct ctdb_deferred_fetch_queue);
	if (dfq == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for deferred fetch queue structure\n"));
		talloc_free(k);
		return -1;
	}
	dfq->deferred_calls = NULL;

	trbt_insertarray32_callback(ctdb_db->deferred_fetch, k[0], &k[0], insert_dfq_callback, dfq);

	talloc_set_destructor(dfq, deferred_fetch_queue_destructor);

	/* if the fetch havent completed in 30 seconds, just tear it all down
	   and let it try again as the events are reissued */
	event_add_timed(ctdb_db->ctdb->ev, dfq, timeval_current_ofs(30, 0), dfq_timeout, dfq);

	talloc_free(k);
	return 0;
}

/* check if this is a duplicate request to a fetch already in-flight
   if it is, make this call deferred to be reprocessed later when
   the in-flight fetch completes.
*/
static int requeue_duplicate_fetch(struct ctdb_db_context *ctdb_db, struct ctdb_client *client, TDB_DATA key, struct ctdb_req_call *c)
{
	uint32_t *k;
	struct ctdb_deferred_fetch_queue *dfq;
	struct ctdb_deferred_fetch_call *dfc;

	k = ctdb_key_to_idkey(c, key);
	if (k == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate key for deferred fetch\n"));
		return -1;
	}

	dfq = trbt_lookuparray32(ctdb_db->deferred_fetch, k[0], &k[0]);
	if (dfq == NULL) {
		talloc_free(k);
		return -1;
	}


	talloc_free(k);

	dfc = talloc(dfq, struct ctdb_deferred_fetch_call);
	if (dfc == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate deferred fetch call structure\n"));
		return -1;
	}

	dfc->w = talloc(dfc, struct ctdb_daemon_packet_wrap);
	if (dfc->w == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate deferred fetch daemon packet wrap structure\n"));
		talloc_free(dfc);
		return -1;
	}

	dfc->c = talloc_steal(dfc, c);
	dfc->w->ctdb = ctdb_db->ctdb;
	dfc->w->client_id = client->client_id;

	DLIST_ADD_END(dfq->deferred_calls, dfc, NULL);

	return 0;
}


/*
  this is called when the ctdb daemon received a ctdb request call
  from a local client over the unix domain socket
 */
static void daemon_request_call_from_client(struct ctdb_client *client, 
					    struct ctdb_req_call *c)
{
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db;
	struct daemon_call_state *dstate;
	struct ctdb_call *call;
	struct ctdb_ltdb_header header;
	TDB_DATA key, data;
	int ret;
	struct ctdb_context *ctdb = client->ctdb;
	struct ctdb_daemon_packet_wrap *w;

	CTDB_INCREMENT_STAT(ctdb, total_calls);
	CTDB_INCREMENT_STAT(ctdb, pending_calls);

	ctdb_db = find_ctdb_db(client->ctdb, c->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR, (__location__ " Unknown database in request. db_id==0x%08x",
			  c->db_id));
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		return;
	}

	if (ctdb_db->unhealthy_reason) {
		/*
		 * this is just a warning, as the tdb should be empty anyway,
		 * and only persistent databases can be unhealthy, which doesn't
		 * use this code patch
		 */
		DEBUG(DEBUG_WARNING,("warn: db(%s) unhealty in daemon_request_call_from_client(): %s\n",
				     ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	key.dptr = c->data;
	key.dsize = c->keylen;

	w = talloc(ctdb, struct ctdb_daemon_packet_wrap);
	CTDB_NO_MEMORY_VOID(ctdb, w);	

	w->ctdb = ctdb;
	w->client_id = client->client_id;

	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, key, &header, 
					   (struct ctdb_req_header *)c, &data,
					   daemon_incoming_packet_wrap, w, true);
	if (ret == -2) {
		/* will retry later */
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		return;
	}

	talloc_free(w);

	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to fetch record\n"));
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		return;
	}


	/* check if this fetch request is a duplicate for a
	   request we already have in flight. If so defer it until
	   the first request completes.
	*/
	if (ctdb->tunable.fetch_collapse == 1) {
		if (requeue_duplicate_fetch(ctdb_db, client, key, c) == 0) {
			ret = ctdb_ltdb_unlock(ctdb_db, key);
			if (ret != 0) {
				DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
			}
			CTDB_DECREMENT_STAT(ctdb, pending_calls);
			return;
		}
	}

	/* Dont do READONLY if we dont have a tracking database */
	if ((c->flags & CTDB_WANT_READONLY) && !ctdb_db->readonly) {
		c->flags &= ~CTDB_WANT_READONLY;
	}

	if (header.flags & CTDB_REC_RO_REVOKE_COMPLETE) {
		header.flags &= ~CTDB_REC_RO_FLAGS;
		CTDB_INCREMENT_STAT(ctdb, total_ro_revokes);
		CTDB_INCREMENT_DB_STAT(ctdb_db, db_ro_revokes);
		if (ctdb_ltdb_store(ctdb_db, key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to write header with cleared REVOKE flag");
		}
		/* and clear out the tracking data */
		if (tdb_delete(ctdb_db->rottdb, key) != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to clear out trackingdb record\n"));
		}
	}

	/* if we are revoking, we must defer all other calls until the revoke
	 * had completed.
	 */
	if (header.flags & CTDB_REC_RO_REVOKING_READONLY) {
		talloc_free(data.dptr);
		ret = ctdb_ltdb_unlock(ctdb_db, key);

		if (ctdb_add_revoke_deferred_call(ctdb, ctdb_db, key, (struct ctdb_req_header *)c, daemon_incoming_packet, client) != 0) {
			ctdb_fatal(ctdb, "Failed to add deferred call for revoke child");
		}
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		return;
	}

	if ((header.dmaster == ctdb->pnn)
	&& (!(c->flags & CTDB_WANT_READONLY))
	&& (header.flags & (CTDB_REC_RO_HAVE_DELEGATIONS|CTDB_REC_RO_HAVE_READONLY)) ) {
		header.flags   |= CTDB_REC_RO_REVOKING_READONLY;
		if (ctdb_ltdb_store(ctdb_db, key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to store record with HAVE_DELEGATIONS set");
		}
		ret = ctdb_ltdb_unlock(ctdb_db, key);

		if (ctdb_start_revoke_ro_record(ctdb, ctdb_db, key, &header, data) != 0) {
			ctdb_fatal(ctdb, "Failed to start record revoke");
		}
		talloc_free(data.dptr);

		if (ctdb_add_revoke_deferred_call(ctdb, ctdb_db, key, (struct ctdb_req_header *)c, daemon_incoming_packet, client) != 0) {
			ctdb_fatal(ctdb, "Failed to add deferred call for revoke child");
		}

		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		return;
	}		

	dstate = talloc(client, struct daemon_call_state);
	if (dstate == NULL) {
		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}

		DEBUG(DEBUG_ERR,(__location__ " Unable to allocate dstate\n"));
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		return;
	}
	dstate->start_time = timeval_current();
	dstate->client = client;
	dstate->reqid  = c->hdr.reqid;
	talloc_steal(dstate, data.dptr);

	call = dstate->call = talloc_zero(dstate, struct ctdb_call);
	if (call == NULL) {
		ret = ctdb_ltdb_unlock(ctdb_db, key);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
		}

		DEBUG(DEBUG_ERR,(__location__ " Unable to allocate call\n"));
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		CTDB_UPDATE_LATENCY(ctdb, ctdb_db, "call_from_client 1", call_latency, dstate->start_time);
		return;
	}

	dstate->readonly_fetch = 0;
	call->call_id = c->callid;
	call->key = key;
	call->call_data.dptr = c->data + c->keylen;
	call->call_data.dsize = c->calldatalen;
	call->flags = c->flags;

	if (c->flags & CTDB_WANT_READONLY) {
		/* client wants readonly record, so translate this into a 
		   fetch with header. remember what the client asked for
		   so we can remap the reply back to the proper format for
		   the client in the reply
		 */
		dstate->client_callid = call->call_id;
		call->call_id = CTDB_FETCH_WITH_HEADER_FUNC;
		dstate->readonly_fetch = 1;
	}

	if (header.dmaster == ctdb->pnn) {
		state = ctdb_call_local_send(ctdb_db, call, &header, &data);
	} else {
		state = ctdb_daemon_call_send_remote(ctdb_db, call, &header);
		if (ctdb->tunable.fetch_collapse == 1) {
			/* This request triggered a remote fetch-lock.
			   set up a deferral for this key so any additional
			   fetch-locks are deferred until the current one
			   finishes.
			 */
			setup_deferred_fetch_locks(ctdb_db, call);
		}
	}

	ret = ctdb_ltdb_unlock(ctdb_db, key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ltdb_unlock() failed with error %d\n", ret));
	}

	if (state == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to setup call send\n"));
		CTDB_DECREMENT_STAT(ctdb, pending_calls);
		CTDB_UPDATE_LATENCY(ctdb, ctdb_db, "call_from_client 2", call_latency, dstate->start_time);
		return;
	}
	talloc_steal(state, dstate);
	talloc_steal(client, state);

	state->async.fn = daemon_call_from_client_callback;
	state->async.private_data = dstate;
}


static void daemon_request_control_from_client(struct ctdb_client *client, 
					       struct ctdb_req_control *c);

/* data contains a packet from the client */
static void daemon_incoming_packet(void *p, struct ctdb_req_header *hdr)
{
	struct ctdb_client *client = talloc_get_type(p, struct ctdb_client);
	TALLOC_CTX *tmp_ctx;
	struct ctdb_context *ctdb = client->ctdb;

	/* place the packet as a child of a tmp_ctx. We then use
	   talloc_free() below to free it. If any of the calls want
	   to keep it, then they will steal it somewhere else, and the
	   talloc_free() will be a no-op */
	tmp_ctx = talloc_new(client);
	talloc_steal(tmp_ctx, hdr);

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(client->ctdb, "Non CTDB packet rejected in daemon\n");
		goto done;
	}

	if (hdr->ctdb_version != CTDB_PROTOCOL) {
		ctdb_set_error(client->ctdb, "Bad CTDB version 0x%x rejected in daemon\n", hdr->ctdb_version);
		goto done;
	}

	switch (hdr->operation) {
	case CTDB_REQ_CALL:
		CTDB_INCREMENT_STAT(ctdb, client.req_call);
		daemon_request_call_from_client(client, (struct ctdb_req_call *)hdr);
		break;

	case CTDB_REQ_MESSAGE:
		CTDB_INCREMENT_STAT(ctdb, client.req_message);
		daemon_request_message_from_client(client, (struct ctdb_req_message *)hdr);
		break;

	case CTDB_REQ_CONTROL:
		CTDB_INCREMENT_STAT(ctdb, client.req_control);
		daemon_request_control_from_client(client, (struct ctdb_req_control *)hdr);
		break;

	default:
		DEBUG(DEBUG_CRIT,(__location__ " daemon: unrecognized operation %u\n",
			 hdr->operation));
	}

done:
	talloc_free(tmp_ctx);
}

/*
  called when the daemon gets a incoming packet
 */
static void ctdb_daemon_read_cb(uint8_t *data, size_t cnt, void *args)
{
	struct ctdb_client *client = talloc_get_type(args, struct ctdb_client);
	struct ctdb_req_header *hdr;

	if (cnt == 0) {
		talloc_free(client);
		return;
	}

	CTDB_INCREMENT_STAT(client->ctdb, client_packets_recv);

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(client->ctdb, "Bad packet length %u in daemon\n", 
			       (unsigned)cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(client->ctdb, "Bad header length %u expected %u\n in daemon", 
			       (unsigned)hdr->length, (unsigned)cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(client->ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_PROTOCOL) {
		ctdb_set_error(client->ctdb, "Bad CTDB version 0x%x rejected in daemon\n", hdr->ctdb_version);
		return;
	}

	DEBUG(DEBUG_DEBUG,(__location__ " client request %u of type %u length %u from "
		 "node %u to %u\n", hdr->reqid, hdr->operation, hdr->length,
		 hdr->srcnode, hdr->destnode));

	/* it is the responsibility of the incoming packet function to free 'data' */
	daemon_incoming_packet(client, hdr);
}


static int ctdb_clientpid_destructor(struct ctdb_client_pid_list *client_pid)
{
	if (client_pid->ctdb->client_pids != NULL) {
		DLIST_REMOVE(client_pid->ctdb->client_pids, client_pid);
	}

	return 0;
}


static void ctdb_accept_client(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private_data)
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	struct ctdb_client *client;
	struct ctdb_client_pid_list *client_pid;
	pid_t peer_pid = 0;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctdb->daemon.sd, (struct sockaddr *)&addr, &len);
	if (fd == -1) {
		return;
	}

	set_nonblocking(fd);
	set_close_on_exec(fd);

	DEBUG(DEBUG_DEBUG,(__location__ " Created SOCKET FD:%d to connected child\n", fd));

	client = talloc_zero(ctdb, struct ctdb_client);
	if (ctdb_get_peer_pid(fd, &peer_pid) == 0) {
		DEBUG(DEBUG_INFO,("Connected client with pid:%u\n", (unsigned)peer_pid));
	}

	client->ctdb = ctdb;
	client->fd = fd;
	client->client_id = ctdb_reqid_new(ctdb, client);
	client->pid = peer_pid;

	client_pid = talloc(client, struct ctdb_client_pid_list);
	if (client_pid == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate client pid structure\n"));
		close(fd);
		talloc_free(client);
		return;
	}		
	client_pid->ctdb   = ctdb;
	client_pid->pid    = peer_pid;
	client_pid->client = client;

	DLIST_ADD(ctdb->client_pids, client_pid);

	client->queue = ctdb_queue_setup(ctdb, client, fd, CTDB_DS_ALIGNMENT, 
					 ctdb_daemon_read_cb, client,
					 "client-%u", client->pid);

	talloc_set_destructor(client, ctdb_client_destructor);
	talloc_set_destructor(client_pid, ctdb_clientpid_destructor);
	ctdb->num_clients++;
}



/*
  create a unix domain socket and bind it
  return a file descriptor open on the socket 
*/
static int ux_socket_bind(struct ctdb_context *ctdb)
{
	struct sockaddr_un addr;

	ctdb->daemon.sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->daemon.sd == -1) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ctdb->daemon.name, sizeof(addr.sun_path)-1);

	/* First check if an old ctdbd might be running */
	if (connect(ctdb->daemon.sd,
		    (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		DEBUG(DEBUG_CRIT,
		      ("Something is already listening on ctdb socket '%s'\n",
		       ctdb->daemon.name));
		goto failed;
	}

	/* Remove any old socket */
	unlink(ctdb->daemon.name);

	set_close_on_exec(ctdb->daemon.sd);
	set_nonblocking(ctdb->daemon.sd);

	if (bind(ctdb->daemon.sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to bind on ctdb socket '%s'\n", ctdb->daemon.name));
		goto failed;
	}

	if (chown(ctdb->daemon.name, geteuid(), getegid()) != 0 ||
	    chmod(ctdb->daemon.name, 0700) != 0) {
		DEBUG(DEBUG_CRIT,("Unable to secure ctdb socket '%s', ctdb->daemon.name\n", ctdb->daemon.name));
		goto failed;
	}


	if (listen(ctdb->daemon.sd, 100) != 0) {
		DEBUG(DEBUG_CRIT,("Unable to listen on ctdb socket '%s'\n", ctdb->daemon.name));
		goto failed;
	}

	return 0;

failed:
	close(ctdb->daemon.sd);
	ctdb->daemon.sd = -1;
	return -1;	
}

static void initialise_node_flags (struct ctdb_context *ctdb)
{
	if (ctdb->pnn == -1) {
		ctdb_fatal(ctdb, "PNN is set to -1 (unknown value)");
	}

	ctdb->nodes[ctdb->pnn]->flags &= ~NODE_FLAGS_DISCONNECTED;

	/* do we start out in DISABLED mode? */
	if (ctdb->start_as_disabled != 0) {
		DEBUG(DEBUG_INFO, ("This node is configured to start in DISABLED state\n"));
		ctdb->nodes[ctdb->pnn]->flags |= NODE_FLAGS_DISABLED;
	}
	/* do we start out in STOPPED mode? */
	if (ctdb->start_as_stopped != 0) {
		DEBUG(DEBUG_INFO, ("This node is configured to start in STOPPED state\n"));
		ctdb->nodes[ctdb->pnn]->flags |= NODE_FLAGS_STOPPED;
	}
}

static void ctdb_setup_event_callback(struct ctdb_context *ctdb, int status,
				      void *private_data)
{
	if (status != 0) {
		ctdb_die(ctdb, "Failed to run setup event");
	}
	ctdb_run_notification_script(ctdb, "setup");

	/* tell all other nodes we've just started up */
	ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL,
				 0, CTDB_CONTROL_STARTUP, 0,
				 CTDB_CTRL_FLAG_NOREPLY,
				 tdb_null, NULL, NULL);

	/* Start the recovery daemon */
	if (ctdb_start_recoverd(ctdb) != 0) {
		DEBUG(DEBUG_ALERT,("Failed to start recovery daemon\n"));
		exit(11);
	}

	ctdb_start_periodic_events(ctdb);

	ctdb_wait_for_first_recovery(ctdb);
}

static struct timeval tevent_before_wait_ts;
static struct timeval tevent_after_wait_ts;

static void ctdb_tevent_trace(enum tevent_trace_point tp,
			      void *private_data)
{
	struct timeval diff;
	struct timeval now;
	struct ctdb_context *ctdb =
		talloc_get_type(private_data, struct ctdb_context);

	if (getpid() != ctdb->ctdbd_pid) {
		return;
	}

	now = timeval_current();

	switch (tp) {
	case TEVENT_TRACE_BEFORE_WAIT:
		if (!timeval_is_zero(&tevent_after_wait_ts)) {
			diff = timeval_until(&tevent_after_wait_ts, &now);
			if (diff.tv_sec > 3) {
				DEBUG(DEBUG_ERR,
				      ("Handling event took %ld seconds!\n",
				       diff.tv_sec));
			}
		}
		tevent_before_wait_ts = now;
		break;

	case TEVENT_TRACE_AFTER_WAIT:
		if (!timeval_is_zero(&tevent_before_wait_ts)) {
			diff = timeval_until(&tevent_before_wait_ts, &now);
			if (diff.tv_sec > 3) {
				DEBUG(DEBUG_CRIT,
				      ("No event for %ld seconds!\n",
				       diff.tv_sec));
			}
		}
		tevent_after_wait_ts = now;
		break;

	default:
		/* Do nothing for future tevent trace points */ ;
	}
}

static void ctdb_remove_pidfile(void)
{
	/* Only the main ctdbd's PID matches the SID */
	if (ctdbd_pidfile != NULL && getsid(0) == getpid()) {
		if (unlink(ctdbd_pidfile) == 0) {
			DEBUG(DEBUG_NOTICE, ("Removed PID file %s\n",
					     ctdbd_pidfile));
		} else {
			DEBUG(DEBUG_WARNING, ("Failed to Remove PID file %s\n",
					      ctdbd_pidfile));
		}
	}
}

static void ctdb_create_pidfile(pid_t pid)
{
	if (ctdbd_pidfile != NULL) {
		FILE *fp;

		fp = fopen(ctdbd_pidfile, "w");
		if (fp == NULL) {
			DEBUG(DEBUG_ALERT,
			      ("Failed to open PID file %s\n", ctdbd_pidfile));
			exit(11);
		}

		fprintf(fp, "%d\n", pid);
		fclose(fp);
		DEBUG(DEBUG_NOTICE, ("Created PID file %s\n", ctdbd_pidfile));
		atexit(ctdb_remove_pidfile);
	}
}

/*
  start the protocol going as a daemon
*/
int ctdb_start_daemon(struct ctdb_context *ctdb, bool do_fork, bool use_syslog)
{
	int res, ret = -1;
	struct fd_event *fde;
	const char *domain_socket_name;

	/* create a unix domain stream socket to listen to */
	res = ux_socket_bind(ctdb);
	if (res!=0) {
		DEBUG(DEBUG_ALERT,("Cannot continue.  Exiting!\n"));
		exit(10);
	}

	if (do_fork && fork()) {
		return 0;
	}

	tdb_reopen_all(false);

	if (do_fork) {
		if (setsid() == -1) {
			ctdb_die(ctdb, "Failed to setsid()\n");
		}
		close(0);
		if (open("/dev/null", O_RDONLY) != 0) {
			DEBUG(DEBUG_ALERT,(__location__ " Failed to setup stdin on /dev/null\n"));
			exit(11);
		}
	}
	ignore_signal(SIGPIPE);

	ctdb->ctdbd_pid = getpid();
	DEBUG(DEBUG_ERR, ("Starting CTDBD (Version %s) as PID: %u\n",
			  CTDB_VERSION_STRING, ctdb->ctdbd_pid));
	ctdb_create_pidfile(ctdb->ctdbd_pid);

	/* Make sure we log something when the daemon terminates.
	 * This must be the first exit handler to run (so the last to
	 * be registered.
	 */
	atexit(print_exit_message);

	if (ctdb->do_setsched) {
		/* try to set us up as realtime */
		if (!set_scheduler()) {
			exit(1);
		}
		DEBUG(DEBUG_NOTICE, ("Set real-time scheduler priority\n"));
	}

	/* ensure the socket is deleted on exit of the daemon */
	domain_socket_name = talloc_strdup(talloc_autofree_context(), ctdb->daemon.name);
	if (domain_socket_name == NULL) {
		DEBUG(DEBUG_ALERT,(__location__ " talloc_strdup failed.\n"));
		exit(12);
	}

	ctdb->ev = event_context_init(NULL);
	tevent_loop_allow_nesting(ctdb->ev);
	tevent_set_trace_callback(ctdb->ev, ctdb_tevent_trace, ctdb);
	ret = ctdb_init_tevent_logging(ctdb);
	if (ret != 0) {
		DEBUG(DEBUG_ALERT,("Failed to initialize TEVENT logging\n"));
		exit(1);
	}

	/* set up a handler to pick up sigchld */
	if (ctdb_init_sigchld(ctdb) == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to set up signal handler for SIGCHLD\n"));
		exit(1);
	}

	ctdb_set_child_logging(ctdb);
	if (use_syslog) {
		if (start_syslog_daemon(ctdb)) {
			DEBUG(DEBUG_CRIT, ("Failed to start syslog daemon\n"));
			exit(10);
		}
	}

	/* initialize statistics collection */
	ctdb_statistics_init(ctdb);

	/* force initial recovery for election */
	ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;

	ctdb_set_runstate(ctdb, CTDB_RUNSTATE_INIT);
	ret = ctdb_event_script(ctdb, CTDB_EVENT_INIT);
	if (ret != 0) {
		ctdb_die(ctdb, "Failed to run init event\n");
	}
	ctdb_run_notification_script(ctdb, "init");

	if (strcmp(ctdb->transport, "tcp") == 0) {
		ret = ctdb_tcp_init(ctdb);
	}
#ifdef USE_INFINIBAND
	if (strcmp(ctdb->transport, "ib") == 0) {
		ret = ctdb_ibw_init(ctdb);
	}
#endif
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to initialise transport '%s'\n", ctdb->transport));
		return -1;
	}

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_ALERT,(__location__ " Can not initialize transport. ctdb->methods is NULL\n"));
		ctdb_fatal(ctdb, "transport is unavailable. can not initialize.");
	}

	/* initialise the transport  */
	if (ctdb->methods->initialise(ctdb) != 0) {
		ctdb_fatal(ctdb, "transport failed to initialise");
	}

	initialise_node_flags(ctdb);

	if (ctdb->public_addresses_file) {
		ret = ctdb_set_public_addresses(ctdb, true);
		if (ret == -1) {
			DEBUG(DEBUG_ALERT,("Unable to setup public address list\n"));
			exit(1);
		}
		if (ctdb->do_checkpublicip) {
			ctdb_start_monitoring_interfaces(ctdb);
		}
	}


	/* attach to existing databases */
	if (ctdb_attach_databases(ctdb) != 0) {
		ctdb_fatal(ctdb, "Failed to attach to databases\n");
	}

	/* start frozen, then let the first election sort things out */
	if (!ctdb_blocking_freeze(ctdb)) {
		ctdb_fatal(ctdb, "Failed to get initial freeze\n");
	}

	/* now start accepting clients, only can do this once frozen */
	fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, 
			   EVENT_FD_READ,
			   ctdb_accept_client, ctdb);
	if (fde == NULL) {
		ctdb_fatal(ctdb, "Failed to add daemon socket to event loop");
	}
	tevent_fd_set_auto_close(fde);

	/* release any IPs we hold from previous runs of the daemon */
	if (ctdb->tunable.disable_ip_failover == 0) {
		ctdb_release_all_ips(ctdb);
	}

	/* Start the transport */
	if (ctdb->methods->start(ctdb) != 0) {
		DEBUG(DEBUG_ALERT,("transport failed to start!\n"));
		ctdb_fatal(ctdb, "transport failed to start");
	}

	/* Recovery daemon and timed events are started from the
	 * callback, only after the setup event completes
	 * successfully.
	 */
	ctdb_set_runstate(ctdb, CTDB_RUNSTATE_SETUP);
	ret = ctdb_event_script_callback(ctdb,
					 ctdb,
					 ctdb_setup_event_callback,
					 ctdb,
					 CTDB_EVENT_SETUP,
					 "%s",
					 "");
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,("Failed to set up 'setup' event\n"));
		exit(1);
	}

	lockdown_memory(ctdb->valgrinding);

	/* go into a wait loop to allow other nodes to complete */
	event_loop_wait(ctdb->ev);

	DEBUG(DEBUG_CRIT,("event_loop_wait() returned. this should not happen\n"));
	exit(1);
}

/*
  allocate a packet for use in daemon<->daemon communication
 */
struct ctdb_req_header *_ctdb_transport_allocate(struct ctdb_context *ctdb,
						 TALLOC_CTX *mem_ctx, 
						 enum ctdb_operation operation, 
						 size_t length, size_t slength,
						 const char *type)
{
	int size;
	struct ctdb_req_header *hdr;

	length = MAX(length, slength);
	size = (length+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Unable to allocate transport packet for operation %u of length %u. Transport is DOWN.\n",
			 operation, (unsigned)length));
		return NULL;
	}

	hdr = (struct ctdb_req_header *)ctdb->methods->allocate_pkt(mem_ctx, size);
	if (hdr == NULL) {
		DEBUG(DEBUG_ERR,("Unable to allocate transport packet for operation %u of length %u\n",
			 operation, (unsigned)length));
		return NULL;
	}
	talloc_set_name_const(hdr, type);
	memset(hdr, 0, slength);
	hdr->length       = length;
	hdr->operation    = operation;
	hdr->ctdb_magic   = CTDB_MAGIC;
	hdr->ctdb_version = CTDB_PROTOCOL;
	hdr->generation   = ctdb->vnn_map->generation;
	hdr->srcnode      = ctdb->pnn;

	return hdr;	
}

struct daemon_control_state {
	struct daemon_control_state *next, *prev;
	struct ctdb_client *client;
	struct ctdb_req_control *c;
	uint32_t reqid;
	struct ctdb_node *node;
};

/*
  callback when a control reply comes in
 */
static void daemon_control_callback(struct ctdb_context *ctdb,
				    int32_t status, TDB_DATA data, 
				    const char *errormsg,
				    void *private_data)
{
	struct daemon_control_state *state = talloc_get_type(private_data, 
							     struct daemon_control_state);
	struct ctdb_client *client = state->client;
	struct ctdb_reply_control *r;
	size_t len;
	int ret;

	/* construct a message to send to the client containing the data */
	len = offsetof(struct ctdb_reply_control, data) + data.dsize;
	if (errormsg) {
		len += strlen(errormsg);
	}
	r = ctdbd_allocate_pkt(ctdb, state, CTDB_REPLY_CONTROL, len, 
			       struct ctdb_reply_control);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	r->hdr.reqid     = state->reqid;
	r->status        = status;
	r->datalen       = data.dsize;
	r->errorlen = 0;
	memcpy(&r->data[0], data.dptr, data.dsize);
	if (errormsg) {
		r->errorlen = strlen(errormsg);
		memcpy(&r->data[r->datalen], errormsg, r->errorlen);
	}

	ret = daemon_queue_send(client, &r->hdr);
	if (ret != -1) {
		talloc_free(state);
	}
}

/*
  fail all pending controls to a disconnected node
 */
void ctdb_daemon_cancel_controls(struct ctdb_context *ctdb, struct ctdb_node *node)
{
	struct daemon_control_state *state;
	while ((state = node->pending_controls)) {
		DLIST_REMOVE(node->pending_controls, state);
		daemon_control_callback(ctdb, (uint32_t)-1, tdb_null, 
					"node is disconnected", state);
	}
}

/*
  destroy a daemon_control_state
 */
static int daemon_control_destructor(struct daemon_control_state *state)
{
	if (state->node) {
		DLIST_REMOVE(state->node->pending_controls, state);
	}
	return 0;
}

/*
  this is called when the ctdb daemon received a ctdb request control
  from a local client over the unix domain socket
 */
static void daemon_request_control_from_client(struct ctdb_client *client, 
					       struct ctdb_req_control *c)
{
	TDB_DATA data;
	int res;
	struct daemon_control_state *state;
	TALLOC_CTX *tmp_ctx = talloc_new(client);

	if (c->hdr.destnode == CTDB_CURRENT_NODE) {
		c->hdr.destnode = client->ctdb->pnn;
	}

	state = talloc(client, struct daemon_control_state);
	CTDB_NO_MEMORY_VOID(client->ctdb, state);

	state->client = client;
	state->c = talloc_steal(state, c);
	state->reqid = c->hdr.reqid;
	if (ctdb_validate_pnn(client->ctdb, c->hdr.destnode)) {
		state->node = client->ctdb->nodes[c->hdr.destnode];
		DLIST_ADD(state->node->pending_controls, state);
	} else {
		state->node = NULL;
	}

	talloc_set_destructor(state, daemon_control_destructor);

	if (c->flags & CTDB_CTRL_FLAG_NOREPLY) {
		talloc_steal(tmp_ctx, state);
	}
	
	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	res = ctdb_daemon_send_control(client->ctdb, c->hdr.destnode,
				       c->srvid, c->opcode, client->client_id,
				       c->flags,
				       data, daemon_control_callback,
				       state);
	if (res != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to send control to remote node %u\n",
			 c->hdr.destnode));
	}

	talloc_free(tmp_ctx);
}

/*
  register a call function
*/
int ctdb_daemon_set_call(struct ctdb_context *ctdb, uint32_t db_id,
			 ctdb_fn_t fn, int id)
{
	struct ctdb_registered_call *call;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	call = talloc(ctdb_db, struct ctdb_registered_call);
	call->fn = fn;
	call->id = id;

	DLIST_ADD(ctdb_db->calls, call);	
	return 0;
}



/*
  this local messaging handler is ugly, but is needed to prevent
  recursion in ctdb_send_message() when the destination node is the
  same as the source node
 */
struct ctdb_local_message {
	struct ctdb_context *ctdb;
	uint64_t srvid;
	TDB_DATA data;
};

static void ctdb_local_message_trigger(struct event_context *ev, struct timed_event *te, 
				       struct timeval t, void *private_data)
{
	struct ctdb_local_message *m = talloc_get_type(private_data, 
						       struct ctdb_local_message);
	int res;

	res = ctdb_dispatch_message(m->ctdb, m->srvid, m->data);
	if (res != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to dispatch message for srvid=%llu\n", 
			  (unsigned long long)m->srvid));
	}
	talloc_free(m);
}

static int ctdb_local_message(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data)
{
	struct ctdb_local_message *m;
	m = talloc(ctdb, struct ctdb_local_message);
	CTDB_NO_MEMORY(ctdb, m);

	m->ctdb = ctdb;
	m->srvid = srvid;
	m->data  = data;
	m->data.dptr = talloc_memdup(m, m->data.dptr, m->data.dsize);
	if (m->data.dptr == NULL) {
		talloc_free(m);
		return -1;
	}

	/* this needs to be done as an event to prevent recursion */
	event_add_timed(ctdb->ev, m, timeval_zero(), ctdb_local_message_trigger, m);
	return 0;
}

/*
  send a ctdb message
*/
int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t pnn,
			     uint64_t srvid, TDB_DATA data)
{
	struct ctdb_req_message *r;
	int len;

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Failed to send message. Transport is DOWN\n"));
		return -1;
	}

	/* see if this is a message to ourselves */
	if (pnn == ctdb->pnn) {
		return ctdb_local_message(ctdb, srvid, data);
	}

	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_MESSAGE, len,
				    struct ctdb_req_message);
	CTDB_NO_MEMORY(ctdb, r);

	r->hdr.destnode  = pnn;
	r->srvid         = srvid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
	return 0;
}



struct ctdb_client_notify_list {
	struct ctdb_client_notify_list *next, *prev;
	struct ctdb_context *ctdb;
	uint64_t srvid;
	TDB_DATA data;
};


static int ctdb_client_notify_destructor(struct ctdb_client_notify_list *nl)
{
	int ret;

	DEBUG(DEBUG_ERR,("Sending client notify message for srvid:%llu\n", (unsigned long long)nl->srvid));

	ret = ctdb_daemon_send_message(nl->ctdb, CTDB_BROADCAST_CONNECTED, (unsigned long long)nl->srvid, nl->data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send client notify message\n"));
	}

	return 0;
}

int32_t ctdb_control_register_notify(struct ctdb_context *ctdb, uint32_t client_id, TDB_DATA indata)
{
	struct ctdb_client_notify_register *notify = (struct ctdb_client_notify_register *)indata.dptr;
        struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client); 
	struct ctdb_client_notify_list *nl;

	DEBUG(DEBUG_INFO,("Register srvid %llu for client %d\n", (unsigned long long)notify->srvid, client_id));

	if (indata.dsize < offsetof(struct ctdb_client_notify_register, notify_data)) {
		DEBUG(DEBUG_ERR,(__location__ " Too little data in control : %d\n", (int)indata.dsize));
		return -1;
	}

	if (indata.dsize != (notify->len + offsetof(struct ctdb_client_notify_register, notify_data))) {
		DEBUG(DEBUG_ERR,(__location__ " Wrong amount of data in control. Got %d, expected %d\n", (int)indata.dsize, (int)(notify->len + offsetof(struct ctdb_client_notify_register, notify_data))));
		return -1;
	}


        if (client == NULL) {
                DEBUG(DEBUG_ERR,(__location__ " Could not find client parent structure. You can not send this control to a remote node\n"));
                return -1;
        }

	for(nl=client->notify; nl; nl=nl->next) {
		if (nl->srvid == notify->srvid) {
			break;
		}
	}
	if (nl != NULL) {
                DEBUG(DEBUG_ERR,(__location__ " Notification for srvid:%llu already exists for this client\n", (unsigned long long)notify->srvid));
                return -1;
        }

	nl = talloc(client, struct ctdb_client_notify_list);
	CTDB_NO_MEMORY(ctdb, nl);
	nl->ctdb       = ctdb;
	nl->srvid      = notify->srvid;
	nl->data.dsize = notify->len;
	nl->data.dptr  = talloc_size(nl, nl->data.dsize);
	CTDB_NO_MEMORY(ctdb, nl->data.dptr);
	memcpy(nl->data.dptr, notify->notify_data, nl->data.dsize);
	
	DLIST_ADD(client->notify, nl);
	talloc_set_destructor(nl, ctdb_client_notify_destructor);

	return 0;
}

int32_t ctdb_control_deregister_notify(struct ctdb_context *ctdb, uint32_t client_id, TDB_DATA indata)
{
	struct ctdb_client_notify_deregister *notify = (struct ctdb_client_notify_deregister *)indata.dptr;
        struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client); 
	struct ctdb_client_notify_list *nl;

	DEBUG(DEBUG_INFO,("Deregister srvid %llu for client %d\n", (unsigned long long)notify->srvid, client_id));

        if (client == NULL) {
                DEBUG(DEBUG_ERR,(__location__ " Could not find client parent structure. You can not send this control to a remote node\n"));
                return -1;
        }

	for(nl=client->notify; nl; nl=nl->next) {
		if (nl->srvid == notify->srvid) {
			break;
		}
	}
	if (nl == NULL) {
                DEBUG(DEBUG_ERR,(__location__ " No notification for srvid:%llu found for this client\n", (unsigned long long)notify->srvid));
                return -1;
        }

	DLIST_REMOVE(client->notify, nl);
	talloc_set_destructor(nl, NULL);
	talloc_free(nl);

	return 0;
}

struct ctdb_client *ctdb_find_client_by_pid(struct ctdb_context *ctdb, pid_t pid)
{
	struct ctdb_client_pid_list *client_pid;

	for (client_pid = ctdb->client_pids; client_pid; client_pid=client_pid->next) {
		if (client_pid->pid == pid) {
			return client_pid->client;
		}
	}
	return NULL;
}


/* This control is used by samba when probing if a process (of a samba daemon)
   exists on the node.
   Samba does this when it needs/wants to check if a subrecord in one of the
   databases is still valied, or if it is stale and can be removed.
   If the node is in unhealthy or stopped state we just kill of the samba
   process holding htis sub-record and return to the calling samba that
   the process does not exist.
   This allows us to forcefully recall subrecords registered by samba processes
   on banned and stopped nodes.
*/
int32_t ctdb_control_process_exists(struct ctdb_context *ctdb, pid_t pid)
{
        struct ctdb_client *client;

	if (ctdb->nodes[ctdb->pnn]->flags & (NODE_FLAGS_BANNED|NODE_FLAGS_STOPPED)) {
		client = ctdb_find_client_by_pid(ctdb, pid);
		if (client != NULL) {
			DEBUG(DEBUG_NOTICE,(__location__ " Killing client with pid:%d on banned/stopped node\n", (int)pid));
			talloc_free(client);
		}
		return -1;
	}

	return kill(pid, 0);
}

void ctdb_shutdown_sequence(struct ctdb_context *ctdb, int exit_code)
{
	if (ctdb->runstate == CTDB_RUNSTATE_SHUTDOWN) {
		DEBUG(DEBUG_NOTICE,("Already shutting down so will not proceed.\n"));
		return;
	}

	DEBUG(DEBUG_NOTICE,("Shutdown sequence commencing.\n"));
	ctdb_set_runstate(ctdb, CTDB_RUNSTATE_SHUTDOWN);
	ctdb_stop_recoverd(ctdb);
	ctdb_stop_keepalive(ctdb);
	ctdb_stop_monitoring(ctdb);
	ctdb_release_all_ips(ctdb);
	ctdb_event_script(ctdb, CTDB_EVENT_SHUTDOWN);
	if (ctdb->methods != NULL) {
		ctdb->methods->shutdown(ctdb);
	}

	DEBUG(DEBUG_NOTICE,("Shutdown sequence complete, exiting.\n"));
	exit(exit_code);
}
