/*
   ctdb database library

   Copyright (C) Ronnie sahlberg 2010
   Copyright (C) Rusty Russell 2010

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

#ifndef _CTDB_H
#define _CTDB_H
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <tdb.h>

/* All *_send() functions are guaranteed to be non-blocking and fully
 * asynchronous.  The non-_send variants are synchronous. */

/*
 * Connect to ctdb using the specified domain socket.
 * Returns a ctdb context if successful or NULL.
 *
 * Use ctdb_free() to release the returned ctdb_connection when finished.
 */
struct ctdb_connection *ctdb_connect(const char *addr);

int ctdb_get_fd(struct ctdb_connection *ctdb);

int ctdb_which_events(struct ctdb_connection *ctdb);

int ctdb_service(struct ctdb_connection *ctdb, int revents);

struct ctdb_request;

void ctdb_request_free(struct ctdb_request *req);

/*
 * Callback for completed requests: it would normally unpack the request
 * using ctdb_*_recv().  You must free the request using ctdb_request_free().
 *
 * Note that due to macro magic, your callback doesn't have to take void *,
 * it can take a type which matches the actual private parameter.
 */
typedef void (*ctdb_callback_t)(struct ctdb_connection *ctdb,
				struct ctdb_request *req, void *private);

/*
 * Special node addresses :
 */
/* used on the domain socket, send a pdu to the local daemon */
#define CTDB_CURRENT_NODE     0xF0000001
/* send a broadcast to all nodes in the cluster, active or not */
#define CTDB_BROADCAST_ALL    0xF0000002
/* send a broadcast to all nodes in the current vnn map */
#define CTDB_BROADCAST_VNNMAP 0xF0000003
/* send a broadcast to all connected nodes */
#define CTDB_BROADCAST_CONNECTED 0xF0000004


/*
 * functions to attach to a database
 * if the database does not exist it will be created.
 *
 * You have to free the handle with ctdb_detach_db() when finished with it.
 */
struct ctdb_db;

struct ctdb_request *
ctdb_attachdb_send(struct ctdb_connection *ctdb,
		   const char *name, int persistent, uint32_t tdb_flags,
		   ctdb_callback_t callback, void *private_data);

struct ctdb_db *ctdb_attachdb_recv(struct ctdb_request *req);

struct ctdb_db *ctdb_attachdb(struct ctdb_connection *ctdb,
			      const char *name, int persistent,
			      uint32_t tdb_flags);

struct ctdb_lock;

/*
 * functions to read a record from the database
 * when the callback is invoked, the client will hold an exclusive lock
 * on the record, the client MUST NOT block during holding this lock and MUST
 * release it quickly by performing ctdb_release_lock(lock).
 *
 * When the lock is released, data is freed too, so make sure to copy the data
 * before that.
 *
 * This returns true on success, and req will be non-NULL if a request was
 * actually sent, otherwise callback will have already been called.
 */
bool
ctdb_readrecordlock_send(struct ctdb_db *ctdb_db, TDB_DATA key,
			 struct ctdb_request **req,
			 ctdb_callback_t callback, void *private_data);
struct ctdb_lock *ctdb_readrecordlock_recv(struct ctdb_db *ctdb_db,
					   struct ctdb_request *handle,
					   TDB_DATA *data);

/* Returns null on failure. */
struct ctdb_lock *ctdb_readrecordlock(struct ctdb_db *ctdb_db, TDB_DATA key,
				      TDB_DATA *data);

/*
 * Function to write data to a record
 * This function may ONLY be called while holding a lock to the record
 * created by ctdb_readrecordlock*
 * Either from the callback provided to ctdb_readrecordlock_send()
 * or after calling ctdb_readrecordlock_recv() but before calling
 * ctdb_release_lock() to release the lock.
 */
int ctdb_writerecord(struct ctdb_lock *lock, TDB_DATA data);


void ctdb_release_lock(struct ctdb_lock *lock);

/*
 * messaging functions
 * these functions provide a messaging layer for applications to communicate
 * with eachother across
 */
typedef void (*ctdb_message_fn_t)(struct ctdb_connection *, uint64_t srvid, TDB_DATA data, void *);

struct ctdb_request *
ctdb_set_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_message_fn_t handler,
			      ctdb_callback_t callback,
			      void *private_data);

int ctdb_set_message_handler_recv(struct ctdb_connection *ctdb,
				  struct ctdb_request *handle);

int ctdb_set_message_handler(struct ctdb_connection *ctdb, uint64_t srvid,
			     ctdb_message_fn_t handler, void *private_data);



/*
 * unregister a message handler and stop listening on teh specified port
 */
struct ctdb_request *
ctdb_remove_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
				 ctdb_callback_t callback,
				 void *private_data);

int ctdb_remove_message_handler_recv(struct ctdb_request *handle);

int ctdb_remove_message_handler(struct ctdb_connection *ctdb, uint64_t srvid);



/*
 * send a message to a specific node/port
 * this function is non-blocking
 */
int ctdb_send_message(struct ctdb_connection *ctdb, uint32_t pnn, uint64_t srvid, TDB_DATA data);



/*
 * functions to read the pnn number of the local node
 */
struct ctdb_request *
ctdb_getpnn_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_callback_t callback,
		 void *private_data);
int ctdb_getpnn_recv(struct ctdb_request *req, uint32_t *pnn);

int ctdb_getpnn(struct ctdb_connection *ctdb,
		uint32_t destnode,
		uint32_t *pnn);




/*
 * functions to read the recovery master of a node
 */
struct ctdb_request *
ctdb_getrecmaster_send(struct ctdb_connection *ctdb,
			uint32_t destnode,
			ctdb_callback_t callback,
			void *private_data);
int ctdb_getrecmaster_recv(struct ctdb_request *handle,
			   uint32_t *recmaster);
int ctdb_getrecmaster(struct ctdb_connection *ctdb,
			uint32_t destnode,
			uint32_t *recmaster);




/*
 * cancel a request
 */
int ctdb_cancel(struct ctdb_request *);


/* These ugly macro wrappers make the callbacks typesafe. */
#include <ccan/typesafe_cb.h>
#define ctdb_sendcb(cb, cbdata)						\
	 typesafe_cb_preargs(void, (cb), (cbdata),			\
			     struct ctdb_connection *, struct ctdb_request *)

#define ctdb_attachdb_send(ctdb, name, persistent, tdb_flags, cb, cbdata) \
	ctdb_attachdb_send((ctdb), (name), (persistent), (tdb_flags),	\
			   ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_readrecordlock_send(ctdb_db, key, reqp, cb, cbdata)	\
	ctdb_readrecordlock_send((ctdb_db), (key), (reqp),		\
				 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_set_message_handler_send(ctdb, srvid, handler, cb, cbdata)	\
	ctdb_set_message_handler_send((ctdb), (srvid), (handler),	\
	      ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_remove_message_handler_send(ctdb, srvid, cb, cbdata)	\
	ctdb_remove_message_handler_send((ctdb), (srvid),		\
	      ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getpnn_send(ctdb, destnode, cb, cbdata)			\
	ctdb_getpnn_send((ctdb), (destnode),				\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getrecmaster_send(ctdb, destnode, cb, cbdata)		\
	ctdb_getrecmaster_send((ctdb), (destnode),			\
			       ctdb_sendcb((cb), (cbdata)), (cbdata))
#endif
