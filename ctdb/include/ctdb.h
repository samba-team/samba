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


struct ctdb_request;

/*
 * functions to attach to a database
 * if the database does not exist it will be created.
 *
 * You have to free the handle with ctdb_detach_db() when finished with it.
 */
struct ctdb_db;

typedef void (*ctdb_attachdb_cb)(int status, struct ctdb_db *ctdb_db, void *private_data);

struct ctdb_request *
ctdb_attachdb_send(struct ctdb_connection *ctdb,
		   const char *name, int persistent, uint32_t tdb_flags,
		   ctdb_attachdb_cb callback,
		   void *private_data);
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
 */
typedef void (*ctdb_readrecordlock_cb)(int status, struct ctdb_lock *lock, TDB_DATA data, void *private_data);

struct ctdb_request *
ctdb_readrecordlock_send(struct ctdb_db *ctdb_db,
		TDB_DATA key,
		ctdb_readrecordlock_cb callback,
		void *private_data);
int ctdb_readrecordlock_recv(struct ctdb_connection *ctdb,
		struct ctdb_request *handle,
		TDB_DATA **data);
int ctdb_readrecordlock(struct ctdb_connection *ctdb,
		struct ctdb_db *ctdb_db,
		TDB_DATA key,
		TDB_DATA **data);



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

/*
 * register a message handler and start listening on a service port
 */
typedef void (*ctdb_set_message_handler_cb)(int status, void *private_data);

struct ctdb_request *
ctdb_set_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_set_message_handler_cb callback,
			      ctdb_message_fn_t handler, void *private_data);

int ctdb_set_message_handler_recv(struct ctdb_connection *ctdb,
				  struct ctdb_request *handle);

int ctdb_set_message_handler(struct ctdb_connection *ctdb, uint64_t srvid,
			     ctdb_message_fn_t handler, void *private_data);



/*
 * unregister a message handler and stop listening on teh specified port
 */
typedef void (*ctdb_remove_message_handler_cb)(int status, void *private_data);

struct ctdb_request *
ctdb_remove_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
				 ctdb_remove_message_handler_cb callback,
				 void *private_data);

int ctdb_remove_message_handler_recv(struct ctdb_connection *ctdb,
				  struct ctdb_request *handle);

int ctdb_remove_message_handler(struct ctdb_connection *ctdb, uint64_t srvid);



/*
 * send a message to a specific node/port
 * this function is non-blocking
 */
int ctdb_send_message(struct ctdb_connection *ctdb, uint32_t pnn, uint64_t srvid, TDB_DATA data);



/*
 * functions to read the pnn number of the local node
 */
typedef void (*ctdb_getpnn_cb)(int status, uint32_t pnn, void *private_data);

struct ctdb_request *
ctdb_getpnn_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_getpnn_cb callback,
		 void *private_data);
int ctdb_getpnn(struct ctdb_connection *ctdb,
		uint32_t destnode,
		uint32_t *pnn);




/*
 * functions to read the recovery master of a node
 */
typedef void (*ctdb_getrecmaster_cb)(int status,
				     uint32_t recmaster, void *private_data);

struct ctdb_request *
ctdb_getrecmaster_send(struct ctdb_connection *ctdb,
			uint32_t destnode,
			ctdb_getrecmaster_cb callback,
			void *private_data);
int ctdb_getrecmaster_recv(struct ctdb_connection *ctdb,
			struct ctdb_request *handle,
			uint32_t *recmaster);
int ctdb_getrecmaster(struct ctdb_connection *ctdb,
			uint32_t destnode,
			uint32_t *recmaster);




/*
 * cancel a request
 */
int ctdb_cancel(struct ctdb_request *);

#endif
