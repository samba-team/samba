/*
   ctdb database library

   Copyright (C) Ronnie sahlberg 2010

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

/* Functions are not thread safe so all function calls must be wrapped
 * inside a pthread_mutex for threaded applications.
 *
 * All *_send() functions are guaranteed to be non-blocking and fully
 * asynchronous.
 *
 * The return data from a _send() call can be accessed through two different
 * mechanisms.
 *
 * 1, by calling *_recv() directly on the handle.
 *    This function will block until the response is received so it
 *    should be avoided.
 *    The exception is when called from in the registered callback,
 *    in this case the fucntion is guaranteed not to block.
 *
 * 2, providing an async callback to be invoked when the call completes.
 *    From inside the callback you use the *_recv() function to extract the
 *    response data.
 *
 * After the *_recv() function returns, the handle will have been destroyed.
 */

/*
 * Connect to ctdb using the specified domain socket.
 * Returns a ctdb context if successful or NULL.
 *
 * Use ctdb_free() to release the returned ctdb_context when finished.
 */
struct ctdb_context *ctdb_connect(const char *addr);

int ctdb_get_fd(struct ctdb_context *ctdb);

int ctdb_which_events(struct ctdb_context *ctdb);

int ctdb_service(struct ctdb_context *ctdb);


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






typedef void ctdb_handle;


typedef void (*ctdb_generic_callback)(int32_t status, struct ctdb_context *ctdb, ctdb_handle *, void *private_data);


/*
 * functions to attach to a database
 * if the database does not exist it will be created.
 *
 * You have to free the handle with ctdb_free() when finished with it.
 */
struct ctdb_db_context;

typedef void (*ctdb_attachdb_cb)(int32_t status, ctdb_handle *, struct ctdb_db_context *ctdb_db, void *private_data);

ctdb_handle *
ctdb_attachdb_send(struct ctdb_context *ctdb,
		   const char *name, int persistent, uint32_t tdb_flags,
		   ctdb_attachdb_cb callback,
		   void *private_data);
int ctdb_attachdb_recv(struct ctdb_context *ctdb,
		       ctdb_handle *handle, struct ctdb_db_context **);
int ctdb_attachdb(struct ctdb_context *ctdb,
		  const char *name, int persistent, uint32_t tdb_flags,
		  struct ctdb_db_context **);


/*
 * functions to read a record from the database
 * when the callback is invoked, the client will hold an exclusive lock
 * on the record, until the handle is ctdb_free()d.
 * the client MUST NOT block during holding this lock and MUST
 * release it quickly by performing ctdb_free(handle).
 *
 * When the handle is freed, data is freed too, so make sure to copy the data
 * before freeing the handle.
 */
typedef void (*ctdb_readrecordlock_cb)(int32_t status, ctdb_handle *handle, TDB_DATA data, void *private_data);

ctdb_handle *
ctdb_readrecordlock_send(struct ctdb_context *ctdb,
		struct ctdb_db_context *ctdb_db_context,
		TDB_DATA key,
		ctdb_readrecordlock_cb callback,
		void *private_data);
int ctdb_readrecordlock_recv(struct ctdb_context *ctdb,
		ctdb_handle *handle,
		TDB_DATA **data);
int ctdb_readrecordlock(struct ctdb_context *ctdb,
		struct ctdb_db_context *ctdb_db_context,
		TDB_DATA key,
		TDB_DATA **data);



/*
 * Function to write data to a record
 * This function may ONLY be called while holding a lock to the record
 * created by ctdb_readrecordlock*
 * Either from the callback provided to ctdb_readrecordlock_send()
 * or after calling ctdb_readrecordlock_recv() but before calling
 * ctdb_free() to release the handle.
 */
int ctdb_writerecord(ctdb_handle *handle,
		TDB_DATA key,
		TDB_DATA data);



/*
 * messaging functions
 * these functions provide a messaging layer for applications to communicate
 * with eachother across
 */
typedef void (*ctdb_message_fn_t)(struct ctdb_context *, uint64_t srvid, TDB_DATA data, void *);

/*
 * register a message handler and start listening on a service port
 */
typedef void (*ctdb_set_message_handler_cb)(int32_t status, void *private_data);

ctdb_handle *
ctdb_set_message_handler_send(struct ctdb_context *ctdb, uint64_t srvid,
			      ctdb_set_message_handler_cb callback,
			      ctdb_message_fn_t handler, void *private_data);

int ctdb_set_message_handler_recv(struct ctdb_context *ctdb,
				  ctdb_handle *handle);

int ctdb_set_message_handler(struct ctdb_context *ctdb, uint64_t srvid,
			     ctdb_message_fn_t handler, void *private_data);



/*
 * unregister a message handler and stop listening on teh specified port
 */
typedef void (*ctdb_remove_message_handler_cb)(int32_t status, void *private_data);

ctdb_handle *
ctdb_remove_message_handler_send(struct ctdb_context *ctdb, uint64_t srvid,
				 ctdb_remove_message_handler_cb callback,
				 void *private_data);

int ctdb_remove_message_handler_recv(struct ctdb_context *ctdb,
				  ctdb_handle *handle);

int ctdb_remove_message_handler(struct ctdb_context *ctdb, uint64_t srvid);



/*
 * send a message to a specific node/port
 * this function is non-blocking
 */
int ctdb_send_message(struct ctdb_context *ctdb, uint32_t pnn, uint64_t srvid, TDB_DATA data);




/*
 * functions to read the pnn number of the local node
 */
ctdb_handle *
ctdb_getpnn_send(struct ctdb_context *ctdb,
		 uint32_t destnode,
		 ctdb_generic_callback callback,
		 void *private_data);
int ctdb_getpnn_recv(struct ctdb_context *ctdb,
		     ctdb_handle *handle,
		     uint32_t *pnn);
int ctdb_getpnn(struct ctdb_context *ctdb,
		uint32_t destnode,
		uint32_t *pnn);




/*
 * functions to read the recovery master of a node
 */
ctdb_handle *
ctdb_getrecmaster_send(struct ctdb_context *ctdb,
			uint32_t destnode,
			ctdb_generic_callback callback,
			void *private_data);
int ctdb_getrecmaster_recv(struct ctdb_context *ctdb,
			ctdb_handle *handle,
			uint32_t *recmaster);
int ctdb_getrecmaster(struct ctdb_context *ctdb,
			uint32_t destnode,
			uint32_t *recmaster);




/*
 * cancel a request/call or release a resource
 */
int ctdb_free(ctdb_handle *);



#endif
