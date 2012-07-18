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
#include <stdarg.h>
#include <stdio.h>
#include <tdb.h>
#include <netinet/in.h>
#include <ctdb_protocol.h>

/**
 * ctdb - a library for accessing tdbs controlled by ctdbd
 *
 * ctdbd (clustered tdb daemon) is a daemon designed to syncronize TDB
 * databases across a cluster.  Using this library, you can communicate with
 * the daemon to access the databases, pass messages across the cluster, and
 * control the daemon itself.
 *
 * The general API is event-driven and asynchronous: you call the
 * *_send functions, supplying callbacks, then when the ctdbd file
 * descriptor is usable, call ctdb_service() to perform read from it
 * and call your callbacks, which use the *_recv functions to unpack
 * the replies from ctdbd.
 *
 * There is also a synchronous wrapper for each function for trivial
 * programs; these can be found in the section marked "Synchronous API".
 */

/**
 * ctdb_log_fn_t - logging function for ctdbd
 * @log_priv: private (typesafe) arg via ctdb_connect
 * @severity: syslog-style severity
 * @format: printf-style format string.
 * @ap: arguments for formatting.
 *
 * The severity passed to log() are as per syslog(3).  In particular,
 * LOG_DEBUG is used for tracing, LOG_WARNING is used for unusual
 * conditions which don't necessarily return an error through the API,
 * LOG_ERR is used for errors such as lost communication with ctdbd or
 * out-of-memory, LOG_ALERT is used for library usage bugs, LOG_CRIT is
 * used for libctdb internal consistency checks.
 *
 * The log() function can be typesafe: the @log_priv arg to
 * ctdb_donnect and signature of log() should match.
 */
typedef void (*ctdb_log_fn_t)(void *log_priv,
			      int severity, const char *format, va_list ap);

/**
 * ctdb_connect - connect to ctdb using the specified domain socket.
 * @addr: the socket address, or NULL for default
 * @log: the logging function
 * @log_priv: the private argument to the logging function.
 *
 * Returns a ctdb context if successful or NULL.  Use ctdb_disconnect() to
 * release the returned ctdb_connection when finished.
 *
 * See Also:
 *	ctdb_log_fn_t, ctdb_log_file()
 */
struct ctdb_connection *ctdb_connect(const char *addr,
				     ctdb_log_fn_t log_fn, void *log_priv);

/**
 * ctdb_log_file - example logging function
 *
 * Logs everything at priority LOG_WARNING or above to the file given (via
 * the log_priv argument, usually stderr).
 */
void ctdb_log_file(FILE *, int, const char *, va_list);

/**
 * ctdb_log_level - level at which to call logging function
 *
 * This variable globally controls filtering on the logging function.
 * It is initialized to LOG_WARNING, meaning that strange but nonfatal
 * events, as well as errors and API misuses are reported.
 *
 * Set it to LOG_DEBUG to receive all messages.
 */
extern int ctdb_log_level;

/**
 * ctdb_disconnect - close down a connection to ctdbd.
 * @ctdb: the ctdb connectio returned from ctdb_connect.
 *
 * The @ctdb arg will be freed by this call, and must not be used again.
 */
void ctdb_disconnect(struct ctdb_connection *ctdb);

/***
 *
 *  Asynchronous API
 *
 ***/

/**
 * ctdb_num_active - get the number of active commands
 * @ctdb: the ctdb_connection from ctdb_connect.
 *
 * This command can be used to find the number of active commands we have
 * issued. An active command is a command we have queued, or sent
 * to the ctdb daemon but which we have not yet received a reply to.
 *
 * See Also:
 *	ctdb_num_in_flight(), ctdb_num_out_queue()
 */
int ctdb_num_active(struct ctdb_connection *ctdb);

/**
 * ctdb_num_in_flight - get the number of commands in flight.
 * @ctdb: the ctdb_connection from ctdb_connect.
 *
 * This command can be used to find the number of commands we have
 * sent to the ctdb daemon to which we have not yet received/processed
 * the reply.
 *
 * See Also:
 *	ctdb_num_out_queue(), ctdb_num_active()
 */
int ctdb_num_in_flight(struct ctdb_connection *ctdb);

/**
 * ctdb_num_out_queue - get the number of commands in the out queue
 * @ctdb: the ctdb_connection from ctdb_connect.
 *
 * This command can be used to find the number of commands we have
 * queued for delivery to the ctdb daemon but have not yet been
 * written to the domain socket.
 *
 * See Also:
 *	ctdb_num_in_flight(), ctdb_num_active()
 */
int ctdb_num_out_queue(struct ctdb_connection *ctdb);

/**
 * ctdb_get_fd - get the filedescriptor to select/poll on
 * @ctdb: the ctdb_connection from ctdb_connect.
 *
 * By using poll or select on this file descriptor, you will know when to call
 * ctdb_service().
 *
 * See Also:
 *	ctdb_which_events(), ctdb_service()
 */
int ctdb_get_fd(struct ctdb_connection *ctdb);

/**
 * ctdb_which_events - determine which events ctdb_service wants to see
 * @ctdb: the ctdb_connection from ctdb_connect.
 *
 * This returns POLLIN, possibly or'd with POLLOUT if there are writes
 * pending.  You can set this straight into poll.events.
 *
 * See Also:
 *	ctdb_service()
 */
int ctdb_which_events(struct ctdb_connection *ctdb);

/**
 * ctdb_service - service any I/O and callbacks from ctdbd communication
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @revents: which events are available.
 *
 * This is the core of the library: it read and writes to the ctdbd
 * socket.  It may call callbacks registered with the various _send
 * functions.
 *
 * revents is a bitset: POLLIN and/or POLLOUT may be set to indicate
 * it is worth attempting to read/write the (nonblocking)
 * filedescriptor respectively.
 *
 * Note that the synchronous functions call this internally.
 * Returns false on catastrophic failure.
 */
bool ctdb_service(struct ctdb_connection *ctdb, int revents);

/**
 * struct ctdb_request - handle for an outstanding request
 *
 * This opaque structure returned from various *_send functions gives
 * you a handle by which you can cancel a request.  You can't do
 * anything else with it until the request is completed and it is
 * handed to your callback function.
 */
struct ctdb_request;

/**
 * ctdb_request_free - free a completed request
 *
 * This frees a request: you should only call it once it has been
 * handed to your callback.  For incomplete requests, see ctdb_cancel().
 */
void ctdb_request_free(struct ctdb_request *req);

/**
 * ctdb_callback_t - callback for completed requests.
 *
 * This would normally unpack the request using ctdb_*_recv().  You
 * must free the request using ctdb_request_free().
 *
 * Note that due to macro magic, actual your callback can be typesafe:
 * instead of taking a void *, it can take a type which matches the
 * actual private parameter.
 */
typedef void (*ctdb_callback_t)(struct ctdb_connection *ctdb,
				struct ctdb_request *req, void *private_data);

/**
 * struct ctdb_db - connection to a particular open TDB
 *
 * This represents a particular open database: you receive it from
 * ctdb_attachdb or ctdb_attachdb_recv to manipulate a database.
 *
 * You have to free the handle with ctdb_detachdb() when finished with it.
 */
struct ctdb_db;

/**
 * ctdb_attachdb_send - open a clustered TDB
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @name: the filename of the database (no /).
 * @persistent: whether the database is persistent across ctdbd's life
 * @tdb_flags: the flags to pass to tdb_open.
 * @callback: the callback when we're attached or failed (typesafe)
 * @cbdata: the argument to callback()
 *
 * This function connects to a TDB controlled by ctdbd.  It can create
 * a new TDB if it does not exist, depending on tdb_flags.  Returns
 * the pending request, or NULL on error.
 */
struct ctdb_request *
ctdb_attachdb_send(struct ctdb_connection *ctdb,
		   const char *name, bool persistent, uint32_t tdb_flags,
		   ctdb_callback_t callback, void *cbdata);

/**
 * ctdb_attachdb_recv - read an ctdb_attach reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 *
 * This returns NULL if something went wrong, or otherwise the open database.
 */
struct ctdb_db *ctdb_attachdb_recv(struct ctdb_connection *ctdb,
				   struct ctdb_request *req);


/**
 * struct ctdb_lock - a record lock on a clustered TDB database
 *
 * This locks a subset of the database across the entire cluster; it
 * is the fundamental sychronization element for ctdb.  You cannot have
 * more than one lock at once.
 *
 * You MUST NOT block during holding this lock and MUST release it
 * quickly by performing ctdb_release_lock(lock).
 * Do NOT make any system calls that may block while holding the lock.
 *
 * Try to release the lock as quickly as possible.
 */
struct ctdb_lock;

/**
 * ctdb_rrl_callback_t - callback for ctdb_readrecordlock_async
 *
 * This is not the standard ctdb_callback_t, because there is often no
 * request required to access a database record (ie. if it is local already).
 * So the callback is handed the lock directly: it might be NULL if there
 * was an error obtaining the lock.
 *
 * See Also:
 *	ctdb_readrecordlock_async(), ctdb_readrecordlock()
 */
typedef void (*ctdb_rrl_callback_t)(struct ctdb_db *ctdb_db,
				    struct ctdb_lock *lock,
				    TDB_DATA data,
				    void *private_data);

/**
 * ctdb_readrecordlock_async - read and lock a record
 * @ctdb_db: the database handle from ctdb_attachdb/ctdb_attachdb_recv.
 * @key: the key of the record to lock.
 * @callback: the callback once the record is locked (typesafe).
 * @cbdata: the argument to callback()
 *
 * This returns true on success.  Commonly, we can obtain the record
 * immediately and so the callback will be invoked.  Otherwise a request
 * will be queued to ctdbd for the record.
 *
 * If failure is immediate, false is returned.  Otherwise, the callback
 * may receive a NULL lock arg to indicate asynchronous failure.
 */
bool ctdb_readrecordlock_async(struct ctdb_db *ctdb_db, TDB_DATA key,
			       ctdb_rrl_callback_t callback, void *cbdata);

/**
 * ctdb_readonlyrecordlock_async - read and lock a record for read-only access
 * @ctdb_db: the database handle from ctdb_attachdb/ctdb_attachdb_recv.
 * @key: the key of the record to lock.
 * @callback: the callback once the record is locked (typesafe).
 * @cbdata: the argument to callback()
 *
 * This returns true on success.  Commonly, we can obtain the record
 * immediately and so the callback will be invoked.  Otherwise a request
 * will be queued to ctdbd for the record.
 *
 * If failure is immediate, false is returned.  Otherwise, the callback
 * may receive a NULL lock arg to indicate asynchronous failure.
 */
bool ctdb_readonlyrecordlock_async(struct ctdb_db *ctdb_db, TDB_DATA key,
			       ctdb_rrl_callback_t callback, void *cbdata);


/**
 * ctdb_writerecord - write a locked record in a TDB
 * @ctdb_db: the database handle from ctdb_attachdb/ctdb_attachdb_recv.
 * @lock: the lock from ctdb_readrecordlock/ctdb_readrecordlock_recv
 * @data: the new data to place in the record.
 */
bool ctdb_writerecord(struct ctdb_db *ctdb_db,
		      struct ctdb_lock *lock, TDB_DATA data);

/**
 * ctdb_release_lock - release a record lock on a TDB
 * @ctdb_db: the database handle from ctdb_attachdb/ctdb_attachdb_recv.
 * @lock: the lock from ctdb_readrecordlock/ctdb_readrecordlock_async
 */
void ctdb_release_lock(struct ctdb_db *ctdb_db, struct ctdb_lock *lock);



/**
 * ctdb_traverse_callback_t - callback for ctdb_traverse_async.
 * return 0 - to continue traverse
 * return 1 - to abort the traverse
 *
 * See Also:
 *	ctdb_traverse_async()
 */
#define TRAVERSE_STATUS_RECORD		0
#define TRAVERSE_STATUS_FINISHED	1
#define TRAVERSE_STATUS_ERROR		2
typedef int (*ctdb_traverse_callback_t)(struct ctdb_connection *ctdb,
				    struct ctdb_db *ctdb_db,
				    int status,
				    TDB_DATA key,
				    TDB_DATA data,
				    void *private_data);

/**
 * ctdb_traverse_async - traverse a database.
 * @ctdb_db: the database handle from ctdb_attachdb/ctdb_attachdb_recv.
 * @callback: the callback once the record is locked (typesafe).
 * @cbdata: the argument to callback()
 *
 * This returns true on success.
 * when successfull, the callback will be invoked for each record
 * until the traversal is finished.
 *
 * status == 
 * TRAVERSE_STATUS_RECORD         key/data contains a record.
 * TRAVERSE_STATUS_FINISHED       traverse is finished. key/data is undefined.
 * TRAVERSE_STATUS_ERROR          an error occured during traverse.
 *                                key/data is undefined.
 *
 * If failure is immediate, false is returned.
 */
bool ctdb_traverse_async(struct ctdb_db *ctdb_db,
			 ctdb_traverse_callback_t callback, void *cbdata);

/**
 * ctdb_message_fn_t - messaging callback for ctdb messages
 *
 * ctdbd provides a simple messaging API; you can register for a particular
 * 64-bit id on which you want to send messages, and send to other ids.
 *
 * See Also:
 *	ctdb_set_message_handler_send()
 */
typedef void (*ctdb_message_fn_t)(struct ctdb_connection *,
				  uint64_t srvid, TDB_DATA data, void *);

/**
 * ctdb_set_message_handler_send - register for messages to a srvid
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @srvid: the 64 bit identifier for our messages.
 * @handler: the callback when we receive such a message (typesafe)
 * @handler_data: the argument to handler()
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * Note: our callback will always be called before handler.
 *
 * See Also:
 *	ctdb_set_message_handler_recv(), ctdb_remove_message_handler_send()
 */
struct ctdb_request *
ctdb_set_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_message_fn_t handler,
			      void *handler_data,
			      ctdb_callback_t callback,
			      void *cbdata);

/**
 * ctdb_set_message_handler_recv - read a set_message_handler result
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request
 *
 * If this returns true, the registered handler may be called from the next
 * ctdb_service().  If this returns false, the registration failed.
 */
bool ctdb_set_message_handler_recv(struct ctdb_connection *ctdb,
				   struct ctdb_request *handle);

/**
 * ctdb_remove_message_handler_send - unregister for messages to a srvid
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @srvid: the 64 bit identifier for our messages.
 * @handler: the callback when we receive such a message (typesafe)
 * @handler_data: the argument to handler()
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * This undoes a successful ctdb_set_message_handler or
 * ctdb_set_message_handler_recv.
 */
struct ctdb_request *
ctdb_remove_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
				 ctdb_message_fn_t handler, void *handler_data,
				 ctdb_callback_t callback, void *cbdata);

/**
 * ctdb_remove_message_handler_recv - read a remove_message_handler result
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request
 *
 * After this returns true, the registered handler will no longer be called.
 * If this returns false, the de-registration failed.
 */
bool ctdb_remove_message_handler_recv(struct ctdb_connection *ctdb,
				      struct ctdb_request *req);


/**
 * ctdb_send_message - send a message via ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @pnn: the physical node number to send to
 * @srvid: the 64 bit identifier for this message type.
 * @data: the data to send
 *
 * This allows arbitrary messages to be sent across the cluster to those
 * listening (via ctdb_set_message_handler et al).
 *
 * This queues a message to be sent: you will need to call
 * ctdb_service() to actually send the message.  There is no callback
 * because there is no acknowledgement.
 *
 * See Also:
 *	ctdb_getpnn_send(), ctdb_getpnn()
 */
bool ctdb_send_message(struct ctdb_connection *ctdb, uint32_t pnn, uint64_t srvid, TDB_DATA data);

/**
 * ctdb_getpnn_send - read the pnn number of a node.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getpnn_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_callback_t callback,
		 void *cbdata);
/**
 * ctdb_getpnn_recv - read an ctdb_getpnn reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @pnn: a pointer to the pnn to fill in
 *
 * This returns false if something went wrong, or otherwise fills in pnn.
 */
bool ctdb_getpnn_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, uint32_t *pnn);


/**
 * ctdb_getdbstat_send - read statistics for a db
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @db_id:    the database to collect the statistics from
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getdbstat_send(struct ctdb_connection *ctdb,
		     uint32_t destnode,
		     uint32_t db_id,
		     ctdb_callback_t callback,
		     void *cbdata);
/**
 * ctdb_getdbstat_recv - read an ctdb_getdbstat reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @stat: a pointer to the *stat to fill in
 *
 * This returns false if something went wrong, or otherwise fills in **stats
 * stats must be freed later by calling ctdb_free_dbstat();
 */
bool ctdb_getdbstat_recv(struct ctdb_connection *ctdb,
			 struct ctdb_request *req,
			 struct ctdb_db_statistics **stat);

void ctdb_free_dbstat(struct ctdb_db_statistics *stat);

/**
 * ctdb_check_message_handlers_send - check a list of message_handlers
 * if they are registered
 * message_handlers are registered on the daemon using the
 *   ctdb_set_message_handler_send() call
 *
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @num: number of srvids to check
 * @mhs: @num message_handlers values to check
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_check_message_handlers_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 uint32_t num,
		 uint64_t *mhs,
		 ctdb_callback_t callback,
		 void *cbdata);
/**
 * ctdb_check_message_handlers_recv - read a ctdb_check_message_handlers
 * reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @num: number of message_handlers to check
 * @result: an array of @num uint8_t fields containing the result of the check
 *     0: message_handler does not exist
 *     1: message_handler exists
 *
 * This returns false if something went wrong, or otherwise fills in result.
 */
bool
ctdb_check_message_handlers_recv(struct ctdb_connection *ctdb,
				  struct ctdb_request *req, uint32_t num,
				  uint8_t *result);


/**
 * ctdb_getcapabilities_send - read the capabilities of a node
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getcapabilities_send(struct ctdb_connection *ctdb,
			  uint32_t destnode,
			  ctdb_callback_t callback, void *cbdata);

/**
 * ctdb_getcapabilities_recv - read an ctdb_getcapabilities reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @capabilities: a pointer to the capabilities to fill in
 *
 * This returns false if something went wrong, or otherwise fills in
 * capabilities.
 */
bool ctdb_getcapabilities_recv(struct ctdb_connection *ctdb,
			       struct ctdb_request *handle,
			       uint32_t *capabilities);

/**
 * ctdb_getdbseqnum_send - read the sequence number off a db
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @dbid: database id
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getdbseqnum_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 uint32_t dbid,
		 ctdb_callback_t callback,
		 void *cbdata);
/**
 * ctdb_getdbseqnum_recv - read the sequence number off a database
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @seqnum: a pointer to the seqnum to fill in
 *
 * This returns false if something went wrong, or otherwise fills in pnn.
 */
bool ctdb_getdbseqnum_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, uint64_t *seqnum);

/**
 * ctdb_getnodemap_send - read the nodemap number from a node.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getnodemap_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_callback_t callback,
		 void *cbdata);
/**
 * ctdb_getnodemap_recv - read an ctdb_getnodemap reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @nodemap: a pointer to the returned nodemap structure
 *
 * This returns false if something went wrong.
 * If the command failed, it guarantees to set nodemap to NULL.
 * A non-NULL value for nodemap means the command was successful.
 *
 * A non-NULL value of the nodemap must be release released/freed
 * by ctdb_free_nodemap().
 */
bool ctdb_getnodemap_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, struct ctdb_node_map **nodemap);

/**
 * ctdb_getifaces_send - read the list of interfaces from a node.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getifaces_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_callback_t callback,
		 void *cbdata);
/**
 * ctdb_getifaces_recv - read an ctdb_getifaces reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @ifaces: the list of interfaces 
 *
 * This returns false if something went wrong.
 * If the command failed, it guarantees to set ifaces to NULL.
 * A non-NULL value for ifaces means the command was successful.
 *
 * A non-NULL value of the ifaces must be release released/freed
 * by ctdb_free_ifaces().
 */
bool ctdb_getifaces_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, struct ctdb_ifaces_list **ifaces);

/* Free a datastructure returned by ctdb_getifaces[_recv] */
void ctdb_free_ifaces(struct ctdb_ifaces_list *ifaces);

/**
 * ctdb_getpublicips_send - read the public ip list from a node.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * This control returns the list of public ips known to the local node.
 * Deamons only know about those ips that are listed in the local
 * public addresses file, which means the returned list of ips may
 * be only a subset of all ips across the entire cluster.
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getpublicips_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_callback_t callback,
		 void *cbdata);
/**
 * ctdb_getpublicips_recv - read the public ip list from a node
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @ips: a pointer to the returned public ip list
 *
 * This returns false if something went wrong.
 * If the command failed, it guarantees to set ips to NULL.
 * A non-NULL value for nodemap means the command was successful.
 *
 * A non-NULL value of the nodemap must be release released/freed
 * by ctdb_free_publicips().
 */
bool ctdb_getpublicips_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, struct ctdb_all_public_ips **ips);


/**
 * ctdb_getrecmaster_send - read the recovery master of a node
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getrecmaster_send(struct ctdb_connection *ctdb,
			uint32_t destnode,
			ctdb_callback_t callback, void *cbdata);

/**
 * ctdb_getrecmaster_recv - read an ctdb_getrecmaster reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @recmaster: a pointer to the recmaster to fill in
 *
 * This returns false if something went wrong, or otherwise fills in
 * recmaster.
 */
bool ctdb_getrecmaster_recv(struct ctdb_connection *ctdb,
			    struct ctdb_request *handle,
			    uint32_t *recmaster);

/**
 * ctdb_getrecmode_send - read the recovery mode of a node
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getrecmode_send(struct ctdb_connection *ctdb,
		     uint32_t destnode,
		     ctdb_callback_t callback, void *cbdata);

/**
 * ctdb_getrecmode_recv - read an ctdb_getrecmode reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @recmode: a pointer to the recmode to fill in
 *
 * This returns false if something went wrong, or otherwise fills in
 * recmode.
 */
bool ctdb_getrecmode_recv(struct ctdb_connection *ctdb,
			  struct ctdb_request *handle,
			  uint32_t *recmode);

/**
 * ctdb_getvnnmap_send - read the vnn map from a node.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @callback: the callback when ctdb replies to our message (typesafe)
 * @cbdata: the argument to callback()
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
struct ctdb_request *
ctdb_getvnnmap_send(struct ctdb_connection *ctdb,
		    uint32_t destnode,
		    ctdb_callback_t callback,
		    void *cbdata);
/**
 * ctdb_getvnnmap_recv - read an ctdb_getvnnmap reply from ctdbd
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the completed request.
 * @vnnmap: the list of interfaces 
 *
 * This returns false if something went wrong.
 * If the command failed, it guarantees to set vnnmap to NULL.
 * A non-NULL value for vnnmap means the command was successful.
 *
 * A non-NULL value of the vnnmap must be released/freed
 * by ctdb_free_vnnmap().
 */
bool ctdb_getvnnmap_recv(struct ctdb_connection *ctdb,
			 struct ctdb_request *req, struct ctdb_vnn_map **vnnmap);

/**
 * ctdb_cancel - cancel an uncompleted request
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @req: the uncompleted request.
 *
 * This cancels a request, returning true.  You may not cancel a
 * request which has already been completed (ie. once its callback has
 * been called); you should simply use ctdb_request_free() in that case.
 */
void ctdb_cancel(struct ctdb_connection *ctdb, struct ctdb_request *req);

/***
 *
 *  Synchronous API
 *
 ***/

/**
 * ctdb_attachdb - open a clustered TDB (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @name: the filename of the database (no /).
 * @persistent: whether the database is persistent across ctdbd's life
 * @tdb_flags: the flags to pass to tdb_open.
 *
 * Do a ctdb_attachdb_send and wait for it to complete.
 * Returns NULL on failure.
 */
struct ctdb_db *ctdb_attachdb(struct ctdb_connection *ctdb,
			      const char *name, bool persistent,
			      uint32_t tdb_flags);

/**
 * ctdb_detachdb - close a clustered TDB.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @db: the database from ctdb_attachdb/ctdb_attachdb_send
 *
 * Closes a clustered tdb.
 */
void ctdb_detachdb(struct ctdb_connection *ctdb, struct ctdb_db *db);

/**
 * ctdb_readrecordlock - read and lock a record (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @ctdb_db: the database handle from ctdb_attachdb/ctdb_attachdb_recv.
 * @key: the key of the record to lock.
 * @req: a pointer to the request, if one is needed.
 *
 * Do a ctdb_readrecordlock_send and wait for it to complete.
 * Returns NULL on failure.
 */
struct ctdb_lock *ctdb_readrecordlock(struct ctdb_connection *ctdb,
				      struct ctdb_db *ctdb_db, TDB_DATA key,
				      TDB_DATA *data);


/**
 * ctdb_set_message_handler - register for messages to a srvid (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @srvid: the 64 bit identifier for our messages.
 * @handler: the callback when we receive such a message (typesafe)
 * @cbdata: the argument to handler()
 *
 * If this returns true, the message handler can be called from any
 * ctdb_service() (which is also called indirectly by other
 * synchronous functions).  If this returns false, the registration
 * failed.
 */
bool ctdb_set_message_handler(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_message_fn_t handler, void *cbdata);


/**
 * ctdb_remove_message_handler - deregister for messages (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @srvid: the 64 bit identifier for our messages.
 * @handler: the callback when we receive such a message (typesafe)
 * @handler_data: the argument to handler()
 *
 * If this returns true, the message handler will no longer be called.
 * If this returns false, the deregistration failed.
 */
bool ctdb_remove_message_handler(struct ctdb_connection *ctdb, uint64_t srvid,
				 ctdb_message_fn_t handler, void *handler_data);

/**
 * ctdb_getpnn - read the pnn number of a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @pnn: a pointer to the pnn to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *pnn on success.
 */
bool ctdb_getpnn(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 uint32_t *pnn);

/**
 * ctdb_getdbstat - read the db stat of a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @db_id:    the database to collect the statistics from
 * @stat: a pointer to the *stat to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * This returns false if something went wrong, or otherwise fills in **stat
 * stat must be freed later by calling ctdb_free_dbstat();
 */
bool ctdb_getdbstat(struct ctdb_connection *ctdb,
		    uint32_t destnode,
		    uint32_t db_id,
		    struct ctdb_db_statistics **stat);


/**
 * ctdb_check_message_handlers - check a list of message_handlers (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @num: number of srvids to check
 * @mhs: @num message_handlers to check
 * @result: an array of @num uint8_t fields containing the result of the check
 *     0: message_handler does not exist
 *     1: message_handler exists
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 */
bool
ctdb_check_message_handlers(struct ctdb_connection *ctdb,
			   uint32_t destnode,
			   uint32_t num,
			   uint64_t *mhs,
			   uint8_t *result);

/**
 * ctdb_getcapabilities - read the capabilities of a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @capabilities: a pointer to the capabilities to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *capabilities on success.
 */
bool ctdb_getcapabilities(struct ctdb_connection *ctdb,
			  uint32_t destnode,
			  uint32_t *capabilities);


/**
 * ctdb_getdbseqnum - read the seqnum of a database
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @dbid: database id
 * @seqnum: sequence number for the database
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *pnn on success.
 */
bool
ctdb_getdbseqnum(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 uint32_t dbid,
		 uint64_t *seqnum);

/**
 * ctdb_getrecmaster - read the recovery master of a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @recmaster: a pointer to the recmaster to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *recmaster on success.
 */
bool ctdb_getrecmaster(struct ctdb_connection *ctdb,
		       uint32_t destnode,
		       uint32_t *recmaster);


/**
 * ctdb_getrecmode - read the recovery mode of a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @recmode: a pointer to the recmode to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *recmode on success.
 */
bool ctdb_getrecmode(struct ctdb_connection *ctdb,
		     uint32_t destnode,
		     uint32_t *recmode);


/**
 * ctdb_getnodemap - read the nodemap from a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @nodemap: a pointer to the nodemap to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *nodemap on success.
 * A non-NULL nodemap must be freed by calling ctdb_free_nodemap.
 */
bool ctdb_getnodemap(struct ctdb_connection *ctdb,
		     uint32_t destnode, struct ctdb_node_map **nodemap);

/**
 * ctdb_getifaces - read the list of interfaces from a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @ifaces: a pointer to the ifaces to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *ifaces on success.
 * A non-NULL value of the ifaces must be release released/freed
 * by ctdb_free_ifaces().
 */
bool ctdb_getifaces(struct ctdb_connection *ctdb,
		    uint32_t destnode, struct ctdb_ifaces_list **ifaces);

/*
 * This function is used to release/free the nodemap structure returned
 * by ctdb_getnodemap() and ctdb_getnodemap_recv()
 */
void ctdb_free_nodemap(struct ctdb_node_map *nodemap);


/**
 * ctdb_getpublicips - read the public ip list from a node.
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @ips: a pointer to the returned public ip list
 *
 * This control returns the list of public ips known to the local node.
 * Deamons only know about those ips that are listed in the local
 * public addresses file, which means the returned list of ips may
 * be only a subset of all ips across the entire cluster.
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * This returns false if something went wrong.
 * If the command failed, it guarantees to set ips to NULL.
 * A non-NULL value for nodemap means the command was successful.
 *
 * A non-NULL value of the nodemap must be release released/freed
 * by ctdb_free_publicips().
 */
bool ctdb_getpublicips(struct ctdb_connection *ctdb,
		     uint32_t destnode, struct ctdb_all_public_ips **ips);

/*
 * This function is used to release/free the public ip structure returned
 * by ctdb_getpublicips() and ctdb_getpublicips_recv()
 */
void ctdb_free_publicips(struct ctdb_all_public_ips *ips);


/**
 * ctdb_getvnnmap - read the vnn map from a node (synchronous)
 * @ctdb: the ctdb_connection from ctdb_connect.
 * @destnode: the destination node (see below)
 * @vnnmap: a pointer to the vnnmap to fill in
 *
 * There are several special values for destnode, detailed in
 * ctdb_protocol.h, particularly CTDB_CURRENT_NODE which means the
 * local ctdbd.
 *
 * Returns true and fills in *vnnmap on success.
 * A non-NULL value of the vnnmap must be  released/freed
 * by ctdb_free_vnnmap().
 */
bool ctdb_getvnnmap(struct ctdb_connection *ctdb,
		    uint32_t destnode, struct ctdb_vnn_map **vnnmap);

/*
 * This function is used to release/free the vnnmap structure returned
 * by ctdb_getvnnmap() and ctdb_getvnnmap_recv()
 */
void ctdb_free_vnnmap(struct ctdb_vnn_map *vnnmap);

/* These ugly macro wrappers make the callbacks typesafe. */
#include <ctdb_typesafe_cb.h>
#define ctdb_sendcb(cb, cbdata)						\
	 typesafe_cb_preargs(void, (cb), (cbdata),			\
			     struct ctdb_connection *, struct ctdb_request *)

#define ctdb_msgcb(cb, cbdata)						\
	typesafe_cb_preargs(void, (cb), (cbdata),			\
			    struct ctdb_connection *, uint64_t, TDB_DATA)

#define ctdb_connect(addr, log, logpriv)				\
	ctdb_connect((addr),						\
		     typesafe_cb_postargs(void, (log), (logpriv),	\
					  int, const char *, va_list),	\
		     (logpriv))

#define ctdb_set_message_handler(ctdb, srvid, handler, hdata)		\
	ctdb_set_message_handler((ctdb), (srvid),			\
				 ctdb_msgcb((handler), (hdata)), (hdata))

#define ctdb_remove_message_handler(ctdb, srvid, handler, hdata)	\
	ctdb_remove_message_handler((ctdb), (srvid),			\
				    ctdb_msgcb((handler), (hdata)), (hdata))

#define ctdb_attachdb_send(ctdb, name, persistent, tdb_flags, cb, cbdata) \
	ctdb_attachdb_send((ctdb), (name), (persistent), (tdb_flags),	\
			   ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_readrecordlock_async(_ctdb_db, key, cb, cbdata)		\
	ctdb_readrecordlock_async((_ctdb_db), (key),			\
		typesafe_cb_preargs(void, (cb), (cbdata),		\
				    struct ctdb_db *, struct ctdb_lock *, \
				    TDB_DATA), (cbdata))

#define ctdb_set_message_handler_send(ctdb, srvid, handler, hdata, cb, cbdata) \
	ctdb_set_message_handler_send((ctdb), (srvid),			\
				      ctdb_msgcb((handler), (hdata)), (hdata), \
				      ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_remove_message_handler_send(ctdb, srvid, handler, hdata, cb, cbdata) \
	ctdb_remove_message_handler_send((ctdb), (srvid),		\
	      ctdb_msgcb((handler), (hdata)), (hdata),			\
	      ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getpnn_send(ctdb, destnode, cb, cbdata)			\
	ctdb_getpnn_send((ctdb), (destnode),				\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getcapabilities_send(ctdb, destnode, cb, cbdata)		\
	ctdb_getcapabilities_send((ctdb), (destnode),			\
				  ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getdbstat_send(ctdb, destnode, db_id, cb, cbdata)		\
	ctdb_getdbstat_send((ctdb), (destnode), (db_id),		\
			    ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_check_message_handlers_send(ctdb, destnode, num, mhs,	\
			 cb, cbdata)					\
	ctdb_check_message_handlers_send((ctdb), (destnode), (num), 	\
			 (mhs),						\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getrecmaster_send(ctdb, destnode, cb, cbdata)		\
	ctdb_getrecmaster_send((ctdb), (destnode),			\
			       ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getrecmode_send(ctdb, destnode, cb, cbdata)		\
	ctdb_getrecmode_send((ctdb), (destnode),			\
			       ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getnodemap_send(ctdb, destnode, cb, cbdata)		\
	ctdb_getnodemap_send((ctdb), (destnode),			\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getpublicips_send(ctdb, destnode, cb, cbdata)		\
	ctdb_getpublicips_send((ctdb), (destnode),			\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getdbseqnum_send(ctdb, destnode, dbid, cb, cbdata)		\
	ctdb_getdbseqnum_send((ctdb), (destnode), (dbid),		\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getifaces_send(ctdb, destnode, cb, cbdata)			\
	ctdb_getifaces_send((ctdb), (destnode),				\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#define ctdb_getvnnmap_send(ctdb, destnode, cb, cbdata)			\
	ctdb_getvnnmap_send((ctdb), (destnode),				\
			 ctdb_sendcb((cb), (cbdata)), (cbdata))

#endif
