/* 
   ctdb database library

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _CTDB_H
#define _CTDB_H

struct ctdb_call {
	int call_id;
	TDB_DATA key;
	TDB_DATA call_data;
	TDB_DATA reply_data;
	uint32_t status;
};

/*
  structure passed to a ctdb call backend function
*/
struct ctdb_call_info {
	TDB_DATA key;          /* record key */
	TDB_DATA record_data;  /* current data in the record */
	TDB_DATA *new_data;    /* optionally updated record data */
	TDB_DATA *call_data;   /* optionally passed from caller */
	TDB_DATA *reply_data;  /* optionally returned by function */
	uint32_t status;       /* optional reply status - defaults to zero */
};

#define CTDB_ERR_INVALID 1
#define CTDB_ERR_NOMEM 2

/*
  ctdb flags
*/
#define CTDB_FLAG_SELF_CONNECT (1<<0)


struct event_context;

/*
  initialise ctdb subsystem
*/
struct ctdb_context *ctdb_init(struct event_context *ev);

/*
  choose the transport
*/
int ctdb_set_transport(struct ctdb_context *ctdb, const char *transport);

/*
  set some flags
*/
void ctdb_set_flags(struct ctdb_context *ctdb, unsigned flags);

/*
  set max acess count before a dmaster migration
*/
void ctdb_set_max_lacount(struct ctdb_context *ctdb, unsigned count);

/*
  tell ctdb what address to listen on, in transport specific format
*/
int ctdb_set_address(struct ctdb_context *ctdb, const char *address);

/*
  tell ctdb what nodes are available. This takes a filename, which will contain
  1 node address per line, in a transport specific format
*/
int ctdb_set_nlist(struct ctdb_context *ctdb, const char *nlist);

/*
  start the ctdb protocol
*/
int ctdb_start(struct ctdb_context *ctdb);

/*
  attach to a ctdb database
*/
struct ctdb_db_context *ctdb_attach(struct ctdb_context *ctdb, const char *name, int tdb_flags, 
				    int open_flags, mode_t mode);

/*
  find an attached ctdb_db handle given a name
 */
struct ctdb_db_context *ctdb_db_handle(struct ctdb_context *ctdb, const char *name);

/*
  error string for last ctdb error
*/
const char *ctdb_errstr(struct ctdb_context *);

/* a ctdb call function */
typedef int (*ctdb_fn_t)(struct ctdb_call_info *);

/*
  setup a ctdb call function
*/
int ctdb_set_call(struct ctdb_db_context *ctdb_db, ctdb_fn_t fn, int id);



/*
  make a ctdb call. The associated ctdb call function will be called on the DMASTER
  for the given record
*/
int ctdb_call(struct ctdb_db_context *ctdb_db, struct ctdb_call *call);

/*
  wait for all nodes to be connected - useful for test code
*/
void ctdb_connect_wait(struct ctdb_context *ctdb);

/*
  wait until we're the only node left
*/
void ctdb_wait_loop(struct ctdb_context *ctdb);

/* return vnn of this node */
uint32_t ctdb_get_vnn(struct ctdb_context *ctdb);

/*
  return the number of nodes
*/
uint32_t ctdb_get_num_nodes(struct ctdb_context *ctdb);

/* setup a handler for ctdb messages */
typedef void (*ctdb_message_fn_t)(struct ctdb_context *, uint32_t srvid, 
				  TDB_DATA data, void *);
int ctdb_set_message_handler(struct ctdb_context *ctdb, ctdb_message_fn_t handler,
			     void *private);

/* send a ctdb message */
int ctdb_send_message(struct ctdb_context *ctdb, uint32_t vnn,
		      uint32_t srvid, TDB_DATA data);

/* 
   fetch and lock a ctdb record. Underneath this will force the
   dmaster for the record to be moved to the local node. 

   The lock is released when is talloc_free() is called on the
   returned ctdb_record_handle. 
*/
struct ctdb_record_handle *ctdb_fetch_lock(struct ctdb_db_context *ctdb_db, TDB_DATA key, TDB_DATA *data);

/*
  change the data in a record held with a ctdb_record_handle
  if the new data is zero length, this implies a delete of the record
 */
int ctdb_record_store(struct ctdb_record_handle *rec, TDB_DATA data);

#endif
