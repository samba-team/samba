/* 
   ctdb_control protocol code to manage server ids

   Copyright (C) Ronnie Sahlberg 2007

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
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"


#define SERVER_ID_KEY_SIZE 3
static uint32_t *get_server_id_key(struct ctdb_server_id *server_id)
{
	static uint32_t key[SERVER_ID_KEY_SIZE];

	key[0] = server_id->type;
	key[1] = server_id->vnn;
	key[2] = server_id->server_id;

	return &key[0];
}

/* add a server_id to the tree.
   if we had already 'data' in the tree then this is a duplicate and we can
   just talloc_free the structure in parm and leave data in the tree.
   othervise if this is a new node we return parm and that is inserted
   into the tree.
*/
static void *add_server_id_callback(void *parm, void *data)
{
	if (data) {
		talloc_free(parm);
		return data;
	}
	return parm;
}

/*
  register a server id
  a serverid that is registered with ctdb will be automatically unregistered
  once the client domain socket dissappears.
 */
int32_t ctdb_control_register_server_id(struct ctdb_context *ctdb, 
				 uint32_t client_id,
				 TDB_DATA indata)
{
	struct ctdb_server_id *server_id;
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);


	if (client == NULL) {
		DEBUG(0,(__location__ " Could not find client parent structure. You can not send this control to a remote node\n"));
		return 1;
	}

	/* hang the server_id structure off client before storing it in the
	   tree so that is will be automatically destroyed when client
	   is destroyed. 
	   when the structure is free'd it will be automatically
	   removed from the tree
	*/
	server_id = talloc_memdup(client, indata.dptr, indata.dsize);
	CTDB_NO_MEMORY(ctdb, server_id);

	trbt_insertarray32_callback(ctdb->server_ids, SERVER_ID_KEY_SIZE,
		get_server_id_key(server_id), 
		add_server_id_callback, server_id);

	return 0;
}


/*
  check whether a server id exists
 */
int32_t ctdb_control_check_server_id(struct ctdb_context *ctdb, 
				 TDB_DATA indata)
{
	struct ctdb_server_id *server_id = (struct ctdb_server_id *)indata.dptr;

	return (int32_t)trbt_lookuparray32(ctdb->server_ids, 
				SERVER_ID_KEY_SIZE,
				get_server_id_key(server_id));
}

/*
  unregisters a server id
 */
int32_t ctdb_control_unregister_server_id(struct ctdb_context *ctdb, 
				 TDB_DATA indata)
{
	struct ctdb_server_id *server_id = (struct ctdb_server_id *)indata.dptr;

	talloc_free(trbt_lookuparray32(ctdb->server_ids, 
			SERVER_ID_KEY_SIZE,
			get_server_id_key(server_id)));
	return 0;
}


