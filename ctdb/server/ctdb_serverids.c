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
	key[1] = server_id->pnn;
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
		DEBUG(DEBUG_ERR,(__location__ " Could not find client parent structure. You can not send this control to a remote node\n"));
		return 1;
	}

	/* hang the server_id structure off client before storing it in the
	   tree so that is will be automatically destroyed when client
	   is destroyed. 
	   when the structure is free'd it will be automatically
	   removed from the tree
	*/
	server_id = talloc_zero(client, struct ctdb_server_id);
	CTDB_NO_MEMORY(ctdb, server_id);
	memcpy(server_id, indata.dptr, sizeof(struct ctdb_server_id));

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

	return trbt_lookuparray32(ctdb->server_ids, 
				  SERVER_ID_KEY_SIZE,
				  get_server_id_key(server_id)) == NULL? 0 : 1;
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




struct count_server_ids {
	int count;
	struct ctdb_server_id_list *list;
};

static int server_id_count(void *param, void *data)
{
	struct count_server_ids *svid = talloc_get_type(param, 
						struct count_server_ids);

	if (svid == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Got null pointer for svid\n"));
		return -1;
	}

	svid->count++;
	return 0;
}

static int server_id_store(void *param, void *data)
{
	struct count_server_ids *svid = talloc_get_type(param, 
						struct count_server_ids);
	struct ctdb_server_id *server_id = talloc_get_type(data, 
						struct ctdb_server_id);

	if (svid == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Got null pointer for svid\n"));
		return -1;
	}

	if (svid->count >= svid->list->num) {
		DEBUG(DEBUG_ERR, (__location__ " size of server id tree changed during traverse\n"));
		return -1;
	}

	memcpy(&svid->list->server_ids[svid->count], server_id, sizeof(struct ctdb_server_id));
	svid->count++;
	return 0;
}

/* 
   returns a list of all registered server ids for a node
*/
int32_t ctdb_control_get_server_id_list(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	struct count_server_ids *svid;


	svid = talloc_zero(outdata, struct count_server_ids);
	CTDB_NO_MEMORY(ctdb, svid);


	/* first we must count how many entries we have */
	trbt_traversearray32(ctdb->server_ids, SERVER_ID_KEY_SIZE,
			server_id_count, svid);


	outdata->dsize = offsetof(struct ctdb_server_id_list, 
				server_ids)
			+ sizeof(struct ctdb_server_id) * svid->count;
	outdata->dptr  = talloc_size(outdata, outdata->dsize);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);


	/* now fill the structure in */
	svid->list = (struct ctdb_server_id_list *)(outdata->dptr);
	svid->list->num = svid->count;
	svid->count=0;
	trbt_traversearray32(ctdb->server_ids, SERVER_ID_KEY_SIZE,
			server_id_store, svid);


	return 0;
}
