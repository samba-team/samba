/* 
   Unix SMB/CIFS implementation.
   SMB client library implementation (server cache)
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002 
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/*
 * Define this to get the real SMBCFILE and SMBCSRV structures 
 */
#define _SMBC_INTERNAL
#include "../include/libsmbclient.h"

/*
 * Structure we use if internal caching mechanism is used 
 * nothing fancy here.
 */
struct smbc_server_cache {
	char *server_name;
	char *share_name;
	char *workgroup;
	char *username;
	SMBCSRV *server;
	
	struct smbc_server_cache *next, *prev;
};
	


/*
 * Add a new connection to the server cache.
 * This function is only used if the external cache is not enabled 
 */
static int smbc_add_cached_server(SMBCCTX * context, SMBCSRV * new,
				  const char * server, const char * share, 
				  const char * workgroup, const char * username)
{
	struct smbc_server_cache * srvcache = NULL;

	if (!(srvcache = malloc(sizeof(*srvcache)))) {
		errno = ENOMEM;
		DEBUG(3, ("Not enough space for server cache allocation\n"));
		return 1;
	}
       
	ZERO_STRUCTP(srvcache);

	srvcache->server = new;

	srvcache->server_name = strdup(server);
	if (!srvcache->server_name) {
		errno = ENOMEM;
		goto failed;
	}

	srvcache->share_name = strdup(share);
	if (!srvcache->share_name) {
		errno = ENOMEM;
		goto failed;
	}

	srvcache->workgroup = strdup(workgroup);
	if (!srvcache->workgroup) {
		errno = ENOMEM;
		goto failed;
	}

	srvcache->username = strdup(username);
	if (!srvcache->username) {
		errno = ENOMEM;
		goto failed;
	}

	DLIST_ADD((context->server_cache), srvcache);
	return 0;

 failed:
	SAFE_FREE(srvcache->server_name);
	SAFE_FREE(srvcache->share_name);
	SAFE_FREE(srvcache->workgroup);
	SAFE_FREE(srvcache->username);
	
	return 1;
}



/*
 * Search the server cache for a server 
 * returns server_fd on success, -1 on error (not found)
 * This function is only used if the external cache is not enabled 
 */
static SMBCSRV * smbc_get_cached_server(SMBCCTX * context, const char * server, 
				  const char * share, const char * workgroup, const char * user)
{
	struct smbc_server_cache * srv = NULL;
	
	/* Search the cache lines */
	for (srv=((struct smbc_server_cache *)context->server_cache);srv;srv=srv->next) {
		if (strcmp(server,srv->server_name)  == 0 &&
		    strcmp(share,srv->share_name)    == 0 &&
		    strcmp(workgroup,srv->workgroup) == 0 &&
		    strcmp(user, srv->username)  == 0) 
			return srv->server;
	}

	return NULL;
}


/* 
 * Search the server cache for a server and remove it
 * returns 0 on success
 * This function is only used if the external cache is not enabled 
 */
static int smbc_remove_cached_server(SMBCCTX * context, SMBCSRV * server)
{
	struct smbc_server_cache * srv = NULL;
	
	for (srv=((struct smbc_server_cache *)context->server_cache);srv;srv=srv->next) {
		if (server == srv->server) { 

			/* remove this sucker */
			DLIST_REMOVE(context->server_cache, srv);
			SAFE_FREE(srv->server_name);
			SAFE_FREE(srv->share_name);
			SAFE_FREE(srv->workgroup);
			SAFE_FREE(srv->username);
			SAFE_FREE(srv);
			return 0;
		}
	}
	/* server not found */
	return 1;
}


/*
 * Try to remove all the servers in cache
 * returns 1 on failure and 0 if all servers could be removed.
 */
static int smbc_purge_cached(SMBCCTX * context)
{
	struct smbc_server_cache * srv;
	struct smbc_server_cache * next;
	int could_not_purge_all = 0;

	for (srv = ((struct smbc_server_cache *) context->server_cache),
                 next = (srv ? srv->next :NULL);
             srv;
             srv = next, next = (srv ? srv->next : NULL)) {

		if (smbc_remove_unused_server(context, srv->server)) {
			/* could not be removed */
			could_not_purge_all = 1;
		}
	}
	return could_not_purge_all;
}



/*
 * This functions initializes all server-cache related functions 
 * to the default (internal) system.
 *
 * We use this to make the rest of the cache system static.
 */

int smbc_default_cache_functions(SMBCCTX * context)
{
	context->callbacks.add_cached_srv_fn    = smbc_add_cached_server;
	context->callbacks.get_cached_srv_fn    = smbc_get_cached_server;
	context->callbacks.remove_cached_srv_fn = smbc_remove_cached_server;
	context->callbacks.purge_cached_fn      = smbc_purge_cached;

	return 0;
}
