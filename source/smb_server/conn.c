/* 
   Unix SMB/CIFS implementation.
   Manage connections_struct structures
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Alexander Bokovoy 2002
   
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

/* set these to define the limits of the server. NOTE These are on a
   per-client basis. Thus any one machine can't connect to more than
   MAX_CONNECTIONS services, but any number of machines may connect at
   one time. */
#define MAX_CONNECTIONS 128

/****************************************************************************
init the conn structures
****************************************************************************/
void conn_init(struct server_context *smb)
{
	smb->tree.bmap = bitmap_allocate(MAX_CONNECTIONS);
}

/****************************************************************************
check if a snum is in use
****************************************************************************/
BOOL conn_snum_used(struct server_context *smb, int snum)
{
	struct tcon_context *conn;
	for (conn=smb->tree.connections;conn;conn=conn->next) {
		if (conn->service == snum) {
			return(True);
		}
	}
	return(False);
}


/****************************************************************************
find a conn given a cnum
****************************************************************************/
struct tcon_context *conn_find(struct server_context *smb, unsigned cnum)
{
	int count=0;
	struct tcon_context *conn;

	for (conn=smb->tree.connections;conn;conn=conn->next,count++) {
		if (conn->cnum == cnum) {
			if (count > 10) {
				DLIST_PROMOTE(smb->tree.connections, conn);
			}
			return conn;
		}
	}

	return NULL;
}


/****************************************************************************
  find first available connection slot, starting from a random position.
The randomisation stops problems with the server dieing and clients
thinking the server is still available.
****************************************************************************/
struct tcon_context *conn_new(struct server_context *smb)
{
	TALLOC_CTX *mem_ctx;
	struct tcon_context *conn;
	int i;

	i = bitmap_find(smb->tree.bmap, 1);
	
	if (i == -1) {
		DEBUG(1,("ERROR! Out of connection structures\n"));	       
		return NULL;
	}

	mem_ctx = talloc_init("tcon_context[%d]", i);

	conn = (struct tcon_context *)talloc(mem_ctx, sizeof(*conn));
	if (!conn) return NULL;

	ZERO_STRUCTP(conn);

	conn->mem_ctx = mem_ctx;
	conn->cnum = i;
	conn->smb = smb;

	bitmap_set(smb->tree.bmap, i);

	smb->tree.num_open++;

	DLIST_ADD(smb->tree.connections, conn);

	return conn;
}

/****************************************************************************
close all conn structures
****************************************************************************/
void conn_close_all(struct server_context *smb)
{
	struct tcon_context *conn, *next;
	for (conn=smb->tree.connections;conn;conn=next) {
		next=conn->next;
		close_cnum(conn);
	}
}


#if REWRITE_REMOVED
/****************************************************************************
clear a vuid out of the validity cache, and as the 'owner' of a connection.
****************************************************************************/
void conn_clear_vuid_cache(struct server_context *smb, uint16_t vuid)
{
	struct tcon_context *conn;
	unsigned int i;

	for (conn=smb->tree.connections;conn;conn=conn->next) {
		for (i=0;i<conn->vuid_cache.entries && i< VUID_CACHE_SIZE;i++) {
			if (conn->vuid_cache.list[i] == vuid) {
				conn->vuid_cache.list[i] = UID_FIELD_INVALID;
			}
		}
	}
}
#endif

/****************************************************************************
 Free a conn structure.
****************************************************************************/

void conn_free(struct server_context *smb, struct tcon_context *conn)
{
	DLIST_REMOVE(smb->tree.connections, conn);

	bitmap_clear(smb->tree.bmap, conn->cnum);
	smb->tree.num_open--;

	talloc_destroy(conn->mem_ctx);
}

