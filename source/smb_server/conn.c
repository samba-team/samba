/* 
   Unix SMB/CIFS implementation.
   Manage smbsrv_tcon structures
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
init the tcon structures
****************************************************************************/
void conn_init(struct smbsrv_context *smb_ctx)
{
	smb_ctx->tree.bmap = bitmap_allocate(MAX_CONNECTIONS);
}

/****************************************************************************
check if a snum is in use
****************************************************************************/
BOOL conn_snum_used(struct smbsrv_context *smb_ctx, int snum)
{
	struct smbsrv_tcon *tcon;
	for (tcon=smb_ctx->tree.tcons;tcon;tcon=tcon->next) {
		if (tcon->service == snum) {
			return(True);
		}
	}
	return(False);
}


/****************************************************************************
find a tcon given a cnum
****************************************************************************/
struct smbsrv_tcon *conn_find(struct smbsrv_context *smb_ctx, uint_t cnum)
{
	int count=0;
	struct smbsrv_tcon *tcon;

	for (tcon=smb_ctx->tree.tcons;tcon;tcon=tcon->next,count++) {
		if (tcon->cnum == cnum) {
			if (count > 10) {
				DLIST_PROMOTE(smb_ctx->tree.tcons, tcon);
			}
			return tcon;
		}
	}

	return NULL;
}


/****************************************************************************
  find first available connection slot, starting from a random position.
The randomisation stops problems with the server dieing and clients
thinking the server is still available.
****************************************************************************/
struct smbsrv_tcon *conn_new(struct smbsrv_context *smb_ctx)
{
	TALLOC_CTX *mem_ctx;
	struct smbsrv_tcon *tcon;
	int i;

	i = bitmap_find(smb_ctx->tree.bmap, 1);
	
	if (i == -1) {
		DEBUG(1,("ERROR! Out of connection structures\n"));	       
		return NULL;
	}

	mem_ctx = talloc_init("smbsrv_tcon[%d]", i);

	tcon = talloc_p(mem_ctx, struct smbsrv_tcon);
	if (!tcon) return NULL;

	ZERO_STRUCTP(tcon);

	tcon->mem_ctx = mem_ctx;
	tcon->cnum = i;
	tcon->smb_ctx = smb_ctx;

	bitmap_set(smb_ctx->tree.bmap, i);

	smb_ctx->tree.num_open++;

	DLIST_ADD(smb_ctx->tree.tcons, tcon);

	return tcon;
}

/****************************************************************************
close all tcon structures
****************************************************************************/
void conn_close_all(struct smbsrv_context *smb_ctx)
{
	struct smbsrv_tcon *tcon, *next;
	for (tcon=smb_ctx->tree.tcons;tcon;tcon=next) {
		next=tcon->next;
		close_cnum(tcon);
	}
}


#if REWRITE_REMOVED
/****************************************************************************
clear a vuid out of the validity cache, and as the 'owner' of a connection.
****************************************************************************/
void conn_clear_vuid_cache(struct smbsrv_context *smb_ctx, uint16_t vuid)
{
	struct smbsrv_tcon *tcon;
	uint_t i;

	for (tcon=smb_ctx->tree.tcons;tcon;tcon=tcon->next) {
		for (i=0;i<tcon->vuid_cache.entries && i< VUID_CACHE_SIZE;i++) {
			if (tcon->vuid_cache.list[i] == vuid) {
				tcon->vuid_cache.list[i] = UID_FIELD_INVALID;
			}
		}
	}
}
#endif

/****************************************************************************
 Free a tcon structure.
****************************************************************************/

void conn_free(struct smbsrv_context *smb_ctx, struct smbsrv_tcon *tcon)
{
	DLIST_REMOVE(smb_ctx->tree.tcons, tcon);

	bitmap_clear(smb_ctx->tree.bmap, tcon->cnum);
	smb_ctx->tree.num_open--;

	talloc_destroy(tcon->mem_ctx);
}

