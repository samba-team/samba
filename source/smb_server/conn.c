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
#include "system/filesys.h"
#include "dlinklist.h"
#include "smb_server/smb_server.h"


/****************************************************************************
init the tcon structures
****************************************************************************/
void conn_init(struct smbsrv_connection *smb_conn)
{
	smb_conn->tree.idtree_tid = idr_init(smb_conn);
}

/****************************************************************************
find a tcon given a cnum
****************************************************************************/
struct smbsrv_tcon *conn_find(struct smbsrv_connection *smb_conn, uint_t cnum)
{
	return idr_find(smb_conn->tree.idtree_tid, cnum);
}

/*
  destroy a connection structure
*/
static int conn_destructor(void *ptr)
{
	struct smbsrv_tcon *tcon = ptr;
	idr_remove(tcon->smb_conn->tree.idtree_tid, tcon->cnum);
	DLIST_REMOVE(tcon->smb_conn->tree.tcons, tcon);
	return 0;
}

/*
  find first available connection slot
*/
struct smbsrv_tcon *conn_new(struct smbsrv_connection *smb_conn)
{
	struct smbsrv_tcon *tcon;
	int i;

	tcon = talloc_zero_p(smb_conn, struct smbsrv_tcon);
	if (!tcon) return NULL;

	i = idr_get_new(smb_conn->tree.idtree_tid, tcon, UINT16_MAX);
	if (i == -1) {
		DEBUG(1,("ERROR! Out of connection structures\n"));	       
		return NULL;
	}

	tcon->cnum = i;
	tcon->smb_conn = smb_conn;

	talloc_set_destructor(tcon, conn_destructor);

	DLIST_ADD(smb_conn->tree.tcons, tcon);

	return tcon;
}

/****************************************************************************
close all tcon structures
****************************************************************************/
void conn_close_all(struct smbsrv_connection *smb_conn)
{
	struct smbsrv_tcon *tcon, *next;
	for (tcon=smb_conn->tree.tcons;tcon;tcon=next) {
		next=tcon->next;
		close_cnum(tcon);
	}
}


/****************************************************************************
 Free a tcon structure.
****************************************************************************/
void conn_free(struct smbsrv_connection *smb_conn, struct smbsrv_tcon *tcon)
{
	talloc_free(tcon);
}

