/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   connection claim routines
   Copyright (C) Andrew Tridgell 1998
   
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


extern fstring remote_machine;
static TDB_CONTEXT *tdb;

extern int DEBUGLEVEL;

/****************************************************************************
delete a connection record
****************************************************************************/
BOOL yield_connection(connection_struct *conn,char *name,int max_connections)
{
	struct connections_key key;
	TDB_DATA kbuf;

	if (!tdb) return False;

	DEBUG(3,("Yielding connection to %s\n",name));

	ZERO_STRUCT(key);
	key.pid = getpid();
	if (conn) key.cnum = conn->cnum;
	fstrcpy(key.name, name);

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	tdb_delete(tdb, kbuf);
	return(True);
}


/****************************************************************************
claim an entry in the connections database
****************************************************************************/
BOOL claim_connection(connection_struct *conn,char *name,int max_connections,BOOL Clear)
{
	struct connections_key key;
	struct connections_data crec;
	TDB_DATA kbuf, dbuf;

	if (max_connections <= 0)
		return(True);

	if (!tdb) {
		tdb = tdb_open(lock_path("connections.tdb"), 0, TDB_CLEAR_IF_FIRST, 
			       O_RDWR | O_CREAT, 0644);
	}
	if (!tdb) return False;

	DEBUG(5,("claiming %s %d\n",name,max_connections));

	ZERO_STRUCT(key);
	key.pid = getpid();
	key.cnum = conn?conn->cnum:-1;
	fstrcpy(key.name, name);

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	/* fill in the crec */
	ZERO_STRUCT(crec);
	crec.magic = 0x280267;
	crec.pid = getpid();
	crec.cnum = conn?conn->cnum:-1;
	if (conn) {
		crec.uid = conn->uid;
		crec.gid = conn->gid;
		StrnCpy(crec.name,
			lp_servicename(SNUM(conn)),sizeof(crec.name)-1);
	}
	crec.start = time(NULL);
	
	StrnCpy(crec.machine,remote_machine,sizeof(crec.machine)-1);
	StrnCpy(crec.addr,conn?conn->client_address:client_connection_addr(),sizeof(crec.addr)-1);

	dbuf.dptr = (char *)&crec;
	dbuf.dsize = sizeof(crec);

	if (tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) != 0) return False;

	return True;
}
