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

extern int DEBUGLEVEL;

/****************************************************************************
open the connections database
****************************************************************************/
TDB_CONTEXT *open_db(char *name)
{
	pstring fname;

	pstrcpy(fname,lp_lockdir());
	trim_string(fname,"","/");
	
	if (!directory_exist(fname,NULL)) {
		mkdir(fname,0755);
	}
	
	pstrcat(fname,"/connections.tdb");
	
	return tdb_open(fname, 0, O_RDWR | O_CREAT, 0644);
}



/****************************************************************************
delete a connection record
****************************************************************************/
BOOL yield_connection(connection_struct *conn,char *name,int max_connections)
{
	struct connections_key key;
	TDB_DATA kbuf;
	TDB_CONTEXT *tdb;

	if (!(tdb = open_db(name))) return False;

	DEBUG(3,("Yielding connection to %s\n",name));

	ZERO_STRUCT(key);
	key.pid = getpid();
	if (conn) key.cnum = conn->cnum;
	fstrcpy(key.name, name);

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	tdb_delete(tdb, kbuf);
	tdb_close(tdb);
	return(True);
}


/****************************************************************************
claim an entry in the connections database
****************************************************************************/
int delete_dead(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf)
{
	struct connections_key key;
	memcpy(&key, kbuf.dptr, sizeof(key));
	if (!process_exists(key.pid)) tdb_delete(tdb, kbuf);
	return 0;
}


/****************************************************************************
claim an entry in the connections database
****************************************************************************/
BOOL claim_connection(connection_struct *conn,char *name,int max_connections,BOOL Clear)
{
	struct connections_key key;
	struct connections_data crec;
	TDB_DATA kbuf, dbuf;
	TDB_CONTEXT *tdb;
	extern int Client;

	if (max_connections <= 0)
		return(True);
	
	if (!(tdb = open_db(name))) return False;

	DEBUG(5,("claiming %s %d\n",name,max_connections));

	ZERO_STRUCT(key);
	key.pid = getpid();
	key.cnum = conn?conn->cnum:-1;
	fstrcpy(key.name, name);

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	if (Clear) {
		tdb_traverse(tdb, delete_dead);
	}

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
	StrnCpy(crec.addr,conn?conn->client_address:client_addr(Client),sizeof(crec.addr)-1);

	dbuf.dptr = (char *)&crec;
	dbuf.dsize = sizeof(crec);

	if (tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) != 0) return False;

	tdb_close(tdb);

	return True;
}
