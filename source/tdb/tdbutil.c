/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   tdb utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
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

/* these are little tdb utility functions that are meant to make
   dealing with a tdb database a little less cumbersome in Samba */


/* fetch a value by a arbitrary blob key, return -1 if not found */
int tdb_get_int_byblob(TDB_CONTEXT *tdb, char *keyval, size_t len)
{
	TDB_DATA key, data;
	int ret;

	key.dptr = keyval;
	key.dsize = len;
	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(int)) return -1;
	
	memcpy(&ret, data.dptr, sizeof(int));
	free(data.dptr);
	return ret;
}

/* fetch a value by string key, return -1 if not found */
int tdb_get_int(TDB_CONTEXT *tdb, char *keystr)
{
	return tdb_get_int_byblob(tdb, keystr, strlen(keystr));
}

/* store a value by an arbitary blob key, return 0 on success, -1 on failure */
int tdb_store_int_byblob(TDB_CONTEXT *tdb, char *keystr, size_t len, int v)
{
	TDB_DATA key, data;

	key.dptr = keystr;
	key.dsize = len;
	data.dptr = (void *)&v;
	data.dsize = sizeof(int);

	return tdb_store(tdb, key, data, TDB_REPLACE);
}

/* store a value by string key, return 0 on success, -1 on failure */
int tdb_store_int(TDB_CONTEXT *tdb, char *keystr, int v)
{
	return tdb_store_int_byblob(tdb, keystr, strlen(keystr), v);
}
