/* 
   Unix SMB/Netbios implementation.
   Version 3.0.
   Samba registry functions
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

/* the Samba secrets database stores any generated, private information
   such as the local SID and machine trust password */

#include "includes.h"

static TDB_CONTEXT *tdb;

/* open up the secrets database */
BOOL secrets_init(void)
{
	pstring fname;
	char *p;

	if (tdb) return True;

	pstrcpy(fname, lp_smb_passwd_file());
	p = strrchr(fname, '/');
	if(!p) return False;

	*p = 0;
	pstrcat(fname,"/secrets.tdb");

	tdb = tdb_open(fname, 0, 0, O_RDWR|O_CREAT, 0600);

	if (!tdb) {
		DEBUG(0,("Failed to open %s\n", fname));
		return False;
	}
	return True;
}

/* read a entry from the secrets database - the caller must free the result
   if size is non-null then the size of the entry is put in there
 */
void *secrets_fetch(char *key, size_t *size)
{
	TDB_DATA kbuf, dbuf;
	if (!tdb) return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	dbuf = tdb_fetch(tdb, kbuf);
	if (size) *size = dbuf.dsize;
	return dbuf.dptr;
}

/* store a secrets entry 
 */
BOOL secrets_store(char *key, void *data, size_t size)
{
	TDB_DATA kbuf, dbuf;
	if (!tdb) return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	dbuf.dptr = data;
	dbuf.dsize = size;
	return tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) == 0;
}


/* delete a secets database entry
 */
BOOL secrets_delete(char *key)
{
	TDB_DATA kbuf;
	if (!tdb) return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	return tdb_delete(tdb, kbuf) == 0;
}

BOOL secrets_store_domain_sid(char *domain, DOM_SID *sid)
{
	fstring key;

	slprintf(key, sizeof(key), "%s/%s", SECRETS_DOMAIN_SID, domain);
	return secrets_store(key, sid, sizeof(DOM_SID));
}

BOOL secrets_fetch_domain_sid(char *domain, DOM_SID *sid)
{
	DOM_SID *dyn_sid;
	fstring key;
	int size;

	slprintf(key, sizeof(key), "%s/%s", SECRETS_DOMAIN_SID, domain);
	dyn_sid = (DOM_SID *)secrets_fetch(key, &size);

	if (dyn_sid == NULL)
		return False;

	if (size != sizeof(DOM_SID))
	{ 
		free(dyn_sid);
		return False;
	}

	*sid = *dyn_sid;
	free(dyn_sid);
	return True;
}

