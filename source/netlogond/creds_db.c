/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   
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

extern int DEBUGLEVEL;

static TDB_CONTEXT *db = NULL;

static char *make_creds_key(const char *domain, const char* wks, int *klen)
{
	char *k;
	int domlen = strlen(domain);
	int wkslen = strlen(wks);

	(*klen) = domlen + wkslen + 2;
	k = malloc((*klen) * sizeof(char));

	if (k != NULL)
	{
		safe_strcpy(k, domain, domlen);
		safe_strcpy(k+domlen+1, wks   , wkslen);
		strlower(k);
		strlower(k+domlen+1);

		DEBUG(10,("make_creds_key: dom %s wks %s\n",
		           domain, wks));
		dump_data(10, k, (*klen));
	}

	return k;
}

BOOL cred_get(const char *domain, const char* wks, struct dcinfo *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;

	DEBUG(10,("cred_get:\n"));

	k = make_creds_key(domain, wks, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen;

	data = tdb_fetch(db, key);

	free(k);

	if (data.dptr == NULL)
	{
		DEBUG(10,("cred_get: NULL data\n"));
		return False;
	}
	if (data.dsize != sizeof(*dc))
	{
		DEBUG(10,("cred_get: data size mismatch\n"));
		free(data.dptr);
		return False;
	}

	memcpy(dc, data.dptr, sizeof(*dc));
	free(data.dptr);

	dump_data(100, (char*)dc, sizeof(*dc));
	return True;
}

BOOL cred_store(const char *domain, const char* wks, struct dcinfo *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;
	BOOL ret;

	DEBUG(10,("cred_store:\n"));

	k = make_creds_key(domain, wks, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen;

	data.dptr  = (char*)dc;
	data.dsize = sizeof(*dc);

	ret = (tdb_store(db, key, data, TDB_REPLACE) == 0);

	free(k);

	dump_data(100, (char*)dc, sizeof(*dc));

	if (!ret)
	{
		DEBUG(0,("cred_store: failed\n"));
	}
	return ret;
}

BOOL cred_init_db(void)
{
	db = tdb_open(lock_path("netlogoncreds.tdb"), 0, 0, 
		      O_RDWR | O_CREAT, 0600);

	if (db == NULL)
	{
		DEBUG(0,("cred_init_db: failed\n"));
		return False;
	}
	
	DEBUG(10,("cred_init_db: opened\n"));

	return True;
}
