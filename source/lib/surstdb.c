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

/* 
 * tdb implementation of a SURS (sid to uid resolution) table.
 */

#include "includes.h"
#include "sids.h"

extern int DEBUGLEVEL;

static TDB_CONTEXT *sdb = NULL;
static TDB_CONTEXT *udb = NULL;

static char *make_sid_key(uint32 pid, const char *domain, const char* wks, int *klen)
{
	char *k;
	int domlen = strlen(domain);
	int wkslen = strlen(wks);

	(*klen) = domlen + wkslen + 2 + sizeof(pid);
	k = malloc((*klen) * sizeof(char));

	if (k != NULL)
	{
		*((uint32*)k) = pid;
		safe_strcpy(k+sizeof(pid)         , domain, domlen);
		safe_strcpy(k+sizeof(pid)+domlen+1, wks   , wkslen);
		strlower(k+sizeof(pid));
		strlower(k+sizeof(pid)+domlen+1);

		DEBUG(10,("make_sid_key: pid: %x dom %s wks %s\n",
		           pid, domain, wks));
		dump_data(10, k, (*klen));
	}

	return k;
}

BOOL surs_get(uint32 pid, const char *domain, const char* wks, struct dcinfo *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;

	DEBUG(10,("surs_get:\n"));

	k = make_sid_key(pid, domain, wks, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen;

	data = tdb_fetch(db, key);

	free(k);

	if (data.dptr == NULL)
	{
		DEBUG(10,("surs_get: NULL data\n"));
		return False;
	}
	if (data.dsize != sizeof(*dc))
	{
		DEBUG(10,("surs_get: data size mismatch\n"));
		free(data.dptr);
		return False;
	}

	memcpy(dc, data.dptr, sizeof(*dc));
	free(data.dptr);

	dump_data(100, (char*)dc, sizeof(*dc));
	return True;
}

BOOL surs_store(uint32 pid, const char *domain, const char* wks, struct dcinfo *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;
	BOOL ret;

	DEBUG(10,("surs_store:\n"));

	k = make_sid_key(pid, domain, wks, &klen);

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
		DEBUG(0,("surs_store: failed\n"));
	}
	return ret;
}

BOOL surs_init_db(void)
{
	if (sdb != NULL && udb != NULL)
	{
		return True;
	}

	sdb = tdb_open(lock_path("surssid.tdb"), 0, 0, O_RONLY | O_CREAT, 0644);
	udb = tdb_open(lock_path("sursuid.tdb"), 0, 0, O_RONLY | O_CREAT, 0644);

	if (sdb == NULL || udb == NULL)
	{
		tdb_close(sdb);
		tdb_close(udb);
		DEBUG(0,("surs_init_db: failed\n"));
		return False;
	}
	
	DEBUG(10,("surs_init_db: opened\n"));

	return True;
}

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.
 ********************************************************************/
BOOL surs_tdb_sam_sid_to_unixid(DOM_SID *sid, uint32 type, uint32 *id,
				BOOL create)
{
	return False;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.
 ********************************************************************/
BOOL surs_tdb_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID *sid,
				BOOL create)
{
	return False;
}

