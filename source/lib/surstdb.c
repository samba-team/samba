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

static TDB_CONTEXT *udb = NULL;
static TDB_CONTEXT *sdb = NULL;
static TDB_CONTEXT *gdb = NULL;

static BOOL surs_init_db(void)
{
	if (sdb != NULL && udb != NULL && gdb != NULL)
	{
		return True;
	}

	become_root(False);
	sdb =
		tdb_open(lock_path("surssid.tdb"), 0, 0, O_RDONLY | O_CREAT,
			 0644);
	udb =
		tdb_open(lock_path("sursuid.tdb"), 0, 0, O_RDONLY | O_CREAT,
			 0644);
	gdb =
		tdb_open(lock_path("sursgid.tdb"), 0, 0, O_RDONLY | O_CREAT,
			 0644);
	unbecome_root(False);

	if (gdb == NULL || sdb == NULL || udb == NULL)
	{
		tdb_close(sdb);
		tdb_close(udb);
		tdb_close(gdb);

		sdb = NULL;
		udb = NULL;
		gdb = NULL;

		DEBUG(0, ("surs_init_db: failed\n"));
		return False;
	}

	DEBUG(10, ("surs_init_db: opened\n"));

	return True;
}

static BOOL tdb_delete_sid(const DOM_SID * sid)
{
	DOM_SID s;
	prs_struct key;

	sid_copy(&s, sid);

	if (sdb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("delete NT user\n"));

	prs_init(&key, 0, 4, False);
	if (!smb_io_dom_sid("sid", &s, &key, 0))
	{
		prs_free_data(&key);
		return False;
	}

	prs_tdb_delete(sdb, &key);
	prs_free_data(&key);

	return True;
}

static BOOL tdb_delete_gid(uint32 id)
{
	prs_struct key;

	if (gdb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("delete unix group\n"));

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("gid", &key, 0, &id))
	{
		prs_free_data(&key);
		return False;
	}

	prs_tdb_delete(gdb, &key);
	prs_free_data(&key);

	return True;
}

static BOOL tdb_delete_uid(uint32 id)
{
	prs_struct key;

	if (udb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("delete unix user\n"));

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("uid", &key, 0, &id))
	{
		prs_free_data(&key);
		return False;
	}

	prs_tdb_delete(udb, &key);
	prs_free_data(&key);

	return True;
}

static BOOL tdb_lookup_gid(uint32 gid, DOM_SID * uk)
{
	prs_struct key;
	prs_struct data;

	if (gdb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("lookup gid\n"));

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("gid", &key, 0, &gid))
	{
		prs_free_data(&key);
		return False;
	}

	prs_tdb_fetch(gdb, &key, &data);

	if (uk != NULL)
	{
		if (!smb_io_dom_sid("sid", uk, &data, 0))
		{
			prs_free_data(&key);
			prs_free_data(&data);
			return False;
		}
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_lookup_uid(uint32 uid, DOM_SID * uk)
{
	prs_struct key;
	prs_struct data;

	if (udb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("lookup uid\n"));

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("uid", &key, 0, &uid))
	{
		prs_free_data(&key);
		return False;
	}

	prs_tdb_fetch(udb, &key, &data);

	if (uk != NULL)
	{
		if (!smb_io_dom_sid("sid", uk, &data, 0))
		{
			prs_free_data(&key);
			prs_free_data(&data);
			return False;
		}
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_store_gid(uint32 gid, const DOM_SID * uk)
{
	prs_struct key;
	prs_struct data;

	DOM_SID k = *uk;

	if (gdb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("storing gid\n"));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!_prs_uint32("gid", &key, 0, &gid) ||
	    !smb_io_dom_sid("sid", &k, &data, 0) ||
	    prs_tdb_store(gdb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

static BOOL tdb_store_uid(uint32 uid, const DOM_SID * uk)
{
	prs_struct key;
	prs_struct data;

	DOM_SID k = *uk;

	if (udb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("storing uid\n"));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!_prs_uint32("uid", &key, 0, &uid) ||
	    !smb_io_dom_sid("sid", &k, &data, 0) ||
	    prs_tdb_store(udb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

static BOOL tdb_lookup_sid(const DOM_SID * uk, uint32 * id)
{
	prs_struct key;
	prs_struct data;
	DOM_SID k;

	sid_copy(&k, uk);

	if (sdb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("lookup sid\n"));

	prs_init(&key, 0, 4, False);
	if (!smb_io_dom_sid("sid", &k, &key, 0))
	{
		prs_free_data(&key);
		return False;
	}

	prs_tdb_fetch(sdb, &key, &data);

	if (id != NULL)
	{
		if (!_prs_uint32("uid", &data, 0, id))
		{
			prs_free_data(&key);
			prs_free_data(&data);
			return False;
		}
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_store_sid(const DOM_SID * uk, uint32 id)
{
	prs_struct key;
	prs_struct data;

	DOM_SID k;

	sid_copy(&k, uk);

	if (sdb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}

	DEBUG(10, ("storing SID\n"));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!smb_io_dom_sid("sid", &k, &key, 0) ||
	    !_prs_uint32("uid", &data, 0, &id) ||
	    prs_tdb_store(sdb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

static BOOL tdb_surs_unlock(void)
{
	BOOL ret = True;
	if (gdb == NULL || sdb == NULL || udb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}
	if (tdb_writeunlock(sdb) != 0)
		ret = False;
	if (tdb_writeunlock(udb) != 0)
		ret = False;
	if (tdb_writeunlock(gdb) != 0)
		ret = False;

	return ret;
}

static BOOL tdb_surs_lock(void)
{
	if (gdb == NULL || sdb == NULL || udb == NULL)
	{
		if (!surs_init_db())
		{
			return False;
		}
	}
	return tdb_writelock(sdb) == 0 &&
		tdb_writelock(udb) == 0 && tdb_writelock(gdb) == 0;
}

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.
 ********************************************************************/
BOOL surs_tdb_sam_sid_to_unixid(DOM_SID * sid, uint32 type, uint32 * id,
				BOOL create)
{
	BOOL ret = False;
	if (create)
	{
		if (!tdb_surs_lock())
		{
			tdb_surs_unlock();
			return False;
		}
	}
	switch (type)
	{
		case SID_NAME_USER:
		{
			ret = tdb_lookup_sid(sid, id);
		}
		case SID_NAME_ALIAS:
		{
			ret = tdb_lookup_sid(sid, id);
		}
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			ret = tdb_lookup_sid(sid, id);
		}
	}
	if (!create)
	{
		/* just in lookup-mode */
		return ret;
	}

	if (ret)
	{
		/* hm, it was already there */
		tdb_surs_unlock();
		return ret;
	}

	switch (type)
	{
		case SID_NAME_USER:
		{
			ret = tdb_store_uid(*id, sid)
				&& tdb_store_sid(sid, *id);
		}
		case SID_NAME_ALIAS:
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			ret = tdb_store_gid(*id, sid)
				&& tdb_store_sid(sid, *id);
		}
	}

	tdb_surs_unlock();

	return ret;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.
 ********************************************************************/
BOOL surs_tdb_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID * sid,
				BOOL create)
{
	BOOL ret = False;

	if (create)
	{
		if (!tdb_surs_lock())
		{
			tdb_surs_unlock();
			return False;
		}
	}
	switch (type)
	{
		case SID_NAME_USER:
		{
			ret = tdb_lookup_uid(id, sid);
		}
		case SID_NAME_ALIAS:
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			ret = tdb_lookup_gid(id, sid);
		}
	}

	if (!create)
	{
		/* just in lookup-mode */
		return ret;
	}

	if (ret)
	{
		/* hm, it was already there */
		tdb_surs_unlock();
		return ret;
	}

	switch (type)
	{
		case SID_NAME_USER:
		{
			ret = tdb_store_uid(id, sid)
				&& tdb_store_sid(sid, id);
		}
		case SID_NAME_ALIAS:
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			ret = tdb_store_gid(id, sid)
				&& tdb_store_sid(sid, id);
		}
	}

	tdb_surs_unlock();

	return ret;
}
