/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
 * this module stores a user_struct which can be globally accessed (by root)
 * across process boundaries, in order to obtain info about users currently
 * accessing * samba. 
 *
 * the database key is the process number (pid) of the creater of the
 * structure plus the vuid - SMB virtual user id.  NORMALLY, this would
 * be smbd pid and an smbd-generated vuid.
 *
 */

#include "includes.h"

extern int DEBUGLEVEL;

static TDB_CONTEXT *tdb = NULL;

BOOL tdb_delete_vuid( const vuser_key *uk)
{
	prs_struct key;
	vuser_key k = *uk;

	if (tdb == NULL)
	{
		if (!vuid_init_db())
		{
			return False;
		}
	}

	DEBUG(10,("delete user %x,%x\n", uk->pid, uk->vuid));

	prs_init(&key, 0, 4, False);
	if (!vuid_io_key("key", &k, &key, 0))
	{
		return False;
	}

	prs_tdb_delete(tdb, &key);

	prs_free_data(&key);

	return True;
}

BOOL tdb_lookup_vuid( const vuser_key *uk, user_struct **usr)
{
	prs_struct key;
	prs_struct data;
	vuser_key k = *uk;

	if (usr != NULL)
	{
		(*usr) = (user_struct *)malloc(sizeof(**usr));
		if ((*usr) == NULL)
		{
			return False;
		}
		ZERO_STRUCTP((*usr));
	}
	if (tdb == NULL)
	{
		if (!vuid_init_db())
		{
			return False;
		}
	}

	DEBUG(10,("lookup user %x,%x\n", uk->pid, uk->vuid));

	prs_init(&key, 0, 4, False);
	if (!vuid_io_key("key", &k, &key, 0))
	{
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (usr != NULL)
	{
		if (!vuid_io_user_struct("usr", (*usr), &data, 0))
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

BOOL tdb_store_vuid( const vuser_key *uk, user_struct *usr)
{
	prs_struct key;
	prs_struct data;
	vuser_key k = *uk;

	if (tdb == NULL)
	{
		if (!vuid_init_db())
		{
			return False;
		}
	}

	DEBUG(10,("storing user %x,%x\n", uk->pid, uk->vuid));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!vuid_io_key("key", &k, &key, 0) ||
	    !vuid_io_user_struct("usr", usr, &data, 0) ||
	     prs_tdb_store(tdb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

BOOL vuid_init_db(void)
{
	tdb = tdb_open(lock_path("vuid.tdb"), 0, 0, O_RDWR | O_CREAT, 0600);

	if (tdb == NULL)
	{
		DEBUG(0,("vuid_init_db: failed\n"));
		return False;
	}
	
	DEBUG(10,("vuid_init_db: opened\n"));

	return True;
}

