/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker               2000
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

typedef struct tdb_dom_info
{
	TDB_CONTEXT *usr_tdb;
	TDB_CONTEXT *grp_tdb;
	TDB_CONTEXT *als_tdb;
	DOM_SID sid;

} TDB_DOM_INFO;

typedef struct tdb_sid_info
{
	TDB_CONTEXT *tdb;
	DOM_SID sid;

} TDB_SID_INFO;

typedef struct tdb_sam_info
{
	TDB_CONTEXT *tdb;

} TDB_SAM_INFO;

static void free_tdbdom_info(void *dev)
{
	TDB_DOM_INFO *tdbi = (TDB_DOM_INFO *)dev;
	DEBUG(10,("free policy connection\n"));
	if (tdbi->usr_tdb != NULL)
	{
		tdb_close(tdbi->usr_tdb);
	}
	if (tdbi->grp_tdb != NULL)
	{
		tdb_close(tdbi->grp_tdb);
	}
	if (tdbi->als_tdb != NULL)
	{
		tdb_close(tdbi->als_tdb);
	}
	free(tdbi);
}

static void free_tdbsam_info(void *dev)
{
	TDB_SAM_INFO *tdbi = (TDB_SAM_INFO *)dev;
	DEBUG(10,("free policy connection\n"));
	if (tdbi->tdb != NULL)
	{
		tdb_close(tdbi->tdb);
	}
	free(tdbi);
}

static void free_tdbsid_info(void *dev)
{
	TDB_SID_INFO *tdbi = (TDB_SID_INFO *)dev;
	DEBUG(10,("free policy connection\n"));
	if (tdbi->tdb != NULL)
	{
		tdb_close(tdbi->tdb);
	}
	free(tdbi);
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_tdbsam(struct policy_cache *cache, POLICY_HND *hnd,
				TDB_CONTEXT *tdb)
{
	pstring sidstr;
	TDB_SAM_INFO *dev;

	dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		dev->tdb = tdb;

		if (set_policy_state(cache, hnd, free_tdbsam_info, (void*)dev))
		{
			DEBUG(3,("Service setting policy sid=%s\n", sidstr));
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3,("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
BOOL get_tdbsam(struct policy_cache *cache, const POLICY_HND *hnd,
				TDB_CONTEXT **tdb)
{
	TDB_SAM_INFO *dev = (TDB_SAM_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		if (tdb != NULL)
		{
			(*tdb) = dev->tdb;
			return (dev->tdb != NULL);
		}
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_tdbdomsid(struct policy_cache *cache, POLICY_HND *hnd,
				TDB_CONTEXT *usr_tdb,
				TDB_CONTEXT *grp_tdb,
				TDB_CONTEXT *als_tdb,
				const DOM_SID *sid)
{
	pstring sidstr;
	TDB_DOM_INFO *dev;

	dev = malloc(sizeof(*dev));

	DEBUG(3,("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		sid_copy(&dev->sid, sid);
		dev->usr_tdb = usr_tdb;
		dev->grp_tdb = grp_tdb;
		dev->als_tdb = als_tdb;

		if (set_policy_state(cache, hnd, free_tdbdom_info, (void*)dev))
		{
			DEBUG(3,("Service setting policy sid=%s\n", sidstr));
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3,("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
BOOL get_tdbdomsid(struct policy_cache *cache, const POLICY_HND *hnd,
				TDB_CONTEXT **usr_tdb,
				TDB_CONTEXT **grp_tdb,
				TDB_CONTEXT **als_tdb,
				DOM_SID *sid)
{
	TDB_DOM_INFO *dev = (TDB_DOM_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		if (sid != NULL)
		{	
			sid_copy(sid, &dev->sid);
			DEBUG(3,("Getting policy sid=%s\n",
			          sid_to_string(tmp, sid)));
		}
		if (usr_tdb != NULL)
		{
			(*usr_tdb) = dev->usr_tdb;
		}
		if (grp_tdb != NULL)
		{
			(*grp_tdb) = dev->grp_tdb;
		}
		if (als_tdb != NULL)
		{
			(*als_tdb) = dev->als_tdb;
		}
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_tdbsid(struct policy_cache *cache, POLICY_HND *hnd,
				TDB_CONTEXT *tdb, const DOM_SID *sid)
{
	pstring sidstr;
	TDB_SID_INFO *dev;

	dev = malloc(sizeof(*dev));

	DEBUG(3,("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		sid_copy(&dev->sid, sid);
		dev->tdb = tdb;

		if (set_policy_state(cache, hnd, free_tdbsid_info, (void*)dev))
		{
			DEBUG(3,("Service setting policy sid=%s\n", sidstr));
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3,("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
BOOL get_tdbsid(struct policy_cache *cache, const POLICY_HND *hnd,
				TDB_CONTEXT **tdb, DOM_SID *sid)
{
	TDB_SID_INFO *dev = (TDB_SID_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		if (sid != NULL)
		{	
			sid_copy(sid, &dev->sid);
			DEBUG(3,("Getting policy sid=%s\n",
			          sid_to_string(tmp, sid)));
		}
		if (tdb != NULL)
		{
			(*tdb) = dev->tdb;
			return (dev->tdb != NULL);
		}
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

