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
	TDB_CONTEXT *usg_tdb;
	TDB_CONTEXT *usa_tdb;
	TDB_CONTEXT *grp_tdb;
	TDB_CONTEXT *als_tdb;
	DOM_SID sid;

}
TDB_DOM_INFO;

typedef struct tdb_sid_info
{
	TDB_CONTEXT *tdb;
	DOM_SID sid;

}
TDB_SID_INFO;

typedef struct tdb_rid_info
{
	TDB_CONTEXT *usr_tdb;
	TDB_CONTEXT *grp_tdb;
	TDB_CONTEXT *als_tdb;
	uint32 rid;

}
TDB_RID_INFO;

typedef struct tdb_sam_info
{
	TDB_CONTEXT *tdb;

}
TDB_SAM_INFO;


#define POL_TYPE_TDBRID  1
#define POL_TYPE_TDBSAM  2


static void free_tdbdom_info(void *dev)
{
	TDB_DOM_INFO *tdbi = (TDB_DOM_INFO *) dev;
	DEBUG(10, ("free dom info \n"));
	if (tdbi->usr_tdb != NULL)
	{
		tdb_close(tdbi->usr_tdb);
	}
	if (tdbi->usg_tdb != NULL)
	{
		tdb_close(tdbi->usg_tdb);
	}
	if (tdbi->usa_tdb != NULL)
	{
		tdb_close(tdbi->usa_tdb);
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

static void free_tdbrid_info(void *dev)
{
	TDB_RID_INFO *tdbi = (TDB_RID_INFO *) dev;
	DEBUG(10, ("free rid info\n"));
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
	TDB_SAM_INFO *tdbi = (TDB_SAM_INFO *) dev;
	DEBUG(10, ("free sam info\n"));
	if (tdbi->tdb != NULL)
	{
		tdb_close(tdbi->tdb);
	}
	free(tdbi);
}

static void free_tdbsid_info(void *dev)
{
	TDB_SID_INFO *tdbi = (TDB_SID_INFO *) dev;
	DEBUG(10, ("free policy connection\n"));
	if (tdbi->tdb != NULL)
	{
		tdb_close(tdbi->tdb);
	}
	free(tdbi);
}

/****************************************************************************
  set samr rid
****************************************************************************/
BOOL set_tdbrid(struct policy_cache *cache, POLICY_HND *hnd,
		TDB_CONTEXT * usr_tdb,
		TDB_CONTEXT * grp_tdb, TDB_CONTEXT * als_tdb, uint32 rid)
{
	TDB_RID_INFO *dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		dev->rid = rid;
		dev->usr_tdb = usr_tdb;
		dev->grp_tdb = grp_tdb;
		dev->als_tdb = als_tdb;
		if (set_policy_state(cache, hnd, NULL,	/*free_tdbrid_info */
				     (void *)dev))
		{
			DEBUG(3, ("Service setting policy rid=%x\n", rid));
			policy_hnd_set_state_type(cache, hnd,
						  POL_TYPE_TDBRID);
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3, ("Error setting policy rid\n"));
	return False;
}

/****************************************************************************
  get samr rid
****************************************************************************/
BOOL get_tdbrid(struct policy_cache *cache, const POLICY_HND *hnd,
		TDB_CONTEXT ** usr_tdb,
		TDB_CONTEXT ** grp_tdb, TDB_CONTEXT ** als_tdb, uint32 * rid)
{
	TDB_RID_INFO *dev;

	if (!policy_hnd_check_state_type(cache, hnd, POL_TYPE_TDBRID))
	{
		DEBUG(1, ("WARNING: get_tdbrid: handle has wrong type!\n"));
	}

	dev = (TDB_RID_INFO *) get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		if (rid != NULL)
		{
			(*rid) = dev->rid;
			DEBUG(3, ("Service getting policy rid=%x\n", (*rid)));
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

	DEBUG(3, ("Error getting policy rid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_tdbsam(struct policy_cache *cache, POLICY_HND *hnd,
		TDB_CONTEXT * tdb)
{
	TDB_SAM_INFO *dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		dev->tdb = tdb;

		if (set_policy_state
		    (cache, hnd, free_tdbsam_info, (void *)dev))
		{
			DEBUG(3, ("Service setting policy sam\n"));
			policy_hnd_set_state_type(cache, hnd,
						  POL_TYPE_TDBSAM);
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3, ("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
BOOL get_tdbsam(struct policy_cache *cache, const POLICY_HND *hnd,
		TDB_CONTEXT ** tdb)
{
	TDB_SAM_INFO *dev;

	if (!policy_hnd_check_state_type(cache, hnd, POL_TYPE_TDBSAM))
	{
		DEBUG(1, ("WARNING: get_tdbsam: handle has wrong type!\n"));
	}

	dev = (TDB_SAM_INFO *) get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		if (tdb != NULL)
		{
			(*tdb) = dev->tdb;
			return (dev->tdb != NULL);
		}
		return True;
	}

	DEBUG(3, ("Error getting policy sid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_tdbdomsid(struct policy_cache *cache, POLICY_HND *hnd,
		   TDB_CONTEXT * usr_tdb,
		   TDB_CONTEXT * usg_tdb,
		   TDB_CONTEXT * usa_tdb,
		   TDB_CONTEXT * grp_tdb,
		   TDB_CONTEXT * als_tdb, const DOM_SID * sid)
{
	pstring sidstr;
	TDB_DOM_INFO *dev;

	dev = malloc(sizeof(*dev));

	DEBUG(3, ("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		sid_copy(&dev->sid, sid);
		dev->usr_tdb = usr_tdb;
		dev->usg_tdb = usg_tdb;
		dev->usa_tdb = usa_tdb;
		dev->grp_tdb = grp_tdb;
		dev->als_tdb = als_tdb;

		if (set_policy_state
		    (cache, hnd, free_tdbdom_info, (void *)dev))
		{
			DEBUG(3, ("Service setting policy sid=%s\n", sidstr));
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3, ("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
BOOL get_tdbdomsid(struct policy_cache *cache, const POLICY_HND *hnd,
		   TDB_CONTEXT ** usr_tdb,
		   TDB_CONTEXT ** usg_tdb,
		   TDB_CONTEXT ** usa_tdb,
		   TDB_CONTEXT ** grp_tdb,
		   TDB_CONTEXT ** als_tdb, DOM_SID * sid)
{
	TDB_DOM_INFO *dev =
		(TDB_DOM_INFO *) get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		if (sid != NULL)
		{
			sid_copy(sid, &dev->sid);
			DEBUG(3, ("Getting policy sid=%s\n",
				  sid_to_string(tmp, sid)));
		}
		if (usr_tdb != NULL)
		{
			(*usr_tdb) = dev->usr_tdb;
		}
		if (usg_tdb != NULL)
		{
			(*usg_tdb) = dev->usg_tdb;
		}
		if (usa_tdb != NULL)
		{
			(*usa_tdb) = dev->usa_tdb;
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

	DEBUG(3, ("Error getting policy sid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_tdbsid(struct policy_cache *cache, POLICY_HND *hnd,
		TDB_CONTEXT * tdb, const DOM_SID * sid)
{
	pstring sidstr;
	TDB_SID_INFO *dev;

	dev = malloc(sizeof(*dev));

	DEBUG(3, ("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		sid_copy(&dev->sid, sid);
		dev->tdb = tdb;

		if (set_policy_state
		    (cache, hnd, free_tdbsid_info, (void *)dev))
		{
			DEBUG(3, ("Service setting policy sid=%s\n", sidstr));
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3, ("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
BOOL get_tdbsid(struct policy_cache *cache, const POLICY_HND *hnd,
		TDB_CONTEXT ** tdb, DOM_SID * sid)
{
	TDB_SID_INFO *dev =
		(TDB_SID_INFO *) get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		if (sid != NULL)
		{
			sid_copy(sid, &dev->sid);
			DEBUG(3, ("Getting policy sid=%s\n",
				  sid_to_string(tmp, sid)));
		}
		if (tdb != NULL)
		{
			(*tdb) = dev->tdb;
			return (dev->tdb != NULL);
		}
		return True;
	}

	DEBUG(3, ("Error getting policy sid\n"));
	return False;
}

TDB_CONTEXT *open_usr_db(const DOM_SID * sid, uint32 rid, int perms)
{
	TDB_CONTEXT *db;
	pstring tmp;
	pstring usr;

	sid_to_string(tmp, sid);
	slprintf(usr, sizeof(usr) - 1, "%s/usr/%x", tmp, rid);

	db = tdb_open(passdb_path(usr), 0, 0, perms, 0644);
	if (db == NULL)
	{
		DEBUG(2,("open_usr_db: open failed, perms: %x\n", perms));
	}
	return db;
}

/*******************************************************************
 opens a samr entiry by rid, returns a policy handle.
 ********************************************************************/
uint32 samr_open_user_tdb(const POLICY_HND *parent_pol,
			  const DOM_SID * sid,
			  TDB_CONTEXT * usr_tdb,
			  POLICY_HND *pol, uint32 ace_perms, uint32 rid)
{
	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
				  parent_pol, pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	policy_hnd_set_name(get_global_hnd_cache(), pol, "sam_user");

	if (usr_tdb == NULL && ace_perms == SEC_RIGHTS_MAXIMUM_ALLOWED)
	{
		DEBUG(10, ("samr_open_user_tdb: max perms requested\n"));

		usr_tdb = open_usr_db(sid, rid, O_RDWR);
		if (usr_tdb == NULL)
		{
			usr_tdb = open_usr_db(sid, rid, O_RDONLY);
		}
	}

	if (usr_tdb == NULL)
	{
		int perms = 0;
		BOOL perms_read;
		BOOL perms_write;

		perms_write = IS_BITS_SET_SOME(ace_perms,
					       SEC_RIGHTS_WRITE_OWNER |
					       SEC_RIGHTS_WRITE_DAC);
		perms_read = IS_BITS_SET_ALL(ace_perms, SEC_RIGHTS_READ_CONTROL);

		DEBUG(10,("_samr_open_user: read: %s ", BOOLSTR(perms_read)));
		DEBUG(10,("write: %s\n", BOOLSTR(perms_write)));
		
		if (perms_write)
			perms = O_WRONLY;
		if (perms_read)
			perms = O_RDONLY;
		if (perms_write && perms_read)
			perms = O_RDWR;

		usr_tdb = open_usr_db(sid, rid, perms);
	}

	if (usr_tdb == NULL)
	{
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* associate a SID with the (unique) handle. */
	if (!set_tdbsam(get_global_hnd_cache(), pol, usr_tdb))
	{
		/* close the policy in case we can't associate a group SID */
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}
