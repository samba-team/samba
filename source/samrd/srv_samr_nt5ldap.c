/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Luke Howard                  2000
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
#include "ldapdb.h"
#include "sids.h"

extern int DEBUGLEVEL;

typedef struct nt5ldap_dom_info
{
	LDAPDB *hds;
	DOM_SID sid;
} NT5LDAP_DOM_INFO;

typedef struct nt5ldap_sid_info
{
	LDAPDB *hds;
	DOM_SID sid;
} NT5LDAP_SID_INFO;

typedef struct nt5ldap_rid_info
{
	LDAPDB *hds;
	uint32 rid;
} NT5LDAP_RID_INFO;

typedef struct nt5ldap_sam_info
{
	LDAPDB *hds;
} NT5LDAP_SAM_INFO;

static void free_nt5ldapdom_info(void *dev)
{
	NT5LDAP_DOM_INFO *ldbi = (NT5LDAP_DOM_INFO *)dev;
	DEBUG(10,("free policy connection\n"));
	if (ldbi->hds != NULL)
	{
		ldapdb_close(&ldbi->hds);
	}
	free(ldbi);
}

static void free_nt5ldapsam_info(void *dev)
{
	NT5LDAP_SAM_INFO *ldbi = (NT5LDAP_SAM_INFO *)dev;
	DEBUG(10,("free policy connection\n"));
	if (ldbi->hds != NULL)
	{
		ldapdb_close(&ldbi->hds);
	}
	free(ldbi);
}

static void free_nt5ldapsid_info(void *dev)
{
	NT5LDAP_SID_INFO *ldbi = (NT5LDAP_SID_INFO *)dev;
	DEBUG(10,("free policy connection\n"));
	if (ldbi->hds != NULL)
	{
		ldapdb_close(&ldbi->hds);
	}
	free(ldbi);
}

/****************************************************************************
  set samr rid
****************************************************************************/
BOOL set_nt5ldaprid(struct policy_cache *cache, POLICY_HND *hnd,
				LDAPDB *hds, uint32 rid)
{
	NT5LDAP_RID_INFO *dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		dev->rid = rid;
		dev->hds = hds;
		if (set_policy_state(cache, hnd, NULL, (void*)dev))
		{
			DEBUG(3,("Service setting policy rid=%x\n", rid));
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3,("Error setting policy rid\n"));
	return False;
}

/****************************************************************************
  get samr rid
****************************************************************************/
BOOL get_nt5ldaprid(struct policy_cache *cache, const POLICY_HND *hnd,
				LDAPDB **hds, uint32 *rid)
{
	NT5LDAP_RID_INFO *dev = (NT5LDAP_RID_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		if (rid != NULL)
		{
			(*rid) = dev->rid;
			DEBUG(3,("Service getting policy rid=%x\n", (*rid)));
		}
		if (hds != NULL)
		{
			(*hds) = dev->hds;
		}
		return True;
	}

	DEBUG(3,("Error getting policy rid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_nt5ldapsam(struct policy_cache *cache, POLICY_HND *hnd,
				LDAPDB *hds)
{
	pstring sidstr;
	NT5LDAP_SAM_INFO *dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		dev->hds = hds;

		if (set_policy_state(cache, hnd, free_nt5ldapsam_info, (void*)dev))
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
BOOL get_nt5ldapsam(struct policy_cache *cache, const POLICY_HND *hnd,
				LDAPDB **hds)
{
	NT5LDAP_SAM_INFO *dev = (NT5LDAP_SAM_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		if (hds != NULL)
		{
			(*hds) = dev->hds;
			return (dev->hds != NULL);
		}
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_nt5ldapdomsid(struct policy_cache *cache, POLICY_HND *hnd,
				LDAPDB *hds,
				const DOM_SID *sid)
{
	pstring sidstr;
	NT5LDAP_DOM_INFO *dev;

	dev = malloc(sizeof(*dev));

	DEBUG(3,("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		sid_copy(&dev->sid, sid);
		dev->hds = hds;

		if (set_policy_state(cache, hnd, free_nt5ldapdom_info, (void*)dev))
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
BOOL get_nt5ldapdomsid(struct policy_cache *cache, const POLICY_HND *hnd,
				LDAPDB **hds,
				DOM_SID *sid)
{
	NT5LDAP_DOM_INFO *dev = (NT5LDAP_DOM_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		if (sid != NULL)
		{	
			sid_copy(sid, &dev->sid);
			DEBUG(3,("Getting policy sid=%s\n",
			          sid_to_string(tmp, sid)));
		}
		if (hds != NULL)
		{
			(*hds) = dev->hds;
		}
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_nt5ldapsid(struct policy_cache *cache, POLICY_HND *hnd,
				LDAPDB *hds, const DOM_SID *sid)
{
	pstring sidstr;
	NT5LDAP_SID_INFO *dev;

	dev = malloc(sizeof(*dev));

	DEBUG(3,("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		sid_copy(&dev->sid, sid);
		dev->hds = hds;

		if (set_policy_state(cache, hnd, free_nt5ldapsid_info, (void*)dev))
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
BOOL get_nt5ldapsid(struct policy_cache *cache, const POLICY_HND *hnd,
				LDAPDB **hds, DOM_SID *sid)
{
	NT5LDAP_SID_INFO *dev = (NT5LDAP_SID_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		if (sid != NULL)
		{	
			sid_copy(sid, &dev->sid);
			DEBUG(3,("Getting policy sid=%s\n",
			          sid_to_string(tmp, sid)));
		}
		if (hds != NULL)
		{
			(*hds) = dev->hds;
			return (dev->hds != NULL);
		}
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

/*******************************************************************
 opens a samr entiry by rid, returns a policy handle.
 ********************************************************************/
uint32 samr_open_by_nt5ldaprid( LDAPDB *hds,
				POLICY_HND *pol, uint32 access_mask, uint32 rid)
{
	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), pol, access_mask))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* associate a RID with the (unique) handle. */
	if (!set_nt5ldaprid(get_global_hnd_cache(), pol, hds, rid))
	{
		/* close the policy in case we can't associate a group SID */
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	return 0x0;
}

BOOL pwdbsam_initialise(void)
{
	DEBUG(0,("TODO: initialise SAM NT5 LDAP Database\n"));
	return True;
}
