
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
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


extern int DEBUGLEVEL;

#ifndef MAX_OPEN_POLS
#define MAX_OPEN_POLS 50
#endif

struct reg_info
{
    /* for use by \PIPE\winreg */
	fstring name; /* name of registry key */
};

struct samr_info
{
    /* for use by the \PIPE\samr policy */
	DOM_SID sid;
    uint32 rid; /* relative id associated with the pol_hnd */
    uint32 status; /* some sort of flag.  best to record it.  comes from opnum 0x39 */
};

static struct
{
  BOOL open;
  POLICY_HND pol_hnd;

  union
  {
    struct samr_info samr;
	struct reg_info reg;

  } dev;

} Policy[MAX_OPEN_POLS];


#define VALID_POL(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_POLS))
#define OPEN_POL(pnum)    (VALID_POL(pnum) && Policy[pnum].open)

/****************************************************************************
  create a unique policy handle
****************************************************************************/
void create_pol_hnd(POLICY_HND *hnd)
{
	static uint32 pol_hnd_low  = 0;
	static uint32 pol_hnd_high = 0;

	if (hnd == NULL) return;

	/* i severely doubt that pol_hnd_high will ever be non-zero... */
	pol_hnd_low++;
	if (pol_hnd_low == 0) pol_hnd_high++;

	SIVAL(hnd->data, 0 , 0x0);  /* first bit must be null */
	SIVAL(hnd->data, 4 , pol_hnd_low ); /* second bit is incrementing */
	SIVAL(hnd->data, 8 , pol_hnd_high); /* second bit is incrementing */
	SIVAL(hnd->data, 12, time(NULL)); /* something random */
	SIVAL(hnd->data, 16, getpid()); /* something more random */
}

/****************************************************************************
  initialise policy handle states...
****************************************************************************/
void init_lsa_policy_hnd(void)
{
	int i;
	for (i = 0; i < MAX_OPEN_POLS; i++)
	{
		Policy[i].open = False;
	}

	return;
}

/****************************************************************************
  find first available policy slot.  creates a policy handle for you.
****************************************************************************/
BOOL open_lsa_policy_hnd(POLICY_HND *hnd)
{
	int i;

	for (i = 0; i < MAX_OPEN_POLS; i++)
	{
		if (!Policy[i].open)
		{
			Policy[i].open = True;
				
			create_pol_hnd(hnd);
			memcpy(&(Policy[i].pol_hnd), hnd, sizeof(*hnd));

			DEBUG(4,("Opened policy hnd[%x] ", i));
			dump_data(4, (char *)hnd->data, sizeof(hnd->data));

			return True;
		}
	}

	/* i love obscure error messages. */
#if TERRY_PRATCHET_INTERESTING_TIMES
	DEBUG(1,("+++ OUT OF CHEESE ERROR +++ REDO FROM START ... @?!*@@\n"));
#else
	DEBUG(1,("ERROR - open_lsa_policy_hnd: out of Policy Handles!\n"));
#endif

	return False;
}

/****************************************************************************
  find policy index by handle
****************************************************************************/
int find_lsa_policy_by_hnd(POLICY_HND *hnd)
{
	int i;

	for (i = 0; i < MAX_OPEN_POLS; i++)
	{
		if (memcmp(&(Policy[i].pol_hnd), hnd, sizeof(*hnd)) == 0)
		{
			DEBUG(4,("Found policy hnd[%x] ", i));
			dump_data(4, (char *)hnd->data, sizeof(hnd->data));

			return i;
		}
	}

	DEBUG(4,("Policy not found: "));
	dump_data(4, (char *)hnd->data, sizeof(hnd->data));

	return -1;
}

/****************************************************************************
  set samr rid
****************************************************************************/
BOOL set_lsa_policy_samr_rid(POLICY_HND *hnd, uint32 rid)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		DEBUG(3,("%s Setting policy device rid=%x pnum=%x\n",
		          timestring(), rid, pnum));

		Policy[pnum].dev.samr.rid = rid;
		return True;
	}
	else
	{
		DEBUG(3,("%s Error setting policy rid=%x (pnum=%x)\n",
		          timestring(), rid, pnum));
		return False;
	}
}

/****************************************************************************
  set samr pol status.  absolutely no idea what this is.
****************************************************************************/
BOOL set_lsa_policy_samr_pol_status(POLICY_HND *hnd, uint32 pol_status)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		DEBUG(3,("%s Setting policy status=%x pnum=%x\n",
		          timestring(), pol_status, pnum));

		Policy[pnum].dev.samr.status = pol_status;
		return True;
	}
	else
	{
		DEBUG(3,("%s Error setting policy status=%x (pnum=%x)\n",
		          timestring(), pol_status, pnum));
		return False;
	}
}

/****************************************************************************
  set samr sid
****************************************************************************/
BOOL set_lsa_policy_samr_sid(POLICY_HND *hnd, DOM_SID *sid)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		DEBUG(3,("%s Setting policy sid=%s pnum=%x\n",
		          timestring(), dom_sid_to_string(sid), pnum));

		memcpy(&(Policy[pnum].dev.samr.sid), sid, sizeof(*sid));
		return True;
	}
	else
	{
		DEBUG(3,("%s Error setting policy sid=%s (pnum=%x)\n",
		          timestring(), dom_sid_to_string(sid), pnum));
		return False;
	}
}

/****************************************************************************
  set samr rid
****************************************************************************/
uint32 get_lsa_policy_samr_rid(POLICY_HND *hnd)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		uint32 rid = Policy[pnum].dev.samr.rid;
		DEBUG(3,("%s Getting policy device rid=%x pnum=%x\n",
		          timestring(), rid, pnum));

		return rid;
	}
	else
	{
		DEBUG(3,("%s Error getting policy (pnum=%x)\n",
		          timestring(), pnum));
		return 0xffffffff;
	}
}

/****************************************************************************
  set reg name 
****************************************************************************/
BOOL set_lsa_policy_reg_name(POLICY_HND *hnd, fstring name)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		DEBUG(3,("%s Setting policy pnum=%x name=%s\n",
		          timestring(), pnum, name));

		fstrcpy(Policy[pnum].dev.reg.name, name);
		return True;
	}
	else
	{
		DEBUG(3,("%s Error setting policy (pnum=%x) name=%s\n",
		          timestring(), pnum, name));
		return False;
	}
}

/****************************************************************************
  get reg name 
****************************************************************************/
BOOL get_lsa_policy_reg_name(POLICY_HND *hnd, fstring name)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		fstrcpy(name, Policy[pnum].dev.reg.name);

		DEBUG(3,("%s Getting policy pnum=%x name=%s\n",
		          timestring(), pnum, name));

		return True;
	}
	else
	{
		DEBUG(3,("%s Error getting policy (pnum=%x)\n",
		          timestring(), pnum));
		return False;
	}
}

/****************************************************************************
  close an lsa policy
****************************************************************************/
BOOL close_lsa_policy_hnd(POLICY_HND *hnd)
{
	int pnum = find_lsa_policy_by_hnd(hnd);

	if (OPEN_POL(pnum))
	{
		DEBUG(3,("%s Closed policy name pnum=%x\n", timestring(), pnum));
		Policy[pnum].open = False;
		return True;
	}
	else
	{
		DEBUG(3,("%s Error closing policy pnum=%x\n", timestring(), pnum));
		return False;
	}
}

