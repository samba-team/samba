
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
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
#define MAX_OPEN_POLS 64
#endif

#define POL_NO_INFO 0
#define POL_REG_INFO 1
#define POL_SAMR_INFO 2
#define POL_CLI_INFO 3
#define POL_SVC_INFO 4


struct policy
{
	struct policy *next, *prev;
	int pnum;
	BOOL open;
	POLICY_HND pol_hnd;
	uint32 access_mask;
	vuser_key key;

	void (*free_fn)(void*);
	void *dev;
};

/****************************************************************************
  i hate this.  a global policy handle cache.  yuk.
****************************************************************************/
struct policy_cache *get_global_hnd_cache(void)
{
	static struct policy_cache *cache = NULL;

	if (cache == NULL)
	{
		cache = init_policy_cache(1024);
	}
	return cache;
}

/****************************************************************************
  create a unique policy handle
****************************************************************************/
static void create_pol_hnd(POLICY_HND *hnd)
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
struct policy_cache *init_policy_cache(int num_pol_hnds)
{
	struct policy_cache *cache = malloc(sizeof(struct policy_cache));
	if (cache != NULL)
	{
		cache->bmap = NULL;
		cache->Policy = NULL;
	}
	return cache;
}

/****************************************************************************
 free policy handle states...
****************************************************************************/
void free_policy_cache(struct policy_cache *cache)
{
	free(cache);
}

/****************************************************************************
  find policy by handle
****************************************************************************/
static struct policy *find_policy(struct policy_cache *cache,
				const POLICY_HND *hnd)
{
	struct policy *p;

	for (p=cache->Policy;p;p=p->next) {
		if (memcmp(&p->pol_hnd, hnd, sizeof(*hnd)) == 0) {
			DEBUG(4,("Found policy hnd[%x] ", p->pnum));
			dump_data(4, (const char *)hnd->data,
			sizeof(hnd->data));
			return p;
		}
	}

	DEBUG(4,("cache->Policy not found: "));
	dump_data(4, (const char *)hnd->data, sizeof(hnd->data));

	return NULL;
}

/****************************************************************************
  find first available policy slot.  copies a policy handle for you.
****************************************************************************/
BOOL dup_policy_hnd(struct policy_cache *cache,
				POLICY_HND *hnd,
				const POLICY_HND *from)
{
	struct policy *p = find_policy(cache, from);

	if (!p || !p->open)
	{
		return False;
	}
	DEBUG(3,("Duplicating policy state pnum=%x\n", p->pnum));
	return register_policy_hnd(cache, &p->key, hnd, p->access_mask);
}

/****************************************************************************
  find first available policy slot.  creates a policy handle for you.
****************************************************************************/
BOOL register_policy_hnd(struct policy_cache *cache,
				const vuser_key *key,
				POLICY_HND *hnd,
				uint32 access_mask)
{
	struct policy *p;
	static int count = 1;

	p = (struct policy *)malloc(sizeof(*p));
	if (!p)
	{
		DEBUG(0,("ERROR: out of memory!\n"));
		return False;
	}

	ZERO_STRUCTP(p);

	p->open = True;				
	p->pnum = count++;
	p->access_mask = access_mask;
	if (key != NULL)
	{
		p->key = *key;
	}
	else
	{
		p->key.vuid = UID_FIELD_INVALID;
		p->key.pid = getpid();
	}


	DLIST_ADD(cache->Policy, p);
	
	DEBUG(4,("Opened policy hnd[%x] ", p->pnum));
	DEBUG(10,("register_policy_hnd: vuser [%d, %x]\n",
	           p->key.pid, p->key.vuid));

	memcpy(&p->pol_hnd, hnd, sizeof(*hnd));
	dump_data(4, (char *)hnd->data, sizeof(hnd->data));

	return True;
}

/****************************************************************************
  find first available policy slot.  creates a policy handle for you.
****************************************************************************/
BOOL open_policy_hnd(struct policy_cache *cache, 
				const vuser_key *key,
				POLICY_HND *hnd,
				uint32 access_mask)
{
	create_pol_hnd(hnd);
	return register_policy_hnd(cache, key, hnd, access_mask);
}

/****************************************************************************
  find first available policy slot.  creates a policy handle for you.
****************************************************************************/
BOOL open_policy_hnd_link(struct policy_cache *cache, 
				const POLICY_HND *parent_hnd,
				POLICY_HND *hnd,
				uint32 access_mask)
{
	const vuser_key *key = get_policy_vuser_key(cache, parent_hnd);
	if (key == NULL)
	{
		return False;
	}
	create_pol_hnd(hnd);
	return register_policy_hnd(cache, key, hnd, access_mask);
}

/****************************************************************************
  find policy index by handle
****************************************************************************/
int find_policy_by_hnd(struct policy_cache *cache, const POLICY_HND *hnd)
{
	struct policy *p = find_policy(cache, hnd);

	return p?p->pnum:-1;
}


/****************************************************************************
  set pol state.
****************************************************************************/
BOOL set_policy_state(struct policy_cache *cache, POLICY_HND *hnd, 
				void(*fn)(void*), void *dev)
{
	struct policy *p = find_policy(cache, hnd);

	if (p && p->open)
	{
		DEBUG(3,("Setting policy state pnum=%x\n", p->pnum));

		p->dev = dev;
		p->free_fn = fn;
		return True;
	} 

	DEBUG(3,("Error setting policy state\n"));

	return False;
}

/****************************************************************************
  get pol state.
****************************************************************************/
void *get_policy_state_info(struct policy_cache *cache, const POLICY_HND *hnd)
{
	struct policy *p = find_policy(cache, hnd);

	if (p != NULL && p->open)
	{
		DEBUG(3,("Getting policy state pnum=%x\n", p->pnum));
		return p->dev;
	}

	DEBUG(3,("Error getting policy state\n"));
	return NULL;
}


/****************************************************************************
  close an lsa policy
****************************************************************************/
BOOL close_policy_hnd(struct policy_cache *cache, POLICY_HND *hnd)
{
	struct policy *p = find_policy(cache, hnd);

	if (!p)
	{
		DEBUG(3,("Error closing policy\n"));
		return False;
	}

	DEBUG(3,("Closed policy name pnum=%x\n",  p->pnum));

	DLIST_REMOVE(cache->Policy, p);

	if (p->free_fn != NULL)
	{
		p->free_fn(p->dev);
	}
	else
	{
		safe_free(p->dev);
	}

	free(p);

	ZERO_STRUCTP(hnd);

	return True;
}

/****************************************************************************
  get pol state.
****************************************************************************/
BOOL policy_link_key(struct policy_cache *cache, const POLICY_HND *hnd,
				POLICY_HND *to)
{
	struct policy *p = find_policy(cache, hnd);
	struct policy *pto = find_policy(cache, to);

	if (p != NULL && p->open && pto != NULL && pto->open)
	{
		DEBUG(3,("Linking policy key pnum=%x pid=%d vuid=%x\n",
		          p->key.pid, p->key.vuid, p->pnum));
		pto->key = p->key;
		return True;
	}

	DEBUG(3,("Error getting policy link states\n"));
	return False;
}

/****************************************************************************
  get pol state.
****************************************************************************/
const vuser_key *get_policy_vuser_key(struct policy_cache *cache,
				const POLICY_HND *hnd)
{
	struct policy *p = find_policy(cache, hnd);

	if (p != NULL && p->open)
	{
		DEBUG(3,("Getting policy vuser_key pnum=%x pid=%d vuid=%x\n",
		          p->pnum, p->key.pid, p->key.vuid));
		return &p->key;
	}

	DEBUG(3,("Error getting policy state\n"));
	return NULL;
}

/****************************************************************************
  get user session key.
****************************************************************************/
BOOL pol_get_usr_sesskey(struct policy_cache *cache, const POLICY_HND *hnd,
				uchar usr_sess_key[16])
{
	const vuser_key *key = get_policy_vuser_key(cache, hnd);
	user_struct *vuser;

	if (key == NULL)
	{
		return False;
	}
	vuser = get_valid_user_struct(key);
	if (vuser == NULL)
	{
		DEBUG(10,("pol_get_usr_sesskey: no vuser struct\n"));
		return False;
	}
	memcpy(usr_sess_key, vuser->usr.user_sess_key, 16);
	vuid_free_user_struct(vuser);
	return True;
}

