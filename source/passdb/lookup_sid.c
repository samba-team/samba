/* 
   Unix SMB/CIFS implementation.
   uid/user handling
   Copyright (C) Andrew Tridgell         1992-1998
   Copyright (C) Gerald (Jerry) Carter   2003
   
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

/*****************************************************************
 *THE CANONICAL* convert name to SID function.
 Tries local lookup first - for local domains - then uses winbind.
*****************************************************************/  

BOOL lookup_name(const char *domain, const char *name, DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	fstring sid;
	BOOL local_lookup = False;
	
	*name_type = SID_NAME_UNKNOWN;

	/* If we are looking up a domain user, make sure it is
	   for the local machine only */
	
	if (strequal(domain, get_global_sam_name())) {
		if (local_lookup_name(name, psid, name_type)) {
			DEBUG(10,
			      ("lookup_name: (local) [%s]\\[%s] -> SID %s (type %s: %u)\n",
			       domain, name, sid_to_string(sid,psid),
			       sid_type_lookup(*name_type), (unsigned int)*name_type));
			return True;
		}
	} else {
		/* Remote */
		if (winbind_lookup_name(domain, name, psid, name_type)) {
			
			DEBUG(10,("lookup_name (winbindd): [%s]\\[%s] -> SID %s (type %u)\n",
				  domain, name, sid_to_string(sid, psid), 
				  (unsigned int)*name_type));
			return True;
		}
	}
	
	DEBUG(10, ("lookup_name: %s lookup for [%s]\\[%s] failed\n", 
		   local_lookup ? "local" : "winbind", domain, name));

	return False;
}

/*****************************************************************
 *THE CANONICAL* convert SID to name function.
 Tries local lookup first - for local sids, then tries winbind.
*****************************************************************/  

BOOL lookup_sid(const DOM_SID *sid, fstring dom_name, fstring name, enum SID_NAME_USE *name_type)
{
	if (!name_type)
		return False;

	*name_type = SID_NAME_UNKNOWN;

	/* Check if this is our own sid.  This should perhaps be done by
	   winbind?  For the moment handle it here. */

	if (sid->num_auths == 5) {
		DOM_SID tmp_sid;
		uint32 rid;

		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);

		if (sid_equal(get_global_sam_sid(), &tmp_sid)) {

			return map_domain_sid_to_name(&tmp_sid, dom_name) &&
				local_lookup_sid(sid, name, name_type);
		}
	}

	if (!winbind_lookup_sid(sid, dom_name, name, name_type)) {
		fstring sid_str;
		DOM_SID tmp_sid;
		uint32 rid;

		DEBUG(10,("lookup_sid: winbind lookup for SID %s failed - trying local.\n", sid_to_string(sid_str, sid) ));

		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);
		return map_domain_sid_to_name(&tmp_sid, dom_name) &&
			lookup_known_rid(&tmp_sid, rid, name, name_type);
	}
	return True;
}


/*****************************************************************
 Id mapping cache.  This is to avoid Winbind mappings already
 seen by smbd to be queried too frequently, keeping winbindd
 busy, and blocking smbd while winbindd is busy with other
 stuff. Written by Michael Steffens <michael.steffens@hp.com>,
 modified to use linked lists by jra.
*****************************************************************/  

#define MAX_UID_SID_CACHE_SIZE 100
#define TURNOVER_UID_SID_CACHE_SIZE 10
#define MAX_GID_SID_CACHE_SIZE 100
#define TURNOVER_GID_SID_CACHE_SIZE 10

static size_t n_uid_sid_cache = 0;
static size_t n_gid_sid_cache = 0;

static struct uid_sid_cache {
	struct uid_sid_cache *next, *prev;
	uid_t uid;
	DOM_SID sid;
	enum SID_NAME_USE sidtype;
} *uid_sid_cache_head;

static struct gid_sid_cache {
	struct gid_sid_cache *next, *prev;
	gid_t gid;
	DOM_SID sid;
	enum SID_NAME_USE sidtype;
} *gid_sid_cache_head;

/*****************************************************************
  Find a SID given a uid.
*****************************************************************/  

static BOOL fetch_sid_from_uid_cache(DOM_SID *psid, uid_t uid)
{
	struct uid_sid_cache *pc;

	for (pc = uid_sid_cache_head; pc; pc = pc->next) {
		if (pc->uid == uid) {
			fstring sid;
			*psid = pc->sid;
			DEBUG(3,("fetch sid from uid cache %u -> %s\n",
				(unsigned int)uid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(uid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
  Find a uid given a SID.
*****************************************************************/  

static BOOL fetch_uid_from_cache( uid_t *puid, const DOM_SID *psid )
{
	struct uid_sid_cache *pc;

	for (pc = uid_sid_cache_head; pc; pc = pc->next) {
		if (sid_compare(&pc->sid, psid) == 0) {
			fstring sid;
			*puid = pc->uid;
			DEBUG(3,("fetch uid from cache %u -> %s\n",
				(unsigned int)*puid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(uid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
 Store uid to SID mapping in cache.
*****************************************************************/  

static void store_uid_sid_cache(const DOM_SID *psid, uid_t uid)
{
	struct uid_sid_cache *pc;

	if (n_uid_sid_cache >= MAX_UID_SID_CACHE_SIZE && n_uid_sid_cache > TURNOVER_UID_SID_CACHE_SIZE) {
		/* Delete the last TURNOVER_UID_SID_CACHE_SIZE entries. */
		struct uid_sid_cache *pc_next;
		size_t i;

		for (i = 0, pc = uid_sid_cache_head; i < (n_uid_sid_cache - TURNOVER_UID_SID_CACHE_SIZE); i++, pc = pc->next)
			;
		for(; pc; pc = pc_next) {
			pc_next = pc->next;
			DLIST_REMOVE(uid_sid_cache_head,pc);
			SAFE_FREE(pc);
			n_uid_sid_cache--;
		}
	}

	pc = (struct uid_sid_cache *)malloc(sizeof(struct uid_sid_cache));
	if (!pc)
		return;
	pc->uid = uid;
	sid_copy(&pc->sid, psid);
	DLIST_ADD(uid_sid_cache_head, pc);
	n_uid_sid_cache++;
}

/*****************************************************************
  Find a SID given a gid.
*****************************************************************/  

static BOOL fetch_sid_from_gid_cache(DOM_SID *psid, gid_t gid)
{
	struct gid_sid_cache *pc;

	for (pc = gid_sid_cache_head; pc; pc = pc->next) {
		if (pc->gid == gid) {
			fstring sid;
			*psid = pc->sid;
			DEBUG(3,("fetch sid from gid cache %u -> %s\n",
				(unsigned int)gid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(gid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
  Find a gid given a SID.
*****************************************************************/  

static BOOL fetch_gid_from_cache(gid_t *pgid, const DOM_SID *psid)
{
	struct gid_sid_cache *pc;

	for (pc = gid_sid_cache_head; pc; pc = pc->next) {
		if (sid_compare(&pc->sid, psid) == 0) {
			fstring sid;
			*pgid = pc->gid;
			DEBUG(3,("fetch uid from cache %u -> %s\n",
				(unsigned int)*pgid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(gid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
 Store gid to SID mapping in cache.
*****************************************************************/  

static void store_gid_sid_cache(const DOM_SID *psid, gid_t gid)
{
	struct gid_sid_cache *pc;

	if (n_gid_sid_cache >= MAX_GID_SID_CACHE_SIZE && n_gid_sid_cache > TURNOVER_GID_SID_CACHE_SIZE) {
		/* Delete the last TURNOVER_GID_SID_CACHE_SIZE entries. */
		struct gid_sid_cache *pc_next;
		size_t i;

		for (i = 0, pc = gid_sid_cache_head; i < (n_gid_sid_cache - TURNOVER_GID_SID_CACHE_SIZE); i++, pc = pc->next)
			;
		for(; pc; pc = pc_next) {
			pc_next = pc->next;
			DLIST_REMOVE(gid_sid_cache_head,pc);
			SAFE_FREE(pc);
			n_gid_sid_cache--;
		}
	}

	pc = (struct gid_sid_cache *)malloc(sizeof(struct gid_sid_cache));
	if (!pc)
		return;
	pc->gid = gid;
	sid_copy(&pc->sid, psid);
	DLIST_ADD(gid_sid_cache_head, pc);
	n_gid_sid_cache++;
}

/*****************************************************************
 *THE CANONICAL* convert uid_t to SID function.
*****************************************************************/  

NTSTATUS uid_to_sid(DOM_SID *psid, uid_t uid)
{
	fstring sid;
	uid_t low, high;

	ZERO_STRUCTP(psid);

	if (fetch_sid_from_uid_cache(psid, uid))
		return ( psid ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL );

	/* DC's never use winbindd to resolve users outside the 
	   defined idmap range */

	if ( lp_server_role()==ROLE_DOMAIN_MEMBER 
		|| (lp_idmap_uid(&low, &high) && uid >= low && uid <= high) ) 
	{
		if (winbind_uid_to_sid(psid, uid)) {

			DEBUG(10,("uid_to_sid: winbindd %u -> %s\n",
				(unsigned int)uid, sid_to_string(sid, psid)));

			if (psid)
				store_uid_sid_cache(psid, uid);
			return ( psid ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL );
		}
	}

	if (!local_uid_to_sid(psid, uid)) {
		DEBUG(10,("uid_to_sid: local %u failed to map to sid\n", (unsigned int)uid ));
		return NT_STATUS_UNSUCCESSFUL;
	}
        
	DEBUG(10,("uid_to_sid: local %u -> %s\n", (unsigned int)uid, sid_to_string(sid, psid)));

	store_uid_sid_cache(psid, uid);
	return NT_STATUS_OK;
}

/*****************************************************************
 *THE CANONICAL* convert gid_t to SID function.
*****************************************************************/  

NTSTATUS gid_to_sid(DOM_SID *psid, gid_t gid)
{
	fstring sid;
	gid_t low, high;

	ZERO_STRUCTP(psid);

	if (fetch_sid_from_gid_cache(psid, gid))
		return ( psid ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL );

	/* DC's never use winbindd to resolve groups outside the
	   defined idmap range */

	if ( lp_server_role()==ROLE_DOMAIN_MEMBER
		|| (lp_idmap_gid(&low, &high) && gid >= low && gid <= high) )
        {
		if (winbind_gid_to_sid(psid, gid)) {

			DEBUG(10,("gid_to_sid: winbindd %u -> %s\n",
				(unsigned int)gid, sid_to_string(sid, psid)));
                        
			if (psid)
				store_gid_sid_cache(psid, gid);
			return ( psid ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL );
		}
	}

	if (!local_gid_to_sid(psid, gid)) {
		DEBUG(10,("gid_to_sid: local %u failed to map to sid\n", (unsigned int)gid ));
		return NT_STATUS_UNSUCCESSFUL;
	}
        
	DEBUG(10,("gid_to_sid: local %u -> %s\n", (unsigned int)gid, sid_to_string(sid, psid)));

	store_gid_sid_cache(psid, gid);
	return NT_STATUS_OK;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
*****************************************************************/  

NTSTATUS sid_to_uid(const DOM_SID *psid, uid_t *puid)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;

	if (fetch_uid_from_cache(puid, psid))
		return NT_STATUS_OK;

	/* if this is our SID then go straight to a local lookup */
	
	if ( sid_compare_domain(get_global_sam_sid(), psid) == 0 ) {
		DEBUG(10,("sid_to_uid: my domain (%s) - trying local.\n",
			sid_string_static(psid) ));
		
		if ( local_sid_to_uid(puid, psid, &name_type) )
			goto success;
			
		DEBUG(10,("sid_to_uid: local lookup failed\n"));
		
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* If it is not our local domain, only hope is winbindd */

	if ( !winbind_lookup_sid(psid, dom_name, name, &name_type) ) {
		DEBUG(10,("sid_to_uid: winbind lookup for non-local sid %s failed\n",
			sid_string_static(psid) ));
			
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* If winbindd does know the SID, ensure this is a user */

	if (name_type != SID_NAME_USER) {
		DEBUG(10,("sid_to_uid: winbind lookup succeeded but SID is not a user (%u)\n",
			(unsigned int)name_type ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* get the uid.  Has to work or else we are dead in the water */

	if ( !winbind_sid_to_uid(puid, psid) ) {
		DEBUG(10,("sid_to_uid: winbind failed to allocate a new uid for sid %s\n",
			sid_to_string(sid_str, psid) ));
		return NT_STATUS_UNSUCCESSFUL;
	}

success:
	DEBUG(10,("sid_to_uid: %s -> %u\n", sid_to_string(sid_str, psid),
		(unsigned int)*puid ));

	store_uid_sid_cache(psid, *puid);
	
	return NT_STATUS_OK;
}
/*****************************************************************
 *THE CANONICAL* convert SID to gid function.
 Group mapping is used for gids that maps to Wellknown SIDs
*****************************************************************/  

NTSTATUS sid_to_gid(const DOM_SID *psid, gid_t *pgid)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;

	if (fetch_gid_from_cache(pgid, psid))
		return NT_STATUS_OK;

	/*
	 * First we must look up the name and decide if this is a group sid.
	 * Group mapping can deal with foreign SIDs
	 */

	if (!winbind_lookup_sid(psid, dom_name, name, &name_type)) {
		DEBUG(10,("sid_to_gid: winbind lookup for sid %s failed - trying local.\n",
			sid_to_string(sid_str, psid) ));

		if ( local_sid_to_gid(pgid, psid, &name_type) )
			goto success;
			
		DEBUG(10,("sid_to_gid: no one knows this SID\n"));
		
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* winbindd knows it; Ensure this is a group sid */

	if ((name_type != SID_NAME_DOM_GRP) && (name_type != SID_NAME_ALIAS) 
		&& (name_type != SID_NAME_WKN_GRP)) 
	{
		DEBUG(10,("sid_to_gid: winbind lookup succeeded but SID is not a known group (%u)\n",
			(unsigned int)name_type ));

		/* winbindd is running and knows about this SID.  Just the wrong type.
		   Don't fallback to a local lookup here */
		   
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	/* winbindd knows it and it is a type of group; sid_to_gid must succeed
	   or we are dead in the water */

	if ( !winbind_sid_to_gid(pgid, psid) ) {
		DEBUG(10,("sid_to_uid: winbind failed to allocate a new gid for sid %s\n",
			sid_to_string(sid_str, psid) ));
		return NT_STATUS_UNSUCCESSFUL;
	}

success:
	DEBUG(10,("sid_to_gid: %s -> %u\n", sid_to_string(sid_str, psid),
		(unsigned int)*pgid ));

	store_gid_sid_cache(psid, *pgid);
	
	return NT_STATUS_OK;
}

