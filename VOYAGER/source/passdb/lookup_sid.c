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
*****************************************************************/  

BOOL lookup_name(const char *domain, const char *name, DOM_SID *psid,
		 enum SID_NAME_USE *name_type)
{
	struct passwd *pwd;
	struct group *grp;
	char *unix_name;
	BOOL is_user;

	if (winbind_lookup_name(domain, name, psid, name_type))
		return True;

	if (!strequal(domain, get_global_sam_name()))
		return False;

	if (!nt_to_unix_name(name, &unix_name, &is_user))
		return False;

	if (is_user) {
		if (((pwd = getpwnam(unix_name)) != NULL) &&
		    (NT_STATUS_IS_OK(uid_to_sid(psid, pwd->pw_uid)))) {
			SAFE_FREE(unix_name);
			*name_type = SID_NAME_USER;
			return True;
		}
	} else {
		if (((grp = getgrnam(unix_name)) != NULL) &&
		    (NT_STATUS_IS_OK(gid_to_sid(psid, grp->gr_gid)))) {
			*name_type = SID_NAME_DOM_GRP;
			return True;
		}
	}

	SAFE_FREE(unix_name);
	return False;
}

/*****************************************************************
 *THE CANONICAL* convert SID to name function.
*****************************************************************/  

BOOL lookup_sid(const DOM_SID *sid, fstring dom_name, fstring name,
		enum SID_NAME_USE *name_type)
{
	uid_t uid;
	struct passwd *pwd;

	gid_t gid;
	struct group *grp;

	if (winbind_lookup_sid(sid, dom_name, name, name_type))
		return True;

	if ((NT_STATUS_IS_OK(sid_to_uid(sid, &uid))) &&
	    ((pwd = getpwuid(uid)) != NULL)) {

		char *ntname;

		fstrcpy(dom_name, get_global_sam_name());

		unix_username_to_ntname(pwd->pw_name, &ntname);
		fstrcpy(name, ntname);
		SAFE_FREE(ntname);

		*name_type = SID_NAME_USER;
		return True;
	}

	if ((NT_STATUS_IS_OK(sid_to_gid(sid, &gid))) &&
	    ((grp = getgrgid(gid)) != NULL)) {

		char *ntname;

		fstrcpy(dom_name, get_global_sam_name());

		unix_groupname_to_ntname(grp->gr_name, &ntname);
		fstrcpy(name, ntname);
		SAFE_FREE(ntname);

		*name_type = SID_NAME_DOM_GRP;
		return True;
	}

	return False;
}

BOOL sid_to_local_user_name(const DOM_SID *sid, fstring username)
{
	fstring dom_name;
	fstring name;
	enum SID_NAME_USE type;

	if (!sid_check_is_in_our_domain(sid))
		return False;

	if (!lookup_sid(sid, dom_name, name, &type))
		return False;
 
	if (type != SID_NAME_USER)
		return False;
 
	fstrcpy(username, name);
 	return True;
}

BOOL sid_to_local_dom_grp_name(const DOM_SID *sid, fstring groupname)
{
	fstring dom_name;
	fstring name;
	enum SID_NAME_USE type;

	if (!sid_check_is_in_our_domain(sid))
		return False;

	if (!lookup_sid(sid, dom_name, name, &type))
		return False;

	if (type != SID_NAME_DOM_GRP)
		return False;

	fstrcpy(groupname, name);
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
	if (fetch_sid_from_uid_cache(psid, uid))
		return NT_STATUS_OK;

	if (!winbind_uid_to_sid(psid, uid)) {
		sid_copy(psid, get_global_sam_sid());
		sid_append_rid(psid, fallback_pdb_uid_to_user_rid(uid));
	}

	store_uid_sid_cache(psid, uid);

	DEBUG(10,("uid_to_sid: local %u -> %s\n", (unsigned int)uid,
		  sid_string_static(psid)));

	return NT_STATUS_OK;
}

/*****************************************************************
 *THE CANONICAL* convert gid_t to SID function.
*****************************************************************/  

NTSTATUS gid_to_sid(DOM_SID *psid, gid_t gid)
{
	if (fetch_sid_from_gid_cache(psid, gid))
		return NT_STATUS_OK;

	if (!winbind_gid_to_sid(psid, gid)) {
		sid_copy(psid, get_global_sam_sid());
		sid_append_rid(psid, pdb_gid_to_group_rid(gid));
	}

	store_gid_sid_cache(psid, gid);
        
	DEBUG(10,("gid_to_sid: local %u -> %s\n", (unsigned int)gid,
		  sid_string_static(psid)));

	return NT_STATUS_OK;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
*****************************************************************/  

NTSTATUS sid_to_uid(const DOM_SID *psid, uid_t *puid)
{
	uint32 rid;

	if (fetch_uid_from_cache(puid, psid))
		return NT_STATUS_OK;

	if (winbind_sid_to_uid_query(puid, psid))
		goto done;

	if (!sid_peek_rid(psid, &rid)) {
		DEBUG(1, ("Not a valid SID %s\n", sid_string_static(psid)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!sid_check_is_in_our_domain(psid) ) {
		DEBUG(5,("%s is not from our domain\n",
			 sid_string_static(psid)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!fallback_pdb_rid_is_user(rid)) {
		DEBUG(5, ("%s is no user SID\n", sid_string_static(psid)));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	*puid = fallback_pdb_user_rid_to_uid(rid);

 done:
	store_uid_sid_cache(psid, *puid);
	
	DEBUG(10, ("SID %s -> uid %u\n", sid_string_static(psid), *puid));

	return NT_STATUS_OK;
}

/*****************************************************************
 *THE CANONICAL* convert SID to gid function.
*****************************************************************/  

NTSTATUS sid_to_gid(const DOM_SID *psid, gid_t *pgid)
{
	uint32 rid;

	if (fetch_gid_from_cache(pgid, psid))
		return NT_STATUS_OK;

	if (winbind_sid_to_gid_query(pgid, psid))
		goto done;

	if (!sid_peek_rid(psid, &rid)) {
		DEBUG(1, ("Not a valid SID %s\n", sid_string_static(psid)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!sid_check_is_in_our_domain(psid) ) {
		DEBUG(5,("This SID (%s) is not from our domain\n",
			 sid_string_static(psid)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (fallback_pdb_rid_is_user(rid)) {
		DEBUG(5, ("%s is no group SID\n", sid_string_static(psid)));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	*pgid = pdb_group_rid_to_gid(rid);

 done:
	store_gid_sid_cache(psid, *pgid);

	DEBUG(10, ("SID %s -> gid %u\n", sid_string_static(psid), *pgid));

	return NT_STATUS_OK;
}
