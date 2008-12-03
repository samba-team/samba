/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - sid related functions

   Copyright (C) Tim Potter 2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Convert a string  */

static void lookupsid_recv(void *private_data, bool success,
			   const char *dom_name, const char *name,
			   enum lsa_SidType type);

void winbindd_lookupsid(struct winbindd_cli_state *state)
{
	DOM_SID sid;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: lookupsid %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(5, ("%s not a SID\n", state->request.data.sid));
		request_error(state);
		return;
	}

	winbindd_lookupsid_async(state->mem_ctx, &sid, lookupsid_recv, state);
}

static void lookupsid_recv(void *private_data, bool success,
			   const char *dom_name, const char *name,
			   enum lsa_SidType type)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		DEBUG(5, ("lookupsid returned an error\n"));
		request_error(state);
		return;
	}

	fstrcpy(state->response.data.name.dom_name, dom_name);
	fstrcpy(state->response.data.name.name, name);
	state->response.data.name.type = type;
	request_ok(state);
}

/**
 * Look up the SID for a qualified name.  
 **/

static void lookupname_recv(void *private_data, bool success,
			    const DOM_SID *sid, enum lsa_SidType type);

void winbindd_lookupname(struct winbindd_cli_state *state)
{
	char *name_domain, *name_user;
	char *p;

	/* Ensure null termination */
	state->request.data.name.dom_name[sizeof(state->request.data.name.dom_name)-1]='\0';

	/* Ensure null termination */
	state->request.data.name.name[sizeof(state->request.data.name.name)-1]='\0';

	/* cope with the name being a fully qualified name */
	p = strstr(state->request.data.name.name, lp_winbind_separator());
	if (p) {
		*p = 0;
		name_domain = state->request.data.name.name;
		name_user = p+1;
	} else {
		name_domain = state->request.data.name.dom_name;
		name_user = state->request.data.name.name;
	}

	DEBUG(3, ("[%5lu]: lookupname %s%s%s\n", (unsigned long)state->pid,
		  name_domain, lp_winbind_separator(), name_user));

	winbindd_lookupname_async(state->mem_ctx, name_domain, name_user,
				  lookupname_recv, WINBINDD_LOOKUPNAME, 
				  state);
}

static void lookupname_recv(void *private_data, bool success,
			    const DOM_SID *sid, enum lsa_SidType type)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		DEBUG(5, ("lookupname returned an error\n"));
		request_error(state);
		return;
	}

	sid_to_fstring(state->response.data.sid.sid, sid);
	state->response.data.sid.type = type;
	request_ok(state);
	return;
}

void winbindd_lookuprids(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	DOM_SID domain_sid;
	
	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(10, ("lookup_rids: %s\n", state->request.data.sid));

	if (!string_to_sid(&domain_sid, state->request.data.sid)) {
		DEBUG(5, ("Could not convert %s to SID\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	domain = find_lookup_domain_from_sid(&domain_sid);
	if (domain == NULL) {
		DEBUG(10, ("Could not find domain for name %s\n",
			   state->request.domain_name));
		request_error(state);
		return;
	}

	sendto_domain(state, domain);
}

/* Convert a sid to a uid.  We assume we only have one rid attached to the
   sid. */

static void sid2uid_recv(void *private_data, bool success, uid_t uid)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);
	struct dom_sid sid;

	string_to_sid(&sid, state->request.data.sid);

	if (!success) {
		DEBUG(5, ("Could not convert sid %s\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	state->response.data.uid = uid;
	request_ok(state);
}

static void sid2uid_lookupsid_recv( void *private_data, bool success, 
				    const char *domain_name, 
				    const char *name, 
				    enum lsa_SidType type)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);
	DOM_SID sid;

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("sid2uid_lookupsid_recv: Could not get convert sid "
			  "%s from string\n", state->request.data.sid));
		request_error(state);
		return;
	}

	if (!success) {
		DEBUG(5, ("sid2uid_lookupsid_recv Could not convert get sid type for %s\n",
			  state->request.data.sid));
		goto fail;
	}

	if ( (type!=SID_NAME_USER) && (type!=SID_NAME_COMPUTER) ) {
		DEBUG(5,("sid2uid_lookupsid_recv: Sid %s is not a user or a computer.\n", 
			 state->request.data.sid));
		goto fail;
	}

	/* always use the async interface (may block) */
	winbindd_sid2uid_async(state->mem_ctx, &sid, sid2uid_recv, state);
	return;

 fail:
	/*
	 * We have to set the cache ourselves here, the child which is
	 * normally responsible was not queried yet.
	 */
	idmap_cache_set_sid2uid(&sid, -1);
	request_error(state);
	return;
}

void winbindd_sid_to_uid(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	uid_t uid;
	bool expired;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: sid to uid %s\n", (unsigned long)state->pid,
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	if (idmap_cache_find_sid2uid(&sid, &uid, &expired)) {
		DEBUG(10, ("idmap_cache_find_sid2uid found %d%s\n",
			   (int)uid, expired ? " (expired)": ""));
		if (expired && IS_DOMAIN_ONLINE(find_our_domain())) {
			DEBUG(10, ("revalidating expired entry\n"));
			goto backend;
		}
		if (uid == -1) {
			DEBUG(10, ("Returning negative cache entry\n"));
			request_error(state);
			return;
		}
		DEBUG(10, ("Returning positive cache entry\n"));
		state->response.data.uid = uid;
		request_ok(state);
		return;
	}

	/* Validate the SID as a user.  Hopefully this will hit cache.
	   Needed to prevent DoS by exhausting the uid allocation
	   range from random SIDs. */

 backend:
	winbindd_lookupsid_async( state->mem_ctx, &sid, sid2uid_lookupsid_recv, state );
}

/* Convert a sid to a gid.  We assume we only have one rid attached to the
   sid.*/

static void sid2gid_recv(void *private_data, bool success, gid_t gid)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);
	struct dom_sid sid;

	string_to_sid(&sid, state->request.data.sid);

	if (!success) {
		DEBUG(5, ("Could not convert sid %s\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	state->response.data.gid = gid;
	request_ok(state);
}

static void sid2gid_lookupsid_recv( void *private_data, bool success, 
				    const char *domain_name, 
				    const char *name, 
				    enum lsa_SidType type)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);
	DOM_SID sid;

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("sid2gid_lookupsid_recv: Could not get convert sid "
			  "%s from string\n", state->request.data.sid));
		request_error(state);
		return;
	}

	if (!success) {
		DEBUG(5, ("sid2gid_lookupsid_recv: Could not get sid type for %s\n",
			  state->request.data.sid));
		goto fail;
	}

	if ( (type!=SID_NAME_DOM_GRP) &&
	     (type!=SID_NAME_ALIAS) && 
	     (type!=SID_NAME_WKN_GRP) ) 
	{
		DEBUG(5,("sid2gid_lookupsid_recv: Sid %s is not a group.\n", 
			 state->request.data.sid));
		goto fail;
	}

	/* always use the async interface (may block) */
	winbindd_sid2gid_async(state->mem_ctx, &sid, sid2gid_recv, state);
	return;

 fail:
	/*
	 * We have to set the cache ourselves here, the child which is
	 * normally responsible was not queried yet.
	 */
	idmap_cache_set_sid2gid(&sid, -1);
	request_error(state);
	return;
}

void winbindd_sid_to_gid(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	gid_t gid;
	bool expired;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: sid to gid %s\n", (unsigned long)state->pid,
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	if (idmap_cache_find_sid2gid(&sid, &gid, &expired)) {
		DEBUG(10, ("idmap_cache_find_sid2gid found %d%s\n",
			   (int)gid, expired ? " (expired)": ""));
		if (expired && IS_DOMAIN_ONLINE(find_our_domain())) {
			DEBUG(10, ("revalidating expired entry\n"));
			goto backend;
		}
		if (gid == -1) {
			DEBUG(10, ("Returning negative cache entry\n"));
			request_error(state);
			return;
		}
		DEBUG(10, ("Returning positive cache entry\n"));
		state->response.data.gid = gid;
		request_ok(state);
		return;
	}

	/* Validate the SID as a group.  Hopefully this will hit cache.
	   Needed to prevent DoS by exhausting the uid allocation
	   range from random SIDs. */

 backend:
	winbindd_lookupsid_async( state->mem_ctx, &sid, sid2gid_lookupsid_recv,
				  state );
}

static void set_mapping_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		DEBUG(5, ("Could not set sid mapping\n"));
		request_error(state);
		return;
	}

	request_ok(state);
}

void winbindd_set_mapping(struct winbindd_cli_state *state)
{
	struct id_map map;
	DOM_SID sid;

	DEBUG(3, ("[%5lu]: set id map\n", (unsigned long)state->pid));

	if ( ! state->privileged) {
		DEBUG(0, ("Only root is allowed to set mappings!\n"));
		request_error(state);
		return;
	}

	if (!string_to_sid(&sid, state->request.data.dual_idmapset.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	map.sid = &sid;
	map.xid.id = state->request.data.dual_idmapset.id;
	map.xid.type = state->request.data.dual_idmapset.type;

	winbindd_set_mapping_async(state->mem_ctx, &map,
			set_mapping_recv, state);
}

static void remove_mapping_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		DEBUG(5, ("Could not remove sid mapping\n"));
		request_error(state);
		return;
	}

	request_ok(state);
}

void winbindd_remove_mapping(struct winbindd_cli_state *state)
{
	struct id_map map;
	DOM_SID sid;

	DEBUG(3, ("[%5lu]: remove id map\n", (unsigned long)state->pid));

	if ( ! state->privileged) {
		DEBUG(0, ("Only root is allowed to remove mappings!\n"));
		request_error(state);
		return;
	}

	if (!string_to_sid(&sid, state->request.data.dual_idmapset.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.sid));
		request_error(state);
		return;
	}

	map.sid = &sid;
	map.xid.id = state->request.data.dual_idmapset.id;
	map.xid.type = state->request.data.dual_idmapset.type;

	winbindd_remove_mapping_async(state->mem_ctx, &map,
			remove_mapping_recv, state);
}

static void set_hwm_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		DEBUG(5, ("Could not set sid mapping\n"));
		request_error(state);
		return;
	}

	request_ok(state);
}

void winbindd_set_hwm(struct winbindd_cli_state *state)
{
	struct unixid xid;

	DEBUG(3, ("[%5lu]: set hwm\n", (unsigned long)state->pid));

	if ( ! state->privileged) {
		DEBUG(0, ("Only root is allowed to set mappings!\n"));
		request_error(state);
		return;
	}

	xid.id = state->request.data.dual_idmapset.id;
	xid.type = state->request.data.dual_idmapset.type;

	winbindd_set_hwm_async(state->mem_ctx, &xid, set_hwm_recv, state);
}

/* Convert a uid to a sid */

static void uid2sid_recv(void *private_data, bool success, const char *sidstr)
{
	struct winbindd_cli_state *state =
		(struct winbindd_cli_state *)private_data;
	struct dom_sid sid;

	if (!success || !string_to_sid(&sid, sidstr)) {
		ZERO_STRUCT(sid);
		idmap_cache_set_sid2uid(&sid, state->request.data.uid);
		request_error(state);
		return;
	}

	DEBUG(10,("uid2sid: uid %lu has sid %s\n",
		  (unsigned long)(state->request.data.uid), sidstr));

	idmap_cache_set_sid2uid(&sid, state->request.data.uid);
	fstrcpy(state->response.data.sid.sid, sidstr);
	state->response.data.sid.type = SID_NAME_USER;
	request_ok(state);
	return;
}

void winbindd_uid_to_sid(struct winbindd_cli_state *state)
{
	struct dom_sid sid;
	bool expired;

	DEBUG(3, ("[%5lu]: uid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.uid));

	if (idmap_cache_find_uid2sid(state->request.data.uid, &sid,
				     &expired)) {
		DEBUG(10, ("idmap_cache_find_uid2sid found %d%s\n",
			   (int)state->request.data.uid,
			   expired ? " (expired)": ""));
		if (expired && IS_DOMAIN_ONLINE(find_our_domain())) {
			DEBUG(10, ("revalidating expired entry\n"));
			goto backend;
		}
		if (is_null_sid(&sid)) {
			DEBUG(10, ("Returning negative cache entry\n"));
			request_error(state);
			return;
		}
		DEBUG(10, ("Returning positive cache entry\n"));
		sid_to_fstring(state->response.data.sid.sid, &sid);
		request_ok(state);
		return;
	}

	/* always go via the async interface (may block) */
 backend:
	winbindd_uid2sid_async(state->mem_ctx, state->request.data.uid, uid2sid_recv, state);
}

/* Convert a gid to a sid */

static void gid2sid_recv(void *private_data, bool success, const char *sidstr)
{
	struct winbindd_cli_state *state =
		(struct winbindd_cli_state *)private_data;
	struct dom_sid sid;

	if (!success || !string_to_sid(&sid, sidstr)) {
		ZERO_STRUCT(sid);
		idmap_cache_set_sid2gid(&sid, state->request.data.gid);
		request_error(state);
		return;
	}
	DEBUG(10,("gid2sid: gid %lu has sid %s\n",
		  (unsigned long)(state->request.data.gid), sidstr));

	idmap_cache_set_sid2gid(&sid, state->request.data.gid);
	fstrcpy(state->response.data.sid.sid, sidstr);
	state->response.data.sid.type = SID_NAME_DOM_GRP;
	request_ok(state);
	return;
}


void winbindd_gid_to_sid(struct winbindd_cli_state *state)
{
	struct dom_sid sid;
	bool expired;

	DEBUG(3, ("[%5lu]: gid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.gid));

	if (idmap_cache_find_gid2sid(state->request.data.gid, &sid,
				     &expired)) {
		DEBUG(10, ("idmap_cache_find_gid2sid found %d%s\n",
			   (int)state->request.data.gid,
			   expired ? " (expired)": ""));
		if (expired && IS_DOMAIN_ONLINE(find_our_domain())) {
			DEBUG(10, ("revalidating expired entry\n"));
			goto backend;
		}
		if (is_null_sid(&sid)) {
			DEBUG(10, ("Returning negative cache entry\n"));
			request_error(state);
			return;
		}
		DEBUG(10, ("Returning positive cache entry\n"));
		sid_to_fstring(state->response.data.sid.sid, &sid);
		request_ok(state);
		return;
	}

	/* always use async calls (may block) */
 backend:
	winbindd_gid2sid_async(state->mem_ctx, state->request.data.gid, gid2sid_recv, state);
}

void winbindd_allocate_uid(struct winbindd_cli_state *state)
{
	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_allocate_uid: non-privileged access "
			  "denied!\n"));
		request_error(state);
		return;
	}

	sendto_child(state, idmap_child());
}

enum winbindd_result winbindd_dual_allocate_uid(struct winbindd_domain *domain,
						struct winbindd_cli_state *state)
{
	struct unixid xid;

	if (!NT_STATUS_IS_OK(idmap_allocate_uid(&xid))) {
		return WINBINDD_ERROR;
	}
	state->response.data.uid = xid.id;
	return WINBINDD_OK;
}

void winbindd_allocate_gid(struct winbindd_cli_state *state)
{
	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_allocate_gid: non-privileged access "
			  "denied!\n"));
		request_error(state);
		return;
	}

	sendto_child(state, idmap_child());
}

enum winbindd_result winbindd_dual_allocate_gid(struct winbindd_domain *domain,
						struct winbindd_cli_state *state)
{
	struct unixid xid;

	if (!NT_STATUS_IS_OK(idmap_allocate_gid(&xid))) {
		return WINBINDD_ERROR;
	}
	state->response.data.gid = xid.id;
	return WINBINDD_OK;
}
