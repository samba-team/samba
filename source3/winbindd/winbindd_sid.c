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

void winbindd_lookuprids(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	DOM_SID domain_sid;
	
	/* Ensure null termination */
	state->request->data.sid[sizeof(state->request->data.sid)-1]='\0';

	DEBUG(10, ("lookup_rids: %s\n", state->request->data.sid));

	if (!string_to_sid(&domain_sid, state->request->data.sid)) {
		DEBUG(5, ("Could not convert %s to SID\n",
			  state->request->data.sid));
		request_error(state);
		return;
	}

	domain = find_lookup_domain_from_sid(&domain_sid);
	if (domain == NULL) {
		DEBUG(10, ("Could not find domain for name %s\n",
			   state->request->domain_name));
		request_error(state);
		return;
	}

	sendto_domain(state, domain);
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

	if (!string_to_sid(&sid, state->request->data.dual_idmapset.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request->data.sid));
		request_error(state);
		return;
	}

	map.sid = &sid;
	map.xid.id = state->request->data.dual_idmapset.id;
	map.xid.type = state->request->data.dual_idmapset.type;

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

	if (!string_to_sid(&sid, state->request->data.dual_idmapset.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request->data.sid));
		request_error(state);
		return;
	}

	map.sid = &sid;
	map.xid.id = state->request->data.dual_idmapset.id;
	map.xid.type = state->request->data.dual_idmapset.type;

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

	xid.id = state->request->data.dual_idmapset.id;
	xid.type = state->request->data.dual_idmapset.type;

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
		idmap_cache_set_sid2uid(&sid, state->request->data.uid);
		request_error(state);
		return;
	}

	DEBUG(10,("uid2sid: uid %lu has sid %s\n",
		  (unsigned long)(state->request->data.uid), sidstr));

	idmap_cache_set_sid2uid(&sid, state->request->data.uid);
	fstrcpy(state->response->data.sid.sid, sidstr);
	state->response->data.sid.type = SID_NAME_USER;
	request_ok(state);
	return;
}

void winbindd_uid_to_sid(struct winbindd_cli_state *state)
{
	struct dom_sid sid;
	bool expired;

	DEBUG(3, ("[%5lu]: uid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request->data.uid));

	if (idmap_cache_find_uid2sid(state->request->data.uid, &sid,
				     &expired)) {
		DEBUG(10, ("idmap_cache_find_uid2sid found %d%s\n",
			   (int)state->request->data.uid,
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
		sid_to_fstring(state->response->data.sid.sid, &sid);
		request_ok(state);
		return;
	}

	/* always go via the async interface (may block) */
 backend:
	winbindd_uid2sid_async(state->mem_ctx, state->request->data.uid, uid2sid_recv, state);
}

/* Convert a gid to a sid */

static void gid2sid_recv(void *private_data, bool success, const char *sidstr)
{
	struct winbindd_cli_state *state =
		(struct winbindd_cli_state *)private_data;
	struct dom_sid sid;

	if (!success || !string_to_sid(&sid, sidstr)) {
		ZERO_STRUCT(sid);
		idmap_cache_set_sid2gid(&sid, state->request->data.gid);
		request_error(state);
		return;
	}
	DEBUG(10,("gid2sid: gid %lu has sid %s\n",
		  (unsigned long)(state->request->data.gid), sidstr));

	idmap_cache_set_sid2gid(&sid, state->request->data.gid);
	fstrcpy(state->response->data.sid.sid, sidstr);
	state->response->data.sid.type = SID_NAME_DOM_GRP;
	request_ok(state);
	return;
}


void winbindd_gid_to_sid(struct winbindd_cli_state *state)
{
	struct dom_sid sid;
	bool expired;

	DEBUG(3, ("[%5lu]: gid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request->data.gid));

	if (idmap_cache_find_gid2sid(state->request->data.gid, &sid,
				     &expired)) {
		DEBUG(10, ("idmap_cache_find_gid2sid found %d%s\n",
			   (int)state->request->data.gid,
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
		sid_to_fstring(state->response->data.sid.sid, &sid);
		request_ok(state);
		return;
	}

	/* always use async calls (may block) */
 backend:
	winbindd_gid2sid_async(state->mem_ctx, state->request->data.gid, gid2sid_recv, state);
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
	state->response->data.uid = xid.id;
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
	state->response->data.gid = xid.id;
	return WINBINDD_OK;
}
