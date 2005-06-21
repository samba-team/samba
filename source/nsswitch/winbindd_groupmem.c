/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - Calculate expanded group memberships

   Copyright (C) Volker Lendecke 2005
   
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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

struct groupmembers_state {
	TALLOC_CTX *mem_ctx;
	DOM_SID group_sid;

	const char *domain_name;
	const char *group_name;
	enum SID_NAME_USE group_type;

	ssize_t member_array_size; /* For add_to_large_array */
	int num_finished, num_members;
	struct sid_ctr *members;
	struct sid_ctr **lookup_ctrs;

	void (*cont)(void *private, BOOL success,
		     uint32 num_members,
		     const char **domains,
		     const char **names);
	void *private;
};

static void grpmem_sid2name_recv(void *private, BOOL success,
				 const char *dom_name,
				 const char *name,
				 enum SID_NAME_USE type);
static void grpmem_aliasmem_recv(void *private, BOOL success,
				 uint32 num_members,
				 DOM_SID *members);
static void grpmem_groupmem_recv(void *private, BOOL success,
				 uint32 num_members,
				 uint32 *members);
static void lookup_members(struct groupmembers_state *state);
static void lookup_members_recv(void *private, BOOL success,
				uint32 num_sids, const char **domains,
				const char **names,
				enum SID_NAME_USE *types);

void winbindd_groupmembers_async(TALLOC_CTX *mem_ctx, const DOM_SID *group_sid,
				 void (*cont)(void *private, BOOL success,
					      uint32 num_members,
					      const char **domains,
					      const char **names),
				 void *private)
{
	struct groupmembers_state *state;

	state = TALLOC_P(mem_ctx, struct groupmembers_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		cont(private, False, 0, NULL, NULL);
		return;
	}

	state->mem_ctx = mem_ctx;
	sid_copy(&state->group_sid, group_sid);

	state->member_array_size = 0;
	state->num_members = 0;
	state->num_finished = 0;
	state->members = NULL;

	state->cont = cont;
	state->private = private;

	winbindd_lookupsid_async(mem_ctx, group_sid, grpmem_sid2name_recv,
				 state);
}

static void grpmem_sid2name_recv(void *private, BOOL success,
				 const char *dom_name,
				 const char *name,
				 enum SID_NAME_USE type)
{
	struct groupmembers_state *state =
		talloc_get_type_abort(private, struct groupmembers_state);

	if (!success) {
		DEBUG(5, ("Could not lookup sid %s\n",
			  sid_string_static(&state->group_sid)));
		state->cont(state->private, False, 0, NULL, NULL);
		return;
	}

	state->domain_name = dom_name;
	state->group_name = name;
	state->group_type = type;

	if ((state->group_type == SID_NAME_ALIAS) ||
	    (state->group_type == SID_NAME_WKN_GRP)) {
		query_aliasmem_async(state->mem_ctx, &state->group_sid,
				     grpmem_aliasmem_recv, state);
		return;
	}

	if (state->group_type == SID_NAME_DOM_GRP) {
		query_groupmem_async(state->mem_ctx, &state->group_sid,
				     grpmem_groupmem_recv, state);
		return;
	}

	DEBUG(5, ("%s\\%s is not a group: %s\n", dom_name, name,
		  sid_type_lookup(type)));
	state->cont(state->private, False, 0, NULL, NULL);
}

static void grpmem_aliasmem_recv(void *private, BOOL success,
				 uint32 num_members,
				 DOM_SID *members)
{
	struct groupmembers_state *state =
		talloc_get_type_abort(private, struct groupmembers_state);
	int i;

	if (!success) {
		DEBUG(5, ("Could not get alias members for %s\n",
			  sid_string_static(&state->group_sid)));
		state->cont(state->private, False, 0, NULL, NULL);
		return;
	}

	if (num_members == 0) {
		state->cont(state->private, True, 0, NULL, NULL);
		return;
	}

	state->members = TALLOC_ARRAY(state->mem_ctx, struct sid_ctr,
				      num_members);
	if (state->members == NULL) {
		DEBUG(0, ("talloc failed\n"));
		state->cont(state->private, False, 0, NULL, NULL);
		return;
	}

	state->member_array_size = state->num_members = num_members;

	for (i=0; i<num_members; i++) {
		state->members[i].sid = &members[i];
		state->members[i].finished = False;
	}

	lookup_members(state);
}

static void grpmem_groupmem_recv(void *private, BOOL success,
				 uint32 num_members,
				 uint32 *members)
{
	struct groupmembers_state *state =
		talloc_get_type_abort(private, struct groupmembers_state);
	int i, j;
	DOM_SID domain_sid;
	uint32 group_rid;

	if (!success) {
		DEBUG(5, ("Could not get group members for %s\n",
			  sid_string_static(&state->group_sid)));
		state->cont(state->private, False, 0, NULL, NULL);
		return;
	}

	if (num_members == 0) {
		state->cont(state->private, True, 0, NULL, NULL);
		return;
	}

	sid_copy(&domain_sid, &state->group_sid);
	sid_split_rid(&domain_sid, &group_rid);

	for (i=0; i<num_members; i++) {
		struct sid_ctr ctr;
		ctr.sid = sid_dup_talloc(state->mem_ctx, &domain_sid);
		if (ctr.sid == NULL) {
			DEBUG(0, ("talloc failed\n"));
			state->cont(state->private, False, 0, NULL, NULL);
			return;
		}
		sid_append_rid(ctr.sid, members[i]);
		ctr.finished = False;

		for (j=0; j<state->num_members; j++) {
			if (sid_equal(ctr.sid, state->members[j].sid)) {
				break;
			}
		}
		if (j<state->num_members) {
			continue;
		}
		ADD_TO_LARGE_ARRAY(state->mem_ctx, struct sid_ctr, ctr,
				   &state->members, &state->num_members,
				   &state->member_array_size);
	}

	lookup_members(state);
}

static void lookup_members(struct groupmembers_state *state)
{
	int i;
	int num_sidptrs = 0;
	int num_lookup_ptrs = 0;
	DOM_SID **sidptrs = NULL;

	state->lookup_ctrs = NULL;

	for (i=0; i<state->num_members; i++) {
		if (state->members[i].finished) {
			continue;
		}
		ADD_TO_ARRAY(state->mem_ctx, DOM_SID *, state->members[i].sid,
			     &sidptrs, &num_sidptrs);
		ADD_TO_ARRAY(state->mem_ctx, struct sid_ctr *,
			     &state->members[i],
			     &state->lookup_ctrs, &num_lookup_ptrs);
	}

	if (sidptrs == NULL) {
		DEBUG(0, ("talloc failed\n"));
		state->cont(state->private, False, 0, NULL, NULL);
		return;
	}

	lookupsids_async(state->mem_ctx, num_sidptrs, sidptrs,
			 lookup_members_recv, state);
}

static void lookup_members_recv(void *private, BOOL success,
				uint32 num_sids, const char **domains,
				const char **names,
				enum SID_NAME_USE *types)
{
	struct groupmembers_state *state =
		talloc_get_type_abort(private, struct groupmembers_state);
	int i;

	const char **result_domains = NULL;
	int num_domains = 0;
	const char **result_names = NULL;
	int num_names = 0;

	if (!success) {
		DEBUG(5, ("Could not lookup groupmembers for %s\n",
			  sid_string_static(&state->group_sid)));
		state->cont(state->private, False, 0, NULL, NULL);
		return;
	}

	for (i=0; i<num_sids; i++) {
		state->lookup_ctrs[i]->domain = domains[i];
		state->lookup_ctrs[i]->name = names[i];
		state->lookup_ctrs[i]->type = types[i];
	}

	for (i=0; i<state->num_members; i++) {
		if (state->members[i].finished) {
			continue;
		}

		if (state->members[i].type == SID_NAME_DOM_GRP) {
			state->members[i].finished = True;
			query_groupmem_async(state->mem_ctx,
					     state->members[i].sid,
					     grpmem_groupmem_recv,
					     state);
			return;
		}

		state->members[i].finished = True;
	}

	for (i=0; i<state->num_members; i++) {
		if (state->members[i].type == SID_NAME_DOM_GRP) {
			continue;
		}
		ADD_TO_ARRAY(state->mem_ctx, const char *,
			     state->members[i].domain,
			     &result_domains, &num_domains);
		ADD_TO_ARRAY(state->mem_ctx, const char *,
			     state->members[i].name,
			     &result_names, &num_names);
	}

	state->cont(state->private, True, num_names, result_domains,
		    result_names);
}
