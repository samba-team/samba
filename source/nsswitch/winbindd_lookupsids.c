/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - Implement the lookupsids function async

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

struct lookupsids_state {
	TALLOC_CTX *mem_ctx;
	uint32 num_sids;
	DOM_SID *sids;

	uint32 num_finished;
	struct sid_ctr *ctrs;

	struct winbindd_domain *domain;
	uint32 num_dom_ctrs;
	struct sid_ctr **dom_ctrs;

	void (*cont)(void *private_data, BOOL success, uint32 num_sids,
		     const char **domains, const char **names,
		     enum SID_NAME_USE *types);
	void *private_data;
};

static void lookup_next_domain(struct lookupsids_state *state);
static void lookupsids_recv(TALLOC_CTX *mem_ctx, BOOL success,
			    struct winbindd_response *response,
			    void *cont, void *private_data);
static void lookupsids_finished(struct lookupsids_state *state);

void lookupsids_async(TALLOC_CTX *mem_ctx, uint32 num_sids, DOM_SID **sids,
		      void (*cont)(void *private_data, BOOL success,
				   uint32 num_sids, const char **domains,
				   const char **names,
				   enum SID_NAME_USE *types),
		      void *private_data)
{
	struct lookupsids_state *state;
	uint32 i;

	state = TALLOC_P(mem_ctx, struct lookupsids_state);

	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		cont(private_data, False, 0, NULL, NULL, NULL);
		return;
	}

	state->mem_ctx = mem_ctx;
	state->num_sids = num_sids;
	state->num_finished = 0;

	state->cont = cont;
	state->private_data = private_data;

	state->ctrs = TALLOC_ARRAY(state, struct sid_ctr, num_sids);
	state->dom_ctrs = TALLOC_ARRAY(state, struct sid_ctr *, num_sids);
	if ((state->ctrs == NULL) || (state->dom_ctrs == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		cont(private_data, False, 0, NULL, NULL, NULL);
		return;
	}

	for (i=0; i<num_sids; i++) {
		const char *dom, *nam;
		state->ctrs[i].sid = sids[i];
		state->ctrs[i].finished =
			lookup_wellknown_sid(mem_ctx, sids[i],
					     &dom, &nam);
		if (state->ctrs[i].finished) {
			state->ctrs[i].domain = dom;
			state->ctrs[i].name = nam;
			state->ctrs[i].type = SID_NAME_WKN_GRP;
			state->num_finished += 1;
		}
		state->ctrs[i].finished =
			lookup_cached_sid(mem_ctx, sids[i],
					  &state->ctrs[i].domain,
					  &state->ctrs[i].name,
					  &state->ctrs[i].type);

		if (state->ctrs[i].finished) {
			/* Ok, that was easy :-) */
			state->num_finished += 1;
			continue;
		}
	}

	state->domain = IS_DC ? domain_list() : find_our_domain();

	lookup_next_domain(state);
}

static void lookup_next_domain(struct lookupsids_state *state)
{
	uint32 i;
	char *sidstring = NULL;
	ssize_t len = 0;
	size_t bufsize = 0;

	struct winbindd_request request;

	if (state->domain == NULL) {
		lookupsids_finished(state);
		return;
	}

	state->num_dom_ctrs = 0;

	for (i=0; i<state->num_sids; i++) {
		if (state->ctrs[i].finished) {
			continue;
		}
		if (IS_DC && (sid_compare_domain(state->ctrs[i].sid,
						 &state->domain->sid) != 0)) {
			continue;
		}
		
		state->dom_ctrs[state->num_dom_ctrs++] = &state->ctrs[i];
		sprintf_append(state->mem_ctx, &sidstring, &len, &bufsize,
			       "%s\n", sid_string_static(state->ctrs[i].sid));
	}

	if (state->num_dom_ctrs == 0) {
		if (!IS_DC) {
			lookupsids_finished(state);
			return;
		}
		state->domain = state->domain->next;
		lookup_next_domain(state);
		return;
	}

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_LOOKUPSIDS;
	request.extra_data = sidstring;
	request.extra_len = len;
	do_async_domain(state->mem_ctx, state->domain, &request,
			lookupsids_recv, NULL, state);
}

static void lookupsids_recv(TALLOC_CTX *mem_ctx, BOOL success,
			    struct winbindd_response *response,
			    void *cont, void *private_data)
{
	struct lookupsids_state *state =
		talloc_get_type_abort(private_data, struct lookupsids_state);
	uint32 i;
	char *p;

	if ((!success) || (response->extra_data == NULL)) {
		goto failed;
	}

	p = response->extra_data;

	for (i=0; i<state->num_dom_ctrs && (*p != '\0'); i++) {
		char *q;

		/* Format: "type DOMAIN\\name\n" */

		state->dom_ctrs[i]->type = strtoull(p, &q, 10);

		if (*q != ' ') {
			goto failed;
		}

		p = q+1;
		q = strchr(p, '\\');
		if (q == NULL) {
			goto failed;
		}
		*q = '\0';
		state->dom_ctrs[i]->domain = talloc_strdup(state->mem_ctx, p);

		p = q+1;
		q = strchr(p, '\n');
		if (q == NULL) {
			goto failed;
		}
		*q = '\0';
		state->dom_ctrs[i]->name = talloc_strdup(state->mem_ctx, p);

		p = q+1;
	}

	if (i < state->num_dom_ctrs) {
		DEBUG(2, ("Got too few replies\n"));
		goto failed;
	}

	if (*p != '\0') {
		DEBUG(2, ("Got invalid response\n"));
		goto failed;
	}

	for (i=0; i<state->num_dom_ctrs; i++) {
		cache_sid2name(state->domain, state->dom_ctrs[i]->sid,
			       state->dom_ctrs[i]->domain,
			       state->dom_ctrs[i]->name,
			       state->dom_ctrs[i]->type);
	}

	state->num_finished += state->num_dom_ctrs;

	if (state->num_finished == state->num_sids) {
		lookupsids_finished(state);
		return;
	}

	state->domain = state->domain->next;
	lookup_next_domain(state);
	return;

 failed:
	DEBUG(5, ("dual_lookupsids failed\n"));
	state->cont(state->private_data, False, 0, NULL, NULL, NULL);
	return;
}

enum winbindd_result winbindd_dual_lookupsids(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state)
{
	NTSTATUS status;
	DOM_SID *sids = NULL;
	size_t i, num_sids = 0;

	char **domains, **names;
	enum SID_NAME_USE *types;

	char *result = NULL;
	ssize_t len = 0;
	size_t bufsize = 0;

	DEBUG(3, ("[%5lu]: lookupsids %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	if (state->request.extra_len == 0) {
		DEBUG(10, ("Got no SIDS\n"));
		return WINBINDD_OK;
	}

	if (!parse_sidlist(state->mem_ctx, state->request.extra_data,
			   &sids, &num_sids)) {
		DEBUG(5, ("Could not parse sidlist\n"));
		return WINBINDD_ERROR;
	}

	status = domain->methods->lookupsids(domain, state->mem_ctx,
					     num_sids, sids,
					     &domains, &names, &types);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		/* We fake successful lookups here */
		for (i=0; i<num_sids; i++) {
			sprintf_append(NULL, &result, &len, &bufsize,
				       "8  \\ \n");
		}
	} else if (NT_STATUS_IS_OK(status) ||
		   NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		for (i=0; i<num_sids; i++) {
			sprintf_append(NULL, &result, &len, &bufsize,
				       "%d %s\\%s\n", types[i],
				       domains[i], names[i]);
		}
	} else {
		/* There was a real error */
		return WINBINDD_ERROR;
	}

	if (result == NULL) {
		DEBUG(0, ("malloc failed\n"));
		return WINBINDD_ERROR;
	}

	state->response.extra_data = result;
	state->response.length += len+1;
	return WINBINDD_OK;
}

static void lookupsids_finished(struct lookupsids_state *state)
{
	uint32 i;
	const char **domains;
	const char **names;
	enum SID_NAME_USE *types;

	domains = TALLOC_ARRAY(state->mem_ctx, const char *, state->num_sids);
	names = TALLOC_ARRAY(state->mem_ctx, const char *, state->num_sids);
	types = TALLOC_ARRAY(state->mem_ctx, enum SID_NAME_USE,
			     state->num_sids);

	if ((domains == NULL) || (names == NULL) || (types == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		state->cont(state->private_data, False, 0, NULL, NULL, NULL);
		return;
	}

	for (i=0; i<state->num_sids; i++) {
		domains[i] = state->ctrs[i].domain;
		names[i] = state->ctrs[i].name;
		types[i] = state->ctrs[i].type;
	}

	state->cont(state->private_data, True, state->num_sids,
		    domains, names, types);
}

static void winbindd_lookupsids_recv(void *private_data, BOOL success,
				     uint32 num_sids,
				     const char **domains, const char **names,
				     enum SID_NAME_USE *types);

void winbindd_lookupsids(struct winbindd_cli_state *state)
{
	DOM_SID *sids = NULL;
	DOM_SID **sidptrs;
	size_t i, num_sids = 0;

	DEBUG(3, ("[%5lu]: lookupsids %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	if (state->request.extra_len == 0) {
		DEBUG(10, ("Got no SIDS\n"));
		request_ok(state);
		return;
	}

	if (!parse_sidlist(state->mem_ctx, state->request.extra_data,
			   &sids, &num_sids)) {
		DEBUG(5, ("Could not parse sidlist\n"));
		request_error(state);
		return;
	}

	sidptrs = TALLOC_ARRAY(state->mem_ctx, DOM_SID *, num_sids);
	if (sidptrs == NULL) {
		DEBUG(0, ("talloc failed\n"));
		request_error(state);
		return;
	}

	for (i=0; i<num_sids; i++) {
		sidptrs[i] = &sids[i];
	}

	lookupsids_async(state->mem_ctx, num_sids, sidptrs,
			 winbindd_lookupsids_recv, state);
}

static void winbindd_lookupsids_recv(void *private_data, BOOL success,
				     uint32 num_sids,
				     const char **domains, const char **names,
				     enum SID_NAME_USE *types)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	char *result = NULL;
	ssize_t len = 0;
	size_t bufsize = 0;
	int i;

	if (!success) {
		request_error(state);
                return;
	}

	for (i=0; i<num_sids; i++) {
		sprintf_append(NULL, &result, &len, &bufsize,
			       "%d %s\\%s\n", types[i], domains[i], names[i]);
	}

	if (result == NULL) {
		DEBUG(0, ("malloc failed\n"));
		request_error(state);
                return;
	}

	state->response.extra_data = result;
	state->response.length += len+1;
	request_ok(state);
}
