/* 
   Unix SMB/CIFS implementation.

   Async helpers for blocking functions

   The helpers always consist of three functions: 

   * A request setup function that takes the necessary parameters together
     with a continuation function that is to be called upon completion

   * A private continuation function that is internal only. This is to be
     called by the lower-level functions in do_async(). Its only task is to
     properly call the continuation function named above.

   * A worker function that is called inside the appropriate child process.

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

struct do_async_state {
	TALLOC_CTX *mem_ctx;
	struct winbindd_request request;
	struct winbindd_response response;
	void (*cont)(TALLOC_CTX *mem_ctx,
		     BOOL success,
		     struct winbindd_response *response,
		     void *c, void *private);
	void *c, *private;
};

static void do_async_recv(void *private, BOOL success)
{
	struct do_async_state *state = private;
	state->cont(state->mem_ctx, success, &state->response,
		    state->c, state->private);
}

static enum winbindd_result do_async(TALLOC_CTX *mem_ctx,
				     struct winbindd_child *child,
				     const struct winbindd_request *request,
				     void (*cont)(TALLOC_CTX *mem_ctx,
						  BOOL success,
						  struct winbindd_response *response,
						  void *c, void *private),
				     void *c, void *private)
{
	struct do_async_state *state;

	state = TALLOC_ZERO_P(mem_ctx, struct do_async_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		cont(mem_ctx, False, NULL, c, private);
		return WINBINDD_ERROR;
	}

	state->mem_ctx = mem_ctx;
	state->request = *request;
	state->request.length = sizeof(state->request);
	state->cont = cont;
	state->c = c;
	state->private = private;

	return async_request(mem_ctx, child, &state->request, &state->response,
			     do_async_recv, state);
}


static void idmap_set_mapping_recv(TALLOC_CTX *mem_ctx, BOOL success,
				   struct winbindd_response *response,
				   void *c, void *private)
{
	void (*cont)(void *priv, BOOL succ) = c;
	cont(private, ((success) && (response->result == WINBINDD_OK)));
}

enum winbindd_result idmap_set_mapping_async(TALLOC_CTX *mem_ctx,
					     const DOM_SID *sid, unid_t id,
					     int id_type,
					     void (*cont)(void *private,
							  BOOL success),
					     void *private)
{
	struct winbindd_request request;
	request.cmd = WINBINDD_DUAL_IDMAPSET;
	if (id_type == ID_USERID)
		request.data.dual_idmapset.uid = id.uid;
	else
		request.data.dual_idmapset.gid = id.gid;
	request.data.dual_idmapset.type = id_type;
	sid_to_string(request.data.dual_idmapset.sid, sid);

	return do_async(mem_ctx, idmap_child(), &request,
			idmap_set_mapping_recv, cont, private);
}

enum winbindd_result winbindd_dual_idmapset(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	unid_t id;
	NTSTATUS result;

	DEBUG(3, ("[%5lu]: dual_idmapset\n", (unsigned long)state->pid));

	if (!string_to_sid(&sid, state->request.data.dual_idmapset.sid))
		return WINBINDD_ERROR;

	if (state->request.data.dual_idmapset.type == ID_USERID)
		id.uid = state->request.data.dual_idmapset.uid;
	else
		id.gid = state->request.data.dual_idmapset.gid;

	result = idmap_set_mapping(&sid, id,
				   state->request.data.dual_idmapset.type);
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}


static void uid2name_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private)
{
	void (*cont)(void *priv, BOOL succ, const char *name) = c;
	cont(private, ((success) && (response->result == WINBINDD_OK)),
	     response->data.name.name);
}

enum winbindd_result winbindd_uid2name_async(TALLOC_CTX *mem_ctx,
					     uid_t uid,
					     void (*cont)(void *private,
							  BOOL success,
							  const char *name),
					     void *private)
{
	struct winbindd_request request;
	request.cmd = WINBINDD_DUAL_UID2NAME;
	request.data.uid = uid;
	return do_async(mem_ctx, idmap_child(), &request,
			uid2name_recv, cont, private);
}

enum winbindd_result winbindd_dual_uid2name(struct winbindd_cli_state *state)
{
	struct passwd *pw;

	DEBUG(3, ("[%5lu]: uid2name %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.uid));

	pw = getpwuid(state->request.data.uid);
	if (pw == NULL) {
		DEBUG(5, ("User %lu not found\n",
			  (unsigned long)state->request.data.uid));
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.name.name, pw->pw_name);
	return WINBINDD_OK;
}


static void gid2name_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private)
{
	void (*cont)(void *priv, BOOL succ, const char *name) = c;
	cont(private, ((success) && (response->result == WINBINDD_OK)),
	     response->data.name.name);
}

enum winbindd_result winbindd_gid2name_async(TALLOC_CTX *mem_ctx,
					     gid_t gid,
					     void (*cont)(void *private,
							  BOOL success,
							  const char *name),
					     void *private)
{
	struct winbindd_request request;
	request.cmd = WINBINDD_DUAL_GID2NAME;
	request.data.gid = gid;
	return do_async(mem_ctx, idmap_child(), &request,
			gid2name_recv, cont, private);
}

enum winbindd_result winbindd_dual_gid2name(struct winbindd_cli_state *state)
{
	struct group *gr;

	DEBUG(3, ("[%5lu]: gid2name %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.gid));

	gr = getgrgid(state->request.data.gid);
	if (gr == NULL)
		return WINBINDD_ERROR;

	fstrcpy(state->response.data.name.name, gr->gr_name);
	return WINBINDD_OK;
}


static void lookup_sid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			    struct winbindd_response *response,
			    void *c, void *private)
{
	void (*cont)(void *priv, BOOL succ, const char *dom_name,
		     const char *name, enum SID_NAME_USE type) = c;

	cont(private, ((success) && (response->result == WINBINDD_OK)),
	     response->data.name.dom_name, response->data.name.name,
	     response->data.name.type);
}

enum winbindd_result winbindd_lookup_sid_async(TALLOC_CTX *mem_ctx,
					       const DOM_SID *sid,
					       void (*cont)(void *private,
							    BOOL success,
							    const char *dom_name,
							    const char *name,
							    enum SID_NAME_USE type),
					       void *private)
{
	struct winbindd_domain *domain;
	struct winbindd_request request;

	domain = find_lookup_domain_from_sid(sid);
	if (domain == NULL) {
		DEBUG(5, ("Could not find domain for sid %s\n",
			  sid_string_static(sid)));
		cont(private, False, NULL, NULL, SID_NAME_UNKNOWN);
		return WINBINDD_ERROR;
	}

	request.cmd = WINBINDD_LOOKUPSID;
	fstrcpy(request.data.sid, sid_string_static(sid));

	return do_async(mem_ctx, &domain->child, &request,
			lookup_sid_recv, cont, private);
}


static void lookup_name_recv(TALLOC_CTX *mem_ctx, BOOL success,
			     struct winbindd_response *response,
			     void *c, void *private)
{
	void (*cont)(void *priv, BOOL succ, const DOM_SID *sid,
		     enum SID_NAME_USE type) = c;
	DOM_SID sid;

	if ((!success) || (response->result != WINBINDD_OK)) {
		cont(private, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	if (!string_to_sid(&sid, response->data.sid.sid)) {
		DEBUG(0, ("Could not convert string %s to sid\n",
			  response->data.sid.sid));
		cont(private, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	cont(private, True, &sid, response->data.sid.type);
}

enum winbindd_result winbindd_lookup_name_async(TALLOC_CTX *mem_ctx,
					       const char *dom_name,
					       const char *name,
					       void (*cont)(void *private,
							    BOOL success,
							    const DOM_SID *sid,
							    enum SID_NAME_USE type),
					       void *private)
{
	struct winbindd_request request;
	struct winbindd_domain *domain;

	domain = find_lookup_domain_from_name(dom_name);

	if (domain == NULL) {
		DEBUG(5, ("Could not find domain for name %s\n", dom_name));
		cont(private, False, NULL, SID_NAME_UNKNOWN);
		return WINBINDD_ERROR;
	}

	request.cmd = WINBINDD_LOOKUPNAME;
	fstrcpy(request.data.name.dom_name, dom_name);
	fstrcpy(request.data.name.name, name);

	return do_async(mem_ctx, &domain->child, &request,
			lookup_name_recv, cont, private);
}


