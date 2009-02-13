/* 
   Unix SMB/CIFS implementation.

   Async helpers for blocking functions

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Gerald Carter 2006

   The helpers always consist of three functions: 

   * A request setup function that takes the necessary parameters together
     with a continuation function that is to be called upon completion

   * A private continuation function that is internal only. This is to be
     called by the lower-level functions in do_async(). Its only task is to
     properly call the continuation function named above.

   * A worker function that is called inside the appropriate child process.

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

struct do_async_state {
	TALLOC_CTX *mem_ctx;
	struct winbindd_request request;
	struct winbindd_response response;
	void (*cont)(TALLOC_CTX *mem_ctx,
		     bool success,
		     struct winbindd_response *response,
		     void *c, void *private_data);
	void *c, *private_data;
};

static void do_async_recv(void *private_data, bool success)
{
	struct do_async_state *state =
		talloc_get_type_abort(private_data, struct do_async_state);

	state->cont(state->mem_ctx, success, &state->response,
		    state->c, state->private_data);
}

void do_async(TALLOC_CTX *mem_ctx, struct winbindd_child *child,
	      const struct winbindd_request *request,
	      void (*cont)(TALLOC_CTX *mem_ctx, bool success,
			   struct winbindd_response *response,
			   void *c, void *private_data),
	      void *c, void *private_data)
{
	struct do_async_state *state;

	state = TALLOC_ZERO_P(mem_ctx, struct do_async_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		cont(mem_ctx, False, NULL, c, private_data);
		return;
	}

	state->mem_ctx = mem_ctx;
	state->request = *request;
	state->request.length = sizeof(state->request);
	state->cont = cont;
	state->c = c;
	state->private_data = private_data;

	async_request(mem_ctx, child, &state->request,
		      &state->response, do_async_recv, state);
}

static void do_async_domain(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
			    const struct winbindd_request *request,
			    void (*cont)(TALLOC_CTX *mem_ctx, bool success,
					 struct winbindd_response *response,
					 void *c, void *private_data),
			    void *c, void *private_data)
{
	struct do_async_state *state;

	state = TALLOC_ZERO_P(mem_ctx, struct do_async_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		cont(mem_ctx, False, NULL, c, private_data);
		return;
	}

	state->mem_ctx = mem_ctx;
	state->request = *request;
	state->request.length = sizeof(state->request);
	state->cont = cont;
	state->c = c;
	state->private_data = private_data;

	async_domain_request(mem_ctx, domain, &state->request,
			     &state->response, do_async_recv, state);
}

struct lookupsid_state {
	DOM_SID sid;	
	void *caller_private_data;
};


static void lookupsid_recv2(TALLOC_CTX *mem_ctx, bool success,
			   struct winbindd_response *response,
			   void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ, const char *dom_name,
		     const char *name, enum lsa_SidType type) =
		(void (*)(void *, bool, const char *, const char *,
			  enum lsa_SidType))c;
	struct lookupsid_state *s = talloc_get_type_abort(private_data, 
							  struct lookupsid_state);

	if (!success) {
		DEBUG(5, ("Could not trigger lookupsid\n"));
		cont(s->caller_private_data, False, NULL, NULL, SID_NAME_UNKNOWN);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("lookupsid (forest root) returned an error\n"));		
		cont(s->caller_private_data, False, NULL, NULL, SID_NAME_UNKNOWN);
		return;
	}

	cont(s->caller_private_data, True, response->data.name.dom_name,
	     response->data.name.name,
	     (enum lsa_SidType)response->data.name.type);
}

static void lookupsid_recv(TALLOC_CTX *mem_ctx, bool success,
			   struct winbindd_response *response,
			   void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ, const char *dom_name,
		     const char *name, enum lsa_SidType type) =
		(void (*)(void *, bool, const char *, const char *,
			  enum lsa_SidType))c;
	struct lookupsid_state *s = talloc_get_type_abort(private_data, 
							  struct lookupsid_state);

	if (!success) {
		DEBUG(5, ("Could not trigger lookupsid\n"));
		cont(s->caller_private_data, False, NULL, NULL, SID_NAME_UNKNOWN);
		return;
	}

	if (response->result != WINBINDD_OK) {
		/* Try again using the forest root */
		struct winbindd_domain *root_domain = find_root_domain();
		struct winbindd_request request;

		if ( !root_domain ) {
			DEBUG(5,("lookupsid_recv: unable to determine forest root\n"));
			cont(s->caller_private_data, False, NULL, NULL, SID_NAME_UNKNOWN);
			return;
		}

		ZERO_STRUCT(request);
		request.cmd = WINBINDD_LOOKUPSID;
		sid_to_fstring(request.data.sid, &s->sid);

		do_async_domain(mem_ctx, root_domain, &request, lookupsid_recv2,
				(void *)cont, s);

		return;
	}

	cont(s->caller_private_data, True, response->data.name.dom_name,
	     response->data.name.name,
	     (enum lsa_SidType)response->data.name.type);
}

void winbindd_lookupsid_async(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			      void (*cont)(void *private_data, bool success,
					   const char *dom_name,
					   const char *name,
					   enum lsa_SidType type),
			      void *private_data)
{
	struct winbindd_domain *domain;
	struct winbindd_request request;
	struct lookupsid_state *s;	

	domain = find_lookup_domain_from_sid(sid);
	if (domain == NULL) {
		DEBUG(5, ("Could not find domain for sid %s\n",
			  sid_string_dbg(sid)));
		cont(private_data, False, NULL, NULL, SID_NAME_UNKNOWN);
		return;
	}

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_LOOKUPSID;
	sid_to_fstring(request.data.sid, sid);

	if ( (s = TALLOC_ZERO_P(mem_ctx, struct lookupsid_state)) == NULL ) {
		DEBUG(0, ("winbindd_lookupsid_async: talloc failed\n"));
		cont(private_data, False, NULL, NULL, SID_NAME_UNKNOWN);
		return;
	}

	sid_copy( &s->sid, sid );	
	s->caller_private_data = private_data;	

	do_async_domain(mem_ctx, domain, &request, lookupsid_recv,
			(void *)cont, s);
}

enum winbindd_result winbindd_dual_lookupsid(struct winbindd_domain *domain,
					     struct winbindd_cli_state *state)
{
	enum lsa_SidType type;
	DOM_SID sid;
	char *name;
	char *dom_name;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: lookupsid %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	/* Lookup sid from PDC using lsa_lookup_sids() */

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(5, ("%s not a SID\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	/* Lookup the sid */

	if (!winbindd_lookup_name_by_sid(state->mem_ctx, domain, &sid, 
					 &dom_name, &name, &type)) 
	{
		TALLOC_FREE(dom_name);
		TALLOC_FREE(name);
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.name.dom_name, dom_name);
	fstrcpy(state->response.data.name.name, name);
	state->response.data.name.type = type;

	TALLOC_FREE(dom_name);
	TALLOC_FREE(name);
	return WINBINDD_OK;
}

/********************************************************************
 This is the second callback after contacting the forest root
********************************************************************/

struct lookupname_state {
	char *dom_name;
	char *name;
	void *caller_private_data;
};


static void lookupname_recv2(TALLOC_CTX *mem_ctx, bool success,
			    struct winbindd_response *response,
			    void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ, const DOM_SID *sid,
		     enum lsa_SidType type) =
		(void (*)(void *, bool, const DOM_SID *, enum lsa_SidType))c;
	DOM_SID sid;
	struct lookupname_state *s = talloc_get_type_abort( private_data,
							    struct lookupname_state );

	if (!success) {
		DEBUG(5, ("Could not trigger lookup_name\n"));
		cont(s->caller_private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("lookup_name returned an error\n"));
		cont(s->caller_private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	if (!string_to_sid(&sid, response->data.sid.sid)) {
		DEBUG(0, ("Could not convert string %s to sid\n",
			  response->data.sid.sid));
		cont(s->caller_private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	cont(s->caller_private_data, True, &sid,
	     (enum lsa_SidType)response->data.sid.type);
}

/********************************************************************
 This is the first callback after contacting our own domain
********************************************************************/

static void lookupname_recv(TALLOC_CTX *mem_ctx, bool success,
			    struct winbindd_response *response,
			    void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ, const DOM_SID *sid,
		     enum lsa_SidType type) =
		(void (*)(void *, bool, const DOM_SID *, enum lsa_SidType))c;
	DOM_SID sid;
	struct lookupname_state *s = talloc_get_type_abort( private_data,
							    struct lookupname_state );	

	if (!success) {
		DEBUG(5, ("lookupname_recv: lookup_name() failed!\n"));
		cont(s->caller_private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	if (response->result != WINBINDD_OK) {
		/* Try again using the forest root */
		struct winbindd_domain *root_domain = find_root_domain();
		struct winbindd_request request;

		if ( !root_domain ) {
			DEBUG(5,("lookupname_recv: unable to determine forest root\n"));
			cont(s->caller_private_data, False, NULL, SID_NAME_UNKNOWN);
			return;
		}

		ZERO_STRUCT(request);
		request.cmd = WINBINDD_LOOKUPNAME;

		fstrcpy( request.data.name.dom_name, s->dom_name );
		fstrcpy( request.data.name.name, s->name );

		do_async_domain(mem_ctx, root_domain, &request, lookupname_recv2,
				(void *)cont, s);

		return;
	}

	if (!string_to_sid(&sid, response->data.sid.sid)) {
		DEBUG(0, ("Could not convert string %s to sid\n",
			  response->data.sid.sid));
		cont(s->caller_private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	cont(s->caller_private_data, True, &sid,
	     (enum lsa_SidType)response->data.sid.type);
}

/********************************************************************
 The lookup name call first contacts a DC in its own domain
 and fallbacks to contact a DC if the forest in our domain doesn't
 know the name.
********************************************************************/

void winbindd_lookupname_async(TALLOC_CTX *mem_ctx,
			       const char *dom_name, const char *name,
			       void (*cont)(void *private_data, bool success,
					    const DOM_SID *sid,
					    enum lsa_SidType type),
			       enum winbindd_cmd orig_cmd,
			       void *private_data)
{
	struct winbindd_request request;
	struct winbindd_domain *domain;
	struct lookupname_state *s;

	if ( (domain = find_lookup_domain_from_name(dom_name)) == NULL ) {
		DEBUG(5, ("Could not find domain for name '%s'\n", dom_name));
		cont(private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_LOOKUPNAME;
	request.original_cmd = orig_cmd;
	fstrcpy(request.data.name.dom_name, dom_name);
	fstrcpy(request.data.name.name, name);

	if ( (s = TALLOC_ZERO_P(mem_ctx, struct lookupname_state)) == NULL ) {
		DEBUG(0, ("winbindd_lookupname_async: talloc failed\n"));
		cont(private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	s->dom_name = talloc_strdup( s, dom_name );
	s->name     = talloc_strdup( s, name );
	if (!s->dom_name || !s->name) {
		cont(private_data, False, NULL, SID_NAME_UNKNOWN);
		return;
	}

	s->caller_private_data = private_data;

	do_async_domain(mem_ctx, domain, &request, lookupname_recv,
			(void *)cont, s);
}

enum winbindd_result winbindd_dual_lookupname(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state)
{
	enum lsa_SidType type;
	char *name_domain, *name_user;
	DOM_SID sid;
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

	/* Lookup name from DC using lsa_lookup_names() */
	if (!winbindd_lookup_sid_by_name(state->mem_ctx, state->request.original_cmd, domain, name_domain,
					 name_user, &sid, &type)) {
		return WINBINDD_ERROR;
	}

	sid_to_fstring(state->response.data.sid.sid, &sid);
	state->response.data.sid.type = type;

	return WINBINDD_OK;
}

/* This is the first callback after enumerating users/groups from a domain */
static void listent_recv(TALLOC_CTX *mem_ctx, bool success,
	                    struct winbindd_response *response,
			    void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ, fstring dom_name, char *data) =
		(void (*)(void *, bool, fstring, char*))c;

	if (!success || response->result != WINBINDD_OK) {
		DEBUG(5, ("list_ent() failed!\n"));
		cont(private_data, False, response->data.name.dom_name, NULL);
		return;
	}

	cont(private_data, True, response->data.name.dom_name,
	     (char *)response->extra_data.data);

	SAFE_FREE(response->extra_data.data);
}

/* Request the name of all users/groups in a single domain */
void winbindd_listent_async(TALLOC_CTX *mem_ctx,
	                       struct winbindd_domain *domain,
	                       void (*cont)(void *private_data, bool success,
				     fstring dom_name, char* extra_data),
			       void *private_data, enum ent_type type)
{
	struct winbindd_request request;

	ZERO_STRUCT(request);
	if (type == LIST_USERS)
		request.cmd = WINBINDD_LIST_USERS;
	else if (type == LIST_GROUPS)
		request.cmd = WINBINDD_LIST_GROUPS;

	do_async_domain(mem_ctx, domain, &request, listent_recv,
		        (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_list_users(struct winbindd_domain *domain,
                                              struct winbindd_cli_state *state)
{
	WINBIND_USERINFO *info;
	NTSTATUS status;
	struct winbindd_methods *methods;
	uint32 num_entries = 0;
	char *extra_data = NULL;
	uint32_t extra_data_len = 0, i;

	/* Must copy domain into response first for debugging in parent */
	fstrcpy(state->response.data.name.dom_name, domain->name);

	/* Query user info */
	methods = domain->methods;
	status = methods->query_user_list(domain, state->mem_ctx, 
					  &num_entries, &info);

	if (!NT_STATUS_IS_OK(status))
		return WINBINDD_ERROR;

	if (num_entries == 0)
		return WINBINDD_OK;

	/* Allocate some memory for extra data.  Note that we limit
	   account names to sizeof(fstring) = 256 characters.		
	   +1 for the ',' between group names */
	extra_data = (char *)SMB_REALLOC(extra_data, 
		(sizeof(fstring) + 1) * num_entries);

	if (!extra_data) {
		DEBUG(0,("failed to enlarge buffer!\n"));
		return WINBINDD_ERROR;
	}

	/* Pack user list into extra data fields */
	for (i = 0; i < num_entries; i++) {
		fstring acct_name, name;

		if (info[i].acct_name == NULL)
			fstrcpy(acct_name, "");
		else
			fstrcpy(acct_name, info[i].acct_name);

		fill_domain_username(name, domain->name, acct_name, True);
		/* Append to extra data */
		memcpy(&extra_data[extra_data_len], name, strlen(name));
		extra_data_len += strlen(name);
		extra_data[extra_data_len++] = ',';
	}   

	/* Assign extra_data fields in response structure */
	if (extra_data) {
		/* remove trailing ',' */
		extra_data[extra_data_len - 1] = '\0';
		state->response.extra_data.data = extra_data;
		state->response.length += extra_data_len;
	}

	return WINBINDD_OK;
}

enum winbindd_result winbindd_dual_list_groups(struct winbindd_domain *domain,
                                               struct winbindd_cli_state *state)
{
	struct getent_state groups;
	char *extra_data = NULL;
	uint32_t extra_data_len = 0, i;

	ZERO_STRUCT(groups);

	/* Must copy domain into response first for debugging in parent */
	fstrcpy(state->response.data.name.dom_name, domain->name);
	fstrcpy(groups.domain_name, domain->name);

	/* Get list of sam groups */
	if (!get_sam_group_entries(&groups)) {
		/* this domain is empty or in an error state */
		return WINBINDD_ERROR;
	}

	/* Allocate some memory for extra data.  Note that we limit
	   account names to sizeof(fstring) = 256 characters.
	   +1 for the ',' between group names */
	extra_data = (char *)SMB_REALLOC(extra_data,
		(sizeof(fstring) + 1) * groups.num_sam_entries);

	if (!extra_data) {
		DEBUG(0,("failed to enlarge buffer!\n"));
		SAFE_FREE(groups.sam_entries);
		return WINBINDD_ERROR;
	}

	/* Pack group list into extra data fields */
	for (i = 0; i < groups.num_sam_entries; i++) {
		char *group_name = ((struct acct_info *)
				    groups.sam_entries)[i].acct_name;
		fstring name;

		fill_domain_username(name, domain->name, group_name, True);
		/* Append to extra data */
		memcpy(&extra_data[extra_data_len], name, strlen(name));
		extra_data_len += strlen(name);
		extra_data[extra_data_len++] = ',';
	}

	SAFE_FREE(groups.sam_entries);

	/* Assign extra_data fields in response structure */
	if (extra_data) {
		/* remove trailing ',' */
		extra_data[extra_data_len - 1] = '\0';
		state->response.extra_data.data = extra_data;
		state->response.length += extra_data_len;
	}

	return WINBINDD_OK;
}

bool print_sidlist(TALLOC_CTX *mem_ctx, const DOM_SID *sids,
		   size_t num_sids, char **result, ssize_t *len)
{
	size_t i;
	size_t buflen = 0;

	*len = 0;
	*result = NULL;
	for (i=0; i<num_sids; i++) {
		fstring tmp;
		sprintf_append(mem_ctx, result, len, &buflen,
			       "%s\n", sid_to_fstring(tmp, &sids[i]));
	}

	if ((num_sids != 0) && (*result == NULL)) {
		return False;
	}

	return True;
}

bool parse_sidlist(TALLOC_CTX *mem_ctx, char *sidstr,
		   DOM_SID **sids, size_t *num_sids)
{
	char *p, *q;

	p = sidstr;
	if (p == NULL)
		return False;

	while (p[0] != '\0') {
		DOM_SID sid;
		q = strchr(p, '\n');
		if (q == NULL) {
			DEBUG(0, ("Got invalid sidstr: %s\n", p));
			return False;
		}
		*q = '\0';
		q += 1;
		if (!string_to_sid(&sid, p)) {
			DEBUG(0, ("Could not parse sid %s\n", p));
			return False;
		}
		if (!NT_STATUS_IS_OK(add_sid_to_array(mem_ctx, &sid, sids,
						      num_sids)))
		{
			return False;
		}
		p = q;
	}
	return True;
}

static bool parse_ridlist(TALLOC_CTX *mem_ctx, char *ridstr,
			  uint32 **rids, size_t *num_rids)
{
	char *p;

	p = ridstr;
	if (p == NULL)
		return False;

	while (p[0] != '\0') {
		uint32 rid;
		char *q;
		rid = strtoul(p, &q, 10);
		if (*q != '\n') {
			DEBUG(0, ("Got invalid ridstr: %s\n", p));
			return False;
		}
		p = q+1;
		ADD_TO_ARRAY(mem_ctx, uint32, rid, rids, num_rids);
	}
	return True;
}

enum winbindd_result winbindd_dual_lookuprids(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state)
{
	uint32 *rids = NULL;
	size_t i, buflen, num_rids = 0;
	ssize_t len;
	DOM_SID domain_sid;
	char *domain_name;
	char **names;
	enum lsa_SidType *types;
	NTSTATUS status;
	char *result;

	DEBUG(10, ("Looking up RIDs for domain %s (%s)\n",
		   state->request.domain_name,
		   state->request.data.sid));

	if (!parse_ridlist(state->mem_ctx, state->request.extra_data.data,
			   &rids, &num_rids)) {
		DEBUG(5, ("Could not parse ridlist\n"));
		return WINBINDD_ERROR;
	}

	if (!string_to_sid(&domain_sid, state->request.data.sid)) {
		DEBUG(5, ("Could not parse domain sid %s\n",
			  state->request.data.sid));
		return WINBINDD_ERROR;
	}

	status = domain->methods->rids_to_names(domain, state->mem_ctx,
						&domain_sid, rids, num_rids,
						&domain_name,
						&names, &types);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		return WINBINDD_ERROR;
	}

	len = 0;
	buflen = 0;
	result = NULL;

	for (i=0; i<num_rids; i++) {
		sprintf_append(state->mem_ctx, &result, &len, &buflen,
			       "%d %s\n", types[i], names[i]);
	}

	fstrcpy(state->response.data.domain_name, domain_name);

	if (result != NULL) {
		state->response.extra_data.data = SMB_STRDUP(result);
		if (!state->response.extra_data.data) {
			return WINBINDD_ERROR;
		}
		state->response.length += len+1;
	}

	return WINBINDD_OK;
}

static void getsidaliases_recv(TALLOC_CTX *mem_ctx, bool success,
			       struct winbindd_response *response,
			       void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ,
		     DOM_SID *aliases, size_t num_aliases) =
		(void (*)(void *, bool, DOM_SID *, size_t))c;
	char *aliases_str;
	DOM_SID *sids = NULL;
	size_t num_sids = 0;

	if (!success) {
		DEBUG(5, ("Could not trigger getsidaliases\n"));
		cont(private_data, success, NULL, 0);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("getsidaliases returned an error\n"));
		cont(private_data, False, NULL, 0);
		return;
	}

	aliases_str = (char *)response->extra_data.data;

	if (aliases_str == NULL) {
		DEBUG(10, ("getsidaliases return 0 SIDs\n"));
		cont(private_data, True, NULL, 0);
		return;
	}

	if (!parse_sidlist(mem_ctx, aliases_str, &sids, &num_sids)) {
		DEBUG(0, ("Could not parse sids\n"));
		cont(private_data, False, NULL, 0);
		return;
	}

	SAFE_FREE(response->extra_data.data);

	cont(private_data, True, sids, num_sids);
}

void winbindd_getsidaliases_async(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const DOM_SID *sids, size_t num_sids,
			 	  void (*cont)(void *private_data,
				 	       bool success,
					       const DOM_SID *aliases,
					       size_t num_aliases),
				  void *private_data)
{
	struct winbindd_request request;
	char *sidstr = NULL;
	ssize_t len;

	if (num_sids == 0) {
		cont(private_data, True, NULL, 0);
		return;
	}

	if (!print_sidlist(mem_ctx, sids, num_sids, &sidstr, &len)) {
		cont(private_data, False, NULL, 0);
		return;
	}

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_GETSIDALIASES;
	request.extra_len = len;
	request.extra_data.data = sidstr;

	do_async_domain(mem_ctx, domain, &request, getsidaliases_recv,
			(void *)cont, private_data);
}

struct gettoken_state {
	TALLOC_CTX *mem_ctx;
	DOM_SID user_sid;
	struct winbindd_domain *alias_domain;
	struct winbindd_domain *local_alias_domain;
	struct winbindd_domain *builtin_domain;
	DOM_SID *sids;
	size_t num_sids;
	void (*cont)(void *private_data, bool success, DOM_SID *sids, size_t num_sids);
	void *private_data;
};

static void gettoken_recvdomgroups(TALLOC_CTX *mem_ctx, bool success,
				   struct winbindd_response *response,
				   void *c, void *private_data);
static void gettoken_recvaliases(void *private_data, bool success,
				 const DOM_SID *aliases,
				 size_t num_aliases);


void winbindd_gettoken_async(TALLOC_CTX *mem_ctx, const DOM_SID *user_sid,
			     void (*cont)(void *private_data, bool success,
					  DOM_SID *sids, size_t num_sids),
			     void *private_data)
{
	struct winbindd_domain *domain;
	struct winbindd_request request;
	struct gettoken_state *state;

	state = TALLOC_ZERO_P(mem_ctx, struct gettoken_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		cont(private_data, False, NULL, 0);
		return;
	}

	state->mem_ctx = mem_ctx;
	sid_copy(&state->user_sid, user_sid);
	state->alias_domain = find_our_domain();
	state->local_alias_domain = find_domain_from_name( get_global_sam_name() );
	state->builtin_domain = find_builtin_domain();
	state->cont = cont;
	state->private_data = private_data;

	domain = find_domain_from_sid_noinit(user_sid);
	if (domain == NULL) {
		DEBUG(5, ("Could not find domain from SID %s\n",
			  sid_string_dbg(user_sid)));
		cont(private_data, False, NULL, 0);
		return;
	}

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_GETUSERDOMGROUPS;
	sid_to_fstring(request.data.sid, user_sid);

	do_async_domain(mem_ctx, domain, &request, gettoken_recvdomgroups,
			NULL, state);
}

static void gettoken_recvdomgroups(TALLOC_CTX *mem_ctx, bool success,
				   struct winbindd_response *response,
				   void *c, void *private_data)
{
	struct gettoken_state *state =
		talloc_get_type_abort(private_data, struct gettoken_state);
	char *sids_str;

	if (!success) {
		DEBUG(10, ("Could not get domain groups\n"));
		state->cont(state->private_data, False, NULL, 0);
		return;
	}

	sids_str = (char *)response->extra_data.data;

	if (sids_str == NULL) {
		/* This could be normal if we are dealing with a
		   local user and local groups */

		if ( !sid_check_is_in_our_domain( &state->user_sid ) ) {
			DEBUG(10, ("Received no domain groups\n"));
			state->cont(state->private_data, True, NULL, 0);
			return;
		}
	}

	state->sids = NULL;
	state->num_sids = 0;

	if (!NT_STATUS_IS_OK(add_sid_to_array(mem_ctx, &state->user_sid,
					      &state->sids, &state->num_sids)))
	{
		DEBUG(0, ("Out of memory\n"));
		state->cont(state->private_data, False, NULL, 0);
		return;
	}

	if (sids_str && !parse_sidlist(mem_ctx, sids_str, &state->sids,
			   &state->num_sids)) {
		DEBUG(0, ("Could not parse sids\n"));
		state->cont(state->private_data, False, NULL, 0);
		return;
	}

	SAFE_FREE(response->extra_data.data);

	if (state->alias_domain == NULL) {
		DEBUG(10, ("Don't expand domain local groups\n"));
		state->cont(state->private_data, True, state->sids,
			    state->num_sids);
		return;
	}

	winbindd_getsidaliases_async(state->alias_domain, mem_ctx,
				     state->sids, state->num_sids,
				     gettoken_recvaliases, state);
}

static void gettoken_recvaliases(void *private_data, bool success,
				 const DOM_SID *aliases,
				 size_t num_aliases)
{
	struct gettoken_state *state = (struct gettoken_state *)private_data;
	size_t i;

	if (!success) {
		DEBUG(10, ("Could not receive domain local groups\n"));
		state->cont(state->private_data, False, NULL, 0);
		return;
	}

	for (i=0; i<num_aliases; i++) {
		if (!NT_STATUS_IS_OK(add_sid_to_array(state->mem_ctx,
						      &aliases[i],
						      &state->sids,
						      &state->num_sids)))
		{
			DEBUG(0, ("Out of memory\n"));
			state->cont(state->private_data, False, NULL, 0);
			return;
		}
	}

	if (state->local_alias_domain != NULL) {
		struct winbindd_domain *local_domain = state->local_alias_domain;
		DEBUG(10, ("Expanding our own local groups\n"));
		state->local_alias_domain = NULL;
		winbindd_getsidaliases_async(local_domain, state->mem_ctx,
					     state->sids, state->num_sids,
					     gettoken_recvaliases, state);
		return;
	}

	if (state->builtin_domain != NULL) {
		struct winbindd_domain *builtin_domain = state->builtin_domain;
		DEBUG(10, ("Expanding our own BUILTIN groups\n"));
		state->builtin_domain = NULL;
		winbindd_getsidaliases_async(builtin_domain, state->mem_ctx,
					     state->sids, state->num_sids,
					     gettoken_recvaliases, state);
		return;
	}

	state->cont(state->private_data, True, state->sids, state->num_sids);
}

static void query_user_recv(TALLOC_CTX *mem_ctx, bool success,
			    struct winbindd_response *response,
			    void *c, void *private_data)
{
	void (*cont)(void *priv, bool succ, const char *acct_name,
		     const char *full_name, const char *homedir, 
		     const char *shell, uint32 gid, uint32 group_rid) =
		(void (*)(void *, bool, const char *, const char *,
			  const char *, const char *, uint32, uint32))c;

	if (!success) {
		DEBUG(5, ("Could not trigger query_user\n"));
		cont(private_data, False, NULL, NULL, NULL, NULL, -1, -1);
		return;
	}

	if (response->result != WINBINDD_OK) {
                DEBUG(5, ("query_user returned an error\n"));
		cont(private_data, False, NULL, NULL, NULL, NULL, -1, -1);
		return;
	}

	cont(private_data, True, response->data.user_info.acct_name,
	     response->data.user_info.full_name,
	     response->data.user_info.homedir,
	     response->data.user_info.shell,
	     response->data.user_info.primary_gid,
	     response->data.user_info.group_rid);
}

void query_user_async(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
		      const DOM_SID *sid,
		      void (*cont)(void *private_data, bool success,
				   const char *acct_name,
				   const char *full_name,
				   const char *homedir,
				   const char *shell,
				   gid_t gid,
				   uint32 group_rid),
		      void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_USERINFO;
	sid_to_fstring(request.data.sid, sid);
	do_async_domain(mem_ctx, domain, &request, query_user_recv,
			(void *)cont, private_data);
}
