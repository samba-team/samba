/* 
   Unix SMB/CIFS implementation.

   endpoint server for the samr pipe

   Copyright (C) Andrew Tridgell 2004
   
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
#include "rpc_server/common/common.h"

/*
  this type allows us to distinguish handle types
*/
enum samr_handle {
	SAMR_HANDLE_CONNECT,
	SAMR_HANDLE_DOMAIN,
	SAMR_HANDLE_USER,
	SAMR_HANDLE_GROUP,
	SAMR_HANDLE_ALIAS
};


/*
  state asscoiated with a samr_Connect*() operation
*/
struct samr_connect_state {
	int reference_count;
	void *sam_ctx;
	TALLOC_CTX *mem_ctx;
	uint32 access_mask;
};

/*
  state associated with a samr_OpenDomain() operation
*/
struct samr_domain_state {
	struct samr_connect_state *connect_state;
	int reference_count;
	void *sam_ctx;
	TALLOC_CTX *mem_ctx;
	uint32 access_mask;
	const char *domain_sid;
	const char *domain_name;
	const char *basedn;
};

/*
  state associated with a open account handle
*/
struct samr_account_state {
	struct samr_domain_state *domain_state;
	void *sam_ctx;
	TALLOC_CTX *mem_ctx;
	uint32 access_mask;
	const char *account_sid;
	const char *account_name;
	const char *basedn;
};


/*
  destroy connection state
*/
static void samr_Connect_close(struct samr_connect_state *state)
{
	state->reference_count--;
	if (state->reference_count == 0) {
		samdb_close(state->sam_ctx);
		talloc_destroy(state->mem_ctx);
	}
}

/*
  destroy an open connection. This closes the database connection
*/
static void samr_Connect_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct samr_connect_state *state = h->data;
	samr_Connect_close(state);
}

/* 
  samr_Connect 

  create a connection to the SAM database
*/
static NTSTATUS samr_Connect(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct samr_Connect *r)
{
	struct samr_connect_state *state;
	struct dcesrv_handle *handle;
	TALLOC_CTX *connect_mem_ctx;

	ZERO_STRUCTP(r->out.handle);

	connect_mem_ctx = talloc_init("samr_Connect");
	if (!connect_mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(connect_mem_ctx, struct samr_connect_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}
	state->mem_ctx = connect_mem_ctx;

	/* make sure the sam database is accessible */
	state->sam_ctx = samdb_connect();
	if (state->sam_ctx == NULL) {
		talloc_destroy(state->mem_ctx);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_CONNECT);
	if (!handle) {
		talloc_destroy(state->mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = state;
	handle->destroy = samr_Connect_destroy;

	state->reference_count = 1;
	state->access_mask = r->in.access_mask;
	*r->out.handle = handle->wire_handle;

	return NT_STATUS_OK;
}


/* 
  samr_Close 
*/
static NTSTATUS samr_Close(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			   struct samr_Close *r)
{
	struct dcesrv_handle *h;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	/* this causes the callback samr_XXX_destroy() to be called by
	   the handle destroy code which destroys the state associated
	   with the handle */
	dcesrv_handle_destroy(dce_call->conn, h);

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/* 
  samr_SetSecurity 
*/
static NTSTATUS samr_SetSecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetSecurity *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QuerySecurity 
*/
static NTSTATUS samr_QuerySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_QuerySecurity *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_Shutdown 

  we refuse this operation completely. If a admin wants to shutdown samr
  in Samba then they should use the samba admin tools to disable the samr pipe
*/
static NTSTATUS samr_Shutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Shutdown *r)
{
	return NT_STATUS_ACCESS_DENIED;
}


/* 
  samr_LookupDomain 

  this maps from a domain name to a SID
*/
static NTSTATUS samr_LookupDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_LookupDomain *r)
{
	struct samr_connect_state *state;
	struct dcesrv_handle *h;
	struct dom_sid2 *sid;
	const char *sidstr;
		
	r->out.sid = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_CONNECT);

	state = h->data;

	if (r->in.domain->name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	sidstr = samdb_search_string(state->sam_ctx,
				     mem_ctx, NULL, "objectSid",
				     "(&(name=%s)(objectclass=domain))",
				     r->in.domain->name);
	if (sidstr == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	sid = dom_sid_parse_talloc(mem_ctx, sidstr);
	if (sid == NULL) {
		DEBUG(1,("samdb: Invalid sid '%s' for domain %s\n",
			 sidstr, r->in.domain->name));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	r->out.sid = sid;

	return NT_STATUS_OK;
}


/* 
  samr_EnumDomains 

  list the domains in the SAM
*/
static NTSTATUS samr_EnumDomains(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_EnumDomains *r)
{
	struct samr_connect_state *state;
	struct dcesrv_handle *h;
	struct samr_SamArray *array;
	const char **domains;
	int count, i, start_i;

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_CONNECT);

	state = h->data;

	count = samdb_search_string_multiple(state->sam_ctx,
					     mem_ctx, NULL, &domains, 
					     "name", "(objectclass=domain)");
	if (count == -1) {
		DEBUG(1,("samdb: no domains found in EnumDomains\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*r->out.resume_handle = count;

	start_i = *r->in.resume_handle;

	if (start_i >= count) {
		/* search past end of list is not an error for this call */
		return NT_STATUS_OK;
	}

	array = talloc_p(mem_ctx, struct samr_SamArray);
	if (array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
		
	array->count = 0;
	array->entries = NULL;

	array->entries = talloc_array_p(mem_ctx, struct samr_SamEntry, count - start_i);
	if (array->entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<count-start_i;i++) {
		array->entries[i].idx = start_i + i;
		array->entries[i].name.name = domains[start_i+i];
	}

	r->out.sam = array;
	r->out.num_entries = i - start_i;
	array->count = r->out.num_entries;

	return NT_STATUS_OK;
}


/*
  close an open domain context
*/
static void samr_Domain_close(struct dcesrv_connection *conn, 
			      struct samr_domain_state *state)
{
	state->reference_count--;
	if (state->reference_count == 0) {
		samr_Connect_close(state->connect_state);
		talloc_destroy(state->mem_ctx);
	}
}

/*
  destroy an open domain context
*/
static void samr_Domain_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct samr_domain_state *state = h->data;
	samr_Domain_close(conn, state);
}

/* 
  samr_OpenDomain 
*/
static NTSTATUS samr_OpenDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_OpenDomain *r)
{
	struct dcesrv_handle *h_conn, *h_domain;
	const char *sidstr, *domain_name;
	struct samr_connect_state *c_state;
	struct samr_domain_state *state;
	TALLOC_CTX *mem_ctx2;
	const char * const attrs[2] = { "name", NULL};
	struct ldb_message **msgs;
	int ret;

	ZERO_STRUCTP(r->out.domain_handle);

	DCESRV_PULL_HANDLE(h_conn, r->in.handle, SAMR_HANDLE_CONNECT);

	c_state = h_conn->data;

	if (r->in.sid == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	sidstr = dom_sid_string(mem_ctx, r->in.sid);
	if (sidstr == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ret = samdb_search(c_state->sam_ctx,
			   mem_ctx, NULL, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=domain))", 
			   sidstr);
	if (ret != 1) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	domain_name = ldb_msg_find_string(msgs[0], "name", NULL);
	if (domain_name == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	mem_ctx2 = talloc_init("OpenDomain(%s)\n", domain_name);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(mem_ctx2, struct samr_domain_state);
	if (!state) {
		talloc_destroy(mem_ctx2);
		return NT_STATUS_NO_MEMORY;
	}

	state->reference_count = 1;
	state->connect_state = c_state;
	state->sam_ctx = c_state->sam_ctx;
	state->mem_ctx = mem_ctx2;
	state->domain_sid = talloc_strdup(mem_ctx2, sidstr);
	state->domain_name = talloc_strdup(mem_ctx2, domain_name);
	state->basedn = talloc_strdup(mem_ctx2, msgs[0]->dn);
	if (!state->domain_sid || !state->domain_name || !state->basedn) {
		talloc_destroy(mem_ctx2);
		return NT_STATUS_NO_MEMORY;		
	}
	state->access_mask = r->in.access_mask;

	h_domain = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_DOMAIN);
	if (!h_domain) {
		talloc_destroy(mem_ctx2);
		return NT_STATUS_NO_MEMORY;
	}

	c_state->reference_count++;
	h_domain->data = state;
	h_domain->destroy = samr_Domain_destroy;
	*r->out.domain_handle = h_domain->wire_handle;

	return NT_STATUS_OK;
}


/* 
  samr_QueryDomainInfo 
*/
static NTSTATUS samr_QueryDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDomainInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_SetDomainInfo 
*/
static NTSTATUS samr_SetDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetDomainInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  destroy an open account context
*/
static void samr_Account_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct samr_account_state *state = h->data;
	samr_Domain_close(conn, state->domain_state);
	talloc_destroy(state->mem_ctx);
}

/* 
  samr_CreateDomainGroup 
*/
static NTSTATUS samr_CreateDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct samr_CreateDomainGroup *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *state;
	struct dcesrv_handle *h;
	const char *name;
	struct ldb_message msg;
	uint32 rid;
	const char *groupname, *sidstr;
	time_t now = time(NULL);
	TALLOC_CTX *mem_ctx2;
	struct dcesrv_handle *g_handle;
	int ret;
	NTSTATUS status;

	ZERO_STRUCTP(r->out.group_handle);
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	groupname = r->in.name->name;

	if (groupname == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* check if the group already exists */
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, d_state->basedn, 
				   "sAMAccountName",
				   "(&(sAMAccountName=%s)(objectclass=group))",
				   groupname);
	if (name != NULL) {
		return NT_STATUS_GROUP_EXISTS;
	}

	ZERO_STRUCT(msg);

	/* pull in all the template attributes */
	ret = samdb_copy_template(d_state->sam_ctx, mem_ctx, &msg, 
				  "(&(name=TemplateGroup)(objectclass=groupTemplate))");
	if (ret != 0) {
		DEBUG(1,("Failed to load TemplateUser from samdb\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* allocate a rid */
	status = samdb_allocate_next_id(d_state->sam_ctx, mem_ctx, 
					d_state->basedn, "nextRid", &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* and the group SID */
	sidstr = talloc_asprintf(mem_ctx, "%s-%u", d_state->domain_sid, rid);
	if (!sidstr) {
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the user */
	msg.dn = talloc_asprintf(mem_ctx, "CN=%s,CN=Users,%s", groupname,
				 d_state->basedn);
	if (!msg.dn) {
		return NT_STATUS_NO_MEMORY;
	}
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg,
			     "name", groupname);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg,
			     "cn", groupname);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg,
			     "sAMAccountName", groupname);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg,
			     "objectClass", "group");
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg,
			     "objectSid", sidstr);
	samdb_msg_set_ldaptime(d_state->sam_ctx, mem_ctx, &msg,
			       "whenCreated", now);
	samdb_msg_set_ldaptime(d_state->sam_ctx, mem_ctx, &msg,
			       "whenChanged", now);
			     
	/* create the group */
	ret = samdb_add(d_state->sam_ctx, mem_ctx, &msg);
	if (ret != 0) {
		DEBUG(1,("Failed to create group record %s\n", msg.dn));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* create group state and new policy handle */
	mem_ctx2 = talloc_init("CreateDomainGroup(%s)", groupname);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}
	state->mem_ctx = mem_ctx2;
	state->sam_ctx = d_state->sam_ctx;
	state->access_mask = r->in.access_mask;
	state->domain_state = d_state;
	state->basedn = talloc_steal(mem_ctx, mem_ctx2, msg.dn);
	state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	state->account_name = talloc_strdup(mem_ctx2, groupname);
	if (!state->account_name || !state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = state;
	g_handle->destroy = samr_Account_destroy;

	/* the domain state is in use one more time */
	d_state->reference_count++;

	*r->out.group_handle = g_handle->wire_handle;
	*r->out.rid = rid;	

	return NT_STATUS_OK;
}


/* 
  samr_EnumDomainGroups 
*/
static NTSTATUS samr_EnumDomainGroups(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct samr_EnumDomainGroups *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_CreateUser2 

  TODO: This should do some form of locking, especially around the rid allocation
*/
static NTSTATUS samr_CreateUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_CreateUser2 *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *state;
	struct dcesrv_handle *h;
	const char *name;
	struct ldb_message msg;
	uint32 rid;
	const char *username, *sidstr;
	time_t now = time(NULL);
	TALLOC_CTX *mem_ctx2;
	struct dcesrv_handle *u_handle;
	int ret;
	NTSTATUS status;

	ZERO_STRUCTP(r->out.acct_handle);
	*r->out.access_granted = 0;
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	username = r->in.username->name;

	if (username == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* check if the user already exists */
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, d_state->basedn, 
				   "sAMAccountName", 
				   "(&(sAMAccountName=%s)(objectclass=user))", username);
	if (name != NULL) {
		return NT_STATUS_USER_EXISTS;
	}

	ZERO_STRUCT(msg);

	/* pull in all the template attributes */
	ret = samdb_copy_template(d_state->sam_ctx, mem_ctx, &msg, 
				  "(&(name=TemplateUser)(objectclass=userTemplate))");
	if (ret != 0) {
		DEBUG(1,("Failed to load TemplateUser from samdb\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	/* allocate a rid */
	status = samdb_allocate_next_id(d_state->sam_ctx, mem_ctx, 
					d_state->basedn, "nextRid", &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* and the users SID */
	sidstr = talloc_asprintf(mem_ctx, "%s-%u", d_state->domain_sid, rid);
	if (!sidstr) {
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the user */
	msg.dn = talloc_asprintf(mem_ctx, "CN=%s,CN=Users,%s", username, d_state->basedn);
	if (!msg.dn) {
		return NT_STATUS_NO_MEMORY;		
	}
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "name", username);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "cn", username);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "sAMAccountName", username);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "objectClass", "user");
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "objectSid", sidstr);
	samdb_msg_set_ldaptime(d_state->sam_ctx, mem_ctx, &msg, "whenCreated", now);
	samdb_msg_set_ldaptime(d_state->sam_ctx, mem_ctx, &msg, "whenChanged", now);

	/* create the user */
	ret = samdb_add(d_state->sam_ctx, mem_ctx, &msg);
	if (ret != 0) {
		DEBUG(1,("Failed to create user record %s\n", msg.dn));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* create user state and new policy handle */
	mem_ctx2 = talloc_init("CreateUser(%s)", username);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}
	state->mem_ctx = mem_ctx2;
	state->sam_ctx = d_state->sam_ctx;
	state->access_mask = r->in.access_mask;
	state->domain_state = d_state;
	state->basedn = talloc_steal(mem_ctx, mem_ctx2, msg.dn);
	state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	state->account_name = talloc_strdup(mem_ctx2, username);
	if (!state->account_name || !state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = state;
	u_handle->destroy = samr_Account_destroy;

	/* the domain state is in use one more time */
	d_state->reference_count++;

	*r->out.acct_handle = u_handle->wire_handle;
	*r->out.access_granted = 0xf07ff; /* TODO: fix access mask calculations */
	*r->out.rid = rid;	

	return NT_STATUS_OK;
}


/* 
  samr_CreateUser 
*/
static NTSTATUS samr_CreateUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_CreateUser *r)
{
	struct samr_CreateUser2 r2;
	uint32 access_granted;


	/* a simple wrapper around samr_CreateUser2 works nicely */
	r2.in.handle = r->in.handle;
	r2.in.username = r->in.username;
	r2.in.acct_flags = 1234;
	r2.in.access_mask = r->in.access_mask;
	r2.out.acct_handle = r->out.acct_handle;
	r2.out.access_granted = &access_granted;
	r2.out.rid = r->out.rid;

	return samr_CreateUser2(dce_call, mem_ctx, &r2);
}

/*
  comparison function for sorting SamEntry array
*/
static int compare_SamEntry(struct samr_SamEntry *e1, struct samr_SamEntry *e2)
{
	return e1->idx - e2->idx;
}

/* 
  samr_EnumDomainUsers 
*/
static NTSTATUS samr_EnumDomainUsers(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct samr_EnumDomainUsers *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *state;
	struct ldb_message **res;
	int count, i, first;
	struct samr_SamEntry *entries;
	const char * const attrs[3] = { "objectSid", "sAMAccountName", NULL };

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	state = h->data;
	
	/* search for all users in this domain. This could possibly be cached and 
	   resumed based on resume_key */
	count = samdb_search(state->sam_ctx, mem_ctx, state->basedn, &res, attrs, 
			     "objectclass=user");
	if (count == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (count == 0 || r->in.max_size == 0) {
		return NT_STATUS_OK;
	}

	/* convert to SamEntry format */
	entries = talloc_array_p(mem_ctx, struct samr_SamEntry, count);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<count;i++) {
		entries[i].idx = samdb_result_rid_from_sid(mem_ctx, res[i], "objectSid", 0);
		entries[i].name.name = samdb_result_string(res[i], "sAMAccountName", "");
	}

	/* sort the results by rid */
	qsort(entries, count, sizeof(struct samr_SamEntry), 
	      (comparison_fn_t)compare_SamEntry);

	/* find the first entry to return */
	for (first=0;
	     first<count && entries[first].idx <= *r->in.resume_handle;
	     first++) ;

	if (first == count) {
		return NT_STATUS_OK;
	}

	/* return the rest, limit by max_size. Note that we 
	   use the w2k3 element size value of 54 */
	r->out.num_entries = count - first;
	r->out.num_entries = MIN(r->out.num_entries, 
				 1+(r->in.max_size/SAMR_ENUM_USERS_MULTIPLIER));

	r->out.sam = talloc_p(mem_ctx, struct samr_SamArray);
	if (!r->out.sam) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sam->entries = entries+first;
	r->out.sam->count = r->out.num_entries;

	if (r->out.num_entries < count - first) {
		*r->out.resume_handle = entries[first+r->out.num_entries-1].idx;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}


/* 
  samr_CreateDomAlias 
*/
static NTSTATUS samr_CreateDomAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_CreateDomAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_EnumDomainAliases 
*/
static NTSTATUS samr_EnumDomainAliases(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_EnumDomainAliases *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetAliasMembership 
*/
static NTSTATUS samr_GetAliasMembership(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetAliasMembership *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_LookupNames 
*/
static NTSTATUS samr_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_LookupNames *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *state;
	int i;
	NTSTATUS status = NT_STATUS_OK;
	const char * const attrs[] = { "sAMAccountType", "objectSid", NULL };
	int count;

	ZERO_STRUCT(r->out.rids);
	ZERO_STRUCT(r->out.types);

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	state = h->data;

	if (r->in.num_names == 0) {
		return NT_STATUS_OK;
	}

	r->out.rids.ids = talloc_array_p(mem_ctx, uint32, r->in.num_names);
	r->out.types.ids = talloc_array_p(mem_ctx, uint32, r->in.num_names);
	if (!r->out.rids.ids || !r->out.types.ids) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.rids.count = r->in.num_names;
	r->out.types.count = r->in.num_names;

	for (i=0;i<r->in.num_names;i++) {
		struct ldb_message **res;
		struct dom_sid2 *sid;
		const char *sidstr;
		uint32 atype, rtype;

		r->out.rids.ids[i] = 0;
		r->out.types.ids[i] = SID_NAME_UNKNOWN;

		count = samdb_search(state->sam_ctx, mem_ctx, state->basedn, &res, attrs, 
				     "sAMAccountName=%s", r->in.names[i].name);
		if (count != 1) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		sidstr = samdb_result_string(res[0], "objectSid", NULL);
		if (sidstr == NULL) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}
		
		sid = dom_sid_parse_talloc(mem_ctx, sidstr);
		if (sid == NULL) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		atype = samdb_result_uint(res[0], "sAMAccountType", 0);
		if (atype == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		switch (atype & 0xF0000000) {
		case ATYPE_ACCOUNT:
			rtype = SID_NAME_USER;
			break;
		case ATYPE_GLOBAL_GROUP:
			rtype = SID_NAME_DOM_GRP;
			break;
		case ATYPE_LOCAL_GROUP:
			rtype = SID_NAME_ALIAS;
			break;
		default:
			DEBUG(1,("Unknown sAMAccountType 0x%08x\n", atype));
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		r->out.rids.ids[i] = sid->sub_auths[sid->num_auths-1];
		r->out.types.ids[i] = rtype;
	}
	

	return status;
}


/* 
  samr_LookupRids 
*/
static NTSTATUS samr_LookupRids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_LookupRids *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_OpenGroup 
*/
static NTSTATUS samr_OpenGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OpenGroup *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *state;
	struct dcesrv_handle *h;
	const char *groupname, *sidstr;
	TALLOC_CTX *mem_ctx2;
	struct ldb_message **msgs;
	struct dcesrv_handle *g_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.acct_handle);

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the group SID */
	sidstr = talloc_asprintf(mem_ctx, "%s-%u", d_state->domain_sid, r->in.rid);
	if (!sidstr) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the group record */
	ret = samdb_search(d_state->sam_ctx,
			   mem_ctx, d_state->basedn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=group))", 
			   sidstr);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_GROUP;
	}
	if (ret != 1) {
		DEBUG(1,("Found %d records matching sid %s\n", ret, sidstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	groupname = samdb_result_string(msgs[0], "sAMAccountName", NULL);
	if (groupname == NULL) {
		DEBUG(1,("sAMAccountName field missing for sid %s\n", sidstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* create group state and new policy handle */
	mem_ctx2 = talloc_init("OpenGroup(%u)", r->in.rid);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}
	state->mem_ctx = mem_ctx2;
	state->sam_ctx = d_state->sam_ctx;
	state->access_mask = r->in.access_mask;
	state->domain_state = d_state;
	state->basedn = talloc_steal(mem_ctx, mem_ctx2, msgs[0]->dn);
	state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	state->account_name = talloc_strdup(mem_ctx2, groupname);
	if (!state->account_name || !state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = state;
	g_handle->destroy = samr_Account_destroy;

	/* the domain state is in use one more time */
	d_state->reference_count++;

	*r->out.acct_handle = g_handle->wire_handle;

	return NT_STATUS_OK;
}

/* these query macros make samr_Query[User|Group]Info a bit easier to read */

#define QUERY_STRING(msg, field, attr) \
	r->out.info->field = samdb_result_string(msg, attr, "");
#define QUERY_UINT(msg, field, attr) \
	r->out.info->field = samdb_result_uint(msg, attr, 0);
#define QUERY_RID(msg, field, attr) \
	r->out.info->field = samdb_result_rid_from_sid(mem_ctx, msg, attr, 0);
#define QUERY_NTTIME(msg, field, attr) \
	r->out.info->field = samdb_result_nttime(msg, attr, 0);
#define QUERY_APASSC(msg, field, attr) \
	r->out.info->field = samdb_result_allow_pwd_change(state->sam_ctx, mem_ctx, \
							   state->domain_state->basedn, msg, attr);
#define QUERY_FPASSC(msg, field, attr) \
	r->out.info->field = samdb_result_force_pwd_change(state->sam_ctx, mem_ctx, \
							   state->domain_state->basedn, msg, attr);
#define QUERY_LHOURS(msg, field, attr) \
	r->out.info->field = samdb_result_logon_hours(mem_ctx, msg, attr);
#define QUERY_AFLAGS(msg, field, attr) \
	r->out.info->field = samdb_result_acct_flags(msg, attr);


/* these are used to make the Set[User|Group]Info code easier to follow */

#define SET_STRING(mod, field, attr) do { \
	if (r->in.info->field == NULL) return NT_STATUS_INVALID_PARAMETER; \
	if (samdb_msg_add_string(state->sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_UINT(mod, field, attr) do { \
	if (samdb_msg_add_uint(state->sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_AFLAGS(msg, field, attr) do { \
	if (samdb_msg_add_acct_flags(state->sam_ctx, mem_ctx, msg, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_LHOURS(msg, field, attr) do { \
	if (samdb_msg_add_logon_hours(state->sam_ctx, mem_ctx, msg, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

/* 
  samr_QueryGroupInfo 
*/
static NTSTATUS samr_QueryGroupInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryGroupInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;
	struct ldb_message *msg, **res;
	const char * const attrs[4] = { "sAMAccountName", "description",
					"numMembers", NULL };
	int ret;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_GROUP);

	state = h->data;

	/* pull all the group attributes */
	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs,
			   "dn=%s", state->basedn);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	r->out.info = talloc_p(mem_ctx, union samr_GroupInfo);
	if (r->out.info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(r->out.info);

	/* Fill in the level */
	switch (r->in.level) {
	case GroupInfoAll:
		QUERY_STRING(msg, all.name.name,        "sAMAccountName");
		r->out.info->all.unknown = 7; /* Do like w2k3 */
		QUERY_UINT  (msg, all.num_members,      "numMembers")
		QUERY_STRING(msg, all.description.name, "description");
		break;
	case GroupInfoName:
		QUERY_STRING(msg, name.name,            "sAMAccountName");
		break;
	case GroupInfoX:
		r->out.info->unknown.unknown = 7;
		break;
	case GroupInfoDescription:
		QUERY_STRING(msg, description.name, "description");
		break;
	default:
		r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	
	return NT_STATUS_OK;
}


/* 
  samr_SetGroupInfo 
*/
static NTSTATUS samr_SetGroupInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetGroupInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;
	struct ldb_message mod, *msg = &mod;
	int i, ret;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_GROUP);

	state = h->data;

	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, state->basedn);
	if (!mod.dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case GroupInfoDescription:
		SET_STRING(msg, description.name,         "description");
		break;
	case GroupInfoName:
		/* On W2k3 this does not change the name, it changes the
		 * sAMAccountName attribute */
		SET_STRING(msg, name.name,                "sAMAccountName");
		break;
	case GroupInfoX:
		/* This does not do anything obviously visible in W2k3 LDAP */
		break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* mark all the message elements as LDB_FLAG_MOD_REPLACE */
	for (i=0;i<mod.num_elements;i++) {
		mod.elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	/* modify the samdb record */
	ret = samdb_modify(state->sam_ctx, mem_ctx, &mod);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/* 
  samr_AddGroupMember 
*/
static NTSTATUS samr_AddGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddGroupMember *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_DeleteDomainGroup 
*/
static NTSTATUS samr_DeleteDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteDomainGroup *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;
	int ret;

        *r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_GROUP);

	state = h->data;

	ret = samdb_delete(state->sam_ctx, mem_ctx, state->basedn);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/* 
  samr_DeleteGroupMember 
*/
static NTSTATUS samr_DeleteGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteGroupMember *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryGroupMember 
*/
static NTSTATUS samr_QueryGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryGroupMember *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_SetMemberAttributesOfGroup 
*/
static NTSTATUS samr_SetMemberAttributesOfGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetMemberAttributesOfGroup *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_OpenAlias 
*/
static NTSTATUS samr_OpenAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OpenAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryAliasInfo 
*/
static NTSTATUS samr_QueryAliasInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryAliasInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_SetAliasInfo 
*/
static NTSTATUS samr_SetAliasInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetAliasInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_DeleteDomAlias 
*/
static NTSTATUS samr_DeleteDomAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteDomAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_AddAliasMember 
*/
static NTSTATUS samr_AddAliasMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddAliasMember *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_DeleteAliasMember 
*/
static NTSTATUS samr_DeleteAliasMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteAliasMember *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetMembersInAlias 
*/
static NTSTATUS samr_GetMembersInAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetMembersInAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_OpenUser 
*/
static NTSTATUS samr_OpenUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_OpenUser *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *state;
	struct dcesrv_handle *h;
	const char *username, *sidstr;
	TALLOC_CTX *mem_ctx2;
	struct ldb_message **msgs;
	struct dcesrv_handle *u_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.acct_handle);

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the users SID */
	sidstr = talloc_asprintf(mem_ctx, "%s-%u", d_state->domain_sid, r->in.rid);
	if (!sidstr) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the user record */
	ret = samdb_search(d_state->sam_ctx,
			   mem_ctx, d_state->basedn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=user))", 
			   sidstr);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
	if (ret != 1) {
		DEBUG(1,("Found %d records matching sid %s\n", ret, sidstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	username = samdb_result_string(msgs[0], "sAMAccountName", NULL);
	if (username == NULL) {
		DEBUG(1,("sAMAccountName field missing for sid %s\n", sidstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* create user state and new policy handle */
	mem_ctx2 = talloc_init("OpenUser(%u)", r->in.rid);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}
	state->mem_ctx = mem_ctx2;
	state->sam_ctx = d_state->sam_ctx;
	state->access_mask = r->in.access_mask;
	state->domain_state = d_state;
	state->basedn = talloc_steal(mem_ctx, mem_ctx2, msgs[0]->dn);
	state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	state->account_name = talloc_strdup(mem_ctx2, username);
	if (!state->account_name || !state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = state;
	u_handle->destroy = samr_Account_destroy;

	/* the domain state is in use one more time */
	d_state->reference_count++;

	*r->out.acct_handle = u_handle->wire_handle;

	return NT_STATUS_OK;

}


/* 
  samr_DeleteUser 
*/
static NTSTATUS samr_DeleteUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_DeleteUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;
	int ret;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	state = h->data;

	ret = samdb_delete(state->sam_ctx, mem_ctx, state->basedn);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/* 
  samr_QueryUserInfo 
*/
static NTSTATUS samr_QueryUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_QueryUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;
	struct ldb_message *msg, **res;
	int ret;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	state = h->data;

	/* pull all the user attributes */
	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, NULL,
			   "dn=%s", state->basedn);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	r->out.info = talloc_p(mem_ctx, union samr_UserInfo);
	if (r->out.info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(r->out.info);

	/* fill in the reply */
	switch (r->in.level) {
	case 1:
		QUERY_STRING(msg, info1.username.name,    "sAMAccountName");
		QUERY_STRING(msg, info1.full_name.name,   "displayName");
		QUERY_UINT  (msg, info1.primary_gid,      "primaryGroupID");
		QUERY_STRING(msg, info1.description.name, "description");
		QUERY_STRING(msg, info1.comment.name,     "comment");
		break;

	case 2:
		QUERY_STRING(msg, info2.comment.name,     "comment");
		QUERY_UINT  (msg, info2.country_code,     "countryCode");
		QUERY_UINT  (msg, info2.code_page,        "codePage");
		break;

	case 3:
		QUERY_STRING(msg, info3.username.name,       "sAMAccountName");
		QUERY_STRING(msg, info3.full_name.name,      "displayName");
		QUERY_RID   (msg, info3.rid,                 "objectSid");
		QUERY_UINT  (msg, info3.primary_gid,         "primaryGroupID");
		QUERY_STRING(msg, info3.home_directory.name, "homeDirectory");
		QUERY_STRING(msg, info3.home_drive.name,     "homeDrive");
		QUERY_STRING(msg, info3.logon_script.name,   "scriptPath");
		QUERY_STRING(msg, info3.profile.name,        "profilePath");
		QUERY_STRING(msg, info3.workstations.name,   "userWorkstations");
		QUERY_NTTIME(msg, info3.last_logon,          "lastLogon");
		QUERY_NTTIME(msg, info3.last_logoff,         "lastLogoff");
		QUERY_NTTIME(msg, info3.last_pwd_change,     "pwdLastSet");
		QUERY_APASSC(msg, info3.allow_pwd_change,    "pwdLastSet");
		QUERY_FPASSC(msg, info3.force_pwd_change,    "pwdLastSet");
		QUERY_LHOURS(msg, info3.logon_hours,         "logonHours");
		QUERY_UINT  (msg, info3.bad_pwd_count,       "badPwdCount");
		QUERY_UINT  (msg, info3.num_logons,          "logonCount");
		QUERY_AFLAGS(msg, info3.acct_flags,          "userAccountControl");
		break;

	case 4:
		QUERY_LHOURS(msg, info4.logon_hours,         "logonHours");
		break;

	case 5:
		QUERY_STRING(msg, info5.username.name,       "sAMAccountName");
		QUERY_STRING(msg, info5.full_name.name,      "displayName");
		QUERY_RID   (msg, info5.rid,                 "objectSid");
		QUERY_UINT  (msg, info5.primary_gid,         "primaryGroupID");
		QUERY_STRING(msg, info5.home_directory.name, "homeDirectory");
		QUERY_STRING(msg, info5.home_drive.name,     "homeDrive");
		QUERY_STRING(msg, info5.logon_script.name,   "scriptPath");
		QUERY_STRING(msg, info5.profile.name,        "profilePath");
		QUERY_STRING(msg, info5.description.name,    "description");
		QUERY_STRING(msg, info5.workstations.name,   "userWorkstations");
		QUERY_NTTIME(msg, info5.last_logon,          "lastLogon");
		QUERY_NTTIME(msg, info5.last_logoff,         "lastLogoff");
		QUERY_LHOURS(msg, info5.logon_hours,         "logonHours");
		QUERY_UINT  (msg, info5.bad_pwd_count,       "badPwdCount");
		QUERY_UINT  (msg, info5.num_logons,          "logonCount");
		QUERY_NTTIME(msg, info5.last_pwd_change,     "pwdLastSet");
		QUERY_NTTIME(msg, info5.acct_expiry,         "accountExpires");
		QUERY_AFLAGS(msg, info5.acct_flags,          "userAccountControl");
		break;

	case 6:
		QUERY_STRING(msg, info6.username.name,       "sAMAccountName");
		QUERY_STRING(msg, info6.full_name.name,      "displayName");
		break;

	case 7:
		QUERY_STRING(msg, info7.username.name,       "sAMAccountName");
		break;

	case 8:
		QUERY_STRING(msg, info8.full_name.name,      "displayName");
		break;

	case 9:
		QUERY_UINT  (msg, info9.primary_gid,         "primaryGroupID");
		break;

	case 10:
		QUERY_STRING(msg, info10.home_directory.name, "homeDirectory");
		QUERY_STRING(msg, info10.home_drive.name,     "homeDrive");
		break;

	case 11:
		QUERY_STRING(msg, info11.logon_script.name,   "scriptPath");
		break;

	case 12:
		QUERY_STRING(msg, info12.profile.name,        "profilePath");
		break;

	case 13:
		QUERY_STRING(msg, info13.description.name,    "description");
		break;

	case 14:
		QUERY_STRING(msg, info14.workstations.name,   "userWorkstations");
		break;

	case 16:
		QUERY_AFLAGS(msg, info16.acct_flags,          "userAccountControl");
		break;

	case 17:
		QUERY_NTTIME(msg, info17.acct_expiry,         "accountExpires");

	case 20:
		QUERY_STRING(msg, info20.callback.name,       "userParameters");
		break;

	case 21:
		QUERY_NTTIME(msg, info21.last_logon,          "lastLogon");
		QUERY_NTTIME(msg, info21.last_logoff,         "lastLogoff");
		QUERY_NTTIME(msg, info21.last_pwd_change,     "pwdLastSet");
		QUERY_NTTIME(msg, info21.acct_expiry,         "accountExpires");
		QUERY_APASSC(msg, info21.allow_pwd_change,    "pwdLastSet");
		QUERY_FPASSC(msg, info21.force_pwd_change,    "pwdLastSet");
		QUERY_STRING(msg, info21.username.name,       "sAMAccountName");
		QUERY_STRING(msg, info21.full_name.name,      "displayName");
		QUERY_STRING(msg, info21.home_directory.name, "homeDirectory");
		QUERY_STRING(msg, info21.home_drive.name,     "homeDrive");
		QUERY_STRING(msg, info21.logon_script.name,   "scriptPath");
		QUERY_STRING(msg, info21.profile.name,        "profilePath");
		QUERY_STRING(msg, info21.description.name,    "description");
		QUERY_STRING(msg, info21.workstations.name,   "userWorkstations");
		QUERY_STRING(msg, info21.comment.name,        "comment");
		QUERY_STRING(msg, info21.callback.name,       "userParameters");
		QUERY_RID   (msg, info21.rid,                 "objectSid");
		QUERY_UINT  (msg, info21.primary_gid,         "primaryGroupID");
		QUERY_AFLAGS(msg, info21.acct_flags,          "userAccountControl");
		r->out.info->info21.fields_present = 0x00FFFFFF;
		QUERY_LHOURS(msg, info21.logon_hours,         "logonHours");
		QUERY_UINT  (msg, info21.bad_pwd_count,       "badPwdCount");
		QUERY_UINT  (msg, info21.num_logons,          "logonCount");
		QUERY_UINT  (msg, info21.country_code,        "countryCode");
		QUERY_UINT  (msg, info21.code_page,           "codePage");
		break;
		

	default:
		r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	
	return NT_STATUS_OK;
}


/*
  set password via a samr_CryptPassword buffer
  this will in the 'msg' with modify operations that will update the user
  password when applied
*/
static NTSTATUS samr_set_password(struct dcesrv_call_state *dce_call,
				  struct samr_account_state *state, TALLOC_CTX *mem_ctx,
				  struct ldb_message *msg, 
				  struct samr_CryptPassword *pwbuf)
{
	char new_pass[512];
	uint32 new_pass_len;
	DATA_BLOB session_key = dce_call->conn->session_key;

	SamOEMhashBlob(pwbuf->data, 516, &session_key);

	if (!decode_pw_buffer(pwbuf->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_UNICODE)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	return samdb_set_password(state->sam_ctx, mem_ctx,
				  state->basedn, state->domain_state->basedn, 
				  msg, new_pass);
}

/* 
  samr_SetUserInfo 
*/
static NTSTATUS samr_SetUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;
	struct ldb_message mod, *msg = &mod;
	int i, ret;
	NTSTATUS status = NT_STATUS_OK;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	state = h->data;

	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, state->basedn);
	if (!mod.dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case 2:
		SET_STRING(msg, info2.comment.name,         "comment");
		SET_UINT  (msg, info2.country_code,         "countryCode");
		SET_UINT  (msg, info2.code_page,            "codePage");
		break;

	case 4:
		SET_LHOURS(msg, info4.logon_hours,          "logonHours");
		break;

	case 6:
		SET_STRING(msg, info6.full_name.name,       "displayName");
		break;

	case 8:
		SET_STRING(msg, info8.full_name.name,       "displayName");
		break;

	case 9:
		SET_UINT(msg, info9.primary_gid,            "primaryGroupID");
		break;

	case 10:
		SET_STRING(msg, info10.home_directory.name, "homeDirectory");
		SET_STRING(msg, info10.home_drive.name,     "homeDrive");
		break;

	case 11:
		SET_STRING(msg, info11.logon_script.name,   "scriptPath");
		break;

	case 12:
		SET_STRING(msg, info12.profile.name,        "profilePath");
		break;

	case 13:
		SET_STRING(msg, info13.description.name,    "description");
		break;

	case 14:
		SET_STRING(msg, info14.workstations.name,   "userWorkstations");
		break;

	case 16:
		SET_AFLAGS(msg, info16.acct_flags,          "userAccountControl");
		break;

	case 20:
		SET_STRING(msg, info20.callback.name,       "userParameters");
		break;

	case 21:
#define IFSET(bit) if (bit & r->in.info->info21.fields_present)
		IFSET(SAMR_FIELD_NAME)         
			SET_STRING(msg, info21.full_name.name,    "displayName");
		IFSET(SAMR_FIELD_DESCRIPTION)  
			SET_STRING(msg, info21.description.name,  "description");
		IFSET(SAMR_FIELD_COMMENT)      
			SET_STRING(msg, info21.comment.name,      "comment");
		IFSET(SAMR_FIELD_LOGON_SCRIPT) 
			SET_STRING(msg, info21.logon_script.name, "scriptPath");
		IFSET(SAMR_FIELD_PROFILE)      
			SET_STRING(msg, info21.profile.name,      "profilePath");
		IFSET(SAMR_FIELD_WORKSTATION)  
			SET_STRING(msg, info21.workstations.name, "userWorkstations");
		IFSET(SAMR_FIELD_LOGON_HOURS)  
			SET_LHOURS(msg, info21.logon_hours,       "logonHours");
		IFSET(SAMR_FIELD_CALLBACK)     
			SET_STRING(msg, info21.callback.name,     "userParameters");
		IFSET(SAMR_FIELD_COUNTRY_CODE) 
			SET_UINT  (msg, info21.country_code,      "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)    
			SET_UINT  (msg, info21.code_page,         "codePage");
		break;

		/* the set password levels are handled separately */
	case 24:
		status = samr_set_password(dce_call, state, mem_ctx, msg, 
					   &r->in.info->info24.password);
		break;
		

	default:
		/* many info classes are not valid for SetUserInfo */
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* mark all the message elements as LDB_FLAG_MOD_REPLACE */
	for (i=0;i<mod.num_elements;i++) {
		mod.elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	/* modify the samdb record */
	ret = samdb_modify(state->sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/* 
  samr_ChangePasswordUser 
*/
static NTSTATUS samr_ChangePasswordUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_ChangePasswordUser *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetGroupsForUser 
*/
static NTSTATUS samr_GetGroupsForUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetGroupsForUser *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryDisplayInfo 
*/
static NTSTATUS samr_QueryDisplayInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetDisplayEnumerationIndex 
*/
static NTSTATUS samr_GetDisplayEnumerationIndex(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetDisplayEnumerationIndex *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_TestPrivateFunctionsDomain 
*/
static NTSTATUS samr_TestPrivateFunctionsDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_TestPrivateFunctionsDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_TestPrivateFunctionsUser 
*/
static NTSTATUS samr_TestPrivateFunctionsUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_TestPrivateFunctionsUser *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetUserPwInfo 
*/
static NTSTATUS samr_GetUserPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_GetUserPwInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *state;

	ZERO_STRUCT(r->out.info);

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	state = h->data;

	r->out.info.min_pwd_len = samdb_search_uint(state->sam_ctx, mem_ctx, 0, NULL, "minPwdLength", 
						    "dn=%s", state->domain_state->basedn);
	r->out.info.password_properties = samdb_search_uint(state->sam_ctx, mem_ctx, 0, NULL, "pwdProperties", 
							    "dn=%s", state->basedn);
	return NT_STATUS_OK;
}


/* 
  samr_RemoveMemberFromForeignDomain 
*/
static NTSTATUS samr_RemoveMemberFromForeignDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_RemoveMemberFromForeignDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryDomainInfo2 
*/
static NTSTATUS samr_QueryDomainInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDomainInfo2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryUserInfo2 

  just an alias for samr_QueryUserInfo
*/
static NTSTATUS samr_QueryUserInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct samr_QueryUserInfo2 *r)
{
	struct samr_QueryUserInfo r1;
	NTSTATUS status;

	r1.in.handle = r->in.handle;
	r1.in.level  = r->in.level;
	
	status = samr_QueryUserInfo(dce_call, mem_ctx, &r1);
	
	r->out.info = r1.out.info;

	return status;
}


/* 
  samr_QueryDisplayInfo2 
*/
static NTSTATUS samr_QueryDisplayInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetDisplayEnumerationIndex2 
*/
static NTSTATUS samr_GetDisplayEnumerationIndex2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetDisplayEnumerationIndex2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryDisplayInfo3 
*/
static NTSTATUS samr_QueryDisplayInfo3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo3 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_AddMultipleMembersToAlias 
*/
static NTSTATUS samr_AddMultipleMembersToAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddMultipleMembersToAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_RemoveMultipleMembersFromAlias 
*/
static NTSTATUS samr_RemoveMultipleMembersFromAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_RemoveMultipleMembersFromAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_OemChangePasswordUser2 
*/
static NTSTATUS samr_OemChangePasswordUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OemChangePasswordUser2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_ChangePasswordUser2 
*/
static NTSTATUS samr_ChangePasswordUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_ChangePasswordUser2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetDomPwInfo 

  this fetches the default password properties for a domain
*/
static NTSTATUS samr_GetDomPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_GetDomPwInfo *r)
{
	struct ldb_message **msgs;
	int ret;
	const char * const attrs[] = {"minPwdLength", "pwdProperties", NULL };
	void *sam_ctx;

	if (r->in.name == NULL || r->in.name->name == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = samdb_search(sam_ctx, 
			   mem_ctx, NULL, &msgs, attrs, 
			   "(&(name=%s)(objectclass=domain))",
			   r->in.name->name);
	if (ret <= 0) {
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	if (ret > 1) {
		samdb_search_free(sam_ctx, mem_ctx, msgs);
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	r->out.info.min_pwd_len         = samdb_result_uint(msgs[0], "minPwdLength", 0);
	r->out.info.password_properties = samdb_result_uint(msgs[0], "pwdProperties", 1);

	samdb_search_free(sam_ctx, mem_ctx, msgs);

	samdb_close(sam_ctx);
	return NT_STATUS_OK;
}


/* 
  samr_Connect2 
*/
static NTSTATUS samr_Connect2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Connect2 *r)
{
	struct samr_Connect c;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.handle = r->out.handle;

	return samr_Connect(dce_call, mem_ctx, &c);
}


/* 
  samr_SetUserInfo2 

  just an alias for samr_SetUserInfo
*/
static NTSTATUS samr_SetUserInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_SetUserInfo2 *r)
{
	struct samr_SetUserInfo r2;

	r2.in.handle = r->in.handle;
	r2.in.level = r->in.level;
	r2.in.info = r->in.info;

	return samr_SetUserInfo(dce_call, mem_ctx, &r2);
}


/* 
  samr_SetBootKeyInformation 
*/
static NTSTATUS samr_SetBootKeyInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetBootKeyInformation *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetBootKeyInformation 
*/
static NTSTATUS samr_GetBootKeyInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetBootKeyInformation *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_Connect3 
*/
static NTSTATUS samr_Connect3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_Connect3 *r)
{
	struct samr_Connect c;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.handle = r->out.handle;

	return samr_Connect(dce_call, mem_ctx, &c);
}


/* 
  samr_Connect4 
*/
static NTSTATUS samr_Connect4(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_Connect4 *r)
{
	struct samr_Connect c;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.handle = r->out.handle;

	return samr_Connect(dce_call, mem_ctx, &c);
}


/* 
  samr_ChangePasswordUser3 
*/
static NTSTATUS samr_ChangePasswordUser3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_ChangePasswordUser3 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_Connect5 
*/
static NTSTATUS samr_Connect5(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Connect5 *r)
{
	struct samr_Connect c;
	NTSTATUS status;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.handle = r->out.handle;

	status = samr_Connect(dce_call, mem_ctx, &c);

	r->out.info->info1.unknown1 = 3;
	r->out.info->info1.unknown2 = 0;
	r->out.level = r->in.level;

	return status;
}


/* 
  samr_RidToSid 
*/
static NTSTATUS samr_RidToSid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_RidToSid *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_SetDsrmPassword 
*/
static NTSTATUS samr_SetDsrmPassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetDsrmPassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_ValidatePassword 
*/
static NTSTATUS samr_ValidatePassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_ValidatePassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_samr_s.c"
