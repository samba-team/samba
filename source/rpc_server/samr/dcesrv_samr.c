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
#include "rpc_server/samr/dcesrv_samr.h"



/*
  destroy connection state
*/
static void samr_Connect_close(struct samr_connect_state *c_state)
{
	c_state->reference_count--;
	if (c_state->reference_count == 0) {
		samdb_close(c_state->sam_ctx);
		talloc_destroy(c_state->mem_ctx);
	}
}

/*
  destroy an open connection. This closes the database connection
*/
static void samr_Connect_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct samr_connect_state *c_state = h->data;
	samr_Connect_close(c_state);
}

/* 
  samr_Connect 

  create a connection to the SAM database
*/
static NTSTATUS samr_Connect(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct samr_Connect *r)
{
	struct samr_connect_state *c_state;
	struct dcesrv_handle *handle;
	TALLOC_CTX *connect_mem_ctx;

	ZERO_STRUCTP(r->out.handle);

	connect_mem_ctx = talloc_init("samr_Connect");
	if (!connect_mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	c_state = talloc_p(connect_mem_ctx, struct samr_connect_state);
	if (!c_state) {
		return NT_STATUS_NO_MEMORY;
	}
	c_state->mem_ctx = connect_mem_ctx;

	/* make sure the sam database is accessible */
	c_state->sam_ctx = samdb_connect();
	if (c_state->sam_ctx == NULL) {
		talloc_destroy(c_state->mem_ctx);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_CONNECT);
	if (!handle) {
		talloc_destroy(c_state->mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = c_state;
	handle->destroy = samr_Connect_destroy;

	c_state->reference_count = 1;
	c_state->access_mask = r->in.access_mask;
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
	struct dcesrv_handle *h;
	struct samr_SdBuf *sd;

	r->out.sdbuf = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	sd = talloc_p(mem_ctx, struct samr_SdBuf);
	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sd->sd = samdb_default_security_descriptor(mem_ctx);

	r->out.sdbuf = sd;

	return NT_STATUS_OK;
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
	struct samr_connect_state *c_state;
	struct dcesrv_handle *h;
	struct dom_sid2 *sid;
	const char *sidstr;
		
	r->out.sid = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_CONNECT);

	c_state = h->data;

	if (r->in.domain->name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	sidstr = samdb_search_string(c_state->sam_ctx,
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
	struct samr_connect_state *c_state;
	struct dcesrv_handle *h;
	struct samr_SamArray *array;
	const char **domains;
	int count, i, start_i;

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_CONNECT);

	c_state = h->data;

	count = samdb_search_string_multiple(c_state->sam_ctx,
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
	r->out.num_entries = i;
	array->count = r->out.num_entries;

	return NT_STATUS_OK;
}


/*
  close an open domain context
*/
static void samr_Domain_close(struct dcesrv_connection *conn, 
			      struct samr_domain_state *d_state)
{
	d_state->reference_count--;
	if (d_state->reference_count == 0) {
		samr_Connect_close(d_state->connect_state);
		talloc_destroy(d_state->mem_ctx);
	}
}

/*
  destroy an open domain context
*/
static void samr_Domain_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct samr_domain_state *d_state = h->data;
	samr_Domain_close(conn, d_state);
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
	struct samr_domain_state *d_state;
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

	d_state = talloc_p(mem_ctx2, struct samr_domain_state);
	if (!d_state) {
		talloc_destroy(mem_ctx2);
		return NT_STATUS_NO_MEMORY;
	}

	d_state->reference_count = 1;
	d_state->connect_state = c_state;
	d_state->sam_ctx = c_state->sam_ctx;
	d_state->mem_ctx = mem_ctx2;
	d_state->domain_sid = talloc_strdup(mem_ctx2, sidstr);
	d_state->domain_name = talloc_strdup(mem_ctx2, domain_name);
	d_state->domain_dn = talloc_strdup(mem_ctx2, msgs[0]->dn);
	if (!d_state->domain_sid || !d_state->domain_name || !d_state->domain_dn) {
		talloc_destroy(mem_ctx2);
		return NT_STATUS_NO_MEMORY;		
	}
	d_state->access_mask = r->in.access_mask;

	h_domain = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_DOMAIN);
	if (!h_domain) {
		talloc_destroy(mem_ctx2);
		return NT_STATUS_NO_MEMORY;
	}

	c_state->reference_count++;
	h_domain->data = d_state;
	h_domain->destroy = samr_Domain_destroy;
	*r->out.domain_handle = h_domain->wire_handle;

	return NT_STATUS_OK;
}

/*
  return DomInfo2
*/
static NTSTATUS samr_info_DomInfo2(struct samr_domain_state *state, TALLOC_CTX *mem_ctx,
				   struct samr_DomInfo2 *info)
{
	const char * const attrs[] = { "comment", "name", NULL };
	int ret;
	struct ldb_message **res;

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, 
			   "dn=%s", state->domain_dn);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* where is this supposed to come from? is it settable? */
	info->force_logoff_time = 0x8000000000000000LL;

	info->comment.name = samdb_result_string(res[0], "comment", NULL);
	info->domain.name  = samdb_result_string(res[0], "name", NULL);

	info->primary.name = lp_netbios_name();
	info->sequence_num = 0;
	info->role = ROLE_DOMAIN_PDC;
	info->num_users = samdb_search_count(state->sam_ctx, mem_ctx, NULL, "(objectClass=user)");
	info->num_groups = samdb_search_count(state->sam_ctx, mem_ctx, NULL,
					      "(&(objectClass=group)(sAMAccountType=%u))",
					      ATYPE_GLOBAL_GROUP);
	info->num_aliases = samdb_search_count(state->sam_ctx, mem_ctx, NULL,
					       "(&(objectClass=group)(sAMAccountType=%u))",
					       ATYPE_LOCAL_GROUP);

	return NT_STATUS_OK;
}

/* 
  samr_QueryDomainInfo 
*/
static NTSTATUS samr_QueryDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct samr_QueryDomainInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	r->out.info = talloc_p(mem_ctx, union samr_DomainInfo);
	if (!r->out.info) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(r->out.info);

	switch (r->in.level) {
	case 2:
		return samr_info_DomInfo2(d_state, mem_ctx, &r->out.info->info2);
	}

	return NT_STATUS_INVALID_INFO_CLASS;
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
	struct samr_account_state *a_state = h->data;
	samr_Domain_close(conn, a_state->domain_state);
	talloc_destroy(a_state->mem_ctx);
}

/* 
  samr_CreateDomainGroup 
*/
static NTSTATUS samr_CreateDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct samr_CreateDomainGroup *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *name;
	struct ldb_message msg;
	uint32_t rid;
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
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL, 
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
		DEBUG(1,("Failed to load TemplateGroup from samdb\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* allocate a rid */
	status = samdb_allocate_next_id(d_state->sam_ctx, mem_ctx, 
					d_state->domain_dn, "nextRid", &rid);
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
				 d_state->domain_dn);
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

	a_state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->mem_ctx = mem_ctx2;
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = d_state;
	a_state->account_dn = talloc_steal(mem_ctx, mem_ctx2, msg.dn);
	a_state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	a_state->account_name = talloc_strdup(mem_ctx2, groupname);
	if (!a_state->account_name || !a_state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = a_state;
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
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *name;
	struct ldb_message msg;
	uint32_t rid;
	const char *account_name, *sidstr;
	time_t now = time(NULL);
	TALLOC_CTX *mem_ctx2;
	struct dcesrv_handle *u_handle;
	int ret;
	NTSTATUS status;
	const char *container, *additional_class=NULL;

	ZERO_STRUCTP(r->out.acct_handle);
	*r->out.access_granted = 0;
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	account_name = r->in.account_name->name;

	if (account_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* check if the user already exists */
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL, 
				   "sAMAccountName", 
				   "(&(sAMAccountName=%s)(objectclass=user))", account_name);
	if (name != NULL) {
		return NT_STATUS_USER_EXISTS;
	}

	ZERO_STRUCT(msg);

	/* This must be one of these values *only* */
	if (r->in.acct_flags == ACB_NORMAL) {
		/* pull in all the template attributes */
		ret = samdb_copy_template(d_state->sam_ctx, mem_ctx, &msg, 
					  "(&(name=TemplateUser)(objectclass=userTemplate))");
		if (ret != 0) {
			DEBUG(1,("Failed to load TemplateUser from samdb\n"));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		container = "Users";

	} else if (r->in.acct_flags == ACB_WSTRUST) {
		/* pull in all the template attributes */
		ret = samdb_copy_template(d_state->sam_ctx, mem_ctx, &msg, 
					  "(&(name=TemplateMemberServer)(objectclass=userTemplate))");
		if (ret != 0) {
			DEBUG(1,("Failed to load TemplateMemberServer from samdb\n"));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		container = "Computers";
		additional_class = "computer";

	} else if (r->in.acct_flags == ACB_SVRTRUST) {
		/* pull in all the template attributes */
		ret = samdb_copy_template(d_state->sam_ctx, mem_ctx, &msg, 
					  "(&(name=TemplateDomainController)(objectclass=userTemplate))");
		if (ret != 0) {
			DEBUG(1,("Failed to load TemplateDomainController from samdb\n"));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		container = "DomainControllers";
		additional_class = "computer";

	} else if (r->in.acct_flags == ACB_DOMTRUST) {
		/* pull in all the template attributes */
		ret = samdb_copy_template(d_state->sam_ctx, mem_ctx, &msg, 
					  "(&(name=TemplateTrustingDomain)(objectclass=userTemplate))");
		if (ret != 0) {
			DEBUG(1,("Failed to load TemplateTrustingDomain from samdb\n"));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		container = "ForeignDomains";  /* FIXME: Is this correct?*/
		additional_class = "computer";

	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* allocate a rid */
	status = samdb_allocate_next_id(d_state->sam_ctx, mem_ctx, 
					d_state->domain_dn, "nextRid", &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* and the users SID */
	sidstr = talloc_asprintf(mem_ctx, "%s-%u", d_state->domain_sid, rid);
	if (!sidstr) {
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the user */
	msg.dn = talloc_asprintf(mem_ctx, "CN=%s,CN=%s,%s", account_name, container, d_state->domain_dn);
	if (!msg.dn) {
		return NT_STATUS_NO_MEMORY;		
	}
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "name", account_name);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "cn", account_name);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "sAMAccountName", account_name);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "objectClass", "user");
	if (additional_class) {
		samdb_msg_add_string(d_state->sam_ctx, mem_ctx, &msg, "objectClass", additional_class);
	}
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
	mem_ctx2 = talloc_init("CreateUser(%s)", account_name);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	a_state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->mem_ctx = mem_ctx2;
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = d_state;
	a_state->account_dn = talloc_steal(mem_ctx, mem_ctx2, msg.dn);
	a_state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	a_state->account_name = talloc_strdup(mem_ctx2, account_name);
	if (!a_state->account_name || !a_state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = a_state;
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
	uint32_t access_granted;


	/* a simple wrapper around samr_CreateUser2 works nicely */
	r2.in.handle = r->in.handle;
	r2.in.account_name = r->in.account_name;
	r2.in.acct_flags = ACB_NORMAL;
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
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int count, i, first;
	struct samr_SamEntry *entries;
	const char * const attrs[3] = { "objectSid", "sAMAccountName", NULL };

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;
	
	/* search for all users in this domain. This could possibly be cached and 
	   resumed based on resume_key */
	count = samdb_search(d_state->sam_ctx, mem_ctx, d_state->domain_dn, &res, attrs, 
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
	struct samr_domain_state *d_state;
	int i;
	NTSTATUS status = NT_STATUS_OK;
	const char * const attrs[] = { "sAMAccountType", "objectSid", NULL };
	int count;

	ZERO_STRUCT(r->out.rids);
	ZERO_STRUCT(r->out.types);

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (r->in.num_names == 0) {
		return NT_STATUS_OK;
	}

	r->out.rids.ids = talloc_array_p(mem_ctx, uint32_t, r->in.num_names);
	r->out.types.ids = talloc_array_p(mem_ctx, uint32_t, r->in.num_names);
	if (!r->out.rids.ids || !r->out.types.ids) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.rids.count = r->in.num_names;
	r->out.types.count = r->in.num_names;

	for (i=0;i<r->in.num_names;i++) {
		struct ldb_message **res;
		struct dom_sid2 *sid;
		const char *sidstr;
		uint32_t atype, rtype;

		r->out.rids.ids[i] = 0;
		r->out.types.ids[i] = SID_NAME_UNKNOWN;

		count = samdb_search(d_state->sam_ctx, mem_ctx, d_state->domain_dn, &res, attrs, 
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

		rtype = samdb_atype_map(atype);
		
		if (rtype == SID_NAME_UNKNOWN) {
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
	struct samr_account_state *a_state;
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
			   mem_ctx, d_state->domain_dn, &msgs, attrs,
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

	a_state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->mem_ctx = mem_ctx2;
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = d_state;
	a_state->account_dn = talloc_steal(mem_ctx, mem_ctx2, msgs[0]->dn);
	a_state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	a_state->account_name = talloc_strdup(mem_ctx2, groupname);
	if (!a_state->account_name || !a_state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = a_state;
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
	r->out.info->field = samdb_result_allow_password_change(a_state->sam_ctx, mem_ctx, \
							   a_state->domain_state->domain_dn, msg, attr);
#define QUERY_FPASSC(msg, field, attr) \
	r->out.info->field = samdb_result_force_password_change(a_state->sam_ctx, mem_ctx, \
							   a_state->domain_state->domain_dn, msg, attr);
#define QUERY_LHOURS(msg, field, attr) \
	r->out.info->field = samdb_result_logon_hours(mem_ctx, msg, attr);
#define QUERY_AFLAGS(msg, field, attr) \
	r->out.info->field = samdb_result_acct_flags(msg, attr);


/* these are used to make the Set[User|Group]Info code easier to follow */

#define SET_STRING(mod, field, attr) do { \
	if (r->in.info->field == NULL) return NT_STATUS_INVALID_PARAMETER; \
	if (samdb_msg_add_string(a_state->sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_UINT(mod, field, attr) do { \
	if (samdb_msg_add_uint(a_state->sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_AFLAGS(msg, field, attr) do { \
	if (samdb_msg_add_acct_flags(a_state->sam_ctx, mem_ctx, msg, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_LHOURS(msg, field, attr) do { \
	if (samdb_msg_add_logon_hours(a_state->sam_ctx, mem_ctx, msg, attr, r->in.info->field) != 0) { \
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
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	const char * const attrs[4] = { "sAMAccountName", "description",
					"numMembers", NULL };
	int ret;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	/* pull all the group attributes */
	ret = samdb_search(a_state->sam_ctx, mem_ctx, NULL, &res, attrs,
			   "dn=%s", a_state->account_dn);
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
	struct samr_account_state *a_state;
	struct ldb_message mod, *msg = &mod;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, a_state->account_dn);
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

	/* modify the samdb record */
	ret = samdb_replace(a_state->sam_ctx, mem_ctx, &mod);
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
	struct samr_account_state *a_state;
	int ret;

        *r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	ret = samdb_delete(a_state->sam_ctx, mem_ctx, a_state->account_dn);
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
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *account_name, *sidstr;
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
			   mem_ctx, d_state->domain_dn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=user))", 
			   sidstr);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
	if (ret != 1) {
		DEBUG(1,("Found %d records matching sid %s\n", ret, sidstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	account_name = samdb_result_string(msgs[0], "sAMAccountName", NULL);
	if (account_name == NULL) {
		DEBUG(1,("sAMAccountName field missing for sid %s\n", sidstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* create user state and new policy handle */
	mem_ctx2 = talloc_init("OpenUser(%u)", r->in.rid);
	if (!mem_ctx2) {
		return NT_STATUS_NO_MEMORY;
	}

	a_state = talloc_p(mem_ctx2, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->mem_ctx = mem_ctx2;
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = d_state;
	a_state->account_dn = talloc_steal(mem_ctx, mem_ctx2, msgs[0]->dn);
	a_state->account_sid = talloc_strdup(mem_ctx2, sidstr);
	a_state->account_name = talloc_strdup(mem_ctx2, account_name);
	if (!a_state->account_name || !a_state->account_sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_new(dce_call->conn, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = a_state;
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
	struct samr_account_state *a_state;
	int ret;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	a_state = h->data;

	ret = samdb_delete(a_state->sam_ctx, mem_ctx, a_state->account_dn);
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
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	int ret;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	a_state = h->data;

	/* pull all the user attributes */
	ret = samdb_search(a_state->sam_ctx, mem_ctx, NULL, &res, NULL,
			   "dn=%s", a_state->account_dn);
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
		QUERY_STRING(msg, info1.account_name.name,"sAMAccountName");
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
		QUERY_STRING(msg, info3.account_name.name,   "sAMAccountName");
		QUERY_STRING(msg, info3.full_name.name,      "displayName");
		QUERY_RID   (msg, info3.rid,                 "objectSid");
		QUERY_UINT  (msg, info3.primary_gid,         "primaryGroupID");
		QUERY_STRING(msg, info3.home_directory.name, "homeDirectory");
		QUERY_STRING(msg, info3.home_drive.name,     "homeDrive");
		QUERY_STRING(msg, info3.logon_script.name,   "scriptPath");
		QUERY_STRING(msg, info3.profile_path.name,   "profilePath");
		QUERY_STRING(msg, info3.workstations.name,   "userWorkstations");
		QUERY_NTTIME(msg, info3.last_logon,          "lastLogon");
		QUERY_NTTIME(msg, info3.last_logoff,         "lastLogoff");
		QUERY_NTTIME(msg, info3.last_password_change,"pwdLastSet");
		QUERY_APASSC(msg, info3.allow_password_change,"pwdLastSet");
		QUERY_FPASSC(msg, info3.force_password_change,"pwdLastSet");
		QUERY_LHOURS(msg, info3.logon_hours,         "logonHours");
		QUERY_UINT  (msg, info3.bad_password_count,  "badPwdCount");
		QUERY_UINT  (msg, info3.num_logons,          "logonCount");
		QUERY_AFLAGS(msg, info3.acct_flags,          "userAccountControl");
		break;

	case 4:
		QUERY_LHOURS(msg, info4.logon_hours,         "logonHours");
		break;

	case 5:
		QUERY_STRING(msg, info5.account_name.name,   "sAMAccountName");
		QUERY_STRING(msg, info5.full_name.name,      "displayName");
		QUERY_RID   (msg, info5.rid,                 "objectSid");
		QUERY_UINT  (msg, info5.primary_gid,         "primaryGroupID");
		QUERY_STRING(msg, info5.home_directory.name, "homeDirectory");
		QUERY_STRING(msg, info5.home_drive.name,     "homeDrive");
		QUERY_STRING(msg, info5.logon_script.name,   "scriptPath");
		QUERY_STRING(msg, info5.profile_path.name,   "profilePath");
		QUERY_STRING(msg, info5.description.name,    "description");
		QUERY_STRING(msg, info5.workstations.name,   "userWorkstations");
		QUERY_NTTIME(msg, info5.last_logon,          "lastLogon");
		QUERY_NTTIME(msg, info5.last_logoff,         "lastLogoff");
		QUERY_LHOURS(msg, info5.logon_hours,         "logonHours");
		QUERY_UINT  (msg, info5.bad_password_count,  "badPwdCount");
		QUERY_UINT  (msg, info5.num_logons,          "logonCount");
		QUERY_NTTIME(msg, info5.last_password_change,"pwdLastSet");
		QUERY_NTTIME(msg, info5.acct_expiry,         "accountExpires");
		QUERY_AFLAGS(msg, info5.acct_flags,          "userAccountControl");
		break;

	case 6:
		QUERY_STRING(msg, info6.account_name.name,   "sAMAccountName");
		QUERY_STRING(msg, info6.full_name.name,      "displayName");
		break;

	case 7:
		QUERY_STRING(msg, info7.account_name.name,   "sAMAccountName");
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
		QUERY_NTTIME(msg, info21.last_password_change,     "pwdLastSet");
		QUERY_NTTIME(msg, info21.acct_expiry,         "accountExpires");
		QUERY_APASSC(msg, info21.allow_password_change,    "pwdLastSet");
		QUERY_FPASSC(msg, info21.force_password_change,    "pwdLastSet");
		QUERY_STRING(msg, info21.account_name.name,       "sAMAccountName");
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
		QUERY_UINT  (msg, info21.bad_password_count,  "badPwdCount");
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
  samr_SetUserInfo 
*/
static NTSTATUS samr_SetUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message mod, *msg = &mod;
	int ret;
	NTSTATUS status = NT_STATUS_OK;

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	a_state = h->data;

	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, a_state->account_dn);
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
#undef IFSET
		break;

	case 23:
#define IFSET(bit) if (bit & r->in.info->info23.info.fields_present)
		IFSET(SAMR_FIELD_NAME)         
			SET_STRING(msg, info23.info.full_name.name,    "displayName");
		IFSET(SAMR_FIELD_DESCRIPTION)  
			SET_STRING(msg, info23.info.description.name,  "description");
		IFSET(SAMR_FIELD_COMMENT)      
			SET_STRING(msg, info23.info.comment.name,      "comment");
		IFSET(SAMR_FIELD_LOGON_SCRIPT) 
			SET_STRING(msg, info23.info.logon_script.name, "scriptPath");
		IFSET(SAMR_FIELD_PROFILE)      
			SET_STRING(msg, info23.info.profile.name,      "profilePath");
		IFSET(SAMR_FIELD_WORKSTATION)  
			SET_STRING(msg, info23.info.workstations.name, "userWorkstations");
		IFSET(SAMR_FIELD_LOGON_HOURS)  
			SET_LHOURS(msg, info23.info.logon_hours,       "logonHours");
		IFSET(SAMR_FIELD_CALLBACK)     
			SET_STRING(msg, info23.info.callback.name,     "userParameters");
		IFSET(SAMR_FIELD_COUNTRY_CODE) 
			SET_UINT  (msg, info23.info.country_code,      "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)    
			SET_UINT  (msg, info23.info.code_page,         "codePage");
		IFSET(SAMR_FIELD_PASSWORD) {
			status = samr_set_password(dce_call,
						   a_state->sam_ctx,
						   a_state->account_dn,
						   a_state->domain_state->domain_dn,
						   mem_ctx, msg, 
						   &r->in.info->info23.password);
		}
#undef IFSET
		break;

		/* the set password levels are handled separately */
	case 24:
		status = samr_set_password(dce_call,
					   a_state->sam_ctx,
					   a_state->account_dn,
					   a_state->domain_state->domain_dn,
					   mem_ctx, msg, 
					   &r->in.info->info24.password);
		break;

	case 25:
#define IFSET(bit) if (bit & r->in.info->info25.info.fields_present)
		IFSET(SAMR_FIELD_NAME)         
			SET_STRING(msg, info25.info.full_name.name,    "displayName");
		IFSET(SAMR_FIELD_DESCRIPTION)  
			SET_STRING(msg, info25.info.description.name,  "description");
		IFSET(SAMR_FIELD_COMMENT)      
			SET_STRING(msg, info25.info.comment.name,      "comment");
		IFSET(SAMR_FIELD_LOGON_SCRIPT) 
			SET_STRING(msg, info25.info.logon_script.name, "scriptPath");
		IFSET(SAMR_FIELD_PROFILE)      
			SET_STRING(msg, info25.info.profile.name,      "profilePath");
		IFSET(SAMR_FIELD_WORKSTATION)  
			SET_STRING(msg, info25.info.workstations.name, "userWorkstations");
		IFSET(SAMR_FIELD_LOGON_HOURS)  
			SET_LHOURS(msg, info25.info.logon_hours,       "logonHours");
		IFSET(SAMR_FIELD_CALLBACK)     
			SET_STRING(msg, info25.info.callback.name,     "userParameters");
		IFSET(SAMR_FIELD_COUNTRY_CODE) 
			SET_UINT  (msg, info25.info.country_code,      "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)    
			SET_UINT  (msg, info25.info.code_page,         "codePage");
		IFSET(SAMR_FIELD_PASSWORD) {
			status = samr_set_password_ex(dce_call,
						      a_state->sam_ctx,
						      a_state->account_dn,
						      a_state->domain_state->domain_dn,
						      mem_ctx, msg, 
						      &r->in.info->info25.password);
		}
#undef IFSET
		break;

		/* the set password levels are handled separately */
	case 26:
		status = samr_set_password_ex(dce_call,
					      a_state->sam_ctx,
					      a_state->account_dn,
					      a_state->domain_state->domain_dn,
					      mem_ctx, msg, 
					      &r->in.info->info26.password);
		break;
		

	default:
		/* many info classes are not valid for SetUserInfo */
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* modify the samdb record */
	ret = samdb_replace(a_state->sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
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
	struct samr_account_state *a_state;

	ZERO_STRUCT(r->out.info);

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	a_state = h->data;

	r->out.info.min_password_len = samdb_search_uint(a_state->sam_ctx, mem_ctx, 0, NULL, "minPwdLength", 
						    "dn=%s", a_state->domain_state->domain_dn);
	r->out.info.password_properties = samdb_search_uint(a_state->sam_ctx, mem_ctx, 0, NULL, "pwdProperties", 
							    "dn=%s", a_state->account_dn);
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
  samr_GetDomPwInfo 

  this fetches the default password properties for a domain

  note that w2k3 completely ignores the domain name in this call, and 
  always returns the information for the servers primary domain
*/
static NTSTATUS samr_GetDomPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_GetDomPwInfo *r)
{
	struct ldb_message **msgs;
	int ret;
	const char * const attrs[] = {"minPwdLength", "pwdProperties", NULL };
	void *sam_ctx;

	ZERO_STRUCT(r->out.info);

	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = samdb_search(sam_ctx, 
			   mem_ctx, NULL, &msgs, attrs, 
			   "(&(name=%s)(objectclass=domain))",
			   lp_workgroup());
	if (ret <= 0) {
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	if (ret > 1) {
		samdb_search_free(sam_ctx, mem_ctx, msgs);
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	r->out.info.min_password_len         = samdb_result_uint(msgs[0], "minPwdLength", 0);
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
