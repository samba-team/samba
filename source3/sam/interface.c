/*
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Jelmer Vernooij			2002
   Copyright (C) Stefan (metze) Metzmacher		2002
   Copyright (C) Kai Krüger				2002

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

/** List of various built-in sam modules */

const struct sam_init_function_entry builtin_sam_init_functions[] = {
	{ "plugin", sam_init_plugin },
	{ NULL, NULL}
};

/* FIXME: wrapper functions : context_* */

/******************************************************************
  context_sam_* functions are used to link the external SAM interface
  with the internal backends. These functions lookup the appropriate
  backends for the domain and pass on to the function in sam_methods
  in the selected backend
 *******************************************************************/

NTSTATUS sam_get_methods_by_sid(const SAM_CONTEXT *context, SAM_METHODS **sam_method, const DOM_SID *domainsid)
{
	SAM_METHODS	*tmp_methods;

	DEBUG(5,("sam_get_methods_by_sid: %d\n", __LINE__));

	/* invalid sam_context specified */
	SAM_ASSERT(context && context->methods)

	tmp_methods = context->methods;

	while (tmp_methods)
	{
		if (sid_equal(domainsid, &(tmp_methods->domain->private.sid)))
		{
			(*sam_method) = tmp_methods;
			return NT_STATUS_OK;
		}
		tmp_methods = tmp_methods->next;
	}

	DEBUG(3,("sam_get_methods_by_sid: There is no backend specified for domain %s\n", sid_string_static(domainsid)));

	return NT_STATUS_NO_SUCH_DOMAIN;
}

NTSTATUS sam_get_methods_by_name(const SAM_CONTEXT *context, SAM_METHODS **sam_method, const char *domainname)
{
	SAM_METHODS	*tmp_methods;

	DEBUG(5,("sam_get_methods_by_name: %d\n", __LINE__));

	/* invalid sam_context specified */
	SAM_ASSERT(context && context->methods)

	tmp_methods = context->methods;

	while (tmp_methods)
	{
		if (strcmp(domainname, tmp_methods->domain->private.name))
		{
			(*sam_method) = tmp_methods;
			return NT_STATUS_OK;
		}
		tmp_methods = tmp_methods->next;
	}

	DEBUG(3,("sam_get_methods_by_sid: There is no backend specified for domain %s\n", domainname));

	return NT_STATUS_NO_SUCH_DOMAIN;
}

NTSTATUS context_sam_get_sec_desc(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS        nt_status;

	DEBUG(5,("context_sam_get_sec_desc: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, sid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_sec_desc) {
		DEBUG(3, ("context_sam_get_sec_desc: sam_methods of the domain did not specify sam_get_sec_desc\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_sec_desc(tmp_methods, access_token, sid, sd))) {
		DEBUG(4,("context_sam_get_sec_desc for %s in backend %s failed\n", sid_string_static(sid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_set_sec_desc(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_set_sec_desc: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, sid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_set_sec_desc) {
		DEBUG(3, ("context_sam_set_sec_desc: sam_methods of the domain did not specify sam_set_sec_desc\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_set_sec_desc(tmp_methods, access_token, sid, sd))) {
		DEBUG(4,("context_sam_set_sec_desc for %s in backend %s failed\n", sid_string_static(sid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}


NTSTATUS context_sam_lookup_name(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const char *domain, const char *name, DOM_SID **sid, uint32 *type)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_lookup_name: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_name(context, &tmp_methods, domain))) {
		DEBUG(4,("sam_get_methods_by_name failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_lookup_name) {
		DEBUG(3, ("context_sam_lookup_name: sam_methods of the domain did not specify sam_lookup_name\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_lookup_name(tmp_methods, access_token, name, sid, type))) {
		DEBUG(4,("context_sam_lookup_name for %s\\%s in backend %s failed\n",
				 tmp_methods->domain->private.name, name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_lookup_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *sid, char **name, uint32 *type)
{
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;
	DOM_SID		domainsid;

	DEBUG(5,("context_sam_lookup_sid: %d\n", __LINE__));

	sid_copy(&domainsid, sid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_lookup_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_lookup_sid) {
		DEBUG(3, ("context_sam_lookup_sid: sam_methods of the domain did not specify sam_lookup_sid\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_lookup_sid(tmp_methods, access_token, sid, name, type))) {
		DEBUG(4,("context_sam_lookup_name for %s in backend %s failed\n",
				 sid_string_static(sid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}


NTSTATUS context_sam_update_domain(const SAM_CONTEXT *context, const SAM_DOMAIN_HANDLE *domain)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS context_sam_enum_domains(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, int32 *domain_count, DOM_SID **domains, char ***domain_names)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	SEC_DESC	*sd;
	size_t		sd_size;
	uint32		acc_granted;
	int		i = 0;

	DEBUG(5,("context_sam_enum_domains: %d\n", __LINE__));

	/* invalid sam_context specified */
	SAM_ASSERT(context && context->methods)

	if (!NT_STATUS_IS_OK(nt_status = samr_make_sam_obj_sd(context->mem_ctx, &sd, &sd_size))) {
		DEBUG(4,("samr_make_sam_obj_sd failed\n"));
		return nt_status;
	}

	if (!se_access_check(sd, access_token, SAMR_ACCESS_ENUM_DOMAINS, &acc_granted, &nt_status)) {
		DEBUG(3,("context_sam_enum_domains: ACCESS DENIED\n"));
			return nt_status;
	}

	tmp_methods= context->methods;

	while (tmp_methods)
	{
		(*domain_count)++;
		tmp_methods= tmp_methods->next;
	}

	DEBUG(6,("context_sam_enum_domains: enumerating %d domains\n", (*domain_count)));

	tmp_methods = context->methods;

	if (((*domains) = malloc( sizeof(DOM_SID) * (*domain_count))) == NULL) {
		DEBUG(0,("context_sam_enum_domains: Out of memory allocating domain list\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (((*domain_names) = malloc( sizeof(char*) * (*domain_count))) == NULL) {
		DEBUG(0,("context_sam_enum_domains: Out of memory allocating domain list\n"));
		SAFE_FREE((*domains));
		return NT_STATUS_NO_MEMORY;
	}

	while (tmp_methods)
	{

		DEBUGADD(7,("    [%d] %s: %s\n", i, tmp_methods->domain->private.name, sid_string_static(&tmp_methods->domain->private.sid)));
		sid_copy(domains[i],&tmp_methods->domain->private.sid);
		if(asprintf(&(*domain_names[i]),"%s",tmp_methods->domain->private.name) < 0) {
			DEBUG(0,("context_sam_enum_domains: asprintf failed"));
			SAFE_FREE((*domains));
			SAFE_FREE((*domain_names));
			return NT_STATUS_NO_MEMORY;
		}

		i++;
		tmp_methods= tmp_methods->next;

	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_lookup_domain(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const char *domain, DOM_SID **domainsid)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	SEC_DESC	*sd;
	size_t		sd_size;
	uint32		acc_granted;

	DEBUG(5,("context_sam_lookup_domain: %d\n", __LINE__));

	/* invalid sam_context specified */
	SAM_ASSERT(context && context->methods)

	if (!NT_STATUS_IS_OK(nt_status = samr_make_sam_obj_sd(context->mem_ctx, &sd, &sd_size))) {
		DEBUG(4,("samr_make_sam_obj_sd failed\n"));
		return nt_status;
	}

	if (!se_access_check(sd, access_token, SAMR_ACCESS_OPEN_DOMAIN, &acc_granted, &nt_status)) {
		DEBUG(3,("context_sam_lookup_domain: ACCESS DENIED\n"));
			return nt_status;
	}

	tmp_methods= context->methods;

	while (tmp_methods)
	{
		if (strcmp(domain, tmp_methods->domain->private.name) == 0) {
			sid_copy((*domainsid), &tmp_methods->domain->private.sid);
			return NT_STATUS_OK;
		}
		tmp_methods= tmp_methods->next;
	}

	return NT_STATUS_NO_SUCH_DOMAIN;
}


NTSTATUS context_sam_get_domain_by_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, SAM_DOMAIN_HANDLE **domain)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_get_domain_by_sid: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_domain_handle) {
		DEBUG(3, ("context_sam_get_domain_by_sid: sam_methods of the domain did not specify sam_get_domain_handle\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_domain_handle(tmp_methods, access_token, access_desired, domain))) {
		DEBUG(4,("context_sam_get_domain_by_sid for %s in backend %s failed\n",
				 sid_string_static(domainsid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_create_account(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, const char *account_name, uint16 acct_ctrl, SAM_ACCOUNT_HANDLE **account)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_create_account: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_create_account) {
		DEBUG(3, ("context_sam_create_account: sam_methods of the domain did not specify sam_create_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_create_account(tmp_methods, access_token, access_desired, account_name, acct_ctrl, account))) {
		DEBUG(4,("context_sam_create_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_add_account(const SAM_CONTEXT *context, const SAM_ACCOUNT_HANDLE *account)
{
	DOM_SID		domainsid;
	const DOM_SID		*accountsid;
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_account_sid(account, &accountsid))) {
		DEBUG(0,("Can't get account SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, accountsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_account_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_add_account) {
		DEBUG(3, ("context_sam_add_account: sam_methods of the domain did not specify sam_add_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_add_account(tmp_methods, account))){
		DEBUG(4,("context_sam_add_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_update_account(const SAM_CONTEXT *context, const SAM_ACCOUNT_HANDLE *account)
{
	DOM_SID		domainsid;
	SAM_METHODS	*tmp_methods;
	const DOM_SID		*accountsid;
	uint32		rid;
	NTSTATUS	nt_status;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_account_sid(account, &accountsid))) {
		DEBUG(0,("Can't get account SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, accountsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_account_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}
	
	if (!tmp_methods->sam_update_account) {
		DEBUG(3, ("context_sam_update_account: sam_methods of the domain did not specify sam_update_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_update_account(tmp_methods, account))){
		DEBUG(4,("context_sam_update_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_delete_account(const SAM_CONTEXT *context, const SAM_ACCOUNT_HANDLE *account)
{
	DOM_SID		domainsid;
	SAM_METHODS	*tmp_methods;
	const DOM_SID	*accountsid;
	uint32		rid;
	NTSTATUS	nt_status;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_account_sid(account, &accountsid))) {
		DEBUG(0,("Can't get account SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, accountsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_account_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_delete_account) {
		DEBUG(3, ("context_sam_delete_account: sam_methods of the domain did not specify sam_delete_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_delete_account(tmp_methods, account))){
		DEBUG(4,("context_sam_delete_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_enum_accounts(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *domainsid, uint16 acct_ctrl, int32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_enum_accounts: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_enum_accounts) {
		DEBUG(3, ("context_sam_enum_accounts: sam_methods of the domain did not specify sam_enum_accounts\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_enum_accounts(tmp_methods, access_token, acct_ctrl, account_count, accounts))) {
		DEBUG(4,("context_sam_enum_accounts for domain %s in backend %s failed\n",
				 tmp_methods->domain->private.name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}


NTSTATUS context_sam_get_account_by_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account)
{
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	DOM_SID		domainsid;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_get_account_by_sid: %d\n", __LINE__));

	sid_copy(&domainsid, accountsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_account_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}


	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_account_by_sid) {
		DEBUG(3, ("context_sam_get_account_by_sid: sam_methods of the domain did not specify sam_get_account_by_sid\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_account_by_sid(tmp_methods, access_token, access_desired, accountsid, account))) {
		DEBUG(4,("context_sam_get_account_by_sid for %s in backend %s failed\n",
				 sid_string_static(accountsid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_get_account_by_name(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *domain, const char *name, SAM_ACCOUNT_HANDLE **account)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_get_account_by_name: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_name(context, &tmp_methods, domain))) {
		DEBUG(4,("sam_get_methods_by_name failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_account_by_name) {
		DEBUG(3, ("context_sam_get_account_by_name: sam_methods of the domain did not specify sam_get_account_by_name\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_account_by_name(tmp_methods, access_token, access_desired, name, account))) {
		DEBUG(4,("context_sam_get_account_by_name for %s\\%s in backend %s failed\n",
				 domain, name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_create_group(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, const char *group_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_create_group: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_create_group) {
		DEBUG(3, ("context_sam_create_group: sam_methods of the domain did not specify sam_create_group\n"));
		return NT_STATUS_UNSUCCESSFUL; 
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_create_group(tmp_methods, access_token, access_desired, group_name, group_ctrl, group))) {
		DEBUG(4,("context_sam_create_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_add_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group)
{
	DOM_SID		domainsid;
	const DOM_SID		*groupsid;
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_group_sid(group, &groupsid))) {
		DEBUG(0,("Can't get group SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, groupsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_group_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_add_group) {
		DEBUG(3, ("context_sam_add_group: sam_methods of the domain did not specify sam_add_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_add_group(tmp_methods, group))){
		DEBUG(4,("context_sam_add_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_update_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group)
{
	DOM_SID		domainsid;
	const DOM_SID		*groupsid;
	struct sam_methods *tmp_methods;
	uint32		rid;
	NTSTATUS nt_status;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_group_sid(group, &groupsid))) {
		DEBUG(0,("Can't get group SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, groupsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_group_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_update_group) {
		DEBUG(3, ("context_sam_update_group: sam_methods of the domain did not specify sam_update_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_update_group(tmp_methods, group))){
		DEBUG(4,("context_sam_update_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_delete_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group)
{
	DOM_SID		domainsid;
	SAM_METHODS 	*tmp_methods;
	const DOM_SID	*groupsid;
	uint32		rid;
	NTSTATUS	nt_status;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_group_sid(group, &groupsid))) {
		DEBUG(0,("Can't get group SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, groupsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_group_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_delete_group) {
		DEBUG(3, ("context_sam_delete_group: sam_methods of the domain did not specify sam_delete_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_delete_group(tmp_methods, group))){
		DEBUG(4,("context_sam_delete_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_enum_groups(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *domainsid, uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_enum_groups: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_enum_accounts) {
		DEBUG(3, ("context_sam_enum_groups: sam_methods of the domain did not specify sam_enum_groups\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_enum_groups(tmp_methods, access_token, group_ctrl, groups_count, groups))) {
		DEBUG(4,("context_sam_enum_groups for domain %s in backend %s failed\n",
				 tmp_methods->domain->private.name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_get_group_by_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group)
{
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;
	DOM_SID		domainsid;

	DEBUG(5,("context_sam_get_group_by_sid: %d\n", __LINE__));

	sid_copy(&domainsid, groupsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("context_sam_get_group_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}


	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_group_by_sid) {
		DEBUG(3, ("context_sam_get_group_by_sid: sam_methods of the domain did not specify sam_get_group_by_sid\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_group_by_sid(tmp_methods, access_token, access_desired, groupsid, group))) {
		DEBUG(4,("context_sam_get_group_by_sid for %s in backend %s failed\n",
				 sid_string_static(groupsid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_get_group_by_name(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *domain, const char *name, SAM_GROUP_HANDLE **group)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("context_sam_get_group_by_name: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_name(context, &tmp_methods, domain))) {
		DEBUG(4,("sam_get_methods_by_name failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_group_by_name) {
		DEBUG(3, ("context_sam_get_group_by_name: sam_methods of the domain did not specify sam_get_group_by_name\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_group_by_name(tmp_methods, access_token, access_desired, name, group))) {
		DEBUG(4,("context_sam_get_group_by_name for %s\\%s in backend %s failed\n",
				 domain, name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS context_sam_add_member_to_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}
NTSTATUS context_sam_delete_member_from_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS context_sam_enum_groupmembers(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS context_sam_get_groups_of_sid(const SAM_CONTEXT *context, const DOM_SID **sids, uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/******************************************************************
  Free and cleanup a sam context, any associated data and anything
  that the attached modules might have associated.
 *******************************************************************/

void free_sam_context(SAM_CONTEXT **context)
{
	SAM_METHODS *sam_selected = (*context)->methods;

	while (sam_selected){
		if (sam_selected->free_private_data) {
			sam_selected->free_private_data(&(sam_selected->private_data));
		}
		sam_selected = sam_selected->next;
	}

	talloc_destroy((*context)->mem_ctx);
	*context = NULL;
}

/******************************************************************
  Make a sam_methods from scratch
 *******************************************************************/

NTSTATUS make_sam_context_list(SAM_CONTEXT **context, char **selected)
{
	int i = 0;
	SAM_METHODS *curmethods, *tmpmethods;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;

	if (!NT_STATUS_IS_OK(nt_status = make_sam_context(context))) {
		return nt_status;
	}                                                                           
	while (selected[i]){
		/* Try to initialise sam */
		DEBUG(5,("Trying to load: %s\n", selected[i]));
		if (!NT_STATUS_IS_OK(nt_status = make_sam_methods_name(&curmethods, *context, selected[i]))) {
			DEBUG(1, ("Loading %s failed!\n", selected[i]));
			free_sam_context(context);
			return nt_status;
		}
		curmethods->parent = *context;
		DLIST_ADD_END((*context)->methods, curmethods, tmpmethods);
		i++;
																	    }
    return NT_STATUS_OK;
}

NTSTATUS make_sam_methods_name(SAM_METHODS **methods, SAM_CONTEXT *context, const char *selected)
{
	char *module_name = smb_xstrdup(selected);
	char *module_location = NULL, *p;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	int i;

	p = strchr(module_name, ':');

	if (p) {
		*p = 0;
		module_location = p+1;
		trim_string(module_location, " ", " ");
	}

	trim_string(module_name, " ", " ");

	DEBUG(5,("Attempting to find an sam backend to match %s (%s)\n", selected, module_name));
	for (i = 0; builtin_sam_init_functions[i].name; i++)
	{
		if (strequal(builtin_sam_init_functions[i].name, module_name))
		{
			DEBUG(5,("Found sam backend %s (at pos %d)\n", module_name, i));
			nt_status = builtin_sam_init_functions[i].init(context, methods, module_location);
			if (NT_STATUS_IS_OK(nt_status)) {
				DEBUG(5,("sam backend %s has a valid init\n", selected));
			} else {
				DEBUG(0,("sam backend %s did not correctly init (error was %s)\n", selected, nt_errstr(nt_status)));
			}
			SAFE_FREE(module_name);
			return nt_status;
			break; /* unreached */
		}
	}

	/* No such backend found */
	SAFE_FREE(module_name);
	return NT_STATUS_INVALID_PARAMETER;
}

/******************************************************************
  Make a sam_context from scratch.
 *******************************************************************/

NTSTATUS make_sam_context(SAM_CONTEXT **context) 
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init_named("sam_context internal allocation context");

	if (!mem_ctx) {
		DEBUG(0, ("make_sam_context: talloc init failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}		

	*context = talloc(mem_ctx, sizeof(**context));
	if (!*context) {
		DEBUG(0, ("make_sam_context: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*context);

	(*context)->mem_ctx = mem_ctx;

	/* FIXME */

	(*context)->free_fn = free_sam_context;

	return NT_STATUS_OK;
}


/******************************************************************
  Return an already initialised sam_context, to facilitate backward 
  compatibility (see functions below).
 *******************************************************************/

struct sam_context *sam_get_static_context(BOOL reload) 
{
	static SAM_CONTEXT *sam_context = NULL;

	if ((sam_context) && (reload)) {
		sam_context->free_fn(&sam_context);
		if (!NT_STATUS_IS_OK(make_sam_context_list(&sam_context, lp_sam_backend()))) {
			return NULL;
		}
	}

	if (!sam_context) {
		if (!NT_STATUS_IS_OK(make_sam_context_list(&sam_context, lp_sam_backend()))) {
			return NULL;
		}
	}

	return sam_context;
}

/***************************************************************
  Initialize the static context (at smbd startup etc). 

  If uninitialised, context will auto-init on first use.
 ***************************************************************/

BOOL initialize_sam(BOOL reload)
{	
	return (sam_get_static_context(reload) != NULL);
}


NTSTATUS make_sam_methods(TALLOC_CTX *mem_ctx, SAM_METHODS **methods) 
{
	*methods = talloc(mem_ctx, sizeof(SAM_METHODS));

	if (!*methods) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*methods);

	return NT_STATUS_OK;
}
