/* 
   Unix SMB/CIFS implementation.
   SAM interface API.

   Copyright (C) Stefan (metze) Metzmacher		2002
      
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

/* these functions should be used by the rest of SAMBA --metze */

/* General API */

NTSTATUS sam_get_sec_desc(const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_sec_desc(sam_context, access_token, sid, sd);
}

NTSTATUS sam_set_sec_desc(const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_set_sec_desc(sam_context, access_token, sid, sd);
}

NTSTATUS sam_lookup_sid(const NT_USER_TOKEN *access_token, const DOM_SID *sid, char **name, uint32 *type)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_lookup_sid(sam_context, access_token, sid, name, type);
}

NTSTATUS sam_lookup_name(const NT_USER_TOKEN *access_token, const char *domain, const char *name, DOM_SID **sid,  uint32 *type)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_lookup_name(sam_context, access_token, domain, name, sid, type);
}

/* Domain API */

NTSTATUS sam_update_domain(const SAM_DOMAIN_HANDLE *domain)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_update_domain(sam_context, domain);
}

NTSTATUS sam_enum_domains(const NT_USER_TOKEN *access_token, int32 *domain_count, DOM_SID **domains, char **domain_names)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_enum_domains(sam_context, access_token, domain_count, domains, domain_names);
}

NTSTATUS sam_lookup_domain(const NT_USER_TOKEN * access_token, const char *domain, DOM_SID **domainsid)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_lookup_domain(sam_context, access_token, domain, domainsid);
}

NTSTATUS sam_get_domain_by_sid(const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, SAM_DOMAIN_HANDLE **domain)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_domain_by_sid(sam_context, access_token, access_desired, domainsid, domain);
}

/* Account API */

NTSTATUS sam_create_account(const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, const char *account_name, uint16 acct_ctrl, SAM_ACCOUNT_HANDLE **account)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_create_account(sam_context, access_token, access_desired, domainsid, account_name, acct_ctrl, account);
}

NTSTATUS sam_add_account(const DOM_SID *domainsid, const SAM_ACCOUNT_HANDLE *account)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_add_account(sam_context, domainsid, account);
}

NTSTATUS sam_update_account(const SAM_ACCOUNT_HANDLE *account)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_update_account(sam_context, account);
}

NTSTATUS sam_delete_account(const SAM_ACCOUNT_HANDLE *account)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_delete_account(sam_context, account);
}

NTSTATUS sam_enum_accounts(const NT_USER_TOKEN *access_token, const DOM_SID *domain, uint16 acct_ctrl, uint32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_enum_accounts(sam_context, access_token, domain, acct_ctrl, account_count, accounts);
}

NTSTATUS sam_get_account_by_sid(const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_account_by_sid(sam_context, access_token, access_desired, accountsid, account);
}

NTSTATUS sam_get_account_by_name(const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *domain, const char *name, SAM_ACCOUNT_HANDLE **account)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_account_by_name(sam_context, access_token, access_desired, domain, name, account);
}

/* Group API */

NTSTATUS sam_create_group(const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, const char *group_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_create_group(sam_context, access_token, access_desired, domainsid, group_name, group_ctrl, group);
}

NTSTATUS sam_add_group(const DOM_SID *domainsid, const SAM_GROUP_HANDLE *group)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_add_group(sam_context, domainsid, group);
}

NTSTATUS sam_update_group(const SAM_GROUP_HANDLE *group)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_update_group(sam_context, group);
}

NTSTATUS sam_delete_group(const SAM_GROUP_HANDLE *group)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_delete_group(sam_context, group);
}

NTSTATUS sam_enum_groups(const NT_USER_TOKEN *access_token, const DOM_SID *domainsid, uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_enum_groups(sam_context, access_token, domainsid, group_ctrl, groups_count, groups);
}

NTSTATUS sam_get_group_by_sid(const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_group_by_sid(sam_context, access_token, access_desired, groupsid, group);
}

NTSTATUS sam_get_group_by_name(const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *domain, const char *name, SAM_GROUP_HANDLE **group)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_group_by_name(sam_context, access_token, access_desired, domain, name, group);
}

NTSTATUS sam_add_member_to_group(const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_add_member_to_group(sam_context, group, member);
}

NTSTATUS sam_delete_member_from_group(const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_delete_member_from_group(sam_context, group, member);
}

NTSTATUS sam_enum_groupmembers(const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_enum_groupmembers(sam_context, group, members_count, members);
}

NTSTATUS sam_get_groups_of_sid(const NT_USER_TOKEN *access_token, const DOM_SID **sids, uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	SAM_CONTEXT *sam_context = sam_get_static_context(False);

	if (!sam_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return sam_context->sam_get_groups_of_sid(sam_context, access_token, sids, group_ctrl, group_count, groups);
}

