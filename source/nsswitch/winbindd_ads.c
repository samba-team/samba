/* 
   Unix SMB/Netbios implementation.

   Winbind ADS backend functions

   Copyright (C) Andrew Tridgell 2001
   
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

#include "winbindd.h"

#ifdef HAVE_ADS

/* Query display info for a realm. This is the basic user list fn */
static NTSTATUS query_dispinfo(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *start_ndx, uint32 *num_entries, 
			       WINBIND_DISPINFO **info)
{
	ADS_STRUCT *ads;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", "primaryGroupID", 
			       "userAccountControl", NULL};
	int rc, i, count;
	void *res;
	void *msg;

	DEBUG(3,("ads: query_dispinfo\n"));

	if ((*start_ndx) != 0) {
		DEBUG(1,("ads backend start_ndx not implemented\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ads = ads_init(NULL, NULL, NULL);
	if (!ads) {
		DEBUG(1,("ads_init failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_connect(ads);
	if (rc) {
		DEBUG(1,("query_dispinfo ads_connect: %s\n", ads_errstr(rc)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_search(ads, &res, "(objectclass=user)", attrs);
	if (rc) {
		DEBUG(1,("query_dispinfo ads_search: %s\n", ads_errstr(rc)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("query_dispinfo: No users found\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	(*info) = talloc(mem_ctx, count * sizeof(**info));
	if (!*info) return NT_STATUS_NO_MEMORY;

	i = 0;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		char *name, *gecos;
		DOM_SID sid;
		uint32 rid, group;
		uint32 account_control;

		if (!ads_pull_uint32(ads, msg, "userAccountControl", 
				     &account_control) ||
		    !(account_control & UF_NORMAL_ACCOUNT)) continue;

		name = ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
		gecos = ads_pull_string(ads, mem_ctx, msg, "name");
		if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
			DEBUG(1,("No sid for %s !?\n", name));
			continue;
		}
		if (!ads_pull_uint32(ads, msg, "primaryGroupID", &group)) {
			DEBUG(1,("No primary group for %s !?\n", name));
			continue;
		}

		if (!sid_peek_rid(&sid, &rid)) {
			DEBUG(1,("No rid for %s !?\n", name));
			continue;
		}

		(*info)[i].acct_name = name;
		(*info)[i].full_name = gecos;
		(*info)[i].user_rid = rid;
		(*info)[i].group_rid = group;
		i++;
	}

	(*num_entries) = i;

	ads_destroy(&ads);

	return NT_STATUS_OK;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *start_ndx, uint32 *num_entries, 
				struct acct_info **info)
{
	ADS_STRUCT *ads;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", 
			       "sAMAccountType", NULL};
	int rc, i, count;
	void *res;
	void *msg;

	DEBUG(3,("ads: enum_dom_groups\n"));

	if ((*start_ndx) != 0) {
		DEBUG(1,("ads backend start_ndx not implemented\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ads = ads_init(NULL, NULL, NULL);
	if (!ads) {
		DEBUG(1,("ads_init failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_connect(ads);
	if (rc) {
		DEBUG(1,("query_dispinfo ads_connect: %s\n", ads_errstr(rc)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_search(ads, &res, "(objectclass=group)", attrs);
	if (rc) {
		DEBUG(1,("query_dispinfo ads_search: %s\n", ads_errstr(rc)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("query_dispinfo: No users found\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	(*info) = talloc(mem_ctx, count * sizeof(**info));
	if (!*info) return NT_STATUS_NO_MEMORY;

	i = 0;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		char *name, *gecos;
		DOM_SID sid;
		uint32 rid;
		uint32 account_type;

		if (!ads_pull_uint32(ads, msg, "sAMAccountType", 
				     &account_type) ||
		    !(account_type & ATYPE_NORMAL_GROUP)) continue;

		name = ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
		gecos = ads_pull_string(ads, mem_ctx, msg, "name");
		if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
			DEBUG(1,("No sid for %s !?\n", name));
			continue;
		}

		if (!sid_peek_rid(&sid, &rid)) {
			DEBUG(1,("No rid for %s !?\n", name));
			continue;
		}

		fstrcpy((*info)[i].acct_name, name);
		fstrcpy((*info)[i].acct_desc, gecos);
		(*info)[i].rid = rid;
		i++;
	}

	(*num_entries) = i;

	ads_destroy(&ads);

	return NT_STATUS_OK;
}


/* the rpc backend methods are exposed via this structure */
struct winbindd_methods ads_methods = {
	query_dispinfo,
	enum_dom_groups
};

#endif
