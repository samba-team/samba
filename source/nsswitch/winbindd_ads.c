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


/*
  return our ads connections structure for a domain. We keep the connection
  open to make things faster
*/
static ADS_STRUCT *ads_cached_connection(struct winbindd_domain *domain)
{
	ADS_STRUCT *ads;
	int rc;

	if (domain->private) {
		return (ADS_STRUCT *)domain->private;
	}

	ads = ads_init(NULL, NULL, NULL, secrets_fetch_machine_password());
	if (!ads) {
		DEBUG(1,("ads_init for domain %s failed\n", domain->name));
		return NULL;
	}

	rc = ads_connect(ads);
	if (rc) {
		DEBUG(1,("ads_connect for domain %s failed: %s\n", domain->name, ads_errstr(rc)));
		ads_destroy(&ads);
		return NULL;
	}

	domain->private = (void *)ads;
	return ads;
}

/* useful utility */
static void sid_from_rid(struct winbindd_domain *domain, uint32 rid, DOM_SID *sid)
{
	sid_copy(sid, &domain->sid);
	sid_append_rid(sid, rid);
}

/* turn a sAMAccountType into a SID_NAME_USE */
static enum SID_NAME_USE ads_atype_map(uint32 atype)
{
	switch (atype & 0xF0000000) {
	case ATYPE_GROUP:
		return SID_NAME_DOM_GRP;
	case ATYPE_USER:
		return SID_NAME_USER;
	default:
		DEBUG(1,("hmm, need to map account type 0x%x\n", atype));
	}
	return SID_NAME_UNKNOWN;
}

/* Query display info for a realm. This is the basic user list fn */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *start_ndx, uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", "primaryGroupID", 
			       "userAccountControl", NULL};
	int rc, i, count;
	void *res = NULL;
	void *msg = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: query_user_list\n"));

	if ((*start_ndx) != 0) {
		DEBUG(1,("ads backend start_ndx not implemented!\n"));
		status = NT_STATUS_NOT_IMPLEMENTED;
		goto done;
	}

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	rc = ads_search(ads, &res, "(objectclass=user)", attrs);
	if (rc) {
		DEBUG(1,("query_user_list ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("query_user_list: No users found\n"));
		goto done;
	}

	(*info) = talloc(mem_ctx, count * sizeof(**info));
	if (!*info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

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
	status = NT_STATUS_OK;

done:
	if (res) ads_msgfree(ads, res);

	return status;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *start_ndx, uint32 *num_entries, 
				struct acct_info **info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", 
			       "sAMAccountType", NULL};
	int rc, i, count;
	void *res = NULL;
	void *msg = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: enum_dom_groups\n"));

	if ((*start_ndx) != 0) {
		DEBUG(1,("ads backend start_ndx not implemented\n"));
		status = NT_STATUS_NOT_IMPLEMENTED;
		goto done;
	}

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	rc = ads_search(ads, &res, "(objectclass=group)", attrs);
	if (rc) {
		DEBUG(1,("query_user_list ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("query_user_list: No users found\n"));
		goto done;
	}

	(*info) = talloc(mem_ctx, count * sizeof(**info));
	if (!*info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	i = 0;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		char *name, *gecos;
		DOM_SID sid;
		uint32 rid;
		uint32 account_type;

		if (!ads_pull_uint32(ads, msg, "sAMAccountType", 
				     &account_type) ||
		    !(account_type & ATYPE_GROUP)) continue;

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

	status = NT_STATUS_OK;

done:
	if (res) ads_msgfree(ads, res);

	return status;
}


/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"objectSid", "sAMAccountType", NULL};
	int rc, count;
	void *res = NULL;
	char *exp;
	uint32 t;
	fstring name2, dom2;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	/* sigh. Need to fix interface to give us a raw name */
	if (!parse_domain_user(name, dom2, name2)) {
		goto done;
	}

	DEBUG(3,("ads: name_to_sid\n"));

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	asprintf(&exp, "(sAMAccountName=%s)", name2);
	rc = ads_search(ads, &res, exp, attrs);
	free(exp);
	if (rc) {
		DEBUG(1,("name_to_sid ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count != 1) {
		DEBUG(1,("name_to_sid: %s not found\n", name));
		goto done;
	}

	if (!ads_pull_sid(ads, res, "objectSid", sid)) {
		DEBUG(1,("No sid for %s !?\n", name));
		goto done;
	}

	if (!ads_pull_uint32(ads, res, "sAMAccountType", &t)) {
		DEBUG(1,("No sAMAccountType for %s !?\n", name));
		goto done;
	}

	*type = ads_atype_map(t);

	status = NT_STATUS_OK;

done:
	if (res) ads_msgfree(ads, res);

	return status;
}

/* convert a sid to a user or group name */
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid,
			    char **name,
			    enum SID_NAME_USE *type)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"sAMAccountName", "sAMAccountType", NULL};
	int rc;
	void *msg = NULL;
	char *exp;
	char *sidstr;
	uint32 atype;
	char *s;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: sid_to_name\n"));

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sidstr = ads_sid_binstring(sid);
	asprintf(&exp, "(objectSid=%s)", sidstr);
	rc = ads_search(ads, &msg, exp, attrs);
	free(exp);
	free(sidstr);
	if (rc) {
		DEBUG(1,("sid_to_name ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	if (!ads_pull_uint32(ads, msg, "sAMAccountType", &atype)) {
		goto done;
	}

	s = ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
	*name = talloc_asprintf(mem_ctx, "%s%s%s", domain->name, lp_winbind_separator(), s);
	*type = ads_atype_map(atype);

	status = NT_STATUS_OK;
done:
	if (msg) ads_msgfree(ads, msg);

	return status;
}


/* Lookup user information from a rid */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   uint32 user_rid, 
			   WINBIND_USERINFO *info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", "primaryGroupID", 
			       "userAccountControl", NULL};
	int rc, count;
	void *msg = NULL;
	char *exp;
	DOM_SID sid;
	char *sidstr;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: query_user\n"));

	sid_from_rid(domain, user_rid, &sid);

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sidstr = ads_sid_binstring(&sid);
	asprintf(&exp, "(objectSid=%s)", sidstr);
	rc = ads_search(ads, &msg, exp, attrs);
	free(exp);
	free(sidstr);
	if (rc) {
		DEBUG(1,("query_user(rid=%d) ads_search: %s\n", user_rid, ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, msg);
	if (count != 1) {
		DEBUG(1,("query_user(rid=%d): Not found\n", user_rid));
		goto done;
	}

	info->acct_name = ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
	info->full_name = ads_pull_string(ads, mem_ctx, msg, "name");
	if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
		DEBUG(1,("No sid for %d !?\n", user_rid));
		goto done;
	}
	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &info->group_rid)) {
		DEBUG(1,("No primary group for %d !?\n", user_rid));
		goto done;
	}
	
	if (!sid_peek_rid(&sid, &info->user_rid)) {
		DEBUG(1,("No rid for %d !?\n", user_rid));
		goto done;
	}

	status = NT_STATUS_OK;

done:
	if (msg) ads_msgfree(ads, msg);

	return status;
}


/* Lookup groups a user is a member of. */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32 user_rid, 
				  uint32 *num_groups, uint32 **user_gids)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"distinguishedName", NULL};
	const char *attrs2[] = {"tokenGroups", "primaryGroupID", NULL};
	int rc, count;
	void *msg = NULL;
	char *exp;
	char *user_dn;
	DOM_SID *sids;
	int i;
	uint32 primary_group;
	DOM_SID sid;
	char *sidstr;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: lookup_usergroups\n"));

	(*num_groups) = 0;

	sid_from_rid(domain, user_rid, &sid);

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sidstr = ads_sid_binstring(&sid);
	asprintf(&exp, "(objectSid=%s)", sidstr);
	rc = ads_search(ads, &msg, exp, attrs);
	free(exp);
	free(sidstr);
	if (rc) {
		DEBUG(1,("lookup_usergroups(rid=%d) ads_search: %s\n", user_rid, ads_errstr(rc)));
		goto done;
	}

	user_dn = ads_pull_string(ads, mem_ctx, msg, "distinguishedName");

	if (msg) ads_msgfree(ads, msg);

	rc = ads_search_dn(ads, &msg, user_dn, attrs2);
	if (rc) {
		DEBUG(1,("lookup_usergroups(rid=%d) ads_search tokenGroups: %s\n", user_rid, ads_errstr(rc)));
		goto done;
	}

	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &primary_group)) {
		DEBUG(1,("No primary group for rid=%d !?\n", user_rid));
		goto done;
	}

	count = ads_pull_sids(ads, mem_ctx, msg, "tokenGroups", &sids) + 1;
	(*user_gids) = (uint32 *)talloc(mem_ctx, sizeof(uint32) * count);
	(*user_gids)[(*num_groups)++] = primary_group;

	for (i=1;i<count;i++) {
		uint32 rid;
		if (!sid_peek_rid(&sids[i-1], &rid)) continue;
		(*user_gids)[*num_groups] = rid;
		(*num_groups)++;
	}

	status = NT_STATUS_OK;
done:
	if (msg) ads_msgfree(ads, msg);

	return status;
}


static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 group_rid, uint32 *num_names, 
				uint32 **rid_mem, char ***names, 
				uint32 **name_types)
{
	DOM_SID group_sid;
	char *sidstr;
	const char *attrs[] = {"sAMAccountName", "objectSid", "sAMAccountType", NULL};
	int rc, count;
	void *res=NULL, *msg=NULL;
	ADS_STRUCT *ads = NULL;
	char *exp;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	*num_names = 0;

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sid_from_rid(domain, group_rid, &group_sid);
	sidstr = ads_sid_binstring(&group_sid);
	/* search for all users who have that group sid as primary group or as member */
	asprintf(&exp, "(&(objectclass=user)(|(primaryGroupID=%d)(memberOf=%s)))",
		 group_rid, sidstr);
	rc = ads_search(ads, &res, exp, attrs);
	free(exp);
	free(sidstr);
	if (rc) {
		DEBUG(1,("query_user_list ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		status = NT_STATUS_OK;
		goto done;
	}

	(*rid_mem) = talloc(mem_ctx, sizeof(uint32) * count);
	(*name_types) = talloc(mem_ctx, sizeof(uint32) * count);
	(*names) = talloc(mem_ctx, sizeof(char *) * count);

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		uint32 atype, rid;
		DOM_SID sid;

		(*names)[*num_names] = ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
		if (!ads_pull_uint32(ads, msg, "sAMAccountType", &atype)) {
			continue;
		}
		(*name_types)[*num_names] = ads_atype_map(atype);
		if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
			DEBUG(1,("No sid for %s !?\n", (*names)[*num_names]));
			continue;
		}
		if (!sid_peek_rid(&sid, &rid)) {
			DEBUG(1,("No rid for %s !?\n", (*names)[*num_names]));
			continue;
		}
		(*rid_mem)[*num_names] = rid;
		(*num_names)++;
	}	

	status = NT_STATUS_OK;
done:
	if (res) ads_msgfree(ads, res);

	return status;
}

/* find the sequence number for a domain */
static uint32 sequence_number(struct winbindd_domain *domain)
{
	uint32 usn;
	ADS_STRUCT *ads = NULL;

	ads = ads_cached_connection(domain);
	if (!ads) return DOM_SEQUENCE_NONE;

	if (!ads_USN(ads, &usn)) return DOM_SEQUENCE_NONE;

	return usn;
}

/* the ADS backend methods are exposed via this structure */
struct winbindd_methods ads_methods = {
	query_user_list,
	enum_dom_groups,
	name_to_sid,
	sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number
};

#endif
