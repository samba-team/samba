/* 
   Unix SMB/CIFS implementation.

   Winbind ADS backend functions

   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett 2002
   
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
#ifdef HAVE_LDAP

/* convert a single name to a sid in a domain */
NTSTATUS ads_name_to_sid(ADS_STRUCT *ads,
			 const char *name,
			 DOM_SID *sid,
			 enum SID_NAME_USE *type)
{
	const char *attrs[] = {"objectSid", "sAMAccountType", NULL};
	int count;
	ADS_STATUS rc;
	void *res = NULL;
	char *ldap_exp;
	uint32 t;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *escaped_name = escape_ldap_string_alloc(name);
	char *escaped_realm = escape_ldap_string_alloc(ads->config.realm);

	if (!escaped_name || !escaped_realm) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (asprintf(&ldap_exp, "(|(sAMAccountName=%s)(userPrincipalName=%s@%s))", 
		     escaped_name, escaped_name, escaped_realm) == -1) {
		DEBUG(1,("ads_name_to_sid: asprintf failed!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	rc = ads_search_retry(ads, &res, ldap_exp, attrs);
	free(ldap_exp);
	if (!ADS_ERR_OK(rc)) {
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

	DEBUG(3,("ads name_to_sid mapped %s\n", name));

done:
	if (res) ads_msgfree(ads, res);

	SAFE_FREE(escaped_name);
	SAFE_FREE(escaped_realm);

	return status;
}

/* convert a sid to a user or group name */
NTSTATUS ads_sid_to_name(ADS_STRUCT *ads,
			 TALLOC_CTX *mem_ctx,
			 const DOM_SID *sid,
			 char **name,
			 enum SID_NAME_USE *type)
{
	const char *attrs[] = {"userPrincipalName", 
			       "sAMAccountName",
			       "sAMAccountType", NULL};
	ADS_STATUS rc;
	void *msg = NULL;
	char *ldap_exp = NULL;
	char *sidstr = NULL;
	uint32 atype;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	if (!(sidstr = sid_binstring(sid))) {
		DEBUG(1,("ads_sid_to_name: sid_binstring failed!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (asprintf(&ldap_exp, "(objectSid=%s)", sidstr) == -1) {
		DEBUG(1,("ads_sid_to_name: asprintf failed!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	rc = ads_search_retry(ads, &msg, ldap_exp, attrs);
	if (!ADS_ERR_OK(rc)) {
		status = ads_ntstatus(rc);
		DEBUG(1,("ads_sid_to_name ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	if (!ads_pull_uint32(ads, msg, "sAMAccountType", &atype)) {
		goto done;
	}

	*name = ads_pull_username(ads, mem_ctx, msg);
	if (!*name) {
		DEBUG(1,("ads_sid_to_name: ads_pull_username retuned NULL!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
		
	*type = ads_atype_map(atype);

	status = NT_STATUS_OK;

	DEBUG(3,("ads sid_to_name mapped %s\n", *name));

done:
	if (msg) ads_msgfree(ads, msg);

	SAFE_FREE(ldap_exp);
	SAFE_FREE(sidstr);

	return status;
}


/* convert a sid to a DN */

ADS_STATUS ads_sid_to_dn(ADS_STRUCT *ads,
			 TALLOC_CTX *mem_ctx,
			 const DOM_SID *sid,
			 char **dn)
{
	ADS_STATUS rc;
	LDAPMessage *msg = NULL;
	LDAPMessage *entry = NULL;
	char *ldap_exp;
	char *sidstr = NULL;
	int count;
	char *dn2 = NULL;

	const char *attr[] = {
		"dn",
		NULL
	};

	if (!(sidstr = sid_binstring(sid))) {
		DEBUG(1,("ads_sid_to_dn: sid_binstring failed!\n"));
		rc = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto done;
	}

	if(!(ldap_exp = talloc_asprintf(mem_ctx, "(objectSid=%s)", sidstr))) {
		DEBUG(1,("ads_sid_to_dn: talloc_asprintf failed!\n"));
		rc = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto done;
	}

	rc = ads_search_retry(ads, (void **)&msg, ldap_exp, attr);

	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("ads_sid_to_dn ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	if ((count = ads_count_replies(ads, msg)) != 1) {
		fstring sid_string;
		DEBUG(1,("ads_sid_to_dn (sid=%s): Not found (count=%d)\n", 
			 sid_to_string(sid_string, sid), count));
		rc = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
		goto done;
	}

	entry = ads_first_entry(ads, msg);

	dn2 = ads_get_dn(ads, entry);

	if (!dn2) {
		rc = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto done;
	}

	*dn = talloc_strdup(mem_ctx, dn2);

	if (!*dn) {
		ads_memfree(ads, dn2);
		rc = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto done;
	}

	rc = ADS_ERROR_NT(NT_STATUS_OK);

	DEBUG(3,("ads sid_to_dn mapped %s\n", dn2));

	SAFE_FREE(dn2);
done:
	if (msg) ads_msgfree(ads, msg);
	if (dn2) ads_memfree(ads, dn2);

	SAFE_FREE(sidstr);

	return rc;
}

#endif
