/*
   Unix SMB/CIFS implementation.
   Winbind Utility functions

   Copyright (C) Gerald (Jerry) Carter   2007

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
#include "../libcli/security/security.h"
#include "../lib/util/util_pw.h"
#include "nsswitch/libwbclient/wbclient.h"

#include "lib/winbind_util.h"

#if defined(WITH_WINBIND)

struct passwd * winbind_getpwnam(const char * name)
{
	wbcErr result;
	struct passwd * tmp_pwd = NULL;
	struct passwd * pwd = NULL;

	result = wbcGetpwnam(name, &tmp_pwd);
	if (result != WBC_ERR_SUCCESS)
		return pwd;

	pwd = tcopy_passwd(talloc_tos(), tmp_pwd);

	wbcFreeMemory(tmp_pwd);

	return pwd;
}

struct passwd * winbind_getpwsid(const struct dom_sid *sid)
{
	wbcErr result;
	struct passwd * tmp_pwd = NULL;
	struct passwd * pwd = NULL;
	struct wbcDomainSid dom_sid;

	memcpy(&dom_sid, sid, sizeof(dom_sid));

	result = wbcGetpwsid(&dom_sid, &tmp_pwd);
	if (result != WBC_ERR_SUCCESS)
		return pwd;

	pwd = tcopy_passwd(talloc_tos(), tmp_pwd);

	wbcFreeMemory(tmp_pwd);

	return pwd;
}

/* Call winbindd to convert a name to a sid */

bool winbind_lookup_name(const char *dom_name, const char *name, struct dom_sid *sid,
                         enum lsa_SidType *name_type)
{
	struct wbcDomainSid dom_sid;
	wbcErr result;
	enum wbcSidType type;

	result = wbcLookupName(dom_name, name, &dom_sid, &type);
	if (result != WBC_ERR_SUCCESS)
		return false;

	memcpy(sid, &dom_sid, sizeof(struct dom_sid));
	*name_type = (enum lsa_SidType)type;

	return true;
}

/* Call winbindd to convert sid to name */

bool winbind_lookup_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			const char **domain, const char **name,
                        enum lsa_SidType *name_type)
{
	struct wbcDomainSid dom_sid;
	wbcErr result;
	enum wbcSidType type;
	char *domain_name = NULL;
	char *account_name = NULL;
	struct dom_sid_buf buf;

	memcpy(&dom_sid, sid, sizeof(dom_sid));

	result = wbcLookupSid(&dom_sid, &domain_name, &account_name, &type);
	if (result != WBC_ERR_SUCCESS)
		return false;

	/* Copy out result */

	if (domain) {
		*domain = talloc_strdup(mem_ctx, domain_name);
	}
	if (name) {
		*name = talloc_strdup(mem_ctx, account_name);
	}
	*name_type = (enum lsa_SidType)type;

	DEBUG(10, ("winbind_lookup_sid: SUCCESS: SID %s -> %s %s\n",
		   dom_sid_str_buf(sid, &buf), domain_name, account_name));

	wbcFreeMemory(domain_name);
	wbcFreeMemory(account_name);

	if ((domain && !*domain) || (name && !*name)) {
		DEBUG(0,("winbind_lookup_sid: talloc() failed!\n"));
		return false;
	}


	return true;
}

/* Ping winbindd to see it is alive */

bool winbind_ping(void)
{
	wbcErr result = wbcPing();

	return (result == WBC_ERR_SUCCESS);
}

/* Call winbindd to convert SID to uid */

bool winbind_sid_to_uid(uid_t *puid, const struct dom_sid *sid)
{
	struct wbcDomainSid dom_sid;
	wbcErr result;

	memcpy(&dom_sid, sid, sizeof(dom_sid));

	result = wbcSidToUid(&dom_sid, puid);

	return (result == WBC_ERR_SUCCESS);
}

/* Call winbindd to convert SID to gid */

bool winbind_sid_to_gid(gid_t *pgid, const struct dom_sid *sid)
{
	struct wbcDomainSid dom_sid;
	wbcErr result;

	memcpy(&dom_sid, sid, sizeof(dom_sid));

	result = wbcSidToGid(&dom_sid, pgid);

	return (result == WBC_ERR_SUCCESS);
}

bool winbind_xid_to_sid(struct dom_sid *sid, const struct unixid *xid)
{
	struct wbcUnixId wbc_xid;
	struct wbcDomainSid dom_sid;
	wbcErr result;

	switch (xid->type) {
	case ID_TYPE_UID:
		wbc_xid = (struct wbcUnixId) {
			.type = WBC_ID_TYPE_UID, .id.uid = xid->id
		};
		break;
	case ID_TYPE_GID:
		wbc_xid = (struct wbcUnixId) {
			.type = WBC_ID_TYPE_GID, .id.gid = xid->id
		};
		break;
	default:
		return false;
	}

	result = wbcUnixIdsToSids(&wbc_xid, 1, &dom_sid);
	if (result != WBC_ERR_SUCCESS) {
		return false;
	}

	memcpy(sid, &dom_sid, sizeof(struct dom_sid));
	return true;
}

/* Check for a trusted domain */

wbcErr wb_is_trusted_domain(const char *domain)
{
	wbcErr result;
	struct wbcDomainInfo *info = NULL;

	result = wbcDomainInfo(domain, &info);

	if (WBC_ERROR_IS_OK(result)) {
		wbcFreeMemory(info);
	}

	return result;
}

/* Lookup a set of rids in a given domain */

bool winbind_lookup_rids(TALLOC_CTX *mem_ctx,
			 const struct dom_sid *domain_sid,
			 int num_rids, uint32_t *rids,
			 const char **domain_name,
			 const char ***names, enum lsa_SidType **types)
{
	const char *dom_name = NULL;
	const char **namelist = NULL;
	enum wbcSidType *name_types = NULL;
	struct wbcDomainSid dom_sid;
	wbcErr ret;
	int i;

	memcpy(&dom_sid, domain_sid, sizeof(struct wbcDomainSid));

	ret = wbcLookupRids(&dom_sid, num_rids, rids,
			    &dom_name, &namelist, &name_types);
	if (ret != WBC_ERR_SUCCESS) {
		return false;
	}

	*domain_name = talloc_strdup(mem_ctx, dom_name);
	*names       = talloc_array(mem_ctx, const char*, num_rids);
	*types       = talloc_array(mem_ctx, enum lsa_SidType, num_rids);

	for(i=0; i<num_rids; i++) {
		(*names)[i] = talloc_strdup(*names, namelist[i]);
		(*types)[i] = (enum lsa_SidType)name_types[i];
	}

	wbcFreeMemory(discard_const_p(char, dom_name));
	wbcFreeMemory(namelist);
	wbcFreeMemory(name_types);

	return true;
}

/* Ask Winbind to allocate a new uid for us */

bool winbind_allocate_uid(uid_t *uid)
{
	wbcErr ret;

	ret = wbcAllocateUid(uid);

	return (ret == WBC_ERR_SUCCESS);
}

/* Ask Winbind to allocate a new gid for us */

bool winbind_allocate_gid(gid_t *gid)
{
	wbcErr ret;

	ret = wbcAllocateGid(gid);

	return (ret == WBC_ERR_SUCCESS);
}

bool winbind_lookup_usersids(TALLOC_CTX *mem_ctx,
			     const struct dom_sid *user_sid,
			     uint32_t *p_num_sids,
			     struct dom_sid **p_sids)
{
	wbcErr ret;
	struct wbcDomainSid dom_sid;
	struct wbcDomainSid *sid_list = NULL;
	uint32_t num_sids;

	memcpy(&dom_sid, user_sid, sizeof(dom_sid));

	ret = wbcLookupUserSids(&dom_sid,
				false,
				&num_sids,
				&sid_list);
	if (ret != WBC_ERR_SUCCESS) {
		return false;
	}

	*p_sids = talloc_array(mem_ctx, struct dom_sid, num_sids);
	if (*p_sids == NULL) {
		wbcFreeMemory(sid_list);
		return false;
	}

	memcpy(*p_sids, sid_list, sizeof(dom_sid) * num_sids);

	*p_num_sids = num_sids;
	wbcFreeMemory(sid_list);

	return true;
}

#else      /* WITH_WINBIND */

struct passwd * winbind_getpwnam(const char * name)
{
	return NULL;
}

struct passwd * winbind_getpwsid(const struct dom_sid *sid)
{
	return NULL;
}

bool winbind_lookup_name(const char *dom_name, const char *name, struct dom_sid *sid,
                         enum lsa_SidType *name_type)
{
	return false;
}

/* Call winbindd to convert sid to name */

bool winbind_lookup_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			const char **domain, const char **name,
                        enum lsa_SidType *name_type)
{
	return false;
}

/* Ping winbindd to see it is alive */

bool winbind_ping(void)
{
	return false;
}

/* Call winbindd to convert SID to uid */

bool winbind_sid_to_uid(uid_t *puid, const struct dom_sid *sid)
{
	return false;
}

/* Call winbindd to convert SID to gid */

bool winbind_sid_to_gid(gid_t *pgid, const struct dom_sid *sid)
{
	return false;
}

/* Call winbindd to convert uid or gid to SID */

bool winbind_xid_to_sid(struct dom_sid *sid, const struct unixid *xid)
{
	return false;
}

/* Check for a trusted domain */

wbcErr wb_is_trusted_domain(const char *domain)
{
	return WBC_ERR_UNKNOWN_FAILURE;
}

/* Lookup a set of rids in a given domain */

bool winbind_lookup_rids(TALLOC_CTX *mem_ctx,
			 const struct dom_sid *domain_sid,
			 int num_rids, uint32_t *rids,
			 const char **domain_name,
			 const char ***names, enum lsa_SidType **types)
{
	return false;
}

/* Ask Winbind to allocate a new uid for us */

bool winbind_allocate_uid(uid_t *uid)
{
	return false;
}

/* Ask Winbind to allocate a new gid for us */

bool winbind_allocate_gid(gid_t *gid)
{
	return false;
}

bool winbind_lookup_usersids(TALLOC_CTX *mem_ctx,
			     const struct dom_sid *user_sid,
			     uint32_t *p_num_sids,
			     struct dom_sid **p_sids)
{
	return false;
}

#endif     /* WITH_WINBIND */
