/*
 *  idmap_rid: static map between Active Directory/NT RIDs and RFC 2307 accounts
 *  Copyright (C) Guenther Deschner, 2004
 *  Copyright (C) Sumit Bose, 2004
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "includes.h"
#include "winbindd.h"
#include "idmap.h"
#include "../libcli/security/dom_sid.h"
#include "ads.h"
#include "../libcli/ldap/ldap_ndr.h"
#include "libsmb/samlogon_cache.h"
#include "winbindd_ads.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_rid_context {
	uint32_t base_rid;
};

/******************************************************************************
  compat params can't be used because of the completely different way
  we support multiple domains in the new idmap
 *****************************************************************************/

static NTSTATUS idmap_rid_sid_to_id(struct idmap_domain *dom, struct id_map *map);

static NTSTATUS idmap_rid_query_user(struct idmap_domain *domain,
				     struct wbint_userinfo *info)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = { "*", NULL };
	ADS_STATUS rc;
	int count;
	LDAPMessage *msg = NULL;
	char *ldap_exp;
	char *sidstr;
	uint32_t group_rid;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int ret;
	char *full_name;
	struct dom_sid *domain_sid;
	struct id_map group_map;

	DEBUG(3,("ads: query_user\n"));

	status = dom_sid_split_rid(mem_ctx, &(info->user_sid),
				   &domain_sid, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dom_sid_split_rid(%s) failed - %s\n",
			sid_string_dbg(&(info->user_sid)), nt_errstr(status));
		TALLOC_FREE(mem_ctx);
		return status;
	}

	/* no cache...do the query */
	rc = ads_idmap_cached_connection(&ads, domain->name);
	if (!ADS_ERR_OK(rc)) {
		TALLOC_FREE(mem_ctx);
		return ads_ntstatus(rc);
	}

	sidstr = ldap_encode_ndr_dom_sid(talloc_tos(), &(info->user_sid));

	ret = asprintf(&ldap_exp, "(objectSid=%s)", sidstr);
	TALLOC_FREE(sidstr);
	if (ret == -1) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	rc = ads_search_retry(ads, &msg, ldap_exp, attrs);
	SAFE_FREE(ldap_exp);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("query_user(sid=%s) ads_search: %s\n",
			 sid_string_dbg(&(info->user_sid)), ads_errstr(rc)));
		TALLOC_FREE(mem_ctx);
		return ads_ntstatus(rc);
	} else if (!msg) {
		DEBUG(1,("query_user(sid=%s) ads_search returned NULL res\n",
			 sid_string_dbg(&(info->user_sid))));
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	count = ads_count_replies(ads, msg);
	if (count != 1) {
		DEBUG(1,("query_user(sid=%s): Not found\n",
			 sid_string_dbg(&(info->user_sid))));
		ads_msgfree(ads, msg);
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	info->acct_name = ads_pull_username(ads, mem_ctx, msg);

	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &group_rid)) {
		DEBUG(1,("No primary group for %s !?\n",
			 sid_string_dbg(&(info->user_sid))));
		ads_msgfree(ads, msg);
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}
	sid_compose(&info->group_sid, domain_sid, group_rid);
	group_map.sid = &info->group_sid;
	idmap_rid_sid_to_id(domain, &group_map);
	if (group_map.xid.type == ID_TYPE_GID ||
	    group_map.xid.type == ID_TYPE_BOTH) {
		info->primary_gid = group_map.xid.id;
	}

	full_name = ads_pull_string(ads, mem_ctx, msg, "displayName");
	if (full_name == NULL) {
		full_name = ads_pull_string(ads, mem_ctx, msg, "name");
	}

	ads_msgfree(ads, msg);
	msg = NULL;

	if (info->full_name == NULL) {
		info->full_name = full_name;
	} else {
		TALLOC_FREE(full_name);
	}

	DEBUG(3,("ads query_user gave %s\n", info->acct_name));
	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS idmap_rid_initialize(struct idmap_domain *dom)
{
	struct idmap_rid_context *ctx;

	ctx = talloc_zero(dom, struct idmap_rid_context);
	if (ctx == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ctx->base_rid = idmap_config_int(dom->name, "base_rid", 0);

	dom->private_data = ctx;
	dom->query_user = idmap_rid_query_user;

	return NT_STATUS_OK;
}

static NTSTATUS idmap_rid_id_to_sid(struct idmap_domain *dom, struct id_map *map)
{
	struct idmap_rid_context *ctx;

	ctx = talloc_get_type(dom->private_data, struct idmap_rid_context);

	/* apply filters before checking */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		return NT_STATUS_NONE_MAPPED;
	}

	if (is_null_sid(&dom->dom_sid)) {
		DBG_INFO("idmap domain '%s' without SID\n", dom->name);
		return NT_STATUS_NONE_MAPPED;
	}

	sid_compose(map->sid, &dom->dom_sid,
		    map->xid.id - dom->low_id + ctx->base_rid);

	map->status = ID_MAPPED;
	map->xid.type = ID_TYPE_BOTH;

	return NT_STATUS_OK;
}

/**********************************
 Single sid to id lookup function.
**********************************/

static NTSTATUS idmap_rid_sid_to_id(struct idmap_domain *dom, struct id_map *map)
{
	uint32_t rid;
	struct idmap_rid_context *ctx;

	ctx = talloc_get_type(dom->private_data, struct idmap_rid_context);

	sid_peek_rid(map->sid, &rid);
	map->xid.id = rid - ctx->base_rid + dom->low_id;
	map->xid.type = ID_TYPE_BOTH;

	/* apply filters before returning result */

	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		map->status = ID_UNMAPPED;
		return NT_STATUS_NONE_MAPPED;
	}

	map->status = ID_MAPPED;

	return NT_STATUS_OK;
}

/**********************************
 lookup a set of unix ids.
**********************************/

static NTSTATUS idmap_rid_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	int i;

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {

		ret = idmap_rid_id_to_sid(dom, ids[i]);

		if (( ! NT_STATUS_IS_OK(ret)) &&
		    ( ! NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED))) {
			/* some fatal error occurred, log it */
			DBG_NOTICE("Unexpected error resolving an ID "
				   "(%d): %s\n", ids[i]->xid.id,
				   nt_errstr(ret));
		}
	}

	return NT_STATUS_OK;
}

/**********************************
 lookup a set of sids.
**********************************/

static NTSTATUS idmap_rid_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	int i;

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {

		ret = idmap_rid_sid_to_id(dom, ids[i]);

		if (( ! NT_STATUS_IS_OK(ret)) &&
		    ( ! NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED))) {
			/* some fatal error occurred, log it */
			DEBUG(3, ("Unexpected error resolving a SID (%s)\n",
				  sid_string_dbg(ids[i]->sid)));
		}
	}

	return NT_STATUS_OK;
}

static struct idmap_methods rid_methods = {
	.init = idmap_rid_initialize,
	.unixids_to_sids = idmap_rid_unixids_to_sids,
	.sids_to_unixids = idmap_rid_sids_to_unixids,
};

static_decl_idmap;
NTSTATUS idmap_rid_init(TALLOC_CTX *ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "rid", &rid_methods);
}

