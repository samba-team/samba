/*
 *  idmap_ad: map between Active Directory and RFC 2307 or "Services for Unix" (SFU) Accounts
 *
 * Unix SMB/CIFS implementation.
 *
 * Winbind ADS backend functions
 *
 * Copyright (C) Andrew Tridgell 2001
 * Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
 * Copyright (C) Gerald (Jerry) Carter 2004-2007
 * Copyright (C) Luke Howard 2001-2004
 * Copyright (C) Michael Adam 2008,2010
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "winbindd.h"
#include "../libds/common/flags.h"
#include "ads.h"
#include "libads/ldap_schema.h"
#include "nss_info.h"
#include "idmap.h"
#include "../libcli/ldap/ldap_ndr.h"
#include "../libcli/security/security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

#define CHECK_ALLOC_DONE(mem) do { \
     if (!mem) { \
           DEBUG(0, ("Out of memory!\n")); \
           ret = NT_STATUS_NO_MEMORY; \
           goto done; \
      } \
} while (0)

struct idmap_ad_context {
	ADS_STRUCT *ads;
	struct posix_schema *ad_schema;
	enum wb_posix_mapping ad_map_type; /* WB_POSIX_MAP_UNKNOWN */
};

/************************************************************************
 ***********************************************************************/

static ADS_STATUS ad_idmap_cached_connection(struct idmap_domain *dom)
{
	ADS_STATUS status;
	struct idmap_ad_context * ctx;

	DEBUG(10, ("ad_idmap_cached_connection: called for domain '%s'\n",
		   dom->name));

	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);

	status = ads_idmap_cached_connection(&ctx->ads, dom->name);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);

	/* if we have a valid ADS_STRUCT and the schema model is
	   defined, then we can return here. */

	if ( ctx->ad_schema ) {
		return ADS_SUCCESS;
	}

	/* Otherwise, set the schema model */

	if ( (ctx->ad_map_type ==  WB_POSIX_MAP_SFU) ||
	     (ctx->ad_map_type ==  WB_POSIX_MAP_SFU20) ||
	     (ctx->ad_map_type ==  WB_POSIX_MAP_RFC2307) )
	{
		status = ads_check_posix_schema_mapping(
			ctx, ctx->ads, ctx->ad_map_type, &ctx->ad_schema);
		if ( !ADS_ERR_OK(status) ) {
			DEBUG(2,("ad_idmap_cached_connection: Failed to obtain schema details!\n"));
		}
	}

	return status;
}

static int idmap_ad_context_destructor(struct idmap_ad_context *ctx)
{
	if (ctx->ads != NULL) {
		/* we own this ADS_STRUCT so make sure it goes away */
		ctx->ads->is_mine = True;
		ads_destroy( &ctx->ads );
		ctx->ads = NULL;
	}
	return 0;
}

/************************************************************************
 ***********************************************************************/

static NTSTATUS idmap_ad_initialize(struct idmap_domain *dom)
{
	struct idmap_ad_context *ctx;
	char *config_option;
	const char *schema_mode = NULL;	

	ctx = talloc_zero(dom, struct idmap_ad_context);
	if (ctx == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(ctx, idmap_ad_context_destructor);

	config_option = talloc_asprintf(ctx, "idmap config %s", dom->name);
	if (config_option == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		talloc_free(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* default map type */
	ctx->ad_map_type = WB_POSIX_MAP_RFC2307;

	/* schema mode */
	schema_mode = lp_parm_const_string(-1, config_option, "schema_mode", NULL);
	if ( schema_mode && schema_mode[0] ) {
		if ( strequal(schema_mode, "sfu") )
			ctx->ad_map_type = WB_POSIX_MAP_SFU;
		else if ( strequal(schema_mode, "sfu20" ) )
			ctx->ad_map_type = WB_POSIX_MAP_SFU20;
		else if ( strequal(schema_mode, "rfc2307" ) )
			ctx->ad_map_type = WB_POSIX_MAP_RFC2307;
		else
			DEBUG(0,("idmap_ad_initialize: Unknown schema_mode (%s)\n",
				 schema_mode));
	}

	dom->private_data = ctx;

	talloc_free(config_option);

	return NT_STATUS_OK;
}

/************************************************************************
 ***********************************************************************/

static NTSTATUS idmap_ad_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ad_context *ctx;
	ADS_STATUS rc;
	const char *attrs[] = { "sAMAccountType", 
				"objectSid",
				NULL, /* uidnumber */
				NULL, /* gidnumber */
				NULL };
	LDAPMessage *res = NULL;
	LDAPMessage *entry = NULL;
	char *filter = NULL;
	int idx = 0;
	int bidx = 0;
	int count;
	int i;
	char *u_filter = NULL;
	char *g_filter = NULL;

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	/* Only do query if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);

	if ( (memctx = talloc_new(ctx)) == NULL ) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	rc = ad_idmap_cached_connection(dom);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1, ("ADS uninitialized: %s\n", ads_errstr(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		/* ret = ads_ntstatus(rc); */
		goto done;
	}

	attrs[2] = ctx->ad_schema->posix_uidnumber_attr;
	attrs[3] = ctx->ad_schema->posix_gidnumber_attr;

again:
	bidx = idx;
	for (i = 0; (i < IDMAP_LDAP_MAX_IDS) && ids[idx]; i++, idx++) {
		switch (ids[idx]->xid.type) {
		case ID_TYPE_UID:     
			if ( ! u_filter) {
				u_filter = talloc_asprintf(memctx, "(&(|"
							   "(sAMAccountType=%d)"
							   "(sAMAccountType=%d)"
							   "(sAMAccountType=%d))(|",
							   ATYPE_NORMAL_ACCOUNT,
							   ATYPE_WORKSTATION_TRUST,
							   ATYPE_INTERDOMAIN_TRUST);
			}
			u_filter = talloc_asprintf_append_buffer(u_filter, "(%s=%lu)",
							  ctx->ad_schema->posix_uidnumber_attr,
							  (unsigned long)ids[idx]->xid.id);
			CHECK_ALLOC_DONE(u_filter);
			break;

		case ID_TYPE_GID:
			if ( ! g_filter) {
				g_filter = talloc_asprintf(memctx, "(&(|"
							   "(sAMAccountType=%d)"
							   "(sAMAccountType=%d))(|",
							   ATYPE_SECURITY_GLOBAL_GROUP,
							   ATYPE_SECURITY_LOCAL_GROUP);
			}
			g_filter = talloc_asprintf_append_buffer(g_filter, "(%s=%lu)",
							  ctx->ad_schema->posix_gidnumber_attr,
							  (unsigned long)ids[idx]->xid.id);
			CHECK_ALLOC_DONE(g_filter);
			break;

		default:
			DEBUG(3, ("Error: mapping requested but Unknown ID type\n"));
			ids[idx]->status = ID_UNKNOWN;
			continue;
		}
	}
	filter = talloc_asprintf(memctx, "(|");
	CHECK_ALLOC_DONE(filter);
	if ( u_filter) {
		filter = talloc_asprintf_append_buffer(filter, "%s))", u_filter);
		CHECK_ALLOC_DONE(filter);
			TALLOC_FREE(u_filter);
	}
	if ( g_filter) {
		filter = talloc_asprintf_append_buffer(filter, "%s))", g_filter);
		CHECK_ALLOC_DONE(filter);
		TALLOC_FREE(g_filter);
	}
	filter = talloc_asprintf_append_buffer(filter, ")");
	CHECK_ALLOC_DONE(filter);

	rc = ads_search_retry(ctx->ads, &res, filter, attrs);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1, ("ERROR: ads search returned: %s\n", ads_errstr(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if ( (count = ads_count_replies(ctx->ads, res)) == 0 ) {
		DEBUG(10, ("No IDs found\n"));
	}

	entry = res;
	for (i = 0; (i < count) && entry; i++) {
		struct dom_sid sid;
		enum id_type type;
		struct id_map *map;
		uint32_t id;
		uint32_t atype;

		if (i == 0) { /* first entry */
			entry = ads_first_entry(ctx->ads, entry);
		} else { /* following ones */
			entry = ads_next_entry(ctx->ads, entry);
		}

		if ( !entry ) {
			DEBUG(2, ("ERROR: Unable to fetch ldap entries from results\n"));
			break;
		}

		/* first check if the SID is present */
		if (!ads_pull_sid(ctx->ads, entry, "objectSid", &sid)) {
			DEBUG(2, ("Could not retrieve SID from entry\n"));
			continue;
		}

		/* get type */
		if (!ads_pull_uint32(ctx->ads, entry, "sAMAccountType", &atype)) {
			DEBUG(1, ("could not get SAM account type\n"));
			continue;
		}

		switch (atype & 0xF0000000) {
		case ATYPE_SECURITY_GLOBAL_GROUP:
		case ATYPE_SECURITY_LOCAL_GROUP:
			type = ID_TYPE_GID;
			break;
		case ATYPE_NORMAL_ACCOUNT:
		case ATYPE_WORKSTATION_TRUST:
		case ATYPE_INTERDOMAIN_TRUST:
			type = ID_TYPE_UID;
			break;
		default:
			DEBUG(1, ("unrecognized SAM account type %08x\n", atype));
			continue;
		}

		if (!ads_pull_uint32(ctx->ads, entry, (type==ID_TYPE_UID) ?
				                 ctx->ad_schema->posix_uidnumber_attr :
				                 ctx->ad_schema->posix_gidnumber_attr,
				     &id)) 
		{
			DEBUG(1, ("Could not get unix ID for SID %s\n",
				  dom_sid_string(talloc_tos(), &sid)));
			continue;
		}

		if (!idmap_unix_id_is_in_range(id, dom)) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				id, dom->low_id, dom->high_id));
			continue;
		}

		map = idmap_find_map_by_id(&ids[bidx], type, id);
		if (!map) {
			DEBUG(2, ("WARNING: couldn't match result with requested ID\n"));
			continue;
		}

		sid_copy(map->sid, &sid);

		/* mapped */
		map->status = ID_MAPPED;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n", sid_string_dbg(map->sid),
			   (unsigned long)map->xid.id,
			   map->xid.type));
	}

	if (res) {
		ads_msgfree(ctx->ads, res);
	}

	if (ids[idx]) { /* still some values to map */
		goto again;
	}

	ret = NT_STATUS_OK;

	/* mark all unknown/expired ones as unmapped */
	for (i = 0; ids[i]; i++) {
		if (ids[i]->status != ID_MAPPED) 
			ids[i]->status = ID_UNMAPPED;
	}

done:
	talloc_free(memctx);
	return ret;
}

/************************************************************************
 ***********************************************************************/

static NTSTATUS idmap_ad_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ad_context *ctx;
	ADS_STATUS rc;
	const char *attrs[] = { "sAMAccountType", 
				"objectSid",
				NULL, /* attr_uidnumber */
				NULL, /* attr_gidnumber */
				NULL };
	LDAPMessage *res = NULL;
	LDAPMessage *entry = NULL;
	char *filter = NULL;
	int idx = 0;
	int bidx = 0;
	int count;
	int i;
	char *sidstr;

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	/* Only do query if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);	

	if ( (memctx = talloc_new(ctx)) == NULL ) {		
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	rc = ad_idmap_cached_connection(dom);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1, ("ADS uninitialized: %s\n", ads_errstr(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		/* ret = ads_ntstatus(rc); */
		goto done;
	}

	if (ctx->ad_schema == NULL) {
		DEBUG(0, ("haven't got ctx->ad_schema ! \n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	attrs[2] = ctx->ad_schema->posix_uidnumber_attr;
	attrs[3] = ctx->ad_schema->posix_gidnumber_attr;

again:
	filter = talloc_asprintf(memctx, "(&(|"
				 "(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d)" /* user account types */
				 "(sAMAccountType=%d)(sAMAccountType=%d)" /* group account types */
				 ")(|",
				 ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST, ATYPE_INTERDOMAIN_TRUST,
				 ATYPE_SECURITY_GLOBAL_GROUP, ATYPE_SECURITY_LOCAL_GROUP);

	CHECK_ALLOC_DONE(filter);

	bidx = idx;
	for (i = 0; (i < IDMAP_LDAP_MAX_IDS) && ids[idx]; i++, idx++) {

		ids[idx]->status = ID_UNKNOWN;

		sidstr = ldap_encode_ndr_dom_sid(talloc_tos(), ids[idx]->sid);
		filter = talloc_asprintf_append_buffer(filter, "(objectSid=%s)", sidstr);

		TALLOC_FREE(sidstr);
		CHECK_ALLOC_DONE(filter);
	}
	filter = talloc_asprintf_append_buffer(filter, "))");
	CHECK_ALLOC_DONE(filter);
	DEBUG(10, ("Filter: [%s]\n", filter));

	rc = ads_search_retry(ctx->ads, &res, filter, attrs);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1, ("ERROR: ads search returned: %s\n", ads_errstr(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if ( (count = ads_count_replies(ctx->ads, res)) == 0 ) {
		DEBUG(10, ("No IDs found\n"));
	}

	entry = res;	
	for (i = 0; (i < count) && entry; i++) {
		struct dom_sid sid;
		enum id_type type;
		struct id_map *map;
		uint32_t id;
		uint32_t atype;

		if (i == 0) { /* first entry */
			entry = ads_first_entry(ctx->ads, entry);
		} else { /* following ones */
			entry = ads_next_entry(ctx->ads, entry);
		}

		if ( !entry ) {
			DEBUG(2, ("ERROR: Unable to fetch ldap entries from results\n"));
			break;
		}

		/* first check if the SID is present */
		if (!ads_pull_sid(ctx->ads, entry, "objectSid", &sid)) {
			DEBUG(2, ("Could not retrieve SID from entry\n"));
			continue;
		}

		map = idmap_find_map_by_sid(&ids[bidx], &sid);
		if (!map) {
			DEBUG(2, ("WARNING: couldn't match result with requested SID\n"));
			continue;
		}

		/* get type */
		if (!ads_pull_uint32(ctx->ads, entry, "sAMAccountType", &atype)) {
			DEBUG(1, ("could not get SAM account type\n"));
			continue;
		}

		switch (atype & 0xF0000000) {
		case ATYPE_SECURITY_GLOBAL_GROUP:
		case ATYPE_SECURITY_LOCAL_GROUP:
			type = ID_TYPE_GID;
			break;
		case ATYPE_NORMAL_ACCOUNT:
		case ATYPE_WORKSTATION_TRUST:
		case ATYPE_INTERDOMAIN_TRUST:
			type = ID_TYPE_UID;
			break;
		default:
			DEBUG(1, ("unrecognized SAM account type %08x\n", atype));
			continue;
		}

		if (!ads_pull_uint32(ctx->ads, entry, (type==ID_TYPE_UID) ?
				                 ctx->ad_schema->posix_uidnumber_attr :
				                 ctx->ad_schema->posix_gidnumber_attr,
				     &id)) 
		{
			DEBUG(1, ("Could not get unix ID for SID %s\n",
				sid_string_dbg(map->sid)));
			continue;
		}
		if (!idmap_unix_id_is_in_range(id, dom)) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				id, dom->low_id, dom->high_id));
			continue;
		}

		/* mapped */
		map->xid.type = type;
		map->xid.id = id;
		map->status = ID_MAPPED;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n", sid_string_dbg(map->sid),
			   (unsigned long)map->xid.id,
			   map->xid.type));
	}

	if (res) {
		ads_msgfree(ctx->ads, res);
	}

	if (ids[idx]) { /* still some values to map */
		goto again;
	}

	ret = NT_STATUS_OK;

	/* mark all unknown/expired ones as unmapped */
	for (i = 0; ids[i]; i++) {
		if (ids[i]->status != ID_MAPPED) 
			ids[i]->status = ID_UNMAPPED;
	}

done:
	talloc_free(memctx);
	return ret;
}

/************************************************************************
 Function dispatch tables for the idmap and nss plugins
 ***********************************************************************/

static struct idmap_methods ad_methods = {
	.init            = idmap_ad_initialize,
	.unixids_to_sids = idmap_ad_unixids_to_sids,
	.sids_to_unixids = idmap_ad_sids_to_unixids,
};

/************************************************************************
 Initialize the plugins
 ***********************************************************************/

static_decl_idmap;
NTSTATUS idmap_ad_init(void)
{
	static NTSTATUS status_idmap_ad = NT_STATUS_UNSUCCESSFUL;
	static NTSTATUS status_ad_nss = NT_STATUS_UNSUCCESSFUL;

	/* Always register the AD method first in order to get the
	   idmap_domain interface called */

	if ( !NT_STATUS_IS_OK(status_idmap_ad) ) {
		status_idmap_ad = smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, 
						     "ad", &ad_methods);
		if ( !NT_STATUS_IS_OK(status_idmap_ad) )
			return status_idmap_ad;		
	}

	if ( !NT_STATUS_IS_OK( status_ad_nss ) ) {
		status_ad_nss = idmap_ad_nss_init();
		if ( !NT_STATUS_IS_OK(status_ad_nss) )
			return status_ad_nss;
	}

	return NT_STATUS_OK;	
}
