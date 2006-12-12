/*
 *  idmap_ad: map between Active Directory and RFC 2307 or "Services for Unix" (SFU) Accounts
 *
 * Unix SMB/CIFS implementation.
 *
 * Winbind ADS backend functions
 *
 * Copyright (C) Andrew Tridgell 2001
 * Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
 * Copyright (C) Gerald (Jerry) Carter 2004
 * Copyright (C) Luke Howard 2001-2004
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

#define WINBIND_CCACHE_NAME "MEMORY:winbind_ccache"

NTSTATUS init_module(void);

static ADS_STRUCT *ad_idmap_ads = NULL;

static char *attr_uidnumber = NULL;
static char *attr_gidnumber = NULL;

static ADS_STATUS ad_idmap_check_attr_mapping(ADS_STRUCT *ads)
{
	ADS_STATUS status;
	enum wb_posix_mapping map_type;

	if (attr_uidnumber != NULL && attr_gidnumber != NULL) {
		return ADS_ERROR(LDAP_SUCCESS);
	}

	SMB_ASSERT(ads->server.workgroup);

	map_type = get_nss_info(ads->server.workgroup);

	if ((map_type == WB_POSIX_MAP_SFU) ||
	    (map_type == WB_POSIX_MAP_RFC2307)) {

		status = ads_check_posix_schema_mapping(ads, map_type);
		if (ADS_ERR_OK(status)) {
			attr_uidnumber = SMB_STRDUP(ads->schema.posix_uidnumber_attr);
			attr_gidnumber = SMB_STRDUP(ads->schema.posix_gidnumber_attr);
			ADS_ERROR_HAVE_NO_MEMORY(attr_uidnumber);
			ADS_ERROR_HAVE_NO_MEMORY(attr_gidnumber);
			return ADS_ERROR(LDAP_SUCCESS);
		} else {
			DEBUG(0,("ads_check_posix_schema_mapping failed: %s\n", ads_errstr(status)));
			/* return status; */
		}
	}
	
	/* fallback to XAD defaults */
	attr_uidnumber = SMB_STRDUP("uidNumber");
	attr_gidnumber = SMB_STRDUP("gidNumber");
	ADS_ERROR_HAVE_NO_MEMORY(attr_uidnumber);
	ADS_ERROR_HAVE_NO_MEMORY(attr_gidnumber);

	return ADS_ERROR(LDAP_SUCCESS);
}

static ADS_STRUCT *ad_idmap_cached_connection(void)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	BOOL local = False;

	if (ad_idmap_ads != NULL) {
		ads = ad_idmap_ads;

		/* check for a valid structure */

		DEBUG(7, ("Current tickets expire at %d, time is now %d\n",
			  (uint32) ads->auth.expire, (uint32) time(NULL)));
		if ( ads->config.realm && (ads->auth.expire > time(NULL))) {
			return ads;
		} else {
			/* we own this ADS_STRUCT so make sure it goes away */
			ads->is_mine = True;
			ads_destroy( &ads );
			ads_kdestroy(WINBIND_CCACHE_NAME);
			ad_idmap_ads = NULL;
		}
	}

	if (!local) {
		/* we don't want this to affect the users ccache */
		setenv("KRB5CCNAME", WINBIND_CCACHE_NAME, 1);
	}

	ads = ads_init(lp_realm(), lp_workgroup(), NULL);
	if (!ads) {
		DEBUG(1,("ads_init failed\n"));
		return NULL;
	}

	/* the machine acct password might have change - fetch it every time */
	SAFE_FREE(ads->auth.password);
	ads->auth.password = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);

	SAFE_FREE(ads->auth.realm);
	ads->auth.realm = SMB_STRDUP(lp_realm());

	status = ads_connect(ads);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1, ("ad_idmap_init: failed to connect to AD\n"));
		ads_destroy(&ads);
		return NULL;
	}

	ads->is_mine = False;

	status = ad_idmap_check_attr_mapping(ads);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1, ("ad_idmap_init: failed to check attribute mapping\n"));
		return NULL;
	}

	ad_idmap_ads = ads;
	return ads;
}

struct idmap_ad_context {
	uint32_t filter_low_id, filter_high_id;		/* Filter range */
};

/* Initialize and check conf is appropriate */
static NTSTATUS idmap_ad_initialize(struct idmap_domain *dom, const char *params)
{
	struct idmap_ad_context *ctx;
	char *config_option;
	const char *range;
	ADS_STRUCT *ads;

	/* verify AD is reachable (not critical, we may just be offline at start) */
	ads = ad_idmap_cached_connection();
	if (ads == NULL) {
		DEBUG(1, ("WARNING: Could not init an AD connection! Mapping might not work.\n"));
	}

	ctx = talloc_zero(dom, struct idmap_ad_context);
	if ( ! ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	config_option = talloc_asprintf(ctx, "idmap config %s", dom->name);
	if ( ! config_option) {
		DEBUG(0, ("Out of memory!\n"));
		talloc_free(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* load ranges */
	range = lp_parm_const_string(-1, config_option, "range", NULL);
	if (range && range[0]) {
		if ((sscanf(range, "%u - %u", &ctx->filter_low_id, &ctx->filter_high_id) != 2) ||
		    (ctx->filter_low_id > ctx->filter_high_id)) {
			DEBUG(1, ("ERROR: invalid filter range [%s]", range));
			ctx->filter_low_id = 0;
			ctx->filter_high_id = 0;
		}
	}

	/* idmap AD can work well only if it is the default module (trusts)
	 * with additional BUILTIN and alloc using TDB */
	if ( ! dom->default_domain) {
		DEBUG(1, ("WARNING: idmap_ad is not configured as the default domain.\n"
			  "For best results we suggest you to configure this module as\n"
			  "default and configure BULTIN to use idmap_tdb\n"
			  "ex: idmap domains = BUILTIN %s\n"
			  "    idmap alloc config: range = 5000 - 9999\n"
			  "    idmap config %s: default = yes\n"
			  "    idmap config %s: backend = ad\n"
			  "    idmap config %s: range = 10000 - 10000000  #this is optional\n"
			  "NOTE: make sure the ranges do not overlap\n",
			  dom->name, dom->name, dom->name, dom->name));
	}
	if ( ! dom->readonly) {
		DEBUG(1, ("WARNING: forcing to readonly, as idmap_ad can't write on AD.\n"));
		dom->readonly = true; /* force readonly */
	}

	dom->private_data = ctx;

	talloc_free(config_option);
	return NT_STATUS_OK;
}

#define IDMAP_AD_MAX_IDS 30
#define CHECK_ALLOC_DONE(mem) do { if (!mem) { DEBUG(0, ("Out of memory!\n")); ret = NT_STATUS_NO_MEMORY; goto done; } } while (0)

/* this function searches up to IDMAP_AD_MAX_IDS entries in maps for a match */
static struct id_map *find_map_by_id(struct id_map **maps, enum id_type type, uint32_t id)
{
	int i;

	for (i = 0; i < IDMAP_AD_MAX_IDS; i++) {
		if (maps[i] == NULL) { /* end of the run */
			return NULL;
		}
		if ((maps[i]->xid.type == type) && (maps[i]->xid.id == id)) {
			return maps[i];
		}
	}

	return NULL;	
}

static NTSTATUS idmap_ad_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ad_context *ctx;
	ADS_STATUS rc;
	ADS_STRUCT *ads;
	const char *attrs[] = { "sAMAccountType", 
				"objectSid",
				NULL, /* attr_uidnumber */
				NULL, /* attr_gidnumber */
				NULL };
	LDAPMessage *res = NULL;
	char *filter = NULL;
	BOOL multi = False;
	int idx = 0;
	int bidx = 0;
	int count;
	int i;

	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);	

	memctx = talloc_new(ctx);
	if ( ! memctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ads = ad_idmap_cached_connection();
	if (ads == NULL) {
		DEBUG(1, ("ADS uninitialized\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* attr_uidnumber and attr_gidnumber are surely successfully initialized now */
	attrs[2] = attr_uidnumber;
	attrs[3] = attr_gidnumber;

	if ( ! ids[1]) {
		/* if we are requested just one mapping use the simple filter */
		switch (ids[0]->xid.type) {
		case ID_TYPE_UID:

			filter = talloc_asprintf(memctx,
				"(&(|(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d))(%s=%lu))",
				ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST, ATYPE_INTERDOMAIN_TRUST,
				attr_uidnumber,
				(unsigned long)ids[0]->xid.id);
			break;
		case ID_TYPE_GID:

			filter = talloc_asprintf(memctx,
				"(&(|(sAMAccountType=%d)(sAMAccountType=%d))(%s=%lu))",
				ATYPE_SECURITY_GLOBAL_GROUP, ATYPE_SECURITY_LOCAL_GROUP,
				attr_gidnumber,
				(unsigned long)ids[0]->xid.id);
			break;
		default:
			DEBUG(3, ("Unknown ID type\n"));
			ret = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		/* multiple mappings */
		multi = True;
	}

again:
	if (multi) {
		char *u_filter = NULL;
		char *g_filter = NULL;

		bidx = idx;
		for (i = 0; (i < IDMAP_AD_MAX_IDS) && ids[idx]; i++, idx++) {
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
				u_filter = talloc_asprintf_append(u_filter, "(%s=%lu)",
					attr_uidnumber,
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
				g_filter = talloc_asprintf_append(g_filter, "(%s=%lu)",
					attr_gidnumber,
					(unsigned long)ids[idx]->xid.id);
				CHECK_ALLOC_DONE(g_filter);
				break;

			default:
				DEBUG(3, ("Unknown ID type\n"));
				ids[idx]->mapped = false;
				continue;
			}
		}
		filter = talloc_asprintf(memctx, "(|");
		CHECK_ALLOC_DONE(filter);
		if ( u_filter) {
			filter = talloc_asprintf_append(filter, "%s))", u_filter);
			CHECK_ALLOC_DONE(filter);
			TALLOC_FREE(u_filter);
		}
		if ( g_filter) {
			filter = talloc_asprintf_append(filter, "%s))", g_filter);
			CHECK_ALLOC_DONE(filter);
			TALLOC_FREE(g_filter);
		}
		filter = talloc_asprintf_append(filter, ")");
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		bidx = 0;
		idx = 1;
	}

	rc = ads_search_retry(ads, &res, filter, attrs);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1, ("ERROR: ads search returned: %s\n", ads_errstr(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(10, ("No IDs found\n"));
	}

	for (i = 0; i < count; i++) {
		LDAPMessage *entry = NULL;
		DOM_SID sid;
		enum id_type type;
		struct id_map *map;
		uint32_t id;
		uint32_t atype;

		if (i == 0) { /* first entry */
			entry = ads_first_entry(ads, res);
		} else { /* following ones */
			entry = ads_next_entry(ads, entry);
		}
		if ( ! entry) {
			DEBUG(2, ("ERROR: Unable to fetch ldap entries from results\n"));
			continue;
		}

		/* first check if the SID is present */
		if (!ads_pull_sid(ads, entry, "objectSid", &sid)) {
			DEBUG(2, ("Could not retrieve SID from entry\n"));
			continue;
		}

		/* get type */
		if (!ads_pull_uint32(ads, entry, "sAMAccountType", &atype)) {
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

		if (!ads_pull_uint32(ads, entry, (type==ID_TYPE_UID)?attr_uidnumber:attr_gidnumber, &id)) {
			DEBUG(1, ("Could not get unix ID\n"));
			continue;
		}
		if ((id == 0) ||
		    (ctx->filter_low_id && (id < ctx->filter_low_id)) ||
		    (ctx->filter_high_id && (id > ctx->filter_high_id))) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				id, ctx->filter_low_id, ctx->filter_high_id));
			continue;
		}

		map = find_map_by_id(&ids[bidx], type, id);
		if (!map) {
			DEBUG(2, ("WARNING: couldn't match result with requested ID\n"));
			continue;
		}

		sid_copy(map->sid, &sid);

		/* mapped */
		map->mapped = True;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n",
			   sid_string_static(map->sid),
			   (unsigned long)map->xid.id,
			   map->xid.type));
	}

	if (res) {
		ads_msgfree(ads, res);
	}

	if (multi && ids[idx]) { /* still some values to map */
		goto again;
	}

	ret = NT_STATUS_OK;
done:
	talloc_free(memctx);
	return ret;
}

/* this function searches up to IDMAP_AD_MAX_IDS entries in maps for a match */
static struct id_map *find_map_by_sid(struct id_map **maps, DOM_SID *sid)
{
	int i;

	for (i = 0; i < IDMAP_AD_MAX_IDS; i++) {
		if (maps[i] == NULL) { /* end of the run */
			return NULL;
		}
		if (sid_equal(maps[i]->sid, sid)) {
			return maps[i];
		}
	}

	return NULL;	
}

static NTSTATUS idmap_ad_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ad_context *ctx;
	ADS_STATUS rc;
	ADS_STRUCT *ads;
	const char *attrs[] = { "sAMAccountType", 
				"objectSid",
				NULL, /* attr_uidnumber */
				NULL, /* attr_gidnumber */
				NULL };
	LDAPMessage *res = NULL;
	char *filter = NULL;
	BOOL multi = False;
	int idx = 0;
	int bidx = 0;
	int count;
	int i;

	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);	

	memctx = talloc_new(ctx);
	if ( ! memctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ads = ad_idmap_cached_connection();
	if (ads == NULL) {
		DEBUG(1, ("ADS uninitialized\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* attr_uidnumber and attr_gidnumber are surely successfully initialized now */
	attrs[2] = attr_uidnumber;
	attrs[3] = attr_gidnumber;


	if ( ! ids[1]) {
		/* if we are requested just one mapping use the simple filter */
		char *sidstr;

		sidstr = sid_binstring(ids[0]->sid);
		filter = talloc_asprintf(memctx, "(&(objectSid=%s)(|" /* the requested Sid */
						 "(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d)" /* user account types */
						 "(sAMAccountType=%d)(sAMAccountType=%d)))", /* group account types */
						 sidstr,
						 ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST, ATYPE_INTERDOMAIN_TRUST,
						 ATYPE_SECURITY_GLOBAL_GROUP, ATYPE_SECURITY_LOCAL_GROUP);
		if (! filter) {
			free(sidstr);
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		/* multiple mappings */
		multi = True;
	}

again:
	if (multi) {
		char *sidstr;

		filter = talloc_asprintf(memctx,
				"(&(|"
				    "(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d)" /* user account types */
				    "(sAMAccountType=%d)(sAMAccountType=%d)" /* group account types */
				  ")(|",
					ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST, ATYPE_INTERDOMAIN_TRUST,
					ATYPE_SECURITY_GLOBAL_GROUP, ATYPE_SECURITY_LOCAL_GROUP);
		
		CHECK_ALLOC_DONE(filter);

		bidx = idx;
		for (i = 0; (i < IDMAP_AD_MAX_IDS) && ids[idx]; i++, idx++) {

			sidstr = sid_binstring(ids[idx]->sid);
			filter = talloc_asprintf_append(filter, "(objectSid=%s)", sidstr);
			
			free(sidstr);
			CHECK_ALLOC_DONE(filter);
		}
		filter = talloc_asprintf_append(filter, "))");
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		bidx = 0;
		idx = 1;
	}

	rc = ads_search_retry(ads, &res, filter, attrs);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1, ("ERROR: ads search returned: %s\n", ads_errstr(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(10, ("No IDs found\n"));
	}

	for (i = 0; i < count; i++) {
		LDAPMessage *entry = NULL;
		DOM_SID sid;
		enum id_type type;
		struct id_map *map;
		uint32_t id;
		uint32_t atype;

		if (i == 0) { /* first entry */
			entry = ads_first_entry(ads, res);
		} else { /* following ones */
			entry = ads_next_entry(ads, entry);
		}
		if ( ! entry) {
			DEBUG(2, ("ERROR: Unable to fetch ldap entries from results\n"));
			continue;
		}

		/* first check if the SID is present */
		if (!ads_pull_sid(ads, entry, "objectSid", &sid)) {
			DEBUG(2, ("Could not retrieve SID from entry\n"));
			continue;
		}

		map = find_map_by_sid(&ids[bidx], &sid);
		if (!map) {
			DEBUG(2, ("WARNING: couldn't match result with requested SID\n"));
			continue;
		}

		/* get type */
		if (!ads_pull_uint32(ads, entry, "sAMAccountType", &atype)) {
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

		if (!ads_pull_uint32(ads, entry, (type==ID_TYPE_UID)?attr_uidnumber:attr_gidnumber, &id)) {
			DEBUG(1, ("Could not get unix ID\n"));
			continue;
		}
		if ((id == 0) ||
		    (ctx->filter_low_id && (id < ctx->filter_low_id)) ||
		    (ctx->filter_high_id && (id > ctx->filter_high_id))) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				id, ctx->filter_low_id, ctx->filter_high_id));
			continue;
		}

		/* mapped */
		map->xid.type = type;
		map->xid.id = id;
		map->mapped = True;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n",
			   sid_string_static(map->sid),
			   (unsigned long)map->xid.id,
			   map->xid.type));
	}

	if (res) {
		ads_msgfree(ads, res);
	}

	if (multi && ids[idx]) { /* still some values to map */
		goto again;
	}

	ret = NT_STATUS_OK;
done:
	talloc_free(memctx);
	return ret;
}

static NTSTATUS idmap_ad_close(struct idmap_domain *dom)
{
	ADS_STRUCT *ads = ad_idmap_ads;

	if (ads != NULL) {
		/* we own this ADS_STRUCT so make sure it goes away */
		ads->is_mine = True;
		ads_destroy( &ads );
		ad_idmap_ads = NULL;
	}

	SAFE_FREE(attr_uidnumber);
	SAFE_FREE(attr_gidnumber);
	
	return NT_STATUS_OK;
}

static struct idmap_methods ad_methods = {
	.init = idmap_ad_initialize,
	.unixids_to_sids = idmap_ad_unixids_to_sids,
	.sids_to_unixids = idmap_ad_sids_to_unixids,
	.close_fn = idmap_ad_close
};

/* support for new authentication subsystem */
NTSTATUS idmap_ad_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "ad", &ad_methods);
}

