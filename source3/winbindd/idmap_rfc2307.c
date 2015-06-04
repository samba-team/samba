/*
 * Unix SMB/CIFS implementation.
 *
 * Id mapping using LDAP records as defined in RFC 2307
 *
 * The SID<->uid/gid mapping is performed in two steps: 1) Query the
 * AD server for the name<->sid mapping. 2) Query an LDAP server
 * according to RFC 2307 for the name<->uid/gid mapping.
 *
 * Copyright (C) Christof Schmitt 2012,2013
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
#include "ads.h"
#include "idmap.h"
#include "smbldap.h"
#include "nsswitch/winbind_client.h"
#include "lib/winbind_util.h"

/*
 * Config and connection info per domain.
 */
struct idmap_rfc2307_context {
	const char *bind_path_user;
	const char *bind_path_group;
	const char *ldap_domain;
	bool cn_realm;
	bool user_cn;
	const char *realm;

	/*
	 * Pointer to ldap struct in ads or smbldap_state, has to be
	 * updated after connecting to server
	 */
	LDAP *ldap;

	/* Optional function to check connection to server */
	NTSTATUS (*check_connection)(struct idmap_domain *dom);

	/* Issue ldap query */
	NTSTATUS (*search)(struct idmap_rfc2307_context *ctx,
			   const char *bind_path, const char *expr,
			   const char **attrs, LDAPMessage **res);

	/* Access to LDAP in AD server */
	ADS_STRUCT *ads;

	/* Access to stand-alone LDAP server */
	struct smbldap_state *smbldap_state;
};

/*
 * backend functions for LDAP queries through ADS
 */

static NTSTATUS idmap_rfc2307_ads_check_connection(struct idmap_domain *dom)
{
	struct idmap_rfc2307_context *ctx;
	const char *dom_name = dom->name;
	ADS_STATUS status;

	DEBUG(10, ("ad_idmap_cached_connection: called for domain '%s'\n",
		   dom->name));

	ctx = talloc_get_type(dom->private_data, struct idmap_rfc2307_context);
	dom_name = ctx->ldap_domain ? ctx->ldap_domain : dom->name;

	status = ads_idmap_cached_connection(&ctx->ads, dom_name);
	if (ADS_ERR_OK(status)) {
		ctx->ldap = ctx->ads->ldap.ld;
		if (ctx->cn_realm) {
			ctx->realm = ctx->ads->server.realm;
		}
	} else {
		DEBUG(1, ("Could not connect to domain %s: %s\n", dom->name,
			  ads_errstr(status)));
	}

	return ads_ntstatus(status);
}

static NTSTATUS idmap_rfc2307_ads_search(struct idmap_rfc2307_context *ctx,
					 const char *bind_path,
					 const char *expr,
					 const char **attrs,
					 LDAPMessage **result)
{
	ADS_STATUS status;

	status = ads_do_search_retry(ctx->ads, bind_path,
				     LDAP_SCOPE_SUBTREE, expr, attrs, result);
	ctx->ldap = ctx->ads->ldap.ld;
	return ads_ntstatus(status);
}

static NTSTATUS idmap_rfc2307_init_ads(struct idmap_rfc2307_context *ctx,
				       const char *cfg_opt)
{
	const char *ldap_domain;

	ctx->search = idmap_rfc2307_ads_search;
	ctx->check_connection = idmap_rfc2307_ads_check_connection;

	ldap_domain = lp_parm_const_string(-1, cfg_opt, "ldap_domain",
					      NULL);
	if (ldap_domain) {
		ctx->ldap_domain = talloc_strdup(ctx, ldap_domain);
		if (ctx->ldap_domain == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

/*
 * backend function for LDAP queries through stand-alone LDAP server
 */

static NTSTATUS idmap_rfc2307_ldap_search(struct idmap_rfc2307_context *ctx,
					  const char *bind_path,
					  const char *expr,
					  const char **attrs,
					  LDAPMessage **result)
{
	int ret;

	ret = smbldap_search(ctx->smbldap_state, bind_path, LDAP_SCOPE_SUBTREE,
			     expr, attrs, 0, result);
	ctx->ldap = ctx->smbldap_state->ldap_struct;

	if (ret == LDAP_SUCCESS) {
		return NT_STATUS_OK;
	}

	return NT_STATUS_LDAP(ret);
}

static bool idmap_rfc2307_get_uint32(LDAP *ldap, LDAPMessage *entry,
				     const char *field, uint32 *value)
{
	bool b;
	char str[20];

	b = smbldap_get_single_attribute(ldap, entry, field, str, sizeof(str));

	if (b) {
		*value = atoi(str);
	}

	return b;
}

static NTSTATUS idmap_rfc2307_init_ldap(struct idmap_rfc2307_context *ctx,
					struct idmap_domain *dom,
					const char *config_option)
{
	NTSTATUS ret;
	char *url;
	char *secret = NULL;
	const char *ldap_url, *user_dn, *ldap_realm;
	TALLOC_CTX *mem_ctx = ctx;

	ldap_url = lp_parm_const_string(-1, config_option, "ldap_url", NULL);
	if (!ldap_url) {
		DEBUG(1, ("ERROR: missing idmap ldap url\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	url = talloc_strdup(talloc_tos(), ldap_url);

	user_dn = lp_parm_const_string(-1, config_option, "ldap_user_dn", NULL);
	if (user_dn) {
		secret = idmap_fetch_secret("ldap", dom->name, user_dn);
		if (!secret) {
			ret = NT_STATUS_ACCESS_DENIED;
			goto done;
		}
	}

	/* assume anonymous if we don't have a specified user */
	ret = smbldap_init(mem_ctx, winbind_event_context(), url,
			   (user_dn == NULL), user_dn, secret,
			   &ctx->smbldap_state);
	SAFE_FREE(secret);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("ERROR: smbldap_init (%s) failed!\n", url));
		goto done;
	}

	ctx->search = idmap_rfc2307_ldap_search;

	if (ctx->cn_realm) {
		ldap_realm = lp_parm_const_string(-1, config_option,
						  "ldap_realm", NULL);
		if (!ldap_realm) {
			DEBUG(1, ("ERROR: cn_realm set, "
				  "but ldap_realm is missing\n"));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		ctx->realm = talloc_strdup(mem_ctx, ldap_realm);
		if (!ctx->realm) {
			ret = NT_STATUS_NO_MEMORY;
		}
	}

done:
	talloc_free(url);
	return ret;
}

/*
 * common code for stand-alone LDAP and ADS
 */

static void idmap_rfc2307_map_sid_results(struct idmap_rfc2307_context *ctx,
					  TALLOC_CTX *mem_ctx,
					  struct id_map **ids,
					  LDAPMessage *result,
					  const char *dom_name,
					  const char **attrs, int type)
{
	int count, i;
	LDAPMessage *entry;

	count = ldap_count_entries(ctx->ldap, result);

	for (i = 0; i < count; i++) {
		char *name;
		enum lsa_SidType lsa_type;
		struct id_map *map;
		uint32_t id;
		bool b;

		if (i == 0) {
			entry = ldap_first_entry(ctx->ldap, result);
		} else {
			entry = ldap_next_entry(ctx->ldap, result);
		}
		if (!entry) {
			DEBUG(2, ("Unable to fetch entry.\n"));
			break;
		}

		name = smbldap_talloc_single_attribute(ctx->ldap, entry,
						       attrs[0], mem_ctx);
		if (!name) {
			DEBUG(1, ("Could not get user name\n"));
			continue;
		}

		b = idmap_rfc2307_get_uint32(ctx->ldap, entry, attrs[1], &id);
		if (!b) {
			DEBUG(1, ("Could not pull id for record %s\n", name));
			continue;
		}

		map = idmap_find_map_by_id(ids, type, id);
		if (!map) {
			DEBUG(1, ("Could not find id %d, name %s\n", id, name));
			continue;
		}

		if (ctx->cn_realm) {
			/* Strip @realm from user or group name */
			char *delim;

			delim = strchr(name, '@');
			if (delim) {
				*delim = '\0';
			}
		}

		/* by default calls to winbindd are disabled
		   the following call will not recurse so this is safe */
		(void)winbind_on();
		/* Lookup name from PDC using lsa_lookup_names() */
		b = winbind_lookup_name(dom_name, name, map->sid, &lsa_type);
		(void)winbind_off();

		if (!b) {
			DEBUG(1, ("SID lookup failed for id %d, %s\n",
				  id, name));
			continue;
		}

		if (type == ID_TYPE_UID && lsa_type != SID_NAME_USER) {
			DEBUG(1, ("Wrong type %d for user name %s\n",
				  type, name));
			continue;
		}

		if (type == ID_TYPE_GID && lsa_type != SID_NAME_DOM_GRP &&
		    lsa_type != SID_NAME_ALIAS &&
		    lsa_type != SID_NAME_WKN_GRP) {
			DEBUG(1, ("Wrong type %d for group name %s\n",
				  type, name));
			continue;
		}

		map->status = ID_MAPPED;
	}
}

/*
 * Map unixids to names and then to sids.
 */
static NTSTATUS idmap_rfc2307_unixids_to_sids(struct idmap_domain *dom,
					      struct id_map **ids)
{
	struct idmap_rfc2307_context *ctx;
	char *fltr_usr = NULL, *fltr_grp = NULL;
	TALLOC_CTX *mem_ctx;
	int cnt_usr = 0, cnt_grp = 0, idx = 0, bidx = 0;
	LDAPMessage *result = NULL;
	NTSTATUS ret;

	ctx = talloc_get_type(dom->private_data, struct idmap_rfc2307_context);
	mem_ctx = talloc_new(ctx);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (ctx->check_connection) {
		ret = ctx->check_connection(dom);
		if (!NT_STATUS_IS_OK(ret)) {
			goto out;
		}
	}

again:
	bidx = idx;

	if (!fltr_usr) {
		/* prepare new user query, see getpwuid() in RFC2307 */
		fltr_usr = talloc_asprintf(mem_ctx,
					     "(&(objectClass=posixAccount)(|");
	}

	if (!fltr_grp) {
		/* prepare new group query, see getgrgid() in RFC2307 */
		fltr_grp = talloc_asprintf(mem_ctx,
					     "(&(objectClass=posixGroup)(|");
	}

	if (!fltr_usr || !fltr_grp) {
		ret = NT_STATUS_NO_MEMORY;
		goto out;
	}

	while (cnt_usr < IDMAP_LDAP_MAX_IDS &&
	       cnt_grp < IDMAP_LDAP_MAX_IDS && ids[idx]) {

		switch (ids[idx]->xid.type) {
		case ID_TYPE_UID:
			fltr_usr = talloc_asprintf_append_buffer(fltr_usr,
					"(uidNumber=%d)", ids[idx]->xid.id);
			cnt_usr++;
			break;
		case ID_TYPE_GID:
			fltr_grp = talloc_asprintf_append_buffer(fltr_grp,
					"(gidNumber=%d)", ids[idx]->xid.id);
			cnt_grp++;
			break;
		default:
			DEBUG(3, ("Error: unknown ID type %d\n",
				  ids[idx]->xid.type));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}

		if (!fltr_usr || !fltr_grp) {
			ret = NT_STATUS_NO_MEMORY;
			goto out;
		}

		idx++;
	}

	if (cnt_usr == IDMAP_LDAP_MAX_IDS || (cnt_usr != 0 && !ids[idx])) {
		const char *attrs[] = { NULL, /* uid or cn */
					"uidNumber",
					NULL };

		fltr_usr = talloc_strdup_append(fltr_usr, "))");
		if (!fltr_usr) {
			ret = NT_STATUS_NO_MEMORY;
			goto out;
		}

		attrs[0] = ctx->user_cn ? "cn" : "uid";
		ret = ctx->search(ctx, ctx->bind_path_user, fltr_usr, attrs,
				  &result);
		if (!NT_STATUS_IS_OK(ret)) {
			goto out;
		}

		idmap_rfc2307_map_sid_results(ctx, mem_ctx, &ids[bidx], result,
					      dom->name, attrs, ID_TYPE_UID);
		cnt_usr = 0;
		TALLOC_FREE(fltr_usr);
	}

	if (cnt_grp == IDMAP_LDAP_MAX_IDS || (cnt_grp != 0 && !ids[idx])) {
		const char *attrs[] = { "cn", "gidNumber", NULL };

		fltr_grp = talloc_strdup_append(fltr_grp, "))");
		if (!fltr_grp) {
			ret = NT_STATUS_NO_MEMORY;
			goto out;
		}
		ret = ctx->search(ctx, ctx->bind_path_group, fltr_grp, attrs,
				  &result);
		if (!NT_STATUS_IS_OK(ret)) {
			goto out;
		}

		idmap_rfc2307_map_sid_results(ctx, mem_ctx, &ids[bidx], result,
					      dom->name, attrs, ID_TYPE_GID);
		cnt_grp = 0;
		TALLOC_FREE(fltr_grp);
	}

	if (ids[idx]) {
		goto again;
	}

	ret = NT_STATUS_OK;

out:
	talloc_free(mem_ctx);
	return ret;
}

struct idmap_rfc2307_map {
	struct id_map *map;
	const char *name;
	enum id_type type;
};

/*
 * Lookup names for SIDS and store the data in the local mapping
 * array.
 */
static NTSTATUS idmap_rfc_2307_sids_to_names(TALLOC_CTX *mem_ctx,
					     struct id_map **ids,
					     struct idmap_rfc2307_map *maps,
					     struct idmap_rfc2307_context *ctx)
{
	int i;

	for (i = 0; ids[i]; i++) {
		const char *domain, *name;
		enum lsa_SidType lsa_type;
		struct id_map *id = ids[i];
		struct idmap_rfc2307_map *map = &maps[i];
		bool b;

		/* by default calls to winbindd are disabled
		   the following call will not recurse so this is safe */
		(void)winbind_on();
		b = winbind_lookup_sid(mem_ctx, ids[i]->sid, &domain, &name,
				       &lsa_type);
		(void)winbind_off();

		if (!b) {
			DEBUG(1, ("Lookup sid %s failed.\n",
				  sid_string_dbg(ids[i]->sid)));
			continue;
		}

		switch(lsa_type) {
		case SID_NAME_USER:
			id->xid.type = map->type = ID_TYPE_UID;
			if (ctx->user_cn && ctx->cn_realm) {
				name = talloc_asprintf(mem_ctx, "%s@%s",
						       name, ctx->realm);
			}
			id->xid.type = map->type = ID_TYPE_UID;
			break;

		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:
			if (ctx->cn_realm) {
				name = talloc_asprintf(mem_ctx, "%s@%s",
						       name, ctx->realm);
			}
			id->xid.type = map->type = ID_TYPE_GID;
			break;

		default:
			DEBUG(1, ("Unknown lsa type %d for sid %s\n",
				  lsa_type, sid_string_dbg(id->sid)));
			id->status = ID_UNMAPPED;
			continue;
		}

		map->map = id;
		id->status = ID_UNKNOWN;
		map->name = strupper_talloc(mem_ctx, name);

		if (!map->name) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

/*
 * Find id_map entry by looking up the name in the internal
 * mapping array.
 */
static struct id_map* idmap_rfc2307_find_map(struct idmap_rfc2307_map *maps,
					     enum id_type type,
					     const char *name)
{
	int i;

	DEBUG(10, ("Looking for name %s, type %d\n", name, type));

	for (i = 0; i < IDMAP_LDAP_MAX_IDS; i++) {
		if (maps[i].map == NULL) { /* end of the run */
			return NULL;
		}
		DEBUG(10, ("Entry %d: name %s, type %d\n",
			   i, maps[i].name, maps[i].type));
		if (type == maps[i].type && strcmp(name, maps[i].name) == 0) {
			return maps[i].map;
		}
	}

	return NULL;
}

static void idmap_rfc2307_map_xid_results(struct idmap_rfc2307_context *ctx,
					  TALLOC_CTX *mem_ctx,
					  struct id_map **ids,
					  struct idmap_rfc2307_map *maps,
					  LDAPMessage *result,
					  struct idmap_domain *dom,
					  const char **attrs, enum id_type type)
{
	int count, i;
	LDAPMessage *entry;

	count = ldap_count_entries(ctx->ldap, result);

	for (i = 0; i < count; i++) {
		uint32_t id;
		char *name;
		bool b;
		struct id_map *id_map;

		if (i == 0) {
			entry = ldap_first_entry(ctx->ldap, result);
		} else {
			entry = ldap_next_entry(ctx->ldap, result);
		}
		if (!entry) {
			DEBUG(2, ("Unable to fetch entry.\n"));
			break;
		}

		name = smbldap_talloc_single_attribute(ctx->ldap, entry,
						       attrs[0], mem_ctx);
		if (!name) {
			DEBUG(1, ("Could not get user name\n"));
			continue;
		}

		b = idmap_rfc2307_get_uint32(ctx->ldap, entry, attrs[1], &id);
		if (!b) {
			DEBUG(5, ("Could not pull id for record %s\n", name));
			continue;
		}

		if (!idmap_unix_id_is_in_range(id, dom)) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u).\n",
				  id, dom->low_id, dom->high_id));
			continue;
		}

		if (!strupper_m(name)) {
			DEBUG(5, ("Could not convert %s to uppercase\n", name));
			continue;
		}
		id_map = idmap_rfc2307_find_map(maps, type, name);
		if (!id_map) {
			DEBUG(0, ("Could not find mapping entry for name %s\n",
				  name));
			continue;
		}

		id_map->xid.id = id;
		id_map->status = ID_MAPPED;
	}
}

/*
 * Map sids to names and then to unixids.
 */
static NTSTATUS idmap_rfc2307_sids_to_unixids(struct idmap_domain *dom,
					      struct id_map **ids)
{
	struct idmap_rfc2307_context *ctx;
	TALLOC_CTX *mem_ctx;
	struct idmap_rfc2307_map *int_maps;
	int cnt_usr = 0, cnt_grp = 0, idx = 0, bidx = 0;
	char *fltr_usr = NULL, *fltr_grp = NULL;
	NTSTATUS ret;
	int i;

	ctx = talloc_get_type(dom->private_data, struct idmap_rfc2307_context);
	mem_ctx = talloc_new(talloc_tos());
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (ctx->check_connection) {
		ret = ctx->check_connection(dom);
		if (!NT_STATUS_IS_OK(ret)) {
			goto out;
		}
	}

	for (i = 0; ids[i]; i++);
	int_maps = talloc_zero_array(mem_ctx, struct idmap_rfc2307_map, i);
	if (!int_maps) {
		ret = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = idmap_rfc_2307_sids_to_names(mem_ctx, ids, int_maps, ctx);
	if (!NT_STATUS_IS_OK(ret)) {
		goto out;
	}

again:
	if (!fltr_usr) {
		/* prepare new user query, see getpwuid() in RFC2307 */
		fltr_usr = talloc_asprintf(mem_ctx,
					     "(&(objectClass=posixAccount)(|");
	}

	if (!fltr_grp) {
		/* prepare new group query, see getgrgid() in RFC2307 */
		fltr_grp = talloc_asprintf(mem_ctx,
					     "(&(objectClass=posixGroup)(|");
	}

	if (!fltr_usr || !fltr_grp) {
		ret = NT_STATUS_NO_MEMORY;
		goto out;
	}

	while (cnt_usr < IDMAP_LDAP_MAX_IDS &&
	       cnt_grp < IDMAP_LDAP_MAX_IDS && ids[idx]) {
		struct id_map *id = ids[idx];
		struct idmap_rfc2307_map *map = &int_maps[idx];

		switch(id->xid.type) {
		case ID_TYPE_UID:
			fltr_usr = talloc_asprintf_append_buffer(fltr_usr,
				     "(%s=%s)", (ctx->user_cn ? "cn" : "uid"),
				      map->name);
			cnt_usr++;
			break;

		case ID_TYPE_GID:
			fltr_grp = talloc_asprintf_append_buffer(fltr_grp,
					 "(cn=%s)", map->name);
			cnt_grp++;
			break;

		default:
			DEBUG(10, ("Nothing to do for SID %s, "
				   "previous name lookup failed\n",
				   sid_string_dbg(map->map->sid)));
		}

		if (!fltr_usr || !fltr_grp) {
			ret = NT_STATUS_NO_MEMORY;
			goto out;
		}

		idx++;
	}

	if (cnt_usr == IDMAP_LDAP_MAX_IDS || (cnt_usr != 0 && !ids[idx])) {
		const char *attrs[] = { NULL, /* uid or cn */
					"uidNumber",
					NULL };
		LDAPMessage *result;

		fltr_usr = talloc_strdup_append(fltr_usr, "))");
		if (!fltr_usr) {
			ret = NT_STATUS_NO_MEMORY;
			goto out;
		}

		attrs[0] = ctx->user_cn ? "cn" : "uid";
		ret = ctx->search(ctx, ctx->bind_path_user, fltr_usr, attrs,
				  &result);
		if (!NT_STATUS_IS_OK(ret)) {
			goto out;
		}

		idmap_rfc2307_map_xid_results(ctx, mem_ctx, &ids[bidx],
					      int_maps, result, dom,
					      attrs, ID_TYPE_UID);

		cnt_usr = 0;
		TALLOC_FREE(fltr_usr);
	}

	if (cnt_grp == IDMAP_LDAP_MAX_IDS || (cnt_grp != 0 && !ids[idx])) {
		const char *attrs[] = {"cn", "gidNumber", NULL };
		LDAPMessage *result;

		fltr_grp = talloc_strdup_append(fltr_grp, "))");
		if (!fltr_grp) {
			ret = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ret = ctx->search(ctx, ctx->bind_path_group, fltr_grp, attrs,
				  &result);
		if (!NT_STATUS_IS_OK(ret)) {
			goto out;
		}

		idmap_rfc2307_map_xid_results(ctx, mem_ctx, &ids[bidx],
					      int_maps, result, dom,
					      attrs, ID_TYPE_GID);
		cnt_grp = 0;
		TALLOC_FREE(fltr_grp);
	}

	if (ids[idx]) {
		goto again;
	}

	ret = NT_STATUS_OK;

out:
	talloc_free(mem_ctx);
	return ret;
}

static int idmap_rfc2307_context_destructor(struct idmap_rfc2307_context *ctx)
{
	if (ctx->ads != NULL) {
		/* we own this ADS_STRUCT so make sure it goes away */
		ctx->ads->is_mine = True;
		ads_destroy( &ctx->ads );
		ctx->ads = NULL;
	}

	if (ctx->smbldap_state != NULL) {
		smbldap_free_struct(&ctx->smbldap_state);
	}

	return 0;
}

static NTSTATUS idmap_rfc2307_initialize(struct idmap_domain *domain)
{
	struct idmap_rfc2307_context *ctx;
	char *cfg_opt;
	const char *bind_path_user, *bind_path_group, *ldap_server;
	NTSTATUS status;

	ctx = talloc_zero(domain, struct idmap_rfc2307_context);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(ctx, idmap_rfc2307_context_destructor);

	cfg_opt = talloc_asprintf(ctx, "idmap config %s", domain->name);
	if (cfg_opt == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	bind_path_user = lp_parm_const_string(-1, cfg_opt, "bind_path_user",
					      NULL);
	if (bind_path_user) {
		ctx->bind_path_user = talloc_strdup(ctx, bind_path_user);
		if (ctx->bind_path_user == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}
	} else {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err;
	}

	bind_path_group = lp_parm_const_string(-1, cfg_opt, "bind_path_group",
					       NULL);
	if (bind_path_group) {
		ctx->bind_path_group = talloc_strdup(ctx, bind_path_group);
		if (ctx->bind_path_group == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}
	} else {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err;
	}

	ldap_server = lp_parm_const_string(-1, cfg_opt, "ldap_server", NULL);
	if (!ldap_server) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err;
	}

	if (strcmp(ldap_server, "stand-alone") == 0) {
		status = idmap_rfc2307_init_ldap(ctx, domain, cfg_opt);

	} else if (strcmp(ldap_server, "ad") == 0) {
		status = idmap_rfc2307_init_ads(ctx, cfg_opt);

	} else {
		status = NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto err;
	}

	ctx->cn_realm = lp_parm_bool(-1, cfg_opt, "cn_realm", false);
	ctx->user_cn = lp_parm_bool(-1, cfg_opt, "user_cn", false);

	domain->private_data = ctx;
	talloc_free(cfg_opt);
	return NT_STATUS_OK;

err:
	talloc_free(cfg_opt);
	talloc_free(ctx);
	return status;
}

static struct idmap_methods rfc2307_methods = {
	.init = idmap_rfc2307_initialize,
	.unixids_to_sids = idmap_rfc2307_unixids_to_sids,
	.sids_to_unixids = idmap_rfc2307_sids_to_unixids,
};

NTSTATUS idmap_rfc2307_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "rfc2307",
				  &rfc2307_methods);
}
