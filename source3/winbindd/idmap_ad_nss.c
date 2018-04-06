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
#include "winbindd_ads.h"
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

/*
 * nss_info_{sfu,sfu20,rfc2307}
 */

/************************************************************************
 Initialize the {sfu,sfu20,rfc2307} state
 ***********************************************************************/

static const char *wb_posix_map_unknown_string = "WB_POSIX_MAP_UNKNOWN";
static const char *wb_posix_map_template_string = "WB_POSIX_MAP_TEMPLATE";
static const char *wb_posix_map_sfu_string = "WB_POSIX_MAP_SFU";
static const char *wb_posix_map_sfu20_string = "WB_POSIX_MAP_SFU20";
static const char *wb_posix_map_rfc2307_string = "WB_POSIX_MAP_RFC2307";
static const char *wb_posix_map_unixinfo_string = "WB_POSIX_MAP_UNIXINFO";

static const char *ad_map_type_string(enum wb_posix_mapping map_type)
{
	switch (map_type) {
		case WB_POSIX_MAP_TEMPLATE:
			return wb_posix_map_template_string;
		case WB_POSIX_MAP_SFU:
			return wb_posix_map_sfu_string;
		case WB_POSIX_MAP_SFU20:
			return wb_posix_map_sfu20_string;
		case WB_POSIX_MAP_RFC2307:
			return wb_posix_map_rfc2307_string;
		case WB_POSIX_MAP_UNIXINFO:
			return wb_posix_map_unixinfo_string;
		default:
			return wb_posix_map_unknown_string;
	}
}

static NTSTATUS nss_ad_generic_init(struct nss_domain_entry *e,
				    enum wb_posix_mapping new_ad_map_type)
{
	struct idmap_domain *dom;
	struct idmap_ad_context *ctx;

	if (e->state != NULL) {
		dom = talloc_get_type(e->state, struct idmap_domain);
	} else {
		dom = talloc_zero(e, struct idmap_domain);
		if (dom == NULL) {
			DEBUG(0, ("Out of memory!\n"));
			return NT_STATUS_NO_MEMORY;
		}
		e->state = dom;
	}

	if (e->domain != NULL) {
		dom->name = talloc_strdup(dom, e->domain);
		if (dom->name == NULL) {
			DEBUG(0, ("Out of memory!\n"));
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (dom->private_data != NULL) {
		ctx = talloc_get_type(dom->private_data,
				      struct idmap_ad_context);
	} else {
		ctx = talloc_zero(dom, struct idmap_ad_context);
		if (ctx == NULL) {
			DEBUG(0, ("Out of memory!\n"));
			return NT_STATUS_NO_MEMORY;
		}
		ctx->ad_map_type = WB_POSIX_MAP_RFC2307;
		dom->private_data = ctx;
	}

	if ((ctx->ad_map_type != WB_POSIX_MAP_UNKNOWN) &&
	    (ctx->ad_map_type != new_ad_map_type))
	{
		DEBUG(2, ("nss_ad_generic_init: "
			  "Warning: overriding previously set posix map type "
			  "%s for domain %s with map type %s.\n",
			  ad_map_type_string(ctx->ad_map_type),
			  dom->name,
			  ad_map_type_string(new_ad_map_type)));
	}

	ctx->ad_map_type = new_ad_map_type;

	return NT_STATUS_OK;
}

static NTSTATUS nss_sfu_init( struct nss_domain_entry *e )
{
	return nss_ad_generic_init(e, WB_POSIX_MAP_SFU);
}

static NTSTATUS nss_sfu20_init( struct nss_domain_entry *e )
{
	return nss_ad_generic_init(e, WB_POSIX_MAP_SFU20);
}

static NTSTATUS nss_rfc2307_init( struct nss_domain_entry *e )
{
	return nss_ad_generic_init(e, WB_POSIX_MAP_RFC2307);
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS nss_ad_map_to_alias(TALLOC_CTX *mem_ctx,
				    struct nss_domain_entry *e,
				    const char *name,
				    char **alias)
{
	const char *attrs[] = {NULL, /* attr_uid */
			       NULL };
	char *filter = NULL;
	LDAPMessage *msg = NULL;
	ADS_STATUS ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct idmap_domain *dom;
	struct idmap_ad_context *ctx = NULL;

	/* Check incoming parameters */

	if ( !e || !e->domain || !name || !*alias) {
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* Only do query if we are online */

	if (idmap_is_offline())	{
		nt_status = NT_STATUS_FILE_IS_OFFLINE;
		goto done;
	}

	dom = talloc_get_type(e->state, struct idmap_domain);
	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);

	ads_status = ad_idmap_cached_connection(dom);
	if (!ADS_ERR_OK(ads_status)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!ctx->ad_schema) {
		nt_status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto done;
	}

	attrs[0] = ctx->ad_schema->posix_uid_attr;

	filter = talloc_asprintf(mem_ctx,
				 "(sAMAccountName=%s)",
				 name);
	if (!filter) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ads_status = ads_search_retry(ctx->ads, &msg, filter, attrs);
	if (!ADS_ERR_OK(ads_status)) {
		nt_status = ads_ntstatus(ads_status);
		goto done;
	}

	*alias = ads_pull_string(ctx->ads, mem_ctx, msg, ctx->ad_schema->posix_uid_attr);

	if (!*alias) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	nt_status = NT_STATUS_OK;

done:
	if (filter) {
		talloc_destroy(filter);
	}
	if (msg) {
		ads_msgfree(ctx->ads, msg);
	}

	return nt_status;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS nss_ad_map_from_alias( TALLOC_CTX *mem_ctx,
					     struct nss_domain_entry *e,
					     const char *alias,
					     char **name )
{
	const char *attrs[] = {"sAMAccountName",
			       NULL };
	char *filter = NULL;
	LDAPMessage *msg = NULL;
	ADS_STATUS ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	char *username = NULL;
	struct idmap_domain *dom;
	struct idmap_ad_context *ctx = NULL;

	/* Check incoming parameters */

	if ( !alias || !name) {
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* Only do query if we are online */

	if (idmap_is_offline())	{
		nt_status = NT_STATUS_FILE_IS_OFFLINE;
		goto done;
	}

	dom = talloc_get_type(e->state, struct idmap_domain);
	ctx = talloc_get_type(dom->private_data, struct idmap_ad_context);

	ads_status = ad_idmap_cached_connection(dom);
	if (!ADS_ERR_OK(ads_status)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!ctx->ad_schema) {
		nt_status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto done;
	}

	filter = talloc_asprintf(mem_ctx,
				 "(%s=%s)",
				 ctx->ad_schema->posix_uid_attr,
				 alias);
	if (!filter) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ads_status = ads_search_retry(ctx->ads, &msg, filter, attrs);
	if (!ADS_ERR_OK(ads_status)) {
		nt_status = ads_ntstatus(ads_status);
		goto done;
	}

	username = ads_pull_string(ctx->ads, mem_ctx, msg,
				   "sAMAccountName");
	if (!username) {
		nt_status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	*name = talloc_asprintf(mem_ctx, "%s\\%s",
				lp_workgroup(),
				username);
	if (!*name) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	nt_status = NT_STATUS_OK;

done:
	TALLOC_FREE(username);
	TALLOC_FREE(filter);
	if (msg) {
		ads_msgfree(ctx->ads, msg);
	}

	return nt_status;
}

/************************************************************************
 Function dispatch tables for the idmap and nss plugins
 ***********************************************************************/

/* The SFU and RFC2307 NSS plugins share everything but the init
   function which sets the intended schema model to use */

static struct nss_info_methods nss_rfc2307_methods = {
	.init           = nss_rfc2307_init,
	.map_to_alias   = nss_ad_map_to_alias,
	.map_from_alias = nss_ad_map_from_alias,
};

static struct nss_info_methods nss_sfu_methods = {
	.init           = nss_sfu_init,
	.map_to_alias   = nss_ad_map_to_alias,
	.map_from_alias = nss_ad_map_from_alias,
};

static struct nss_info_methods nss_sfu20_methods = {
	.init           = nss_sfu20_init,
	.map_to_alias   = nss_ad_map_to_alias,
	.map_from_alias = nss_ad_map_from_alias,
};



/************************************************************************
 Initialize the plugins
 ***********************************************************************/

NTSTATUS idmap_ad_nss_init(TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	status = smb_register_idmap_nss(SMB_NSS_INFO_INTERFACE_VERSION,
					"rfc2307",  &nss_rfc2307_methods);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smb_register_idmap_nss(SMB_NSS_INFO_INTERFACE_VERSION,
					"sfu",  &nss_sfu_methods);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smb_register_idmap_nss(SMB_NSS_INFO_INTERFACE_VERSION,
					"sfu20",  &nss_sfu20_methods);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
