/*
 * idmap_ad: map between Active Directory and RFC 2307 accounts
 *
 * Copyright (C) Volker Lendecke 2015
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
#include "libsmb/namequery.h"
#include "idmap.h"
#include "tldap.h"
#include "tldap_util.h"
#include "tldap_tls_connect.h"
#include "tldap_gensec_bind.h"
#include "passdb.h"
#include "lib/param/param.h"
#include "auth/gensec/gensec.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "libads/ldap_schema_oids.h"
#include "../libds/common/flags.h"
#include "libcli/ldap/ldap_ndr.h"
#include "libcli/security/dom_sid.h"
#include "source3/libads/sitename_cache.h"
#include "source3/libads/kerberos_proto.h"
#include "source3/librpc/gen_ndr/ads.h"
#include "source3/lib/global_contexts.h"
#include <ldb.h>
#include "source4/lib/tls/tls.h"

struct idmap_ad_schema_names;

struct idmap_ad_context {
	struct idmap_domain *dom;
	struct tldap_context *ld;
	struct idmap_ad_schema_names *schema;
	const char *default_nc;

	bool unix_primary_group;
	bool unix_nss_info;
	int ldap_timeout;

	struct ldb_context *ldb;
	struct ldb_dn **deny_ous;
	struct ldb_dn **allow_ous;
};

static NTSTATUS idmap_ad_get_context(struct idmap_domain *dom,
				     struct idmap_ad_context **pctx);

static char *get_schema_path(TALLOC_CTX *mem_ctx, struct tldap_context *ld)
{
	struct tldap_message *rootdse;

	rootdse = tldap_rootdse(ld);
	if (rootdse == NULL) {
		return NULL;
	}

	return tldap_talloc_single_attribute(rootdse, "schemaNamingContext",
					     mem_ctx);
}

static char *get_default_nc(TALLOC_CTX *mem_ctx, struct tldap_context *ld)
{
	struct tldap_message *rootdse;

	rootdse = tldap_rootdse(ld);
	if (rootdse == NULL) {
		return NULL;
	}

	return tldap_talloc_single_attribute(rootdse, "defaultNamingContext",
					     mem_ctx);
}

struct idmap_ad_schema_names {
	char *name;
	char *uid;
	char *gid;
	char *gecos;
	char *dir;
	char *shell;
};

static TLDAPRC get_attrnames_by_oids(struct tldap_context *ld,
				     TALLOC_CTX *mem_ctx,
				     const char *schema_path,
				     size_t num_oids,
				     const char **oids,
				     char **names)
{
	char *filter;
	const char *attrs[] = { "lDAPDisplayName", "attributeId" };
	size_t i;
	TLDAPRC rc;
	struct tldap_message **msgs;
	size_t num_msgs;

	filter = talloc_strdup(mem_ctx, "(|");

	for (i=0; i<num_oids; i++) {
		talloc_asprintf_addbuf(&filter, "(attributeId=%s)", oids[i]);
	}
	talloc_asprintf_addbuf(&filter, ")");

	if (filter == NULL) {
		return TLDAP_NO_MEMORY;
	}

	rc = tldap_search(ld, schema_path, TLDAP_SCOPE_SUB, filter,
			  attrs, ARRAY_SIZE(attrs), 0, NULL, 0, NULL, 0,
			  0, 0, 0, mem_ctx, &msgs);;
	TALLOC_FREE(filter);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		return rc;
	}

	for (i=0; i<num_oids; i++) {
		names[i] = NULL;
	}

	num_msgs = talloc_array_length(msgs);

	for (i=0; i<num_msgs; i++) {
		struct tldap_message *msg = msgs[i];
		char *oid;
		size_t j;

		if (tldap_msg_type(msg) != TLDAP_RES_SEARCH_ENTRY) {
			/* Could be a TLDAP_RES_SEARCH_REFERENCE */
			continue;
		}

		oid = tldap_talloc_single_attribute(
			msg, "attributeId", msg);
		if (oid == NULL) {
			continue;
		}

		for (j=0; j<num_oids; j++) {
			if (strequal(oid, oids[j])) {
				break;
			}
		}
		TALLOC_FREE(oid);

		if (j == num_oids) {
			/* not found */
			continue;
		}

		names[j] = tldap_talloc_single_attribute(
			msg, "lDAPDisplayName", mem_ctx);
	}

	TALLOC_FREE(msgs);
	for (i=0; i<num_oids; i++) {
		if (names[i] == NULL) {
			DBG_ERR("Failed to retrieve schema name for "
				"oid [%s]. Schema mode is incorrect "
				"for this domain.\n", oids[i]);
			return TLDAP_FILTER_ERROR;
		}
	}

	return TLDAP_SUCCESS;
}

static TLDAPRC get_posix_schema_names(struct tldap_context *ld,
				      const char *schema_mode,
				      TALLOC_CTX *mem_ctx,
				      struct idmap_ad_schema_names **pschema)
{
	char *schema_path;
	struct idmap_ad_schema_names *schema;
	char *names[6];
	const char *oids_sfu[] = {
		ADS_ATTR_SFU_UIDNUMBER_OID,
		ADS_ATTR_SFU_GIDNUMBER_OID,
		ADS_ATTR_SFU_HOMEDIR_OID,
		ADS_ATTR_SFU_SHELL_OID,
		ADS_ATTR_SFU_GECOS_OID,
		ADS_ATTR_SFU_UID_OID
	};
	const char *oids_sfu20[] = {
		ADS_ATTR_SFU20_UIDNUMBER_OID,
		ADS_ATTR_SFU20_GIDNUMBER_OID,
		ADS_ATTR_SFU20_HOMEDIR_OID,
		ADS_ATTR_SFU20_SHELL_OID,
		ADS_ATTR_SFU20_GECOS_OID,
		ADS_ATTR_SFU20_UID_OID
	};
	const char *oids_rfc2307[] = {
		ADS_ATTR_RFC2307_UIDNUMBER_OID,
		ADS_ATTR_RFC2307_GIDNUMBER_OID,
		ADS_ATTR_RFC2307_HOMEDIR_OID,
		ADS_ATTR_RFC2307_SHELL_OID,
		ADS_ATTR_RFC2307_GECOS_OID,
		ADS_ATTR_RFC2307_UID_OID
	};
	const char **oids;

	TLDAPRC rc;

	schema = talloc(mem_ctx, struct idmap_ad_schema_names);
	if (schema == NULL) {
		return TLDAP_NO_MEMORY;
	}

	schema_path = get_schema_path(schema, ld);
	if (schema_path == NULL) {
		TALLOC_FREE(schema);
		return TLDAP_NO_MEMORY;
	}

	oids = oids_rfc2307;

	if ((schema_mode != NULL) && (schema_mode[0] != '\0')) {
		if (strequal(schema_mode, "sfu")) {
			oids = oids_sfu;
		} else if (strequal(schema_mode, "sfu20")) {
			oids = oids_sfu20;
		} else if (strequal(schema_mode, "rfc2307" )) {
			oids = oids_rfc2307;
		} else {
			DBG_WARNING("Unknown schema mode %s\n", schema_mode);
		}
	}

	rc = get_attrnames_by_oids(ld, schema, schema_path, 6, oids, names);
	TALLOC_FREE(schema_path);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		TALLOC_FREE(schema);
		return rc;
	}

	schema->uid = names[0];
	schema->gid = names[1];
	schema->dir = names[2];
	schema->shell = names[3];
	schema->gecos = names[4];
	schema->name = names[5];

	*pschema = schema;

	return TLDAP_SUCCESS;
}

static void PRINTF_ATTRIBUTE(3, 0) idmap_ad_tldap_debug(
	void *log_private,
	enum tldap_debug_level level,
	const char *fmt,
	va_list ap)
{
       int samba_level = -1;

       switch (level) {
       case TLDAP_DEBUG_FATAL:
               samba_level = DBGLVL_ERR;
               break;
       case TLDAP_DEBUG_ERROR:
               samba_level = DBGLVL_ERR;
               break;
       case TLDAP_DEBUG_WARNING:
               samba_level = DBGLVL_WARNING;
               break;
       case TLDAP_DEBUG_TRACE:
               samba_level = DBGLVL_DEBUG;
               break;
       }

       if (CHECK_DEBUGLVL(samba_level)) {
               char *s = NULL;
               int ret;

               ret = vasprintf(&s, fmt, ap);
               if (ret == -1) {
                       return;
               }
               DEBUG(samba_level, ("idmap_ad_tldap: %s", s));
               free(s);
       }
}

static NTSTATUS idmap_ad_get_tldap_ctx(TALLOC_CTX *mem_ctx,
				       const char *domname,
				       struct tldap_context **pld)
{
	struct netr_DsRGetDCNameInfo *dcinfo;
	struct sockaddr_storage dcaddr = {
		.ss_family = AF_UNSPEC,
	};
	struct sockaddr_storage *pdcaddr = NULL;
	struct winbindd_domain *creds_domain = NULL;
	struct cli_credentials *creds;
	struct loadparm_context *lp_ctx;
	struct tldap_context *ld;
	int tcp_port = 389;
	bool use_tls = false;
	bool use_starttls = false;
	int wrap_flags = -1;
	uint32_t gensec_features = 0;
	char *sitename = NULL;
	int fd;
	NTSTATUS status;
	bool ok;
	TLDAPRC rc;

	wrap_flags = lp_client_ldap_sasl_wrapping();

	if (wrap_flags & ADS_AUTH_SASL_LDAPS) {
		use_tls = true;
		tcp_port = 636;
	} else if (wrap_flags & ADS_AUTH_SASL_STARTTLS) {
		use_tls = true;
		use_starttls = true;
	}
	if (wrap_flags & ADS_AUTH_SASL_SEAL) {
		gensec_features |= GENSEC_FEATURE_SEAL;
	}
	if (wrap_flags & ADS_AUTH_SASL_SIGN) {
		gensec_features |= GENSEC_FEATURE_SIGN;
	}

	if (gensec_features != 0) {
		gensec_features |= GENSEC_FEATURE_LDAP_STYLE;
	}

	status = wb_dsgetdcname_gencache_get(mem_ctx, domname, &dcinfo);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Could not get dcinfo for %s: %s\n", domname,
			  nt_errstr(status));
		return status;
	}

	if (dcinfo->dc_unc == NULL) {
		TALLOC_FREE(dcinfo);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}
	if (dcinfo->dc_unc[0] == '\\') {
		dcinfo->dc_unc += 1;
	}
	if (dcinfo->dc_unc[0] == '\\') {
		dcinfo->dc_unc += 1;
	}

	ok = resolve_name(dcinfo->dc_unc, &dcaddr, 0x20, true);
	if (!ok) {
		DBG_DEBUG("Could not resolve name %s\n", dcinfo->dc_unc);
		TALLOC_FREE(dcinfo);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	sitename = sitename_fetch(talloc_tos(), lp_realm());

	/*
	 * create_local_private_krb5_conf_for_domain() can deal with
	 * sitename==NULL
	 */
	if (strequal(domname, lp_realm()) || strequal(domname, lp_workgroup()))
	{
		pdcaddr = &dcaddr;
	}

	ok = create_local_private_krb5_conf_for_domain(
		lp_realm(), lp_workgroup(), sitename, pdcaddr);
	TALLOC_FREE(sitename);
	if (!ok) {
		DBG_DEBUG("Could not create private krb5.conf\n");
		TALLOC_FREE(dcinfo);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	status = open_socket_out(&dcaddr, tcp_port, 10000, &fd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("open_socket_out failed: %s\n", nt_errstr(status));
		TALLOC_FREE(dcinfo);
		return status;
	}

	ld = tldap_context_create(dcinfo, fd);
	if (ld == NULL) {
		DBG_DEBUG("tldap_context_create failed\n");
		close(fd);
		TALLOC_FREE(dcinfo);
		return NT_STATUS_NO_MEMORY;
	}
	tldap_set_debug(ld, idmap_ad_tldap_debug, NULL);

	/*
	 * Here we use or own machine account as
	 * we run as domain member.
	 */
	creds_domain = find_our_domain();
	if (creds_domain == NULL) {
		DBG_ERR("find_our_domain() returned NULL\n");
		TALLOC_FREE(dcinfo);
		return NT_STATUS_INTERNAL_ERROR;
	}
	status = winbindd_get_trust_credentials(creds_domain,
						dcinfo,
						false, /* netlogon */
						false, /* ipc_fallback */
						&creds);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("winbindd_get_trust_credentials(%s) failed - %s\n",
			creds_domain->name, nt_errstr(status));
		TALLOC_FREE(dcinfo);
		return status;
	}

	lp_ctx = loadparm_init_s3(dcinfo, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DBG_DEBUG("loadparm_init_s3 failed\n");
		TALLOC_FREE(dcinfo);
		return NT_STATUS_NO_MEMORY;
	}

	if (use_tls && !tldap_has_tls_tstream(ld)) {
		struct tstream_tls_params *tls_params = NULL;

		if (use_starttls) {
		       rc = tldap_extended(ld,
					   LDB_EXTENDED_START_TLS_OID,
					   NULL,
					   NULL,
					   0,
					   NULL,
					   0,
					   NULL,
					   NULL,
					   NULL);
		       if (!TLDAP_RC_IS_SUCCESS(rc)) {
				DBG_ERR("tldap_extended(%s) failed: %s\n",
					LDB_EXTENDED_START_TLS_OID,
					tldap_errstr(talloc_tos(), ld, rc));
				return NT_STATUS_LDAP(TLDAP_RC_V(rc));
		       }
		}

		status = tstream_tls_params_client_lpcfg(talloc_tos(),
							 lp_ctx,
							 dcinfo->dc_unc,
							 &tls_params);
		if (!NT_STATUS_IS_OK(status)) {
		       DBG_ERR("tstream_tls_params_client_lpcfg failed: %s\n",
			       nt_errstr(status));
		       TALLOC_FREE(dcinfo);
		       return status;
		}

		rc = tldap_tls_connect(ld, tls_params);
		if (!TLDAP_RC_IS_SUCCESS(rc)) {
			DBG_ERR("tldap_gensec_bind(%s) failed: %s\n",
				dcinfo->dc_unc,
				tldap_errstr(dcinfo, ld, rc));
			TALLOC_FREE(dcinfo);
			return NT_STATUS_LDAP(TLDAP_RC_V(rc));
		}
	}

	rc = tldap_gensec_bind(ld, creds, "ldap", dcinfo->dc_unc, NULL, lp_ctx,
			       gensec_features);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		DBG_DEBUG("tldap_gensec_bind failed: %s\n",
			  tldap_errstr(dcinfo, ld, rc));
		TALLOC_FREE(dcinfo);
		return NT_STATUS_LDAP(TLDAP_RC_V(rc));
	}

	rc = tldap_fetch_rootdse(ld);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		DBG_DEBUG("tldap_fetch_rootdse failed: %s\n",
			  tldap_errstr(dcinfo, ld, rc));
		TALLOC_FREE(dcinfo);
		return NT_STATUS_LDAP(TLDAP_RC_V(rc));
	}

	*pld = talloc_move(mem_ctx, &ld);
	TALLOC_FREE(dcinfo);
	return NT_STATUS_OK;
}

static int idmap_ad_context_destructor(struct idmap_ad_context *ctx)
{
	if ((ctx->dom != NULL) && (ctx->dom->private_data == ctx)) {
		ctx->dom->private_data = NULL;
	}
	return 0;
}

static struct ldb_dn **str_list_to_dns(TALLOC_CTX *mem_ctx,
				       const char *dbgmsg,
				       struct ldb_context *ldb,
				       const char **strlist)
{
	size_t i, num_dns = str_list_length(strlist);
	char *dbgstr = NULL;
	struct ldb_dn **dns = NULL;

	dns = talloc_array(mem_ctx, struct ldb_dn *, num_dns);
	if (dns == NULL) {
		TALLOC_FREE(dbgstr);
		return NULL;
	}

	dbgstr = talloc_strdup(talloc_tos(), "");

	for (i = 0; i < num_dns; i++) {
		dns[i] = ldb_dn_new(dns, ldb, strlist[i]);
		if (dns[i] == NULL) {
			DBG_WARNING("ldb_dn_new(%s) failed\n", strlist[i]);
			TALLOC_FREE(dns);
			return NULL;
		}
		talloc_asprintf_addbuf(
			&dbgstr,
			"%s ",
			ldb_dn_get_extended_linearized(dbgstr, dns[i], 1));
	}

	DBG_DEBUG("%s %s\n", dbgmsg, dbgstr);
	TALLOC_FREE(dbgstr);

	return dns;
}

static NTSTATUS idmap_ad_context_create(TALLOC_CTX *mem_ctx,
					struct idmap_domain *dom,
					const char *domname,
					struct idmap_ad_context **pctx)
{
	struct idmap_ad_context *ctx;
	const char *schema_mode;
	const char **allow = NULL;
	const char **deny = NULL;
	NTSTATUS status;
	TLDAPRC rc;

	ctx = talloc_zero(mem_ctx, struct idmap_ad_context);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ctx->dom = dom;

	talloc_set_destructor(ctx, idmap_ad_context_destructor);

	status = idmap_ad_get_tldap_ctx(ctx, domname, &ctx->ld);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("idmap_ad_get_tldap_ctx failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	ctx->default_nc = get_default_nc(ctx, ctx->ld);
	if (ctx->default_nc == NULL) {
		DBG_DEBUG("No default nc\n");
		TALLOC_FREE(ctx);
		return status;
	}

	ctx->unix_primary_group = idmap_config_bool(
		domname, "unix_primary_group", false);
	ctx->unix_nss_info = idmap_config_bool(
		domname, "unix_nss_info", false);
	ctx->ldap_timeout = idmap_config_int(
		domname, "ldap_timeout", 10);

	schema_mode = idmap_config_const_string(
		domname, "schema_mode", "rfc2307");

	rc = get_posix_schema_names(ctx->ld, schema_mode, ctx, &ctx->schema);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		DBG_DEBUG("get_posix_schema_names failed: %s\n",
			  tldap_errstr(ctx, ctx->ld, rc));
		TALLOC_FREE(ctx);
		return NT_STATUS_LDAP(TLDAP_RC_V(rc));
	}

	deny = idmap_config_string_list(domname, "deny ous", NULL);
	allow = idmap_config_string_list(domname, "allow ous", NULL);

	if ((deny != NULL) || (allow != NULL)) {
		int ret = ldb_global_init();
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			DBG_WARNING("ldb_global_init() failed: %s\n",
				    strerror(errno));
			TALLOC_FREE(ctx);
			return status;
		}

		ctx->ldb = ldb_init(ctx, global_event_context());
		if (ctx->ldb == NULL) {
			status = map_nt_error_from_unix(errno);
			DBG_WARNING("ldb_init() failed: %s\n", strerror(errno));
			TALLOC_FREE(ctx);
			return status;
		}
	}

	if (deny != NULL) {
		ctx->deny_ous = str_list_to_dns(ctx, "Denying", ctx->ldb, deny);
		if (ctx->deny_ous == NULL) {
			DBG_DEBUG("str_list_to_dns failed\n");
			TALLOC_FREE(ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (allow != NULL) {
		ctx->allow_ous =
			str_list_to_dns(ctx, "Allowing", ctx->ldb, allow);
		if (ctx->allow_ous == NULL) {
			DBG_DEBUG("str_list_to_dns failed\n");
			TALLOC_FREE(ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*pctx = ctx;
	return NT_STATUS_OK;
}

static bool check_dn(struct ldb_dn **dns, struct ldb_dn *dn)
{
	size_t i, num_dns = talloc_array_length(dns);

	for (i = 0; i < num_dns; i++) {
		struct ldb_dn *base = dns[i];
		int ret = ldb_dn_compare_base(base, dn);
		if (ret == 0) {
			return true;
		}
	}
	return false;
}

static bool idmap_ad_dn_filter(struct idmap_domain *dom, const char *dnstr)
{
	struct idmap_ad_context *ctx = NULL;
	struct ldb_dn *dn = NULL;
	NTSTATUS status;
	bool result = false;

	status = idmap_ad_get_context(dom, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("idmap_ad_get_context failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	if ((ctx->allow_ous == NULL) && (ctx->deny_ous == NULL)) {
		/*
		 * Nothing to check
		 */
		return true;
	}

	dn = ldb_dn_new(talloc_tos(), ctx->ldb, dnstr);
	if (dn == NULL) {
		DBG_DEBUG("ldb_dn_new(%s) failed\n", dnstr);
		return false;
	}

	if (ctx->deny_ous != NULL) {
		bool denied = check_dn(ctx->deny_ous, dn);
		if (denied) {
			DBG_WARNING("Denied %s\n", dnstr);
			TALLOC_FREE(dn);
			return false;
		}

		if (ctx->allow_ous == NULL) {
			/*
			 * Only a few denied OUs around, allow by
			 * default
			 */
			result = true;
		}
	}

	if (ctx->allow_ous != NULL) {
		bool allowed = check_dn(ctx->allow_ous, dn);
		if (allowed) {
			return true;
		}
		DBG_WARNING("Did not allow %s\n", dnstr);
	}

	return result;
}

static NTSTATUS idmap_ad_query_user(struct idmap_domain *domain,
				    struct wbint_userinfo *info)
{
	struct idmap_ad_context *ctx;
	TLDAPRC rc;
	NTSTATUS status;
	char *sidstr, *filter;
	const char *attrs[4];
	size_t i, num_msgs;
	struct tldap_message **msgs;

	status = idmap_ad_get_context(domain, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!(ctx->unix_primary_group || ctx->unix_nss_info)) {
		return NT_STATUS_OK;
	}

	attrs[0] = ctx->schema->gid;
	attrs[1] = ctx->schema->gecos;
	attrs[2] = ctx->schema->dir;
	attrs[3] = ctx->schema->shell;

	sidstr = ldap_encode_ndr_dom_sid(talloc_tos(), &info->user_sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	filter = talloc_asprintf(talloc_tos(), "(objectsid=%s)", sidstr);
	TALLOC_FREE(sidstr);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("Filter: [%s]\n", filter);

	rc = tldap_search(ctx->ld, ctx->default_nc, TLDAP_SCOPE_SUB, filter,
			  attrs, ARRAY_SIZE(attrs), 0, NULL, 0, NULL, 0,
			  ctx->ldap_timeout, 0, 0, talloc_tos(), &msgs);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		return NT_STATUS_LDAP(TLDAP_RC_V(rc));
	}

	TALLOC_FREE(filter);

	num_msgs = talloc_array_length(msgs);

	for (i=0; i<num_msgs; i++) {
		struct tldap_message *msg = msgs[i];
		char *dn = NULL;
		bool ok;

		if (tldap_msg_type(msg) != TLDAP_RES_SEARCH_ENTRY) {
			continue;
		}
		ok = tldap_entry_dn(msg, &dn);
		if (!ok) {
			continue;
		}
		ok = idmap_ad_dn_filter(domain, dn);
		if (!ok) {
			DBG_DEBUG("%s filtered out\n", dn);
			continue;
		}

		if (ctx->unix_primary_group) {
			uint32_t gid;

			ok = tldap_pull_uint32(msg, ctx->schema->gid, &gid);
			if (ok) {
				DBG_DEBUG("Setting primary group "
					  "to %"PRIu32" from attr %s\n",
					  gid, ctx->schema->gid);
				info->primary_gid = gid;
			}
		}

		if (ctx->unix_nss_info) {
			char *attr;

			attr = tldap_talloc_single_attribute(
				msg, ctx->schema->dir, talloc_tos());
			if (attr != NULL) {
				info->homedir = talloc_move(info, &attr);
			}
			TALLOC_FREE(attr);

			attr = tldap_talloc_single_attribute(
				msg, ctx->schema->shell, talloc_tos());
			if (attr != NULL) {
				info->shell = talloc_move(info, &attr);
			}
			TALLOC_FREE(attr);

			attr = tldap_talloc_single_attribute(
				msg, ctx->schema->gecos, talloc_tos());
			if (attr != NULL) {
				info->full_name = talloc_move(info, &attr);
			}
			TALLOC_FREE(attr);
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS idmap_ad_query_user_retry(struct idmap_domain *domain,
				          struct wbint_userinfo *info)
{
	const NTSTATUS status_server_down =
		NT_STATUS_LDAP(TLDAP_RC_V(TLDAP_SERVER_DOWN));
	const NTSTATUS status_timeout =
		NT_STATUS_LDAP(TLDAP_RC_V(TLDAP_TIMEOUT));
	NTSTATUS status;

	status = idmap_ad_query_user(domain, info);

	if (NT_STATUS_EQUAL(status, status_server_down) ||
	    NT_STATUS_EQUAL(status, status_timeout))
	{
		TALLOC_FREE(domain->private_data);
		return NT_STATUS_HOST_UNREACHABLE;
	}

	return status;
}

static NTSTATUS idmap_ad_initialize(struct idmap_domain *dom)
{
	dom->query_user = idmap_ad_query_user_retry;
	dom->private_data = NULL;
	return NT_STATUS_OK;
}

static NTSTATUS idmap_ad_get_context(struct idmap_domain *dom,
				     struct idmap_ad_context **pctx)
{
	struct idmap_ad_context *ctx = NULL;
	NTSTATUS status;

	if (IS_AD_DC) {
		/*
		 * Make sure we never try to use LDAP against
		 * a trusted domain as AD_DC.
		 *
		 * This shouldn't be called currently,
		 * but you never know what happens in future.
		 */
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	if (dom->private_data != NULL) {
		*pctx = talloc_get_type_abort(dom->private_data,
					      struct idmap_ad_context);
		return NT_STATUS_OK;
	}

	status = idmap_ad_context_create(dom, dom, dom->name, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("idmap_ad_context_create failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	dom->private_data = ctx;
	*pctx = ctx;
	return NT_STATUS_OK;
}

static NTSTATUS idmap_ad_unixids_to_sids(struct idmap_domain *dom,
					 struct id_map **ids)
{
	struct idmap_ad_context *ctx;
	TLDAPRC rc;
	NTSTATUS status;
	struct tldap_message **msgs;

	size_t i, num_msgs;
	char *u_filter, *g_filter, *filter;

	const char *attrs[] = {
		"sAMAccountType",
		"objectSid",
		NULL, /* attr_uidnumber */
		NULL, /* attr_gidnumber */
	};

	status = idmap_ad_get_context(dom, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	attrs[2] = ctx->schema->uid;
	attrs[3] = ctx->schema->gid;

	u_filter = talloc_strdup(talloc_tos(), "");
	if (u_filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	g_filter = talloc_strdup(talloc_tos(), "");
	if (g_filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; ids[i] != NULL; i++) {
		struct id_map *id = ids[i];

		id->status = ID_UNKNOWN;

		switch (id->xid.type) {
		    case ID_TYPE_UID: {
			    u_filter = talloc_asprintf_append_buffer(
				    u_filter, "(%s=%ju)", ctx->schema->uid,
				    (uintmax_t)id->xid.id);
			    if (u_filter == NULL) {
				    return NT_STATUS_NO_MEMORY;
			    }
			    break;
		    }

		    case ID_TYPE_GID: {
			    g_filter = talloc_asprintf_append_buffer(
				    g_filter, "(%s=%ju)", ctx->schema->gid,
				    (uintmax_t)id->xid.id);
			    if (g_filter == NULL) {
				    return NT_STATUS_NO_MEMORY;
			    }
			    break;
		    }

		    default:
			    DBG_WARNING("Unknown id type: %u\n",
					(unsigned)id->xid.type);
			    break;
		}
	}

	filter = talloc_strdup(talloc_tos(), "(|");
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (*u_filter != '\0') {
		filter = talloc_asprintf_append_buffer(
			filter,
			"(&(|(sAMAccountType=%d)(sAMAccountType=%d)"
			"(sAMAccountType=%d))(|%s))",
			ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST,
			ATYPE_INTERDOMAIN_TRUST, u_filter);
		if (filter == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	TALLOC_FREE(u_filter);

	if (*g_filter != '\0') {
		filter = talloc_asprintf_append_buffer(
			filter,
			"(&(|(sAMAccountType=%d)(sAMAccountType=%d))(|%s))",
			ATYPE_SECURITY_GLOBAL_GROUP,
			ATYPE_SECURITY_LOCAL_GROUP,
			g_filter);
		if (filter == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	TALLOC_FREE(g_filter);

	filter = talloc_asprintf_append_buffer(filter, ")");
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("Filter: [%s]\n", filter);

	rc = tldap_search(ctx->ld, ctx->default_nc, TLDAP_SCOPE_SUB, filter,
			  attrs, ARRAY_SIZE(attrs), 0, NULL, 0, NULL, 0,
			  ctx->ldap_timeout, 0, 0, talloc_tos(), &msgs);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		return NT_STATUS_LDAP(TLDAP_RC_V(rc));
	}

	TALLOC_FREE(filter);

	num_msgs = talloc_array_length(msgs);

	for (i=0; i<num_msgs; i++) {
		struct tldap_message *msg = msgs[i];
		char *dn;
		struct id_map *map;
		struct dom_sid sid;
		size_t j;
		bool ok;
		uint32_t atype, xid;
		enum id_type type;
		struct dom_sid_buf sidbuf;

		if (tldap_msg_type(msg) != TLDAP_RES_SEARCH_ENTRY) {
			continue;
		}

		ok = tldap_entry_dn(msg, &dn);
		if (!ok) {
			DBG_DEBUG("No dn found in msg %zu\n", i);
			continue;
		}

		ok = idmap_ad_dn_filter(dom, dn);
		if (!ok) {
			DBG_DEBUG("%s filtered out\n", dn);
			continue;
		}

		ok = tldap_pull_uint32(msg, "sAMAccountType", &atype);
		if (!ok) {
			DBG_DEBUG("No atype in object %s\n", dn);
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
			    DBG_WARNING("unrecognized SAM account type %08x\n",
					atype);
			continue;
		}

		ok = tldap_pull_uint32(msg, (type == ID_TYPE_UID) ?
				       ctx->schema->uid : ctx->schema->gid,
				       &xid);
		if (!ok) {
			DBG_WARNING("No unix id in object %s\n", dn);
			continue;
		}

		ok = tldap_pull_binsid(msg, "objectSid", &sid);
		if (!ok) {
			DBG_DEBUG("No objectSid in object %s\n", dn);
			continue;
		}

		map = NULL;
		for (j=0; ids[j]; j++) {
			if ((type == ids[j]->xid.type) &&
			    (xid == ids[j]->xid.id)) {
				map = ids[j];
				break;
			}
		}
		if (map == NULL) {
			DBG_DEBUG("Got unexpected sid %s from object %s\n",
				  dom_sid_str_buf(&sid, &sidbuf),
				  dn);
			continue;
		}

		sid_copy(map->sid, &sid);
		map->status = ID_MAPPED;

		DBG_DEBUG("Mapped %s -> %ju (%d)\n",
			  dom_sid_str_buf(map->sid, &sidbuf),
			  (uintmax_t)map->xid.id, map->xid.type);
	}

	TALLOC_FREE(msgs);

	return NT_STATUS_OK;
}

static NTSTATUS idmap_ad_sids_to_unixids(struct idmap_domain *dom,
					 struct id_map **ids)
{
	struct idmap_ad_context *ctx;
	TLDAPRC rc;
	NTSTATUS status;
	struct tldap_message **msgs;

	char *filter;
	size_t i, num_msgs;

	const char *attrs[] = {
		"sAMAccountType",
		"objectSid",
		NULL, /* attr_uidnumber */
		NULL, /* attr_gidnumber */
	};

	status = idmap_ad_get_context(dom, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	attrs[2] = ctx->schema->uid;
	attrs[3] = ctx->schema->gid;

	filter = talloc_asprintf(
		talloc_tos(),
		"(&(|(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d)"
		"(sAMAccountType=%d)(sAMAccountType=%d))(|",
		ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST,
		ATYPE_INTERDOMAIN_TRUST, ATYPE_SECURITY_GLOBAL_GROUP,
		ATYPE_SECURITY_LOCAL_GROUP);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; ids[i]; i++) {
		char *sidstr;

		ids[i]->status = ID_UNKNOWN;

		sidstr = ldap_encode_ndr_dom_sid(talloc_tos(), ids[i]->sid);
		if (sidstr == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		filter = talloc_asprintf_append_buffer(
			filter, "(objectSid=%s)", sidstr);
		TALLOC_FREE(sidstr);
		if (filter == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	filter = talloc_asprintf_append_buffer(filter, "))");
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("Filter: [%s]\n", filter);

	rc = tldap_search(ctx->ld, ctx->default_nc, TLDAP_SCOPE_SUB, filter,
			  attrs, ARRAY_SIZE(attrs), 0, NULL, 0, NULL, 0,
			  ctx->ldap_timeout, 0, 0, talloc_tos(), &msgs);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		return NT_STATUS_LDAP(TLDAP_RC_V(rc));
	}

	TALLOC_FREE(filter);

	num_msgs = talloc_array_length(msgs);

	for (i=0; i<num_msgs; i++) {
		struct tldap_message *msg = msgs[i];
		char *dn;
		struct id_map *map;
		struct dom_sid sid;
		size_t j;
		bool ok;
		uint64_t account_type, xid;
		enum id_type type;
		struct dom_sid_buf buf;

		if (tldap_msg_type(msg) != TLDAP_RES_SEARCH_ENTRY) {
			continue;
		}

		ok = tldap_entry_dn(msg, &dn);
		if (!ok) {
			DBG_DEBUG("No dn found in msg %zu\n", i);
			continue;
		}

		ok = idmap_ad_dn_filter(dom, dn);
		if (!ok) {
			DBG_DEBUG("%s filtered out\n", dn);
			continue;
		}

		ok = tldap_pull_binsid(msg, "objectSid", &sid);
		if (!ok) {
			DBG_DEBUG("No objectSid in object %s\n", dn);
			continue;
		}

		map = NULL;
		for (j=0; ids[j]; j++) {
			if (dom_sid_equal(&sid, ids[j]->sid)) {
				map = ids[j];
				break;
			}
		}
		if (map == NULL) {
			DBG_DEBUG("Got unexpected sid %s from object %s\n",
				  dom_sid_str_buf(&sid, &buf),
				  dn);
			continue;
		}

		ok = tldap_pull_uint64(msg, "sAMAccountType", &account_type);
		if (!ok) {
			DBG_DEBUG("No sAMAccountType in %s\n", dn);
			continue;
		}

		switch (account_type & 0xF0000000) {
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
			DBG_WARNING("unrecognized SAM account type %"PRIu64"\n",
				    account_type);
			continue;
		}

		ok = tldap_pull_uint64(msg,
				       type == ID_TYPE_UID ?
				       ctx->schema->uid : ctx->schema->gid,
				       &xid);
		if (!ok) {
			DBG_DEBUG("No xid in %s\n", dn);
			continue;
		}

		/* mapped */
		map->xid.type = type;
		map->xid.id = xid;
		map->status = ID_MAPPED;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n",
			   dom_sid_str_buf(map->sid, &buf),
			   (unsigned long)map->xid.id, map->xid.type));
	}

	TALLOC_FREE(msgs);

	return NT_STATUS_OK;
}

static NTSTATUS idmap_ad_unixids_to_sids_retry(struct idmap_domain *dom,
					       struct id_map **ids)
{
	const NTSTATUS status_server_down =
		NT_STATUS_LDAP(TLDAP_RC_V(TLDAP_SERVER_DOWN));
	const NTSTATUS status_timeout =
		NT_STATUS_LDAP(TLDAP_RC_V(TLDAP_TIMEOUT));
	NTSTATUS status;

	status = idmap_ad_unixids_to_sids(dom, ids);

	if (NT_STATUS_EQUAL(status, status_server_down) ||
	    NT_STATUS_EQUAL(status, status_timeout))
	{
		TALLOC_FREE(dom->private_data);
		return NT_STATUS_HOST_UNREACHABLE;
	}

	return status;
}

static NTSTATUS idmap_ad_sids_to_unixids_retry(struct idmap_domain *dom,
					       struct id_map **ids)
{
	const NTSTATUS status_server_down =
		NT_STATUS_LDAP(TLDAP_RC_V(TLDAP_SERVER_DOWN));
	const NTSTATUS status_timeout =
		NT_STATUS_LDAP(TLDAP_RC_V(TLDAP_TIMEOUT));
	NTSTATUS status;

	status = idmap_ad_sids_to_unixids(dom, ids);

	if (NT_STATUS_EQUAL(status, status_server_down) ||
	    NT_STATUS_EQUAL(status, status_timeout))
	{
		TALLOC_FREE(dom->private_data);
		return NT_STATUS_HOST_UNREACHABLE;
	}

	return status;
}

static const struct idmap_methods ad_methods = {
	.init            = idmap_ad_initialize,
	.unixids_to_sids = idmap_ad_unixids_to_sids_retry,
	.sids_to_unixids = idmap_ad_sids_to_unixids_retry,
};

static_decl_idmap;
NTSTATUS idmap_ad_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION,
				    "ad", &ad_methods);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = idmap_ad_nss_init(ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
