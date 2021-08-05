/* 
   Unix SMB/CIFS implementation.

   endpoint server for the drsuapi pipe

   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006
   
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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "libcli/security/security.h"
#include "libcli/security/session.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "auth/auth.h"
#include "param/param.h"
#include "lib/messaging/irpc.h"

#undef DBGC_CLASS
#define DBGC_CLASS            DBGC_DRS_REPL

#define DRSUAPI_UNSUPPORTED(fname) do { \
	DEBUG(1,(__location__ ": Unsupported DRS call %s\n", #fname)); \
	if (DEBUGLVL(2)) NDR_PRINT_IN_DEBUG(fname, r); \
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR); \
} while (0)

#define DCESRV_INTERFACE_DRSUAPI_BIND(context, iface) \
	dcesrv_interface_drsuapi_bind(context, iface)
static NTSTATUS dcesrv_interface_drsuapi_bind(struct dcesrv_connection_context *context,
					      const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_require_privacy(context, iface);
}

/* 
  drsuapi_DsBind 
*/
static WERROR dcesrv_drsuapi_DsBind(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsBind *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *handle;
	struct drsuapi_DsBindInfoCtr *bind_info;
	struct drsuapi_DsBindInfoCtr *local_info;
	struct GUID site_guid, config_guid;
	struct ldb_result *site_res, *config_res;
	struct ldb_dn *server_site_dn, *config_dn;
	static const char *site_attrs[] = { "objectGUID", NULL };
	static const char *config_attrs[] = { "objectGUID", NULL };
	struct ldb_result *ntds_res;
	struct ldb_dn *ntds_dn;
	static const char *ntds_attrs[] = { "ms-DS-ReplicationEpoch", NULL };
	uint32_t pid;
	uint32_t repl_epoch;
	uint32_t supported_extensions;
	uint32_t req_length;
	int ret;
	WERROR werr;

	r->out.bind_info = NULL;
	ZERO_STRUCTP(r->out.bind_handle);

	b_state = talloc_zero(mem_ctx, struct drsuapi_bind_state);
	W_ERROR_HAVE_NO_MEMORY(b_state);

	/* if this is a DC connecting, give them system level access */
	werr = drs_security_level_check(dce_call, NULL, SECURITY_DOMAIN_CONTROLLER, NULL);
	if (W_ERROR_IS_OK(werr)) {
		DBG_NOTICE("doing DsBind with system_session\n");
		b_state->sam_ctx_system = dcesrv_samdb_connect_as_system(b_state, dce_call);
		if (b_state->sam_ctx_system == NULL) {
			return WERR_DS_UNAVAILABLE;
		}
		b_state->sam_ctx = b_state->sam_ctx_system;
	} else {
		b_state->sam_ctx = dcesrv_samdb_connect_as_user(b_state, dce_call);
		if (b_state->sam_ctx == NULL) {
			return WERR_DS_UNAVAILABLE;
		}

		/*
		 * an RODC also needs system samdb access for secret
		 * attribute replication
		 */
		werr = drs_security_level_check(dce_call, NULL, SECURITY_RO_DOMAIN_CONTROLLER,
						samdb_domain_sid(b_state->sam_ctx));
		if (W_ERROR_IS_OK(werr)) {
			DBG_NOTICE("doing DsBind as RODC\n");
			b_state->sam_ctx_system =
				dcesrv_samdb_connect_as_system(b_state, dce_call);
			if (b_state->sam_ctx_system == NULL) {
				return WERR_DS_UNAVAILABLE;
			}
		}
	}

	/*
	 * find out the guid of our own site
	 */
	server_site_dn = samdb_server_site_dn(b_state->sam_ctx, mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(server_site_dn);

	ret = ldb_search(b_state->sam_ctx, mem_ctx, &site_res,
				 server_site_dn, LDB_SCOPE_BASE, site_attrs,
				 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	if (site_res->count != 1) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	site_guid = samdb_result_guid(site_res->msgs[0], "objectGUID");

	/*
	 * lookup the local servers Replication Epoch
	 */
	ntds_dn = samdb_ntds_settings_dn(b_state->sam_ctx, mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(ntds_dn);

	ret = ldb_search(b_state->sam_ctx, mem_ctx, &ntds_res,
				 ntds_dn, LDB_SCOPE_BASE, ntds_attrs,
				 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	if (ntds_res->count != 1) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	repl_epoch = ldb_msg_find_attr_as_uint(ntds_res->msgs[0],
					       "ms-DS-ReplicationEpoch", 0);

	/*
	 * The "process identifier" of the client.
	 * According to the WSPP docs, sectin 5.35, this is
	 * for informational and debugging purposes only.
	 * The assignment is implementation specific.
	 */
	pid = 0;

	/*
	 * store the clients bind_guid
	 */
	if (r->in.bind_guid) {
		b_state->remote_bind_guid = *r->in.bind_guid;
	}

	/*
	 * store the clients bind_info
	 */
	if (r->in.bind_info) {
		b_state->remote_info = r->in.bind_info;
	}

	/*
	 * fill in our local bind info
	 */
	local_info = talloc_zero(mem_ctx, struct drsuapi_DsBindInfoCtr);
	W_ERROR_HAVE_NO_MEMORY(local_info);

	/*
	 * Fill in supported extensions
	 */
	supported_extensions = 0;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_BASE;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2;
#if 0 /* we don't support MSZIP compression (only decompression) */
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS;
#endif
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V5;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7;
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT;
#if 0 /* we don't support XPRESS compression yet */
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS;
#endif
	supported_extensions |= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V10;

	/*
	 * There is a chance for r->in.bind_info == NULL
	 * Currently we don't care, since it seems to be used nowhere else.
	 * But we need a request length. So use 28 as default.
	 */
	req_length = 28;
	if (r->in.bind_info) {
		req_length = r->in.bind_info->length;
	}

	/*
	 * fill 28 or 48 info, depends on request
	 */
	if (req_length < 48) {
		local_info->length = 28;
		local_info->info.info28.supported_extensions = supported_extensions;
		local_info->info.info28.site_guid = site_guid;
		local_info->info.info28.pid = pid;
		local_info->info.info28.repl_epoch = repl_epoch;
	} else {
		local_info->length = 48;
		local_info->info.info48.supported_extensions = supported_extensions;
		local_info->info.info48.site_guid = site_guid;
		local_info->info.info48.pid = pid;
		local_info->info.info48.repl_epoch = repl_epoch;

		local_info->info.info48.supported_extensions_ext = 0;
		local_info->info.info48.supported_extensions_ext |= DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2;

		/*
		 * find out the guid of our own site
		 */
		config_dn = ldb_get_config_basedn(b_state->sam_ctx);
		W_ERROR_HAVE_NO_MEMORY(config_dn);

		ret = ldb_search(b_state->sam_ctx, mem_ctx, &config_res,
		             config_dn, LDB_SCOPE_BASE, config_attrs,
		             "(objectClass=*)");
		if (ret != LDB_SUCCESS) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		if (config_res->count != 1) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		config_guid = samdb_result_guid(config_res->msgs[0], "objectGUID");
		local_info->info.info48.config_dn_guid = config_guid;
	}

	/*
	 * set local_info
	 */
	b_state->local_info = local_info;

	/*
	 * set bind_info
	 */
	bind_info = local_info;

	/*
	 * allocate a bind handle
	 */
	handle = dcesrv_handle_create(dce_call, DRSUAPI_BIND_HANDLE);
	W_ERROR_HAVE_NO_MEMORY(handle);
	handle->data = talloc_steal(handle, b_state);

	/*
	 * prepare reply
	 */
	r->out.bind_info = bind_info;
	*r->out.bind_handle = handle->wire_handle;

	return WERR_OK;
}


/* 
  drsuapi_DsUnbind 
*/
static WERROR dcesrv_drsuapi_DsUnbind(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct drsuapi_DsUnbind *r)
{
	struct dcesrv_handle *h;

	*r->out.bind_handle = *r->in.bind_handle;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);

	talloc_free(h);

	ZERO_STRUCTP(r->out.bind_handle);

	return WERR_OK;
}


/* 
  drsuapi_DsReplicaSync 
*/
static WERROR dcesrv_drsuapi_DsReplicaSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					   struct drsuapi_DsReplicaSync *r)
{
	WERROR status;
	uint32_t timeout;

	status = drs_security_level_check(dce_call, "DsReplicaSync", SECURITY_DOMAIN_CONTROLLER, NULL);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	if (r->in.level != 1) {
		DEBUG(0,("DsReplicaSync called with unsupported level %d\n", r->in.level));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	if (r->in.req->req1.options & DRSUAPI_DRS_ASYNC_OP) {
		timeout = IRPC_CALL_TIMEOUT;
	} else {
		/*
		 * use Infinite time for timeout in case
		 * the caller made a sync call
		 */
		timeout = IRPC_CALL_TIMEOUT_INF;
	}

	dcesrv_irpc_forward_rpc_call(dce_call, mem_ctx,
				     r, NDR_DRSUAPI_DSREPLICASYNC,
				     &ndr_table_drsuapi,
				     "dreplsrv", "DsReplicaSync",
				     timeout);

	return WERR_OK;
}


/* 
  drsuapi_DsReplicaAdd 
*/
static WERROR dcesrv_drsuapi_DsReplicaAdd(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					  struct drsuapi_DsReplicaAdd *r)
{
	WERROR status;

	status = drs_security_level_check(dce_call, "DsReplicaAdd", SECURITY_DOMAIN_CONTROLLER, NULL);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	dcesrv_irpc_forward_rpc_call(dce_call, mem_ctx,
				     r, NDR_DRSUAPI_DSREPLICAADD,
				     &ndr_table_drsuapi,
				     "dreplsrv", "DsReplicaAdd",
				     IRPC_CALL_TIMEOUT);

	return WERR_OK;
}


/* 
  drsuapi_DsReplicaDel 
*/
static WERROR dcesrv_drsuapi_DsReplicaDel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					  struct drsuapi_DsReplicaDel *r)
{
	WERROR status;

	status = drs_security_level_check(dce_call, "DsReplicaDel", SECURITY_DOMAIN_CONTROLLER, NULL);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	dcesrv_irpc_forward_rpc_call(dce_call, mem_ctx,
				     r, NDR_DRSUAPI_DSREPLICADEL,
				     &ndr_table_drsuapi,
				     "dreplsrv", "DsReplicaDel",
				     IRPC_CALL_TIMEOUT);

	return WERR_OK;
}


/* 
  drsuapi_DsReplicaModify 
*/
static WERROR dcesrv_drsuapi_DsReplicaMod(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					  struct drsuapi_DsReplicaMod *r)
{
	WERROR status;

	status = drs_security_level_check(dce_call, "DsReplicaMod", SECURITY_DOMAIN_CONTROLLER, NULL);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	dcesrv_irpc_forward_rpc_call(dce_call, mem_ctx,
				     r, NDR_DRSUAPI_DSREPLICAMOD,
				     &ndr_table_drsuapi,
				     "dreplsrv", "DsReplicaMod",
				     IRPC_CALL_TIMEOUT);

	return WERR_OK;
}


/* 
  DRSUAPI_VERIFY_NAMES 
*/
static WERROR dcesrv_DRSUAPI_VERIFY_NAMES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_VERIFY_NAMES *r)
{
	DRSUAPI_UNSUPPORTED(DRSUAPI_VERIFY_NAMES);
}


/* 
  drsuapi_DsGetMemberships 
*/
static WERROR dcesrv_drsuapi_DsGetMemberships(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetMemberships *r)
{
	DRSUAPI_UNSUPPORTED(drsuapi_DsGetMemberships);
}


/* 
  DRSUAPI_INTER_DOMAIN_MOVE 
*/
static WERROR dcesrv_DRSUAPI_INTER_DOMAIN_MOVE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_INTER_DOMAIN_MOVE *r)
{
	DRSUAPI_UNSUPPORTED(DRSUAPI_INTER_DOMAIN_MOVE);
}


/* 
  drsuapi_DsGetNT4ChangeLog 
*/
static WERROR dcesrv_drsuapi_DsGetNT4ChangeLog(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetNT4ChangeLog *r)
{
	DRSUAPI_UNSUPPORTED(drsuapi_DsGetNT4ChangeLog);
}

/* 
  drsuapi_DsCrackNames 
*/
static WERROR dcesrv_drsuapi_DsCrackNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			    struct drsuapi_DsCrackNames *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;

	*r->out.level_out = r->in.level;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	r->out.ctr = talloc_zero(mem_ctx, union drsuapi_DsNameCtr);
	W_ERROR_HAVE_NO_MEMORY(r->out.ctr);

	switch (r->in.level) {
		case 1: {
			switch(r->in.req->req1.format_offered){
			case DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX:
			case DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT_NAME_SANS_DOMAIN:
			case DRSUAPI_DS_NAME_FORMAT_STRING_SID_NAME:
			case DRSUAPI_DS_NAME_FORMAT_ALT_SECURITY_IDENTITIES_NAME:
			case DRSUAPI_DS_NAME_FORMAT_MAP_SCHEMA_GUID:
			case DRSUAPI_DS_NAME_FORMAT_LIST_NCS:
			case DRSUAPI_DS_NAME_FORMAT_LIST_DOMAINS:
			case DRSUAPI_DS_NAME_FORMAT_LIST_GLOBAL_CATALOG_SERVERS:
			case DRSUAPI_DS_NAME_FORMAT_LIST_SERVERS_WITH_DCS_IN_SITE:
			case DRSUAPI_DS_NAME_FORMAT_LIST_SERVERS_FOR_DOMAIN_IN_SITE:
			case DRSUAPI_DS_NAME_FORMAT_LIST_DOMAINS_IN_SITE:
			case DRSUAPI_DS_NAME_FORMAT_LIST_SERVERS_IN_SITE:
			case DRSUAPI_DS_NAME_FORMAT_LIST_SITES:
			case DRSUAPI_DS_NAME_FORMAT_UPN_AND_ALTSECID:
			case DRSUAPI_DS_NAME_FORMAT_UPN_FOR_LOGON:
				DEBUG(0, ("DsCrackNames: Unsupported operation requested: %X",
					  r->in.req->req1.format_offered));
				return WERR_OK;
			case DRSUAPI_DS_NAME_FORMAT_LIST_INFO_FOR_SERVER:
				return dcesrv_drsuapi_ListInfoServer(b_state->sam_ctx, mem_ctx, &r->in.req->req1, &r->out.ctr->ctr1);
			case DRSUAPI_DS_NAME_FORMAT_LIST_ROLES:
				return dcesrv_drsuapi_ListRoles(b_state->sam_ctx, mem_ctx,
								&r->in.req->req1, &r->out.ctr->ctr1);
			default:/* format_offered is in the enum drsuapi_DsNameFormat*/
				return dcesrv_drsuapi_CrackNamesByNameFormat(b_state->sam_ctx, mem_ctx,
									     &r->in.req->req1, &r->out.ctr->ctr1);
			}
		}
	}
	return WERR_INVALID_LEVEL;
}


/* 
  drsuapi_DsRemoveDSServer
*/
static WERROR dcesrv_drsuapi_DsRemoveDSServer(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsRemoveDSServer *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;
	struct ldb_dn *ntds_dn;
	int ret;
	bool ok;
	WERROR status;

	*r->out.level_out = 1;

	status = drs_security_level_check(dce_call, "DsRemoveDSServer", SECURITY_DOMAIN_CONTROLLER, NULL);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
	case 1:
		ntds_dn = ldb_dn_new(mem_ctx, b_state->sam_ctx, r->in.req->req1.server_dn);
		W_ERROR_HAVE_NO_MEMORY(ntds_dn);

		ok = ldb_dn_validate(ntds_dn);
		if (!ok) {
			return WERR_FOOBAR;
		}

		/* TODO: it's likely that we need more checks here */

		ok = ldb_dn_add_child_fmt(ntds_dn, "CN=NTDS Settings");
		if (!ok) {
			return WERR_FOOBAR;
		}

		if (r->in.req->req1.commit) {
			ret = dsdb_delete(b_state->sam_ctx, ntds_dn, DSDB_TREE_DELETE);
			if (ret != LDB_SUCCESS) {
				return WERR_FOOBAR;
			}
		}

		return WERR_OK;
	default:
		break;
	}

	return WERR_FOOBAR;
}


/* 
  DRSUAPI_REMOVE_DS_DOMAIN 
*/
static WERROR dcesrv_DRSUAPI_REMOVE_DS_DOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REMOVE_DS_DOMAIN *r)
{
	DRSUAPI_UNSUPPORTED(DRSUAPI_REMOVE_DS_DOMAIN);
}

/* Obtain the site name from a server DN */
static const char *result_site_name(struct ldb_dn *server_dn)
{
	/* Format is cn=<NETBIOS name>,cn=Servers,cn=<site>,cn=sites.... */
	const struct ldb_val *val = ldb_dn_get_component_val(server_dn, 2);
	const char *name = ldb_dn_get_component_name(server_dn, 2);

	if (!name || (ldb_attr_cmp(name, "cn") != 0)) {
		/* Ensure this matches the format.  This gives us a
		 * bit more confidence that a 'cn' value will be a
		 * ascii string */
		return NULL;
	}
	if (val) {
		return (char *)val->data;
	}
	return NULL;
}

/* 
  drsuapi_DsGetDomainControllerInfo 
*/
static WERROR dcesrv_drsuapi_DsGetDomainControllerInfo_1(struct drsuapi_bind_state *b_state, 
						TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetDomainControllerInfo *r)
{
	struct ldb_dn *sites_dn;
	struct ldb_result *res;

	const char *attrs_account_1[] = { "cn", "dnsHostName", NULL };
	const char *attrs_account_2[] = { "cn", "dnsHostName", "objectGUID", NULL };

	const char *attrs_none[] = { NULL };

	const char *attrs_site[] = { "objectGUID", NULL };

	const char *attrs_ntds[] = { "options", "objectGUID", NULL };

	const char *attrs_1[] = { "serverReference", "cn", "dnsHostName", NULL };
	const char *attrs_2[] = { "serverReference", "cn", "dnsHostName", "objectGUID", NULL };
	const char **attrs;

	struct drsuapi_DsGetDCInfoCtr1 *ctr1;
	struct drsuapi_DsGetDCInfoCtr2 *ctr2;
	struct drsuapi_DsGetDCInfoCtr3 *ctr3;

	int ret;
	unsigned int i;

	*r->out.level_out = r->in.req->req1.level;
	r->out.ctr = talloc_zero(mem_ctx, union drsuapi_DsGetDCInfoCtr);
	W_ERROR_HAVE_NO_MEMORY(r->out.ctr);

	switch (*r->out.level_out) {
	case -1:
		/* this level is not like the others */
		return WERR_INVALID_LEVEL;
	case 1:
		attrs = attrs_1;
		break;
	case 2:
	case 3:
		attrs = attrs_2;
		break;
	default:
		return WERR_INVALID_LEVEL;
	}

	sites_dn = samdb_sites_dn(b_state->sam_ctx, mem_ctx);
	if (!sites_dn) {
		return WERR_DS_OBJ_NOT_FOUND;
	}

	ret = ldb_search(b_state->sam_ctx, mem_ctx, &res, sites_dn, LDB_SCOPE_SUBTREE, attrs,
				 "(&(objectClass=server)(serverReference=*))");
	
	if (ret) {
		DEBUG(1, ("searching for servers in sites DN %s failed: %s\n", 
			  ldb_dn_get_linearized(sites_dn), ldb_errstring(b_state->sam_ctx)));
		return WERR_GEN_FAILURE;
	}

	switch (*r->out.level_out) {
	case 1:
		ctr1 = &r->out.ctr->ctr1;
		ctr1->count = res->count;
		ctr1->array = talloc_zero_array(mem_ctx, 
						struct drsuapi_DsGetDCInfo1, 
						res->count);
		for (i=0; i < res->count; i++) {
			struct ldb_dn *domain_dn;
			struct ldb_result *res_domain;
			struct ldb_result *res_account;
			struct ldb_dn *ntds_dn = ldb_dn_copy(mem_ctx, res->msgs[i]->dn);
			
			struct ldb_dn *ref_dn
				= ldb_msg_find_attr_as_dn(b_state->sam_ctx, 
							  mem_ctx, res->msgs[i], 
							  "serverReference");

			if (!ntds_dn || !ldb_dn_add_child_fmt(ntds_dn, "CN=NTDS Settings")) {
				return WERR_NOT_ENOUGH_MEMORY;
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_account, ref_dn,
						 LDB_SCOPE_BASE, attrs_account_1,
						"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=%u))",
						UF_SERVER_TRUST_ACCOUNT);
			if (ret == LDB_SUCCESS && res_account->count == 1) {
				const char *errstr;
				ctr1->array[i].dns_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "dNSHostName", NULL);
				ctr1->array[i].netbios_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "cn", NULL);
				ctr1->array[i].computer_dn
					= ldb_dn_get_linearized(res_account->msgs[0]->dn);

				/* Determine if this is the PDC */
				ret = samdb_search_for_parent_domain(b_state->sam_ctx, 
								     mem_ctx, res_account->msgs[0]->dn,
								     &domain_dn, &errstr);
				
				if (ret == LDB_SUCCESS) {
					ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_domain, domain_dn,
								 LDB_SCOPE_BASE, attrs_none, "fSMORoleOwner=%s",
								 ldb_dn_get_linearized(ntds_dn));
					if (ret) {
						return WERR_GEN_FAILURE;
					}
					if (res_domain->count == 1) {
						ctr1->array[i].is_pdc = true;
					}
				}
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for computer DN %s failed: %s\n", 
					  ldb_dn_get_linearized(ref_dn), ldb_errstring(b_state->sam_ctx)));
			}

			/* Look at server DN and extract site component */
			ctr1->array[i].site_name = result_site_name(res->msgs[i]->dn);
			ctr1->array[i].server_dn = ldb_dn_get_linearized(res->msgs[i]->dn);


			ctr1->array[i].is_enabled = true;

		}
		break;
	case 2:
		ctr2 = &r->out.ctr->ctr2;
		ctr2->count = res->count;
		ctr2->array = talloc_zero_array(mem_ctx, 
						 struct drsuapi_DsGetDCInfo2, 
						 res->count);
		for (i=0; i < res->count; i++) {
			struct ldb_dn *domain_dn;
			struct ldb_result *res_domain;
			struct ldb_result *res_account;
			struct ldb_dn *ntds_dn = ldb_dn_copy(mem_ctx, res->msgs[i]->dn);
			struct ldb_result *res_ntds;
			struct ldb_dn *site_dn = ldb_dn_copy(mem_ctx, res->msgs[i]->dn);
			struct ldb_result *res_site;
			struct ldb_dn *ref_dn
				= ldb_msg_find_attr_as_dn(b_state->sam_ctx, 
							  mem_ctx, res->msgs[i], 
							  "serverReference");

			if (!ntds_dn || !ldb_dn_add_child_fmt(ntds_dn, "CN=NTDS Settings")) {
				return WERR_NOT_ENOUGH_MEMORY;
			}

			/* Format is cn=<NETBIOS name>,cn=Servers,cn=<site>,cn=sites.... */
			if (!site_dn || !ldb_dn_remove_child_components(site_dn, 2)) {
				return WERR_NOT_ENOUGH_MEMORY;
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_ntds, ntds_dn,
						 LDB_SCOPE_BASE, attrs_ntds, "objectClass=nTDSDSA");
			if (ret == LDB_SUCCESS && res_ntds->count == 1) {
				ctr2->array[i].is_gc
					= (ldb_msg_find_attr_as_uint(res_ntds->msgs[0], "options", 0) & DS_NTDSDSA_OPT_IS_GC);
				ctr2->array[i].ntds_guid 
					= samdb_result_guid(res_ntds->msgs[0], "objectGUID");
				ctr2->array[i].ntds_dn = ldb_dn_get_linearized(res_ntds->msgs[0]->dn);
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for NTDS DN %s failed: %s\n", 
					  ldb_dn_get_linearized(ntds_dn), ldb_errstring(b_state->sam_ctx)));
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_site, site_dn,
						 LDB_SCOPE_BASE, attrs_site, "objectClass=site");
			if (ret == LDB_SUCCESS && res_site->count == 1) {
				ctr2->array[i].site_guid 
					= samdb_result_guid(res_site->msgs[0], "objectGUID");
				ctr2->array[i].site_dn = ldb_dn_get_linearized(res_site->msgs[0]->dn);
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for site DN %s failed: %s\n", 
					  ldb_dn_get_linearized(site_dn), ldb_errstring(b_state->sam_ctx)));
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_account, ref_dn,
						 LDB_SCOPE_BASE, attrs_account_2, "objectClass=computer");
			if (ret == LDB_SUCCESS && res_account->count == 1) {
				const char *errstr;
				ctr2->array[i].dns_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "dNSHostName", NULL);
				ctr2->array[i].netbios_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "cn", NULL);
				ctr2->array[i].computer_dn = ldb_dn_get_linearized(res_account->msgs[0]->dn);
				ctr2->array[i].computer_guid 
					= samdb_result_guid(res_account->msgs[0], "objectGUID");

				/* Determine if this is the PDC */
				ret = samdb_search_for_parent_domain(b_state->sam_ctx, 
								     mem_ctx, res_account->msgs[0]->dn,
								     &domain_dn, &errstr);
				
				if (ret == LDB_SUCCESS) {
					ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_domain, domain_dn,
								 LDB_SCOPE_BASE, attrs_none, "fSMORoleOwner=%s",
								 ldb_dn_get_linearized(ntds_dn));
					if (ret == LDB_SUCCESS && res_domain->count == 1) {
						ctr2->array[i].is_pdc = true;
					}
					if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
						DEBUG(5, ("warning: searching for domain DN %s failed: %s\n", 
							  ldb_dn_get_linearized(domain_dn), ldb_errstring(b_state->sam_ctx)));
					}
				}
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for computer account DN %s failed: %s\n", 
					  ldb_dn_get_linearized(ref_dn), ldb_errstring(b_state->sam_ctx)));
			}

			/* Look at server DN and extract site component */
			ctr2->array[i].site_name = result_site_name(res->msgs[i]->dn);
			ctr2->array[i].server_dn = ldb_dn_get_linearized(res->msgs[i]->dn);
			ctr2->array[i].server_guid 
				= samdb_result_guid(res->msgs[i], "objectGUID");

			ctr2->array[i].is_enabled = true;

		}
		break;
	case 3:
		ctr3 = &r->out.ctr->ctr3;
		ctr3->count = res->count;
		ctr3->array = talloc_zero_array(mem_ctx,
						 struct drsuapi_DsGetDCInfo3,
						 res->count);
		for (i=0; i<res->count; i++) {
			struct ldb_dn *domain_dn;
			struct ldb_result *res_domain;
			struct ldb_result *res_account;
			struct ldb_dn *ntds_dn = ldb_dn_copy(mem_ctx, res->msgs[i]->dn);
			struct ldb_result *res_ntds;
			struct ldb_dn *site_dn = ldb_dn_copy(mem_ctx, res->msgs[i]->dn);
			struct ldb_result *res_site;
			bool is_rodc;
			struct ldb_dn *ref_dn
				= ldb_msg_find_attr_as_dn(b_state->sam_ctx,
							  mem_ctx, res->msgs[i],
							  "serverReference");

			if (!ntds_dn || !ldb_dn_add_child_fmt(ntds_dn, "CN=NTDS Settings")) {
				return WERR_NOT_ENOUGH_MEMORY;
			}

			/* Format is cn=<NETBIOS name>,cn=Servers,cn=<site>,cn=sites.... */
			if (!site_dn || !ldb_dn_remove_child_components(site_dn, 2)) {
				return WERR_NOT_ENOUGH_MEMORY;
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_ntds, ntds_dn,
						 LDB_SCOPE_BASE, attrs_ntds, "objectClass=nTDSDSA");
			if (ret == LDB_SUCCESS && res_ntds->count == 1) {
				ctr3->array[i].is_gc
					= (ldb_msg_find_attr_as_uint(res_ntds->msgs[0], "options", 0) & DS_NTDSDSA_OPT_IS_GC);
				ctr3->array[i].ntds_guid
					= samdb_result_guid(res_ntds->msgs[0], "objectGUID");
				ctr3->array[i].ntds_dn = ldb_dn_get_linearized(res_ntds->msgs[0]->dn);
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for NTDS DN %s failed: %s\n",
					  ldb_dn_get_linearized(ntds_dn), ldb_errstring(b_state->sam_ctx)));
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_site, site_dn,
						 LDB_SCOPE_BASE, attrs_site, "objectClass=site");
			if (ret == LDB_SUCCESS && res_site->count == 1) {
				ctr3->array[i].site_guid
					= samdb_result_guid(res_site->msgs[0], "objectGUID");
				ctr3->array[i].site_dn = ldb_dn_get_linearized(res_site->msgs[0]->dn);
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for site DN %s failed: %s\n",
					  ldb_dn_get_linearized(site_dn), ldb_errstring(b_state->sam_ctx)));
			}

			ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_account, ref_dn,
						 LDB_SCOPE_BASE, attrs_account_2, "objectClass=computer");
			if (ret == LDB_SUCCESS && res_account->count == 1) {
				const char *errstr;
				ctr3->array[i].dns_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "dNSHostName", NULL);
				ctr3->array[i].netbios_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "cn", NULL);
				ctr3->array[i].computer_dn = ldb_dn_get_linearized(res_account->msgs[0]->dn);
				ctr3->array[i].computer_guid
					= samdb_result_guid(res_account->msgs[0], "objectGUID");

				/* Determine if this is the PDC */
				ret = samdb_search_for_parent_domain(b_state->sam_ctx,
								     mem_ctx, res_account->msgs[0]->dn,
								     &domain_dn, &errstr);

				if (ret == LDB_SUCCESS) {
					ret = ldb_search(b_state->sam_ctx, mem_ctx, &res_domain, domain_dn,
								 LDB_SCOPE_BASE, attrs_none, "fSMORoleOwner=%s",
								 ldb_dn_get_linearized(ntds_dn));
					if (ret == LDB_SUCCESS && res_domain->count == 1) {
						ctr3->array[i].is_pdc = true;
					}
					if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
						DEBUG(5, ("warning: searching for domain DN %s failed: %s\n",
							  ldb_dn_get_linearized(domain_dn), ldb_errstring(b_state->sam_ctx)));
					}
				}
			}
			if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
				DEBUG(5, ("warning: searching for computer account DN %s failed: %s\n",
					  ldb_dn_get_linearized(ref_dn), ldb_errstring(b_state->sam_ctx)));
			}

			/* Look at server DN and extract site component */
			ctr3->array[i].site_name = result_site_name(res->msgs[i]->dn);
			ctr3->array[i].server_dn = ldb_dn_get_linearized(res->msgs[i]->dn);
			ctr3->array[i].server_guid
				= samdb_result_guid(res->msgs[i], "objectGUID");

			ctr3->array[i].is_enabled = true;

			/* rodc? */
			ret = samdb_is_rodc(b_state->sam_ctx, &ctr3->array[i].server_guid, &is_rodc);
			if (ret == LDB_SUCCESS && is_rodc) {
				ctr3->array[i].is_rodc = true;
			}
		}
		break;
	default:
		return WERR_INVALID_LEVEL;
	}
	return WERR_OK;
}

/* 
  drsuapi_DsGetDomainControllerInfo 
*/
static WERROR dcesrv_drsuapi_DsGetDomainControllerInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetDomainControllerInfo *r)
{
	struct dcesrv_handle *h;
	struct drsuapi_bind_state *b_state;	
	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
	case 1:
		return dcesrv_drsuapi_DsGetDomainControllerInfo_1(b_state, mem_ctx, r);
	}

	return WERR_INVALID_LEVEL;
}



/* 
  drsuapi_DsExecuteKCC 
*/
static WERROR dcesrv_drsuapi_DsExecuteKCC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct drsuapi_DsExecuteKCC *r)
{
	WERROR status;
	uint32_t timeout;
	status = drs_security_level_check(dce_call, "DsExecuteKCC", SECURITY_DOMAIN_CONTROLLER, NULL);

	if (!W_ERROR_IS_OK(status)) {
		return status;
	}
	if (r->in.req->ctr1.taskID != 0) {
		return WERR_INVALID_PARAMETER;
	}
	if (r->in.req->ctr1.flags & DRSUAPI_DS_EXECUTE_KCC_ASYNCHRONOUS_OPERATION) {
		timeout = IRPC_CALL_TIMEOUT;
	} else {
		/*
		 * use Infinite time for timeout in case
		 * the caller made a sync call
		 */
		timeout = IRPC_CALL_TIMEOUT_INF;
	}

	dcesrv_irpc_forward_rpc_call(dce_call, mem_ctx, r, NDR_DRSUAPI_DSEXECUTEKCC,
				     &ndr_table_drsuapi, "kccsrv", "DsExecuteKCC",
				     timeout);
	DEBUG(10, ("Forwarded the call to execute the KCC\n"));
	return WERR_OK;
}


/* 
  drsuapi_DsReplicaGetInfo 
*/
static WERROR dcesrv_drsuapi_DsReplicaGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsReplicaGetInfo *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	enum security_user_level level;

	if (!lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL,
			 "drs", "disable_sec_check", false)) {
		level = security_session_user_level(session_info, NULL);
		if (level < SECURITY_DOMAIN_CONTROLLER) {
			DEBUG(1,(__location__ ": Administrator access required for DsReplicaGetInfo\n"));
			security_token_debug(DBGC_DRS_REPL, 2,
					     session_info->security_token);
			return WERR_DS_DRA_ACCESS_DENIED;
		}
	}

	dcesrv_irpc_forward_rpc_call(dce_call, mem_ctx, r, NDR_DRSUAPI_DSREPLICAGETINFO,
				     &ndr_table_drsuapi, "kccsrv", "DsReplicaGetInfo",
				     IRPC_CALL_TIMEOUT);

	return WERR_OK;
}


/* 
  DRSUAPI_ADD_SID_HISTORY 
*/
static WERROR dcesrv_DRSUAPI_ADD_SID_HISTORY(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_ADD_SID_HISTORY *r)
{
	DRSUAPI_UNSUPPORTED(DRSUAPI_ADD_SID_HISTORY);
}

/* 
  drsuapi_DsGetMemberships2 
*/
static WERROR dcesrv_drsuapi_DsGetMemberships2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetMemberships2 *r)
{
	DRSUAPI_UNSUPPORTED(drsuapi_DsGetMemberships2);
}

/* 
  DRSUAPI_REPLICA_VERIFY_OBJECTS 
*/
static WERROR dcesrv_DRSUAPI_REPLICA_VERIFY_OBJECTS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_VERIFY_OBJECTS *r)
{
	DRSUAPI_UNSUPPORTED(DRSUAPI_REPLICA_VERIFY_OBJECTS);
}


/* 
  DRSUAPI_GET_OBJECT_EXISTENCE 
*/
static WERROR dcesrv_DRSUAPI_GET_OBJECT_EXISTENCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_OBJECT_EXISTENCE *r)
{
	DRSUAPI_UNSUPPORTED(DRSUAPI_GET_OBJECT_EXISTENCE);
}


/* 
  drsuapi_QuerySitesByCost 
*/
static WERROR dcesrv_drsuapi_QuerySitesByCost(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_QuerySitesByCost *r)
{
	DRSUAPI_UNSUPPORTED(drsuapi_QuerySitesByCost);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_drsuapi_s.c"
