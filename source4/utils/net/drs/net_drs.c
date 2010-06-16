/*
   Samba Unix/Linux SMB client library

   Implements functions offered by repadmin.exe tool under Windows

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2010

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
#include "utils/net/net.h"
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "utils/net/drs/net_drs.h"
#include "lib/ldb/include/ldb.h"
#include "ldb_wrap.h"
#include "system/filesys.h"


/**
 * 'net drs' supported sub-commands
 */
static const struct net_functable net_drs_functable[] = {
	{ "bind", "Display replication features for a domain controller\n", net_drs_bind_cmd, net_drs_bind_usage },
	{ "kcc", "Forces the KCC to recalculate replication topology for a specified domain controller\n",
			net_drs_kcc_cmd, net_drs_kcc_usage },
	{ "replicate", "Triggers replication event for the specified naming context between the source and destination domain controllers.\n",
			net_drs_replicate_cmd, net_drs_replicate_usage },
	{ "showrepl", "Displays the replication partners for each directory partition on the specified domain controller.\n",
			net_drs_showrepl_cmd, net_drs_showrepl_usage },
	{ NULL, NULL }
};

/**
 * 'net drs' entry point
 */
int net_drs(struct net_context *ctx, int argc, const char **argv)
{
	return net_run_function(ctx, argc, argv, net_drs_functable, net_drs_usage);
}

/**
 * 'net drs' usage message
 */
int net_drs_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net drs <command> [options]\n");
	d_printf("\n");
	d_printf("Currently implemented commands:\n");
	d_printf("  bind      - Display DC replication features\n");
	d_printf("  kcc       - Forces the KCC to recalculate replication topology for a specified domain controller\n");
	d_printf("  replicate - Triggers replication event for the specified naming context between the source and destination domain controllers.\n");
	d_printf("  showrepl  - Displays the replication partners for each directory partition on the specified domain controller.\n");
	return 0;
}

/**
 * Create drsuapi connection to remote DC
 * and fill-in DC capabilities
 */
static bool net_drs_DsBind(struct net_drs_context *drs_ctx, struct net_drs_connection *conn)
{
	NTSTATUS status;
	struct GUID bind_guid;
	struct drsuapi_DsBind req;
	struct drsuapi_DsBindInfoCtr in_bind_ctr;
	union drsuapi_DsBindInfo *bind_info;

	SMB_ASSERT(conn->binding != NULL);

	status = dcerpc_pipe_connect_b(conn,
				       &conn->drs_pipe,
				       conn->binding,
				       &ndr_table_drsuapi,
				       drs_ctx->net_ctx->credentials,
				       drs_ctx->net_ctx->event_ctx,
				       drs_ctx->net_ctx->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to connect to server: %s\n", nt_errstr(status));
		return false;
	}
	conn->drs_handle = conn->drs_pipe->binding_handle;

	ZERO_STRUCT(in_bind_ctr);
	in_bind_ctr.length = 48;
	in_bind_ctr.info.info48.pid = (uint32_t)getpid();
	GUID_from_string(DRSUAPI_DS_BIND_GUID, &bind_guid);
	req.in.bind_guid = &bind_guid;
	req.in.bind_info = &in_bind_ctr;
	req.out.bind_handle = &conn->bind_handle;

	status = dcerpc_drsuapi_DsBind_r(conn->drs_handle, conn, &req);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		d_printf("dcerpc_drsuapi_DsBind failed - %s\n", errstr);
		return false;
	} else if (!W_ERROR_IS_OK(req.out.result)) {
		d_printf("DsBind failed - %s\n", win_errstr(req.out.result));
		return false;
	}

	/* fill-in remote DC capabilities */
	ZERO_STRUCT(conn->info48);
	bind_info = &req.out.bind_info->info;
	conn->bind_info_len = req.out.bind_info->length;
	switch (conn->bind_info_len) {
	case 48:
		conn->info48.supported_extensions_ext = bind_info->info48.supported_extensions_ext;
		conn->info48.config_dn_guid = bind_info->info48.config_dn_guid;
	case 28:
		conn->info48.repl_epoch = bind_info->info28.repl_epoch;
	case 24:
		conn->info48.supported_extensions = bind_info->info24.supported_extensions;
		conn->info48.site_guid = bind_info->info24.site_guid;
		conn->info48.pid = bind_info->info24.pid;
		break;
	default:
		d_printf("Error: server returned BindInfo length %d", req.out.bind_info->length);
		return false;
	}

	return true;
}

/**
 * Close DRSUAPI connection to remote DC
 */
static bool net_drs_DsUnbind(struct net_drs_connection *conn)
{
	struct drsuapi_DsUnbind r;
	struct policy_handle bind_handle;

	SMB_ASSERT(conn->drs_pipe);

	ZERO_STRUCT(r);
	r.out.bind_handle = &bind_handle;

	r.in.bind_handle = &conn->bind_handle;
	dcerpc_drsuapi_DsUnbind_r(conn->drs_handle, conn, &r);

	/* free dcerpc pipe in case we get called more than once */
	talloc_free(conn->drs_pipe);
	conn->drs_pipe = NULL;
	conn->drs_handle = NULL;

	return true;
}

/**
 * Destroy drsuapi connection
 */
static int net_drs_connection_destructor(struct net_drs_connection *conn)
{
	if (conn->drs_pipe) {
		net_drs_DsUnbind(conn);
	}
	return 0;
}

/**
 * Create DRSUAPI connection to target DC
 * @return ptr to net_drs_connection or NULL on failure
 */
struct net_drs_connection * net_drs_connect_dc(struct net_drs_context *drs_ctx, const char *dc_name)
{
	struct net_drs_connection *conn = NULL;

	conn = talloc_zero(drs_ctx, struct net_drs_connection);
	NET_DRS_NOMEM_GOTO(conn, failed);

	/* init binding */
	conn->binding = talloc_zero(conn, struct dcerpc_binding);
	conn->binding->transport = NCACN_IP_TCP;
	conn->binding->flags = drs_ctx->drs_conn->binding->flags;
	conn->binding->host = talloc_strdup(conn, dc_name);
	conn->binding->target_hostname = conn->binding->host;

	if (!net_drs_DsBind(drs_ctx, conn)) {
		goto failed;
	}

	talloc_set_destructor(conn, net_drs_connection_destructor);

	return conn;

failed:
	talloc_free(conn);
	return NULL;
}

/**
 * Open secured LDAP connection to remote DC
 */
static bool net_drs_ldap_connect(struct net_drs_context *drs_ctx)
{
	char *url;
	bool bret = true;

	url = talloc_asprintf(drs_ctx, "ldap://%s/", drs_ctx->dc_name);
	if (!url) {
		d_printf(__location__ ": Have no memory");
		return false;
	}

	drs_ctx->ldap.ldb = ldb_wrap_connect(drs_ctx,
	                                     drs_ctx->net_ctx->event_ctx, drs_ctx->net_ctx->lp_ctx,
	                                     url,
	                                     NULL,
	                                     drs_ctx->net_ctx->credentials,
	                                     0);
	if (drs_ctx->ldap.ldb == NULL) {
		d_printf("Unable to connect to LDAP %s", url);
		bret = false;
	}

	talloc_free(url);

	return bret;
}

/**
 * fetch RootDSE record
 */
static bool net_drs_ldap_rootdse(struct net_drs_context *drs_ctx)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"*",
		NULL
	};

	SMB_ASSERT(drs_ctx->ldap.ldb != NULL);

	basedn = ldb_dn_new(drs_ctx, drs_ctx->ldap.ldb, NULL);
	if (!basedn) {
		d_printf(__location__ ": No memory");
		return false;
	}

	ret = ldb_search(drs_ctx->ldap.ldb, drs_ctx, &r,
	                 basedn, LDB_SCOPE_BASE, attrs,
			 "(objectClass=*)");
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		d_printf("RootDSE search failed: %s", ldb_errstring(drs_ctx->ldap.ldb));
		talloc_free(r);
		return false;
	} else if (r->count != 1) {
		d_printf("RootDSE search returned more than one record!");
		talloc_free(r);
		return false;
	}

	drs_ctx->ldap.rootdse = r->msgs[0];

	return true;
}

/**
 * parses binding from command line
 * and gets target DC name
 */
static bool net_drs_parse_binding(struct net_drs_context *drs_ctx, const char *dc_binding)
{
	NTSTATUS status;
	struct dcerpc_binding *b;

	status = dcerpc_parse_binding(drs_ctx->drs_conn, dc_binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Bad binding supplied %s\n", dc_binding);
		return false;
	}

	b->transport = NCACN_IP_TCP;
	b->flags |= DCERPC_SIGN | DCERPC_SEAL;

	/* cache target DC name */
	drs_ctx->dc_name = b->target_hostname;

	drs_ctx->drs_conn->binding = b;

	return true;
}

/**
 * Free DRSUAPI connection upon net_drs_context
 * destruction
 */
static int net_drs_context_destructor(struct net_drs_context *drs_ctx)
{
	if (drs_ctx->drs_conn && drs_ctx->drs_conn->drs_pipe) {
		net_drs_DsUnbind(drs_ctx->drs_conn);
	}
	return 0;
}

/**
 * Create net_drs_context context to be used
 * by 'net drs' sub-commands
 */
bool net_drs_create_context(struct net_context *net_ctx,
			    const char *dc_binding,
			    struct net_drs_context **_drs_ctx)
{
	struct net_drs_context *drs_ctx;

	drs_ctx = talloc_zero(net_ctx, struct net_drs_context);
	if (!drs_ctx) {
		d_printf(__location__ ": No memory");
		return false;
	}

	drs_ctx->drs_conn = talloc_zero(drs_ctx, struct net_drs_connection);
	if (!drs_ctx->drs_conn) {
		d_printf(__location__ ": No memory");
		return false;
	}

	drs_ctx->net_ctx = net_ctx;

	if (!net_drs_parse_binding(drs_ctx, dc_binding)) {
		goto failed;
	}

	/* LDAP connect */
	if (!net_drs_ldap_connect(drs_ctx)) {
		goto failed;
	}
	/* fetch RootDSE */
	if (!net_drs_ldap_rootdse(drs_ctx)) {
		goto failed;
	}

	/* DRSUAPI connection */
	if (!net_drs_DsBind(drs_ctx, drs_ctx->drs_conn)) {
		goto failed;
	}

	/* set destructor to free any open connections */
	talloc_set_destructor(drs_ctx, net_drs_context_destructor);

	*_drs_ctx = drs_ctx;
	return true;

failed:
	talloc_free(drs_ctx);
	return false;
}
