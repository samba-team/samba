/*
   Unix SMB/CIFS implementation.

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
#include "utils/net/drs/net_drs.h"
#include "lib/ldb/include/ldb.h"


static bool net_drs_kcc_site_info(struct net_drs_context *drs_ctx,
				  const char **site_name,
				  uint32_t *site_options)
{
	struct ldb_dn *dn;
	const struct ldb_val *ldb_val;
	TALLOC_CTX *mem_ctx;
	int ret;
	struct ldb_result *ldb_res;
	static const char *attrs[] = {
		"options",
		"whenChanged",
		NULL
	};

	mem_ctx = talloc_new(drs_ctx);

	/* get dsServiceName, which is NTDS Settings
	 * object for the server
	 * e.g.: CN=NTDS Settings,CN=<DC_NAME>,CN=Servers,CN=<SITE_NAME>,CN=Sites,<CONFIG> */
	dn = ldb_msg_find_attr_as_dn(drs_ctx->ldap.ldb, mem_ctx, drs_ctx->ldap.rootdse, "dsServiceName");
	if (!dn) {
		d_printf("No dsServiceName value in RootDSE!\n");
		goto failed;
	}

	/* work out site name */
	if (!ldb_dn_remove_child_components(dn, 3)) {
		d_printf("Failed to find Site DN.\n");
		goto failed;
	}

	ldb_val = ldb_dn_get_rdn_val(dn);
	if (!ldb_val) {
		d_printf("Failed to get site name.\n");
		goto failed;
	}
	*site_name = talloc_strndup(drs_ctx, (const char*)ldb_val->data, ldb_val->length);

	/* get 'NTDS Site Settings' */
	if (!ldb_dn_add_child_fmt(dn, "CN=NTDS Site Settings")) {
		d_printf("Failed to create NTDS Site Settings DN.\n");
		goto failed;
	}

	ret = ldb_search(drs_ctx->ldap.ldb, mem_ctx, &ldb_res,
	                     dn, LDB_SCOPE_BASE,  attrs, "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		d_printf("Failed to get Site object\n");
		goto failed;
	}
	if (ldb_res->count != 1) {
		d_printf("Error: returned %d messages for Site object.\n", ldb_res->count);
		goto failed;
	}
	*site_options = ldb_msg_find_attr_as_uint(ldb_res->msgs[0], "options", 0);

	talloc_free(mem_ctx);
	return true;

failed:
	talloc_free(mem_ctx);
	return false;
}

/**
 * 'net drs kcc' command entry point
 */
int net_drs_kcc_cmd(struct net_context *ctx, int argc, const char **argv)
{
	NTSTATUS status;
	struct net_drs_context *drs_ctx;
	struct net_drs_connection *drs_conn;
	struct drsuapi_DsBindInfo48 *info48;
	struct drsuapi_DsExecuteKCC req;
	union drsuapi_DsExecuteKCCRequest kcc_req;
	const char *site_name;
	uint32_t site_options;

	/* only one arg expected */
	if (argc != 1) {
		return net_drs_kcc_usage(ctx, argc, argv);
	}

	if (!net_drs_create_context(ctx, argv[0], &drs_ctx)) {
		return -1;
	}
	drs_conn = drs_ctx->drs_conn;
	info48 = &drs_conn->info48;

	/* check if target DC supports ExecuteKCC */
	if (!(info48->supported_extensions & DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE)) {
		d_printf("%s does not support EXECUTE_KCC extension.\n", drs_ctx->dc_name);
		goto failed;
	}

	/* gather some Site info */
	if (!net_drs_kcc_site_info(drs_ctx, &site_name, &site_options)) {
		goto failed;
	}

	d_printf("%s\n", site_name);
	if (site_options) {
		/* TODO: print meaningfull site options here */
		d_printf("Current Site Options: 0x%X\n", site_options);
	} else {
		d_printf("Current Site Options: (none)\n");
	}

	/* execute KCC */
	ZERO_STRUCT(req);
	ZERO_STRUCT(kcc_req);
	req.in.bind_handle = &drs_conn->bind_handle;
	req.in.level = 1;
	req.in.req = &kcc_req;
	status = dcerpc_drsuapi_DsExecuteKCC_r(drs_conn->drs_handle, drs_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		d_printf("dcerpc_drsuapi_DsExecuteKCC failed - %s.\n", errstr);
		goto failed;
	} else if (!W_ERROR_IS_OK(req.out.result)) {
		d_printf("DsExecuteKCC failed - %s.\n", win_errstr(req.out.result));
		goto failed;
	}

	d_printf("Consistency check on %s successful.\n", drs_ctx->dc_name);

	talloc_free(drs_ctx);
	return 0;

failed:
	talloc_free(drs_ctx);
	return -1;
}

/**
 * 'net drs kcc' usage
 */
int net_drs_kcc_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net drs kcc <DC_NAME>\n");
	return 0;
}
