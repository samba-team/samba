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
#include "net_drs.h"
#include "lib/ldb/include/ldb.h"
#include "dsdb/samdb/samdb.h"


/**
 * Figure out what is the NDTS Settings objectGUID
 * when DC_NAME is given
 */
static struct ldb_dn *
net_drs_server_dn_from_dc_name(struct net_drs_context *drs_ctx,
                               const char *dc_name)
{
	int ldb_err;
	struct ldb_dn *dn;
	struct ldb_dn *server_dn = NULL;
	struct ldb_result *ldb_res;
	static const char *attrs[] = {
		"objectGUID",
		"name",
		"dNSHostName",
		NULL
	};
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(drs_ctx);

	/* Make DN for Sites container */
	dn = ldb_msg_find_attr_as_dn(drs_ctx->ldap.ldb, mem_ctx, drs_ctx->ldap.rootdse, "dsServiceName");
	NET_DRS_CHECK_GOTO(dn != NULL, failed, "RootDSE doesn't have dsServiceName!?\n");
	if (!ldb_dn_remove_child_components(dn, 4)) {
		d_printf("Failed to make DN for Sites container.\n");
		goto failed;
	}

	/* search for Server in Sites container */
	ldb_err = ldb_search(drs_ctx->ldap.ldb, mem_ctx, &ldb_res,
	                     dn, LDB_SCOPE_SUBTREE, attrs,
	                     "(&(objectCategory=server)(|(name=%1$s)(dNSHostName=%1$s)))",
	                     dc_name);
	if (ldb_err != LDB_SUCCESS) {
		d_printf("ldb_seach() failed with err: %d (%s).\n",
		         ldb_err, ldb_errstring(drs_ctx->ldap.ldb));
		goto failed;
	}
	if (ldb_res->count != 1) {
		d_printf("ldb_search() should return exactly one record!\n");
		goto failed;
	}

	server_dn = talloc_steal(drs_ctx, ldb_res->msgs[0]->dn);

failed:
	talloc_free(mem_ctx);
	return server_dn;
}


/**
 * Figure out what is the NDTS Settings objectGUID
 * when DC_NAME is given
 */
static bool net_drs_ntds_guid_from_dc_name(struct net_drs_context *drs_ctx,
					   const char *dc_name,
					   struct GUID *_ntds_guid)
{
	int ldb_err;
	struct ldb_dn *server_dn;
	struct ldb_result *ldb_res;
	static const char *attrs[] = {
		"objectGUID",
		"msDS-portLDAP",
		"name",
		"objectCategory",
		NULL
	};
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(drs_ctx);

	/* resolve Server_DN for dc_name */
	server_dn = net_drs_server_dn_from_dc_name(drs_ctx, dc_name);
	if (!server_dn) {
		d_printf("DSA object for %s could not be found.\n", dc_name);
		goto failed;
	}

	/* move server_dn mem to local context */
	server_dn = talloc_steal(mem_ctx, server_dn);

	/* search ntdsDsa object under Server container */
	ldb_err = ldb_search(drs_ctx->ldap.ldb, mem_ctx, &ldb_res,
	                     server_dn, LDB_SCOPE_ONELEVEL, attrs,
	                     "%s", "(|(objectCategory=nTDSDSA)(objectCategory=nTDSDSARO))");
	if (ldb_err != LDB_SUCCESS) {
		d_printf("ldb_seach() failed with err: %d (%s).\n",
		         ldb_err, ldb_errstring(drs_ctx->ldap.ldb));
		goto failed;
	}
	if (ldb_res->count != 1) {
		d_printf("ldb_search() should return exactly one record!\n");
		goto failed;
	}

	*_ntds_guid =  samdb_result_guid(ldb_res->msgs[0], "objectGUID");

	talloc_free(mem_ctx);
	return true;

failed:
	talloc_free(mem_ctx);
	return false;
}

/**
 * Sends DsReplicaSync to dc_name_dest to
 * replicate naming context nc_dn_str from
 * server with ntds_guid_src GUID
 */
static bool net_drs_replicate_sync_nc(struct net_drs_context *drs_ctx,
				      struct GUID ntds_guid_src,
				      const char *nc_dn_str,
				      uint32_t options)
{
	NTSTATUS status;
	struct net_drs_connection *drs_conn;
	struct drsuapi_DsReplicaSync req;
	union drsuapi_DsReplicaSyncRequest sync_req;
	struct drsuapi_DsReplicaObjectIdentifier nc;

	/* use already opened connection */
	drs_conn = drs_ctx->drs_conn;

	/* construct naming context object */
	ZERO_STRUCT(nc);
	nc.dn = nc_dn_str;

	/* construct request object for DsReplicaSync */
	req.in.bind_handle 			= &drs_conn->bind_handle;
	req.in.level 				= 1;
	req.in.req  				= &sync_req;
	req.in.req->req1.naming_context 	= &nc;
	req.in.req->req1.options 		= options;
	req.in.req->req1.source_dsa_dns 	= NULL;
	req.in.req->req1.source_dsa_guid 	= ntds_guid_src;

	/* send DsReplicaSync request */
	status = dcerpc_drsuapi_DsReplicaSync_r(drs_conn->drs_handle, drs_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		d_printf("DsReplicaSync RPC failed - %s.\n", errstr);
		return false;
	} else if (!W_ERROR_IS_OK(req.out.result)) {
		d_printf("DsReplicaSync failed - %s (nc=[%s], dsa_guid=[%s]).\n",
		         win_errstr(req.out.result),
		         nc.dn, GUID_string(drs_ctx, &ntds_guid_src));
		return false;
	}

	return true;
}

/**
 * 'net drs replicate' command entry point
 */
int net_drs_replicate_cmd(struct net_context *ctx, int argc, const char **argv)
{
	bool bret;
	struct net_drs_context *drs_ctx;
	struct GUID ntds_guid_src;
	const char *dc_name_dest;
	const char *dc_name_src;
	const char *nc_dn_str;

	/* only one arg expected */
	if (argc != 3) {
		return net_drs_replicate_usage(ctx, argc, argv);
	}

	dc_name_dest = argv[0];
	dc_name_src = argv[1];
	nc_dn_str = argv[2];

	if (!net_drs_create_context(ctx, dc_name_dest, &drs_ctx)) {
		return -1;
	}

	/* Resolve source DC_NAME to its NDTS Settings GUID */
	if (!net_drs_ntds_guid_from_dc_name(drs_ctx, dc_name_src, &ntds_guid_src)) {
		d_printf("Error: DSA object for %s could not be found.\n", dc_name_src);
		goto failed;
	}

	/* Synchronize given Naming Context */
	bret = net_drs_replicate_sync_nc(drs_ctx,
	                                 ntds_guid_src, nc_dn_str,
	                                 DRSUAPI_DRS_WRIT_REP);
	if (!bret) {
		goto failed;
	}

	d_printf("Replicate from %s to %s was successful.\n", dc_name_src, drs_ctx->dc_name);

	talloc_free(drs_ctx);
	return 0;

failed:
	d_printf("Replicate terminated with errors.\n");
	talloc_free(drs_ctx);
	return -1;
}

/**
 * 'net drs replicate' usage
 */
int net_drs_replicate_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net drs replicate <Dest_DC_NAME> <Src_DC_NAME> <Naming Context>\n");
	return 0;
}
