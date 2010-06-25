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
#include "lib/util/util_ldb.h"


/**
 * Parses NTDS Settings DN to find out:
 *  - DC name
 *  - Site name
 *  - Domain DNS name
 */
static bool net_drs_parse_ntds_dn(struct ldb_dn *ntds_dn,
				  TALLOC_CTX *mem_ctx,
				  const char **_dc_name,
				  const char **_site_name,
				  const char **_domain_dns_name)
{
	struct ldb_dn *dn = NULL;
	const struct ldb_val *val;

	dn = ldb_dn_copy(mem_ctx, ntds_dn);
	NET_DRS_NOMEM_GOTO(dn, failed);

	/* remove NTDS Settings component */
	ldb_dn_remove_child_components(dn, 1);
	if (_dc_name) {
		val = ldb_dn_get_rdn_val(dn);
		*_dc_name = talloc_strdup(mem_ctx, (const char *)val->data);
	}

	/* remove DC and Servers components */
	ldb_dn_remove_child_components(dn, 2);
	if (_site_name) {
		val = ldb_dn_get_rdn_val(dn);
		*_site_name = talloc_strdup(mem_ctx, (const char *)val->data);
	}

	if (_domain_dns_name) {
		char *pstr;
		char *dns_name;

		dns_name = ldb_dn_canonical_string(mem_ctx, dn);
		NET_DRS_NOMEM_GOTO(dns_name, failed);

		pstr = strchr(dns_name, '/');
		if (pstr) {
			*pstr = '\0';
		}

		*_domain_dns_name = dns_name;
	}

	talloc_free(dn);
	return true;

failed:
	talloc_free(dn);
	return false;
}

static char * net_drs_dc_canonical_string(struct ldb_dn *ntds_dn, TALLOC_CTX *mem_ctx)
{
	const char *dc_name;
	const char *site_name;
	char *canonical_name;

	if (!net_drs_parse_ntds_dn(ntds_dn, mem_ctx, &dc_name, &site_name, NULL)) {
		return NULL;
	}

	canonical_name = talloc_asprintf(mem_ctx, "%s\\%s", site_name, dc_name);

	talloc_free(discard_const(dc_name));
	talloc_free(discard_const(site_name));

	return canonical_name;
}

/**
 * Prints DC information for showrepl command
 */
static bool net_drs_showrepl_print_dc_info(struct net_drs_context *drs_ctx)
{
	int ret;
	const char *dc_name;
	const char *site_name;
	struct ldb_dn *dn;
	struct ldb_message **ntds_msgs;
	struct ldb_message **site_msgs;
	uint32_t options;
	struct GUID guid;
	TALLOC_CTX *mem_ctx;
	const char *ntds_attr[] = {"options", "objectGuid", "invocationId", NULL};
	const char *site_ntds_attr[] = {"options", "whenChanged", NULL};

	mem_ctx = talloc_new(drs_ctx);

	/* Get NTDS Settings DN string for the DC */
	dn = samdb_result_dn(drs_ctx->ldap.ldb, mem_ctx,
	                     drs_ctx->ldap.rootdse, "dsServiceName", NULL);
	NET_DRS_CHECK_GOTO(dn, failed, "No dsServiceName value in RootDSE!\n");

	/* parse NTDS Settings DN */
	if (!net_drs_parse_ntds_dn(dn, mem_ctx, &dc_name, &site_name, NULL)) {
		d_printf("Unexpected: Failed to parse %s DN!\n",
		         ldb_dn_get_linearized(dn));
		goto failed;
	}

	/* Query DC record for DSA's NTDS Settings DN */
	ret = gendb_search_dn(drs_ctx->ldap.ldb, mem_ctx, dn, &ntds_msgs, ntds_attr);
	if (ret != 1) {
		d_printf("Error while fetching %s, Possible error: %s\n",
		         ldb_dn_get_linearized(dn),
		         ldb_errstring(drs_ctx->ldap.ldb));
		goto failed;
	}

	/* find out NTDS Site Settings DN */
	if (!ldb_dn_remove_child_components(dn, 3)) {
		d_printf("Unexpected: ldb_dn_remove_child_components() failed!\n");
		goto failed;
	}
	if (!ldb_dn_add_child_fmt(dn, "CN=%s", "NTDS Site Settings")) {
		d_printf("Unexpected: ldb_dn_add_child_fmt() failed!\n");
		goto failed;
	}
	/* Query Site record for DSA's NTDS Settings DN */
	ret = gendb_search_dn(drs_ctx->ldap.ldb, mem_ctx, dn, &site_msgs, site_ntds_attr);
	if (ret != 1) {
		d_printf("Error while fetching %s, Possible error: %s\n",
		         ldb_dn_get_linearized(dn),
		         ldb_errstring(drs_ctx->ldap.ldb));
		goto failed;
	}

	/* Site-name\DC-name */
	d_printf("%s\\%s\n", site_name, dc_name);
	/* DSA Options */
	options = samdb_result_uint(ntds_msgs[0], "options", 0);
	if (options) {
		/* TODO: Print options as string in IS_GC... etc form */
		d_printf("DSA Options: 0x%08X\n", options);
	} else {
		d_printf("DSA Options: (none)\n");
	}
	/* Site Options */
	options = samdb_result_uint(site_msgs[0], "options", 0);
	if (options) {
		/* TODO: Print options in string */
		d_printf("DSA Options: 0x%08X\n", options);
	} else {
		d_printf("Site Options: (none)\n");
	}
	/* DSA GUID */
	guid = samdb_result_guid(ntds_msgs[0], "objectGUID");
	d_printf("DSA object GUID: %s\n", GUID_string(mem_ctx, &guid));
	/* DSA invocationId */
	guid = samdb_result_guid(ntds_msgs[0], "invocationId");
	d_printf("DSA invocationID: %s\n", GUID_string(mem_ctx, &guid));

	talloc_free(mem_ctx);
	return true;

failed:
	talloc_free(mem_ctx);
	return false;
}

/**
 * Convenience function to call DsReplicaGetInfo
 */
static bool net_drs_exec_DsReplicaGetInfo(struct net_drs_context *drs_ctx,
					  enum drsuapi_DsReplicaInfoType info_type,
					  union drsuapi_DsReplicaInfo *_replica_info)
{
	NTSTATUS status;
	struct drsuapi_DsReplicaGetInfo r;
	union drsuapi_DsReplicaGetInfoRequest req;
	enum drsuapi_DsReplicaInfoType info_type_got;
	struct net_drs_connection *drs_conn = drs_ctx->drs_conn;

	ZERO_STRUCT(req);
	req.req1.info_type = info_type;

	r.in.bind_handle	= &drs_conn->bind_handle;
	r.in.level		= 1;
	r.in.req		= &req;
	r.out.info		= _replica_info;
	r.out.info_type		= &info_type_got;

	status = dcerpc_drsuapi_DsReplicaGetInfo_r(drs_conn->drs_handle, drs_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		d_printf("DsReplicaGetInfo failed - %s.\n", errstr);
		return false;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		d_printf("DsReplicaGetInfo failed - %s.\n", win_errstr(r.out.result));
		return false;
	}

	if (info_type != info_type_got) {
		d_printf("DsReplicaGetInfo: Error requested info %d, got info %d.\n",
		         info_type, info_type_got);
		return false;
	}

	return true;
}

/**
 * Return transport type string for given transport object DN.
 * Currently always return 'RPC'.
 *
 * TODO: Implement getting transport type for all kind of transports
 */
static const char *
net_drs_transport_type_str(struct net_drs_context *drs_ctx, const char *transport_obj_dn)
{
	return "RPC";
}

/**
 * Prints most of the info we got about
 * a replication partner
 */
static bool net_drs_showrepl_print_heighbor(struct net_drs_context *drs_ctx,
					    struct drsuapi_DsReplicaNeighbour *neighbor)
{
	struct ldb_dn *ntds_dn;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(drs_ctx);

	ntds_dn = ldb_dn_new(drs_ctx, drs_ctx->ldap.ldb, neighbor->source_dsa_obj_dn);
	NET_DRS_NOMEM_GOTO(ntds_dn, failed);

	d_printf("%s\n", neighbor->naming_context_dn);
	/* TODO: Determine connection type */
	d_printf("\t%s via %s\n",
		 net_drs_dc_canonical_string(ntds_dn, mem_ctx),
		 net_drs_transport_type_str(drs_ctx, neighbor->transport_obj_dn));
	d_printf("\t\tDSA object GUID: %s\n", GUID_string(mem_ctx, &neighbor->source_dsa_obj_guid));
	if (W_ERROR_IS_OK(neighbor->result_last_attempt)) {
		d_printf("\t\tLast attempt @ %s was successful.\n",
		         nt_time_string(mem_ctx, neighbor->last_attempt));
	} else {
		d_printf("\t\tLast attempt @ %s failed, result %d (%s):\n",
		         nt_time_string(mem_ctx, neighbor->last_attempt),
		         W_ERROR_V(neighbor->result_last_attempt),
		         win_errstr(neighbor->result_last_attempt));
		d_printf("\t\t\t%s\n", get_friendly_werror_msg(neighbor->result_last_attempt));
	}
	d_printf("\t\t%d consecutive failure(s).\n", neighbor->consecutive_sync_failures);
	d_printf("\t\tLast success @ %s\n", nt_time_string(mem_ctx, neighbor->last_success));

	talloc_free(mem_ctx);
	return true;

failed:
	talloc_free(mem_ctx);
	return false;
}

/**
 * Prints list of all servers that target DC
 * replicates from
 */
static bool net_drs_showrepl_print_inbound_neihbors(struct net_drs_context *drs_ctx)
{
	int i;
	bool bret;
	struct drsuapi_DsReplicaNeighbourCtr *reps_from;
	union drsuapi_DsReplicaInfo replica_info;

	d_printf("\n==== INBOUND NEIGHBORS ====\n");

	bret = net_drs_exec_DsReplicaGetInfo(drs_ctx,
	                                     DRSUAPI_DS_REPLICA_INFO_NEIGHBORS, &replica_info);
	if (!bret) {
		d_printf("DsReplicaGetInfo() failed for DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES.\n");
		return false;
	}
	reps_from = replica_info.neighbours;

	for (i = 0; i < reps_from->count; i++) {
		d_printf("\n");
		net_drs_showrepl_print_heighbor(drs_ctx, &reps_from->array[i]);
	}

	return true;
}

/**
 * Prints list of all servers that target DC
 * notifies for changes
 */
static bool net_drs_showrepl_print_outbound_neihbors(struct net_drs_context *drs_ctx)
{
	int i;
	bool bret;
	struct drsuapi_DsReplicaNeighbourCtr *reps_to;
	union drsuapi_DsReplicaInfo replica_info;

	d_printf("\n==== OUTBOUND NEIGHBORS ====\n");

	bret = net_drs_exec_DsReplicaGetInfo(drs_ctx,
	                                     DRSUAPI_DS_REPLICA_INFO_REPSTO, &replica_info);
	if (!bret) {
		d_printf("DsReplicaGetInfo() failed for DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES.\n");
		return false;
	}
	reps_to = replica_info.repsto;

	for (i = 0; i < reps_to->count; i++) {
		d_printf("\n");
		net_drs_showrepl_print_heighbor(drs_ctx, &reps_to->array[i]);
	}

	return true;
}

/**
 * Prints all connections under
 * NTDS Settings for target DC.
 *
 * NOTE: All connections are printed
 * no matter what their status is
 */
static bool net_drs_showrepl_print_connection_objects(struct net_drs_context *drs_ctx)
{
	int i;
	int conn_count;
	struct ldb_message **conn_msgs;
	struct ldb_dn *dn;
	uint32_t options;
	const char *dc_dns_name;
	TALLOC_CTX *mem_ctx;
	const char *conn_attr[] = {
			"name",
			"enabledConnection",
			"fromServer",
			"mS-DS-ReplicatesNCReason",
			"options",
			"schedule",
			"transportType",
			"whenChanged",
			"whenCreated",
			NULL
	};

	mem_ctx = talloc_new(drs_ctx);

	d_printf("\n==== KCC CONNECTION OBJECTS ====\n");

	/* Get NTDS Settings DN string for the DC */
	dn = samdb_result_dn(drs_ctx->ldap.ldb, mem_ctx,
	                     drs_ctx->ldap.rootdse, "dsServiceName", NULL);
	NET_DRS_CHECK_GOTO(dn, failed, "No dsServiceName value in RootDSE!\n");

	/* DNS host name for target DC */
	dc_dns_name = samdb_result_string(drs_ctx->ldap.rootdse	, "dnsHostName", NULL);
	NET_DRS_CHECK_GOTO(dc_dns_name, failed, "No dsServiceName value in dnsHostName!\n");

	/* Enum. Connection objects under NTDS Settings */
	conn_count = gendb_search(drs_ctx->ldap.ldb, mem_ctx, dn,
	                          &conn_msgs, conn_attr, "(objectClass=nTDSConnection)");
	if (conn_count == -1) {
		d_printf("Error searching Connections for %s, Possible error: %s\n",
		         ldb_dn_get_linearized(dn),
		         ldb_errstring(drs_ctx->ldap.ldb));
		goto failed;
	}

	for (i = 0; i < conn_count; i++) {
		int k;
		const char *transport_type;
		struct ldb_message_element *msg_elem;
		struct ldb_message *conn_msg = conn_msgs[i];

		d_printf("Connection --\n");
		d_printf("\tConnection name : %s\n",
			 samdb_result_string(conn_msg, "name", NULL));
		d_printf("\tEnabled         : %s\n",
			 samdb_result_string(conn_msg, "enabledConnection", "TRUE"));
		d_printf("\tServer DNS name : %s\n", dc_dns_name);
		d_printf("\tServer DN  name : %s\n",
			 samdb_result_string(conn_msg, "fromServer", NULL));
		transport_type = samdb_result_string(conn_msg, "transportType", NULL);
		d_printf("\t\tTransportType: %s\n",
		         net_drs_transport_type_str(drs_ctx, transport_type));
		/* TODO: print Connection options in friendly format */
		options = samdb_result_uint(conn_msg, "options", 0);
		d_printf("\t\toptions:  0x%08X\n", options);

		/* print replicated NCs for this connection */
		msg_elem = ldb_msg_find_element(conn_msg, "mS-DS-ReplicatesNCReason");
		if (!msg_elem) {
			d_printf("Warning: No NC replicated for Connection!\n");
			continue;
		}
		for (k = 0; k < msg_elem->num_values; k++) {
			struct dsdb_dn *bin_dn;

			bin_dn = dsdb_dn_parse(mem_ctx, drs_ctx->ldap.ldb,
			                       &msg_elem->values[k], DSDB_SYNTAX_BINARY_DN);
			if (!bin_dn) {
				d_printf("Unexpected: Failed to parse DN - %s\n",
				         msg_elem->values[k].data);
			}
			d_printf("\t\tReplicatesNC: %s\n", ldb_dn_get_linearized(bin_dn->dn));
			/* TODO: print Reason flags in friendly format */
			options = RIVAL(bin_dn->extra_part.data, 0);
			d_printf("\t\tReason: 0x%08X\n", options);
			d_printf("\t\t\tReplica link has been added.\n");
		}
	}

	talloc_free(mem_ctx);
	return true;

failed:
	talloc_free(mem_ctx);
	return false;
}

/**
 * Prints all DC's connections failure.
 *
 * NOTE: Still don't know exactly what
 * this information means
 */
static bool net_drs_showrepl_print_connect_failures(struct net_drs_context *drs_ctx)
{
	int i;
	bool bret;
	struct ldb_dn *ntds_dn;
	struct drsuapi_DsReplicaKccDsaFailure *failure;
	struct drsuapi_DsReplicaKccDsaFailuresCtr *connect_failures;
	union drsuapi_DsReplicaInfo replica_info;
	TALLOC_CTX *mem_ctx;

	d_printf("\n==== CONNECION FAILURES ====\n");

	bret = net_drs_exec_DsReplicaGetInfo(drs_ctx,
	                                     DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES,
	                                     &replica_info);
	if (!bret) {
		d_printf("DsReplicaGetInfo() failed for DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES.\n");
		return false;
	}
	connect_failures = replica_info.connectfailures;

	mem_ctx = talloc_new(drs_ctx);

	for (i = 0; i < connect_failures->count; i++) {
		failure = &connect_failures->array[i];

		ntds_dn = ldb_dn_new(mem_ctx, drs_ctx->ldap.ldb, failure->dsa_obj_dn);
		d_printf("Source: %s\n", net_drs_dc_canonical_string(ntds_dn, mem_ctx));
		d_printf("******* %d CONSECUTIVE FAILURES since %s\n",
			 failure->num_failures,
			 nt_time_string(mem_ctx, failure->first_failure));
		d_printf("Last error: %d (%s):\n",
		         W_ERROR_V(failure->last_result),
		         win_errstr(failure->last_result));
		d_printf("\t\t\t%s\n", get_friendly_werror_msg(failure->last_result));
	}

	talloc_free(mem_ctx);
	return true;
}

/**
 * Prints all DC's link failures
 */
static bool net_drs_showrepl_print_link_failures(struct net_drs_context *drs_ctx)
{
	int i;
	bool bret;
	struct ldb_dn *ntds_dn;
	struct drsuapi_DsReplicaKccDsaFailure *failure;
	struct drsuapi_DsReplicaKccDsaFailuresCtr *link_failures;
	union drsuapi_DsReplicaInfo replica_info;
	TALLOC_CTX *mem_ctx;

	d_printf("\n==== LINK FAILURES ====\n");

	bret = net_drs_exec_DsReplicaGetInfo(drs_ctx,
	                                     DRSUAPI_DS_REPLICA_INFO_KCC_DSA_LINK_FAILURES, &replica_info);
	if (!bret) {
		d_printf("DsReplicaGetInfo() failed for DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES.\n");
		return false;
	}
	link_failures = replica_info.linkfailures;

	mem_ctx = talloc_new(drs_ctx);

	for (i = 0; i < link_failures->count; i++) {
		failure = &link_failures->array[i];

		ntds_dn = ldb_dn_new(mem_ctx, drs_ctx->ldap.ldb, failure->dsa_obj_dn);
		d_printf("Source: %s\n", net_drs_dc_canonical_string(ntds_dn, mem_ctx));
		d_printf("******* %d CONSECUTIVE FAILURES since %s\n",
			 failure->num_failures,
			 nt_time_string(mem_ctx, failure->first_failure));
		d_printf("Last error: %d (%s):\n",
		         W_ERROR_V(failure->last_result),
		         win_errstr(failure->last_result));
		d_printf("\t\t\t%s\n", get_friendly_werror_msg(failure->last_result));
	}

	talloc_free(mem_ctx);
	return true;
}

/**
 * 'net drs showrepl' command entry point
 */
int net_drs_showrepl_cmd(struct net_context *ctx, int argc, const char **argv)
{
	const char *dc_name;
	struct net_drs_context *drs_ctx = NULL;

	/* only one arg expected */
	if (argc != 1) {
		return net_drs_showrepl_usage(ctx, argc, argv);
	}

	dc_name = argv[0];

	if (!net_drs_create_context(ctx, dc_name, &drs_ctx)) {
		goto failed;
	}

	/* Print DC and Site info */
	if (!net_drs_showrepl_print_dc_info(drs_ctx)) {
		goto failed;
	}

	/* INBOUND Neighbors */
	if (!net_drs_showrepl_print_inbound_neihbors(drs_ctx)) {
		goto failed;
	}

	/* OUTBOUND Neighbors */
	if (!net_drs_showrepl_print_outbound_neihbors(drs_ctx)) {
		goto failed;
	}

	/* Connection objects for DC */
	if (!net_drs_showrepl_print_connection_objects(drs_ctx)) {
		goto failed;
	}

	/* Connection failures */
	if (!net_drs_showrepl_print_connect_failures(drs_ctx)) {
		goto failed;
	}

	/* Link failures */
	if (!net_drs_showrepl_print_link_failures(drs_ctx)) {
		goto failed;
	}

	talloc_free(drs_ctx);
	return 0;

failed:
	talloc_free(drs_ctx);
	return -1;
}

/**
 * 'net drs showrepl' usage
 */
int net_drs_showrepl_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net drs showrepl <DC_NAME>\n");
	return 0;
}
