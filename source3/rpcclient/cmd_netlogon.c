/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2000
   Copyright (C) Guenther Deschner 2008

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
#include "rpcclient.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "rpc_client/cli_netlogon.h"
#include "secrets.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "rpc_client/util_netlogon.h"

static WERROR cmd_netlogon_logon_ctrl2(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx, int argc,
				       const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr;
	const char *logon_server = cli->desthost;
	enum netr_LogonControlCode function_code = NETLOGON_CONTROL_REDISCOVER;
	uint32_t level = 1;
	union netr_CONTROL_DATA_INFORMATION data;
	union netr_CONTROL_QUERY_INFORMATION query;
	const char *domain = lp_workgroup();
	struct dcerpc_binding_handle *b = cli->binding_handle;
	int i;
#define fn_code_level(x, item) { x, #x, #item }
	struct {
		enum netr_LogonControlCode code;
		const char *name;
		const char *argument;
	} supported_levels[] = {
		fn_code_level(NETLOGON_CONTROL_REDISCOVER, domain),
		fn_code_level(NETLOGON_CONTROL_TC_QUERY, domain),
		fn_code_level(NETLOGON_CONTROL_TRANSPORT_NOTIFY, domain),
		fn_code_level(NETLOGON_CONTROL_FIND_USER, user),
		fn_code_level(NETLOGON_CONTROL_CHANGE_PASSWORD, domain),
		fn_code_level(NETLOGON_CONTROL_TC_VERIFY, domain),
		fn_code_level(NETLOGON_CONTROL_SET_DBFLAG, debug_level),
		{0, 0, 0}
	};
#undef fn_code_level
	if ((argc > 5) || (argc < 2)) {
		fprintf(stderr, "Usage: %s <logon_server> <function_code> "
			"<level:1..4> <argument>\n", argv[0]);
		fprintf(stderr, "Supported combinations:\n");
		fprintf(stderr, "function_code\targument\n");
		for(i=0; supported_levels[i].code; i++) {
			fprintf(stderr, "%7d\t\t%s\t(%s)\n",
				supported_levels[i].code,
				supported_levels[i].argument,
				supported_levels[i].name);
		}
		return WERR_OK;
	}

	if (argc >= 2) {
		logon_server = argv[1];
	}

	if (argc >= 3) {
		function_code = atoi(argv[2]);
	}

	if (argc >= 4) {
		level = atoi(argv[3]);
	}

	if (argc >= 5) {
		domain = argv[4];
	}

	switch (function_code) {
		case NETLOGON_CONTROL_REDISCOVER:
		case NETLOGON_CONTROL_TC_QUERY:
		case NETLOGON_CONTROL_CHANGE_PASSWORD:
		case NETLOGON_CONTROL_TRANSPORT_NOTIFY:
		case NETLOGON_CONTROL_TC_VERIFY:
			data.domain = domain;
			break;
		case NETLOGON_CONTROL_FIND_USER:
			data.user = domain;
			break;
		case NETLOGON_CONTROL_SET_DBFLAG:
			data.debug_level = atoi(domain);
		default:
			break;
	}

	status = dcerpc_netr_LogonControl2(b, mem_ctx,
					  logon_server,
					  function_code,
					  level,
					  &data,
					  &query,
					  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	/* Display results */

	return werr;
}

static WERROR cmd_netlogon_getanydcname(struct rpc_pipe_client *cli, 
					TALLOC_CTX *mem_ctx, int argc, 
					const char **argv)
{
	const char *dcname = NULL;
	WERROR werr;
	NTSTATUS status;
	int old_timeout;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s domainname\n", argv[0]);
		return WERR_OK;
	}

	/* Make sure to wait for our DC's reply */
	old_timeout = rpccli_set_timeout(cli, 30000); /* 30 seconds. */
	rpccli_set_timeout(cli, MAX(old_timeout, 30000)); /* At least 30 sec */

	status = dcerpc_netr_GetAnyDCName(b, mem_ctx,
					  cli->desthost,
					  argv[1],
					  &dcname,
					  &werr);
	rpccli_set_timeout(cli, old_timeout);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	/* Display results */

	printf("%s\n", dcname);

	return werr;
}

static WERROR cmd_netlogon_getdcname(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx, int argc,
				     const char **argv)
{
	const char *dcname = NULL;
	NTSTATUS status;
	WERROR werr;
	int old_timeout;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s domainname\n", argv[0]);
		return WERR_OK;
	}

	/* Make sure to wait for our DC's reply */
	old_timeout = rpccli_set_timeout(cli, 30000); /* 30 seconds. */
	rpccli_set_timeout(cli, MAX(30000, old_timeout)); /* At least 30 sec */

	status = dcerpc_netr_GetDcName(b, mem_ctx,
				       cli->desthost,
				       argv[1],
				       &dcname,
				       &werr);
	rpccli_set_timeout(cli, old_timeout);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	/* Display results */

	printf("%s\n", dcname);

	return werr;
}

static WERROR cmd_netlogon_dsr_getdcname(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx, int argc,
					 const char **argv)
{
	NTSTATUS result;
	WERROR werr = WERR_OK;
	uint32_t flags = DS_RETURN_DNS_NAME;
	const char *server_name = cli->desthost;
	const char *domain_name = NULL;
	struct GUID domain_guid = GUID_zero();
	struct GUID site_guid = GUID_zero();
	struct netr_DsRGetDCNameInfo *info = NULL;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [domain_name] [domain_guid] "
				"[site_guid] [flags]\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2)
		domain_name = argv[1];

	if (argc >= 3) {
		if (!NT_STATUS_IS_OK(GUID_from_string(argv[2], &domain_guid))) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	if (argc >= 4) {
		if (!NT_STATUS_IS_OK(GUID_from_string(argv[3], &site_guid))) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	if (argc >= 5)
		sscanf(argv[4], "%x", &flags);

	result = dcerpc_netr_DsRGetDCName(b, mem_ctx,
					  server_name,
					  domain_name,
					  &domain_guid,
					  &site_guid,
					  flags,
					  &info,
					  &werr);
	if (!NT_STATUS_IS_OK(result)) {
		return ntstatus_to_werror(result);
	}

	if (W_ERROR_IS_OK(werr)) {
		d_printf("DsGetDcName gave: %s\n",
		NDR_PRINT_STRUCT_STRING(mem_ctx, netr_DsRGetDCNameInfo, info));
		return WERR_OK;
	}

	printf("rpccli_netlogon_dsr_getdcname returned %s\n",
	       win_errstr(werr));

	return werr;
}

static WERROR cmd_netlogon_dsr_getdcnameex(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx, int argc,
					   const char **argv)
{
	WERROR result;
	NTSTATUS status;
	uint32_t flags = DS_RETURN_DNS_NAME;
	const char *server_name = cli->desthost;
	const char *domain_name;
	const char *site_name = NULL;
	struct GUID domain_guid = GUID_zero();
	struct netr_DsRGetDCNameInfo *info = NULL;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [domain_name] [domain_guid] "
				"[site_name] [flags]\n", argv[0]);
		return WERR_OK;
	}

	domain_name = argv[1];

	if (argc >= 3) {
		if (!NT_STATUS_IS_OK(GUID_from_string(argv[2], &domain_guid))) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	if (argc >= 4) {
		site_name = argv[3];
	}

	if (argc >= 5) {
		sscanf(argv[4], "%x", &flags);
	}

	status = dcerpc_netr_DsRGetDCNameEx(b, mem_ctx,
					    server_name,
					    domain_name,
					    &domain_guid,
					    site_name,
					    flags,
					    &info,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(result)) {
		return result;
	}

	d_printf("DsRGetDCNameEx gave %s\n",
		NDR_PRINT_STRUCT_STRING(mem_ctx, netr_DsRGetDCNameInfo, info));

	return result;
}

static WERROR cmd_netlogon_dsr_getdcnameex2(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx, int argc,
					    const char **argv)
{
	WERROR result;
	NTSTATUS status;
	uint32_t flags = DS_RETURN_DNS_NAME;
	const char *server_name = cli->desthost;
	const char *domain_name = NULL;
	const char *client_account = NULL;
	uint32_t mask = 0;
	const char *site_name = NULL;
	struct GUID domain_guid = GUID_zero();
	struct netr_DsRGetDCNameInfo *info = NULL;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [client_account] [acb_mask] "
				"[domain_name] [domain_guid] [site_name] "
				"[flags]\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		client_account = argv[1];
	}

	if (argc >= 3) {
		mask = atoi(argv[2]);
	}

	if (argc >= 4) {
		domain_name = argv[3];
	}

	if (argc >= 5) {
		if (!NT_STATUS_IS_OK(GUID_from_string(argv[4], &domain_guid))) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	if (argc >= 6) {
		site_name = argv[5];
	}

	if (argc >= 7) {
		sscanf(argv[6], "%x", &flags);
	}

	status = dcerpc_netr_DsRGetDCNameEx2(b, mem_ctx,
					     server_name,
					     client_account,
					     mask,
					     domain_name,
					     &domain_guid,
					     site_name,
					     flags,
					     &info,
					     &result);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(result)) {
		return result;
	}

	d_printf("DsRGetDCNameEx2 gave %s\n",
		NDR_PRINT_STRUCT_STRING(mem_ctx, netr_DsRGetDCNameInfo, info));

	return result;
}


static WERROR cmd_netlogon_dsr_getsitename(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx, int argc,
					   const char **argv)
{
	WERROR werr;
	NTSTATUS status;
	const char *sitename = NULL;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s computername\n", argv[0]);
		return WERR_OK;
	}

	status = dcerpc_netr_DsRGetSiteName(b, mem_ctx,
					    argv[1],
					    &sitename,
					    &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(werr)) {
		printf("rpccli_netlogon_dsr_gesitename returned %s\n",
		       nt_errstr(werror_to_ntstatus(werr)));
		return werr;
	}

	printf("Computer %s is on Site: %s\n", argv[1], sitename);

	return WERR_OK;
}

static WERROR cmd_netlogon_logon_ctrl(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx, int argc,
				      const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr;
	const char *logon_server = cli->desthost;
	enum netr_LogonControlCode function_code = 1;
	uint32_t level = 1;
	union netr_CONTROL_QUERY_INFORMATION info;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc > 4) {
		fprintf(stderr, "Usage: %s <logon_server> <function_code> "
			"<level>\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		logon_server = argv[1];
	}

	if (argc >= 3) {
		function_code = atoi(argv[2]);
	}

	if (argc >= 4) {
		level = atoi(argv[3]);
	}

	status = dcerpc_netr_LogonControl(b, mem_ctx,
					  logon_server,
					  function_code,
					  level,
					  &info,
					  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	/* Display results */

	return werr;
}

/* Log on a domain user */

static NTSTATUS cmd_netlogon_sam_logon(struct rpc_pipe_client *cli, 
				       TALLOC_CTX *mem_ctx, int argc,
				       const char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int logon_type = NetlogonNetworkInformation;
	const char *username, *password;
	uint32_t logon_param = 0;
	const char *workstation = NULL;
	struct netr_SamInfo3 *info3 = NULL;
	uint8_t authoritative = 1;
	uint32_t flags = 0;
	uint16_t validation_level;
	union netr_Validation *validation = NULL;
	uint64_t logon_id = 0;

	/* Check arguments */

	if (argc < 3 || argc > 6) {
		fprintf(stderr, "Usage: samlogon <username> <password> [workstation]"
			"[logon_type (1 or 2)] [logon_parameter]\n");
		return NT_STATUS_OK;
	}

	username = argv[1];
	password = argv[2];

	if (argc >= 4) 
		workstation = argv[3];

	if (argc >= 5)
		sscanf(argv[4], "%i", &logon_type);

	if (argc == 6)
		sscanf(argv[5], "%x", &logon_param);

	if (rpcclient_netlogon_creds == NULL) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	logon_id = generate_random_u64();

	/* Perform the sam logon */

	result = rpccli_netlogon_password_logon(rpcclient_netlogon_creds,
						cli->binding_handle,
						mem_ctx,
						logon_param,
						lp_workgroup(),
						username,
						password,
						workstation,
						logon_id,
						logon_type,
						&authoritative,
						&flags,
						&validation_level,
						&validation);
	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = map_validation_to_info3(mem_ctx,
					 validation_level,
					 validation,
					 &info3);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

 done:
	return result;
}

/* Change the trust account password */

static NTSTATUS cmd_netlogon_change_trust_pw(struct rpc_pipe_client *cli, 
					     TALLOC_CTX *mem_ctx, int argc,
					     const char **argv)
{
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	const char *dcname = cli->desthost;

        /* Check arguments */

        if (argc > 1) {
                fprintf(stderr, "Usage: change_trust_pw");
                return NT_STATUS_OK;
        }

	result = trust_pw_change(rpcclient_netlogon_creds,
				 rpcclient_msg_ctx,
				 cli->binding_handle,
				 lp_workgroup(),
				 dcname,
				 true); /* force */
	if (!NT_STATUS_IS_OK(result))
		goto done;

 done:
        return result;
}

static WERROR cmd_netlogon_gettrustrid(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx, int argc,
				       const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr = WERR_GEN_FAILURE;
	const char *server_name = cli->desthost;
	const char *domain_name = lp_workgroup();
	uint32_t rid = 0;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 1 || argc > 3) {
		fprintf(stderr, "Usage: %s <server_name> <domain_name>\n",
			argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	if (argc >= 3) {
		domain_name = argv[2];
	}

	status = dcerpc_netr_LogonGetTrustRid(b, mem_ctx,
					      server_name,
					      domain_name,
					      &rid,
					      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("Rid: %d\n", rid);
	}
 done:
	return werr;
}

static WERROR cmd_netlogon_dsr_enumtrustdom(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx, int argc,
					    const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr = WERR_GEN_FAILURE;
	const char *server_name = cli->desthost;
	uint32_t trust_flags = NETR_TRUST_FLAG_IN_FOREST;
	struct netr_DomainTrustList trusts;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 1 || argc > 3) {
		fprintf(stderr, "Usage: %s <server_name> <trust_flags>\n",
			argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	if (argc >= 3) {
		sscanf(argv[2], "%x", &trust_flags);
	}

	status = dcerpc_netr_DsrEnumerateDomainTrusts(b, mem_ctx,
						      server_name,
						      trust_flags,
						      &trusts,
						      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (W_ERROR_IS_OK(werr)) {
		int i;

		printf("%d domains returned\n", trusts.count);

		for (i=0; i<trusts.count; i++ ) {
			printf("%s (%s)\n",
				trusts.array[i].dns_name,
				trusts.array[i].netbios_name);
		}
	}
 done:
	return werr;
}

static WERROR cmd_netlogon_deregisterdnsrecords(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx, int argc,
						const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr = WERR_GEN_FAILURE;
	const char *server_name = cli->desthost;
	const char *domain = lp_workgroup();
	const char *dns_host = NULL;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 1 || argc > 4) {
		fprintf(stderr, "Usage: %s <server_name> <domain_name> "
			"<dns_host>\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	if (argc >= 3) {
		domain = argv[2];
	}

	if (argc >= 4) {
		dns_host = argv[3];
	}

	status = dcerpc_netr_DsrDeregisterDNSHostRecords(b, mem_ctx,
							 server_name,
							 domain,
							 NULL,
							 NULL,
							 dns_host,
							 &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("success\n");
	}
 done:
	return werr;
}

static WERROR cmd_netlogon_dsr_getforesttrustinfo(struct rpc_pipe_client *cli,
						  TALLOC_CTX *mem_ctx, int argc,
						  const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr = WERR_GEN_FAILURE;
	const char *server_name = cli->desthost;
	const char *trusted_domain_name = NULL;
	struct lsa_ForestTrustInformation *info = NULL;
	uint32_t flags = 0;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 1 || argc > 4) {
		fprintf(stderr, "Usage: %s <server_name> <trusted_domain_name> "
			"<flags>\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	if (argc >= 3) {
		trusted_domain_name = argv[2];
	}

	if (argc >= 4) {
		sscanf(argv[3], "%x", &flags);
	}

	status = dcerpc_netr_DsRGetForestTrustInformation(b, mem_ctx,
							 server_name,
							 trusted_domain_name,
							 flags,
							 &info,
							 &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("success\n");
	}
 done:
	return werr;
}

static NTSTATUS cmd_netlogon_enumtrusteddomains(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx, int argc,
						const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	NTSTATUS result;
	const char *server_name = cli->desthost;
	struct netr_Blob blob;
	struct dcerpc_binding_handle *b = cli->binding_handle;


	if (argc < 1 || argc > 3) {
		fprintf(stderr, "Usage: %s <server_name>\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	status = dcerpc_netr_NetrEnumerateTrustedDomains(b, mem_ctx,
							 server_name,
							 &blob,
							 &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	printf("success\n");
	dump_data(1, blob.data, blob.length);
 done:
	return status;
}

static WERROR cmd_netlogon_enumtrusteddomainsex(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx, int argc,
						const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr = WERR_GEN_FAILURE;
	const char *server_name = cli->desthost;
	struct netr_DomainTrustList list;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 1 || argc > 3) {
		fprintf(stderr, "Usage: %s <server_name>\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	status = dcerpc_netr_NetrEnumerateTrustedDomainsEx(b, mem_ctx,
							   server_name,
							   &list,
							   &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("success\n");
	}
 done:
	return werr;
}

static WERROR cmd_netlogon_getdcsitecoverage(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx, int argc,
					     const char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	WERROR werr = WERR_GEN_FAILURE;
	const char *server_name = cli->desthost;
	struct DcSitesCtr *ctr = NULL;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc < 1 || argc > 3) {
		fprintf(stderr, "Usage: %s <server_name>\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		server_name = argv[1];
	}

	status = dcerpc_netr_DsrGetDcSiteCoverageW(b, mem_ctx,
						   server_name,
						   &ctr,
						   &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (W_ERROR_IS_OK(werr) && ctr->num_sites) {
		int i;
		printf("sites covered by this DC: %d\n", ctr->num_sites);
		for (i=0; i<ctr->num_sites; i++) {
			printf("%s\n", ctr->sites[i].string);
		}
	}
 done:
	return werr;
}

static NTSTATUS cmd_netlogon_capabilities(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx, int argc,
					  const char **argv)
{
	struct netlogon_creds_cli_lck *lck;
	union netr_Capabilities capabilities;
	NTSTATUS status;

	if (argc > 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = netlogon_creds_cli_lck(rpcclient_netlogon_creds,
					NETLOGON_CREDS_CLI_LCK_EXCLUSIVE,
					mem_ctx, &lck);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "netlogon_creds_cli_lck failed: %s\n",
			nt_errstr(status));
		return status;
	}

	status = netlogon_creds_cli_check(rpcclient_netlogon_creds,
					  cli->binding_handle,
					  &capabilities);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "netlogon_creds_cli_check failed: %s\n",
			nt_errstr(status));
		return status;
	}

	TALLOC_FREE(lck);

	printf("capabilities: 0x%08x\n", capabilities.server_capabilities);

	return NT_STATUS_OK;
}

static NTSTATUS cmd_netlogon_logongetdomaininfo(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx, int argc,
						const char **argv)
{
	union netr_WorkstationInfo query;
	struct netr_WorkstationInformation workstation_info;
	union netr_DomainInfo *domain_info;
	NTSTATUS status;
	char *s;

	if (argc > 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	ZERO_STRUCT(workstation_info);

	query.workstation_info = &workstation_info;

	status = netlogon_creds_cli_LogonGetDomainInfo(rpcclient_netlogon_creds,
						       cli->binding_handle,
						       mem_ctx,
						       1,
						       &query,
						       &domain_info);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "netlogon_creds_cli_LogonGetDomainInfo failed: %s\n",
			nt_errstr(status));
		return status;
	}

	s = NDR_PRINT_STRUCT_STRING(mem_ctx, netr_DomainInformation, domain_info->domain_info);
	if (s) {
		printf("%s\n", s);
		TALLOC_FREE(s);
	}

	return NT_STATUS_OK;
}

/* List of commands exported by this module */

struct cmd_set netlogon_commands[] = {

	{
		.name = "NETLOGON",
	},

	{
		.name               = "logonctrl2",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_logon_ctrl2,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Logon Control 2",
		.usage              = "",
	},
	{
		.name               = "getanydcname",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_getanydcname,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get trusted DC name",
		.usage              = "",
	},
	{
		.name               = "getdcname",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_getdcname,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get trusted PDC name",
		.usage              = "",
	},
	{
		.name               = "dsr_getdcname",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_getdcname,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get trusted DC name",
		.usage              = "",
	},
	{
		.name               = "dsr_getdcnameex",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_getdcnameex,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get trusted DC name",
		.usage              = "",
	},
	{
		.name               = "dsr_getdcnameex2",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_getdcnameex2,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get trusted DC name",
		.usage              = "",
	},
	{
		.name               = "dsr_getsitename",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_getsitename,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get sitename",
		.usage              = "",
	},
	{
		.name               = "dsr_getforesttrustinfo",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_getforesttrustinfo,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get Forest Trust Info",
		.usage              = "",
	},
	{
		.name               = "logonctrl",
		.returntype         =  RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_logon_ctrl,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Logon Control",
		.usage              = "",
	},
	{
		.name               = "samlogon",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_netlogon_sam_logon,
		.wfn                = NULL,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Sam Logon",
		.usage              = "",
		.use_netlogon_creds = true,
	},
	{
		.name               = "change_trust_pw",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_netlogon_change_trust_pw,
		.wfn                = NULL,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Change Trust Account Password",
		.usage              = "",
		.use_netlogon_creds = true,
	},
	{
		.name               = "gettrustrid",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_gettrustrid,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get trust rid",
		.usage              = "",
	},
	{
		.name               = "dsr_enumtrustdom",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_enumtrustdom,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Enumerate trusted domains",
		.usage              = "",
	},
	{
		.name               = "dsenumdomtrusts",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_dsr_enumtrustdom,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Enumerate all trusted domains in an AD forest",
		.usage              = "",
	},
	{
		.name               = "deregisterdnsrecords",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_deregisterdnsrecords,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Deregister DNS records",
		.usage              = "",
	},
	{
		.name               = "netrenumtrusteddomains",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_netlogon_enumtrusteddomains,
		.wfn                = NULL,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Enumerate trusted domains",
		.usage              = "",
	},
	{
		.name               = "netrenumtrusteddomainsex",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_enumtrusteddomainsex,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Enumerate trusted domains",
		.usage              = "",
	},
	{
		.name               = "getdcsitecoverage",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_netlogon_getdcsitecoverage,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Get the Site-Coverage from a DC",
		.usage              = "",
	},
	{
		.name               = "capabilities",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_netlogon_capabilities,
		.wfn                = NULL,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Return Capabilities",
		.usage              = "",
		.use_netlogon_creds = true,
	},
	{
		.name               = "logongetdomaininfo",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_netlogon_logongetdomaininfo,
		.wfn                = NULL,
		.table              = &ndr_table_netlogon,
		.rpc_pipe           = NULL,
		.description        = "Return LogonGetDomainInfo",
		.usage              = "",
		.use_netlogon_creds = true,
	},
	{
		.name = NULL,
	}
};
