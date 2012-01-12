/*
   Unix SMB/CIFS implementation.

   DNS Server

   Copyright (C) Amitay Isaacs 2011

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
#include "talloc.h"
#include "rpc_server/dcerpc_server.h"
#include "dsdb/samdb/samdb.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_dnsserver.h"
#include "dnsserver.h"
#include "lib/ldb/include/ldb_private.h"

struct dnsserver_state {
	struct loadparm_context *lp_ctx;
	struct ldb_context *samdb;
	struct dnsserver_partition *partitions;
	struct dnsserver_zone *zones;
	int zones_count;
	struct dnsserver_serverinfo *serverinfo;
};


/* Utility functions */

static void dnsserver_reload_zones(struct dnsserver_state *dsstate)
{
	struct dnsserver_partition *p;
	struct dnsserver_zone *zones, *z, *znext, *zmatch;
	struct dnsserver_zone *old_list, *new_list;

	old_list = dsstate->zones;
	new_list = NULL;

	for (p = dsstate->partitions; p; p = p->next) {
		zones = dnsserver_db_enumerate_zones(dsstate, dsstate->samdb, p);
		if (zones == NULL) {
			continue;
		}
		for (z = zones; z; ) {
			znext = z->next;
			zmatch = dnsserver_find_zone(old_list, z->name);
			if (zmatch == NULL) {
				/* Missing zone */
				z->zoneinfo = dnsserver_init_zoneinfo(z, dsstate->serverinfo);
				if (z->zoneinfo == NULL) {
					continue;
				}
				DLIST_ADD_END(new_list, z, NULL);
				p->zones_count++;
				dsstate->zones_count++;
			} else {
				/* Existing zone */
				talloc_free(z);
				DLIST_REMOVE(old_list, zmatch);
				DLIST_ADD_END(new_list, zmatch, NULL);
			}
			z = znext;
		}
	}

	if (new_list == NULL) {
		return;
	}

	/* Deleted zones */
	for (z = old_list; z; ) {
		znext = z->next;
		z->partition->zones_count--;
		dsstate->zones_count--;
		talloc_free(z);
		z = znext;
	}

	dsstate->zones = new_list;
}


static struct dnsserver_state *dnsserver_connect(struct dcesrv_call_state *dce_call)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *zones, *z, *znext;
	struct dnsserver_partition *partitions, *p;

	dsstate = talloc_get_type(dce_call->context->private_data, struct dnsserver_state);
	if (dsstate != NULL) {
		return dsstate;
	}

	dsstate = talloc_zero(dce_call->context, struct dnsserver_state);
	if (dsstate == NULL) {
		return NULL;
	}

	dsstate->lp_ctx = dce_call->conn->dce_ctx->lp_ctx;

	/* FIXME: create correct auth_session_info for connecting user */
	dsstate->samdb = samdb_connect(dsstate, dce_call->event_ctx, dsstate->lp_ctx,
				dce_call->conn->auth_state.session_info, 0);
	if (dsstate->samdb == NULL) {
		DEBUG(0,("dnsserver: Failed to open samdb"));
		goto failed;
	}

	/* Initialize server info */
	dsstate->serverinfo = dnsserver_init_serverinfo(dsstate,
							dsstate->lp_ctx,
							dsstate->samdb);
	if (dsstate->serverinfo == NULL) {
		goto failed;
	}

	/* Search for DNS partitions */
	partitions = dnsserver_db_enumerate_partitions(dsstate, dsstate->serverinfo, dsstate->samdb);
	if (partitions == NULL) {
		goto failed;
	}
	dsstate->partitions = partitions;

	/* Search for DNS zones */
	for (p = partitions; p; p = p->next) {
		zones = dnsserver_db_enumerate_zones(dsstate, dsstate->samdb, p);
		if (zones == NULL) {
			goto failed;
		}
		for (z = zones; z; ) {
			znext = z->next;
			z->zoneinfo = dnsserver_init_zoneinfo(z, dsstate->serverinfo);
			if (z->zoneinfo == NULL) {
				goto failed;
			}
			DLIST_ADD_END(dsstate->zones, z, NULL);
			p->zones_count++;
			dsstate->zones_count++;
			z = znext;
		}
	}

	dce_call->context->private_data = dsstate;

	return dsstate;

failed:
	talloc_free(dsstate);
	dsstate = NULL;
	return NULL;
}


/* dnsserver query functions */

/* [MS-DNSP].pdf Section 3.1.1.1 DNS Server Configuration Information */
static WERROR dnsserver_query_server(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					const char *operation,
					const unsigned int client_version,
					enum DNS_RPC_TYPEID *typeid,
					union DNSSRV_RPC_UNION *r)
{
	uint8_t is_integer, is_addresses, is_string, is_wstring, is_stringlist;
	uint32_t answer_integer;
	struct IP4_ARRAY *answer_iparray;
	struct DNS_ADDR_ARRAY *answer_addrarray;
	char *answer_string;
	struct DNS_RPC_UTF8_STRING_LIST *answer_stringlist;
	struct dnsserver_serverinfo *serverinfo;

	serverinfo = dsstate->serverinfo;

	if (strcasecmp(operation, "ServerInfo") == 0) {
		if (client_version == DNS_CLIENT_VERSION_W2K) {
			*typeid = DNSSRV_TYPEID_SERVER_INFO_W2K;
			r->ServerInfoW2K = talloc_zero(mem_ctx, struct DNS_RPC_SERVER_INFO_W2K);

			r->ServerInfoW2K->dwVersion = serverinfo->dwVersion;
			r->ServerInfoW2K->fBootMethod = serverinfo->fBootMethod;
			r->ServerInfoW2K->fAdminConfigured = serverinfo->fAdminConfigured;
			r->ServerInfoW2K->fAllowUpdate = serverinfo->fAllowUpdate;
			r->ServerInfoW2K->fDsAvailable = serverinfo->fDsAvailable;
			r->ServerInfoW2K->pszServerName = talloc_strdup(mem_ctx, serverinfo->pszServerName);
			r->ServerInfoW2K->pszDsContainer = talloc_strdup(mem_ctx, serverinfo->pszDsContainer);
			r->ServerInfoW2K->aipServerAddrs = ip4_array_copy(mem_ctx, serverinfo->aipServerAddrs);
			r->ServerInfoW2K->aipListenAddrs = ip4_array_copy(mem_ctx, serverinfo->aipListenAddrs);
			r->ServerInfoW2K->aipForwarders = ip4_array_copy(mem_ctx, serverinfo->aipForwarders);
			r->ServerInfoW2K->dwLogLevel = serverinfo->dwLogLevel;
			r->ServerInfoW2K->dwDebugLevel = serverinfo->dwDebugLevel;
			r->ServerInfoW2K->dwForwardTimeout = serverinfo->dwForwardTimeout;
			r->ServerInfoW2K->dwRpcProtocol = serverinfo->dwRpcProtocol;
			r->ServerInfoW2K->dwNameCheckFlag = serverinfo->dwNameCheckFlag;
			r->ServerInfoW2K->cAddressAnswerLimit = serverinfo->cAddressAnswerLimit;
			r->ServerInfoW2K->dwRecursionRetry = serverinfo->dwRecursionRetry;
			r->ServerInfoW2K->dwRecursionTimeout = serverinfo->dwRecursionTimeout;
			r->ServerInfoW2K->dwMaxCacheTtl = serverinfo->dwMaxCacheTtl;
			r->ServerInfoW2K->dwDsPollingInterval = serverinfo->dwDsPollingInterval;
			r->ServerInfoW2K->dwScavengingInterval = serverinfo->dwScavengingInterval;
			r->ServerInfoW2K->dwDefaultRefreshInterval = serverinfo->dwDefaultRefreshInterval;
			r->ServerInfoW2K->dwDefaultNoRefreshInterval = serverinfo->dwDefaultNoRefreshInterval;
			r->ServerInfoW2K->fAutoReverseZones = serverinfo->fAutoReverseZones;
			r->ServerInfoW2K->fAutoCacheUpdate = serverinfo->fAutoCacheUpdate;
			r->ServerInfoW2K->fRecurseAfterForwarding = serverinfo->fRecurseAfterForwarding;
			r->ServerInfoW2K->fForwardDelegations = serverinfo->fForwardDelegations;
			r->ServerInfoW2K->fNoRecursion = serverinfo->fNoRecursion;
			r->ServerInfoW2K->fSecureResponses = serverinfo->fSecureResponses;
			r->ServerInfoW2K->fRoundRobin = serverinfo->fRoundRobin;
			r->ServerInfoW2K->fLocalNetPriority = serverinfo->fLocalNetPriority;
			r->ServerInfoW2K->fBindSecondaries = serverinfo->fBindSecondaries;
			r->ServerInfoW2K->fWriteAuthorityNs = serverinfo->fWriteAuthorityNs;
			r->ServerInfoW2K->fStrictFileParsing = serverinfo->fStrictFileParsing;
			r->ServerInfoW2K->fLooseWildcarding = serverinfo->fLooseWildcarding;
			r->ServerInfoW2K->fDefaultAgingState = serverinfo->fDefaultAgingState;

		} else if (client_version == DNS_CLIENT_VERSION_DOTNET) {
			*typeid = DNSSRV_TYPEID_SERVER_INFO_DOTNET;
			r->ServerInfoDotNet = talloc_zero(mem_ctx, struct DNS_RPC_SERVER_INFO_DOTNET);

			r->ServerInfoDotNet->dwRpcStructureVersion = 0x01;
			r->ServerInfoDotNet->dwVersion = serverinfo->dwVersion;
			r->ServerInfoDotNet->fBootMethod = serverinfo->fBootMethod;
			r->ServerInfoDotNet->fAdminConfigured = serverinfo->fAdminConfigured;
			r->ServerInfoDotNet->fAllowUpdate = serverinfo->fAllowUpdate;
			r->ServerInfoDotNet->fDsAvailable = serverinfo->fDsAvailable;
			r->ServerInfoDotNet->pszServerName = talloc_strdup(mem_ctx, serverinfo->pszServerName);
			r->ServerInfoDotNet->pszDsContainer = talloc_strdup(mem_ctx, serverinfo->pszDsContainer);
			r->ServerInfoDotNet->aipServerAddrs = ip4_array_copy(mem_ctx, serverinfo->aipServerAddrs);
			r->ServerInfoDotNet->aipListenAddrs = ip4_array_copy(mem_ctx, serverinfo->aipListenAddrs);
			r->ServerInfoDotNet->aipForwarders = ip4_array_copy(mem_ctx, serverinfo->aipForwarders);
			r->ServerInfoDotNet->aipLogFilter = ip4_array_copy(mem_ctx, serverinfo->aipLogFilter);
			r->ServerInfoDotNet->pwszLogFilePath = talloc_strdup(mem_ctx, serverinfo->pwszLogFilePath);
			r->ServerInfoDotNet->pszDomainName = talloc_strdup(mem_ctx, serverinfo->pszDomainName);
			r->ServerInfoDotNet->pszForestName = talloc_strdup(mem_ctx, serverinfo->pszForestName);
			r->ServerInfoDotNet->pszDomainDirectoryPartition = talloc_strdup(mem_ctx, serverinfo->pszDomainDirectoryPartition);
			r->ServerInfoDotNet->pszForestDirectoryPartition = talloc_strdup(mem_ctx, serverinfo->pszForestDirectoryPartition);
			r->ServerInfoDotNet->dwLogLevel = serverinfo->dwLogLevel;
			r->ServerInfoDotNet->dwDebugLevel = serverinfo->dwDebugLevel;
			r->ServerInfoDotNet->dwForwardTimeout = serverinfo->dwForwardTimeout;
			r->ServerInfoDotNet->dwRpcProtocol = serverinfo->dwRpcProtocol;
			r->ServerInfoDotNet->dwNameCheckFlag = serverinfo->dwNameCheckFlag;
			r->ServerInfoDotNet->cAddressAnswerLimit = serverinfo->cAddressAnswerLimit;
			r->ServerInfoDotNet->dwRecursionRetry = serverinfo->dwRecursionRetry;
			r->ServerInfoDotNet->dwRecursionTimeout = serverinfo->dwRecursionTimeout;
			r->ServerInfoDotNet->dwMaxCacheTtl = serverinfo->dwMaxCacheTtl;
			r->ServerInfoDotNet->dwDsPollingInterval = serverinfo->dwDsPollingInterval;
			r->ServerInfoDotNet->dwLocalNetPriorityNetMask = serverinfo->dwLocalNetPriorityNetMask;
			r->ServerInfoDotNet->dwScavengingInterval = serverinfo->dwScavengingInterval;
			r->ServerInfoDotNet->dwDefaultRefreshInterval = serverinfo->dwDefaultRefreshInterval;
			r->ServerInfoDotNet->dwDefaultNoRefreshInterval = serverinfo->dwDefaultNoRefreshInterval;
			r->ServerInfoDotNet->dwLastScavengeTime = serverinfo->dwLastScavengeTime;
			r->ServerInfoDotNet->dwEventLogLevel = serverinfo->dwEventLogLevel;
			r->ServerInfoDotNet->dwLogFileMaxSize = serverinfo->dwLogFileMaxSize;
			r->ServerInfoDotNet->dwDsForestVersion = serverinfo->dwDsForestVersion;
			r->ServerInfoDotNet->dwDsDomainVersion = serverinfo->dwDsDomainVersion;
			r->ServerInfoDotNet->dwDsDsaVersion = serverinfo->dwDsDsaVersion;
			r->ServerInfoDotNet->fAutoReverseZones = serverinfo->fAutoReverseZones;
			r->ServerInfoDotNet->fAutoCacheUpdate = serverinfo->fAutoCacheUpdate;
			r->ServerInfoDotNet->fRecurseAfterForwarding = serverinfo->fRecurseAfterForwarding;
			r->ServerInfoDotNet->fForwardDelegations = serverinfo->fForwardDelegations;
			r->ServerInfoDotNet->fNoRecursion = serverinfo->fNoRecursion;
			r->ServerInfoDotNet->fSecureResponses = serverinfo->fSecureResponses;
			r->ServerInfoDotNet->fRoundRobin = serverinfo->fRoundRobin;
			r->ServerInfoDotNet->fLocalNetPriority = serverinfo->fLocalNetPriority;
			r->ServerInfoDotNet->fBindSecondaries = serverinfo->fBindSecondaries;
			r->ServerInfoDotNet->fWriteAuthorityNs = serverinfo->fWriteAuthorityNs;
			r->ServerInfoDotNet->fStrictFileParsing = serverinfo->fStrictFileParsing;
			r->ServerInfoDotNet->fLooseWildcarding = serverinfo->fLooseWildcarding;
			r->ServerInfoDotNet->fDefaultAgingState = serverinfo->fDefaultAgingState;

		} else if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			*typeid = DNSSRV_TYPEID_SERVER_INFO;
			r->ServerInfo = talloc_zero(mem_ctx, struct DNS_RPC_SERVER_INFO_LONGHORN);

			r->ServerInfo->dwRpcStructureVersion = 0x02;
			r->ServerInfo->dwVersion = serverinfo->dwVersion;
			r->ServerInfo->fBootMethod = serverinfo->fBootMethod;
			r->ServerInfo->fAdminConfigured = serverinfo->fAdminConfigured;
			r->ServerInfo->fAllowUpdate = serverinfo->fAllowUpdate;
			r->ServerInfo->fDsAvailable = serverinfo->fDsAvailable;
			r->ServerInfo->pszServerName = talloc_strdup(mem_ctx, serverinfo->pszServerName);
			r->ServerInfo->pszDsContainer = talloc_strdup(mem_ctx, serverinfo->pszDsContainer);
			r->ServerInfo->aipServerAddrs = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipServerAddrs);
			r->ServerInfo->aipListenAddrs = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipListenAddrs);
			r->ServerInfo->aipForwarders = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipForwarders);
			r->ServerInfo->aipLogFilter = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipLogFilter);
			r->ServerInfo->pwszLogFilePath = talloc_strdup(mem_ctx, serverinfo->pwszLogFilePath);
			r->ServerInfo->pszDomainName = talloc_strdup(mem_ctx, serverinfo->pszDomainName);
			r->ServerInfo->pszForestName = talloc_strdup(mem_ctx, serverinfo->pszForestName);
			r->ServerInfo->pszDomainDirectoryPartition = talloc_strdup(mem_ctx, serverinfo->pszDomainDirectoryPartition);
			r->ServerInfo->pszForestDirectoryPartition = talloc_strdup(mem_ctx, serverinfo->pszForestDirectoryPartition);
			r->ServerInfo->dwLogLevel = serverinfo->dwLogLevel;
			r->ServerInfo->dwDebugLevel = serverinfo->dwDebugLevel;
			r->ServerInfo->dwForwardTimeout = serverinfo->dwForwardTimeout;
			r->ServerInfo->dwRpcProtocol = serverinfo->dwRpcProtocol;
			r->ServerInfo->dwNameCheckFlag = serverinfo->dwNameCheckFlag;
			r->ServerInfo->cAddressAnswerLimit = serverinfo->cAddressAnswerLimit;
			r->ServerInfo->dwRecursionRetry = serverinfo->dwRecursionRetry;
			r->ServerInfo->dwRecursionTimeout = serverinfo->dwRecursionTimeout;
			r->ServerInfo->dwMaxCacheTtl = serverinfo->dwMaxCacheTtl;
			r->ServerInfo->dwDsPollingInterval = serverinfo->dwDsPollingInterval;
			r->ServerInfo->dwLocalNetPriorityNetMask = serverinfo->dwLocalNetPriorityNetMask;
			r->ServerInfo->dwScavengingInterval = serverinfo->dwScavengingInterval;
			r->ServerInfo->dwDefaultRefreshInterval = serverinfo->dwDefaultRefreshInterval;
			r->ServerInfo->dwDefaultNoRefreshInterval = serverinfo->dwDefaultNoRefreshInterval;
			r->ServerInfo->dwLastScavengeTime = serverinfo->dwLastScavengeTime;
			r->ServerInfo->dwEventLogLevel = serverinfo->dwEventLogLevel;
			r->ServerInfo->dwLogFileMaxSize = serverinfo->dwLogFileMaxSize;
			r->ServerInfo->dwDsForestVersion = serverinfo->dwDsForestVersion;
			r->ServerInfo->dwDsDomainVersion = serverinfo->dwDsDomainVersion;
			r->ServerInfo->dwDsDsaVersion = serverinfo->dwDsDsaVersion;
			r->ServerInfo->fReadOnlyDC = serverinfo->fReadOnlyDC;
			r->ServerInfo->fAutoReverseZones = serverinfo->fAutoReverseZones;
			r->ServerInfo->fAutoCacheUpdate = serverinfo->fAutoCacheUpdate;
			r->ServerInfo->fRecurseAfterForwarding = serverinfo->fRecurseAfterForwarding;
			r->ServerInfo->fForwardDelegations = serverinfo->fForwardDelegations;
			r->ServerInfo->fNoRecursion = serverinfo->fNoRecursion;
			r->ServerInfo->fSecureResponses = serverinfo->fSecureResponses;
			r->ServerInfo->fRoundRobin = serverinfo->fRoundRobin;
			r->ServerInfo->fLocalNetPriority = serverinfo->fLocalNetPriority;
			r->ServerInfo->fBindSecondaries = serverinfo->fBindSecondaries;
			r->ServerInfo->fWriteAuthorityNs = serverinfo->fWriteAuthorityNs;
			r->ServerInfo->fStrictFileParsing = serverinfo->fStrictFileParsing;
			r->ServerInfo->fLooseWildcarding = serverinfo->fLooseWildcarding;
			r->ServerInfo->fDefaultAgingState = serverinfo->fDefaultAgingState;
		}
		return WERR_OK;
	}

	is_integer = 0;

	if (strcasecmp(operation, "AddressAnswerLimit") == 0) {
		answer_integer = serverinfo->cAddressAnswerLimit;
		is_integer = 1;
	} else if (strcasecmp(operation, "AdminConfigured") == 0) {
		answer_integer = serverinfo->fAdminConfigured;
		is_integer = 1;
	} else if (strcasecmp(operation, "AllowCNAMEAtNS") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "AllowUpdate") == 0) {
		answer_integer = serverinfo->fAllowUpdate;
		is_integer = 1;
	} else if (strcasecmp(operation, "AutoCacheUpdate") == 0) {
		answer_integer = serverinfo->fAutoCacheUpdate;
		is_integer = 1;
	} else if (strcasecmp(operation, "AutoConfigFileZones") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "BindSecondaries") == 0) {
		answer_integer = serverinfo->fBindSecondaries;
		is_integer = 1;
	} else if (strcasecmp(operation, "BootMethod") == 0) {
		answer_integer = serverinfo->fBootMethod;
		is_integer = 1;
	} else if (strcasecmp(operation, "DebugLevel") == 0) {
		answer_integer = serverinfo->dwDebugLevel;
		is_integer = 1;
	} else if (strcasecmp(operation, "DefaultAgingState") == 0) {
		answer_integer = serverinfo->fDefaultAgingState;
		is_integer = 1;
	} else if (strcasecmp(operation, "DefaultNoRefreshInterval") == 0) {
		answer_integer = serverinfo->dwDefaultNoRefreshInterval;
		is_integer = 1;
	} else if (strcasecmp(operation, "DefaultRefreshInterval") == 0) {
		answer_integer = serverinfo->dwDefaultRefreshInterval;
		is_integer = 1;
	} else if (strcasecmp(operation, "DeleteOutsideGlue") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DisjointNets") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DsLazyUpdateInterval") == 0) {
		answer_integer = 3; /* seconds */
		is_integer = 1;
	} else if (strcasecmp(operation, "DsPollingInterval") == 0) {
		answer_integer = serverinfo->dwDsPollingInterval;
		is_integer = 1;
	} else if (strcasecmp(operation, "DsTombstoneInterval") == 0) {
		answer_integer = 0x00127500; /* 14 days */
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableRegistryBoot") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EventLogLevel") == 0) {
		answer_integer = serverinfo->dwEventLogLevel;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceSoaSerial") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceSaoRetry") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceSoaRefresh") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceSoaMinimumTtl") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForwardDelegations") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForwardingTimeout") == 0) {
		answer_integer = serverinfo->dwForwardTimeout;
		is_integer = 1;
	} else if (strcasecmp(operation, "IsSlave") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "LocalNetPriority") == 0) {
		answer_integer = serverinfo->fLocalNetPriority;
		is_integer = 1;
	} else if (strcasecmp(operation, "LogFileMaxSize") == 0) {
		answer_integer = serverinfo->dwLogFileMaxSize;
		is_integer = 1;
	} else if (strcasecmp(operation, "LogLevel") == 0) {
		answer_integer = serverinfo->dwLogLevel;
		is_integer = 1;
	} else if (strcasecmp(operation, "LooseWildcarding") == 0) {
		answer_integer = serverinfo->fLooseWildcarding;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaxCacheTtl") == 0) {
		answer_integer = serverinfo->dwMaxCacheTtl;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaxNegativeCacheTtl") == 0) {
		answer_integer = 0x00000384; /* 15 minutes */
		is_integer = 1;
	} else if (strcasecmp(operation, "NameCheckFlag") == 0) {
		answer_integer = serverinfo->dwNameCheckFlag;
		is_integer = 1;
	} else if (strcasecmp(operation, "NoRecursion") == 0) {
		answer_integer = serverinfo->fNoRecursion;
		is_integer = 1;
	} else if (strcasecmp(operation, "NoUpdateDelegations") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "PublishAutonet") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "QuietRecvFaultInterval") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "QuietRecvLogInterval") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "RecursionRetry") == 0) {
		answer_integer = serverinfo->dwRecursionRetry;
		is_integer = 1;
	} else if (strcasecmp(operation, "RecursionTimeout") == 0) {
		answer_integer = serverinfo->dwRecursionTimeout;
		is_integer = 1;
	} else if (strcasecmp(operation, "ReloadException") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "RoundRobin") == 0) {
		answer_integer = serverinfo->fRoundRobin;
		is_integer = 1;
	} else if (strcasecmp(operation, "RpcProtocol") == 0) {
		answer_integer = serverinfo->dwRpcProtocol;
		is_integer = 1;
	} else if (strcasecmp(operation, "SecureResponses") == 0) {
		answer_integer = serverinfo->fSecureResponses;
		is_integer = 1;
	} else if (strcasecmp(operation, "SendPort") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ScavengingInterval") == 0) {
		answer_integer = serverinfo->dwScavengingInterval;
		is_integer = 1;
	} else if (strcasecmp(operation, "SocketPoolSize") == 0) {
		answer_integer = 0x000009C4;
		is_integer = 1;
	} else if (strcasecmp(operation, "StrictFileParsing") == 0) {
		answer_integer = serverinfo->fStrictFileParsing;
		is_integer = 1;
	} else if (strcasecmp(operation, "SyncDnsZoneSerial") == 0) {
		answer_integer = 2; /* ZONE_SERIAL_SYNC_XFER */
		is_integer = 1;
	} else if (strcasecmp(operation, "UpdateOptions") == 0) {
		answer_integer = 0x0000030F; /* DNS_DEFAULT_UPDATE_OPTIONS */
		is_integer = 1;
	} else if (strcasecmp(operation, "UseSystemEvengLog") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "Version") == 0) {
		answer_integer = serverinfo->dwVersion;
		is_integer = 1;
	} else if (strcasecmp(operation, "XfrConnectTimeout") == 0) {
		answer_integer = 0x0000001E;
		is_integer = 1;
	} else if (strcasecmp(operation, "WriteAuthorityNs") == 0) {
		answer_integer = serverinfo->fWriteAuthorityNs;
		is_integer = 1;
	} else if (strcasecmp(operation, "AdditionalRecursionTimeout") == 0) {
		answer_integer = 0x00000004;
		is_integer = 1;
	} else if (strcasecmp(operation, "AppendMsZoneTransferFlag") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "AutoCreateDelegations") == 0) {
		answer_integer = 0; /* DNS_ACD_DONT_CREATE */
		is_integer = 1;
	} else if (strcasecmp(operation, "BreakOnAscFailure") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "CacheEmptyAuthResponses") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DirectoryPartitionAutoEnlistInterval") == 0) {
		answer_integer = 0x00015180; /* 1 day */
		is_integer = 1;
	} else if (strcasecmp(operation, "DisableAutoReverseZones") == 0) {
		answer_integer = ~serverinfo->fAutoReverseZones;
		is_integer = 1;
	} else if (strcasecmp(operation, "EDnsCacheTimeout") == 0) {
		answer_integer = 0x00000384; /* 15 minutes */
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableDirectoryPartitions") == 0) {
		answer_integer = serverinfo->fDsAvailable;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableDnsSec") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableEDnsProbes") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableEDnsReception") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableIPv6") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableIQueryResponseGeneration") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableSendErrorSuppression") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableUpdateForwarding") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableWinsR") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceDsaBehaviorVersion") == 0) {
		answer_integer = serverinfo->dwDsDsaVersion;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceDomainBehaviorVersion") == 0) {
		answer_integer = serverinfo->dwDsDsaVersion;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceForestBehaviorVersion") == 0) {
		answer_integer = serverinfo->dwDsDsaVersion;
		is_integer = 1;
	} else if (strcasecmp(operation, "HeapDebug") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "LameDelegationTtl") == 0) {
		answer_integer = 0; /* seconds */
		is_integer = 1;
	} else if (strcasecmp(operation, "LocalNetPriorityNetMask") == 0) {
		answer_integer = serverinfo->dwLocalNetPriorityNetMask;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaxCacheSize") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaxResourceRecordsInNonSecureUpdate") == 0) {
		answer_integer = 0x0000001E;
		is_integer = 1;
	} else if (strcasecmp(operation, "OperationsLogLevel") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "OperationsLogLevel2") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaximumUdpPacketSize") == 0) {
		answer_integer = 0x00004000; /* maximum possible */
		is_integer = 1;
	} else if (strcasecmp(operation, "RecurseToInternetRootMask") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "SelfTest") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "SilentlyIgnoreCNameUpdateConflicts") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "TcpReceivePacketSize") == 0) {
		answer_integer = 0x00010000;
		is_integer = 1;
	} else if (strcasecmp(operation, "XfrThrottleMultiplier") == 0) {
		answer_integer = 0x0000000A;
		is_integer = 1;
	} else if (strcasecmp(operation, "AllowMsdcsLookupRetry") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "AllowReadOnlyZoneTransfer") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DsBackGroundLoadPaused") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DsMinimumBackgroundLoadThreads") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DsRemoteReplicationDelay") == 0) {
		answer_integer = 0x0000001E; /* 30 seconds */
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableDuplicateQuerySuppresion") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableGlobalNamesSupport") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableVersionQuery") == 0) {
		answer_integer = 1; /* DNS_VERSION_QUERY_FULL */
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableRsoForRodc") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForceRODCMode") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesAlwaysQuerySrv") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesBlockUpdates") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesEnableEDnsProbes") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesPreferAAAA") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesQueryOrder") == 0) {
		answer_integer = 1;
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesSendTimeout") == 0) {
		answer_integer = 3; /* seconds */
		is_integer = 1;
	} else if (strcasecmp(operation, "GlobalNamesServerQueryInterval") == 0) {
		answer_integer = 0x00005460; /* 6 hours */
		is_integer = 1;
	} else if (strcasecmp(operation, "RemoteIPv4RankBoost") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "RemoteIPv6RankBoost") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaximumRodcRsoAttemptsPerCycle") == 0) {
		answer_integer = 0x00000064;
		is_integer = 1;
	} else if (strcasecmp(operation, "MaximumRodcRsoQueueLength") == 0) {
		answer_integer = 0x0000012C;
		is_integer = 1;
	} else if (strcasecmp(operation, "EnableGlobalQueryBlockList") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "OpenACLOnProxyUpdates") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "CacheLockingPercent") == 0) {
		answer_integer = 0x00000064;
		is_integer = 1;
	}

	if (is_integer == 1) {
		*typeid = DNSSRV_TYPEID_DWORD;
		r->Dword = answer_integer;
		return WERR_OK;
	}

	is_addresses = 0;

	if (strcasecmp(operation, "Forwarders") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipForwarders);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, serverinfo->aipForwarders);
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "ListenAddresses") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipListenAddrs);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, serverinfo->aipListenAddrs);
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "BreakOnReceiveFrom") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = NULL;
		} else {
			answer_iparray = NULL;
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "BreakOnUpdateFrom") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = NULL;
		} else {
			answer_iparray = NULL;
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "LogIPFilterList") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, serverinfo->aipLogFilter);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, serverinfo->aipLogFilter);
		}
		is_addresses = 1;
	}

	if (is_addresses == 1) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			*typeid = DNSSRV_TYPEID_ADDRARRAY;
			r->AddrArray = answer_addrarray;
		} else {
			*typeid = DNSSRV_TYPEID_IPARRAY;
			r->IpArray = answer_iparray;
		}
		return WERR_OK;
	}

	is_string = is_wstring = 0;

	if (strcasecmp(operation, "DomainDirectoryPartitionBaseName") == 0) {
		answer_string = talloc_strdup(mem_ctx, "DomainDnsZones");
		if (! answer_string) {
			return WERR_OUTOFMEMORY;
		}
		is_string = 1;
	} else if (strcasecmp(operation, "ForestDirectoryPartitionBaseName") == 0) {
		answer_string = talloc_strdup(mem_ctx, "ForestDnsZones");
		if (! answer_string) {
			return WERR_OUTOFMEMORY;
		}
		is_string = 1;
	} else if (strcasecmp(operation, "LogFilePath") == 0) {
		answer_string = talloc_strdup(mem_ctx, serverinfo->pwszLogFilePath);
		is_wstring = 1;
	} else if (strcasecmp(operation, "ServerLevelPluginDll") == 0) {
		answer_string = NULL;
		is_wstring = 1;
	} else if (strcasecmp(operation, "DsBackgroundPauseName") == 0) {
		answer_string = NULL;
		is_string = 1;
	} else if (strcasecmp(operation, "DsNotRoundRobinTypes") == 0) {
		answer_string = NULL;
		is_string = 1;
	}

	if (is_string == 1) {
		*typeid = DNSSRV_TYPEID_LPSTR;
		r->String = answer_string;
		return WERR_OK;
	} else if (is_wstring == 1) {
		*typeid = DNSSRV_TYPEID_LPWSTR;
		r->WideString = answer_string;
		return WERR_OK;
	}

	is_stringlist = 0;

	if (strcasecmp(operation, "GlobalQueryBlockList") == 0) {
		answer_stringlist = NULL;
		is_stringlist = 1;
	} else if (strcasecmp(operation, "SocketPoolExcludedPortRanges") == 0) {
		answer_stringlist = NULL;
		is_stringlist = 1;
	}

	if (is_stringlist == 1) {
		*typeid = DNSSRV_TYPEID_UTF8_STRING_LIST;
		r->Utf8StringList = answer_stringlist;
		return WERR_OK;
	}

	DEBUG(0,("dnsserver: Invalid server operation %s", operation));
	return WERR_DNS_ERROR_INVALID_PROPERTY;
}

/* [MS-DNSP].pdf Section 3.1.1.2 Zone Configuration Information */
static WERROR dnsserver_query_zone(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					struct dnsserver_zone *z,
					const char *operation,
					const unsigned int client_version,
					enum DNS_RPC_TYPEID *typeid,
					union DNSSRV_RPC_UNION *r)
{
	uint8_t is_integer, is_addresses, is_string;
	uint32_t answer_integer;
	struct IP4_ARRAY *answer_iparray;
	struct DNS_ADDR_ARRAY *answer_addrarray;
	char *answer_string;
	struct dnsserver_zoneinfo *zoneinfo;

	zoneinfo = z->zoneinfo;

	if (strcasecmp(operation, "Zone") == 0) {
		if (client_version == DNS_CLIENT_VERSION_W2K) {
			*typeid = DNSSRV_TYPEID_ZONE_W2K;
			r->ZoneW2K = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_W2K);

			r->ZoneW2K->pszZoneName = talloc_strdup(mem_ctx, z->name);
			r->ZoneW2K->Flags = zoneinfo->Flags;
			r->ZoneW2K->ZoneType = zoneinfo->dwZoneType;
			r->ZoneW2K->Version = zoneinfo->Version;
		} else {
			*typeid = DNSSRV_TYPEID_ZONE;
			r->Zone = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_DOTNET);

			r->Zone->dwRpcStructureVersion = 0x01;
			r->Zone->pszZoneName = talloc_strdup(mem_ctx, z->name);
			r->Zone->Flags = zoneinfo->Flags;
			r->Zone->ZoneType = zoneinfo->dwZoneType;
			r->Zone->Version = zoneinfo->Version;
			r->Zone->dwDpFlags = z->partition->dwDpFlags;
			r->Zone->pszDpFqdn = talloc_strdup(mem_ctx, z->partition->pszDpFqdn);
		}
		return WERR_OK;
	}

	if (strcasecmp(operation, "ZoneInfo") == 0) {
		if (client_version == DNS_CLIENT_VERSION_W2K) {
			*typeid = DNSSRV_TYPEID_ZONE_INFO_W2K;
			r->ZoneInfoW2K = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_INFO_W2K);

			r->ZoneInfoW2K->pszZoneName = talloc_strdup(mem_ctx, z->name);
			r->ZoneInfoW2K->dwZoneType = zoneinfo->dwZoneType;
			r->ZoneInfoW2K->fReverse = zoneinfo->fReverse;
			r->ZoneInfoW2K->fAllowUpdate = zoneinfo->fAllowUpdate;
			r->ZoneInfoW2K->fPaused = zoneinfo->fPaused;
			r->ZoneInfoW2K->fShutdown = zoneinfo->fShutdown;
			r->ZoneInfoW2K->fAutoCreated = zoneinfo->fAutoCreated;
			r->ZoneInfoW2K->fUseDatabase = zoneinfo->fUseDatabase;
			r->ZoneInfoW2K->pszDataFile = talloc_strdup(mem_ctx, zoneinfo->pszDataFile);
			r->ZoneInfoW2K->aipMasters = ip4_array_copy(mem_ctx, zoneinfo->aipMasters);
			r->ZoneInfoW2K->fSecureSecondaries = zoneinfo->fSecureSecondaries;
			r->ZoneInfoW2K->fNotifyLevel = zoneinfo->fNotifyLevel;
			r->ZoneInfoW2K->aipSecondaries = ip4_array_copy(mem_ctx, zoneinfo->aipSecondaries);
			r->ZoneInfoW2K->aipNotify = ip4_array_copy(mem_ctx, zoneinfo->aipNotify);
			r->ZoneInfoW2K->fUseWins = zoneinfo->fUseWins;
			r->ZoneInfoW2K->fUseNbstat = zoneinfo->fUseNbstat;
			r->ZoneInfoW2K->fAging = zoneinfo->fAging;
			r->ZoneInfoW2K->dwNoRefreshInterval = zoneinfo->dwNoRefreshInterval;
			r->ZoneInfoW2K->dwRefreshInterval = zoneinfo->dwRefreshInterval;
			r->ZoneInfoW2K->dwAvailForScavengeTime = zoneinfo->dwAvailForScavengeTime;
			r->ZoneInfoW2K->aipScavengeServers = ip4_array_copy(mem_ctx, zoneinfo->aipScavengeServers);

		} else if (client_version == DNS_CLIENT_VERSION_DOTNET) {
			*typeid = DNSSRV_TYPEID_ZONE_INFO_DOTNET;
			r->ZoneInfoDotNet = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_INFO_DOTNET);

			r->ZoneInfoDotNet->dwRpcStructureVersion = 0x01;
			r->ZoneInfoDotNet->pszZoneName = talloc_strdup(mem_ctx, z->name);
			r->ZoneInfoDotNet->dwZoneType = zoneinfo->dwZoneType;
			r->ZoneInfoDotNet->fReverse = zoneinfo->fReverse;
			r->ZoneInfoDotNet->fAllowUpdate = zoneinfo->fAllowUpdate;
			r->ZoneInfoDotNet->fPaused = zoneinfo->fPaused;
			r->ZoneInfoDotNet->fShutdown = zoneinfo->fShutdown;
			r->ZoneInfoDotNet->fAutoCreated = zoneinfo->fAutoCreated;
			r->ZoneInfoDotNet->fUseDatabase = zoneinfo->fUseDatabase;
			r->ZoneInfoDotNet->pszDataFile = talloc_strdup(mem_ctx, zoneinfo->pszDataFile);
			r->ZoneInfoDotNet->aipMasters = ip4_array_copy(mem_ctx, zoneinfo->aipMasters);
			r->ZoneInfoDotNet->fSecureSecondaries = zoneinfo->fSecureSecondaries;
			r->ZoneInfoDotNet->fNotifyLevel = zoneinfo->fNotifyLevel;
			r->ZoneInfoDotNet->aipSecondaries = ip4_array_copy(mem_ctx, zoneinfo->aipSecondaries);
			r->ZoneInfoDotNet->aipNotify = ip4_array_copy(mem_ctx, zoneinfo->aipNotify);
			r->ZoneInfoDotNet->fUseWins = zoneinfo->fUseWins;
			r->ZoneInfoDotNet->fUseNbstat = zoneinfo->fUseNbstat;
			r->ZoneInfoDotNet->fAging = zoneinfo->fAging;
			r->ZoneInfoDotNet->dwNoRefreshInterval = zoneinfo->dwNoRefreshInterval;
			r->ZoneInfoDotNet->dwRefreshInterval = zoneinfo->dwRefreshInterval;
			r->ZoneInfoDotNet->dwAvailForScavengeTime = zoneinfo->dwAvailForScavengeTime;
			r->ZoneInfoDotNet->aipScavengeServers = ip4_array_copy(mem_ctx, zoneinfo->aipScavengeServers);
			r->ZoneInfoDotNet->dwForwarderTimeout = zoneinfo->dwForwarderTimeout;
			r->ZoneInfoDotNet->fForwarderSlave = zoneinfo->fForwarderSlave;
			r->ZoneInfoDotNet->aipLocalMasters = ip4_array_copy(mem_ctx, zoneinfo->aipLocalMasters);
			r->ZoneInfoDotNet->dwDpFlags = z->partition->dwDpFlags;
			r->ZoneInfoDotNet->pszDpFqdn = talloc_strdup(mem_ctx, z->partition->pszDpFqdn);
			r->ZoneInfoDotNet->pwszZoneDn = talloc_strdup(mem_ctx, zoneinfo->pwszZoneDn);
			r->ZoneInfoDotNet->dwLastSuccessfulSoaCheck = zoneinfo->dwLastSuccessfulSoaCheck;
			r->ZoneInfoDotNet->dwLastSuccessfulXfr = zoneinfo->dwLastSuccessfulXfr;

		} else {
			*typeid = DNSSRV_TYPEID_ZONE_INFO;
			r->ZoneInfo = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_INFO_LONGHORN);

			r->ZoneInfo->dwRpcStructureVersion = 0x02;
			r->ZoneInfo->pszZoneName = talloc_strdup(mem_ctx, z->name);
			r->ZoneInfo->dwZoneType = zoneinfo->dwZoneType;
			r->ZoneInfo->fReverse = zoneinfo->fReverse;
			r->ZoneInfo->fAllowUpdate = zoneinfo->fAllowUpdate;
			r->ZoneInfo->fPaused = zoneinfo->fPaused;
			r->ZoneInfo->fShutdown = zoneinfo->fShutdown;
			r->ZoneInfo->fAutoCreated = zoneinfo->fAutoCreated;
			r->ZoneInfo->fUseDatabase = zoneinfo->fUseDatabase;
			r->ZoneInfo->pszDataFile = talloc_strdup(mem_ctx, zoneinfo->pszDataFile);
			r->ZoneInfo->aipMasters = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipMasters);
			r->ZoneInfo->fSecureSecondaries = zoneinfo->fSecureSecondaries;
			r->ZoneInfo->fNotifyLevel = zoneinfo->fNotifyLevel;
			r->ZoneInfo->aipSecondaries = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipSecondaries);
			r->ZoneInfo->aipNotify = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipNotify);
			r->ZoneInfo->fUseWins = zoneinfo->fUseWins;
			r->ZoneInfo->fUseNbstat = zoneinfo->fUseNbstat;
			r->ZoneInfo->fAging = zoneinfo->fAging;
			r->ZoneInfo->dwNoRefreshInterval = zoneinfo->dwNoRefreshInterval;
			r->ZoneInfo->dwRefreshInterval = zoneinfo->dwRefreshInterval;
			r->ZoneInfo->dwAvailForScavengeTime = zoneinfo->dwAvailForScavengeTime;
			r->ZoneInfo->aipScavengeServers = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipScavengeServers);
			r->ZoneInfo->dwForwarderTimeout = zoneinfo->dwForwarderTimeout;
			r->ZoneInfo->fForwarderSlave = zoneinfo->fForwarderSlave;
			r->ZoneInfo->aipLocalMasters = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipLocalMasters);
			r->ZoneInfo->dwDpFlags = z->partition->dwDpFlags;
			r->ZoneInfo->pszDpFqdn = talloc_strdup(mem_ctx, z->partition->pszDpFqdn);
			r->ZoneInfo->pwszZoneDn = talloc_strdup(mem_ctx, zoneinfo->pwszZoneDn);
			r->ZoneInfo->dwLastSuccessfulSoaCheck = zoneinfo->dwLastSuccessfulSoaCheck;
			r->ZoneInfo->dwLastSuccessfulXfr = zoneinfo->dwLastSuccessfulXfr;

			r->ZoneInfo->fQueuedForBackgroundLoad = zoneinfo->fQueuedForBackgroundLoad;
			r->ZoneInfo->fBackgroundLoadInProgress = zoneinfo->fBackgroundLoadInProgress;
			r->ZoneInfo->fReadOnlyZone = zoneinfo->fReadOnlyZone;
			r->ZoneInfo->dwLastXfrAttempt = zoneinfo->dwLastXfrAttempt;
			r->ZoneInfo->dwLastXfrResult = zoneinfo->dwLastXfrResult;
		}

		return WERR_OK;
	}

	is_integer = 0;

	if (strcasecmp(operation, "AllowUpdate") == 0) {
		answer_integer = zoneinfo->fAllowUpdate;
		is_integer = 1;
	} else if (strcasecmp(operation, "Secured") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "DsIntegrated") == 0) {
		answer_integer = zoneinfo->fUseDatabase;
		is_integer = 1;
	} else if (strcasecmp(operation, "LogUpdates") == 0) {
		answer_integer = 0;
		is_integer = 1;
	} else if (strcasecmp(operation, "NoRefreshInterval") == 0) {
		answer_integer = zoneinfo->dwNoRefreshInterval;
		is_integer = 1;
	} else if (strcasecmp(operation, "NotifyLevel") == 0) {
		answer_integer = zoneinfo->fNotifyLevel;
		is_integer = 1;
	} else if (strcasecmp(operation, "RefreshInterval") == 0) {
		answer_integer = zoneinfo->dwRefreshInterval;
		is_integer = 1;
	} else if (strcasecmp(operation, "SecureSecondaries") == 0) {
		answer_integer = zoneinfo->fSecureSecondaries;
		is_integer = 1;
	} else if (strcasecmp(operation, "Type") == 0) {
		answer_integer = zoneinfo->dwZoneType;
		is_integer = 1;
	} else if (strcasecmp(operation, "Aging") == 0) {
		answer_integer = zoneinfo->fAging;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForwarderSlave") == 0) {
		answer_integer = zoneinfo->fForwarderSlave;
		is_integer = 1;
	} else if (strcasecmp(operation, "ForwarderTimeout") == 0) {
		answer_integer = zoneinfo->dwForwarderTimeout;
		is_integer = 1;
	} else if (strcasecmp(operation, "Unicode") == 0) {
		answer_integer = 0;
		is_integer = 1;
	}

	if (is_integer == 1) {
		*typeid = DNSSRV_TYPEID_DWORD;
		r->Dword = answer_integer;
		return WERR_OK;
	}

	is_addresses = 0;

	if (strcasecmp(operation, "AllowNSRecordsAutoCreation") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = NULL;
		} else {
			answer_iparray = NULL;
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "ScavengeServers") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipScavengeServers);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, zoneinfo->aipScavengeServers);
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "MasterServers") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipMasters);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, zoneinfo->aipMasters);
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "LocalMasterServers") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipLocalMasters);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, zoneinfo->aipLocalMasters);
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "NotifyServers") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipNotify);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, zoneinfo->aipNotify);
		}
		is_addresses = 1;
	} else if (strcasecmp(operation, "SecondaryServers") == 0) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			answer_addrarray = ip4_array_to_dns_addr_array(mem_ctx, zoneinfo->aipSecondaries);
		} else {
			answer_iparray = ip4_array_copy(mem_ctx, zoneinfo->aipSecondaries);
		}
		is_addresses = 1;
	}

	if (is_addresses == 1) {
		if (client_version == DNS_CLIENT_VERSION_LONGHORN) {
			*typeid = DNSSRV_TYPEID_ADDRARRAY;
			r->AddrArray = answer_addrarray;
		} else {
			*typeid = DNSSRV_TYPEID_IPARRAY;
			r->IpArray = answer_iparray;
		}
		return WERR_OK;
	}

	is_string = 0;

	if (strcasecmp(operation, "DatabaseFile") == 0) {
		answer_string = talloc_strdup(mem_ctx, zoneinfo->pszDataFile);
		is_string = 1;
	} else if (strcasecmp(operation, "ApplicationDirectoryPartition") == 0) {
		answer_string = talloc_strdup(mem_ctx, z->partition->pszDpFqdn);
		is_string = 1;
	} else if (strcasecmp(operation, "BreakOnNameUpdate") == 0) {
		answer_string = NULL;
		is_string = 1;
	}

	if (is_string == 1) {
		*typeid = DNSSRV_TYPEID_LPSTR;
		r->String = answer_string;
		return WERR_OK;
	}

	DEBUG(0,("dnsserver: Invalid zone operation %s", operation));
	return WERR_DNS_ERROR_INVALID_PROPERTY;

}

/* dnsserver operation functions */

/* [MS-DNSP].pdf Section 3.1.1.1 DNS Server Configuration Information */
static WERROR dnsserver_operate_server(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					const char *operation,
					const unsigned int client_version,
					enum DNS_RPC_TYPEID typeid,
					union DNSSRV_RPC_UNION *r)
{
	bool valid_operation = false;

	if (strcasecmp(operation, "ResetDwordProperty") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "Restart") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ClearDebugLog") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ClearCache") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "WriteDirtyZones") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ZoneCreate") == 0) {
		struct dnsserver_zone *z, *z2;
		WERROR status;

		z = talloc_zero(mem_ctx, struct dnsserver_zone);
		W_ERROR_HAVE_NO_MEMORY(z);
		z->partition = talloc_zero(z, struct dnsserver_partition);
		W_ERROR_HAVE_NO_MEMORY_AND_FREE(z->partition, z);
		z->zoneinfo = talloc_zero(z, struct dnsserver_zoneinfo);
		W_ERROR_HAVE_NO_MEMORY_AND_FREE(z->zoneinfo, z);

		if (typeid == DNSSRV_TYPEID_ZONE_CREATE_W2K) {
			z->name = talloc_strdup(z, r->ZoneCreateW2K->pszZoneName);
			z->zoneinfo->dwZoneType = r->ZoneCreateW2K->dwZoneType;
			z->zoneinfo->fAllowUpdate = r->ZoneCreateW2K->fAllowUpdate;
			z->zoneinfo->fAging = r->ZoneCreateW2K->fAging;
			z->zoneinfo->Flags = r->ZoneCreateW2K->dwFlags;
		} else if (typeid == DNSSRV_TYPEID_ZONE_CREATE_DOTNET) {
			z->name = talloc_strdup(z, r->ZoneCreateDotNet->pszZoneName);
			z->zoneinfo->dwZoneType = r->ZoneCreateDotNet->dwZoneType;
			z->zoneinfo->fAllowUpdate = r->ZoneCreateDotNet->fAllowUpdate;
			z->zoneinfo->fAging = r->ZoneCreateDotNet->fAging;
			z->zoneinfo->Flags = r->ZoneCreateDotNet->dwFlags;
			z->partition->dwDpFlags = r->ZoneCreateDotNet->dwDpFlags;
		} else if (typeid == DNSSRV_TYPEID_ZONE_CREATE) {
			z->name = talloc_strdup(z, r->ZoneCreate->pszZoneName);
			z->zoneinfo->dwZoneType = r->ZoneCreate->dwZoneType;
			z->zoneinfo->fAllowUpdate = r->ZoneCreate->fAllowUpdate;
			z->zoneinfo->fAging = r->ZoneCreate->fAging;
			z->zoneinfo->Flags = r->ZoneCreate->dwFlags;
			z->partition->dwDpFlags = r->ZoneCreate->dwDpFlags;
		} else {
			talloc_free(z);
			return WERR_DNS_ERROR_INVALID_PROPERTY;
		}

		z2 = dnsserver_find_zone(dsstate->zones, z->name);
		if (z2 != NULL) {
			talloc_free(z);
			return WERR_DNS_ERROR_ZONE_ALREADY_EXISTS;
		}

		status = dnsserver_db_create_zone(dsstate->samdb, dsstate->partitions, z,
						  dsstate->lp_ctx);
		talloc_free(z);

		if (W_ERROR_IS_OK(status)) {
			dnsserver_reload_zones(dsstate);
		}
		return status;
	} else if (strcasecmp(operation, "ClearStatistics") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "EnlistDirectoryPartition") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "StartScavenging") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "AbortScavenging") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "AutoConfigure") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ExportSettings") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "PrepareForDemotion") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "PrepareForUninstall") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DeleteNode") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DeleteRecord") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "WriteBackFile") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ListenAddresses") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "Forwarders") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "LogFilePath") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "LogIpFilterList") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ForestDirectoryPartitionBaseName") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DomainDirectoryPartitionBaseName") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "GlobalQueryBlockList") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "BreakOnReceiveFrom") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "BreakOnUpdateFrom") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ServerLevelPluginDll") == 0) {
		valid_operation = true;
	}

	if (valid_operation) {
		DEBUG(0, ("dnsserver: server operation '%s' not implemented", operation));
		return WERR_CALL_NOT_IMPLEMENTED;
	}

	DEBUG(0, ("dnsserver: invalid server operation '%s'", operation));
	return WERR_DNS_ERROR_INVALID_PROPERTY;
}

static WERROR dnsserver_complex_operate_server(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					const char *operation,
					const unsigned int client_version,
					enum DNS_RPC_TYPEID typeid_in,
					union DNSSRV_RPC_UNION *rin,
					enum DNS_RPC_TYPEID *typeid_out,
					union DNSSRV_RPC_UNION *rout)
{
	int valid_operation = 0;
	struct dnsserver_zone *z, **zlist;
	int zcount;
	bool found1, found2, found3, found4;
	int i;

	if (strcasecmp(operation, "QueryDwordProperty") == 0) {
		if (typeid_in == DNSSRV_TYPEID_LPSTR) {
			return dnsserver_query_server(dsstate, mem_ctx,
							rin->String,
							client_version,
							typeid_out,
							rout);
		}
	} else if (strcasecmp(operation, "EnumZones") == 0) {
		if (typeid_in != DNSSRV_TYPEID_DWORD) {
			return WERR_DNS_ERROR_INVALID_PROPERTY;
		}

		zcount = 0;
		zlist = talloc_zero_array(mem_ctx, struct dnsserver_zone *, 0);
		for (z = dsstate->zones; z; z = z->next) {

			/* Match the flags in groups
			 *
			 * Group1 : PRIMARY, SECONDARY, CACHE, AUTO
			 * Group2 : FORWARD, REVERSE, FORWARDER, STUB
			 * Group3 : DS, NON_DS, DOMAIN_DP, FOREST_DP
			 * Group4 : CUSTOM_DP, LEGACY_DP
			 */
			
			/* Group 1 */
			found1 = false;
			if (rin->Dword & 0x0000000f) {
				if (rin->Dword & DNS_ZONE_REQUEST_PRIMARY) {
					if (z->zoneinfo->dwZoneType == DNS_ZONE_TYPE_PRIMARY) {
					found1 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_SECONDARY) {
					if (z->zoneinfo->dwZoneType == DNS_ZONE_TYPE_SECONDARY) {
						found1 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_CACHE) {
					if (z->zoneinfo->dwZoneType == DNS_ZONE_TYPE_CACHE) {
						found1 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_AUTO) {
					if (z->zoneinfo->fAutoCreated 
						|| z->partition->dwDpFlags & DNS_DP_AUTOCREATED) {
						found1 = true;
					}
				}
			} else {
				found1 = true;
			}

			/* Group 2 */
			found2 = false;
			if (rin->Dword & 0x000000f0) {
				if (rin->Dword & DNS_ZONE_REQUEST_FORWARD) {
					if (!(z->zoneinfo->fReverse)) {
						found2 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_REVERSE) {
					if (z->zoneinfo->fReverse) {
						found2 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_FORWARDER) {
					if (z->zoneinfo->dwZoneType == DNS_ZONE_TYPE_FORWARDER) {
						found2 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_STUB) {
					if (z->zoneinfo->dwZoneType == DNS_ZONE_TYPE_STUB) {
						found2 = true;
					}
				}
			} else {
				found2 = true;
			}

			/* Group 3 */
			found3 = false;
			if (rin->Dword & 0x00000f00) {
				if (rin->Dword & DNS_ZONE_REQUEST_DS) {
					if (z->zoneinfo->Flags & DNS_RPC_ZONE_DSINTEGRATED) {
						found3 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_NON_DS) {
					if (!(z->zoneinfo->Flags & DNS_RPC_ZONE_DSINTEGRATED)) {
						found3 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_DOMAIN_DP) {
					if (!(z->partition->dwDpFlags & DNS_DP_DOMAIN_DEFAULT)) {
						found3 = true;
					}
				}
				if (rin->Dword & DNS_ZONE_REQUEST_FOREST_DP) {
					if (!(z->partition->dwDpFlags & DNS_DP_FOREST_DEFAULT)) {
						found3 = true;
					}
				}
			} else {
				found3 = true;
			}
	
			/* Group 4 */
			if (rin->Dword & 0x0000f000) {
				found4 = false;
			} else {
				found4 = true;
			}

			if (found1 && found2 && found3 && found4) {
				zlist = talloc_realloc(mem_ctx, zlist, struct dnsserver_zone *, zcount+1);
				zlist[zcount] = z;
				zcount++;
			}
		}

		if (client_version == DNS_CLIENT_VERSION_W2K) {
			*typeid_out = DNSSRV_TYPEID_ZONE_LIST_W2K;
			rout->ZoneListW2K = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_LIST_W2K);

			if (zcount == 0) {
				rout->ZoneListW2K->dwZoneCount = 0;
				rout->ZoneListW2K->ZoneArray = NULL;

				return WERR_OK;
			}

			rout->ZoneListW2K->ZoneArray = talloc_zero_array(mem_ctx, struct DNS_RPC_ZONE_W2K *, zcount);
			W_ERROR_HAVE_NO_MEMORY_AND_FREE(rout->ZoneListW2K->ZoneArray, zlist);

			for (i=0; i<zcount; i++) {
				rout->ZoneListW2K->ZoneArray[i] = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_W2K);

				rout->ZoneListW2K->ZoneArray[i]->pszZoneName = talloc_strdup(mem_ctx, zlist[i]->name);
				rout->ZoneListW2K->ZoneArray[i]->Flags = zlist[i]->zoneinfo->Flags;
				rout->ZoneListW2K->ZoneArray[i]->ZoneType = zlist[i]->zoneinfo->dwZoneType;
				rout->ZoneListW2K->ZoneArray[i]->Version = zlist[i]->zoneinfo->Version;
			}
			rout->ZoneListW2K->dwZoneCount = zcount;

		} else {
			*typeid_out = DNSSRV_TYPEID_ZONE_LIST;
			rout->ZoneList = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_LIST_DOTNET);

			if (zcount == 0) {
				rout->ZoneList->dwRpcStructureVersion = 1;
				rout->ZoneList->dwZoneCount = 0;
				rout->ZoneList->ZoneArray = NULL;

				return WERR_OK;
			}

			rout->ZoneList->ZoneArray = talloc_zero_array(mem_ctx, struct DNS_RPC_ZONE_DOTNET *, zcount);
			W_ERROR_HAVE_NO_MEMORY_AND_FREE(rout->ZoneList->ZoneArray, zlist);

			for (i=0; i<zcount; i++) {
				rout->ZoneList->ZoneArray[i] = talloc_zero(mem_ctx, struct DNS_RPC_ZONE_DOTNET);

				rout->ZoneList->ZoneArray[i]->dwRpcStructureVersion = 1;
				rout->ZoneList->ZoneArray[i]->pszZoneName = talloc_strdup(mem_ctx, zlist[i]->name);
				rout->ZoneList->ZoneArray[i]->Flags = zlist[i]->zoneinfo->Flags;
				rout->ZoneList->ZoneArray[i]->ZoneType = zlist[i]->zoneinfo->dwZoneType;
				rout->ZoneList->ZoneArray[i]->Version = zlist[i]->zoneinfo->Version;
				rout->ZoneList->ZoneArray[i]->dwDpFlags = zlist[i]->partition->dwDpFlags;
				rout->ZoneList->ZoneArray[i]->pszDpFqdn = talloc_strdup(mem_ctx, zlist[i]->partition->pszDpFqdn);
			}
			rout->ZoneList->dwRpcStructureVersion = 1;
			rout->ZoneList->dwZoneCount = zcount;
		}
		talloc_free(zlist);
		return WERR_OK;
	} else if (strcasecmp(operation, "EnumZones2") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "EnumDirectoryPartitions") == 0) {
		if (typeid_in != DNSSRV_TYPEID_DWORD) {
			return WERR_DNS_ERROR_INVALID_PROPERTY;
		}

		*typeid_out = DNSSRV_TYPEID_DP_LIST;
		rout->DirectoryPartitionList = talloc_zero(mem_ctx, struct DNS_RPC_DP_LIST);

		if (rin->Dword != 0) {
			rout->DirectoryPartitionList->dwDpCount = 0;
			rout->DirectoryPartitionList->DpArray = NULL;
		} else {
			struct DNS_RPC_DP_ENUM **dplist;
			struct dnsserver_partition *p;
			int pcount = 2;

			dplist = talloc_zero_array(mem_ctx, struct DNS_RPC_DP_ENUM *, pcount);
			W_ERROR_HAVE_NO_MEMORY(dplist);

			p = dsstate->partitions;
			for (i=0; i<pcount; i++) {
				dplist[i] = talloc_zero(dplist, struct DNS_RPC_DP_ENUM);

				dplist[i]->pszDpFqdn = talloc_strdup(mem_ctx, p->pszDpFqdn);
				dplist[i]->dwFlags = p->dwDpFlags;
				dplist[i]->dwZoneCount = p->zones_count;
				p = p->next;
			}

			rout->DirectoryPartitionList->dwDpCount = pcount;
			rout->DirectoryPartitionList->DpArray = dplist;
		}
		return WERR_OK;
	} else if (strcasecmp(operation, "DirectoryPartitionInfo") == 0) {
		struct dnsserver_partition *p;
		struct dnsserver_partition_info *partinfo;
		struct DNS_RPC_DP_INFO *dpinfo = NULL;

		if (typeid_in != DNSSRV_TYPEID_LPSTR) {
			return WERR_DNS_ERROR_INVALID_PROPERTY;
		}

		*typeid_out = DNSSRV_TYPEID_DP_INFO;

		for (p = dsstate->partitions; p; p = p->next) {
			if (strcasecmp(p->pszDpFqdn, rin->String) == 0) {
				dpinfo = talloc_zero(mem_ctx, struct DNS_RPC_DP_INFO);
				W_ERROR_HAVE_NO_MEMORY(dpinfo);

				partinfo = dnsserver_db_partition_info(mem_ctx, dsstate->samdb, p);
				W_ERROR_HAVE_NO_MEMORY(partinfo);

				dpinfo->pszDpFqdn = talloc_strdup(dpinfo, p->pszDpFqdn);
				dpinfo->pszDpDn = talloc_strdup(dpinfo, ldb_dn_get_linearized(p->partition_dn));
				dpinfo->pszCrDn = talloc_steal(dpinfo, partinfo->pszCrDn);
				dpinfo->dwFlags = p->dwDpFlags;
				dpinfo->dwZoneCount = p->zones_count;
				dpinfo->dwState = partinfo->dwState;
				dpinfo->dwReplicaCount = partinfo->dwReplicaCount;
				if (partinfo->dwReplicaCount > 0) {
					dpinfo->ReplicaArray = talloc_steal(dpinfo,
									    partinfo->ReplicaArray);
				} else {
					dpinfo->ReplicaArray = NULL;
				}
				break;
			}
		}

		if (dpinfo == NULL) {
			return WERR_DNS_ERROR_DP_DOES_NOT_EXIST;
		}

		rout->DirectoryPartition = dpinfo;
		return WERR_OK;
	} else if (strcasecmp(operation, "Statistics") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "IpValidate") == 0) {
		valid_operation = true;
	}

	if (valid_operation) {
		DEBUG(0, ("dnsserver: server complex operation '%s' not implemented", operation));
		return WERR_CALL_NOT_IMPLEMENTED;
	}

	DEBUG(0, ("dnsserver: invalid server complex operation '%s'", operation));
	return WERR_DNS_ERROR_INVALID_PROPERTY;
}

/* [MS-DNSP].pdf Section 3.1.1.2 Zone Configuration Information */
static WERROR dnsserver_operate_zone(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					struct dnsserver_zone *z,
					unsigned int request_filter,
					const char *operation,
					const unsigned int client_version,
					enum DNS_RPC_TYPEID typeid,
					union DNSSRV_RPC_UNION *r)
{
	bool valid_operation = false;

	if (strcasecmp(operation, "ResetDwordProperty") == 0) {
		if (typeid != DNSSRV_TYPEID_NAME_AND_PARAM) {
			return WERR_DNS_ERROR_INVALID_PROPERTY;
		}

		/* Ignore property resets */
		if (strcasecmp(r->NameAndParam->pszNodeName, "AllowUpdate") == 0) {
			return WERR_OK;
		}
		valid_operation = true;
	} else if (strcasecmp(operation, "ZoneTypeReset") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "PauseZone") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ResumeZone") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DeleteZone") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ReloadZone") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "RefreshZone") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ExpireZone") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "IncrementVersion") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "WriteBackFile") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DeleteZoneFromDs") == 0) {
		WERROR status;
		if (z == NULL) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}
		status =  dnsserver_db_delete_zone(dsstate->samdb, z);
		if (W_ERROR_IS_OK(status)) {
			dnsserver_reload_zones(dsstate);
		}
		return status;
	} else if (strcasecmp(operation, "UpdateZoneFromDs") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ZoneExport") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ZoneChangeDirectoryPartition") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DeleteNode") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DeleteRecordSet") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ForceAgingOnNode") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "DatabaseFile") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "MasterServers") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "LocalMasterServers") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "NotifyServers") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "SecondaryServers") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ScavengingServers") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "AllowNSRecordsAutoCreation") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "BreakOnNameUpdate") == 0) {
		valid_operation = true;
	} else if (strcasecmp(operation, "ApplicationDirectoryPartition") == 0) {
		valid_operation = true;
	}

	if (valid_operation) {
		DEBUG(0, ("dnsserver: zone operation '%s' not implemented", operation));
		return WERR_CALL_NOT_IMPLEMENTED;
	}

	DEBUG(0, ("dnsserver: invalid zone operation '%s'", operation));
	return WERR_DNS_ERROR_INVALID_PROPERTY;
}

static WERROR dnsserver_complex_operate_zone(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					struct dnsserver_zone *z,
					const char *operation,
					const unsigned int client_version,
					enum DNS_RPC_TYPEID typeid_in,
					union DNSSRV_RPC_UNION *rin,
					enum DNS_RPC_TYPEID *typeid_out,
					union DNSSRV_RPC_UNION *rout)
{
	if (strcasecmp(operation, "QueryDwordProperty") == 0) {
		if (typeid_in == DNSSRV_TYPEID_LPSTR) {
			return dnsserver_query_zone(dsstate, mem_ctx, z,
						rin->String,
						client_version,
						typeid_out,
						rout);

		}
	}

	DEBUG(0,("dnsserver: Invalid zone operation %s", operation));
	return WERR_DNS_ERROR_INVALID_PROPERTY;
}

/* dnsserver enumerate function */

static WERROR dnsserver_enumerate_root_records(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					unsigned int client_version,
					const char *node_name,
					enum dns_record_type record_type,
					unsigned int select_flag,
					unsigned int *buffer_length,
					struct DNS_RPC_RECORDS_ARRAY **buffer)
{
	TALLOC_CTX *tmp_ctx;
	struct dnsserver_zone *z;
	const char * const attrs[] = { "name", "dnsRecord", NULL };
	struct ldb_result *res;
	struct DNS_RPC_RECORDS_ARRAY *recs;
	char **add_names;
	char *rname;
	int add_count;
	int i, ret, len;
	WERROR status;

	tmp_ctx = talloc_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(tmp_ctx);

	z = dnsserver_find_zone(dsstate->zones, ".");
	if (z == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	ret = ldb_search(dsstate->samdb, tmp_ctx, &res, z->zone_dn,
				LDB_SCOPE_ONELEVEL, attrs, "(&(objectClass=dnsNode)(name=@))");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return WERR_INTERNAL_DB_ERROR;
	}
	if (res->count == 0) {
		talloc_free(tmp_ctx);
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	recs = talloc_zero(mem_ctx, struct DNS_RPC_RECORDS_ARRAY);
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(recs, tmp_ctx);

	add_names = NULL;
	add_count = 0;

	for (i=0; i<res->count; i++) {
		status = dns_fill_records_array(tmp_ctx, NULL, record_type,
						select_flag, NULL,
						res->msgs[i], 0, recs,
						&add_names, &add_count);
		if (!W_ERROR_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
	}
	talloc_free(res);

	/* Add any additional records */
	if (select_flag & DNS_RPC_VIEW_ADDITIONAL_DATA) {
		for (i=0; i<add_count; i++) {
			ret = ldb_search(dsstate->samdb, tmp_ctx, &res, z->zone_dn,
					LDB_SCOPE_ONELEVEL, attrs,
					"(&(objectClass=dnsNode)(name=%s))", add_names[i]);
			if (ret != LDB_SUCCESS || res->count == 0) {
				talloc_free(res);
				continue;
			}

			len = strlen(add_names[i]);
			if (add_names[i][len-1] == '.') {
				rname = talloc_strdup(tmp_ctx, add_names[i]);
			} else {
				rname = talloc_asprintf(tmp_ctx, "%s.", add_names[i]);
			}
			status = dns_fill_records_array(tmp_ctx, NULL, DNS_TYPE_A,
							select_flag, rname,
							res->msgs[0], 0, recs,
							NULL, NULL);
			talloc_free(rname);
			talloc_free(res);
		}
	}

	talloc_free(tmp_ctx);

	*buffer_length = ndr_size_DNS_RPC_RECORDS_ARRAY(recs, 0);
	*buffer = recs;

	return WERR_OK;
}


static WERROR dnsserver_enumerate_records(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					struct dnsserver_zone *z,
					unsigned int client_version,
					const char *node_name,
					const char *start_child,
					enum dns_record_type record_type,
					unsigned int select_flag,
					const char *filter_start,
					const char *filter_stop,
					unsigned int *buffer_length,
					struct DNS_RPC_RECORDS_ARRAY **buffer)
{
	TALLOC_CTX *tmp_ctx;
	char *name;
	const char * const attrs[] = { "name", "dnsRecord", NULL };
	struct ldb_result *res;
	struct DNS_RPC_RECORDS_ARRAY *recs;
	char **add_names = NULL;
	char *rname;
	int add_count = 0;
	int i, ret, len;
	WERROR status;
	struct dns_tree *tree, *base, *node;

	tmp_ctx = talloc_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(tmp_ctx);

	name = dns_split_node_name(tmp_ctx, node_name, z->name);
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(name, tmp_ctx);

	/* search all records under parent tree */
	if (strcasecmp(name, z->name) == 0) {
		ret = ldb_search(dsstate->samdb, tmp_ctx, &res, z->zone_dn,
				LDB_SCOPE_ONELEVEL, attrs, "(objectClass=dnsNode)");
	} else {
		ret = ldb_search(dsstate->samdb, tmp_ctx, &res, z->zone_dn,
				LDB_SCOPE_ONELEVEL, attrs,
				"(&(objectClass=dnsNode)(|(name=%s)(name=*.%s)))",
				name, name);
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return WERR_INTERNAL_DB_ERROR;
	}
	if (res->count == 0) {
		talloc_free(tmp_ctx);
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	recs = talloc_zero(mem_ctx, struct DNS_RPC_RECORDS_ARRAY);
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(recs, tmp_ctx);

	/* Sort the names, so that the first record is the parent record */
	ldb_qsort(res->msgs, res->count, sizeof(struct ldb_message *), name,
			(ldb_qsort_cmp_fn_t)dns_name_compare);

	/* Build a tree of name components from dns name */
	if (strcasecmp(name, z->name) == 0) {
		tree = dns_build_tree(tmp_ctx, "@", res);
	} else {
		tree = dns_build_tree(tmp_ctx, name, res);
	}
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(tree, tmp_ctx);

	/* Find the parent record in the tree */
	base = tree;
	while (base->level != -1) {
		base = base->children[0];
	}

	/* Add the parent record with blank name */
	if (!(select_flag & DNS_RPC_VIEW_ONLY_CHILDREN)) {
		status = dns_fill_records_array(tmp_ctx, z, record_type,
						select_flag, NULL,
						base->data, 0,
						recs, &add_names, &add_count);
		if (!W_ERROR_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
	}

	/* Add all the children records */
	if (!(select_flag & DNS_RPC_VIEW_NO_CHILDREN)) {
		for (i=0; i<base->num_children; i++) {
			node = base->children[i];

			status = dns_fill_records_array(tmp_ctx, z, record_type,
							select_flag, node->name,
							node->data, node->num_children,
							recs, &add_names, &add_count);
			if (!W_ERROR_IS_OK(status)) {
				talloc_free(tmp_ctx);
				return status;
			}
		}
	}

	talloc_free(res);
	talloc_free(tree);
	talloc_free(name);

	/* Add any additional records */
	if (select_flag & DNS_RPC_VIEW_ADDITIONAL_DATA) {
		for (i=0; i<add_count; i++) {
			struct dnsserver_zone *z2;

			/* Search all the available zones for additional name */
			for (z2 = dsstate->zones; z2; z2 = z2->next) {
				name = dns_split_node_name(tmp_ctx, add_names[i], z2->name);
				ret = ldb_search(dsstate->samdb, tmp_ctx, &res, z2->zone_dn,
						LDB_SCOPE_ONELEVEL, attrs,
						"(&(objectClass=dnsNode)(name=%s))", name);
				talloc_free(name);
				if (ret != LDB_SUCCESS) {
					continue;
				}
				if (res->count == 1) {
					break;
				} else {
					talloc_free(res);
					continue;
				}
			}

			len = strlen(add_names[i]);
			if (add_names[i][len-1] == '.') {
				rname = talloc_strdup(tmp_ctx, add_names[i]);
			} else {
				rname = talloc_asprintf(tmp_ctx, "%s.", add_names[i]);
			}
			status = dns_fill_records_array(tmp_ctx, NULL, DNS_TYPE_A,
							select_flag, rname,
							res->msgs[0], 0, recs,
							NULL, NULL);
			talloc_free(rname);
			talloc_free(res);
		}
	}

	*buffer_length = ndr_size_DNS_RPC_RECORDS_ARRAY(recs, 0);
	*buffer = recs;

	return WERR_OK;
}

/* dnsserver update function */

static WERROR dnsserver_update_record(struct dnsserver_state *dsstate,
					TALLOC_CTX *mem_ctx,
					struct dnsserver_zone *z,
					unsigned int client_version,
					const char *node_name,
					struct DNS_RPC_RECORD_BUF *add_buf,
					struct DNS_RPC_RECORD_BUF *del_buf)
{
	TALLOC_CTX *tmp_ctx;
	char *name;
	WERROR status;

	tmp_ctx = talloc_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(tmp_ctx);

	/* If node_name is @ or zone name, dns record is @ */
	if (strcmp(node_name, "@") == 0 || strcasecmp(node_name, z->name) == 0) {
		name = talloc_strdup(tmp_ctx, "@");
	} else {
		name = dns_split_node_name(tmp_ctx, node_name, z->name);
	}
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(name, tmp_ctx);

	if (add_buf != NULL) {
		if (del_buf == NULL) {
			/* Add record */
			status = dnsserver_db_add_record(tmp_ctx, dsstate->samdb,
								z, name,
								&add_buf->rec);
		} else {
			/* Update record */
			status = dnsserver_db_update_record(tmp_ctx, dsstate->samdb,
								z, name,
								&add_buf->rec,
								&del_buf->rec);
		}
	} else {
		if (del_buf == NULL) {
			/* Add empty node */
			status = dnsserver_db_add_empty_node(tmp_ctx, dsstate->samdb,
								z, name);
		} else {
			/* Delete record */
			status = dnsserver_db_delete_record(tmp_ctx, dsstate->samdb,
								z, name,
								&del_buf->rec);
		}
	}

	talloc_free(tmp_ctx);
	return status;
}


/* dnsserver interface functions */

static WERROR dcesrv_DnssrvOperation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvOperation *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z = NULL;
	uint32_t request_filter = 0;
	WERROR ret;

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.dwContext == 0) {
		if (r->in.pszZone != NULL) {
			request_filter = dnsserver_zone_to_request_filter(r->in.pszZone);
		}
	} else {
		request_filter = r->in.dwContext;
	}

	if (r->in.pszZone == NULL) {
		ret = dnsserver_operate_server(dsstate, mem_ctx,
						r->in.pszOperation,
						DNS_CLIENT_VERSION_W2K,
						r->in.dwTypeId,
						&r->in.pData);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL && request_filter == 0) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}

		ret = dnsserver_operate_zone(dsstate, mem_ctx, z,
						request_filter,
						r->in.pszOperation,
						DNS_CLIENT_VERSION_W2K,
						r->in.dwTypeId,
						&r->in.pData);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvOperation, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvQuery(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvQuery *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	ZERO_STRUCTP(r->out.pdwTypeId);
	ZERO_STRUCTP(r->out.ppData);

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		/* FIXME: DNS Server Configuration Access Control List */
		ret = dnsserver_query_server(dsstate, mem_ctx,
						r->in.pszOperation,
						DNS_CLIENT_VERSION_W2K,
						r->out.pdwTypeId,
						r->out.ppData);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}

		ret = dnsserver_query_zone(dsstate, mem_ctx, z,
						r->in.pszOperation,
						DNS_CLIENT_VERSION_W2K,
						r->out.pdwTypeId,
						r->out.ppData);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvQuery, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvComplexOperation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvComplexOperation *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	ZERO_STRUCTP(r->out.pdwTypeOut);
	ZERO_STRUCTP(r->out.ppDataOut);

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		/* Server operation */
		ret = dnsserver_complex_operate_server(dsstate, mem_ctx,
							r->in.pszOperation,
							DNS_CLIENT_VERSION_W2K,
							r->in.dwTypeIn,
							&r->in.pDataIn,
							r->out.pdwTypeOut,
							r->out.ppDataOut);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}

		ret = dnsserver_complex_operate_zone(dsstate, mem_ctx, z,
							r->in.pszOperation,
							DNS_CLIENT_VERSION_W2K,
							r->in.dwTypeIn,
							&r->in.pDataIn,
							r->out.pdwTypeOut,
							r->out.ppDataOut);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvComplexOperation, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvEnumRecords(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvEnumRecords *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	ZERO_STRUCTP(r->out.pdwBufferLength);
	ZERO_STRUCTP(r->out.pBuffer);

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	if (strcasecmp(r->in.pszZone, "..RootHints") == 0) {
		ret = dnsserver_enumerate_root_records(dsstate, mem_ctx,
					DNS_CLIENT_VERSION_W2K,
					r->in.pszNodeName,
					r->in.wRecordType,
					r->in.fSelectFlag,
					r->out.pdwBufferLength,
					r->out.pBuffer);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL) {
			return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
		}

		ret = dnsserver_enumerate_records(dsstate, mem_ctx, z,
					DNS_CLIENT_VERSION_W2K,
					r->in.pszNodeName,
					r->in.pszStartChild,
					r->in.wRecordType,
					r->in.fSelectFlag,
					r->in.pszFilterStart,
					r->in.pszFilterStop,
					r->out.pdwBufferLength,
					r->out.pBuffer);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvEnumRecords, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvUpdateRecord(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvUpdateRecord *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
	if (z == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	ret = dnsserver_update_record(dsstate, mem_ctx, z,
					DNS_CLIENT_VERSION_W2K,
					r->in.pszNodeName,
					r->in.pAddRecord,
					r->in.pDeleteRecord);

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvUpdateRecord, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvOperation2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvOperation2 *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z = NULL;
	uint32_t request_filter = 0;
	WERROR ret;

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.dwContext == 0) {
		if (r->in.pszZone != NULL) {
			request_filter = dnsserver_zone_to_request_filter(r->in.pszZone);
		}
	} else {
		request_filter = r->in.dwContext;
	}

	if (r->in.pszZone == NULL) {
		ret = dnsserver_operate_server(dsstate, mem_ctx,
						r->in.pszOperation,
						r->in.dwClientVersion,
						r->in.dwTypeId,
						&r->in.pData);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL && request_filter == 0) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}

		ret = dnsserver_operate_zone(dsstate, mem_ctx, z,
						request_filter,
						r->in.pszOperation,
						r->in.dwClientVersion,
						r->in.dwTypeId,
						&r->in.pData);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvOperation2, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvQuery2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvQuery2 *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	ZERO_STRUCTP(r->out.pdwTypeId);
	ZERO_STRUCTP(r->out.ppData);

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		/* FIXME: DNS Server Configuration Access Control List */
		ret = dnsserver_query_server(dsstate, mem_ctx,
						r->in.pszOperation,
						r->in.dwClientVersion,
						r->out.pdwTypeId,
						r->out.ppData);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}

		ret = dnsserver_query_zone(dsstate, mem_ctx, z,
					r->in.pszOperation,
					r->in.dwClientVersion,
					r->out.pdwTypeId,
					r->out.ppData);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvQuery2, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvComplexOperation2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvComplexOperation2 *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	ZERO_STRUCTP(r->out.pdwTypeOut);
	ZERO_STRUCTP(r->out.ppDataOut);

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		/* Server operation */
		ret =  dnsserver_complex_operate_server(dsstate, mem_ctx,
							r->in.pszOperation,
							r->in.dwClientVersion,
							r->in.dwTypeIn,
							&r->in.pDataIn,
							r->out.pdwTypeOut,
							r->out.ppDataOut);
	} else {

		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL) {
			return WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST;
		}

		ret = dnsserver_complex_operate_zone(dsstate, mem_ctx, z,
							r->in.pszOperation,
							r->in.dwClientVersion,
							r->in.dwTypeIn,
							&r->in.pDataIn,
							r->out.pdwTypeOut,
							r->out.ppDataOut);
	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvComplexOperation2, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvEnumRecords2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvEnumRecords2 *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	ZERO_STRUCTP(r->out.pdwBufferLength);
	ZERO_STRUCTP(r->out.pBuffer);

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	if (strcasecmp(r->in.pszZone, "..RootHints") == 0) {
		ret =  dnsserver_enumerate_root_records(dsstate, mem_ctx,
					r->in.dwClientVersion,
					r->in.pszNodeName,
					r->in.wRecordType,
					r->in.fSelectFlag,
					r->out.pdwBufferLength,
					r->out.pBuffer);
	} else {
		z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
		if (z == NULL) {
			return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
		}

		ret =  dnsserver_enumerate_records(dsstate, mem_ctx, z,
					r->in.dwClientVersion,
					r->in.pszNodeName,
					r->in.pszStartChild,
					r->in.wRecordType,
					r->in.fSelectFlag,
					r->in.pszFilterStart,
					r->in.pszFilterStop,
					r->out.pdwBufferLength,
					r->out.pBuffer);

	}

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvEnumRecords2, NDR_IN, r);
	}
	return ret;
}

static WERROR dcesrv_DnssrvUpdateRecord2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct DnssrvUpdateRecord2 *r)
{
	struct dnsserver_state *dsstate;
	struct dnsserver_zone *z;
	WERROR ret;

	if ((dsstate = dnsserver_connect(dce_call)) == NULL) {
		return WERR_DNS_ERROR_DS_UNAVAILABLE;
	}

	if (r->in.pszZone == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	z = dnsserver_find_zone(dsstate->zones, r->in.pszZone);
	if (z == NULL) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}

	ret = dnsserver_update_record(dsstate, mem_ctx, z,
					r->in.dwClientVersion,
					r->in.pszNodeName,
					r->in.pAddRecord,
					r->in.pDeleteRecord);

	if (W_ERROR_EQUAL(ret, WERR_CALL_NOT_IMPLEMENTED)) {
		NDR_PRINT_FUNCTION_DEBUG(DnssrvUpdateRecord2, NDR_IN, r);
	}
	return ret;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_dnsserver_s.c"
