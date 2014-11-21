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
#include "dnsserver.h"
#include "rpc_server/common/common.h"
#include "dsdb/samdb/samdb.h"
#include "lib/socket/netif.h"
#include "lib/util/util_net.h"

static struct DNS_ADDR_ARRAY *fill_dns_addr_array(TALLOC_CTX *mem_ctx,
					   struct loadparm_context *lp_ctx,
					   bool listen_only)
{
	struct interface *ifaces;
	int num_interfaces, i;
	struct DNS_ADDR_ARRAY *dns_addr_array;
	const char *ipstr;
	bool have_ipv4, have_ipv6;
	uint16_t family;

	have_ipv4 = have_ipv6 = false;

	if (!listen_only) {
		/*
		  Return all interfaces from kernel
		  Not implemented!
		*/
		return NULL;
	}

	/* Only the used interfaces */
	load_interface_list(mem_ctx, lp_ctx, &ifaces);
	num_interfaces = iface_list_count(ifaces);

	dns_addr_array = talloc_zero(mem_ctx, struct DNS_ADDR_ARRAY);
	if (dns_addr_array == NULL) {
		goto nomem;
	}
	dns_addr_array->MaxCount = num_interfaces;
	dns_addr_array->AddrCount = num_interfaces;
	if (num_interfaces == 0) {
		goto nomem;
	}

	dns_addr_array->AddrArray = talloc_zero_array(mem_ctx, struct DNS_ADDR,
						      num_interfaces);
	if (!dns_addr_array->AddrArray) {
		TALLOC_FREE(dns_addr_array);
		goto nomem;
	}

	for (i = 0; i < num_interfaces; i++) {
		ipstr = iface_list_n_ip(ifaces, i);
		if (is_ipaddress_v4(ipstr)) {
			have_ipv4 = true;
			dns_addr_array->AddrArray[i].MaxSa[0] = 0x02;
			inet_pton(AF_INET, ipstr,
				  &dns_addr_array->AddrArray[i].MaxSa[4]);
		} else {
			have_ipv6 = true;
			dns_addr_array->AddrArray[i].MaxSa[0] = 0x17;
			inet_pton(AF_INET6, ipstr,
				  &dns_addr_array->AddrArray[i].MaxSa[8]);
		}
	}

	if (have_ipv4 && have_ipv6) {
		family = 0;   /* mixed: MS-DNSP */
	} else if (have_ipv4 && !have_ipv6) {
		family = AF_INET;
	} else {
		family = AF_INET6;
	}
	dns_addr_array->Family = family;

nomem:
	talloc_free(ifaces);
	return dns_addr_array;
}

struct dnsserver_serverinfo *dnsserver_init_serverinfo(TALLOC_CTX *mem_ctx,
							struct loadparm_context *lp_ctx,
							struct ldb_context *samdb)
{
	struct dnsserver_serverinfo *serverinfo;
	struct dcerpc_server_info *dinfo;
	struct ldb_dn *domain_dn, *forest_dn;

	serverinfo = talloc_zero(mem_ctx, struct dnsserver_serverinfo);
	if (serverinfo == NULL) {
		return NULL;
	}

	dinfo = lpcfg_dcerpc_server_info(mem_ctx, lp_ctx);
	if (dinfo) {
		serverinfo->dwVersion = (dinfo->version_build & 0x0000FFFF) << 16 |
				(dinfo->version_minor & 0x000000FF) << 8 |
				(dinfo->version_major & 0x000000FF);
		talloc_free(dinfo);
	} else {
		serverinfo->dwVersion = 0x0ECE0205; /* build, os_minor, os_major */;
	}

	serverinfo->fBootMethod = DNS_BOOT_METHOD_DIRECTORY;
	serverinfo->fAdminConfigured = 0;
	serverinfo->fAllowUpdate = 1;
	serverinfo->fDsAvailable = 1;

	serverinfo->pszServerName = talloc_asprintf(mem_ctx, "%s.%s",
					lpcfg_netbios_name(lp_ctx),
					lpcfg_dnsdomain(lp_ctx));

	domain_dn = ldb_get_default_basedn(samdb);
	forest_dn = ldb_get_root_basedn(samdb);

	serverinfo->pszDsContainer = talloc_asprintf(mem_ctx,
					"CN=MicrosoftDNS,DC=DomainDnsZones,%s",
					ldb_dn_get_linearized(domain_dn));

	serverinfo->dwDsForestVersion = dsdb_forest_functional_level(samdb);
	serverinfo->dwDsDomainVersion = dsdb_functional_level(samdb);
	serverinfo->dwDsDsaVersion = 4; /* need to do ldb search here */

	serverinfo->pszDomainName = samdb_dn_to_dns_domain(mem_ctx, domain_dn);
	serverinfo->pszForestName = samdb_dn_to_dns_domain(mem_ctx, forest_dn);

	serverinfo->pszDomainDirectoryPartition = talloc_asprintf(mem_ctx,
							"DC=DomainDnsZones,%s",
							ldb_dn_get_linearized(domain_dn));
	serverinfo->pszForestDirectoryPartition = talloc_asprintf(mem_ctx,
							"DC=ForestDnsZones,%s",
							ldb_dn_get_linearized(forest_dn));
	/* IP addresses on which the DNS server listens for DNS requests */
	serverinfo->aipListenAddrs = fill_dns_addr_array(mem_ctx, lp_ctx, true);

	/* All IP addresses available on the server
	 * Not implemented!
	 * Use same as listen addresses
	 */
	serverinfo->aipServerAddrs = serverinfo->aipListenAddrs;

	serverinfo->aipForwarders = NULL;

	serverinfo->aipLogFilter = NULL;
	serverinfo->pwszLogFilePath = NULL;

	serverinfo->dwLogLevel = 0;
	serverinfo->dwDebugLevel = 0;
	serverinfo->dwEventLogLevel = DNS_EVENT_LOG_INFORMATION_TYPE;
	serverinfo->dwLogFileMaxSize = 0;

	serverinfo->dwForwardTimeout = 3; /* seconds (default) */
	serverinfo->dwRpcProtocol = 5;
	serverinfo->dwNameCheckFlag = DNS_ALLOW_MULTIBYTE_NAMES;
	serverinfo->cAddressAnswerLimit = 0;
	serverinfo->dwRecursionRetry = 3 /* seconds (default) */;
	serverinfo->dwRecursionTimeout = 8 /* seconds (default) */;
	serverinfo->dwMaxCacheTtl = 0x00015180; /* 1 day (default) */;
	serverinfo->dwDsPollingInterval = 0xB4; /* 3 minutes (default) */;
	serverinfo->dwLocalNetPriorityNetMask = 0x000000FF;;

	serverinfo->dwScavengingInterval = 0;
	serverinfo->dwDefaultRefreshInterval = 0xA8; /* 7 days in hours */;
	serverinfo->dwDefaultNoRefreshInterval = 0xA8; /* 7 days in hours */;;
	serverinfo->dwLastScavengeTime = 0;

	serverinfo->fAutoReverseZones = 0;
	serverinfo->fAutoCacheUpdate = 0;

	serverinfo->fRecurseAfterForwarding = 0;
	serverinfo->fForwardDelegations = 1;
	serverinfo->fNoRecursion = 0;
	serverinfo->fSecureResponses = 0;

	serverinfo->fRoundRobin = 1;
	serverinfo->fLocalNetPriority = 0;

	serverinfo->fBindSecondaries = 0;
	serverinfo->fWriteAuthorityNs = 0;

	serverinfo->fStrictFileParsing = 0;
	serverinfo->fLooseWildcarding = 0 ;
	serverinfo->fDefaultAgingState = 0;

	return serverinfo;
}


struct dnsserver_zoneinfo *dnsserver_init_zoneinfo(struct dnsserver_zone *zone,
						struct dnsserver_serverinfo *serverinfo)
{
	struct dnsserver_zoneinfo *zoneinfo;
	uint32_t fReverse;
	const char *revzone = "in-addr.arpa";
	const char *revzone6 = "ip6.arpa";
	int len1, len2;

	zoneinfo = talloc_zero(zone, struct dnsserver_zoneinfo);
	if (zoneinfo == NULL) {
		return NULL;
	}

	/* If the zone name ends with in-addr.arpa, it's reverse zone */
	/* If the zone name ends with ip6.arpa, it's reverse zone (IPv6) */
	fReverse = 0;
	len1 = strlen(zone->name);
	len2 = strlen(revzone);
	if (len1 > len2 && strcasecmp(&zone->name[len1-len2], revzone) == 0) {
		fReverse = 1;
	} else {
		len2 = strlen(revzone6);
		if (len1 > len2 && strcasecmp(&zone->name[len1-len2], revzone6) == 0) {
			fReverse = 1;
		}
	}

	zoneinfo->Version = 0x32;
	zoneinfo->Flags = DNS_RPC_ZONE_DSINTEGRATED;

	if (strcmp(zone->name, ".") == 0) {
		zoneinfo->dwZoneType = DNS_ZONE_TYPE_CACHE;
		zoneinfo->fAllowUpdate = DNS_ZONE_UPDATE_OFF;
		zoneinfo->fSecureSecondaries = DNS_ZONE_SECSECURE_NO_SECURITY;
		zoneinfo->fNotifyLevel = DNS_ZONE_NOTIFY_OFF;
		zoneinfo->dwNoRefreshInterval = 0;
		zoneinfo->dwRefreshInterval = 0;
	} else {
		zoneinfo->Flags |= DNS_RPC_ZONE_UPDATE_SECURE;
		zoneinfo->dwZoneType = DNS_ZONE_TYPE_PRIMARY;
		zoneinfo->fAllowUpdate = DNS_ZONE_UPDATE_SECURE;
		zoneinfo->fSecureSecondaries = DNS_ZONE_SECSECURE_NO_XFER;
		zoneinfo->fNotifyLevel = DNS_ZONE_NOTIFY_LIST_ONLY;
		zoneinfo->dwNoRefreshInterval = serverinfo->dwDefaultNoRefreshInterval;
		zoneinfo->dwRefreshInterval = serverinfo->dwDefaultRefreshInterval;
	}

	zoneinfo->fReverse = fReverse;
	zoneinfo->fPaused = 0;
	zoneinfo->fShutdown = 0;
	zoneinfo->fAutoCreated = 0;
	zoneinfo->fUseDatabase = 1;
	zoneinfo->pszDataFile = NULL;
	zoneinfo->aipMasters = NULL;
	zoneinfo->aipSecondaries = NULL;
	zoneinfo->aipNotify = NULL;
	zoneinfo->fUseWins = 0;
	zoneinfo->fUseNbstat = 0;
	zoneinfo->fAging = 0;
	zoneinfo->dwAvailForScavengeTime = 0;
	zoneinfo->aipScavengeServers = NULL;
	zoneinfo->dwForwarderTimeout = 0;
	zoneinfo->fForwarderSlave = 0;
	zoneinfo->aipLocalMasters = NULL;
	zoneinfo->pwszZoneDn = discard_const_p(char, ldb_dn_get_linearized(zone->zone_dn));
	zoneinfo->dwLastSuccessfulSoaCheck = 0;
	zoneinfo->dwLastSuccessfulXfr = 0;
	zoneinfo->fQueuedForBackgroundLoad = 0;
	zoneinfo->fBackgroundLoadInProgress = 0;
	zoneinfo->fReadOnlyZone = 0;
	zoneinfo->dwLastXfrAttempt = 0;
	zoneinfo->dwLastXfrResult = 0;

	return zoneinfo;
}

struct dnsserver_partition *dnsserver_find_partition(struct dnsserver_partition *partitions,
						     const char *dp_fqdn)
{
	struct dnsserver_partition *p = NULL;

	for (p = partitions; p; p = p->next) {
		if (strcasecmp(dp_fqdn, p->pszDpFqdn) == 0) {
			break;
		}
	}

	return p;
}

struct dnsserver_zone *dnsserver_find_zone(struct dnsserver_zone *zones, const char *zone_name)
{
	struct dnsserver_zone *z = NULL;

	for (z = zones; z; z = z->next) {
		if (strcasecmp(zone_name, z->name) == 0) {
			break;
		}
	}

	return z;
}

struct ldb_dn *dnsserver_name_to_dn(TALLOC_CTX *mem_ctx, struct dnsserver_zone *z, const char *name)
{
	struct ldb_dn *dn;
	bool ret;

	dn = ldb_dn_copy(mem_ctx, z->zone_dn);
	if (dn == NULL) {
		return NULL;
	}
	if (strcasecmp(name, z->name) == 0) {
		ret = ldb_dn_add_child_fmt(dn, "DC=@");
	} else {
		ret = ldb_dn_add_child_fmt(dn, "DC=%s", name);
	}
	if (!ret) {
		talloc_free(dn);
		return NULL;
	}

	return dn;
}

uint32_t dnsserver_zone_to_request_filter(const char *zone_name)
{
	uint32_t request_filter = 0;

	if (strcmp(zone_name, "..AllZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_PRIMARY
			| DNS_ZONE_REQUEST_SECONDARY
			| DNS_ZONE_REQUEST_AUTO
			| DNS_ZONE_REQUEST_FORWARD
			| DNS_ZONE_REQUEST_REVERSE
			| DNS_ZONE_REQUEST_FORWARDER
			| DNS_ZONE_REQUEST_STUB
			| DNS_ZONE_REQUEST_DS
			| DNS_ZONE_REQUEST_NON_DS
			| DNS_ZONE_REQUEST_DOMAIN_DP
			| DNS_ZONE_REQUEST_FOREST_DP
			| DNS_ZONE_REQUEST_CUSTOM_DP
			| DNS_ZONE_REQUEST_LEGACY_DP;
	} else if (strcmp(zone_name, "..AllZonesAndCache") == 0) {
		request_filter = DNS_ZONE_REQUEST_PRIMARY
			| DNS_ZONE_REQUEST_SECONDARY
			| DNS_ZONE_REQUEST_CACHE
			| DNS_ZONE_REQUEST_AUTO
			| DNS_ZONE_REQUEST_FORWARD
			| DNS_ZONE_REQUEST_REVERSE
			| DNS_ZONE_REQUEST_FORWARDER
			| DNS_ZONE_REQUEST_STUB
			| DNS_ZONE_REQUEST_DS
			| DNS_ZONE_REQUEST_NON_DS
			| DNS_ZONE_REQUEST_DOMAIN_DP
			| DNS_ZONE_REQUEST_FOREST_DP
			| DNS_ZONE_REQUEST_CUSTOM_DP
			| DNS_ZONE_REQUEST_LEGACY_DP;
	} else if (strcmp(zone_name, "..AllPrimaryZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_PRIMARY;
	} else if (strcmp(zone_name, "..AllSecondaryZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_SECONDARY;
	} else if (strcmp(zone_name, "..AllForwardZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_FORWARD;
	} else if (strcmp(zone_name, "..AllReverseZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_REVERSE;
	} else if (strcmp(zone_name, "..AllDsZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_DS;
	} else if (strcmp(zone_name, "..AllNonDsZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_NON_DS;
	} else if (strcmp(zone_name, "..AllPrimaryReverseZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_PRIMARY
			| DNS_ZONE_REQUEST_REVERSE;
	} else if (strcmp(zone_name, "..AllPrimaryForwardZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_PRIMARY
			| DNS_ZONE_REQUEST_FORWARD;
	} else if (strcmp(zone_name, "..AllSecondaryReverseZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_SECONDARY
			| DNS_ZONE_REQUEST_REVERSE;
	} else if (strcmp(zone_name, "..AllSecondaryForwardZones") == 0) {
		request_filter = DNS_ZONE_REQUEST_SECONDARY
			| DNS_ZONE_REQUEST_REVERSE;
	}

	return request_filter;
}
