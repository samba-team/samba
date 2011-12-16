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

#ifndef __DNSSERVER_H__
#define __DNSSERVER_H__

#include "librpc/gen_ndr/dnsp.h"
#include "librpc/gen_ndr/dnsserver.h"
#include "param/param.h"
#include "ldb.h"

struct dnsserver_serverinfo {
	uint32_t	dwVersion;
	uint8_t		fBootMethod;
	uint8_t		fAdminConfigured;
	uint8_t		fAllowUpdate;
	uint8_t		fDsAvailable;

	char *		pszServerName;
	char *		pszDsContainer;

	uint32_t	dwDsForestVersion;
	uint32_t	dwDsDomainVersion;
	uint32_t	dwDsDsaVersion;
	uint32_t	fReadOnlyDC;
	char *		pszDomainName;
	char *		pszForestName;
	char *		pszDomainDirectoryPartition;
	char *		pszForestDirectoryPartition;

	struct IP4_ARRAY * aipServerAddrs;
	struct IP4_ARRAY * aipListenAddrs;
	struct IP4_ARRAY * aipForwarders;

	struct IP4_ARRAY * aipLogFilter;
	char *		pwszLogFilePath;

	uint32_t 	dwLogLevel;
	uint32_t 	dwDebugLevel;
	uint32_t 	dwEventLogLevel;
	uint32_t 	dwLogFileMaxSize;

	uint32_t 	dwForwardTimeout;
	uint32_t 	dwRpcProtocol;
	uint32_t 	dwNameCheckFlag;
	uint32_t 	cAddressAnswerLimit;
	uint32_t 	dwRecursionRetry;
	uint32_t 	dwRecursionTimeout;
	uint32_t 	dwMaxCacheTtl;
	uint32_t 	dwDsPollingInterval;
	uint32_t 	dwLocalNetPriorityNetMask;

	uint32_t 	dwScavengingInterval;
	uint32_t 	dwDefaultRefreshInterval;
	uint32_t 	dwDefaultNoRefreshInterval;
	uint32_t 	dwLastScavengeTime;

	uint8_t 	fAutoReverseZones;
	uint8_t 	fAutoCacheUpdate;

	uint8_t 	fRecurseAfterForwarding;
	uint8_t 	fForwardDelegations;
	uint8_t 	fNoRecursion;
	uint8_t 	fSecureResponses;

	uint8_t 	fRoundRobin;
	uint8_t 	fLocalNetPriority;

	uint8_t 	fBindSecondaries;
	uint8_t 	fWriteAuthorityNs;

	uint8_t 	fStrictFileParsing;
	uint8_t 	fLooseWildcarding;
	uint8_t 	fDefaultAgingState;
};

struct dnsserver_zoneinfo {
	uint8_t		Version;
	uint32_t	Flags;
	uint8_t		dwZoneType;
	uint8_t		fReverse;
	uint8_t		fAllowUpdate;
	uint8_t		fPaused;
	uint8_t		fShutdown;
	uint8_t		fAutoCreated;

	uint8_t		fUseDatabase;
	char *		pszDataFile;

	struct IP4_ARRAY * aipMasters;

	uint32_t	fSecureSecondaries;
	uint32_t	fNotifyLevel;
	struct IP4_ARRAY * aipSecondaries;
	struct IP4_ARRAY * aipNotify;

	uint32_t	fUseWins;
	uint32_t	fUseNbstat;

	uint32_t	fAging;
	uint32_t	dwNoRefreshInterval;
	uint32_t	dwRefreshInterval;
	uint32_t	dwAvailForScavengeTime;
	struct IP4_ARRAY * aipScavengeServers;

	uint32_t	dwForwarderTimeout;
	uint32_t	fForwarderSlave;

	struct IP4_ARRAY * aipLocalMasters;

	char *		pwszZoneDn;

	uint32_t	dwLastSuccessfulSoaCheck;
	uint32_t	dwLastSuccessfulXfr;

	uint32_t	fQueuedForBackgroundLoad;
	uint32_t	fBackgroundLoadInProgress;
	uint8_t		fReadOnlyZone;

	uint32_t	dwLastXfrAttempt;
	uint32_t	dwLastXfrResult;
};


struct dnsserver_partition {
	struct dnsserver_partition *prev, *next;
	struct ldb_dn *partition_dn;
	const char *pszDpFqdn;
	uint32_t dwDpFlags;
	bool is_forest;
	int zones_count;
};


struct dnsserver_partition_info {
	const char *pszCrDn;
	uint32_t dwState;
	uint32_t dwReplicaCount;
	struct DNS_RPC_DP_REPLICA **ReplicaArray;
};


struct dnsserver_zone {
	struct dnsserver_zone *prev, *next;
	struct dnsserver_partition *partition;
	const char *name;
	struct ldb_dn *zone_dn;
	struct dnsserver_zoneinfo *zoneinfo;
};


struct dns_tree {
	const char *name;
	int level;
	unsigned int num_children;
	struct dns_tree **children;
	void *data;
};

/* Data structure manipulation functions from dnsdata.c */

struct IP4_ARRAY *ip4_array_copy(TALLOC_CTX *mem_ctx, struct IP4_ARRAY *ip4);
struct DNS_ADDR_ARRAY *ip4_array_to_dns_addr_array(TALLOC_CTX *mem_ctx, struct IP4_ARRAY *ip4);
struct DNS_ADDR_ARRAY *dns_addr_array_copy(TALLOC_CTX *mem_ctx, struct DNS_ADDR_ARRAY *addr);

int dns_split_name_components(TALLOC_CTX *mem_ctx, const char *name, char ***components);
char *dns_split_node_name(TALLOC_CTX *mem_ctx, const char *node_name, const char *zone_name);

int dns_name_compare(const struct ldb_message **m1, const struct ldb_message **m2,
			char *search_name);
bool dns_name_equal(const char *name1, const char *name2);
bool dns_record_match(struct dnsp_DnssrvRpcRecord *rec1, struct dnsp_DnssrvRpcRecord *rec2);

void dnsp_to_dns_copy(TALLOC_CTX *mem_ctx, struct dnsp_DnssrvRpcRecord *dnsp,
			struct DNS_RPC_RECORD *dns);
struct dnsp_DnssrvRpcRecord *dns_to_dnsp_copy(TALLOC_CTX *mem_ctx, struct DNS_RPC_RECORD *dns);

struct dns_tree *dns_build_tree(TALLOC_CTX *mem_ctx, const char *name, struct ldb_result *res);
WERROR dns_fill_records_array(TALLOC_CTX *mem_ctx, struct dnsserver_zone *z,
			enum dns_record_type record_type,
			unsigned int select_flag, const char *zone_name,
			struct ldb_message *msg, int num_children,
			struct DNS_RPC_RECORDS_ARRAY *recs,
			char ***add_names, int *add_count);


/* Utility functions from dnsutils.c */

struct dnsserver_serverinfo *dnsserver_init_serverinfo(TALLOC_CTX *mem_ctx,
					struct loadparm_context *lp_ctx,
					struct ldb_context *samdb);
struct dnsserver_zoneinfo *dnsserver_init_zoneinfo(struct dnsserver_zone *zone,
					struct dnsserver_serverinfo *serverinfo);
struct dnsserver_partition *dnsserver_find_partition(struct dnsserver_partition *partitions,
					const char *dp_fqdn);
struct dnsserver_zone *dnsserver_find_zone(struct dnsserver_zone *zones,
					const char *zone_name);
struct ldb_dn *dnsserver_name_to_dn(TALLOC_CTX *mem_ctx, struct dnsserver_zone *z,
					const char *name);
uint32_t dnsserver_zone_to_request_filter(const char *zone);


/* Database functions from dnsdb.c */

struct dnsserver_partition *dnsserver_db_enumerate_partitions(TALLOC_CTX *mem_ctx,
					struct dnsserver_serverinfo *serverinfo,
					struct ldb_context *samdb);
struct dnsserver_zone *dnsserver_db_enumerate_zones(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_partition *p);
struct dnsserver_partition_info *dnsserver_db_partition_info(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_partition *p);
WERROR dnsserver_db_add_empty_node(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *node_name);
WERROR dnsserver_db_add_record(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *node_name,
					struct DNS_RPC_RECORD *add_record);
WERROR dnsserver_db_update_record(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *node_name,
					struct DNS_RPC_RECORD *add_record,
					struct DNS_RPC_RECORD *del_record);
WERROR dnsserver_db_delete_record(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *node_name,
					struct DNS_RPC_RECORD *del_record);
WERROR dnsserver_db_create_zone(struct ldb_context *samdb,
				struct dnsserver_partition *partitions,
				struct dnsserver_zone *z,
				struct loadparm_context *lp_ctx);
WERROR dnsserver_db_delete_zone(struct ldb_context *samdb,
				struct dnsserver_zone *z);

#endif /* __DNSSERVER_H__ */
