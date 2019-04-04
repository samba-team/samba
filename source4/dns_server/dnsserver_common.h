/*
   Unix SMB/CIFS implementation.

   DNS server utils

   Copyright (C) 2014 Stefan Metzmacher

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

#include "rpc_server/dnsserver/dnsserver.h"

#ifndef __DNSSERVER_COMMON_H__
#define __DNSSERVER_COMMON_H__

uint8_t werr_to_dns_err(WERROR werr);
#define DNS_ERR(err_str) WERR_DNS_ERROR_RCODE_##err_str

struct ldb_message_element;
struct ldb_context;
struct dnsp_DnssrvRpcRecord;

struct dns_server_zone {
	struct dns_server_zone *prev, *next;
	const char *name;
	struct ldb_dn *dn;
};

WERROR dns_common_extract(struct ldb_context *samdb,
			  const struct ldb_message_element *el,
			  TALLOC_CTX *mem_ctx,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *num_records);

WERROR dns_common_lookup(struct ldb_context *samdb,
			 TALLOC_CTX *mem_ctx,
			 struct ldb_dn *dn,
			 struct dnsp_DnssrvRpcRecord **records,
			 uint16_t *num_records,
			 bool *tombstoned);
WERROR dns_common_wildcard_lookup(struct ldb_context *samdb,
				  TALLOC_CTX *mem_ctx,
				  struct ldb_dn *dn,
				  struct dnsp_DnssrvRpcRecord **records,
				  uint16_t *num_records);
WERROR dns_name_check(TALLOC_CTX *mem_ctx,
		      size_t len,
		      const char *name);
WERROR dns_get_zone_properties(struct ldb_context *samdb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_dn *zone_dn,
			       struct dnsserver_zoneinfo *zoneinfo);
bool dns_name_is_static(struct dnsp_DnssrvRpcRecord *records,
			uint16_t rec_count);
WERROR dns_common_replace(struct ldb_context *samdb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  bool needs_add,
			  uint32_t serial,
			  struct dnsp_DnssrvRpcRecord *records,
			  uint16_t rec_count);
bool dns_name_match(const char *zone, const char *name, size_t *host_part_len);
WERROR dns_common_name2dn(struct ldb_context *samdb,
			  struct dns_server_zone *zones,
			  TALLOC_CTX *mem_ctx,
			  const char *name,
			  struct ldb_dn **_dn);
bool dns_name_equal(const char *name1, const char *name2);

/*
 * For this routine, base_dn is generally NULL.  The exception comes
 * from the python bindings to support setting ACLs on DNS objects
 * when joining Windows
 */
NTSTATUS dns_common_zones(struct ldb_context *samdb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *base_dn,
			  struct dns_server_zone **zones_ret);

bool dns_zoneinfo_load_zone_property(struct dnsserver_zoneinfo *zoneinfo,
				     struct dnsp_DnsProperty *prop);
/*
 * Log a DNS operation along with it's duration
 * Enabled by setting a log level of "dns:10"
 *
 * const char *operation
 * const char *result
 * const struct timeval *start
 * const char *zone
 * const char *name
 * const char *data
 */
#define DNS_COMMON_LOG_OPERATION(result, start, zone, name, data) \
	if (CHECK_DEBUGLVLC(DBGC_DNS, DBGLVL_DEBUG)) { \
		struct timeval now = timeval_current(); \
		uint64_t duration = usec_time_diff(&now, (start));\
		const char *re = (result);\
		const char *zn = (zone); \
		const char *nm = (name); \
		const char *dt = (data); \
		DBG_DEBUG( \
			"DNS timing: result: [%s] duration: (%" PRIi64 ") " \
			"zone: [%s] name: [%s] data: [%s]\n", \
			re == NULL ? "" : re, \
			duration, \
			zn == NULL ? "" : zn, \
			nm == NULL ? "" : nm, \
			dt == NULL ? "" : dt); \
	}

#endif /* __DNSSERVER_COMMON_H__ */
