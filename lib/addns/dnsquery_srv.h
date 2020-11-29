/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_ADDNS_DNSQUERY_SRV_H__
#define __LIB_ADDNS_DNSQUERY_SRV_H__

#include "replace.h"
#include <tevent.h>
#include "libcli/util/ntstatus.h"
#include "libcli/dns/dns.h"

struct tevent_req *ads_dns_query_srv_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t async_dns_timeout,
	const char *sitename,
	const char *query);
NTSTATUS ads_dns_query_srv_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct dns_rr_srv **srvs,
	size_t *num_srvs);
NTSTATUS ads_dns_query_srv(
	TALLOC_CTX *mem_ctx,
	uint32_t async_dns_timeout,
	const char *sitename,
	const char *query,
	struct dns_rr_srv **srvs,
	size_t *num_srvs);

char *ads_dns_query_string_dcs(TALLOC_CTX *mem_ctx, const char *realm);
char *ads_dns_query_string_gcs(TALLOC_CTX *mem_ctx, const char *realm);
char *ads_dns_query_string_kdcs(TALLOC_CTX *mem_ctx, const char *realm);
char *ads_dns_query_string_pdc(TALLOC_CTX *mem_ctx, const char *realm);

struct GUID;
char *ads_dns_query_string_dcs_guid(
	TALLOC_CTX *mem_ctx,
	const struct GUID *domain_guid,
	const char *realm);

#endif	/* _ADS_DNS_H */
