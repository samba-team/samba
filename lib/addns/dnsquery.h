/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Gerald Carter                2006.
 *
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

#ifndef __LIB_ADDNS_DNSQUERY_H__
#define __LIB_ADDNS_DNSQUERY_H__

#include "replace.h"
#include <tevent.h>
#include "libcli/dns/dns.h"
#include "lib/util/util_net.h"
#include "libcli/util/ntstatus.h"

/* The following definitions come from libads/dns.c  */

struct tevent_req *ads_dns_lookup_srv_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   const char *name);
NTSTATUS ads_dns_lookup_srv_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 struct dns_rr_srv **srvs,
				 size_t *num_srvs);
NTSTATUS ads_dns_lookup_srv(TALLOC_CTX *ctx,
				const char *name,
				struct dns_rr_srv **dclist,
				size_t *numdcs);
struct tevent_req *ads_dns_lookup_ns_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  const char *name);
NTSTATUS ads_dns_lookup_ns_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				struct dns_rr_ns **nss,
				size_t *num_nss);
NTSTATUS ads_dns_lookup_ns(TALLOC_CTX *ctx,
				const char *dnsdomain,
				struct dns_rr_ns **nslist,
				size_t *numns);
struct tevent_req *ads_dns_lookup_a_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				const char *name);
NTSTATUS ads_dns_lookup_a_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				uint8_t *rcode_out,
				size_t *num_names_out,
				char ***hostnames_out,
				struct samba_sockaddr **addrs_out);
NTSTATUS ads_dns_lookup_a(TALLOC_CTX *ctx,
			const char *name_in,
			size_t *num_names_out,
			char ***hostnames_out,
			struct samba_sockaddr **addrs_out);
#if defined(HAVE_IPV6)
struct tevent_req *ads_dns_lookup_aaaa_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				const char *name);
NTSTATUS ads_dns_lookup_aaaa_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				uint8_t *rcode_out,
				size_t *num_names_out,
				char ***hostnames_out,
				struct samba_sockaddr **addrs_out);
NTSTATUS ads_dns_lookup_aaaa(TALLOC_CTX *ctx,
			const char *name_in,
			size_t *num_names_out,
			char ***hostnames_out,
			struct samba_sockaddr **addrs_out);
#endif

#endif	/* __LIB_ADDNS_DNSQUERY_H__ */
