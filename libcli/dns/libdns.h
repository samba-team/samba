/*
   Unix SMB/CIFS implementation.

   Small async DNS library for Samba with socketwrapper support

   Copyright (C) 2012 Kai Blin  <kai@samba.org>

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

#ifndef __LIBDNS_H__
#define __LIBDNS_H__

#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "librpc/gen_ndr/dns.h"
#include "libcli/util/ntstatus.h"

struct gensec_security;
struct samba_sockaddr;

/*
 * DNS request with fallback to TCP on truncation
 */

struct tevent_req *dns_cli_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *nameserver,
					const struct dns_name_packet *q);
int dns_cli_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct dns_name_packet **reply);
int dns_cli_request(TALLOC_CTX *mem_ctx,
		    const char *nameserver,
		    const struct dns_name_packet *q,
		    struct dns_name_packet **reply);
struct dns_name_packet *dns_cli_create_query(TALLOC_CTX *mem_ctx,
					     const char *name,
					     enum dns_qclass qclass,
					     enum dns_qtype qtype);
struct dns_name_packet *dns_cli_create_probe(TALLOC_CTX *mem_ctx,
					     const char *zone,
					     const char *host,
					     const struct samba_sockaddr *ips,
					     size_t num_ips);
struct dns_name_packet *dns_cli_create_update(TALLOC_CTX *mem_ctx,
					      const char *zone,
					      const char *host,
					      const struct samba_sockaddr *ips,
					      size_t num_ips,
					      uint32_t ttl);

int dns_cli_sign_packet(
	struct dns_name_packet *p,
	struct gensec_security *gensec,
	NTSTATUS (*sign)(struct gensec_security *gensec_security,
			 TALLOC_CTX *mem_ctx,
			 const uint8_t *data,
			 size_t length,
			 const uint8_t *whole_pdu,
			 size_t pdu_length,
			 DATA_BLOB *sig),
	const char *keyname,
	const char *algorithmname);
#endif /*__LIBDNS_H__*/
