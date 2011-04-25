/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Gerald Carter                2006.
 *  Copyright (C) Andrew Bartlett 2011
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

/* DNS query section in replies */

struct dns_query {
	const char *hostname;
	uint16_t type;
	uint16_t in_class;
};

/* DNS RR record in reply */

struct dns_rr {
	const char *hostname;
	uint16_t type;
	uint16_t in_class;
	uint32_t ttl;
	uint16_t rdatalen;
	uint8_t *rdata;
};

/* SRV records */

struct dns_rr_srv {
	const char *hostname;
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	size_t num_ips;
	struct sockaddr_storage *ss_s;	/* support multi-homed hosts */
};

/* NS records */

struct dns_rr_ns {
	const char *hostname;
	struct sockaddr_storage ss;
};

NTSTATUS resolve_dns_hosts_file_as_sockaddr(const char *dns_hosts_file,
					    const char *name, bool srv_lookup,
					    TALLOC_CTX *mem_ctx,
					    struct sockaddr_storage **return_iplist,
					    int *return_count);

NTSTATUS resolve_dns_hosts_file_as_dns_rr(const char *dns_hosts_file,
					  const char *name, bool srv_lookup,
					  TALLOC_CTX *mem_ctx,
					  struct dns_rr_srv **return_rr,
					  int *return_count);
