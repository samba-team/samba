/*
   Unix SMB/CIFS implementation.
   Utility functions for Samba
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Jelmer Vernooij 2005

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

#ifndef _SAMBA_UTIL_NET_H_
#define _SAMBA_UTIL_NET_H_

#include "system/network.h"

struct samba_sockaddr {
	socklen_t sa_socklen;
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
#ifdef HAVE_IPV6
		struct sockaddr_in6 in6;
#endif
		struct sockaddr_un un;
		struct sockaddr_storage ss;
	} u;
};

/* The following definitions come from lib/util/util_net.c  */

void zero_sockaddr(struct sockaddr_storage *pss);

bool interpret_string_addr_internal(struct addrinfo **ppres,
				    const char *str, int flags);

bool interpret_string_addr(struct sockaddr_storage *pss,
			   const char *str,
			   int flags);

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Version that prefers IPv4.
******************************************************************/

bool interpret_string_addr_prefer_ipv4(struct sockaddr_storage *pss,
				       const char *str,
				       int flags);

void set_sockaddr_port(struct sockaddr *psa, uint16_t port);

/**
 Check if an IP is the 0.0.0.0.
**/
_PUBLIC_ bool is_zero_ip_v4(struct in_addr ip);

void in_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
				 struct in_addr ip);
#if defined(HAVE_IPV6)
/**
 * Convert an IPv6 struct in_addr to a struct sockaddr_storage.
 */
void in6_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
				  struct in6_addr ip);
#endif
/**
 Are two IPs on the same subnet?
**/
_PUBLIC_ bool same_net_v4(struct in_addr ip1,struct in_addr ip2,struct in_addr mask);

/**
 Return true if a string could be a pure IP address.
**/
_PUBLIC_ bool is_ipaddress(const char *str);

bool is_broadcast_addr(const struct sockaddr *pss);
bool is_loopback_ip_v4(struct in_addr ip);
bool is_loopback_addr(const struct sockaddr *pss);
bool is_zero_addr(const struct sockaddr_storage *pss);
void zero_ip_v4(struct in_addr *ip);
bool is_linklocal_addr(const struct sockaddr_storage *pss);
/**
 Interpret an internet address or name into an IP address in 4 byte form.
**/
_PUBLIC_ uint32_t interpret_addr(const char *str);

/**
 A convenient addition to interpret_addr().
**/
_PUBLIC_ struct in_addr interpret_addr2(const char *str);

_PUBLIC_ bool is_ipaddress_v4(const char *str);
_PUBLIC_ bool is_ipv6_literal(const char *str);
_PUBLIC_ bool is_ipaddress_v6(const char *str);

bool is_address_any(const struct sockaddr *psa);
bool same_net(const struct sockaddr *ip1,
	      const struct sockaddr *ip2,
	      const struct sockaddr *mask);
bool sockaddr_equal(const struct sockaddr *ip1,
		    const struct sockaddr *ip2);

bool is_address_any(const struct sockaddr *psa);
uint16_t get_sockaddr_port(const struct sockaddr_storage *pss);
char *print_sockaddr_len(char *dest,
			 size_t destlen,
			 const struct sockaddr *psa,
			 socklen_t psalen);
char *print_sockaddr(char *dest,
			size_t destlen,
			const struct sockaddr_storage *psa);
char *print_canonical_sockaddr(TALLOC_CTX *ctx,
			const struct sockaddr_storage *pss);

void set_socket_options(int fd, const char *options);

bool sockaddr_storage_to_samba_sockaddr(
	struct samba_sockaddr *sa, const struct sockaddr_storage *ss);
bool samba_sockaddr_set_port(struct samba_sockaddr *sa, uint16_t port);
bool samba_sockaddr_get_port(const struct samba_sockaddr *sa, uint16_t *port);

#endif /* _SAMBA_UTIL_NET_H_ */
