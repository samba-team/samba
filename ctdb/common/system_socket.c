/*
   ctdb system specific code to manage raw sockets on linux

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"

#include "protocol/protocol.h"

#include "common/logging.h"
#include "common/system_socket.h"

/*
  uint16 checksum for n bytes
 */
uint32_t uint16_checksum(uint16_t *data, size_t n)
{
	uint32_t sum=0;
	while (n>=2) {
		sum += (uint32_t)ntohs(*data);
		data++;
		n -= 2;
	}
	if (n == 1) {
		sum += (uint32_t)ntohs(*(uint8_t *)data);
	}
	return sum;
}


/*
 * See if the given IP is currently on an interface
 */
bool ctdb_sys_have_ip(ctdb_sock_addr *_addr)
{
	int s;
	int ret;
	ctdb_sock_addr __addr = *_addr;
	ctdb_sock_addr *addr = &__addr;
	socklen_t addrlen = 0;

	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->ip.sin_port = 0;
		addrlen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		addr->ip6.sin6_port = 0;
		addrlen = sizeof(struct sockaddr_in6);
		break;
	}

	s = socket(addr->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		return false;
	}

	ret = bind(s, (struct sockaddr *)addr, addrlen);

	close(s);
	return ret == 0;
}

static bool parse_ipv4(const char *s, unsigned port, struct sockaddr_in *sin)
{
	sin->sin_family = AF_INET;
	sin->sin_port   = htons(port);

	if (inet_pton(AF_INET, s, &sin->sin_addr) != 1) {
		DBG_ERR("Failed to translate %s into sin_addr\n", s);
		return false;
	}

#ifdef HAVE_SOCK_SIN_LEN
	sin->sin_len = sizeof(*sin);
#endif
	return true;
}

static bool parse_ipv6(const char *s,
		       const char *ifaces,
		       unsigned port,
		       ctdb_sock_addr *saddr)
{
	saddr->ip6.sin6_family   = AF_INET6;
	saddr->ip6.sin6_port     = htons(port);
	saddr->ip6.sin6_flowinfo = 0;
	saddr->ip6.sin6_scope_id = 0;

	if (inet_pton(AF_INET6, s, &saddr->ip6.sin6_addr) != 1) {
		DBG_ERR("Failed to translate %s into sin6_addr\n", s);
		return false;
	}

	if (ifaces && IN6_IS_ADDR_LINKLOCAL(&saddr->ip6.sin6_addr)) {
		if (strchr(ifaces, ',')) {
			DBG_ERR("Link local address %s "
				"is specified for multiple ifaces %s\n",
				s, ifaces);
			return false;
		}
		saddr->ip6.sin6_scope_id = if_nametoindex(ifaces);
	}

#ifdef HAVE_SOCK_SIN6_LEN
	saddr->ip6.sin6_len = sizeof(*saddr);
#endif
	return true;
}

static bool parse_ip(const char *addr,
		     const char *ifaces,
		     unsigned port,
		     ctdb_sock_addr *saddr)
{
	char *p;
	bool ret;

	ZERO_STRUCTP(saddr); /* valgrind :-) */

	/*
	 * IPv4 or IPv6 address?
	 *
	 * Use rindex() because we need the right-most ':' below for
	 * IPv4-mapped IPv6 addresses anyway...
	 */
	p = rindex(addr, ':');
	if (p == NULL) {
		ret = parse_ipv4(addr, port, &saddr->ip);
	} else {
		uint8_t ipv4_mapped_prefix[12] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
		};

		ret = parse_ipv6(addr, ifaces, port, saddr);
		if (! ret) {
			return ret;
		}

		/*
		 * Check for IPv4-mapped IPv6 address
		 * (e.g. ::ffff:192.0.2.128) - reparse as IPv4 if
		 * necessary
		 */
		if (memcmp(&saddr->ip6.sin6_addr.s6_addr[0],
			   ipv4_mapped_prefix,
			   sizeof(ipv4_mapped_prefix)) == 0) {
			/* Reparse as IPv4 */
			ret = parse_ipv4(p+1, port, &saddr->ip);
		}
	}

	return ret;
}

/*
 * Parse an ip/mask pair
 */
bool parse_ip_mask(const char *str,
		   const char *ifaces,
		   ctdb_sock_addr *addr,
		   unsigned *mask)
{
	char *p;
	char s[64]; /* Much longer than INET6_ADDRSTRLEN */
	char *endp = NULL;
	ssize_t len;
	bool ret;

	ZERO_STRUCT(*addr);

	len = strlen(str);
	if (len >= sizeof(s)) {
		DBG_ERR("Address %s is unreasonably long\n", str);
		return false;
	}

	strncpy(s, str, len+1);

	p = rindex(s, '/');
	if (p == NULL) {
		DBG_ERR("Address %s does not contain a mask\n", s);
		return false;
	}

	*mask = strtoul(p+1, &endp, 10);
	if (endp == NULL || *endp != 0) {
		/* trailing garbage */
		DBG_ERR("Trailing garbage after the mask in %s\n", s);
		return false;
	}
	*p = 0;


	/* now is this a ipv4 or ipv6 address ?*/
	ret = parse_ip(s, ifaces, 0, addr);

	return ret;
}
