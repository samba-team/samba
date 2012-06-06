/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison  1992-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   Copyright (C) Tim Potter      2000-2001

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
#include "system/network.h"
#include "system/locale.h"
#include "system/filesys.h"
#include "lib/util/util_net.h"
#undef strcasecmp

/*******************************************************************
 Set an address to INADDR_ANY.
******************************************************************/

void zero_sockaddr(struct sockaddr_storage *pss)
{
	ZERO_STRUCTP(pss);
	/* Ensure we're at least a valid sockaddr-storage. */
	pss->ss_family = AF_INET;
}

/**
 * Wrap getaddrinfo...
 */
bool interpret_string_addr_internal(struct addrinfo **ppres,
					const char *str, int flags)
{
	int ret;
	struct addrinfo hints;

	ZERO_STRUCT(hints);

	/* By default make sure it supports TCP. */
	hints.ai_socktype = SOCK_STREAM;

	/* always try as a numeric host first. This prevents unnecessary name
	 * lookups, and also ensures we accept IPv6 addresses */
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
	ret = getaddrinfo(str, NULL, &hints, ppres);
	if (ret == 0) {
		return true;
	}

	hints.ai_flags = flags;

	/* Linux man page on getaddrinfo() says port will be
	   uninitialized when service string is NULL */

	ret = getaddrinfo(str, NULL,
			&hints,
			ppres);

	if (ret) {
		DEBUG(3, ("interpret_string_addr_internal: "
			  "getaddrinfo failed for name %s (flags %d) [%s]\n",
			  str, flags, gai_strerror(ret)));
		return false;
	}
	return true;
}

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Takes a flag which allows it to
 prefer an IPv4 address (needed for DC's).
******************************************************************/

static bool interpret_string_addr_pref(struct sockaddr_storage *pss,
		const char *str,
		int flags,
		bool prefer_ipv4)
{
	struct addrinfo *res = NULL;
	int int_flags;
#if defined(HAVE_IPV6)
	char addr[INET6_ADDRSTRLEN];
	unsigned int scope_id = 0;

	if (strchr_m(str, ':')) {
		char *p = strchr_m(str, '%');

		/*
		 * Cope with link-local.
		 * This is IP:v6:addr%ifname.
		 */

		if (p && (p > str) && ((scope_id = if_nametoindex(p+1)) != 0)) {
			/* Length of string we want to copy.
			   This is IP:v6:addr (removing the %ifname).
			 */
			size_t len = PTR_DIFF(p,str);

			if (len+1 > sizeof(addr)) {
				/* string+nul too long for array. */
				return false;
			}
			memcpy(addr, str, len);
			addr[len] = '\0';

			str = addr;
		}
	}
#endif

	zero_sockaddr(pss);

	if (flags & AI_NUMERICHOST) {
		int_flags = flags;
	} else {
		int_flags = flags|AI_ADDRCONFIG;
	}

	if (!interpret_string_addr_internal(&res, str, int_flags)) {
		return false;
	}
	if (!res) {
		return false;
	}

	if (prefer_ipv4) {
		struct addrinfo *p;

		for (p = res; p; p = p->ai_next) {
			if (p->ai_family == AF_INET) {
				memcpy(pss, p->ai_addr, p->ai_addrlen);
				break;
			}
		}
		if (p == NULL) {
			/* Copy the first sockaddr. */
			memcpy(pss, res->ai_addr, res->ai_addrlen);
		}
	} else {
		/* Copy the first sockaddr. */
		memcpy(pss, res->ai_addr, res->ai_addrlen);
	}

#if defined(HAVE_IPV6)
	if (pss->ss_family == AF_INET6 && scope_id) {
		struct sockaddr_in6 *ps6 = (struct sockaddr_in6 *)pss;
		if (IN6_IS_ADDR_LINKLOCAL(&ps6->sin6_addr) &&
				ps6->sin6_scope_id == 0) {
			ps6->sin6_scope_id = scope_id;
		}
	}
#endif

	freeaddrinfo(res);
	return true;
}

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Address agnostic version.
******************************************************************/

bool interpret_string_addr(struct sockaddr_storage *pss,
		const char *str,
		int flags)
{
	return interpret_string_addr_pref(pss,
					str,
					flags,
					false);
}

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Version that prefers IPv4.
******************************************************************/

bool interpret_string_addr_prefer_ipv4(struct sockaddr_storage *pss,
		const char *str,
		int flags)
{
	return interpret_string_addr_pref(pss,
					str,
					flags,
					true);
}

/**
 * Interpret an internet address or name into an IP address in 4 byte form.
 * RETURNS IN NETWORK BYTE ORDER (big endian).
 */

uint32_t interpret_addr(const char *str)
{
	uint32_t ret;

	/* If it's in the form of an IP address then
	 * get the lib to interpret it */
	if (is_ipaddress_v4(str)) {
		struct in_addr dest;

		if (inet_pton(AF_INET, str, &dest) <= 0) {
			/* Error - this shouldn't happen ! */
			DEBUG(0,("interpret_addr: inet_pton failed "
				"host %s\n",
				str));
			return 0;
		}
		ret = dest.s_addr; /* NETWORK BYTE ORDER ! */
	} else {
		/* Otherwise assume it's a network name of some sort and use
			getadddrinfo. */
		struct addrinfo *res = NULL;
		struct addrinfo *res_list = NULL;
		if (!interpret_string_addr_internal(&res_list,
					str,
					AI_ADDRCONFIG)) {
			DEBUG(3,("interpret_addr: Unknown host. %s\n",str));
			return 0;
		}

		/* Find the first IPv4 address. */
		for (res = res_list; res; res = res->ai_next) {
			if (res->ai_family != AF_INET) {
				continue;
			}
			if (res->ai_addr == NULL) {
				continue;
			}
			break;
		}
		if(res == NULL) {
			DEBUG(3,("interpret_addr: host address is "
				"invalid for host %s\n",str));
			if (res_list) {
				freeaddrinfo(res_list);
			}
			return 0;
		}
		memcpy((char *)&ret,
			&((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr,
			sizeof(ret));
		if (res_list) {
			freeaddrinfo(res_list);
		}
	}

	/* This is so bogus - all callers need fixing... JRA. */
	if (ret == (uint32_t)-1) {
		return 0;
	}

	return ret;
}

/**
 A convenient addition to interpret_addr().
**/
_PUBLIC_ struct in_addr interpret_addr2(const char *str)
{
	struct in_addr ret;
	uint32_t a = interpret_addr(str);
	ret.s_addr = a;
	return ret;
}

/**
 Check if an IP is the 0.0.0.0.
**/

_PUBLIC_ bool is_zero_ip_v4(struct in_addr ip)
{
	return ip.s_addr == 0;
}

/**
 Are two IPs on the same subnet?
**/

_PUBLIC_ bool same_net_v4(struct in_addr ip1, struct in_addr ip2, struct in_addr mask)
{
	uint32_t net1,net2,nmask;

	nmask = ntohl(mask.s_addr);
	net1  = ntohl(ip1.s_addr);
	net2  = ntohl(ip2.s_addr);
            
	return((net1 & nmask) == (net2 & nmask));
}

/**
 * Return true if a string could be an IPv4 address.
 */

bool is_ipaddress_v4(const char *str)
{
	int ret = -1;
	struct in_addr dest;

	ret = inet_pton(AF_INET, str, &dest);
	if (ret > 0) {
		return true;
	}
	return false;
}

/**
 * Return true if a string could be a IPv6 address.
 */

bool is_ipaddress_v6(const char *str)
{
#if defined(HAVE_IPV6)
	int ret = -1;

	if (strchr_m(str, ':')) {
		char addr[INET6_ADDRSTRLEN];
		struct in6_addr dest6;
		const char *sp = str;
		char *p = strchr_m(str, '%');

		/*
		 * Cope with link-local.
		 * This is IP:v6:addr%ifname.
		 */

		if (p && (p > str) && (if_nametoindex(p+1) != 0)) {
			size_t len = MIN(PTR_DIFF(p,str)+1, sizeof(addr));
			if (strlcpy(addr, str, len) >= len) {
				/* Truncate. */
				return false;
			}
			sp = addr;
		}
		ret = inet_pton(AF_INET6, sp, &dest6);
		if (ret > 0) {
			return true;
		}
	}
#endif
	return false;
}

/**
 * Return true if a string could be an IPv4 or IPv6 address.
 */

bool is_ipaddress(const char *str)
{
	return is_ipaddress_v4(str) || is_ipaddress_v6(str);
}

/**
 * Is a sockaddr a broadcast address ?
 */

bool is_broadcast_addr(const struct sockaddr *pss)
{
#if defined(HAVE_IPV6)
	if (pss->sa_family == AF_INET6) {
		const struct in6_addr *sin6 =
			&((const struct sockaddr_in6 *)pss)->sin6_addr;
		return IN6_IS_ADDR_MULTICAST(sin6);
	}
#endif
	if (pss->sa_family == AF_INET) {
		uint32_t addr =
		ntohl(((const struct sockaddr_in *)pss)->sin_addr.s_addr);
		return addr == INADDR_BROADCAST;
	}
	return false;
}

/**
 * Check if an IPv7 is 127.0.0.1
 */
bool is_loopback_ip_v4(struct in_addr ip)
{
	struct in_addr a;
	a.s_addr = htonl(INADDR_LOOPBACK);
	return(ip.s_addr == a.s_addr);
}

/**
 * Check if a struct sockaddr is the loopback address.
 */
bool is_loopback_addr(const struct sockaddr *pss)
{
#if defined(HAVE_IPV6)
	if (pss->sa_family == AF_INET6) {
		const struct in6_addr *pin6 =
			&((const struct sockaddr_in6 *)pss)->sin6_addr;
		return IN6_IS_ADDR_LOOPBACK(pin6);
	}
#endif
	if (pss->sa_family == AF_INET) {
		const struct in_addr *pin = &((const struct sockaddr_in *)pss)->sin_addr;
		return is_loopback_ip_v4(*pin);
	}
	return false;
}

/**
 * Check if a struct sockaddr has an unspecified address.
 */
bool is_zero_addr(const struct sockaddr_storage *pss)
{
#if defined(HAVE_IPV6)
	if (pss->ss_family == AF_INET6) {
		const struct in6_addr *pin6 =
			&((const struct sockaddr_in6 *)pss)->sin6_addr;
		return IN6_IS_ADDR_UNSPECIFIED(pin6);
	}
#endif
	if (pss->ss_family == AF_INET) {
		const struct in_addr *pin = &((const struct sockaddr_in *)pss)->sin_addr;
		return is_zero_ip_v4(*pin);
	}
	return false;
}

/**
 * Set an IP to 0.0.0.0.
 */
void zero_ip_v4(struct in_addr *ip)
{
	ZERO_STRUCTP(ip);
}

bool is_linklocal_addr(const struct sockaddr_storage *pss)
{
#ifdef HAVE_IPV6
	if (pss->ss_family == AF_INET6) {
		const struct in6_addr *pin6 =
			&((const struct sockaddr_in6 *)pss)->sin6_addr;
		return IN6_IS_ADDR_LINKLOCAL(pin6);
	}
#endif
	if (pss->ss_family == AF_INET) {
		const struct in_addr *pin =
			&((const struct sockaddr_in *)pss)->sin_addr;
		struct in_addr ll_addr;
		struct in_addr mask_addr;

		/* 169.254.0.0/16, is link local, see RFC 3927 */
		ll_addr.s_addr = 0xa9fe0000;
		mask_addr.s_addr = 0xffff0000;
		return same_net_v4(*pin, ll_addr, mask_addr);
	}
	return false;
}

/**
 * Convert an IPv4 struct in_addr to a struct sockaddr_storage.
 */
void in_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
		struct in_addr ip)
{
	struct sockaddr_in *sa = (struct sockaddr_in *)ss;
	ZERO_STRUCTP(ss);
	sa->sin_family = AF_INET;
	sa->sin_addr = ip;
}

#if defined(HAVE_IPV6)
/**
 * Convert an IPv6 struct in_addr to a struct sockaddr_storage.
 */
void in6_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
		struct in6_addr ip)
{
	struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;
	memset(ss, '\0', sizeof(*ss));
	sa->sin6_family = AF_INET6;
	sa->sin6_addr = ip;
}
#endif

/**
 * Are two IPs on the same subnet?
 */
bool same_net(const struct sockaddr *ip1,
		const struct sockaddr *ip2,
		const struct sockaddr *mask)
{
	if (ip1->sa_family != ip2->sa_family) {
		/* Never on the same net. */
		return false;
	}

#if defined(HAVE_IPV6)
	if (ip1->sa_family == AF_INET6) {
		struct sockaddr_in6 ip1_6 = *(const struct sockaddr_in6 *)ip1;
		struct sockaddr_in6 ip2_6 = *(const struct sockaddr_in6 *)ip2;
		struct sockaddr_in6 mask_6 = *(const struct sockaddr_in6 *)mask;
		char *p1 = (char *)&ip1_6.sin6_addr;
		char *p2 = (char *)&ip2_6.sin6_addr;
		char *m = (char *)&mask_6.sin6_addr;
		int i;

		for (i = 0; i < sizeof(struct in6_addr); i++) {
			*p1++ &= *m;
			*p2++ &= *m;
			m++;
		}
		return (memcmp(&ip1_6.sin6_addr,
				&ip2_6.sin6_addr,
				sizeof(struct in6_addr)) == 0);
	}
#endif
	if (ip1->sa_family == AF_INET) {
		return same_net_v4(((const struct sockaddr_in *)ip1)->sin_addr,
				((const struct sockaddr_in *)ip2)->sin_addr,
				((const struct sockaddr_in *)mask)->sin_addr);
	}
	return false;
}

/**
 * Are two sockaddr 's the same family and address ? Ignore port etc.
 */

bool sockaddr_equal(const struct sockaddr *ip1,
		const struct sockaddr *ip2)
{
	if (ip1->sa_family != ip2->sa_family) {
		/* Never the same. */
		return false;
	}

#if defined(HAVE_IPV6)
	if (ip1->sa_family == AF_INET6) {
		return (memcmp(&((const struct sockaddr_in6 *)ip1)->sin6_addr,
				&((const struct sockaddr_in6 *)ip2)->sin6_addr,
				sizeof(struct in6_addr)) == 0);
	}
#endif
	if (ip1->sa_family == AF_INET) {
		return (memcmp(&((const struct sockaddr_in *)ip1)->sin_addr,
				&((const struct sockaddr_in *)ip2)->sin_addr,
				sizeof(struct in_addr)) == 0);
	}
	return false;
}

/**
 * Is an IP address the INADDR_ANY or in6addr_any value ?
 */
bool is_address_any(const struct sockaddr *psa)
{
#if defined(HAVE_IPV6)
	if (psa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *si6 = (const struct sockaddr_in6 *)psa;
		if (memcmp(&in6addr_any,
				&si6->sin6_addr,
				sizeof(in6addr_any)) == 0) {
			return true;
		}
		return false;
	}
#endif
	if (psa->sa_family == AF_INET) {
		const struct sockaddr_in *si = (const struct sockaddr_in *)psa;
		if (si->sin_addr.s_addr == INADDR_ANY) {
			return true;
		}
		return false;
	}
	return false;
}

void set_sockaddr_port(struct sockaddr *psa, uint16_t port)
{
#if defined(HAVE_IPV6)
	if (psa->sa_family == AF_INET6) {
		((struct sockaddr_in6 *)psa)->sin6_port = htons(port);
	}
#endif
	if (psa->sa_family == AF_INET) {
		((struct sockaddr_in *)psa)->sin_port = htons(port);
	}
}


/****************************************************************************
 Get a port number in host byte order from a sockaddr_storage.
****************************************************************************/

uint16_t get_sockaddr_port(const struct sockaddr_storage *pss)
{
	uint16_t port = 0;

	if (pss->ss_family != AF_INET) {
#if defined(HAVE_IPV6)
		/* IPv6 */
		const struct sockaddr_in6 *sa6 =
			(const struct sockaddr_in6 *)pss;
		port = ntohs(sa6->sin6_port);
#endif
	} else {
		const struct sockaddr_in *sa =
			(const struct sockaddr_in *)pss;
		port = ntohs(sa->sin_port);
	}
	return port;
}

/****************************************************************************
 Print out an IPv4 or IPv6 address from a struct sockaddr_storage.
****************************************************************************/

char *print_sockaddr_len(char *dest,
			 size_t destlen,
			const struct sockaddr *psa,
			socklen_t psalen)
{
	if (destlen > 0) {
		dest[0] = '\0';
	}
	(void)sys_getnameinfo(psa,
			psalen,
			dest, destlen,
			NULL, 0,
			NI_NUMERICHOST);
	return dest;
}

/****************************************************************************
 Print out an IPv4 or IPv6 address from a struct sockaddr_storage.
****************************************************************************/

char *print_sockaddr(char *dest,
			size_t destlen,
			const struct sockaddr_storage *psa)
{
	return print_sockaddr_len(dest, destlen, (const struct sockaddr *)psa,
			sizeof(struct sockaddr_storage));
}

/****************************************************************************
 Print out a canonical IPv4 or IPv6 address from a struct sockaddr_storage.
****************************************************************************/

char *print_canonical_sockaddr(TALLOC_CTX *ctx,
			const struct sockaddr_storage *pss)
{
	char addr[INET6_ADDRSTRLEN];
	char *dest = NULL;
	int ret;

	/* Linux getnameinfo() man pages says port is unitialized if
	   service name is NULL. */

	ret = sys_getnameinfo((const struct sockaddr *)pss,
			sizeof(struct sockaddr_storage),
			addr, sizeof(addr),
			NULL, 0,
			NI_NUMERICHOST);
	if (ret != 0) {
		return NULL;
	}

	if (pss->ss_family != AF_INET) {
#if defined(HAVE_IPV6)
		dest = talloc_asprintf(ctx, "[%s]", addr);
#else
		return NULL;
#endif
	} else {
		dest = talloc_asprintf(ctx, "%s", addr);
	}

	return dest;
}

/****************************************************************************
 Return the port number we've bound to on a socket.
****************************************************************************/

int get_socket_port(int fd)
{
	struct sockaddr_storage sa;
	socklen_t length = sizeof(sa);

	if (fd == -1) {
		return -1;
	}

	if (getsockname(fd, (struct sockaddr *)&sa, &length) < 0) {
		int level = (errno == ENOTCONN) ? 2 : 0;
		DEBUG(level, ("getsockname failed. Error was %s\n",
			       strerror(errno)));
		return -1;
	}

#if defined(HAVE_IPV6)
	if (sa.ss_family == AF_INET6) {
		return ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
	}
#endif
	if (sa.ss_family == AF_INET) {
		return ntohs(((struct sockaddr_in *)&sa)->sin_port);
	}
	return -1;
}

/****************************************************************************
 Return the string of an IP address (IPv4 or IPv6).
****************************************************************************/

static const char *get_socket_addr(int fd, char *addr_buf, size_t addr_len)
{
	struct sockaddr_storage sa;
	socklen_t length = sizeof(sa);

	/* Ok, returning a hard coded IPv4 address
	 * is bogus, but it's just as bogus as a
	 * zero IPv6 address. No good choice here.
	 */

	if (strlcpy(addr_buf, "0.0.0.0", addr_len) >= addr_len) {
		/* Truncate ! */
		return NULL;
	}

	if (fd == -1) {
		return addr_buf;
	}

	if (getsockname(fd, (struct sockaddr *)&sa, &length) < 0) {
		DEBUG(0,("getsockname failed. Error was %s\n",
			strerror(errno) ));
		return addr_buf;
	}

	return print_sockaddr_len(addr_buf, addr_len, (struct sockaddr *)&sa, length);
}

const char *client_socket_addr(int fd, char *addr, size_t addr_len)
{
	return get_socket_addr(fd, addr, addr_len);
}


enum SOCK_OPT_TYPES {OPT_BOOL,OPT_INT,OPT_ON};

typedef struct smb_socket_option {
	const char *name;
	int level;
	int option;
	int value;
	int opttype;
} smb_socket_option;

static const smb_socket_option socket_options[] = {
  {"SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE, 0, OPT_BOOL},
  {"SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR, 0, OPT_BOOL},
  {"SO_BROADCAST", SOL_SOCKET, SO_BROADCAST, 0, OPT_BOOL},
#ifdef TCP_NODELAY
  {"TCP_NODELAY", IPPROTO_TCP, TCP_NODELAY, 0, OPT_BOOL},
#endif
#ifdef TCP_KEEPCNT
  {"TCP_KEEPCNT", IPPROTO_TCP, TCP_KEEPCNT, 0, OPT_INT},
#endif
#ifdef TCP_KEEPIDLE
  {"TCP_KEEPIDLE", IPPROTO_TCP, TCP_KEEPIDLE, 0, OPT_INT},
#endif
#ifdef TCP_KEEPINTVL
  {"TCP_KEEPINTVL", IPPROTO_TCP, TCP_KEEPINTVL, 0, OPT_INT},
#endif
#ifdef IPTOS_LOWDELAY
  {"IPTOS_LOWDELAY", IPPROTO_IP, IP_TOS, IPTOS_LOWDELAY, OPT_ON},
#endif
#ifdef IPTOS_THROUGHPUT
  {"IPTOS_THROUGHPUT", IPPROTO_IP, IP_TOS, IPTOS_THROUGHPUT, OPT_ON},
#endif
#ifdef SO_REUSEPORT
  {"SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT, 0, OPT_BOOL},
#endif
#ifdef SO_SNDBUF
  {"SO_SNDBUF", SOL_SOCKET, SO_SNDBUF, 0, OPT_INT},
#endif
#ifdef SO_RCVBUF
  {"SO_RCVBUF", SOL_SOCKET, SO_RCVBUF, 0, OPT_INT},
#endif
#ifdef SO_SNDLOWAT
  {"SO_SNDLOWAT", SOL_SOCKET, SO_SNDLOWAT, 0, OPT_INT},
#endif
#ifdef SO_RCVLOWAT
  {"SO_RCVLOWAT", SOL_SOCKET, SO_RCVLOWAT, 0, OPT_INT},
#endif
#ifdef SO_SNDTIMEO
  {"SO_SNDTIMEO", SOL_SOCKET, SO_SNDTIMEO, 0, OPT_INT},
#endif
#ifdef SO_RCVTIMEO
  {"SO_RCVTIMEO", SOL_SOCKET, SO_RCVTIMEO, 0, OPT_INT},
#endif
#ifdef TCP_FASTACK
  {"TCP_FASTACK", IPPROTO_TCP, TCP_FASTACK, 0, OPT_INT},
#endif
#ifdef TCP_QUICKACK
  {"TCP_QUICKACK", IPPROTO_TCP, TCP_QUICKACK, 0, OPT_BOOL},
#endif
#ifdef TCP_NODELAYACK
  {"TCP_NODELAYACK", IPPROTO_TCP, TCP_NODELAYACK, 0, OPT_BOOL},
#endif
#ifdef TCP_KEEPALIVE_THRESHOLD
  {"TCP_KEEPALIVE_THRESHOLD", IPPROTO_TCP, TCP_KEEPALIVE_THRESHOLD, 0, OPT_INT},
#endif
#ifdef TCP_KEEPALIVE_ABORT_THRESHOLD
  {"TCP_KEEPALIVE_ABORT_THRESHOLD", IPPROTO_TCP, TCP_KEEPALIVE_ABORT_THRESHOLD, 0, OPT_INT},
#endif
#ifdef TCP_DEFER_ACCEPT
  {"TCP_DEFER_ACCEPT", IPPROTO_TCP, TCP_DEFER_ACCEPT, 0, OPT_INT},
#endif
  {NULL,0,0,0,0}};

/****************************************************************************
 Print socket options.
****************************************************************************/

static void print_socket_options(int s)
{
	int value;
	socklen_t vlen = 4;
	const smb_socket_option *p = &socket_options[0];

	/* wrapped in if statement to prevent streams
	 * leak in SCO Openserver 5.0 */
	/* reported on samba-technical  --jerry */
	if ( DEBUGLEVEL >= 5 ) {
		DEBUG(5,("Socket options:\n"));
		for (; p->name != NULL; p++) {
			if (getsockopt(s, p->level, p->option,
						(void *)&value, &vlen) == -1) {
				DEBUGADD(5,("\tCould not test socket option %s.\n",
							p->name));
			} else {
				DEBUGADD(5,("\t%s = %d\n",
							p->name,value));
			}
		}
	}
 }

/****************************************************************************
 Set user socket options.
****************************************************************************/

void set_socket_options(int fd, const char *options)
{
	TALLOC_CTX *ctx = talloc_new(NULL);
	char *tok;

	while (next_token_talloc(ctx, &options, &tok," \t,")) {
		int ret=0,i;
		int value = 1;
		char *p;
		bool got_value = false;

		if ((p = strchr_m(tok,'='))) {
			*p = 0;
			value = atoi(p+1);
			got_value = true;
		}

		for (i=0;socket_options[i].name;i++)
			if (strequal(socket_options[i].name,tok))
				break;

		if (!socket_options[i].name) {
			DEBUG(0,("Unknown socket option %s\n",tok));
			continue;
		}

		switch (socket_options[i].opttype) {
		case OPT_BOOL:
		case OPT_INT:
			ret = setsockopt(fd,socket_options[i].level,
					socket_options[i].option,
					(char *)&value,sizeof(int));
			break;

		case OPT_ON:
			if (got_value)
				DEBUG(0,("syntax error - %s "
					"does not take a value\n",tok));

			{
				int on = socket_options[i].value;
				ret = setsockopt(fd,socket_options[i].level,
					socket_options[i].option,
					(char *)&on,sizeof(int));
			}
			break;
		}

		if (ret != 0) {
			/* be aware that some systems like Solaris return
			 * EINVAL to a setsockopt() call when the client
			 * sent a RST previously - no need to worry */
			DEBUG(2,("Failed to set socket option %s (Error %s)\n",
				tok, strerror(errno) ));
		}
	}

	TALLOC_FREE(ctx);
	print_socket_options(fd);
}
