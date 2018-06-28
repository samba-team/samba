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

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif
#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#endif

#ifndef ETHERTYPE_IP6
#define ETHERTYPE_IP6 0x86dd
#endif

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

static uint16_t ip6_checksum(uint16_t *data, size_t n, struct ip6_hdr *ip6)
{
	uint32_t phdr[2];
	uint32_t sum = 0;
	uint16_t sum2;

	sum += uint16_checksum((uint16_t *)(void *)&ip6->ip6_src, 16);
	sum += uint16_checksum((uint16_t *)(void *)&ip6->ip6_dst, 16);

	phdr[0] = htonl(n);
	phdr[1] = htonl(ip6->ip6_nxt);
	sum += uint16_checksum((uint16_t *)phdr, 8);

	sum += uint16_checksum(data, n);

	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum2 = htons(sum);
	sum2 = ~sum2;
	if (sum2 == 0) {
		return 0xFFFF;
	}
	return sum2;
}

/*
 * Send gratuitous ARP request/reply or IPv6 neighbor advertisement
 */

#ifdef HAVE_PACKETSOCKET

int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface)
{
	int s, ret;
	struct sockaddr_ll sall;
	struct ether_header *eh;
	struct arphdr *ah;
	struct ip6_hdr *ip6;
	struct nd_neighbor_advert *nd_na;
	struct nd_opt_hdr *nd_oh;
	struct ifreq if_hwaddr;
	/* Size of IPv6 neighbor advertisement (with option) */
	unsigned char buffer[sizeof(struct ether_header) +
			     sizeof(struct ip6_hdr) +
			     sizeof(struct nd_neighbor_advert) +
			     sizeof(struct nd_opt_hdr) + ETH_ALEN];
	char *ptr;
	char bdcast[] = {0xff,0xff,0xff,0xff,0xff,0xff};
	struct ifreq ifr;

	ZERO_STRUCT(sall);
	ZERO_STRUCT(ifr);
	ZERO_STRUCT(if_hwaddr);

	switch (addr->ip.sin_family) {
	case AF_INET:
		s = socket(AF_PACKET, SOCK_RAW, 0);
		if (s == -1){
			DBG_ERR("Failed to open raw socket\n");
			return -1;
		}

		DBG_DEBUG("Created SOCKET FD:%d for sending arp\n", s);
		strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			DBG_ERR("Interface '%s' not found\n", iface);
			close(s);
			return -1;
		}

		/* get the mac address */
		strlcpy(if_hwaddr.ifr_name, iface, sizeof(if_hwaddr.ifr_name));
		ret = ioctl(s, SIOCGIFHWADDR, &if_hwaddr);
		if ( ret < 0 ) {
			close(s);
			DBG_ERR("ioctl failed\n");
			return -1;
		}
		if (ARPHRD_LOOPBACK == if_hwaddr.ifr_hwaddr.sa_family) {
			D_DEBUG("Ignoring loopback arp request\n");
			close(s);
			return 0;
		}
		if (if_hwaddr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			close(s);
			errno = EINVAL;
			DBG_ERR("Not an ethernet address family (0x%x)\n",
				if_hwaddr.ifr_hwaddr.sa_family);
			return -1;
		}


		memset(buffer, 0 , 64);
		eh = (struct ether_header *)buffer;
		memset(eh->ether_dhost, 0xff, ETH_ALEN);
		memcpy(eh->ether_shost, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
		eh->ether_type = htons(ETHERTYPE_ARP);

		ah = (struct arphdr *)&buffer[sizeof(struct ether_header)];
		ah->ar_hrd = htons(ARPHRD_ETHER);
		ah->ar_pro = htons(ETH_P_IP);
		ah->ar_hln = ETH_ALEN;
		ah->ar_pln = 4;

		/* send a gratious arp */
		ah->ar_op  = htons(ARPOP_REQUEST);
		ptr = (char *)&ah[1];
		memcpy(ptr, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
		ptr+=ETH_ALEN;
		memcpy(ptr, &addr->ip.sin_addr, 4);
		ptr+=4;
		memset(ptr, 0, ETH_ALEN);
		ptr+=ETH_ALEN;
		memcpy(ptr, &addr->ip.sin_addr, 4);
		ptr+=4;

		sall.sll_family = AF_PACKET;
		sall.sll_halen = 6;
		memcpy(&sall.sll_addr[0], bdcast, sall.sll_halen);
		sall.sll_protocol = htons(ETH_P_ALL);
		sall.sll_ifindex = ifr.ifr_ifindex;
		ret = sendto(s,buffer, 64, 0,
			     (struct sockaddr *)&sall, sizeof(sall));
		if (ret < 0 ){
			close(s);
			DBG_ERR("Failed sendto\n");
			return -1;
		}

		/* send unsolicited arp reply broadcast */
		ah->ar_op  = htons(ARPOP_REPLY);
		ptr = (char *)&ah[1];
		memcpy(ptr, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
		ptr+=ETH_ALEN;
		memcpy(ptr, &addr->ip.sin_addr, 4);
		ptr+=4;
		memcpy(ptr, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
		ptr+=ETH_ALEN;
		memcpy(ptr, &addr->ip.sin_addr, 4);
		ptr+=4;

		ret = sendto(s, buffer, 64, 0,
			     (struct sockaddr *)&sall, sizeof(sall));
		if (ret < 0 ){
			DBG_ERR("Failed sendto\n");
			close(s);
			return -1;
		}

		close(s);
		break;
	case AF_INET6:
		s = socket(AF_PACKET, SOCK_RAW, 0);
		if (s == -1){
			DBG_ERR("Failed to open raw socket\n");
			return -1;
		}

		DBG_DEBUG("Created SOCKET FD:%d for sending arp\n", s);
		strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			DBG_ERR("Interface '%s' not found\n", iface);
			close(s);
			return -1;
		}

		/* get the mac address */
		strlcpy(if_hwaddr.ifr_name, iface, sizeof(if_hwaddr.ifr_name));
		ret = ioctl(s, SIOCGIFHWADDR, &if_hwaddr);
		if ( ret < 0 ) {
			close(s);
			DBG_ERR("ioctl failed\n");
			return -1;
		}
		if (ARPHRD_LOOPBACK == if_hwaddr.ifr_hwaddr.sa_family) {
			DBG_DEBUG("Ignoring loopback arp request\n");
			close(s);
			return 0;
		}
		if (if_hwaddr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			close(s);
			errno = EINVAL;
			DBG_ERR("Not an ethernet address family (0x%x)\n",
				if_hwaddr.ifr_hwaddr.sa_family);
			return -1;
		}

		memset(buffer, 0 , sizeof(buffer));
		eh = (struct ether_header *)buffer;
		/*
		 * Ethernet multicast: 33:33:00:00:00:01 (see RFC2464,
		 * section 7) - note zeroes above!
		 */
		eh->ether_dhost[0] = eh->ether_dhost[1] = 0x33;
		eh->ether_dhost[5] = 0x01;
		memcpy(eh->ether_shost, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
		eh->ether_type = htons(ETHERTYPE_IP6);

		ip6 = (struct ip6_hdr *)(eh+1);
		ip6->ip6_vfc  = 0x60;
		ip6->ip6_plen = htons(sizeof(*nd_na) +
				      sizeof(struct nd_opt_hdr) +
				      ETH_ALEN);
		ip6->ip6_nxt  = IPPROTO_ICMPV6;
		ip6->ip6_hlim = 255;
		ip6->ip6_src  = addr->ip6.sin6_addr;
		/* all-nodes multicast */

		ret = inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);
		if (ret != 1) {
			close(s);
			DBG_ERR("Failed inet_pton\n");
			return -1;
		}

		nd_na = (struct nd_neighbor_advert *)(ip6+1);
		nd_na->nd_na_type = ND_NEIGHBOR_ADVERT;
		nd_na->nd_na_code = 0;
		nd_na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
		nd_na->nd_na_target = addr->ip6.sin6_addr;
		/* Option: Target link-layer address */
		nd_oh = (struct nd_opt_hdr *)(nd_na+1);
		nd_oh->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		nd_oh->nd_opt_len = 1;
		memcpy(&(nd_oh+1)[0], if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);

		nd_na->nd_na_cksum = ip6_checksum((uint16_t *)nd_na,
						  ntohs(ip6->ip6_plen), ip6);

		sall.sll_family = AF_PACKET;
		sall.sll_halen = 6;
		memcpy(&sall.sll_addr[0], &eh->ether_dhost[0], sall.sll_halen);
		sall.sll_protocol = htons(ETH_P_ALL);
		sall.sll_ifindex = ifr.ifr_ifindex;
		ret = sendto(s, buffer, sizeof(buffer),
			     0, (struct sockaddr *)&sall, sizeof(sall));
		if (ret < 0 ){
			close(s);
			DBG_ERR("Failed sendto\n");
			return -1;
		}

		close(s);
		break;
	default:
		DBG_ERR("Not an ipv4/ipv6 address (family is %u)\n",
			addr->ip.sin_family);
		return -1;
	}

	return 0;
}

#else /* HAVE_PACKETSOCKET */

int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface)
{
	/* Not implemented */
	errno = ENOSYS;
	return -1;
}

#endif /* HAVE_PACKETSOCKET */
