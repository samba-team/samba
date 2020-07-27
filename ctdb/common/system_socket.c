/*
   ctdb system specific code to manage raw sockets on linux

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Marc Dequènes (Duck) 2009
   Copyright (C) Volker Lendecke 2012

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

/*
 * Use BSD struct tcphdr field names for portability.  Modern glibc
 * makes them available by default via <netinet/tcp.h> but older glibc
 * requires __FAVOR_BSD to be defined.
 *
 * __FAVOR_BSD is normally defined in <features.h> if _DEFAULT_SOURCE
 * (new) or _BSD_SOURCE (now deprecated) is set and _GNU_SOURCE is not
 * set.  Including "replace.h" above causes <features.h> to be
 * indirectly included and this will not set __FAVOR_BSD because
 * _GNU_SOURCE is set in Samba's "config.h" (which is included by
 * "replace.h").
 *
 * Therefore, set __FAVOR_BSD by hand below.
 */
#define __FAVOR_BSD 1
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
#include "lib/util/blocking.h"

#include "protocol/protocol.h"

#include "common/logging.h"
#include "common/system_socket.h"

/*
  uint16 checksum for n bytes
 */
static uint32_t uint16_checksum(uint8_t *data, size_t n)
{
	uint32_t sum=0;
	uint16_t value;

	while (n>=2) {
		memcpy(&value, data, 2);
		sum += (uint32_t)ntohs(value);
		data += 2;
		n -= 2;
	}
	if (n == 1) {
		sum += (uint32_t)ntohs(*data);
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

/*
 * simple TCP checksum - assumes data is multiple of 2 bytes long
 */
static uint16_t ip_checksum(uint8_t *data, size_t n, struct ip *ip)
{
	uint32_t sum = uint16_checksum(data, n);
	uint16_t sum2;

	sum += uint16_checksum((uint8_t *)&ip->ip_src, sizeof(ip->ip_src));
	sum += uint16_checksum((uint8_t *)&ip->ip_dst, sizeof(ip->ip_dst));
	sum += ip->ip_p + n;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum2 = htons(sum);
	sum2 = ~sum2;
	if (sum2 == 0) {
		return 0xFFFF;
	}
	return sum2;
}

static uint16_t ip6_checksum(uint8_t *data, size_t n, struct ip6_hdr *ip6)
{
	uint16_t phdr[3];
	uint32_t sum = 0;
	uint16_t sum2;
	uint32_t len;

	sum += uint16_checksum((uint8_t *)&ip6->ip6_src, 16);
	sum += uint16_checksum((uint8_t *)&ip6->ip6_dst, 16);

	len = htonl(n);
	phdr[0] = len & UINT16_MAX;
	phdr[1] = (len >> 16) & UINT16_MAX;
	/* ip6_nxt is only 8 bits, so fits comfortably into a uint16_t */
	phdr[2] = htons(ip6->ip6_nxt);
	sum += uint16_checksum((uint8_t *)phdr, sizeof(phdr));

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

/*
 * Create IPv4 ARP requests/replies or IPv6 neighbour advertisement
 * packets
 */

#define ARP_STRUCT_SIZE sizeof(struct ether_header) + \
			sizeof(struct ether_arp)

#define IP6_NA_STRUCT_SIZE sizeof(struct ether_header) + \
			   sizeof(struct ip6_hdr) + \
			   sizeof(struct nd_neighbor_advert) + \
			   sizeof(struct nd_opt_hdr) + \
			   sizeof(struct ether_addr)

#define ARP_BUFFER_SIZE MAX(ARP_STRUCT_SIZE, 64)

#define IP6_NA_BUFFER_SIZE MAX(IP6_NA_STRUCT_SIZE, 64)

static int arp_build(uint8_t *buffer,
		     size_t buflen,
		     const struct sockaddr_in *addr,
		     const struct ether_addr *hwaddr,
		     bool reply,
		     struct ether_addr **ether_dhost,
		     size_t *len)
{
	size_t l = ARP_BUFFER_SIZE;
	struct ether_header *eh;
	struct ether_arp *ea;
	struct arphdr *ah;

	if (addr->sin_family != AF_INET) {
		return EINVAL;
	}

	if (buflen < l) {
		return EMSGSIZE;
	}

	memset(buffer, 0 , l);

	eh = (struct ether_header *)buffer;
	memset(eh->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eh->ether_shost, hwaddr, ETH_ALEN);
	eh->ether_type = htons(ETHERTYPE_ARP);

	ea = (struct ether_arp *)(buffer + sizeof(struct ether_header));
	ah = &ea->ea_hdr;
	ah->ar_hrd = htons(ARPHRD_ETHER);
	ah->ar_pro = htons(ETH_P_IP);
	ah->ar_hln = ETH_ALEN;
	ah->ar_pln = sizeof(ea->arp_spa);

	if (! reply) {
		ah->ar_op  = htons(ARPOP_REQUEST);
		memcpy(ea->arp_sha, hwaddr, ETH_ALEN);
		memcpy(ea->arp_spa, &addr->sin_addr, sizeof(ea->arp_spa));
		memset(ea->arp_tha, 0, ETH_ALEN);
		memcpy(ea->arp_tpa, &addr->sin_addr, sizeof(ea->arp_tpa));
	} else {
		ah->ar_op  = htons(ARPOP_REPLY);
		memcpy(ea->arp_sha, hwaddr, ETH_ALEN);
		memcpy(ea->arp_spa, &addr->sin_addr, sizeof(ea->arp_spa));
		memcpy(ea->arp_tha, hwaddr, ETH_ALEN);
		memcpy(ea->arp_tpa, &addr->sin_addr, sizeof(ea->arp_tpa));
	}

	*ether_dhost = (struct ether_addr *)eh->ether_dhost;
	*len = l;
	return 0;
}

static int ip6_na_build(uint8_t *buffer,
			size_t buflen,
			const struct sockaddr_in6 *addr,
			const struct ether_addr *hwaddr,
			struct ether_addr **ether_dhost,
			size_t *len)
{
	size_t l = IP6_NA_BUFFER_SIZE;
	struct ether_header *eh;
	struct ip6_hdr *ip6;
	struct nd_neighbor_advert *nd_na;
	struct nd_opt_hdr *nd_oh;
	struct ether_addr *ea;
	int ret;

	if (addr->sin6_family != AF_INET6) {
		return EINVAL;
	}

	if (buflen < l) {
		return EMSGSIZE;
	}

	memset(buffer, 0 , l);

	eh = (struct ether_header *)buffer;
	/*
	 * Ethernet multicast: 33:33:00:00:00:01 (see RFC2464,
	 * section 7) - note memset 0 above!
	 */
	eh->ether_dhost[0] = 0x33;
	eh->ether_dhost[1] = 0x33;
	eh->ether_dhost[5] = 0x01;
	memcpy(eh->ether_shost, hwaddr, ETH_ALEN);
	eh->ether_type = htons(ETHERTYPE_IP6);

	ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
	ip6->ip6_vfc  = 6 << 4;
	ip6->ip6_plen = htons(sizeof(struct nd_neighbor_advert) +
			      sizeof(struct nd_opt_hdr) +
			      ETH_ALEN);
	ip6->ip6_nxt  = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	ip6->ip6_src  = addr->sin6_addr;
	/* all-nodes multicast */

	ret = inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);
	if (ret != 1) {
		return EIO;
	}

	nd_na = (struct nd_neighbor_advert *)(buffer +
					      sizeof(struct ether_header) +
					      sizeof(struct ip6_hdr));
	nd_na->nd_na_type = ND_NEIGHBOR_ADVERT;
	nd_na->nd_na_code = 0;
	nd_na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
	nd_na->nd_na_target = addr->sin6_addr;

	/* Option: Target link-layer address */
	nd_oh = (struct nd_opt_hdr *)(buffer +
				      sizeof(struct ether_header) +
				      sizeof(struct ip6_hdr) +
				      sizeof(struct nd_neighbor_advert));
	nd_oh->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	nd_oh->nd_opt_len = 1;  /* multiple of 8 octets */

	ea = (struct ether_addr *)(buffer +
				   sizeof(struct ether_header) +
				   sizeof(struct ip6_hdr) +
				   sizeof(struct nd_neighbor_advert) +
				   sizeof(struct nd_opt_hdr));
	memcpy(ea, hwaddr, ETH_ALEN);

	nd_na->nd_na_cksum = ip6_checksum((uint8_t *)nd_na,
					  ntohs(ip6->ip6_plen),
					  ip6);

	*ether_dhost = (struct ether_addr *)eh->ether_dhost;
	*len = l;
	return 0;
}

int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface)
{
	int s;
	struct sockaddr_ll sall = {0};
	struct ifreq if_hwaddr = {
		.ifr_ifru = {
			.ifru_flags = 0
		},
	};
	uint8_t buffer[MAX(ARP_BUFFER_SIZE, IP6_NA_BUFFER_SIZE)];
	struct ifreq ifr = {
		.ifr_ifru = {
			.ifru_flags = 0
		},
	};
	struct ether_addr *hwaddr = NULL;
	struct ether_addr *ether_dhost = NULL;
	size_t len = 0;
	int ret = 0;

	s = socket(AF_PACKET, SOCK_RAW, 0);
	if (s == -1) {
		ret = errno;
		DBG_ERR("Failed to open raw socket\n");
		return ret;
	}
	DBG_DEBUG("Created SOCKET FD:%d for sending arp\n", s);

	/* Find interface */
	strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		ret = errno;
		DBG_ERR("Interface '%s' not found\n", iface);
		goto fail;
	}

	/* Get MAC address */
	strlcpy(if_hwaddr.ifr_name, iface, sizeof(if_hwaddr.ifr_name));
	ret = ioctl(s, SIOCGIFHWADDR, &if_hwaddr);
	if ( ret < 0 ) {
		ret = errno;
		DBG_ERR("ioctl failed\n");
		goto fail;
	}
	if (ARPHRD_LOOPBACK == if_hwaddr.ifr_hwaddr.sa_family) {
		ret = 0;
		D_DEBUG("Ignoring loopback arp request\n");
		goto fail;
	}
	if (if_hwaddr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		ret = EINVAL;
		DBG_ERR("Not an ethernet address family (0x%x)\n",
			if_hwaddr.ifr_hwaddr.sa_family);
		goto fail;;
	}

	/* Set up most of destination address structure */
	sall.sll_family = AF_PACKET;
	sall.sll_halen = sizeof(struct ether_addr);
	sall.sll_protocol = htons(ETH_P_ALL);
	sall.sll_ifindex = ifr.ifr_ifindex;

	/* For clarity */
	hwaddr = (struct ether_addr *)if_hwaddr.ifr_hwaddr.sa_data;

	switch (addr->ip.sin_family) {
	case AF_INET:
		/* Send gratuitous ARP */
		ret = arp_build(buffer,
				sizeof(buffer),
				&addr->ip,
				hwaddr,
				false,
				&ether_dhost,
				&len);
		if (ret != 0) {
			DBG_ERR("Failed to build ARP request\n");
			goto fail;
		}

		memcpy(&sall.sll_addr[0], ether_dhost, sall.sll_halen);

		ret = sendto(s,
			     buffer,
			     len,
			     0,
			     (struct sockaddr *)&sall,
			     sizeof(sall));
		if (ret < 0 ) {
			ret = errno;
			DBG_ERR("Failed sendto\n");
			goto fail;
		}

		/* Send unsolicited ARP reply */
		ret = arp_build(buffer,
				sizeof(buffer),
				&addr->ip,
				hwaddr,
				true,
				&ether_dhost,
				&len);
		if (ret != 0) {
			DBG_ERR("Failed to build ARP reply\n");
			goto fail;
		}

		memcpy(&sall.sll_addr[0], ether_dhost, sall.sll_halen);

		ret = sendto(s,
			     buffer,
			     len,
			     0,
			     (struct sockaddr *)&sall,
			     sizeof(sall));
		if (ret < 0 ) {
			ret = errno;
			DBG_ERR("Failed sendto\n");
			goto fail;
		}

		close(s);
		break;

	case AF_INET6:
		ret = ip6_na_build(buffer,
				   sizeof(buffer),
				   &addr->ip6,
				   hwaddr,
				   &ether_dhost,
				   &len);
		if (ret != 0) {
			DBG_ERR("Failed to build IPv6 neighbor advertisement\n");
			goto fail;
		}

		memcpy(&sall.sll_addr[0], ether_dhost, sall.sll_halen);

		ret = sendto(s,
			     buffer,
			     len,
			     0,
			     (struct sockaddr *)&sall,
			     sizeof(sall));
		if (ret < 0 ) {
			ret = errno;
			DBG_ERR("Failed sendto\n");
			goto fail;
		}

		close(s);
		break;

	default:
		ret = EINVAL;
		DBG_ERR("Not an ipv4/ipv6 address (family is %u)\n",
			addr->ip.sin_family);
		goto fail;
	}

	return 0;

fail:
	close(s);
	return ret;
}

#else /* HAVE_PACKETSOCKET */

int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface)
{
	/* Not implemented */
	return ENOSYS;
}

#endif /* HAVE_PACKETSOCKET */


#define IP4_TCP_BUFFER_SIZE sizeof(struct ip) + \
			    sizeof(struct tcphdr)

#define IP6_TCP_BUFFER_SIZE sizeof(struct ip6_hdr) + \
			    sizeof(struct tcphdr)

static int tcp4_build(uint8_t *buf,
		      size_t buflen,
		      const struct sockaddr_in *src,
		      const struct sockaddr_in *dst,
		      uint32_t seq,
		      uint32_t ack,
		      int rst,
		      size_t *len)
{
	size_t l = IP4_TCP_BUFFER_SIZE;
	struct {
		struct ip ip;
		struct tcphdr tcp;
	} *ip4pkt;

	if (l != sizeof(*ip4pkt)) {
		return EMSGSIZE;
	}

	if (buflen < l) {
		return EMSGSIZE;
	}

	ip4pkt = (void *)buf;
	memset(ip4pkt, 0, l);

	ip4pkt->ip.ip_v     = 4;
	ip4pkt->ip.ip_hl    = sizeof(ip4pkt->ip)/sizeof(uint32_t);
	ip4pkt->ip.ip_len   = htons(sizeof(ip4pkt));
	ip4pkt->ip.ip_ttl   = 255;
	ip4pkt->ip.ip_p     = IPPROTO_TCP;
	ip4pkt->ip.ip_src.s_addr = src->sin_addr.s_addr;
	ip4pkt->ip.ip_dst.s_addr = dst->sin_addr.s_addr;
	ip4pkt->ip.ip_sum   = 0;

	ip4pkt->tcp.th_sport = src->sin_port;
	ip4pkt->tcp.th_dport = dst->sin_port;
	ip4pkt->tcp.th_seq   = seq;
	ip4pkt->tcp.th_ack   = ack;
	ip4pkt->tcp.th_flags = 0;
	ip4pkt->tcp.th_flags |= TH_ACK;
	if (rst) {
		ip4pkt->tcp.th_flags |= TH_RST;
	}
	ip4pkt->tcp.th_off   = sizeof(ip4pkt->tcp)/sizeof(uint32_t);
	/* this makes it easier to spot in a sniffer */
	ip4pkt->tcp.th_win   = htons(1234);
	ip4pkt->tcp.th_sum   = ip_checksum((uint8_t *)&ip4pkt->tcp,
					   sizeof(ip4pkt->tcp),
					   &ip4pkt->ip);

	*len = l;
	return 0;
}

static int tcp6_build(uint8_t *buf,
		      size_t buflen,
		      const struct sockaddr_in6 *src,
		      const struct sockaddr_in6 *dst,
		      uint32_t seq,
		      uint32_t ack,
		      int rst,
		      size_t *len)
{
	size_t l = IP6_TCP_BUFFER_SIZE;
	struct {
		struct ip6_hdr ip6;
		struct tcphdr tcp;
	} *ip6pkt;

	if (l != sizeof(*ip6pkt)) {
		return EMSGSIZE;
	}

	if (buflen < l) {
		return EMSGSIZE;
	}

	ip6pkt = (void *)buf;
	memset(ip6pkt, 0, l);

	ip6pkt->ip6.ip6_vfc  = 6 << 4;
	ip6pkt->ip6.ip6_plen = htons(sizeof(struct tcphdr));
	ip6pkt->ip6.ip6_nxt  = IPPROTO_TCP;
	ip6pkt->ip6.ip6_hlim = 64;
	ip6pkt->ip6.ip6_src  = src->sin6_addr;
	ip6pkt->ip6.ip6_dst  = dst->sin6_addr;

	ip6pkt->tcp.th_sport = src->sin6_port;
	ip6pkt->tcp.th_dport = dst->sin6_port;
	ip6pkt->tcp.th_seq   = seq;
	ip6pkt->tcp.th_ack   = ack;
	ip6pkt->tcp.th_flags = 0;
	ip6pkt->tcp.th_flags |= TH_ACK;
	if (rst) {
		ip6pkt->tcp.th_flags |= TH_RST;
	}
	ip6pkt->tcp.th_off    = sizeof(ip6pkt->tcp)/sizeof(uint32_t);
	/* this makes it easier to spot in a sniffer */
	ip6pkt->tcp.th_win   = htons(1234);
	ip6pkt->tcp.th_sum   = ip6_checksum((uint8_t *)&ip6pkt->tcp,
					    sizeof(ip6pkt->tcp),
					    &ip6pkt->ip6);

	*len = l;
	return 0;
}

/*
 * Send tcp segment from the specified IP/port to the specified
 * destination IP/port.
 *
 * This is used to trigger the receiving host into sending its own ACK,
 * which should trigger early detection of TCP reset by the client
 * after IP takeover
 *
 * This can also be used to send RST segments (if rst is true) and also
 * if correct seq and ack numbers are provided.
 */
int ctdb_sys_send_tcp(const ctdb_sock_addr *dest,
		      const ctdb_sock_addr *src,
		      uint32_t seq,
		      uint32_t ack,
		      int rst)
{
	uint8_t buf[MAX(IP4_TCP_BUFFER_SIZE, IP6_TCP_BUFFER_SIZE)];
	size_t len = 0;
	int ret;
	int s;
	uint32_t one = 1;
	struct sockaddr_in6 tmpdest = { 0 };
	int saved_errno;

	switch (src->ip.sin_family) {
	case AF_INET:
		ret = tcp4_build(buf,
				 sizeof(buf),
				 &src->ip,
				 &dest->ip,
				 seq,
				 ack,
				 rst,
				 &len);
		if (ret != 0) {
			DBG_ERR("Failed to build TCP packet (%d)\n", ret);
			return ret;
		}

		/* open a raw socket to send this segment from */
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (s == -1) {
			DBG_ERR("Failed to open raw socket (%s)\n",
				strerror(errno));
			return -1;
		}

		ret = setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		if (ret != 0) {
			DBG_ERR("Failed to setup IP headers (%s)\n",
				strerror(errno));
			close(s);
			return -1;
		}

		ret = sendto(s,
			     buf,
			     len,
			     0,
			     (const struct sockaddr *)&dest->ip,
			     sizeof(dest->ip));
		saved_errno = errno;
		close(s);
		if (ret == -1) {
			D_ERR("Failed sendto (%s)\n", strerror(saved_errno));
			return -1;
		}
		if ((size_t)ret != len) {
			DBG_ERR("Failed sendto - didn't send full packet\n");
			return -1;
		}
		break;

	case AF_INET6:
		ret = tcp6_build(buf,
				 sizeof(buf),
				 &src->ip6,
				 &dest->ip6,
				 seq,
				 ack,
				 rst,
				 &len);
		if (ret != 0) {
			DBG_ERR("Failed to build TCP packet (%d)\n", ret);
			return ret;
		}

		s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (s == -1) {
			DBG_ERR("Failed to open sending socket\n");
			return -1;

		}
		/*
		 * sendto() on an IPv6 raw socket requires the port to
		 * be either 0 or a protocol value
		 */
		tmpdest = dest->ip6;
		tmpdest.sin6_port = 0;

		ret = sendto(s,
			     buf,
			     len,
			     0,
			     (const struct sockaddr *)&tmpdest,
			     sizeof(tmpdest));
		saved_errno = errno;
		close(s);
		if (ret == -1) {
			D_ERR("Failed sendto (%s)\n", strerror(saved_errno));
			return -1;
		}
		if ((size_t)ret != len) {
			DBG_ERR("Failed sendto - didn't send full packet\n");
			return -1;
		}
		break;

	default:
		DBG_ERR("Not an ipv4/v6 address\n");
		return -1;
	}

	return 0;
}

/*
 * Packet capture
 *
 * If AF_PACKET is available then use a raw socket otherwise use pcap.
 * wscript has checked to make sure that pcap is available if needed.
 */

static int tcp4_extract(const uint8_t *ip_pkt,
			size_t pktlen,
			struct sockaddr_in *src,
			struct sockaddr_in *dst,
			uint32_t *ack_seq,
			uint32_t *seq,
			int *rst,
			uint16_t *window)
{
	const struct ip *ip;
	const struct tcphdr *tcp;

	if (pktlen < sizeof(struct ip)) {
		return EMSGSIZE;
	}

	ip = (const struct ip *)ip_pkt;

	/* IPv4 only */
	if (ip->ip_v != 4) {
		return ENOMSG;
	}
	/* Don't look at fragments */
	if ((ntohs(ip->ip_off)&0x1fff) != 0) {
		return ENOMSG;
	}
	/* TCP only */
	if (ip->ip_p != IPPROTO_TCP) {
		return ENOMSG;
	}

	/* Ensure there is enough of the packet to gather required fields */
	if (pktlen <
	    (ip->ip_hl * sizeof(uint32_t)) + offsetof(struct tcphdr, th_sum)) {
		return EMSGSIZE;
	}

	tcp = (const struct tcphdr *)(ip_pkt + (ip->ip_hl * sizeof(uint32_t)));

	src->sin_family      = AF_INET;
	src->sin_addr.s_addr = ip->ip_src.s_addr;
	src->sin_port        = tcp->th_sport;

	dst->sin_family      = AF_INET;
	dst->sin_addr.s_addr = ip->ip_dst.s_addr;
	dst->sin_port        = tcp->th_dport;

	*ack_seq             = tcp->th_ack;
	*seq                 = tcp->th_seq;
	if (window != NULL) {
		*window = tcp->th_win;
	}
	if (rst != NULL) {
		*rst = tcp->th_flags & TH_RST;
	}

	return 0;
}

static int tcp6_extract(const uint8_t *ip_pkt,
			size_t pktlen,
			struct sockaddr_in6 *src,
			struct sockaddr_in6 *dst,
			uint32_t *ack_seq,
			uint32_t *seq,
			int *rst,
			uint16_t *window)
{
	const struct ip6_hdr *ip6;
	const struct tcphdr *tcp;

	/* Ensure there is enough of the packet to gather required fields */
	if (pktlen < sizeof(struct ip6_hdr) + offsetof(struct tcphdr, th_sum)) {
		return EMSGSIZE;
	}

	ip6 = (const struct ip6_hdr *)ip_pkt;

	/* IPv6 only */
	if ((ip6->ip6_vfc >> 4) != 6){
		return ENOMSG;
	}

	/* TCP only */
	if (ip6->ip6_nxt != IPPROTO_TCP) {
		return ENOMSG;
	}

	tcp = (const struct tcphdr *)(ip_pkt + sizeof(struct ip6_hdr));

	src->sin6_family = AF_INET6;
	src->sin6_port   = tcp->th_sport;
	src->sin6_addr   = ip6->ip6_src;

	dst->sin6_family = AF_INET6;
	dst->sin6_port   = tcp->th_dport;
	dst->sin6_addr   = ip6->ip6_dst;

	*ack_seq             = tcp->th_ack;
	*seq                 = tcp->th_seq;
	if (window != NULL) {
		*window = tcp->th_win;
	}
	if (rst != NULL) {
		*rst = tcp->th_flags & TH_RST;
	}

	return 0;
}


#ifdef HAVE_AF_PACKET

/*
 * This function is used to open a raw socket to capture from
 */
int ctdb_sys_open_capture_socket(const char *iface, void **private_data)
{
	int s, ret;

	/* Open a socket to capture all traffic */
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) {
		DBG_ERR("Failed to open raw socket\n");
		return -1;
	}

	DBG_DEBUG("Created RAW SOCKET FD:%d for tcp tickle\n", s);

	ret = set_blocking(s, false);
	if (ret != 0) {
		DBG_ERR("Failed to set socket non-blocking (%s)\n",
			strerror(errno));
		close(s);
		return -1;
	}

	set_close_on_exec(s);

	return s;
}

/*
 * This function is used to do any additional cleanup required when closing
 * a capture socket.
 * Note that the socket itself is closed automatically in the caller.
 */
int ctdb_sys_close_capture_socket(void *private_data)
{
	return 0;
}


/*
 * called when the raw socket becomes readable
 */
int ctdb_sys_read_tcp_packet(int s, void *private_data,
			     ctdb_sock_addr *src,
			     ctdb_sock_addr *dst,
			     uint32_t *ack_seq,
			     uint32_t *seq,
			     int *rst,
			     uint16_t *window)
{
	ssize_t nread;
	uint8_t pkt[100]; /* Large enough for simple ACK/RST packets */
	struct ether_header *eth;
	int ret;

	nread = recv(s, pkt, sizeof(pkt), MSG_TRUNC);
	if (nread == -1) {
		return errno;
	}
	if ((size_t)nread < sizeof(*eth)) {
		return EMSGSIZE;
	}

	ZERO_STRUCTP(src);
	ZERO_STRUCTP(dst);

	/* Ethernet */
	eth = (struct ether_header *)pkt;

	/* we want either IPv4 or IPv6 */
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		ret = tcp4_extract(pkt + sizeof(struct ether_header),
				   (size_t)nread - sizeof(struct ether_header),
				   &src->ip,
				   &dst->ip,
				   ack_seq,
				   seq,
				   rst,
				   window);
		return ret;

	} else if (ntohs(eth->ether_type) == ETHERTYPE_IP6) {
		ret = tcp6_extract(pkt + sizeof(struct ether_header),
				   (size_t)nread - sizeof(struct ether_header),
				   &src->ip6,
				   &dst->ip6,
				   ack_seq,
				   seq,
				   rst,
				   window);
		return ret;
	}

	return ENOMSG;
}

#else /* HAVE_AF_PACKET */

#include <pcap.h>

int ctdb_sys_open_capture_socket(const char *iface, void **private_data)
{
	pcap_t *pt;

	pt=pcap_open_live(iface, 100, 0, 0, NULL);
	if (pt == NULL) {
		DBG_ERR("Failed to open capture device %s\n", iface);
		return -1;
	}
	*((pcap_t **)private_data) = pt;

	return pcap_fileno(pt);
}

int ctdb_sys_close_capture_socket(void *private_data)
{
	pcap_t *pt = (pcap_t *)private_data;
	pcap_close(pt);
	return 0;
}

int ctdb_sys_read_tcp_packet(int s,
			     void *private_data,
			     ctdb_sock_addr *src,
			     ctdb_sock_addr *dst,
			     uint32_t *ack_seq,
			     uint32_t *seq,
			     int *rst,
			     uint16_t *window)
{
	int ret;
	struct ether_header *eth;
	struct pcap_pkthdr pkthdr;
	const u_char *buffer;
	pcap_t *pt = (pcap_t *)private_data;

	buffer=pcap_next(pt, &pkthdr);
	if (buffer==NULL) {
		return ENOMSG;
	}

	ZERO_STRUCTP(src);
	ZERO_STRUCTP(dst);

	/* Ethernet */
	eth = (struct ether_header *)buffer;

	/* we want either IPv4 or IPv6 */
	if (eth->ether_type == htons(ETHERTYPE_IP)) {
		ret = tcp4_extract(buffer + sizeof(struct ether_header),
				   (size_t)(pkthdr.caplen -
					    sizeof(struct ether_header)),
				   &src->ip,
				   &dst->ip,
				   ack_seq,
				   seq,
				   rst,
				   window);
		return ret;

	} else if (eth->ether_type == htons(ETHERTYPE_IP6)) {
		ret = tcp6_extract(buffer + sizeof(struct ether_header),
				   (size_t)(pkthdr.caplen -
					    sizeof(struct ether_header)),
				   &src->ip6,
				   &dst->ip6,
				   ack_seq,
				   seq,
				   rst,
				   window);
		return ret;
	}

	return ENOMSG;
}

#endif /* HAVE_AF_PACKET */
