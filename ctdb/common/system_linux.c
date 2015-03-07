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

#include "includes.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/prctl.h>

#ifndef ETHERTYPE_IP6
#define ETHERTYPE_IP6 0x86dd
#endif

/*
  calculate the tcp checksum for tcp over ipv6
*/
static uint16_t tcp_checksum6(uint16_t *data, size_t n, struct ip6_hdr *ip6)
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
  send gratuitous arp reply after we have taken over an ip address

  saddr is the address we are trying to claim
  iface is the interface name we will be using to claim the address
 */
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
		s = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_ARP));
		if (s == -1){
			DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket\n"));
			return -1;
		}

		DEBUG(DEBUG_DEBUG, (__location__ " Created SOCKET FD:%d for sending arp\n", s));
		strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			DEBUG(DEBUG_CRIT,(__location__ " interface '%s' not found\n", iface));
			close(s);
			return -1;
		}

		/* get the mac address */
		strncpy(if_hwaddr.ifr_name, iface, sizeof(if_hwaddr.ifr_name)-1);
		ret = ioctl(s, SIOCGIFHWADDR, &if_hwaddr);
		if ( ret < 0 ) {
			close(s);
			DEBUG(DEBUG_CRIT,(__location__ " ioctl failed\n"));
			return -1;
		}
		if (ARPHRD_LOOPBACK == if_hwaddr.ifr_hwaddr.sa_family) {
			DEBUG(DEBUG_DEBUG,("Ignoring loopback arp request\n"));
			close(s);
			return 0;
		}
		if (if_hwaddr.ifr_hwaddr.sa_family != AF_LOCAL) {
			close(s);
			errno = EINVAL;
			DEBUG(DEBUG_CRIT,(__location__ " not an ethernet address family (0x%x)\n",
				 if_hwaddr.ifr_hwaddr.sa_family));
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
		ret = sendto(s, buffer, 64, 0, (struct sockaddr *)&sall, sizeof(sall));
		if (ret < 0 ){
			close(s);
			DEBUG(DEBUG_CRIT,(__location__ " failed sendto\n"));
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

		ret = sendto(s, buffer, 64, 0, (struct sockaddr *)&sall, sizeof(sall));
		if (ret < 0 ){
			DEBUG(DEBUG_CRIT,(__location__ " failed sendto\n"));
			close(s);
			return -1;
		}

		close(s);
		break;
	case AF_INET6:
		s = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_ARP));
		if (s == -1){
			DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket\n"));
			return -1;
		}

		DEBUG(DEBUG_DEBUG, (__location__ " Created SOCKET FD:%d for sending arp\n", s));
		strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			DEBUG(DEBUG_CRIT,(__location__ " interface '%s' not found\n", iface));
			close(s);
			return -1;
		}

		/* get the mac address */
		strncpy(if_hwaddr.ifr_name, iface, sizeof(if_hwaddr.ifr_name)-1);
		ret = ioctl(s, SIOCGIFHWADDR, &if_hwaddr);
		if ( ret < 0 ) {
			close(s);
			DEBUG(DEBUG_CRIT,(__location__ " ioctl failed\n"));
			return -1;
		}
		if (ARPHRD_LOOPBACK == if_hwaddr.ifr_hwaddr.sa_family) {
			DEBUG(DEBUG_DEBUG,("Ignoring loopback arp request\n"));
			close(s);
			return 0;
		}
		if (if_hwaddr.ifr_hwaddr.sa_family != AF_LOCAL) {
			close(s);
			errno = EINVAL;
			DEBUG(DEBUG_CRIT,(__location__ " not an ethernet address family (0x%x)\n",
				 if_hwaddr.ifr_hwaddr.sa_family));
			return -1;
		}

		memset(buffer, 0 , sizeof(buffer));
		eh = (struct ether_header *)buffer;
		/* Ethernet multicast: 33:33:00:00:00:01 (see RFC2464,
		 * section 7) - note zeroes above! */
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
		inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);

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

		nd_na->nd_na_cksum = tcp_checksum6((uint16_t *)nd_na,
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
			DEBUG(DEBUG_CRIT,(__location__ " failed sendto\n"));
			return -1;
		}	

		close(s);
		break;
	default:
		DEBUG(DEBUG_CRIT,(__location__ " not an ipv4/ipv6 address (family is %u)\n", addr->ip.sin_family));
		return -1;
	}

	return 0;
}


/*
  simple TCP checksum - assumes data is multiple of 2 bytes long
 */
static uint16_t tcp_checksum(uint16_t *data, size_t n, struct iphdr *ip)
{
	uint32_t sum = uint16_checksum(data, n);
	uint16_t sum2;
	sum += uint16_checksum((uint16_t *)(void *)&ip->saddr,
			       sizeof(ip->saddr));
	sum += uint16_checksum((uint16_t *)(void *)&ip->daddr,
			       sizeof(ip->daddr));
	sum += ip->protocol + n;
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
  Send tcp segment from the specified IP/port to the specified
  destination IP/port. 

  This is used to trigger the receiving host into sending its own ACK,
  which should trigger early detection of TCP reset by the client
  after IP takeover

  This can also be used to send RST segments (if rst is true) and also
  if correct seq and ack numbers are provided.
 */
int ctdb_sys_send_tcp(const ctdb_sock_addr *dest, 
		      const ctdb_sock_addr *src,
		      uint32_t seq, uint32_t ack, int rst)
{
	int s;
	int ret;
	uint32_t one = 1;
	uint16_t tmpport;
	ctdb_sock_addr *tmpdest;
	struct {
		struct iphdr ip;
		struct tcphdr tcp;
	} ip4pkt;
	struct {
		struct ip6_hdr ip6;
		struct tcphdr tcp;
	} ip6pkt;

	switch (src->ip.sin_family) {
	case AF_INET:
		ZERO_STRUCT(ip4pkt);
		ip4pkt.ip.version  = 4;
		ip4pkt.ip.ihl      = sizeof(ip4pkt.ip)/4;
		ip4pkt.ip.tot_len  = htons(sizeof(ip4pkt));
		ip4pkt.ip.ttl      = 255;
		ip4pkt.ip.protocol = IPPROTO_TCP;
		ip4pkt.ip.saddr    = src->ip.sin_addr.s_addr;
		ip4pkt.ip.daddr    = dest->ip.sin_addr.s_addr;
		ip4pkt.ip.check    = 0;

		ip4pkt.tcp.source   = src->ip.sin_port;
		ip4pkt.tcp.dest     = dest->ip.sin_port;
		ip4pkt.tcp.seq      = seq;
		ip4pkt.tcp.ack_seq  = ack;
		ip4pkt.tcp.ack      = 1;
		if (rst) {
			ip4pkt.tcp.rst      = 1;
		}
		ip4pkt.tcp.doff     = sizeof(ip4pkt.tcp)/4;
		/* this makes it easier to spot in a sniffer */
		ip4pkt.tcp.window   = htons(1234);
		ip4pkt.tcp.check    = tcp_checksum((uint16_t *)&ip4pkt.tcp, sizeof(ip4pkt.tcp), &ip4pkt.ip);

		/* open a raw socket to send this segment from */
		s = socket(AF_INET, SOCK_RAW, htons(IPPROTO_RAW));
		if (s == -1) {
			DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket (%s)\n",
				 strerror(errno)));
			return -1;
		}

		ret = setsockopt(s, SOL_IP, IP_HDRINCL, &one, sizeof(one));
		if (ret != 0) {
			DEBUG(DEBUG_CRIT,(__location__ " failed to setup IP headers (%s)\n",
				 strerror(errno)));
			close(s);
			return -1;
		}

		set_nonblocking(s);
		set_close_on_exec(s);

		ret = sendto(s, &ip4pkt, sizeof(ip4pkt), 0,
			     (const struct sockaddr *)&dest->ip,
			     sizeof(dest->ip));
		close(s);
		if (ret != sizeof(ip4pkt)) {
			DEBUG(DEBUG_CRIT,(__location__ " failed sendto (%s)\n", strerror(errno)));
			return -1;
		}
		break;
	case AF_INET6:
		ZERO_STRUCT(ip6pkt);
		ip6pkt.ip6.ip6_vfc  = 0x60;
		ip6pkt.ip6.ip6_plen = htons(20);
		ip6pkt.ip6.ip6_nxt  = IPPROTO_TCP;
		ip6pkt.ip6.ip6_hlim = 64;
		ip6pkt.ip6.ip6_src  = src->ip6.sin6_addr;
		ip6pkt.ip6.ip6_dst  = dest->ip6.sin6_addr;

		ip6pkt.tcp.source   = src->ip6.sin6_port;
		ip6pkt.tcp.dest     = dest->ip6.sin6_port;
		ip6pkt.tcp.seq      = seq;
		ip6pkt.tcp.ack_seq  = ack;
		ip6pkt.tcp.ack      = 1;
		if (rst) {
			ip6pkt.tcp.rst      = 1;
		}
		ip6pkt.tcp.doff     = sizeof(ip6pkt.tcp)/4;
		/* this makes it easier to spot in a sniffer */
		ip6pkt.tcp.window   = htons(1234);
		ip6pkt.tcp.check    = tcp_checksum6((uint16_t *)&ip6pkt.tcp, sizeof(ip6pkt.tcp), &ip6pkt.ip6);

		s = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (s == -1) {
			DEBUG(DEBUG_CRIT, (__location__ " Failed to open sending socket\n"));
			return -1;

		}
		/* sendto() dont like if the port is set and the socket is
		   in raw mode.
		*/
		tmpdest = discard_const(dest);
		tmpport = tmpdest->ip6.sin6_port;

		tmpdest->ip6.sin6_port = 0;
		ret = sendto(s, &ip6pkt, sizeof(ip6pkt), 0,
			     (const struct sockaddr *)&dest->ip6,
			     sizeof(dest->ip6));
		tmpdest->ip6.sin6_port = tmpport;
		close(s);

		if (ret != sizeof(ip6pkt)) {
			DEBUG(DEBUG_CRIT,(__location__ " failed sendto (%s)\n", strerror(errno)));
			return -1;
		}
		break;

	default:
		DEBUG(DEBUG_CRIT,(__location__ " not an ipv4/v6 address\n"));
		return -1;
	}

	return 0;
}

/* 
   This function is used to open a raw socket to capture from
 */
int ctdb_sys_open_capture_socket(const char *iface, void **private_data)
{
	int s;

	/* Open a socket to capture all traffic */
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) {
		DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket\n"));
		return -1;
	}

	DEBUG(DEBUG_DEBUG, (__location__ " Created RAW SOCKET FD:%d for tcp tickle\n", s));

	set_nonblocking(s);
	set_close_on_exec(s);

	return s;
}

/* 
   This function is used to do any additional cleanup required when closing
   a capture socket.
   Note that the socket itself is closed automatically in the caller.
 */
int ctdb_sys_close_capture_socket(void *private_data)
{
	return 0;
}


/*
  called when the raw socket becomes readable
 */
int ctdb_sys_read_tcp_packet(int s, void *private_data, 
			ctdb_sock_addr *src, ctdb_sock_addr *dst,
			uint32_t *ack_seq, uint32_t *seq)
{
	int ret;
#define RCVPKTSIZE 100
	char pkt[RCVPKTSIZE];
	struct ether_header *eth;
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;

	ret = recv(s, pkt, RCVPKTSIZE, MSG_TRUNC);
	if (ret < sizeof(*eth)+sizeof(*ip)) {
		return -1;
	}

	/* Ethernet */
	eth = (struct ether_header *)pkt;

	/* we want either IPv4 or IPv6 */
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		/* IP */
		ip = (struct iphdr *)(eth+1);

		/* We only want IPv4 packets */
		if (ip->version != 4) {
			return -1;
		}
		/* Dont look at fragments */
		if ((ntohs(ip->frag_off)&0x1fff) != 0) {
			return -1;
		}
		/* we only want TCP */
		if (ip->protocol != IPPROTO_TCP) {
			return -1;
		}

		/* make sure its not a short packet */
		if (offsetof(struct tcphdr, ack_seq) + 4 + 
		    (ip->ihl*4) + sizeof(*eth) > ret) {
			return -1;
		}
		/* TCP */
		tcp = (struct tcphdr *)((ip->ihl*4) + (char *)ip);

		/* tell the caller which one we've found */
		src->ip.sin_family      = AF_INET;
		src->ip.sin_addr.s_addr = ip->saddr;
		src->ip.sin_port        = tcp->source;
		dst->ip.sin_family      = AF_INET;
		dst->ip.sin_addr.s_addr = ip->daddr;
		dst->ip.sin_port        = tcp->dest;
		*ack_seq                = tcp->ack_seq;
		*seq                    = tcp->seq;

		return 0;
	} else if (ntohs(eth->ether_type) == ETHERTYPE_IP6) {
		/* IP6 */
		ip6 = (struct ip6_hdr *)(eth+1);

		/* we only want TCP */
		if (ip6->ip6_nxt != IPPROTO_TCP) {
			return -1;
		}

		/* TCP */
		tcp = (struct tcphdr *)(ip6+1);

		/* tell the caller which one we've found */
		src->ip6.sin6_family = AF_INET6;
		src->ip6.sin6_port   = tcp->source;
		src->ip6.sin6_addr   = ip6->ip6_src;

		dst->ip6.sin6_family = AF_INET6;
		dst->ip6.sin6_port   = tcp->dest;
		dst->ip6.sin6_addr   = ip6->ip6_dst;

		*ack_seq             = tcp->ack_seq;
		*seq                 = tcp->seq;

		return 0;
	}

	return -1;
}


bool ctdb_sys_check_iface_exists(const char *iface)
{
	int s;
	struct ifreq ifr;

	s = socket(PF_PACKET, SOCK_RAW, 0);
	if (s == -1){
		/* We dont know if the interface exists, so assume yes */
		DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket\n"));
		return true;
	}

	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0 && errno == ENODEV) {
		DEBUG(DEBUG_CRIT,(__location__ " interface '%s' not found\n", iface));
		close(s);
		return false;
	}
	close(s);
	
	return true;
}

int ctdb_get_peer_pid(const int fd, pid_t *peer_pid)
{
	struct ucred cr;
	socklen_t crl = sizeof(struct ucred);
	int ret;
	if ((ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crl) == 0)) {
		*peer_pid = cr.pid;
	}
	return ret;
}

/*
 * Find the process name from process ID
 */
char *ctdb_get_process_name(pid_t pid)
{
	char path[32];
	char buf[PATH_MAX];
	char *ptr;
	int n;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	n = readlink(path, buf, sizeof(buf)-1);
	if (n < 0) {
		return NULL;
	}

	/* Remove any extra fields */
	buf[n] = '\0';
	ptr = strtok(buf, " ");
	return (ptr == NULL ? ptr : strdup(ptr));
}

/*
 * Set process name
 */
int ctdb_set_process_name(const char *name)
{
	char procname[16];

	strncpy(procname, name, 15);
	procname[15] = '\0';
	return prctl(PR_SET_NAME, (unsigned long)procname, 0, 0, 0);
}

/*
 * Parsing a line from /proc/locks,
 */
static bool parse_proc_locks_line(char *line, pid_t *pid,
				  struct ctdb_lock_info *curlock)
{
	char *ptr, *saveptr;

	/* output of /proc/locks
	 *
	 * lock assigned
	 * 1: POSIX  ADVISORY  WRITE 25945 fd:00:6424820 212 212
	 *
	 * lock waiting
	 * 1: -> POSIX  ADVISORY  WRITE 25946 fd:00:6424820 212 212
	 */

	/* Id: */
	ptr = strtok_r(line, " ", &saveptr);
	if (ptr == NULL) return false;

	/* -> */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	if (strcmp(ptr, "->") == 0) {
		curlock->waiting = true;
		ptr = strtok_r(NULL, " ", &saveptr);
	} else {
		curlock->waiting = false;
	}

	/* POSIX */
	if (ptr == NULL || strcmp(ptr, "POSIX") != 0) {
		return false;
	}

	/* ADVISORY */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;

	/* WRITE */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	if (strcmp(ptr, "READ") == 0) {
		curlock->read_only = true;
	} else if (strcmp(ptr, "WRITE") == 0) {
		curlock->read_only = false;
	} else {
		return false;
	}

	/* PID */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	*pid = atoi(ptr);

	/* MAJOR:MINOR:INODE */
	ptr = strtok_r(NULL, " :", &saveptr);
	if (ptr == NULL) return false;
	ptr = strtok_r(NULL, " :", &saveptr);
	if (ptr == NULL) return false;
	ptr = strtok_r(NULL, " :", &saveptr);
	if (ptr == NULL) return false;
	curlock->inode = atol(ptr);

	/* START OFFSET */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	curlock->start = atol(ptr);

	/* END OFFSET */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	if (strncmp(ptr, "EOF", 3) == 0) {
		curlock->end = (off_t)-1;
	} else {
		curlock->end = atol(ptr);
	}

	return true;
}

/*
 * Find information of lock being waited on for given process ID
 */
bool ctdb_get_lock_info(pid_t req_pid, struct ctdb_lock_info *lock_info)
{
	FILE *fp;
	struct ctdb_lock_info curlock;
	pid_t pid;
	char buf[1024];
	bool status = false;

	if ((fp = fopen("/proc/locks", "r")) == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to read locks information"));
		return false;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (! parse_proc_locks_line(buf, &pid, &curlock)) {
			continue;
		}
		if (pid == req_pid && curlock.waiting) {
			*lock_info = curlock;
			status = true;
			break;
		}
	}
	fclose(fp);

	return status;
}

/*
 * Find process ID which holds an overlapping byte lock for required
 * inode and byte range.
 */
bool ctdb_get_blocker_pid(struct ctdb_lock_info *reqlock, pid_t *blocker_pid)
{
	FILE *fp;
	struct ctdb_lock_info curlock;
	pid_t pid;
	char buf[1024];
	bool status = false;

	if ((fp = fopen("/proc/locks", "r")) == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to read locks information"));
		return false;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (! parse_proc_locks_line(buf, &pid, &curlock)) {
			continue;
		}

		if (curlock.waiting) {
			continue;
		}

		if (curlock.inode != reqlock->inode) {
			continue;
		}

		if (curlock.start > reqlock->end ||
		    curlock.end < reqlock->start) {
			/* Outside the required range */
			continue;
		}
		*blocker_pid = pid;
		status = true;
		break;
	}
	fclose(fp);

	return status;
}
