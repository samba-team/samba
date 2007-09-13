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
#include "lib/events/events.h"
#include <netinet/if_ether.h>
#include <net/if_arp.h>



/*
  send gratuitous arp reply after we have taken over an ip address

  saddr is the address we are trying to claim
  iface is the interface name we will be using to claim the address
 */
int ctdb_sys_send_arp(const struct sockaddr_in *saddr, const char *iface)
{
	int s, ret;
	struct sockaddr sa;
	struct ether_header *eh;
	struct arphdr *ah;
	struct ifreq if_hwaddr;
	unsigned char buffer[64]; /*minimum eth frame size */
	char *ptr;

	ZERO_STRUCT(sa);

	/* for now, we only handle AF_INET addresses */
	if (saddr->sin_family != AF_INET) {
		DEBUG(0,(__location__ " not an ipv4 address (family is %u)\n", saddr->sin_family));
		return -1;
	}

	s = socket(AF_INET, SOCK_PACKET, htons(ETHERTYPE_ARP));
	if (s == -1){
		DEBUG(0,(__location__ " failed to open raw socket\n"));
		return -1;
	}

	/* get the mac address */
	strcpy(if_hwaddr.ifr_name, iface);
	ret = ioctl(s, SIOCGIFHWADDR, &if_hwaddr);
	if ( ret < 0 ) {
		close(s);
		DEBUG(0,(__location__ " ioctl failed\n"));
		return -1;
	}
	if (ARPHRD_LOOPBACK == if_hwaddr.ifr_hwaddr.sa_family) {
		DEBUG(3,("Ignoring loopback arp request\n"));
		close(s);
		return 0;
	}
	if (if_hwaddr.ifr_hwaddr.sa_family != AF_LOCAL) {
		close(s);
		errno = EINVAL;
		DEBUG(0,(__location__ " not an ethernet address family (0x%x)\n",
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
	memcpy(ptr, &saddr->sin_addr, 4);	  
	ptr+=4;
	memset(ptr, 0, ETH_ALEN); 
	ptr+=ETH_ALEN;
	memcpy(ptr, &saddr->sin_addr, 4);	  
	ptr+=4;

	strncpy(sa.sa_data, iface, sizeof(sa.sa_data));
	ret = sendto(s, buffer, 64, 0, &sa, sizeof(sa));
	if (ret < 0 ){
		close(s);
		DEBUG(0,(__location__ " failed sendto\n"));
		return -1;
	}

	/* send unsolicited arp reply broadcast */
	ah->ar_op  = htons(ARPOP_REPLY);
	ptr = (char *)&ah[1];
	memcpy(ptr, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
	ptr+=ETH_ALEN;
	memcpy(ptr, &saddr->sin_addr, 4);	  
	ptr+=4;
	memcpy(ptr, if_hwaddr.ifr_hwaddr.sa_data, ETH_ALEN);
	ptr+=ETH_ALEN;
	memcpy(ptr, &saddr->sin_addr, 4);	  
	ptr+=4;

	strncpy(sa.sa_data, iface, sizeof(sa.sa_data));
	ret = sendto(s, buffer, 64, 0, &sa, sizeof(sa));
	if (ret < 0 ){
		DEBUG(0,(__location__ " failed sendto\n"));
		return -1;
	}

	close(s);
	return 0;
}


/*
  uint16 checksum for n bytes
 */
static uint32_t uint16_checksum(uint16_t *data, size_t n)
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
int ctdb_sys_send_tcp(int s,
		      const struct sockaddr_in *dest, 
		      const struct sockaddr_in *src,
		      uint32_t seq, uint32_t ack, int rst)
{
	int ret;
	struct {
		struct iphdr ip;
		struct tcphdr tcp;
	} pkt;

	/* for now, we only handle AF_INET addresses */
	if (src->sin_family != AF_INET || dest->sin_family != AF_INET) {
		DEBUG(0,(__location__ " not an ipv4 address\n"));
		return -1;
	}

	ZERO_STRUCT(pkt);
	pkt.ip.version  = 4;
	pkt.ip.ihl      = sizeof(pkt.ip)/4;
	pkt.ip.tot_len  = htons(sizeof(pkt));
	pkt.ip.ttl      = 255;
	pkt.ip.protocol = IPPROTO_TCP;
	pkt.ip.saddr    = src->sin_addr.s_addr;
	pkt.ip.daddr    = dest->sin_addr.s_addr;
	pkt.ip.check    = 0;

	pkt.tcp.source   = src->sin_port;
	pkt.tcp.dest     = dest->sin_port;
	pkt.tcp.seq      = seq;
	pkt.tcp.ack_seq  = ack;
	pkt.tcp.ack      = 1;
	if (rst) {
		pkt.tcp.rst      = 1;
	}
	pkt.tcp.doff     = sizeof(pkt.tcp)/4;
	pkt.tcp.window   = htons(1234); /* this makes it easier to spot in a sniffer */
	pkt.tcp.check    = tcp_checksum((uint16_t *)&pkt.tcp, sizeof(pkt.tcp), &pkt.ip);

	ret = sendto(s, &pkt, sizeof(pkt), 0, dest, sizeof(*dest));
	if (ret != sizeof(pkt)) {
		DEBUG(0,(__location__ " failed sendto (%s)\n", strerror(errno)));
		return -1;
	}

	return 0;
}


/*
  see if we currently have an interface with the given IP

  we try to bind to it, and if that fails then we don't have that IP
  on an interface

  ifname, if non-NULL, will return the name of the interface this ip is tied to
 */
bool ctdb_sys_have_ip(struct sockaddr_in ip)
{
	int s;
	int ret;

	ip.sin_port = 0;
	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		return false;
	}
	ret = bind(s, (struct sockaddr *)&ip, sizeof(ip));

	close(s);
	return ret == 0;
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
		DEBUG(0,(__location__ " failed to open raw socket\n"));
		return -1;
	}

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
   This function is used to open a raw socket to send tickles from
 */
int ctdb_sys_open_sending_socket(void)
{
	int s, ret;
	uint32_t one = 1;

	s = socket(AF_INET, SOCK_RAW, htons(IPPROTO_RAW));
	if (s == -1) {
		DEBUG(0,(__location__ " failed to open raw socket (%s)\n",
			 strerror(errno)));
		return -1;
	}

	ret = setsockopt(s, SOL_IP, IP_HDRINCL, &one, sizeof(one));
	if (ret != 0) {
		DEBUG(0,(__location__ " failed to setup IP headers (%s)\n",
			 strerror(errno)));
		close(s);
		return -1;
	}

	set_nonblocking(s);
	set_close_on_exec(s);

	return s;
}

/*
  called when the raw socket becomes readable
 */
int ctdb_sys_read_tcp_packet(int s, void *private_data, 
			struct sockaddr_in *src, struct sockaddr_in *dst,
			uint32_t *ack_seq, uint32_t *seq)
{
	int ret;
#define RCVPKTSIZE 100
	char pkt[RCVPKTSIZE];
	struct ether_header *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;

	ret = recv(s, pkt, RCVPKTSIZE, MSG_TRUNC);
	if (ret < sizeof(*eth)+sizeof(*ip)) {
		return -1;
	}

	/* Ethernet */
	eth = (struct ether_header *)pkt;

	/* We only want IP packets */
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
		return -1;
	}
	
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
	src->sin_addr.s_addr = ip->saddr;
	src->sin_port        = tcp->source;
	dst->sin_addr.s_addr = ip->daddr;
	dst->sin_port        = tcp->dest;
	*ack_seq             = tcp->ack_seq;
	*seq                 = tcp->seq;

	return 0;
}


