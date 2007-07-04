/* 
   socketkiller   a tool to kill off established tcp connections

   Copyright (C) Ronnie Sahlberg  2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/network.h"
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"
#include <netinet/if_ether.h>

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
	sum += uint16_checksum((uint16_t *)&ip->saddr, sizeof(ip->saddr));
	sum += uint16_checksum((uint16_t *)&ip->daddr, sizeof(ip->daddr));
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

static int send_tcp(const struct sockaddr_in *dest, const struct sockaddr_in *src, uint32_t seq, uint32_t ack, int rst)
{
	int s, ret;
	uint32_t one = 1;
	struct {
		struct iphdr ip;
		struct tcphdr tcp;
	} pkt;


	/* for now, we only handle AF_INET addresses */
	if (src->sin_family != AF_INET || dest->sin_family != AF_INET) {
		DEBUG(0,(__location__ " not an ipv4 address\n"));
		return -1;
	}

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
	pkt.tcp.window   = htons(1234);
	pkt.tcp.check    = tcp_checksum((uint16_t *)&pkt.tcp, sizeof(pkt.tcp), &pkt.ip);

	ret = sendto(s, &pkt, sizeof(pkt), 0, dest, sizeof(*dest));
	if (ret != sizeof(pkt)) {
		DEBUG(0,(__location__ " failed sendto (%s)\n", strerror(errno)));
		close(s);
		return -1;
	}

	close(s);
	return 0;
}


static void usage(void)
{
	printf("Usage: socketkiller <SRCIP> <SRCPORT> <DSTIP> <DSTPORT>\n");
}

int main(int argc, char *argv[])
{
	struct sockaddr_in src,dst;

	if(argc!=5){
		usage();
		_exit(10);
	}
	int s, ret;
#define RCVPKTSIZE 100
	char pkt[RCVPKTSIZE];
	struct ether_header *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;

	src.sin_family=AF_INET;
	src.sin_port=htons(atoi(argv[2]));
	inet_aton(argv[1], &src.sin_addr);

	dst.sin_family=AF_INET;
	dst.sin_port=htons(atoi(argv[4]));
	inet_aton(argv[3], &dst.sin_addr);


	/* wait for up to 5 seconds before giving up */
	alarm(5);

	s=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

	send_tcp(&dst, &src, 0, 0, 0);

	while (1) {
		ret = recv(s, pkt, RCVPKTSIZE, MSG_TRUNC);
		if (ret<40) {
			continue;
		}

		/* Ethernet */
		eth = (struct ether_header *)pkt;
		/* We only want IP packets */
		if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
			continue;
		}
	
		/* IP */
		ip = (struct iphdr *)&pkt[14];
		/* We only want IPv4 packets */
		if (ip->version != 4) {
			continue;
		}
		/* Dont look at fragments */
		if ((ntohs(ip->frag_off)&0x1fff) != 0) {
			continue;
		}
		/* we only want TCP */
		if (ip->protocol != IPPROTO_TCP) {
			continue;
		}

		/* We only want packets sent from the guy we tickled */
		if (ip->saddr != dst.sin_addr.s_addr) {
			continue;
		}
		/* We only want packets sent to us */
		if (ip->daddr != src.sin_addr.s_addr) {
			continue;
		}

		/* TCP */
		tcp = (struct tcphdr *)&pkt[14+ip->ihl*4];
		/* We only want replies from the port we tickled */
		if (tcp->source != dst.sin_port) {
			continue;
		}
		if (tcp->dest != src.sin_port) {
			continue;
		}

		printf("sending a RESET to tear down the connection\n");
		send_tcp(&dst, &src, tcp->ack_seq, tcp->seq, 1);
		close(s);
		_exit(0);
	}

	close(s);
	return 1;
}
