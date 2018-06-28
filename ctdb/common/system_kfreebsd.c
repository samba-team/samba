/* 
   ctdb system specific code to manage raw sockets on linux

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Marc Dequènes (Duck) 2009

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


  This file is a copy of 'common/system_linux.c' adapted for Hurd^W kFreeBSD
  needs, and inspired by 'common/system_aix.c' for the pcap usage.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"

#include "lib/util/debug.h"
#include "lib/util/blocking.h"

#include "protocol/protocol.h"

#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <pcap.h>

#include "common/logging.h"
#include "common/system.h"
#include "common/system_socket.h"

/* 
   This function is used to open a raw socket to capture from
 */
int ctdb_sys_open_capture_socket(const char *iface, void **private_data)
{
	pcap_t *pt;

	pt=pcap_open_live(iface, 100, 0, 0, NULL);
	if (pt == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to open capture device %s\n", iface));
		return -1;
	}
	*((pcap_t **)private_data) = pt;

	return pcap_fileno(pt);
}

/* This function is used to close the capture socket
 */
int ctdb_sys_close_capture_socket(void *private_data)
{
	pcap_t *pt = (pcap_t *)private_data;
	pcap_close(pt);
	return 0;
}


/*
  called when the raw socket becomes readable
 */
int ctdb_sys_read_tcp_packet(int s, void *private_data,
			     ctdb_sock_addr *src, ctdb_sock_addr *dst,
			     uint32_t *ack_seq, uint32_t *seq,
			     int *rst, uint16_t *window)
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

	ZERO_STRUCTP(src);
	ZERO_STRUCTP(dst);

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
		if (window != NULL) {
			*window = tcp->window;
		}
		if (rst != NULL) {
			*rst = tcp->rst;
		}

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
		if (window != NULL) {
			*window = tcp->window;
		}
		if (rst != NULL) {
			*rst = tcp->rst;
		}

		return 0;
	}

	return -1;
}
