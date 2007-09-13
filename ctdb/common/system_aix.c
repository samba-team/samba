/* 
   ctdb system specific code to manage raw sockets on aix

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
#include <netinet/if_ether.h>
#include "../include/ctdb_private.h"
#include <sys/ndd_var.h>
#include <sys/kinfo.h>
#include <pcap.h>




/* This function is used to open a raw socket to send tickles from
 */
int ctdb_sys_open_sending_socket(void)
{
	int s, ret;
	uint32_t one = 1;

	s = socket(AF_INET, SOCK_RAW, htons(IPPROTO_RAW));
	if (s == -1) {
		DEBUG(0,(" failed to open raw socket (%s)\n",
			 strerror(errno)));
		return -1;
	}

	ret = setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	if (ret != 0) {
		DEBUG(0,(" failed to setup IP headers (%s)\n",
			 strerror(errno)));
		close(s);
		return -1;
	}

	set_nonblocking(s);
	set_close_on_exec(s);

	return s;
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
static uint16_t tcp_checksum(uint16_t *data, size_t n, struct ip *ip)
{
	uint32_t sum = uint16_checksum(data, n);
	uint16_t sum2;

	sum += uint16_checksum((uint16_t *)&ip->ip_src, sizeof(ip->ip_src));
	sum += uint16_checksum((uint16_t *)&ip->ip_dst, sizeof(ip->ip_dst));
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
		struct ip ip;
		struct tcphdr tcp;
	} pkt;

	/* for now, we only handle AF_INET addresses */
	if (src->sin_family != AF_INET || dest->sin_family != AF_INET) {
		DEBUG(0,(__location__ " not an ipv4 address\n"));
		return -1;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.ip.ip_v     = 4;
	pkt.ip.ip_hl    = sizeof(pkt.ip)/4;
	pkt.ip.ip_len   = htons(sizeof(pkt));
	pkt.ip.ip_ttl   = 255;
	pkt.ip.ip_p     = IPPROTO_TCP;
	pkt.ip.ip_src.s_addr   = src->sin_addr.s_addr;
	pkt.ip.ip_dst.s_addr   = dest->sin_addr.s_addr;
	pkt.ip.ip_sum   = 0;

	pkt.tcp.th_sport   = src->sin_port;
	pkt.tcp.th_dport     = dest->sin_port;
	pkt.tcp.th_seq      = seq;
	pkt.tcp.th_ack    = ack;
	pkt.tcp.th_flags  = TH_ACK;
	if (rst) {
		pkt.tcp.th_flags      = TH_RST;
	}
	pkt.tcp.th_off    = sizeof(pkt.tcp)/4;
	pkt.tcp.th_win   = htons(1234);
	pkt.tcp.th_sum    = tcp_checksum((uint16_t *)&pkt.tcp, sizeof(pkt.tcp), &pkt.ip);

	ret = sendto(s, &pkt, sizeof(pkt), 0, (struct sockaddr *)dest, sizeof(*dest));
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




/* This function is used to open a raw socket to capture from
 */
int ctdb_sys_open_capture_socket(const char *iface, void **private_data)
{
	pcap_t *pt;

	pt=pcap_open_live(iface, 100, 0, 0, NULL);
	if (pt == NULL) {
		DEBUG(0,("Failed to open capture device %s\n", iface));
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
  send gratuitous arp reply after we have taken over an ip address

  saddr is the address we are trying to claim
  iface is the interface name we will be using to claim the address
 */
int ctdb_sys_send_arp(const struct sockaddr_in *saddr, const char *iface)
{
	/* We dont do grat arp on aix yet */
	return 0;
}



/*
  get ethernet MAC address on AIX
 */
static int aix_get_mac_addr(const char *device_name, uint8_t mac[6])
{
        size_t ksize;
        struct kinfo_ndd *ndd;
	int count, i;

        ksize = getkerninfo(KINFO_NDD, 0, 0, 0);
        if (ksize == 0) {
		errno = ENOSYS;
		return -1;
        }

        ndd = (struct kinfo_ndd *)malloc(ksize);
        if (ndd == NULL) {
		errno = ENOMEM;
		return -1;
        }

        if (getkerninfo(KINFO_NDD, ndd, &ksize, 0) == -1) {
		errno = ENOSYS;
		return -1;
        }

	count= ksize/sizeof(struct kinfo_ndd);
	for (i=0;i<count;i++) {
		if ( (ndd[i].ndd_type != NDD_ETHER) 
		&&   (ndd[i].ndd_type != NDD_ISO88023) ) {
			continue;
		}
		if (ndd[i].ndd_addrlen != 6) {
			continue;
		}
		if (!(ndd[i].ndd_flags&NDD_UP)) {
			continue;
		}
		if ( strcmp(device_name, ndd[i].ndd_name)
		&&   strcmp(device_name, ndd[i].ndd_alias) ) {
			continue;
		}
                memcpy(mac, ndd[i].ndd_addr, 6);
		free(ndd);
		return 0;
        }
	free(ndd);
	errno = ENOENT;
	return -1;
}

int ctdb_sys_read_tcp_packet(int s, void *private_data, 
			struct sockaddr_in *src, struct sockaddr_in *dst,
			uint32_t *ack_seq, uint32_t *seq)
{
	int ret;
	struct ether_header *eth;
	struct ip *ip;
	struct tcphdr *tcp;
	struct ctdb_killtcp_connection *conn;
	struct pcap_pkthdr pkthdr;
	const u_char *buffer;
	pcap_t *pt = (pcap_t *)private_data;

	buffer=pcap_next(pt, &pkthdr);
	if (buffer==NULL) {
		return -1;
	}

	/* Ethernet */
	eth = (struct ether_header *)buffer;

	/* We are only interested in IP packets */
	if (eth->ether_type != htons(ETHERTYPE_IP)) {
		return -1;
	}

	/* IP */
	ip = (struct ip *)(eth+1);

	/* We only want IPv4 packets */
	if (ip->ip_v != 4) {
		return -1;
	}
	/* Dont look at fragments */
	if ((ntohs(ip->ip_off)&0x1fff) != 0) {
		return -1;
	}
	/* we only want TCP */
	if (ip->ip_p != IPPROTO_TCP) {
		return -1;
	}

	/* make sure its not a short packet */
	if (offsetof(struct tcphdr, th_ack) + 4 + 
	    (ip->ip_hl*4) > ret) {
		return -1;
	}
	/* TCP */
	tcp = (struct tcphdr *)((ip->ip_hl*4) + (char *)ip);
	
	/* tell the caller which one we've found */
	src->sin_addr.s_addr = ip->ip_src.s_addr;
	src->sin_port        = tcp->th_sport;
	dst->sin_addr.s_addr = ip->ip_dst.s_addr;
	dst->sin_port        = tcp->th_dport;
	*ack_seq             = tcp->th_ack;
	*seq                 = tcp->th_seq;

	return 0;
}



