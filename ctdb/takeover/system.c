/* 
   ctdb recovery code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include <net/ethernet.h>
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


	/* for now, we only handle AF_INET addresses */
	if (saddr->sin_family != AF_INET) {
		DEBUG(0,(__location__ " not an ipv4 address\n"));
		return -1;
	}

	s = socket(AF_INET, SOCK_PACKET, htons(ETHERTYPE_ARP));
	if (s == -1){
		DEBUG(0,(__location__ "failed to open raw socket\n"));
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
	if (if_hwaddr.ifr_hwaddr.sa_family != AF_LOCAL) {
		close(s);
		DEBUG(0,(__location__ " not an ethernet address\n"));
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
