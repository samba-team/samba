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

#include "ctdb_private.h"

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
  see if we currently have an interface with the given IP

  we try to bind to it, and if that fails then we don't have that IP
  on an interface
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


/* find which interface an ip address is currently assigned to */
char *ctdb_sys_find_ifname(ctdb_sock_addr *addr)
{
	int s;
	int size;
	struct ifconf ifc;
	char *ptr;

	s = socket(AF_INET, SOCK_RAW, htons(IPPROTO_RAW));
	if (s == -1) {
		DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket (%s)\n",
			 strerror(errno)));
		return NULL;
	}


	size = sizeof(struct ifreq);
	ifc.ifc_buf = NULL;
	ifc.ifc_len = size;

	while(ifc.ifc_len > (size - sizeof(struct ifreq))) {
		size *= 2;

		free(ifc.ifc_buf);	
		ifc.ifc_len = size;
		ifc.ifc_buf = malloc(size);
		memset(ifc.ifc_buf, 0, size);
		if (ioctl(s, SIOCGIFCONF, (caddr_t)&ifc) < 0) {
			DEBUG(DEBUG_CRIT,("Failed to read ifc buffer from socket\n"));
			free(ifc.ifc_buf);	
			close(s);
			return NULL;
		}
	}

	for (ptr =(char *)ifc.ifc_buf; ptr < ((char *)ifc.ifc_buf) + ifc.ifc_len; ) {
		char *ifname;
		struct ifreq *ifr;

		ifr = (struct ifreq *)ptr;

#ifdef HAVE_SOCKADDR_LEN
		if (ifr->ifr_addr.sa_len > sizeof(struct sockaddr)) {
			ptr += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
		} else {
			ptr += sizeof(ifr->ifr_name) + sizeof(struct sockaddr);
		}
#else
		ptr += sizeof(struct ifreq);
#endif

		if (ifr->ifr_addr.sa_family != addr->sa.sa_family) {
			continue;
		}

		switch (addr->sa.sa_family) {
		case AF_INET:


			if (memcmp(&addr->ip.sin_addr, &((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr, sizeof(addr->ip.sin_addr))) {
				continue;
			}
			break;
		case AF_INET6:
			if (memcmp(&addr->ip6.sin6_addr, &((struct sockaddr_in6 *)&ifr->ifr_addr)->sin6_addr, sizeof(addr->ip6.sin6_addr))) {
				continue;
			}
			break;
		}

		ifname = strdup(ifr->ifr_name);
		free(ifc.ifc_buf);	
		close(s);
		return ifname;
	}


	free(ifc.ifc_buf);	
	close(s);

	return NULL;
}
