/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   return a list of network interfaces
   Copyright (C) Andrew Tridgell 1998
   
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


/* working out the interfaces for a OS is an incredibly non-portable
   thing. We have several possible implementations below, and autoconf
   tries each of them to see what works

   Note that this file does _not_ include includes.h. That is so this code
   can be called directly from the autoconf tests. That also means
   this code cannot use any of the normal Samba debug stuff or defines.
   This is standalone code.

*/

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif


#ifdef HAVE_IFACE_IFCONF

/* this works for Linux 2.2, Solaris 2.5, SunOS4 and IRIX 6.4 */

/****************************************************************************
  get the netmask address for a local interface
****************************************************************************/
int get_interfaces(void (*fn)(char *iname, struct in_addr ip, struct in_addr mask))
{  
	struct ifconf ifc;
	char buff[2048];
	int fd, i, n;
	struct ifreq *ifr=NULL;
	int total = 0;
	struct in_addr ipaddr;
	struct in_addr nmask;
	char *iname;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}
  
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;

	if (ioctl(fd, SIOCGIFCONF, &ifc) != 0) {
		close(fd);
		return -1;
	} 

	ifr = ifc.ifc_req;
  
	n = ifc.ifc_len / sizeof(struct ifreq);

	/* Loop through interfaces, looking for given IP address */
	for (i=n-1;i>=0;i--) {
		if (ioctl(fd, SIOCGIFADDR, &ifr[i]) != 0) {
			continue;
		}

		iname = ifr[i].ifr_name;
		ipaddr = (*(struct sockaddr_in *)&ifr[i].ifr_addr).sin_addr;

		if (ioctl(fd, SIOCGIFFLAGS, &ifr[i]) != 0) {
			continue;
		}  

		if (!(ifr[i].ifr_flags & IFF_UP)) {
			continue;
		}

		if (ioctl(fd, SIOCGIFNETMASK, &ifr[i]) != 0) {
			continue;
		}  

		nmask = ((struct sockaddr_in *)&ifr[i].ifr_addr)->sin_addr;

		fn(iname, ipaddr, nmask);
		total++;
	}

	close(fd);

	return total;
}  

#elif defined(HAVE_IFACE_IFREQ)

#ifndef I_STR
#include <sys/stropts.h>
#endif

/****************************************************************************
this should cover most of the rest of systems
****************************************************************************/
int get_interfaces(void (*fn)(char *iname, struct in_addr ip, struct in_addr mask))
{
	struct ifreq ifreq;
	struct strioctl strioctl;
	struct ifconf *ifc;
	char buff[2048];
	int fd, i, n;
	struct ifreq *ifr=NULL;
	int total = 0;
	struct in_addr ipaddr;
	struct in_addr nmask;
	char *iname;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}
  
	ifc = (struct ifconf *)buff;
	ifc->ifc_len = BUFSIZ - sizeof(struct ifconf);
	strioctl.ic_cmd = SIOCGIFCONF;
	strioctl.ic_dp  = (char *)ifc;
	strioctl.ic_len = sizeof(buff);
	if (ioctl(fd, I_STR, &strioctl) < 0) {
		close(fd);
		return -1;
	} 
	
	ifr = (struct ifreq *)ifc->ifc_req;  

	/* Loop through interfaces */
	n = ifc->ifc_len / sizeof(struct ifreq);

	for (i = 0; i<n; i++, ifr++) {
		ifreq = *ifr;
  
		strioctl.ic_cmd = SIOCGIFADDR;
		strioctl.ic_dp  = (char *)&ifreq;
		strioctl.ic_len = sizeof(struct ifreq);
		if (ioctl(fd, I_STR, &strioctl) != 0) {
			continue;
		}

		ipaddr = (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr;
		iname = ifr[i].ifr_name;

		strioctl.ic_cmd = SIOCGIFFLAGS;
		strioctl.ic_dp  = (char *)&ifreq;
		strioctl.ic_len = sizeof(struct ifreq);
		if (ioctl(fd, I_STR, &strioctl) != 0) {
			continue;
		}
		
		if (!(ifreq.ifr_flags & IFF_UP)) {
			continue;
		}

		strioctl.ic_cmd = SIOCGIFNETMASK;
		strioctl.ic_dp  = (char *)&ifreq;
		strioctl.ic_len = sizeof(struct ifreq);
		if (ioctl(fd, I_STR, &strioctl) != 0) {
			continue;
		}

		nmask = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr;
		
		fn(iname, ipaddr, nmask);

		total++;
	}

	close(fd);

	return total;
}

#elif defined(HAVE_IFACE_AIX)

/****************************************************************************
this one is for AIX (tested on 4.2)
****************************************************************************/
int get_interfaces(void (*fn)(char *iname, struct in_addr ip, struct in_addr mask))
{
	char buff[2048];
	int fd, i;
	struct ifconf ifc;
	struct ifreq *ifr=NULL;
	struct in_addr ipaddr;
	struct in_addr lastip;
	struct in_addr nmask;
	char *iname;
	int total = 0;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}


	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;

	if (ioctl(fd, SIOCGIFCONF, &ifc) != 0) {
		close(fd);
		return -1;
	}

	ifr = ifc.ifc_req;

	/* Loop through interfaces */
	i = ifc.ifc_len;

	while (i > 0) {
		unsigned inc;

		inc = ifr->ifr_addr.sa_len;

		if (ioctl(fd, SIOCGIFADDR, ifr) != 0) {
			goto next;
		}

		ipaddr = (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr;
		iname = ifr->ifr_name;

		if (ioctl(fd, SIOCGIFFLAGS, ifr) != 0) {
			goto next;
		}

		if (!(ifr->ifr_flags & IFF_UP)) {
			goto next;
		}

		if (ioctl(fd, SIOCGIFNETMASK, ifr) != 0) {
			goto next;
		}

		nmask = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;


		if (total && memcmp(&lastip, &ipaddr, sizeof(lastip)) == 0) {
			/* we don't want duplicates */
			goto next;
		}
		
		lastip = ipaddr;

		fn(iname, ipaddr, nmask);

		total++;

	next:
		/*
		 * Patch from Archie Cobbs (archie@whistle.com).  The
		 * addresses in the SIOCGIFCONF interface list have a
		 * minimum size. Usually this doesn't matter, but if
		 * your machine has tunnel interfaces, etc. that have
		 * a zero length "link address", this does matter.  */

		if (inc < sizeof(ifr->ifr_addr))
			inc = sizeof(ifr->ifr_addr);
		inc += IFNAMSIZ;

		ifr = (struct ifreq*) (((char*) ifr) + inc);
		i -= inc;
	}
  

	close(fd);
	return total;
}

#else /* a dummy version */
int get_interfaces()
{
	return 0;
}
#endif


#ifdef AUTOCONF
/* this is the autoconf driver to test get_interfaces() */

static void callback(char *iname, struct in_addr ip, struct in_addr nmask)
{
	printf("%-10s ", iname);
	printf("%s/", inet_ntoa(ip));
	printf("%s\n", inet_ntoa(nmask));
}

 main()
{
	int total = get_interfaces(callback);
	printf("got %d interfaces\n", total);
	if (total == 0) exit(1);
	return 0;
}
#endif
