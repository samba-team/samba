/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   code to query kernel netmask
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


/* working out the netmask for an interface is an incredibly non-portable
   thing. We have several possible implementations below, and autoconf
   tries each of them to see what works 

   Note that this file does _not_ include includes.h. That is so this code
   can be called directly from the autoconf tests. That also means
   this code cannot use any of the normal Samba debug stuff or defines.
   This is standalone code.

*/

#ifndef AUTOCONF
#include "config.h"
#endif

#ifdef HAVE_NETMASK_IFCONF

#ifdef RELIANTUNIX
/*
 * <unistd.h> must be included first to compile this file on ReliantUNIX
 */
#include <unistd.h>
#endif

#include <stdio.h>
#include <unistd.h>
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

/*
 * Prototype for gcc in fussy mode.
 */

int get_netmask(struct in_addr *ipaddr, struct in_addr *nmask);

/****************************************************************************
  get the netmask address for a local interface
****************************************************************************/
int get_netmask(struct in_addr *ipaddr, struct in_addr *nmask)
{  
	struct ifconf ifc;
	char buff[2048];
	int fd, i, n;
	struct ifreq *ifr=NULL;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
#ifdef DEBUG
		fprintf(stderr,"socket failed\n");
#endif
		return -1;
	}
  
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(fd, SIOCGIFCONF, &ifc) != 0) {
#ifdef DEBUG
		fprintf(stderr,"SIOCGIFCONF failed\n");
#endif
		close(fd);
		return -1;
	} 

	ifr = ifc.ifc_req;
  
	n = ifc.ifc_len / sizeof(struct ifreq);
	
#ifdef DEBUG
	fprintf(stderr,"%d interfaces - looking for %s\n", 
		n, inet_ntoa(*ipaddr));
#endif

	/* Loop through interfaces, looking for given IP address */
	for (i=n-1;i>=0;i--) {
		if (ioctl(fd, SIOCGIFADDR, &ifr[i]) != 0) {
#ifdef DEBUG
			fprintf(stderr,"SIOCGIFADDR failed\n");
#endif
			continue;
		}

#ifdef DEBUG
		fprintf(stderr,"interface %s\n", 
			inet_ntoa((*(struct sockaddr_in *)&ifr[i].ifr_addr).sin_addr));
#endif
		if (ipaddr->s_addr !=
		    (*(struct sockaddr_in *)&ifr[i].ifr_addr).sin_addr.s_addr) {
			continue;
		}

		if (ioctl(fd, SIOCGIFNETMASK, &ifr[i]) != 0) {
#ifdef DEBUG
			fprintf(stderr,"SIOCGIFNETMASK failed\n");
#endif
			close(fd);
			return -1;
		}  
		close(fd);
		(*nmask) = ((struct sockaddr_in *)&ifr[i].ifr_addr)->sin_addr;
#ifdef DEBUG
		fprintf(stderr,"netmask %s\n", inet_ntoa(*nmask));
#endif
		return 0;
	}

#ifdef DEBUG
	fprintf(stderr,"interface not found\n");
#endif

	close(fd);
	return -1;
}  

#elif defined(HAVE_NETMASK_IFREQ)

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

#ifndef I_STR
#include <sys/stropts.h>
#endif


/****************************************************************************
this should cover most of the rest of systems
****************************************************************************/
 int get_netmask(struct in_addr *ipaddr, struct in_addr *nmask)
{
	struct ifreq ifreq;
	struct strioctl strioctl;
	struct ifconf *ifc;
	char buff[2048];
	int fd, i, n;
	struct ifreq *ifr=NULL;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
#ifdef DEBUG
		fprintf(stderr,"socket failed\n");
#endif
		return -1;
	}
  
	ifc = (struct ifconf *)buff;
	ifc->ifc_len = BUFSIZ - sizeof(struct ifconf);
	strioctl.ic_cmd = SIOCGIFCONF;
	strioctl.ic_dp  = (char *)ifc;
	strioctl.ic_len = sizeof(buff);
	if (ioctl(fd, I_STR, &strioctl) < 0) {
#ifdef DEBUG
		fprintf(stderr,"SIOCGIFCONF failed\n");
#endif
		close(fd);
		return -1;
	} 
	
	ifr = (struct ifreq *)ifc->ifc_req;  

	/* Loop through interfaces, looking for given IP address */
	n = ifc->ifc_len / sizeof(struct ifreq);

	for (i = 0; i<n; i++, ifr++) {
#ifdef DEBUG
		fprintf(stderr,"interface %s\n", 
			inet_ntoa((*(struct sockaddr_in *)&ifr->ifr_addr).sin_addr.s_addr));
#endif
		if (ipaddr->s_addr ==
		    (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
			break;
		}
	}

#ifdef DEBUG
	if (i == n) {
		fprintf(stderr,"interface not found\n");
		close(fd);
		return -1;
	}
#endif

	ifreq = *ifr;
  
	strioctl.ic_cmd = SIOCGIFNETMASK;
	strioctl.ic_dp  = (char *)&ifreq;
	strioctl.ic_len = sizeof(struct ifreq);
	if (ioctl(fd, I_STR, &strioctl) != 0) {
#ifdef DEBUG
		fprintf(stderr,"Failed SIOCGIFNETMASK\n");
#endif
		close(fd);
		return -1;
	}

	close(fd);
	*nmask = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr;
#ifdef DEBUG
	fprintf(stderr,"netmask %s\n", inet_ntoa(*nmask));
#endif
	return 0;
}

#elif defined(HAVE_NETMASK_AIX)

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

/****************************************************************************
this one is for AIX
****************************************************************************/
 int get_netmask(struct in_addr *ipaddr, struct in_addr *nmask)
{
	char buff[2048];
	int fd, i;
	struct ifconf ifc;
	struct ifreq *ifr=NULL;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
#ifdef DEBUG
		fprintf(stderr,"socket failed\n");
#endif
		return -1;
	}


	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;

	if (ioctl(fd, SIOCGIFCONF, &ifc) != 0) {
#ifdef DEBUG
		fprintf(stderr,"SIOCGIFCONF failed\n");
#endif
		close(fd);
		return -1;
	}

	ifr = ifc.ifc_req;
	/* Loop through interfaces, looking for given IP address */
	i = ifc.ifc_len;
	while (i > 0) {
#ifdef DEBUG
		fprintf(stderr,"interface %s\n", 
			inet_ntoa((*(struct sockaddr_in *)&ifr->ifr_addr).sin_addr));
#endif
		if (ipaddr->s_addr ==
		    (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
			break;
		}
		i -= ifr->ifr_addr.sa_len + IFNAMSIZ;
		ifr = (struct ifreq*) ((char*) ifr + ifr->ifr_addr.sa_len + 
				       IFNAMSIZ);
	}
  

#ifdef DEBUG
	if (i <= 0) {
		fprintf(stderr,"interface not found\n");
		close(fd);
		return -1;
	}
#endif

	if (ioctl(fd, SIOCGIFNETMASK, ifr) != 0) {
#ifdef DEBUG
		fprintf(stderr,"SIOCGIFNETMASK failed\n");
#endif
		close(fd);
		return -1;
	}  

	close(fd);

	(*nmask) = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;
#ifdef DEBUG
	fprintf(stderr,"netmask %s\n", inet_ntoa(*nmask));
#endif
	return 0;
}

#else /* a dummy version */
struct in_addr; /* it may not have been declared before */
 int get_netmask(struct in_addr *ipaddr, struct in_addr *nmask)
{
	return -1;
}
#endif


#ifdef AUTOCONF
/* this is the autoconf driver to test get_netmask() */

 main()
{
	char buf[1024];
	struct hostent *hp;
	struct in_addr ip, nmask;

	if (gethostname(buf, sizeof(buf)-1) != 0) {
		fprintf(stderr,"gethostname failed\n");
		exit(1);
	}

	hp = gethostbyname(buf);

	if (!hp) {
		fprintf(stderr,"gethostbyname failed\n");
		exit(1);
	}

	memcpy((char *)&ip, (char *)hp->h_addr, hp->h_length);

	if (get_netmask(&ip, &nmask) == 0) exit(0);

	fprintf(stderr,"get_netmask failed\n");
	exit(1);
}
#endif
