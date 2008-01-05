/*
   Unix SMB/CIFS implementation.
   return a list of network interfaces
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Jeremy Allison 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


/* working out the interfaces for a OS is an incredibly non-portable
   thing. We have several possible implementations below, and autoconf
   tries each of them to see what works

   Note that this file does _not_ include includes.h. That is so this code
   can be called directly from the autoconf tests. That also means
   this code cannot use any of the normal Samba debug stuff or defines.
   This is standalone code.

*/

#ifndef AUTOCONF_TEST
#include "config.h"
#endif

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifndef SIOCGIFCONF
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef __COMPAR_FN_T
#define QSORT_CAST (__compar_fn_t)
#endif

#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#define SOCKET_WRAPPER_NOT_REPLACE
#include "interfaces.h"
#include "lib/replace/replace.h"

/****************************************************************************
 Utility functions.
****************************************************************************/

/****************************************************************************
 Create a struct sockaddr_storage with the netmask bits set to 1.
****************************************************************************/

bool make_netmask(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			unsigned long masklen)
{
	*pss_out = *pss_in;
	/* Now apply masklen bits of mask. */
#if defined(HAVE_IPV6)
	if (pss_in->ss_family == AF_INET6) {
		char *p = (char *)&((struct sockaddr_in6 *)pss_out)->sin6_addr;
		unsigned int i;

		if (masklen > 128) {
			return false;
		}
		for (i = 0; masklen >= 8; masklen -= 8, i++) {
			*p++ = 0xff;
		}
		/* Deal with the partial byte. */
		*p++ &= (0xff & ~(0xff>>masklen));
		i++;
		for (;i < sizeof(struct in6_addr); i++) {
			*p++ = '\0';
		}
		return true;
	}
#endif
	if (pss_in->ss_family == AF_INET) {
		if (masklen > 32) {
			return false;
		}
		((struct sockaddr_in *)pss_out)->sin_addr.s_addr =
			htonl(((0xFFFFFFFFL >> masklen) ^ 0xFFFFFFFFL));
		return true;
	}
	return false;
}

/****************************************************************************
 Create a struct sockaddr_storage set to the broadcast or network adress from
 an incoming sockaddr_storage.
****************************************************************************/

static void make_bcast_or_net(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			const struct sockaddr_storage *nmask,
			bool make_bcast_p)
{
	unsigned int i = 0, len = 0;
	char *pmask = NULL;
	char *p = NULL;
	*pss_out = *pss_in;

	/* Set all zero netmask bits to 1. */
#if defined(HAVE_IPV6)
	if (pss_in->ss_family == AF_INET6) {
		p = (char *)&((struct sockaddr_in6 *)pss_out)->sin6_addr;
		pmask = (char *)&((struct sockaddr_in6 *)nmask)->sin6_addr;
		len = 16;
	}
#endif
	if (pss_in->ss_family == AF_INET) {
		p = (char *)&((struct sockaddr_in *)pss_out)->sin_addr;
		pmask = (char *)&((struct sockaddr_in *)nmask)->sin_addr;
		len = 4;
	}

	for (i = 0; i < len; i++, p++, pmask++) {
		if (make_bcast_p) {
			*p = (*p & *pmask) | (*pmask ^ 0xff);
		} else {
			/* make_net */
			*p = (*p & *pmask);
		}
	}
}

void make_bcast(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			const struct sockaddr_storage *nmask)
{
	make_bcast_or_net(pss_out, pss_in, nmask, true);
}

void make_net(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			const struct sockaddr_storage *nmask)
{
	make_bcast_or_net(pss_out, pss_in, nmask, false);
}

/****************************************************************************
 Try the "standard" getifaddrs/freeifaddrs interfaces.
 Also gets IPv6 interfaces.
****************************************************************************/

#if HAVE_IFACE_GETIFADDRS
/****************************************************************************
 Get the netmask address for a local interface.
****************************************************************************/

static int _get_interfaces(struct iface_struct *ifaces, int max_interfaces)
{
	struct ifaddrs *iflist = NULL;
	struct ifaddrs *ifptr = NULL;
	int total = 0;
	size_t copy_size;

	if (getifaddrs(&iflist) < 0) {
		return -1;
	}

	/* Loop through interfaces, looking for given IP address */
	for (ifptr = iflist, total = 0;
			ifptr != NULL && total < max_interfaces;
			ifptr = ifptr->ifa_next) {

		memset(&ifaces[total], '\0', sizeof(ifaces[total]));

		copy_size = sizeof(struct sockaddr_in);

		if (!ifptr->ifa_addr || !ifptr->ifa_netmask) {
			continue;
		}

		ifaces[total].flags = ifptr->ifa_flags;

		/* Check the interface is up. */
		if (!(ifaces[total].flags & IFF_UP)) {
			continue;
		}

#if defined(HAVE_IPV6)
		if (ifptr->ifa_addr->sa_family == AF_INET6) {
			copy_size = sizeof(struct sockaddr_in6);
		}
#endif

		memcpy(&ifaces[total].ip, ifptr->ifa_addr, copy_size);
		memcpy(&ifaces[total].netmask, ifptr->ifa_netmask, copy_size);

		if (ifaces[total].flags & (IFF_BROADCAST|IFF_LOOPBACK)) {
			if (ifptr->ifa_broadaddr) {
				memcpy(&ifaces[total].bcast,
					ifptr->ifa_broadaddr,
					copy_size);
			} else {
				/* For some reason ifptr->ifa_broadaddr
				 * is null. Make one from ifa_addr and
				 * ifa_netmask.
				 */
				make_bcast(&ifaces[total].bcast,
					&ifaces[total].ip,
					&ifaces[total].netmask);
			}
		} else if ((ifaces[total].flags & IFF_POINTOPOINT) &&
			       ifptr->ifa_dstaddr ) {
			memcpy(&ifaces[total].bcast,
				ifptr->ifa_dstaddr,
				copy_size);
		} else {
			continue;
		}

		strlcpy(ifaces[total].name, ifptr->ifa_name,
			sizeof(ifaces[total].name));
		total++;
	}

	freeifaddrs(iflist);

	return total;
}

#define _FOUND_IFACE_ANY
#endif /* HAVE_IFACE_GETIFADDRS */
#if HAVE_IFACE_IFCONF

/* this works for Linux 2.2, Solaris 2.5, SunOS4, HPUX 10.20, OSF1
   V4.0, Ultrix 4.4, SCO Unix 3.2, IRIX 6.4 and FreeBSD 3.2.

   It probably also works on any BSD style system.  */

/****************************************************************************
 Get the netmask address for a local interface.
****************************************************************************/

static int _get_interfaces(struct iface_struct *ifaces, int max_interfaces)
{
	struct ifconf ifc;
	char buff[8192];
	int fd, i, n;
	struct ifreq *ifr=NULL;
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

	n = ifc.ifc_len / sizeof(struct ifreq);

	/* Loop through interfaces, looking for given IP address */
	for (i=n-1;i>=0 && total < max_interfaces;i--) {

		memset(&ifaces[total], '\0', sizeof(ifaces[total]));

		/* Check the interface is up. */
		if (ioctl(fd, SIOCGIFFLAGS, &ifr[i]) != 0) {
			continue;
		}

		ifaces[total].flags = ifr[i].ifr_flags;

		if (!(ifaces[total].flags & IFF_UP)) {
			continue;
		}

		if (ioctl(fd, SIOCGIFADDR, &ifr[i]) != 0) {
			continue;
		}

		strlcpy(ifaces[total].name, ifr[i].ifr_name,
			sizeof(ifaces[total].name));

		memcpy(&ifaces[total].ip, &ifr[i].ifr_addr,
				sizeof(struct sockaddr_in));

		if (ioctl(fd, SIOCGIFNETMASK, &ifr[i]) != 0) {
			continue;
		}

		memcpy(&ifaces[total].netmask, &ifr[i].ifr_netmask,
				sizeof(struct sockaddr_in));

		if (ifaces[total].flags & IFF_BROADCAST) {
			if (ioctl(fd, SIOCGIFBRDADDR, &ifr[i]) != 0) {
				continue;
			}
			memcpy(&ifaces[total].bcast, &ifr[i].ifr_broadaddr,
				sizeof(struct sockaddr_in));
		} else if (ifaces[total].flags & IFF_POINTOPOINT) {
			if (ioctl(fd, SIOCGIFDSTADDR, &ifr[i]) != 0) {
				continue;
			}
			memcpy(&ifaces[total].bcast, &ifr[i].ifr_dstaddr,
				sizeof(struct sockaddr_in));
		} else {
			continue;
		}

		total++;
	}

	close(fd);

	return total;
}

#define _FOUND_IFACE_ANY
#endif /* HAVE_IFACE_IFCONF */
#ifdef HAVE_IFACE_IFREQ

#ifndef I_STR
#include <sys/stropts.h>
#endif

/****************************************************************************
 This should cover most of the streams based systems.
 Thanks to Andrej.Borsenkow@mow.siemens.ru for several ideas in this code.
****************************************************************************/

static int _get_interfaces(struct iface_struct *ifaces, int max_interfaces)
{
	struct ifreq ifreq;
	struct strioctl strioctl;
	char buff[8192];
	int fd, i, n;
	struct ifreq *ifr=NULL;
	int total = 0;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}

	strioctl.ic_cmd = SIOCGIFCONF;
	strioctl.ic_dp  = buff;
	strioctl.ic_len = sizeof(buff);
	if (ioctl(fd, I_STR, &strioctl) < 0) {
		close(fd);
		return -1;
	}

	/* we can ignore the possible sizeof(int) here as the resulting
	   number of interface structures won't change */
	n = strioctl.ic_len / sizeof(struct ifreq);

	/* we will assume that the kernel returns the length as an int
           at the start of the buffer if the offered size is a
           multiple of the structure size plus an int */
	if (n*sizeof(struct ifreq) + sizeof(int) == strioctl.ic_len) {
		ifr = (struct ifreq *)(buff + sizeof(int));
	} else {
		ifr = (struct ifreq *)buff;
	}

	/* Loop through interfaces */

	for (i = 0; i<n && total < max_interfaces; i++) {

		memset(&ifaces[total], '\0', sizeof(ifaces[total]));

		ifreq = ifr[i];

		strioctl.ic_cmd = SIOCGIFFLAGS;
		strioctl.ic_dp  = (char *)&ifreq;
		strioctl.ic_len = sizeof(struct ifreq);
		if (ioctl(fd, I_STR, &strioctl) != 0) {
			continue;
		}

		ifaces[total].flags = ifreq.ifr_flags;

		if (!(ifaces[total].flags & IFF_UP)) {
			continue;
		}

		strioctl.ic_cmd = SIOCGIFADDR;
		strioctl.ic_dp  = (char *)&ifreq;
		strioctl.ic_len = sizeof(struct ifreq);
		if (ioctl(fd, I_STR, &strioctl) != 0) {
			continue;
		}

		strlcpy(ifaces[total].name,
				ifreq.ifr_name,
				sizeof(ifaces[total].name));

		memcpy(&ifaces[total].ip, &ifreq.ifr_addr,
				sizeof(struct sockaddr_in));

		strioctl.ic_cmd = SIOCGIFNETMASK;
		strioctl.ic_dp  = (char *)&ifreq;
		strioctl.ic_len = sizeof(struct ifreq);
		if (ioctl(fd, I_STR, &strioctl) != 0) {
			continue;
		}

		memcpy(&ifaces[total].netmask, &ifreq.ifr_addr,
				sizeof(struct sockaddr_in));

		if (ifaces[total].flags & IFF_BROADCAST) {
			strioctl.ic_cmd = SIOCGIFBRDADDR;
			strioctl.ic_dp  = (char *)&ifreq;
			strioctl.ic_len = sizeof(struct ifreq);
			if (ioctl(fd, I_STR, &strioctl) != 0) {
				continue;
			}
			memcpy(&ifaces[total].bcast, &ifreq.ifr_broadaddr,
				sizeof(struct sockaddr_in));
		} else if (ifaces[total].flags & IFF_POINTOPOINT) {
			strioctl.ic_cmd = SIOCGIFDSTADDR;
			strioctl.ic_dp  = (char *)&ifreq;
			strioctl.ic_len = sizeof(struct ifreq);
			if (ioctl(fd, I_STR, &strioctl) != 0) {
				continue;
			}
			memcpy(&ifaces[total].bcast, &ifreq.ifr_dstaddr,
				sizeof(struct sockaddr_in));
		} else {
			continue;
		}

		total++;
	}

	close(fd);

	return total;
}

#define _FOUND_IFACE_ANY
#endif /* HAVE_IFACE_IFREQ */
#ifdef HAVE_IFACE_AIX

/****************************************************************************
 This one is for AIX (tested on 4.2).
****************************************************************************/

static int _get_interfaces(struct iface_struct *ifaces, int max_interfaces)
{
	char buff[8192];
	int fd, i;
	struct ifconf ifc;
	struct ifreq *ifr=NULL;
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

	while (i > 0 && total < max_interfaces) {
		uint_t inc;

		memset(&ifaces[total], '\0', sizeof(ifaces[total]));

		inc = ifr->ifr_addr.sa_len;

		if (ioctl(fd, SIOCGIFFLAGS, ifr) != 0) {
			goto next;
		}

		ifaces[total].flags = ifr->ifr_flags;

		if (!(ifaces[total].flags & IFF_UP)) {
			goto next;
		}

		if (ioctl(fd, SIOCGIFADDR, ifr) != 0) {
			goto next;
		}

		memcpy(&ifaces[total].ip, &ifr->ifr_addr,
				sizeof(struct sockaddr_in));

		strlcpy(ifaces[total].name, ifr->ifr_name,
			sizeof(ifaces[total].name));

		if (ioctl(fd, SIOCGIFNETMASK, ifr) != 0) {
			goto next;
		}

		memcpy(&ifaces[total].netmask, &ifr->ifr_addr,
				sizeof(struct sockaddr_in));

		if (ifaces[total].flags & IFF_BROADCAST) {
			if (ioctl(fd, SIOCGIFBRDADDR, ifr) != 0) {
				goto next;
			}
			memcpy(&ifaces[total].bcast, &ifr->ifr_broadaddr,
				sizeof(struct sockaddr_in));
		} else if (ifaces[total].flags & IFF_POINTOPOINT) {
			if (ioctl(fd, SIOCGIFDSTADDR, ifr) != 0) {
				goto next;
			}
			memcpy(&ifaces[total].bcast, &ifr->ifr_dstaddr,
				sizeof(struct sockaddr_in));
		} else {
			goto next;
		}


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

#define _FOUND_IFACE_ANY
#endif /* HAVE_IFACE_AIX */
#ifndef _FOUND_IFACE_ANY
static int _get_interfaces(struct iface_struct *ifaces, int max_interfaces)
{
	return -1;
}
#endif


static int iface_comp(struct iface_struct *i1, struct iface_struct *i2)
{
	int r;

#if defined(HAVE_IPV6)
	/*
	 * If we have IPv6 - sort these interfaces lower
	 * than any IPv4 ones.
	 */
	if (i1->ip.ss_family == AF_INET6 &&
			i2->ip.ss_family == AF_INET) {
		return -1;
	} else if (i1->ip.ss_family == AF_INET &&
			i2->ip.ss_family == AF_INET6) {
		return 1;
	}

	if (i1->ip.ss_family == AF_INET6) {
		struct sockaddr_in6 *s1 = (struct sockaddr_in6 *)&i1->ip;
		struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&i2->ip;

		r = memcmp(&s1->sin6_addr,
				&s2->sin6_addr,
				sizeof(struct in6_addr));
		if (r) {
			return r;
		}

		s1 = (struct sockaddr_in6 *)&i1->netmask;
		s2 = (struct sockaddr_in6 *)&i2->netmask;

		r = memcmp(&s1->sin6_addr,
				&s2->sin6_addr,
				sizeof(struct in6_addr));
		if (r) {
			return r;
		}
	}
#endif

	/* AIX uses __ss_family instead of ss_family inside of
	   sockaddr_storage. Instead of trying to figure out which field to
	   use, we can just cast it to a sockaddr.
	 */

	if (((struct sockaddr *)&i1->ip)->sa_family == AF_INET) {
		struct sockaddr_in *s1 = (struct sockaddr_in *)&i1->ip;
		struct sockaddr_in *s2 = (struct sockaddr_in *)&i2->ip;

		r = ntohl(s1->sin_addr.s_addr) -
			ntohl(s2->sin_addr.s_addr);
		if (r) {
			return r;
		}

		s1 = (struct sockaddr_in *)&i1->netmask;
		s2 = (struct sockaddr_in *)&i2->netmask;

		return ntohl(s1->sin_addr.s_addr) -
			ntohl(s2->sin_addr.s_addr);
	}
	return 0;
}

int get_interfaces(struct iface_struct *ifaces, int max_interfaces);
/* this wrapper is used to remove duplicates from the interface list generated
   above */
int get_interfaces(struct iface_struct *ifaces, int max_interfaces)
{
	int total, i, j;

	total = _get_interfaces(ifaces, max_interfaces);
	if (total <= 0) return total;

	/* now we need to remove duplicates */
	qsort(ifaces, total, sizeof(ifaces[0]), QSORT_CAST iface_comp);

	for (i=1;i<total;) {
		if (iface_comp(&ifaces[i-1], &ifaces[i]) == 0) {
			for (j=i-1;j<total-1;j++) {
				ifaces[j] = ifaces[j+1];
			}
			total--;
		} else {
			i++;
		}
	}

	return total;
}


#ifdef AUTOCONF_TEST
/* this is the autoconf driver to test get_interfaces() */

static socklen_t calc_sa_size(struct sockaddr *psa)
{
	socklen_t sl = sizeof(struct sockaddr_in);
#if defined(HAVE_IPV6)
	if (psa->sa_family == AF_INET6) {
		sl = sizeof(struct sockaddr_in6);
	}
#endif
	return sl;
}

 int main()
{
	struct iface_struct ifaces[MAX_INTERFACES];
	int total = get_interfaces(ifaces, MAX_INTERFACES);
	int i;

	printf("got %d interfaces:\n", total);
	if (total <= 0) {
		exit(1);
	}

	for (i=0;i<total;i++) {
		char addr[INET6_ADDRSTRLEN];
		int ret;
		printf("%-10s ", ifaces[i].name);
		addr[0] = '\0';
		ret = getnameinfo((struct sockaddr *)&ifaces[i].ip,
				calc_sa_size(&ifaces[i].ip),
				addr, sizeof(addr),
				NULL, 0, NI_NUMERICHOST);
		printf("IP=%s ", addr);
		addr[0] = '\0';
		ret = getnameinfo((struct sockaddr *)&ifaces[i].netmask,
				calc_sa_size(&ifaces[i].netmask),
				addr, sizeof(addr),
				NULL, 0, NI_NUMERICHOST);
		printf("NETMASK=%s ", addr);
		addr[0] = '\0';
		ret = getnameinfo((struct sockaddr *)&ifaces[i].bcast,
				calc_sa_size(&ifaces[i].bcast),
				addr, sizeof(addr),
				NULL, 0, NI_NUMERICHOST);
		printf("BCAST=%s\n", addr);
	}
	return 0;
}
#endif
