/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   multiple interface handling
   Copyright (C) Andrew Tridgell 1992-1997
   
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

#include <assert.h>		/* added by philipp */

extern int DEBUGLEVEL;

struct in_addr ipzero;
struct in_addr wins_ip;

struct interface *local_interfaces  = NULL;
struct interface *present_interfaces = NULL;

struct interface *last_iface;

static void get_interfaces()
{  
  int sock = -1;               /* AF_INET raw socket desc */
  char buff[1024];
  struct ifreq *ifr=NULL, ifr2;
  int i;
  struct interface *iface, *last_iface = NULL;

#ifndef	ifr_mtu
#define	ifr_mtu	ifr_metric
#endif

#if defined(EVEREST)
  int n_interfaces;
  struct ifconf ifc;
  struct ifreq  *ifreqs;
#elif defined(USE_IFREQ)
  struct ifreq ifreq;
  struct strioctl strioctl;
  struct ifconf *ifc;
#else
  struct ifconf ifc;
#endif

  if (present_interfaces) return;	/* already initialized */

  /* Create a socket to the INET kernel. */
#if USE_SOCKRAW
  if ((sock = socket(AF_INET, SOCK_RAW, PF_INET )) < 0)
#else
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0 )) < 0)
#endif
      {
        DEBUG(0,( "Unable to open socket to get broadcast address\n"));
        return;
      }
  
  /* Get a list of the configured interfaces */
#ifdef EVEREST
  /* This is part of SCO Openserver 5: The ioctls are no longer part
     if the lower level STREAMS interface glue. They are now real
     ioctl calls */

  if (ioctl(sock, SIOCGIFANUM, &n_interfaces) < 0) {
    DEBUG(0,( "SIOCGIFANUM: %s\n", strerror(errno)));
  } else {
    DEBUG(0,( "number of interfaces returned is: %d\n", n_interfaces));

    ifc.ifc_len = sizeof(struct ifreq) * n_interfaces;
    ifc.ifc_buf = (caddr_t) alloca(ifc.ifc_len);

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
      DEBUG(0, ( "SIOCGIFCONF: %s\n", strerror(errno)));
    else {
      ifr = ifc.ifc_req;

      for (i = 0; i < n_interfaces; ++i) {
	ifr2 = ifr[i];
	if (ioctl(sock, SIOCGIFFLAGS, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFFLAGS failed\n"));

        if ((ifr2.ifr_flags & (IFF_RUNNING | IFF_LOOPBACK)) != IFF_RUNNING)
	  continue;

	iface = (struct interface *)malloc(sizeof(*iface));
	assert(iface != NULL);
	iface->next = NULL;
	iface->ip = ((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr;
	iface->name = strdup(ifr[i].ifr_name);
	iface->flags = ifr2.ifr_flags;

	/* complete with netmask and b'cast address */
	ifr2 = *ifr;
	if (ioctl(sock, SIOCGIFNETMASK, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFNETMASK failed\n"));
	else
	  iface->nmask = ((struct sockaddr_in *)&ifr2.ifr_addr)->sin_addr;
	if (ioctl(sock, SIOCGIFBRDADDR, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFBRDADDR failed\n"));
	else
	  iface->bcast = ((struct sockaddr_in *)&ifr2.ifr_addr)->sin_addr;
	if (ioctl(sock, SIOCGIFMTU, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFMTU failed\n"));
	else
	  iface->mtu = ifr2.ifr_mtu;

	DEBUG(4,("Netmask for %s = %s\n", iface->name, inet_ntoa(iface->nmask)));

        if (!present_interfaces)
	  present_interfaces = iface;
	else
	  last_iface->next = iface;
	last_iface = iface;
      }
    }
  }
#elif defined(USE_IFREQ)
  ifc = (struct ifconf *)buff;
  ifc->ifc_len = BUFSIZ - sizeof(struct ifconf);
  strioctl.ic_cmd = SIOCGIFCONF;
  strioctl.ic_dp  = (char *)ifc;
  strioctl.ic_len = sizeof(buff);
  if (ioctl(sock, I_STR, &strioctl) < 0) {
    DEBUG(0,( "I_STR/SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = (struct ifreq *)ifc->ifc_req;  

    /* Loop through interfaces, looking for given IP address */
    for (i = ifc->ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
      ifr2 = *ifr;
      if (ioctl(sock, SIOCGIFFLAGS, &ifr2) < 0)
	DEBUG(0,("SIOCGIFFLAGS failed\n"));

      if ((ifr2.ifr_flags & (IFF_RUNNING | IFF_LOOPBACK)) == IFF_RUNNING) {

	iface = (struct interface *)malloc(sizeof(*iface));
	assert(iface != NULL);
	iface->next = NULL;
	iface->ip = (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr;
	iface->name = strdup(ifr->ifr_name);
	iface->flags = ifr2.ifr_flags;

	/* complete with netmask and b'cast address */
	ifr2 = *ifr;
	strioctl.ic_cmd = SIOCGIFNETMASK;
	strioctl.ic_dp  = (char *)&ifr2;
	strioctl.ic_len = sizeof(struct ifr2);
	if (ioctl(sock, I_STR, &strioctl) < 0)
	  DEBUG(0,("Failed I_STR/SIOCGIFNETMASK: %s\n", strerror(errno)));
	else
	  iface->nmask = ((struct sockaddr_in *)&ifr2.ifr_addr)->sin_addr;
	strioctl.ic_cmd = SIOCGIFBRDADDR;
	if (ioctl(sock, I_STR, &strioctl) < 0)
	  DEBUG(0,("SIOCGIFBRDADDR failed\n"));
	else
	  iface->bcast = ((struct sockaddr_in *)&ifr2.ifr_addr)->sin_addr;
	strioctl.ic_cmd = SIOCGIFMTU;
	if (ioctl(sock, I_STR, &strioctl) < 0)
	  DEBUG(0,("SIOCGIFMTU failed\n"));
	else
	  iface->mtu = ifr2.ifr_mtu;

	DEBUG(4,("Netmask for %s = %s\n", iface->name, inet_ntoa(iface->nmask)));

	if (!present_interfaces)
	  present_interfaces = iface;
	else
	  last_iface->next = iface;
	last_iface = iface;
      }
    }
  }
#elif defined(__FreeBSD__) || defined(NETBSD) || defined(AMIGA) || defined(_AIX41)
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
    DEBUG(0,("SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = ifc.ifc_req;
    /* Loop through interfaces, looking for given IP address */
    i = ifc.ifc_len;
    while (i > 0) {
      ifr2 = *ifr;
      if (ioctl(sock, SIOCGIFFLAGS, &ifr2) < 0)
	DEBUG(0,("SIOCGIFFLAGS failed\n"));

      if ((ifr2.ifr_flags & (IFF_RUNNING | IFF_LOOPBACK)) == IFF_RUNNING) {
	iface = (struct interface *)malloc(sizeof(*iface));
	assert(iface != NULL);
	iface->next = NULL;
	iface->ip = (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr;
	iface->name = strdup(ifr->ifr_name);
	iface->flags = ifr2.ifr_flags;

	/* complete with netmask and b'cast address */
	ifr2 = *ifr;
	if (ioctl(sock, SIOCGIFNETMASK, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFNETMASK failed\n"));
	else
	  iface->nmask = (*(struct sockaddr_in *)&ifr2.ifr_addr).sin_addr;
	if (ioctl(sock, SIOCGIFBRDADDR, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFBRDADDR failed\n"));
	else
	  iface->bcast = (*(struct sockaddr_in *)&ifr2.ifr_addr).sin_addr;
	if (ioctl(sock, SIOCGIFMTU, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFMTU failed\n"));
	else
	  iface->mtu = ifr2.ifr_mtu;

	DEBUG(4,("Netmask for %s = %s\n", iface->name, inet_ntoa(iface->nmask)));

	if (!present_interfaces)
	  present_interfaces = iface;
	else
	  last_iface->next = iface;
	last_iface = iface;
      }

      i -= ifr->ifr_addr.sa_len + IFNAMSIZ;
      ifr = (struct ifreq*) ((char*) ifr + ifr->ifr_addr.sa_len + IFNAMSIZ);
    }
  }
#else
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
    DEBUG(0,("SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = ifc.ifc_req;
  
    /* Loop through interfaces, looking for given IP address */
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
      ifr2 = *ifr;
      if (ioctl(sock, SIOCGIFFLAGS, &ifr2) < 0)
	DEBUG(0,("SIOCGIFFLAGS failed\n"));

      if ((ifr2.ifr_flags & (IFF_RUNNING | IFF_LOOPBACK)) == IFF_RUNNING) {
#ifdef BSDI
	if (ioctl(sock, SIOCGIFADDR, ifr) < 0) break;
#endif

	iface = (struct interface *)malloc(sizeof(*iface));
	assert(iface != NULL);
	iface->next = NULL;
	iface->ip = (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr;
	iface->name = strdup(ifr->ifr_name);
	iface->flags = ifr2.ifr_flags;

	/* complete with netmask and b'cast address */
	ifr2 = *ifr;
	if (ioctl(sock, SIOCGIFNETMASK, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFNETMASK failed\n"));
	else
	  iface->nmask = (*(struct sockaddr_in *)&ifr2.ifr_addr).sin_addr;
	if (ioctl(sock, SIOCGIFBRDADDR, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFBRDADDR failed\n"));
	else
	  iface->bcast = (*(struct sockaddr_in *)&ifr2.ifr_addr).sin_addr;
	if (ioctl(sock, SIOCGIFMTU, &ifr2) < 0)
	  DEBUG(0,("SIOCGIFMTU failed\n"));
	else
	  iface->mtu = ifr2.ifr_mtu;

	DEBUG(4,("Netmask for %s = %s\n", iface->name, inet_ntoa(iface->nmask)));

	if (!present_interfaces)
	  present_interfaces = iface;
	else
	  last_iface->next = iface;
	last_iface = iface;
      }
    }
  }
#endif

  /* Close up shop */
  (void) close(sock);

}  /* get_interfaces */


/****************************************************************************
load a list of network interfaces
****************************************************************************/
static void interpret_interfaces(char *s, struct interface **interfaces,
		char *description)
{
  char *ptr = s;
  fstring token;
  struct interface *iface, *i;
  BOOL seenALL = False;

  ipzero = *interpret_addr2("0.0.0.0");
  wins_ip = *interpret_addr2("255.255.255.255");

  get_interfaces();

  while (next_token(&ptr,token,NULL)) {

    if (strcasecmp(token, "ALL")) {
      if (*interfaces) {
	DEBUG(0, ("Error: interface name \"ALL\" must occur alone\n"));
	/* should do something here ... */
      }

      /* should we copy the list, or just point at it? */
      for (i = present_interfaces; i; i = i->next) {
	iface = (struct interface *)malloc(sizeof(*iface));
	if (!iface) return;

	*iface = *i;
	iface->next = NULL;

	if (!(*interfaces))
	  (*interfaces) = iface;
	else
	  last_iface->next = iface;
	last_iface = iface;
      }

      seenALL = True;
      continue;
    } else if (seenALL) {
      DEBUG(0, ("Error: can't mix interface \"ALL\" with other interface namess\n"));
      continue;
    }

    /* maybe we already have it listed */
    for (i=(*interfaces);i;i=i->next)
      if (strcasecmp(token,i->name)) break;
    if (i) continue;

    iface = (struct interface *)malloc(sizeof(*iface));
    if (!iface) return;

    /* make sure name is known */
    for (i=present_interfaces;i;i=i->next)
      if (strcasecmp(token,i->name)) break;

    if (!i) {
      DEBUG(0, ("Warning: unknown interface \"%s\" specified\n", token));
      continue;
    }

    *iface = *i;
    iface->next = NULL;
    if (iface->bcast.s_addr != (iface->ip.s_addr | ~iface->nmask.s_addr)) {
      DEBUG(0, ("Warning: overriding b'cast address %s on interface %s\n",
	    inet_ntoa(iface->bcast), iface->name));
      iface->bcast.s_addr = iface->ip.s_addr | ~iface->nmask.s_addr;
    }

    if (!(*interfaces)) {
      (*interfaces) = iface;
    } else {
      last_iface->next = iface;
    }
    last_iface = iface;
    DEBUG(1,("Added %s ip=%s ",description,inet_ntoa(iface->ip)));
    DEBUG(1,("bcast=%s ",inet_ntoa(iface->bcast)));
    DEBUG(1,("nmask=%s\n",inet_ntoa(iface->nmask)));	     
  }

  if (! *interfaces)
    DEBUG(0,("Error: no interfaces specified.\n"));
}


/****************************************************************************
load the remote and local interfaces
****************************************************************************/
void load_interfaces(void)
{
  /* add the machine's interfaces to local interface structure*/
  interpret_interfaces(lp_interfaces(), &local_interfaces,"interface");
}


/****************************************************************************
  override the defaults
  **************************************************************************/
void iface_set_default(char *ip,char *bcast,char *nmask)
{
  DEBUG(0, ("iface_set_default: function deprecated.\n"));
  exit(1);
}


/****************************************************************************
  check if an IP is one of mine
  **************************************************************************/
BOOL ismyip(struct in_addr ip)
{
  struct interface *i;
  for (i=local_interfaces;i;i=i->next)
    if (ip_equal(i->ip,ip)) return True;
  return False;
}

/****************************************************************************
  check if a bcast is one of mine
  **************************************************************************/
BOOL ismybcast(struct in_addr bcast)
{
  struct interface *i;
  for (i=local_interfaces;i;i=i->next)
    if (ip_equal(i->bcast,bcast)) return True;
  return False;
}

/****************************************************************************
  how many interfaces do we have
  **************************************************************************/
int iface_count(void)
{
  int ret = 0;
  struct interface *i;

  for (i=local_interfaces;i;i=i->next)
    ret++;
  return ret;
}

/****************************************************************************
  return IP of the Nth interface
  **************************************************************************/
struct in_addr *iface_n_ip(int n)
{
  struct interface *i;
  
  for (i=local_interfaces;i && n;i=i->next)
    n--;

  if (i) return &i->ip;
  return NULL;
}

static struct interface *iface_find(struct in_addr ip)
{
  struct interface *i;
  if (zero_ip(ip)) return local_interfaces;

  for (i=local_interfaces;i;i=i->next)
    if (same_net(i->ip,ip,i->nmask)) return i;

  return local_interfaces;
}

/* these 3 functions return the ip/bcast/nmask for the interface
   most appropriate for the given ip address */

struct in_addr *iface_bcast(struct in_addr ip)
{
  return(&iface_find(ip)->bcast);
}

struct in_addr *iface_nmask(struct in_addr ip)
{
  return(&iface_find(ip)->nmask);
}

struct in_addr *iface_ip(struct in_addr ip)
{
  return(&iface_find(ip)->ip);
}

