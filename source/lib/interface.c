/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   multiple interface handling
   Copyright (C) Andrew Tridgell 1992-1995
   
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

extern int DEBUGLEVEL;

struct in_addr ipzero;
struct in_addr ipgrp;
static struct in_addr default_ip;
static struct in_addr default_bcast;
static struct in_addr default_nmask;
static BOOL got_ip=False;
static BOOL got_bcast=False;
static BOOL got_nmask=False;

struct interface *local_interfaces  = NULL;

struct interface *last_iface;

/****************************************************************************
calculate the default netmask for an address
****************************************************************************/
static void default_netmask(struct in_addr *inm, struct in_addr *iad)
{
  uint32 ad = ntohl(iad->s_addr);
  uint32 nm;
  /*
  ** Guess a netmask based on the class of the IP address given.
  */
  if ( (ad & 0x80000000) == 0 ) {
    /* class A address */
    nm = 0xFF000000;
  } else if ( (ad & 0xC0000000) == 0x80000000 ) {
    /* class B address */
    nm = 0xFFFF0000;
  } else if ( (ad & 0xE0000000) == 0xC0000000 ) {
    /* class C address */
    nm = 0xFFFFFF00;
  }  else {
    /* class D or E; netmask doesn't make much sense - guess 4 bits */
    nm =  0xFFFFFFF0;
  }
  inm->s_addr = htonl(nm);
}


/****************************************************************************
  get the broadcast address for our address 
(troyer@saifr00.ateng.az.honeywell.com)
****************************************************************************/
static void get_broadcast(struct in_addr *if_ipaddr,
			  struct in_addr *if_bcast,
			  struct in_addr *if_nmask)
{  
  BOOL found = False;
#ifndef NO_GET_BROADCAST
  int sock = -1;               /* AF_INET raw socket desc */
  char buff[1024];
  struct ifreq *ifr=NULL;
  int i;

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
#endif

  /* get a default netmask and broadcast */
  default_netmask(if_nmask, if_ipaddr);

#ifndef NO_GET_BROADCAST  
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
	if (if_ipaddr->s_addr ==
	    ((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr.s_addr) {
	  found = True;
	  break;
	}
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
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
	found = True;
	break;
      }
    }
  }
#elif defined(__FreeBSD__) || defined(NETBSD)
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
    DEBUG(0,("SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = ifc.ifc_req;
    /* Loop through interfaces, looking for given IP address */
    i = ifc.ifc_len;
    while (i > 0) {
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
	found = True;
	break;
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
#ifdef BSDI
      if (ioctl(sock, SIOCGIFADDR, ifr) < 0) break;
#endif
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
	found = True;
	break;
      }
    }
  }
#endif
  
  if (!found) {
    DEBUG(0,("No interface found for address %s\n", inet_ntoa(*if_ipaddr)));
  } else {
    /* Get the netmask address from the kernel */
#ifdef USE_IFREQ
    ifreq = *ifr;
  
    strioctl.ic_cmd = SIOCGIFNETMASK;
    strioctl.ic_dp  = (char *)&ifreq;
    strioctl.ic_len = sizeof(struct ifreq);
    if (ioctl(sock, I_STR, &strioctl) < 0)
      DEBUG(0,("Failed I_STR/SIOCGIFNETMASK: %s\n", strerror(errno)));
    else
      *if_nmask = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr;
#else
    if (ioctl(sock, SIOCGIFNETMASK, ifr) < 0)
      DEBUG(0,("SIOCGIFNETMASK failed\n"));
    else
      *if_nmask = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;
#endif

    DEBUG(4,("Netmask for %s = %s\n", ifr->ifr_name,
	     inet_ntoa(*if_nmask)));
  }

  /* Close up shop */
  (void) close(sock);
  
#endif

  /* sanity check on the netmask */
  {
    uint32 nm = ntohl(if_nmask->s_addr);
    if ((nm >> 24) != 0xFF) {
      DEBUG(0,("Impossible netmask %s - using defaults\n",inet_ntoa(*if_nmask)));
      default_netmask(if_nmask, if_ipaddr);      
    }
  }

  /* derive the broadcast assuming a 1's broadcast, as this is what
     all MS operating systems do, we have to comply even if the unix
     box is setup differently */
  {
    uint32 ad = ntohl(if_ipaddr->s_addr);
    uint32 nm = ntohl(if_nmask->s_addr);
    uint32 bc = (ad & nm) | (0xffffffff & ~nm);
    if_bcast->s_addr = htonl(bc);
  }
  
  DEBUG(4,("Derived broadcast address %s\n", inet_ntoa(*if_bcast)));
}  /* get_broadcast */



/****************************************************************************
load a list of network interfaces
****************************************************************************/
static void interpret_interfaces(char *s, struct interface **interfaces,
		char *description)
{
  char *ptr = s;
  fstring token;
  struct interface *iface;
  struct in_addr ip;

  ipzero = *interpret_addr2("0.0.0.0");
  ipgrp = *interpret_addr2("255.255.255.255");

  while (next_token(&ptr,token,NULL)) {
    /* parse it into an IP address/netmasklength pair */
    char *p = strchr(token,'/');
    if (p) *p = 0;

    ip = *interpret_addr2(token);

    /* maybe we already have it listed */
    {
      struct interface *i;
      for (i=(*interfaces);i;i=i->next)
	if (ip_equal(ip,i->ip)) break;
      if (i) continue;
    }

    iface = (struct interface *)malloc(sizeof(*iface));
    if (!iface) return;

    iface->ip = ip;

    if (p) {
      if (strlen(p+1)>2)
	iface->nmask = *interpret_addr2(p+1);
      else
	iface->nmask.s_addr = htonl(~((1<<(32-atoi(p+1)))-1));
    } else {
      default_netmask(&iface->nmask,&iface->ip);
    }
    iface->bcast.s_addr = iface->ip.s_addr | ~iface->nmask.s_addr;
    iface->next = NULL;

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

  if (*interfaces) return;

  /* setup a default interface */
  iface = (struct interface *)malloc(sizeof(*iface));
  if (!iface) return;

  iface->next = NULL;

  if (got_ip) {
    iface->ip = default_ip;
  } else {
    get_myname(NULL,&iface->ip);
  }

  if (got_bcast) {
    iface->bcast = default_bcast;
  } else {
    get_broadcast(&iface->ip,&iface->bcast,&iface->nmask);
  }

  if (got_nmask) {
    iface->nmask = default_nmask;
    iface->bcast.s_addr = iface->ip.s_addr | ~iface->nmask.s_addr;
  }

  if (iface->bcast.s_addr != (iface->ip.s_addr | ~iface->nmask.s_addr)) {
    DEBUG(2,("Warning: inconsistant interface %s\n",inet_ntoa(iface->ip)));
  }

  iface->next = NULL;
  (*interfaces) = last_iface = iface;

  DEBUG(1,("Added interface ip=%s ",inet_ntoa(iface->ip)));
  DEBUG(1,("bcast=%s ",inet_ntoa(iface->bcast)));
  DEBUG(1,("nmask=%s\n",inet_ntoa(iface->nmask)));	     
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
  if (ip) {
    got_ip = True;
    default_ip = *interpret_addr2(ip);
  }

  if (bcast) {
    got_bcast = True;
    default_bcast = *interpret_addr2(bcast);
  }

  if (nmask) {
    got_nmask = True;
    default_nmask = *interpret_addr2(nmask);
  }
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



