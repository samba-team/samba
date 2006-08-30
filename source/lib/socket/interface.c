/* 
   Unix SMB/CIFS implementation.

   multiple interface handling

   Copyright (C) Andrew Tridgell 1992-2005
   
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
#include "system/network.h"
#include "lib/socket/netif.h"
#include "lib/util/dlinklist.h"

/** used for network interfaces */
struct interface {
	struct interface *next, *prev;
	struct ipv4_addr ip;
	struct ipv4_addr nmask;
	const char *ip_s;
	const char *bcast_s;
	const char *nmask_s;
};

static struct interface *local_interfaces;

#define ALLONES  ((uint32_t)0xFFFFFFFF)
/*
  address construction based on a patch from fred@datalync.com
*/
#define MKBCADDR(_IP, _NM) ((_IP & _NM) | (_NM ^ ALLONES))
#define MKNETADDR(_IP, _NM) (_IP & _NM)

static struct ipv4_addr tov4(struct in_addr in)
{
	struct ipv4_addr in2;
	in2.addr = in.s_addr;
	return in2;
}

/****************************************************************************
Try and find an interface that matches an ip. If we cannot, return NULL
  **************************************************************************/
static struct interface *iface_find(struct in_addr ip, BOOL CheckMask)
{
	struct interface *i;
	if (is_zero_ip(tov4(ip))) return local_interfaces;

	for (i=local_interfaces;i;i=i->next)
		if (CheckMask) {
			if (same_net(i->ip,tov4(ip),i->nmask)) return i;
		} else if (i->ip.addr == ip.s_addr) return i;

	return NULL;
}


/****************************************************************************
add an interface to the linked list of interfaces
****************************************************************************/
static void add_interface(struct in_addr ip, struct in_addr nmask)
{
	struct interface *iface;
	struct ipv4_addr bcast;
	if (iface_find(ip, False)) {
		DEBUG(3,("not adding duplicate interface %s\n",inet_ntoa(ip)));
		return;
	}

	iface = talloc(local_interfaces, struct interface);
	if (!iface) return;
	
	ZERO_STRUCTPN(iface);

	iface->ip = tov4(ip);
	iface->nmask = tov4(nmask);
	bcast.addr = MKBCADDR(iface->ip.addr, iface->nmask.addr);

	/* keep string versions too, to avoid people tripping over the implied
	   static in sys_inet_ntoa() */
	iface->ip_s = talloc_strdup(iface, sys_inet_ntoa(iface->ip));
	iface->nmask_s = talloc_strdup(iface, sys_inet_ntoa(iface->nmask));
	
	if (nmask.s_addr != ~0) {
		iface->bcast_s = talloc_strdup(iface, sys_inet_ntoa(bcast));
	}

	DLIST_ADD_END(local_interfaces, iface, struct interface *);

	DEBUG(2,("added interface ip=%s nmask=%s\n", iface->ip_s, iface->nmask_s));
}



/**
interpret a single element from a interfaces= config line 

This handles the following different forms:

1) wildcard interface name
2) DNS name
3) IP/masklen
4) ip/mask
5) bcast/mask
**/
static void interpret_interface(const char *token, 
				struct iface_struct *probed_ifaces, 
				int total_probed)
{
	struct in_addr ip, nmask;
	char *p;
	int i, added=0;

	ip.s_addr = 0;
	nmask.s_addr = 0;
	
	/* first check if it is an interface name */
	for (i=0;i<total_probed;i++) {
		if (gen_fnmatch(token, probed_ifaces[i].name) == 0) {
			add_interface(probed_ifaces[i].ip,
				      probed_ifaces[i].netmask);
			added = 1;
		}
	}
	if (added) return;

	/* maybe it is a DNS name */
	p = strchr_m(token,'/');
	if (!p) {
		/* don't try to do dns lookups on wildcard names */
		if (strpbrk(token, "*?") != NULL) {
			return;
		}
		ip.s_addr = interpret_addr2(token).addr;
		for (i=0;i<total_probed;i++) {
			if (ip.s_addr == probed_ifaces[i].ip.s_addr) {
				add_interface(probed_ifaces[i].ip,
					      probed_ifaces[i].netmask);
				return;
			}
		}
		DEBUG(2,("can't determine netmask for %s\n", token));
		return;
	}

	/* parse it into an IP address/netmasklength pair */
	*p++ = 0;

	ip.s_addr = interpret_addr2(token).addr;

	if (strlen(p) > 2) {
		nmask.s_addr = interpret_addr2(p).addr;
	} else {
		nmask.s_addr = htonl(((ALLONES >> atoi(p)) ^ ALLONES));
	}

	/* maybe the first component was a broadcast address */
	if (ip.s_addr == MKBCADDR(ip.s_addr, nmask.s_addr) ||
	    ip.s_addr == MKNETADDR(ip.s_addr, nmask.s_addr)) {
		for (i=0;i<total_probed;i++) {
			if (same_net(tov4(ip), tov4(probed_ifaces[i].ip), tov4(nmask))) {
				add_interface(probed_ifaces[i].ip, nmask);
				return;
			}
		}
		DEBUG(2,("Can't determine ip for broadcast address %s\n", token));
		return;
	}

	add_interface(ip, nmask);
}


/**
load the list of network interfaces
**/
static void load_interfaces(void)
{
	const char **ptr;
	int i;
	struct iface_struct ifaces[MAX_INTERFACES];
	struct ipv4_addr loopback_ip;
	int total_probed;

	if (local_interfaces != NULL) {
		return;
	}

	ptr = lp_interfaces();
	loopback_ip = interpret_addr2("127.0.0.1");

	/* probe the kernel for interfaces */
	total_probed = get_interfaces(ifaces, MAX_INTERFACES);

	/* if we don't have a interfaces line then use all interfaces
	   except loopback */
	if (!ptr || !*ptr || !**ptr) {
		if (total_probed <= 0) {
			DEBUG(0,("ERROR: Could not determine network interfaces, you must use a interfaces config line\n"));
		}
		for (i=0;i<total_probed;i++) {
			if (ifaces[i].ip.s_addr != loopback_ip.addr) {
				add_interface(ifaces[i].ip, 
					      ifaces[i].netmask);
			}
		}
	}

	while (ptr && *ptr) {
		interpret_interface(*ptr, ifaces, total_probed);
		ptr++;
	}

	if (!local_interfaces) {
		DEBUG(0,("WARNING: no network interfaces found\n"));
	}
}


/**
  unload the interfaces list, so it can be reloaded when needed
*/
void unload_interfaces(void)
{
	talloc_free(local_interfaces);
	local_interfaces = NULL;
}

/**
  how many interfaces do we have
  **/
int iface_count(void)
{
	int ret = 0;
	struct interface *i;

	load_interfaces();

	for (i=local_interfaces;i;i=i->next)
		ret++;
	return ret;
}

/**
  return IP of the Nth interface
  **/
const char *iface_n_ip(int n)
{
	struct interface *i;
  
	load_interfaces();

	for (i=local_interfaces;i && n;i=i->next)
		n--;

	if (i) {
		return i->ip_s;
	}
	return NULL;
}

/**
  return bcast of the Nth interface
  **/
const char *iface_n_bcast(int n)
{
	struct interface *i;
  
	load_interfaces();

	for (i=local_interfaces;i && n;i=i->next)
		n--;

	if (i) {
		return i->bcast_s;
	}
	return NULL;
}

/**
  return netmask of the Nth interface
  **/
const char *iface_n_netmask(int n)
{
	struct interface *i;
  
	load_interfaces();

	for (i=local_interfaces;i && n;i=i->next)
		n--;

	if (i) {
		return i->nmask_s;
	}
	return NULL;
}

/**
  return the local IP address that best matches a destination IP, or
  our first interface if none match
*/
const char *iface_best_ip(const char *dest)
{
	struct interface *iface;
	struct in_addr ip;

	load_interfaces();

	ip.s_addr = interpret_addr(dest);
	iface = iface_find(ip, True);
	if (iface) {
		return iface->ip_s;
	}
	return iface_n_ip(0);
}

/**
  return True if an IP is one one of our local networks
*/
BOOL iface_is_local(const char *dest)
{
	struct in_addr ip;

	load_interfaces();

	ip.s_addr = interpret_addr(dest);
	if (iface_find(ip, True)) {
		return True;
	}
	return False;
}

/**
  return True if a IP matches a IP/netmask pair
*/
BOOL iface_same_net(const char *ip1, const char *ip2, const char *netmask)
{
	return same_net(interpret_addr2(ip1),
			interpret_addr2(ip2),
			interpret_addr2(netmask));
}
