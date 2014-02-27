/* 
   Unix SMB/CIFS implementation.

   multiple interface handling

   Copyright (C) Andrew Tridgell 1992-2005
   
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

#include "includes.h"
#include "system/network.h"
#include "param/param.h"
#include "lib/socket/netif.h"
#include "../lib/util/util_net.h"
#include "../lib/util/dlinklist.h"

/* used for network interfaces */
struct interface {
	struct interface *next, *prev;
	char *name;
	int flags;
	struct sockaddr_storage ip;
	struct sockaddr_storage netmask;
	struct sockaddr_storage bcast;
	const char *ip_s;
	const char *bcast_s;
	const char *nmask_s;
};

#define ALLONES  ((uint32_t)0xFFFFFFFF)
/*
  address construction based on a patch from fred@datalync.com
*/
#define MKBCADDR(_IP, _NM) ((_IP & _NM) | (_NM ^ ALLONES))
#define MKNETADDR(_IP, _NM) (_IP & _NM)

/****************************************************************************
Try and find an interface that matches an ip. If we cannot, return NULL
  **************************************************************************/
static struct interface *iface_list_find(struct interface *interfaces,
					 const struct sockaddr *ip,
					 bool check_mask)
{
	struct interface *i;

	if (is_address_any(ip)) {
		return interfaces;
	}

	for (i=interfaces;i;i=i->next) {
		if (check_mask) {
			if (same_net(ip, (struct sockaddr *)&i->ip, (struct sockaddr *)&i->netmask)) {
				return i;
			}
		} else if (sockaddr_equal((struct sockaddr *)&i->ip, ip)) {
			return i;
		}
	}

	return NULL;
}

/****************************************************************************
add an interface to the linked list of interfaces
****************************************************************************/
static void add_interface(TALLOC_CTX *mem_ctx, const struct iface_struct *ifs, struct interface **interfaces,
			  bool enable_ipv6)
{
	char addr[INET6_ADDRSTRLEN];
	struct interface *iface;

	if (iface_list_find(*interfaces, (const struct sockaddr *)&ifs->ip, false)) {
		DEBUG(3,("add_interface: not adding duplicate interface %s\n",
			print_sockaddr(addr, sizeof(addr), &ifs->ip) ));
		return;
	}

	if (ifs->ip.ss_family == AF_INET &&
		!(ifs->flags & (IFF_BROADCAST|IFF_LOOPBACK))) {
		DEBUG(3,("not adding non-broadcast interface %s\n",
					ifs->name ));
		return;
	}

	if (!enable_ipv6 && ifs->ip.ss_family != AF_INET) {
		return;
	}

	iface = talloc(*interfaces == NULL ? mem_ctx : *interfaces, struct interface);
	if (iface == NULL) 
		return;
	
	ZERO_STRUCTPN(iface);

	iface->name = talloc_strdup(iface, ifs->name);
	if (!iface->name) {
		SAFE_FREE(iface);
		return;
	}
	iface->flags = ifs->flags;
	iface->ip = ifs->ip;
	iface->netmask = ifs->netmask;
	iface->bcast = ifs->bcast;

	/* keep string versions too, to avoid people tripping over the implied
	   static in inet_ntoa() */
	print_sockaddr(addr, sizeof(addr), &iface->ip);
	DEBUG(4,("added interface %s ip=%s ",
		 iface->name, addr));
	iface->ip_s = talloc_strdup(iface, addr);

	print_sockaddr(addr, sizeof(addr),
		       &iface->bcast);
	DEBUG(4,("bcast=%s ", addr));
	iface->bcast_s = talloc_strdup(iface, addr);

	print_sockaddr(addr, sizeof(addr),
		       &iface->netmask);
	DEBUG(4,("netmask=%s\n", addr));
	iface->nmask_s = talloc_strdup(iface, addr);

	/*
	   this needs to be a ADD_END, as some tests (such as the
	   spoolss notify test) depend on the interfaces ordering
	*/
	DLIST_ADD_END(*interfaces, iface, NULL);
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
static void interpret_interface(TALLOC_CTX *mem_ctx, 
				const char *token, 
				struct iface_struct *probed_ifaces, 
				int total_probed,
				struct interface **local_interfaces,
				bool enable_ipv6)
{
	struct sockaddr_storage ss;
	struct sockaddr_storage ss_mask;
	struct sockaddr_storage ss_net;
	struct sockaddr_storage ss_bcast;
	struct iface_struct ifs;
	char *p;
	int i;
	bool added=false;
	bool goodaddr = false;

	/* first check if it is an interface name */
	for (i=0;i<total_probed;i++) {
		if (gen_fnmatch(token, probed_ifaces[i].name) == 0) {
			add_interface(mem_ctx, &probed_ifaces[i],
				      local_interfaces, enable_ipv6);
			added = true;
		}
	}
	if (added) {
		return;
	}

	/* maybe it is a DNS name */
	p = strchr_m(token,'/');
	if (p == NULL) {
		if (!interpret_string_addr(&ss, token, 0)) {
			DEBUG(2, ("interpret_interface: Can't find address "
				  "for %s\n", token));
			return;
		}

		for (i=0;i<total_probed;i++) {
			if (sockaddr_equal((struct sockaddr *)&ss, (struct sockaddr *)&probed_ifaces[i].ip)) {
				add_interface(mem_ctx, &probed_ifaces[i],
					      local_interfaces, enable_ipv6);
				return;
			}
		}
		DEBUG(2,("interpret_interface: "
			"can't determine interface for %s\n",
			token));
		return;
	}

	/* parse it into an IP address/netmasklength pair */
	*p = 0;
	goodaddr = interpret_string_addr(&ss, token, 0);
	*p++ = '/';

	if (!goodaddr) {
		DEBUG(2,("interpret_interface: "
			"can't determine interface for %s\n",
			token));
		return;
	}

	if (strlen(p) > 2) {
		goodaddr = interpret_string_addr(&ss_mask, p, 0);
		if (!goodaddr) {
			DEBUG(2,("interpret_interface: "
				"can't determine netmask from %s\n",
				p));
			return;
		}
	} else {
		char *endp = NULL;
		unsigned long val = strtoul(p, &endp, 0);
		if (p == endp || (endp && *endp != '\0')) {
			DEBUG(2,("interpret_interface: "
				"can't determine netmask value from %s\n",
				p));
			return;
		}
		if (!make_netmask(&ss_mask, &ss, val)) {
			DEBUG(2,("interpret_interface: "
				"can't apply netmask value %lu from %s\n",
				val,
				p));
			return;
		}
	}

	make_bcast(&ss_bcast, &ss, &ss_mask);
	make_net(&ss_net, &ss, &ss_mask);

	/* Maybe the first component was a broadcast address. */
	if (sockaddr_equal((struct sockaddr *)&ss_bcast, (struct sockaddr *)&ss) ||
		sockaddr_equal((struct sockaddr *)&ss_net, (struct sockaddr *)&ss)) {
		for (i=0;i<total_probed;i++) {
			if (same_net((struct sockaddr *)&ss,
						 (struct sockaddr *)&probed_ifaces[i].ip,
						 (struct sockaddr *)&ss_mask)) {
				/* Temporarily replace netmask on
				 * the detected interface - user knows
				 * best.... */
				struct sockaddr_storage saved_mask =
					probed_ifaces[i].netmask;
				probed_ifaces[i].netmask = ss_mask;
				DEBUG(2,("interpret_interface: "
					"using netmask value %s from "
					"config file on interface %s\n",
					p,
					probed_ifaces[i].name));
				add_interface(mem_ctx, &probed_ifaces[i],
					      local_interfaces, enable_ipv6);
				probed_ifaces[i].netmask = saved_mask;
				return;
			}
		}
		DEBUG(2,("interpret_interface: Can't determine ip for "
			"broadcast address %s\n",
			token));
		return;
	}

	/* Just fake up the interface definition. User knows best. */

	DEBUG(2,("interpret_interface: Adding interface %s\n",
		token));

	ZERO_STRUCT(ifs);
	(void)strlcpy(ifs.name, token, sizeof(ifs.name));
	ifs.flags = IFF_BROADCAST;
	ifs.ip = ss;
	ifs.netmask = ss_mask;
	ifs.bcast = ss_bcast;
	add_interface(mem_ctx, &ifs,
		      local_interfaces, enable_ipv6);
}


/**
load the list of network interfaces
**/
void load_interface_list(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx, struct interface **local_interfaces)
{
	const char **ptr = lpcfg_interfaces(lp_ctx);
	int i;
	struct iface_struct *ifaces = NULL;
	int total_probed;
	bool enable_ipv6 = lpcfg_parm_bool(lp_ctx, NULL, "ipv6", "enable", true);

	*local_interfaces = NULL;

	/* probe the kernel for interfaces */
	total_probed = get_interfaces(mem_ctx, &ifaces);

	/* if we don't have a interfaces line then use all interfaces
	   except loopback */
	if (!ptr || !*ptr || !**ptr) {
		if (total_probed <= 0) {
			DEBUG(0,("ERROR: Could not determine network interfaces, you must use a interfaces config line\n"));
		}
		for (i=0;i<total_probed;i++) {
			if (!is_loopback_addr((struct sockaddr *)&ifaces[i].ip)) {
				add_interface(mem_ctx, &ifaces[i], local_interfaces, enable_ipv6);
			}
		}
	}

	while (ptr && *ptr) {
		interpret_interface(mem_ctx, *ptr, ifaces, total_probed, local_interfaces, enable_ipv6);
		ptr++;
	}

	if (!*local_interfaces) {
		DEBUG(0,("WARNING: no network interfaces found\n"));
	}
	talloc_free(ifaces);
}

/**
  how many interfaces do we have
  **/
int iface_list_count(struct interface *ifaces)
{
	int ret = 0;
	struct interface *i;

	for (i=ifaces;i;i=i->next)
		ret++;
	return ret;
}

/**
  return IP of the Nth interface
  **/
const char *iface_list_n_ip(struct interface *ifaces, int n)
{
	struct interface *i;
  
	for (i=ifaces;i && n;i=i->next)
		n--;

	if (i) {
		return i->ip_s;
	}
	return NULL;
}


/**
  return the first IPv4 interface address we have registered
  **/
const char *iface_list_first_v4(struct interface *ifaces)
{
	struct interface *i;

	for (i=ifaces; i; i=i->next) {
		if (i->ip.ss_family == AF_INET) {
			return i->ip_s;
		}
	}
	return NULL;
}

/**
  return the first IPv6 interface address we have registered
  **/
static const char *iface_list_first_v6(struct interface *ifaces)
{
	struct interface *i;

#ifdef HAVE_IPV6
	for (i=ifaces; i; i=i->next) {
		if (i->ip.ss_family == AF_INET6) {
			return i->ip_s;
		}
	}
#endif
	return NULL;
}

/**
   check if an interface is IPv4
  **/
bool iface_list_n_is_v4(struct interface *ifaces, int n)
{
	struct interface *i;

	for (i=ifaces;i && n;i=i->next)
		n--;

	if (i) {
		return i->ip.ss_family == AF_INET;
	}
	return false;
}

/**
  return bcast of the Nth interface
  **/
const char *iface_list_n_bcast(struct interface *ifaces, int n)
{
	struct interface *i;
  
	for (i=ifaces;i && n;i=i->next)
		n--;

	if (i) {
		return i->bcast_s;
	}
	return NULL;
}

/**
  return netmask of the Nth interface
  **/
const char *iface_list_n_netmask(struct interface *ifaces, int n)
{
	struct interface *i;
  
	for (i=ifaces;i && n;i=i->next)
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
const char *iface_list_best_ip(struct interface *ifaces, const char *dest)
{
	struct interface *iface;
	struct sockaddr_storage ss;

	if (!interpret_string_addr(&ss, dest, AI_NUMERICHOST)) {
		return iface_list_n_ip(ifaces, 0);
	}
	iface = iface_list_find(ifaces, (const struct sockaddr *)&ss, true);
	if (iface) {
		return iface->ip_s;
	}
#ifdef HAVE_IPV6
	if (ss.ss_family == AF_INET6) {
		return iface_list_first_v6(ifaces);
	}
#endif
	return iface_list_first_v4(ifaces);
}

/**
  return true if an IP is one one of our local networks
*/
bool iface_list_is_local(struct interface *ifaces, const char *dest)
{
	struct sockaddr_storage ss;

	if (!interpret_string_addr(&ss, dest, AI_NUMERICHOST)) {
		return false;
	}
	if (iface_list_find(ifaces, (const struct sockaddr *)&ss, true)) {
		return true;
	}
	return false;
}

/**
  return true if a IP matches a IP/netmask pair
*/
bool iface_list_same_net(const char *ip1, const char *ip2, const char *netmask)
{
	struct sockaddr_storage ip1_ss, ip2_ss, nm_ss;

	if (!interpret_string_addr(&ip1_ss, ip1, AI_NUMERICHOST)) {
		return false;
	}
	if (!interpret_string_addr(&ip2_ss, ip2, AI_NUMERICHOST)) {
		return false;
	}
	if (!interpret_string_addr(&nm_ss, netmask, AI_NUMERICHOST)) {
		return false;
	}

	return same_net((struct sockaddr *)&ip1_ss,
			(struct sockaddr *)&ip2_ss,
			(struct sockaddr *)&nm_ss);
}

/**
   return the list of wildcard interfaces
   this will include the IPv4 0.0.0.0, and may include IPv6 ::
*/
char **iface_list_wildcard(TALLOC_CTX *mem_ctx)
{
	char **ret;
#ifdef HAVE_IPV6
	ret = str_list_make(mem_ctx, "::,0.0.0.0", NULL);
#else
	ret = str_list_make(mem_ctx, "0.0.0.0", NULL);
#endif
	return ret;
}
