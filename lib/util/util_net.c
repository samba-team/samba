/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
    
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
#include "system/locale.h"
#include "system/filesys.h"

/**
 Interpret an internet address or name into an IP address in 4 byte form.
**/
_PUBLIC_ uint32_t interpret_addr(const char *str)
{
	struct hostent *hp;
	uint32_t res;

	if (str == NULL || *str == 0 ||
	    strcmp(str,"0.0.0.0") == 0) {
		return 0;
	}
	if (strcmp(str,"255.255.255.255") == 0) {
		return 0xFFFFFFFF;
	}
	/* recognise 'localhost' as a special name. This fixes problems with
	   some hosts that don't have localhost in /etc/hosts */
	if (strcasecmp(str,"localhost") == 0) {
		str = "127.0.0.1";
	}

	/* if it's in the form of an IP address then get the lib to interpret it */
	if (is_ipaddress(str)) {
		res = inet_addr(str);
	} else {
		/* otherwise assume it's a network name of some sort and use 
			sys_gethostbyname */
		if ((hp = sys_gethostbyname(str)) == 0) {
			DEBUG(3,("sys_gethostbyname: Unknown host. %s\n",str));
			return 0;
		}

		if(hp->h_addr == NULL) {
			DEBUG(3,("sys_gethostbyname: host address is invalid for host %s\n",str));
			return 0;
		}
		memcpy((char *)&res,(char *)hp->h_addr, 4);
	}

	if (res == (uint32_t)-1)
		return(0);

	return(res);
}

/**
 A convenient addition to interpret_addr().
**/
_PUBLIC_ struct in_addr interpret_addr2(const char *str)
{
	struct in_addr ret;
	uint32_t a = interpret_addr(str);
	ret.s_addr = a;
	return ret;
}

/**
 Check if an IP is the 0.0.0.0.
**/

_PUBLIC_ bool is_zero_ip(struct in_addr ip)
{
	return ip.s_addr == 0;
}

/**
 Are two IPs on the same subnet?
**/

_PUBLIC_ bool same_net(struct in_addr ip1, struct in_addr ip2, struct in_addr mask)
{
	uint32_t net1,net2,nmask;

	nmask = ntohl(mask.s_addr);
	net1  = ntohl(ip1.s_addr);
	net2  = ntohl(ip2.s_addr);
            
	return((net1 & nmask) == (net2 & nmask));
}

/**
 Return true if a string could be a pure IP address.
**/

_PUBLIC_ bool is_ipaddress(const char *str)
{
	bool pure_address = true;
	int i;

	if (str == NULL) return false;

	for (i=0; pure_address && str[i]; i++)
		if (!(isdigit((int)str[i]) || str[i] == '.'))
			pure_address = false;

	/* Check that a pure number is not misinterpreted as an IP */
	pure_address = pure_address && (strchr(str, '.') != NULL);

	return pure_address;
}


