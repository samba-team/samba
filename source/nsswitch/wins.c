/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   a WINS nsswitch module 
   Copyright (C) Andrew Tridgell 1999
   
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

#define NO_SYSLOG

#include "includes.h"
#include <nss.h>

extern int DEBUGLEVEL;

#ifndef INADDRSZ
#define INADDRSZ 4
#endif

struct in_addr *lookup_backend(const char *name, int *count)
{
	int fd;
	static int initialised;
	struct in_addr *ret;
	char *p;
	int j;

	if (!initialised) {
		initialised = 1;
		DEBUGLEVEL = 0;
		TimeInit();
		setup_logging("nss_wins",True);
		charset_initialise();
		lp_load(CONFIGFILE,True,False,False);
		load_interfaces();
	}

	*count = 0;

	fd = open_socket_in(SOCK_DGRAM,0, 3, interpret_addr("0.0.0.0"), True);
	if (fd == -1) return NULL;

	set_socket_options(fd,"SO_BROADCAST");

	p = wins_srv();
	if (p && *p) {
		ret = name_query(fd,name,0x20,False,True, *interpret_addr2(p), count);
		goto out;
	}

	if (lp_wins_support()) {
		/* we are our own WINS server */
		ret = name_query(fd,name,0x20,False,True, *interpret_addr2("127.0.0.1"), count);
		goto out;
	}

	/* uggh, we have to broadcast to each interface in turn */
	for (j=iface_count() - 1;
	     j >= 0;
	     j--) {
		struct in_addr *bcast = iface_n_bcast(j);
		ret = name_query(fd,name,0x20,True,True,*bcast,count);
		if (ret) break;
	}

 out:
	close(fd);
	return ret;
}


/****************************************************************************
gethostbyname() - we ignore any domain portion of the name and only
handle names that are at most 15 characters long
  **************************************************************************/
enum nss_status 
_nss_wins_gethostbyname_r(const char *name, struct hostent *he,
			  char *buffer, size_t buflen, int *errnop,
			  int *h_errnop)
{
	char **host_addresses;
	struct in_addr *ip_list;
	int i, count;

	ip_list = lookup_backend(name, &count);
	if (!ip_list) {
		return NSS_STATUS_NOTFOUND;
	}

	if (buflen < (2*count+1)*INADDRSZ) {
		/* no ENOMEM error type?! */
		return NSS_STATUS_NOTFOUND;
	}


	host_addresses = (char **)buffer;
	he->h_addr_list = host_addresses;
	host_addresses[count] = NULL;
	buffer += (count + 1) * INADDRSZ;
	buflen += (count + 1) * INADDRSZ;
	he->h_addrtype = AF_INET;
	he->h_length = INADDRSZ;

	for (i=0;i<count;i++) {
		memcpy(buffer, &ip_list[i].s_addr, INADDRSZ);
		*host_addresses = buffer;
		buffer += INADDRSZ;
		buflen -= INADDRSZ;
		host_addresses++;
	}

	if (ip_list) free(ip_list);

	return NSS_STATUS_SUCCESS;
}
