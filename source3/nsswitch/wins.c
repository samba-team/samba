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
#ifdef HAVE_NS_API_H
#undef VOLATILE

#include <ns_daemon.h>
#define NSD_LOGLEVEL NSD_LOG_MIN
#endif

#ifndef INADDRSZ
#define INADDRSZ 4
#endif

static int initialised;


/* Use our own create socket code so we don't recurse.... */

static int wins_lookup_open_socket_in(void)
{
	struct sockaddr_in sock;
	int val=1;
	int res;

	memset((char *)&sock,'\0',sizeof(sock));

#ifdef HAVE_SOCK_SIN_LEN
	sock.sin_len = sizeof(sock);
#endif
	sock.sin_port = 0;
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = interpret_addr("0.0.0.0");
	res = socket(AF_INET, SOCK_DGRAM, 0);
	if (res == -1)
		return -1;

	setsockopt(res,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));
#ifdef SO_REUSEPORT
	setsockopt(res,SOL_SOCKET,SO_REUSEPORT,(char *)&val,sizeof(val));
#endif /* SO_REUSEPORT */

	/* now we've got a socket - we need to bind it */

	if (bind(res, (struct sockaddr * ) &sock,sizeof(sock)) < 0)
		return(-1);

	return res;
}


static void nss_wins_init(void)
{
	initialised = 1;
	DEBUGLEVEL = 0;

	setup_logging("nss_wins",False);
	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();
}

static struct in_addr *lookup_backend(const char *name, int *count)
{
	int fd;
	struct in_addr *ret = NULL;
	struct in_addr  p;
	int j;

	if (!initialised) {
		nss_wins_init();
	}

	*count = 0;

	fd = wins_lookup_open_socket_in();
	if (fd == -1)
		return NULL;

	set_socket_options(fd,"SO_BROADCAST");

/* The next four lines commented out by JHT
   and replaced with the four lines following */
/*	if( !is_zero_ip( wins_ip ) ) {
 *		ret = name_query( fd, name, 0x20, False, True, wins_src_ip(), count );
 *		goto out;
 *	}
 */
	p = wins_srv_ip();
	if( !is_zero_ip(p) ) {
		ret = name_query(fd,name,0x20,False,True, p, count);
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
#ifdef HAVE_NS_API_H
/* IRIX version */

int init(void)
{
	nsd_logprintf(NSD_LOGLEVEL, "init (wins)\n");
	nss_wins_init();
	return NSD_OK;
}

int lookup(nsd_file_t *rq)
{
	char *map;
	char *key;
	struct in_addr *ip_list;
	int count;
	char response[80];

	nsd_logprintf(NSD_LOGLEVEL, "lookup (wins)\n");
	if (! rq) 
		return NSD_ERROR;

	map = nsd_attr_fetch_string(rq->f_attrs, "table", (char*)0);
	if (! map) {
		rq->f_status = NS_FATAL;
		return NSD_ERROR;
	}

	if (strcasecmp(map,"hosts.byname") != 0) {
		rq->f_status = NS_NOTFOUND;
		return NSD_NEXT;
	}

	key = nsd_attr_fetch_string(rq->f_attrs, "key", (char*)0);
	if (! key || ! *key) {
		rq->f_status = NS_FATAL;
		return NSD_ERROR;
	}

	ip_list = lookup_backend(key, &count);

	if (!ip_list) {
		rq->f_status = NSS_STATUS_NOTFOUND;
		return NSD_NEXT;
	}
	snprintf(response,79,"%s %s\n",inet_ntoa(*ip_list),key);
	free(ip_list);

	nsd_set_result(rq,NS_SUCCESS,response,strlen(response),VOLATILE);
	return NSD_OK;
}

#else
NSS_STATUS
_nss_wins_gethostbyname_r(const char *name, struct hostent *he,
			  char *buffer, size_t buflen, int *errnop,
			  int *h_errnop)
{
	char **host_addresses;
	struct in_addr *ip_list;
	int i, count;
	size_t namelen = strlen(name) + 1;
		
	memset(he, '\0', sizeof(*he));

	ip_list = lookup_backend(name, &count);
	if (!ip_list) {
		return NSS_STATUS_NOTFOUND;
	}

	if (buflen < namelen + (2*count+1)*INADDRSZ) {
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

	if (ip_list)
		free(ip_list);

	memcpy(buffer, name, namelen);
	he->h_name = buffer;

	return NSS_STATUS_SUCCESS;
}
#endif

