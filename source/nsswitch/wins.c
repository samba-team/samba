/* 
   Unix SMB/CIFS implementation.
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
#endif

#ifndef INADDRSZ
#define INADDRSZ 4
#endif

static int initialised;

extern BOOL AllowDebugChange;

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

	if (bind(res, (struct sockaddr * ) &sock,sizeof(sock)) < 0) {
		close(res);
		return(-1);
	}

	set_socket_options(res,"SO_BROADCAST");

	return res;
}


static void nss_wins_init(void)
{
	initialised = 1;
	DEBUGLEVEL = 0;
	AllowDebugChange = False;

	/* needed for lp_xx() functions */
	charset_initialise();

	TimeInit();
	setup_logging("nss_wins",False);
	lp_load(CONFIGFILE,True,False,False);
	load_interfaces();
	codepage_initialise(lp_client_code_page());
}

static struct node_status *lookup_byaddr_backend(char *addr, int *count)
{
	int fd;
	struct in_addr  ip;
	struct nmb_name nname;
	struct node_status *status;

	if (!initialised) {
		nss_wins_init();
	}

	fd = wins_lookup_open_socket_in();
	if (fd == -1)
		return NULL;

	make_nmb_name(&nname, "*", 0);
	ip = *interpret_addr2(addr);
	status = node_status_query(fd,&nname,ip, count);

	close(fd);
	return status;
}

static struct in_addr *lookup_byname_backend(const char *name, int *count)
{
	int fd;
	struct in_addr *ret = NULL;
	struct in_addr  p;
	int j, flags;

	if (!initialised) {
		nss_wins_init();
	}

	*count = 0;

	fd = wins_lookup_open_socket_in();
	if (fd == -1)
		return NULL;

	p = wins_srv_ip();
	if( !is_zero_ip(p) ) {
		ret = name_query(fd,name,0x20,False,True, p, count, &flags);
		goto out;
	}

	if (lp_wins_support()) {
		/* we are our own WINS server */
		ret = name_query(fd,name,0x20,False,True, *interpret_addr2("127.0.0.1"), count, &flags);
		goto out;
	}

	/* uggh, we have to broadcast to each interface in turn */
	for (j=iface_count() - 1;
	     j >= 0;
	     j--) {
		struct in_addr *bcast = iface_n_bcast(j);
		ret = name_query(fd,name,0x20,True,True,*bcast,count, &flags);
		if (ret) break;
	}

 out:

	close(fd);
	return ret;
}


#ifdef HAVE_NS_API_H
/* IRIX version */

int init(void)
{
	nsd_logprintf(NSD_LOG_MIN, "entering init (wins)\n");
	nss_wins_init();
	return NSD_OK;
}

int lookup(nsd_file_t *rq)
{
	char *map;
	char *key;
	char *addr;
	struct in_addr *ip_list;
	struct node_status *status;
	int i, count, len, size;
	char response[1024];
	BOOL found = False;

	nsd_logprintf(NSD_LOG_MIN, "entering lookup (wins)\n");
	if (! rq) 
		return NSD_ERROR;

	map = nsd_attr_fetch_string(rq->f_attrs, "table", (char*)0);
	if (! map) {
		rq->f_status = NS_FATAL;
		return NSD_ERROR;
	}

	key = nsd_attr_fetch_string(rq->f_attrs, "key", (char*)0);
	if (! key || ! *key) {
		rq->f_status = NS_FATAL;
		return NSD_ERROR;
	}

	response[0] = '\0';
	len = sizeof(response) - 2;

	/* 
	 * response needs to be a string of the following format
	 * ip_address[ ip_address]*\tname[ alias]*
	 */
	if (strcasecmp(map,"hosts.byaddr") == 0) {
		if ( status = lookup_byaddr_backend(key, &count)) {
		    size = strlen(key) + 1;
		    if (size > len) {
			free(status);
			return NSD_ERROR;
		    }
		    len -= size;
		    strncat(response,key,size);
		    strncat(response,"\t",1);
		    for (i = 0; i < count; i++) {
			/* ignore group names */
			if (status[i].flags & 0x80) continue;
			if (status[i].type == 0x20) {
				size = sizeof(status[i].name) + 1;
				if (size > len) {
				    free(status);
				    return NSD_ERROR;
				}
				len -= size;
				strncat(response, status[i].name, size);
				strncat(response, " ", 1);
				found = True;
			}
		    }
		    response[strlen(response)-1] = '\n';
		    free(status);
		}
	} else if (strcasecmp(map,"hosts.byname") == 0) {
	    if (ip_list = lookup_byname_backend(key, &count)) {
		for (i = count; i ; i--) {
		    addr = inet_ntoa(ip_list[i-1]);
		    size = strlen(addr) + 1;
		    if (size > len) {
			free(ip_list);
			return NSD_ERROR;
		    }
		    len -= size;
		    if (i != 0)
			response[strlen(response)-1] = ' ';
		    strncat(response,addr,size);
		    strncat(response,"\t",1);
		}
		size = strlen(key) + 1;
		if (size > len) {
		    free(ip_list);
		    return NSD_ERROR;
		}   
		strncat(response,key,size);
		strncat(response,"\n",1);
		found = True;
		free(ip_list);
	    }
	}

	if (found) {
	    nsd_logprintf(NSD_LOG_LOW, "lookup (wins %s) %s\n",map,response);
	    nsd_set_result(rq,NS_SUCCESS,response,strlen(response),VOLATILE);
	    return NSD_OK;
	}
	nsd_logprintf(NSD_LOG_LOW, "lookup (wins) not found\n");
	rq->f_status = NS_NOTFOUND;
	return NSD_NEXT;
}

#else
/****************************************************************************
gethostbyname() - we ignore any domain portion of the name and only
handle names that are at most 15 characters long
  **************************************************************************/
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

	ip_list = lookup_byname_backend(name, &count);
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

NSS_STATUS
_nss_wins_gethostbyname2_r(const char *name, int af, struct hostent *he,
				char *buffer, size_t buflen, int *errnop,
				int *h_errnop)
{
	if(af!=AF_INET) {
		*h_errnop = NO_DATA;
		*errnop = EAFNOSUPPORT;
		return NSS_STATUS_UNAVAIL;
	}

	return _nss_wins_gethostbyname_r(name,he,buffer,buflen,errnop,h_errnop);
}



#endif
