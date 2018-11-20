/*
   Unix SMB/CIFS implementation.
   a WINS nsswitch module
   Copyright (C) Andrew Tridgell 1999

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
#include "nsswitch/winbind_client.h"
#include "nsswitch/libwbclient/wbclient.h"

#ifdef HAVE_NS_API_H

#include <ns_daemon.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_PTHREAD
static pthread_mutex_t wins_nss_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifndef INADDRSZ
#define INADDRSZ 4
#endif

NSS_STATUS _nss_wins_gethostbyname_r(const char *hostname,
				     struct hostent *he,
				     char *buffer,
				     size_t buflen,
				     int *errnop,
				     int *h_errnop);
NSS_STATUS _nss_wins_gethostbyname2_r(const char *name,
				      int af,
				      struct hostent *he,
				      char *buffer,
				      size_t buflen,
				      int *errnop,
				      int *h_errnop);

static char *lookup_byname_backend(const char *name)
{
	const char *p;
	char *ip, *ipp;
	size_t nbt_len;
	wbcErr result;

	nbt_len = strlen(name);
	if (nbt_len > MAX_NETBIOSNAME_LEN - 1) {
		return NULL;
	}
	p = strchr(name, '.');
	if (p != NULL) {
		return NULL;
	}

	wbcSetClientProcessName("nss_wins");
	result = wbcResolveWinsByName(name, &ip);
	if (result != WBC_ERR_SUCCESS) {
		return NULL;
	}

        ipp = strchr(ip, '\t');
        if (ipp != NULL) {
                *ipp = '\0';
        }

	return ip;
}

#ifdef HAVE_NS_API_H

static char *lookup_byaddr_backend(const char *ip)
{
	wbcErr result;
	char *name = NULL;

	wbcSetClientProcessName("nss_wins");
	result = wbcResolveWinsByIP(ip, &name);
	if (result != WBC_ERR_SUCCESS) {
		return NULL;
	}

	return name;
}

/* IRIX version */

int init(void)
{
	bool ok;

	nsd_logprintf(NSD_LOG_MIN, "entering init (wins)\n");

	ok = nss_wins_init();
	if (!ok) {
		return NSD_ERROR;
	}

	return NSD_OK;
}

int lookup(nsd_file_t *rq)
{
	char *map;
	char *key;
	char *addr;
	int i, count, len, size;
	char response[1024];
	bool found = False;

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
	if (strcasecmp_m(map,"hosts.byaddr") == 0) {
		char *name;

		name = lookup_byaddr_backend(key);
		if (name != NULL) {
			size = strlen(key) + 1;
			if (size > len) {
				return NSD_ERROR;
			}
			len -= size;
			strncat(response,key,size);
			strncat(response,"\t",1);

			size = strlen(name) + 1;
			if (size > len) {
				return NSD_ERROR;
			}
			len -= size;
			strncat(response, name, size);
			strncat(response, " ", 1);
			found = True;
		}
		response[strlen(response)-1] = '\n';
	} else if (strcasecmp_m(map,"hosts.byname") == 0) {
		char *ip;

		ip = lookup_byname_backend(key);
		if (ip != NULL) {
			size = strlen(ip) + 1;
			if (size > len) {
				wbcFreeMemory(ip);
				return NSD_ERROR;
			}
			len -= size;
			strncat(response,ip,size);
			strncat(response,"\t",1);
			size = strlen(key) + 1;
			wbcFreeMemory(ip);
			if (size > len) {
				return NSD_ERROR;
			}
			strncat(response,key,size);
			strncat(response,"\n",1);

			found = True;
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

/* Allocate some space from the nss static buffer.  The buffer and buflen
   are the pointers passed in by the C library to the _nss_*_*
   functions. */

static char *get_static(char **buffer, size_t *buflen, size_t len)
{
	char *result;

	/* Error check.  We return false if things aren't set up right, or
	   there isn't enough buffer space left. */

	if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
		return NULL;
	}

	/* Return an index into the static buffer */

	result = *buffer;
	*buffer += len;
	*buflen -= len;

	return result;
}

/****************************************************************************
gethostbyname() - we ignore any domain portion of the name and only
handle names that are at most 15 characters long
  **************************************************************************/
NSS_STATUS
_nss_wins_gethostbyname_r(const char *hostname,
			  struct hostent *he,
			  char *buffer,
			  size_t buflen,
			  int *errnop,
			  int *h_errnop)
{
	NSS_STATUS nss_status = NSS_STATUS_SUCCESS;
	char *ip;
	struct in_addr in;
	int i;
	fstring name;
	size_t namelen;
	int rc;

#ifdef HAVE_PTHREAD
	pthread_mutex_lock(&wins_nss_mutex);
#endif

	memset(he, '\0', sizeof(*he));
	fstrcpy(name, hostname);

	/* Do lookup */

	ip = lookup_byname_backend(name);
	if (ip == NULL) {
		*h_errnop = HOST_NOT_FOUND;
		nss_status = NSS_STATUS_NOTFOUND;
		goto out;
	}

	rc = inet_pton(AF_INET, ip, &in);
	wbcFreeMemory(ip);
	if (rc == 0) {
		*errnop = errno;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	/* Copy h_name */

	namelen = strlen(name) + 1;

	if ((he->h_name = get_static(&buffer, &buflen, namelen)) == NULL) {
		*errnop = EAGAIN;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	memcpy(he->h_name, name, namelen);

	/* Copy h_addr_list, align to pointer boundary first */

	if ((i = (unsigned long)(buffer) % sizeof(char*)) != 0)
		i = sizeof(char*) - i;

	if (get_static(&buffer, &buflen, i) == NULL) {
		*errnop = EAGAIN;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	if ((he->h_addr_list = (char **)get_static(
		     &buffer, &buflen, 2 * sizeof(char *))) == NULL) {
		*errnop = EAGAIN;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	if ((he->h_addr_list[0] = get_static(&buffer, &buflen,
					     INADDRSZ)) == NULL) {
		*errnop = EAGAIN;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	memcpy(he->h_addr_list[0], &in, INADDRSZ);

	he->h_addr_list[1] = NULL;

	/* Set h_addr_type and h_length */

	he->h_addrtype = AF_INET;
	he->h_length = INADDRSZ;

	/* Set h_aliases */

	if ((i = (unsigned long)(buffer) % sizeof(char*)) != 0)
		i = sizeof(char*) - i;

	if (get_static(&buffer, &buflen, i) == NULL) {
		*errnop = EAGAIN;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	if ((he->h_aliases = (char **)get_static(
		     &buffer, &buflen, sizeof(char *))) == NULL) {
		*errnop = EAGAIN;
		*h_errnop = NETDB_INTERNAL;
		nss_status = NSS_STATUS_TRYAGAIN;
		goto out;
	}

	he->h_aliases[0] = NULL;

	*h_errnop = NETDB_SUCCESS;
	nss_status = NSS_STATUS_SUCCESS;

  out:

#ifdef HAVE_PTHREAD
	pthread_mutex_unlock(&wins_nss_mutex);
#endif
	return nss_status;
}


NSS_STATUS
_nss_wins_gethostbyname2_r(const char *name,
			   int af,
			   struct hostent *he,
			   char *buffer,
			   size_t buflen,
			   int *errnop,
			   int *h_errnop)
{
	NSS_STATUS nss_status;

	if(af!=AF_INET) {
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_DATA;
		nss_status = NSS_STATUS_UNAVAIL;
	} else {
		nss_status = _nss_wins_gethostbyname_r(name,
						       he,
						       buffer,
						       buflen,
						       errnop,
						       h_errnop);
	}
	return nss_status;
}
#endif
