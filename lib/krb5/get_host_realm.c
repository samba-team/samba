/*
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "krb5_locl.h"
#include <resolve.h>

RCSID("$Id$");

/* To automagically find the correct realm of a host (without
 * krb.realms) add a text record for your domain with the name of your
 * realm, like this:
 *
 * krb5-realm	IN	TXT	FOO.SE
 *
 * The search is recursive, so you can add entries for specific
 * hosts. To find the realm of host a.b.c, it first tries
 * krb5-realm.a.b.c, then krb5-realm.b.c and so on.
 */

static int
dns_find_realm(krb5_context context,
	       const char *domain,
	       krb5_realm *realm)
{
    char dom[MAXHOSTNAMELEN];
    struct dns_reply *r;
    struct resource_record *rr;
    
    if(*domain == '.')
	domain++;
    snprintf(dom, sizeof(dom), "krb5-realm.%s.", domain);
    r = dns_lookup(dom, "TXT");
    if(r == NULL)
	return -1;
    for(rr = r->head; rr; rr = rr->next) {
	if(rr->type != T_TXT)
	    continue;
	*realm = strdup(rr->u.txt);
	dns_free_data(r);
	if(*realm == NULL)
	    return ENOMEM;
	return 0;
    }
    /* this shouldn't happen */
    dns_free_data(r);
    return -1;
}

static int
config_find_realm(krb5_context context, 
		  const char *domain, 
		  krb5_realm *realm)
{
    const char *s = krb5_config_get_string(context, NULL, 
					   "domain_realm",
					   domain,
					   NULL);
    if(s == NULL)
	return -1;
    *realm = strdup(s);
    if(*realm == NULL)
	return ENOMEM;
    return 0;
}

krb5_error_code
krb5_get_host_realm(krb5_context context,
		    const char *host,
		    krb5_realm **realms)
{
    char hostname[MAXHOSTNAMELEN];
    const char *p;
    struct in_addr addr;
    struct hostent *hostent;
    const char *orig_host;

    if (host == NULL) {
	if (gethostname (hostname, sizeof(hostname)))
	    return errno;
	host = hostname;
    }

    orig_host = host;

    addr.s_addr = inet_addr(host);
    hostent = roken_gethostbyname (host);
    if (hostent == NULL && addr.s_addr != INADDR_NONE)
	hostent = roken_gethostbyaddr ((const char *)&addr,
				       sizeof(addr),
				       AF_INET);
    if (hostent != NULL)
	host = hostent->h_name;

    *realms = malloc(2 * sizeof(krb5_realm));
    if (*realms == NULL)
	return ENOMEM;
    (*realms)[0] = NULL;
    (*realms)[1] = NULL;

    p = host;
    while(p) {
	printf("%s\n", p);
	if(config_find_realm(context, p, *realms) == 0)
	    return 0;
	else if(dns_find_realm(context, p, *realms) == 0)
	    return 0;
	p = strchr(p, '.');
	if(p) p++;
    }
    p = strchr(host, '.');
    if(p == NULL)
	p = strchr(orig_host, '.');
    if(p) {
	p++;
	(*realms)[0] = strdup(p);
	if((*realms)[0] == NULL)
	    return ENOMEM;
	strupr((*realms)[0]);
	return 0;
    }
    free(*realms);
    return KRB5_ERR_HOST_REALM_UNKNOWN;
}
