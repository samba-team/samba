/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
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

RCSID("$Id$");

static int
exact_match (const char *s, const char *pattern)
{
    return strcasecmp (s, pattern) == 0;
}

static int
domain_match (const char *s, const char *pattern)
{
    const char *dot = strchr (s, '.');

    return dot && strcasecmp (dot, pattern) == 0;
}

krb5_error_code
krb5_get_host_realm(krb5_context context,
		    const char *host,
		    krb5_realm **realms)
{
    krb5_error_code ret;
    char hostname[MAXHOSTNAMELEN];
    char *res = NULL;
    const krb5_config_binding *l;
    struct in_addr addr;
    struct hostent *hostent;
    char *orig_host;

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

    for(l = krb5_config_get_list (context, NULL,
				  "domain_realm",
				  NULL);
	l;
	l = l->next) {
	if (l->type != krb5_config_string)
	    continue;
	if (exact_match (host, l->name)) {
	    res = l->u.string;
	    break;
	} else if (domain_match (host, l->name)) {
	    res = l->u.string;
	}
    }

    if (res) {
	(*realms)[0] = strdup(res);
	if ((*realms)[0] == NULL) {
	    free (*realms);
	    return ENOMEM;
	}
    } else {
	const char *dot = strchr (host, '.');

	if (dot == NULL)
	    dot = strchr (orig_host, '.');

	if (dot != NULL) {
	    (*realms)[0] = strdup (dot + 1);
	    if ((*realms)[0] == NULL) {
		free (*realms);
		return ENOMEM;
	    }
	    strupr ((*realms)[0]);
	} else {
	    ret = krb5_get_default_realm (context, *realms);
	    if (ret) {
		free (*realms);
		*realms = NULL;
		return KRB5_ERR_HOST_REALM_UNKNOWN;
	    }
	}
    }

    return 0;
}
