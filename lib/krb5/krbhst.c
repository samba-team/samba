/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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

krb5_error_code
krb5_get_krbhst (krb5_context context,
		 const krb5_realm *realm,
		 char ***hostlist)
{
    char **res;
    unsigned max, count;
    krb5_config_binding *pointer;
    char *r;
    krb5_boolean done;
    char **tmp;

     r = *realm;

    count = 0;
    max = 10;
    res = malloc(max * sizeof(*res));
    if(res == NULL)
	return KRB5_REALM_UNKNOWN;
    pointer = NULL;
    for(done = FALSE; !done;) {
	char *h = (char *)krb5_config_get_next (context->cf,
						&pointer,
						krb5_config_string,
						"realms",
						r,
						"kdc",
						NULL);

	if (count > max - 2) {
	    max += 10;
	    tmp = realloc (res, max * sizeof(*res));
	    if (tmp == NULL) {
		res[count] = NULL;
		free (r);
		krb5_free_krbhst (context, res);
		return KRB5_REALM_UNKNOWN;
	    }
	    res = tmp;
	}
	if (h == NULL) {
	    done = TRUE;
	    asprintf(&res[count], "kerberos.%s", r);
	} else {
	    res[count] = strdup(h);
	}
	if (res[count] == NULL) {
	    free(r);
	    krb5_free_krbhst (context, res);
	    return KRB5_REALM_UNKNOWN;
	}
	++count;
    }

    /* There should always be room for the NULL here */
    res[count++] = NULL;
    tmp = realloc (res, count * sizeof(*res));
    if (tmp == NULL) {
	krb5_free_krbhst (context, res);
	return KRB5_REALM_UNKNOWN;
    }
    res = tmp;
    *hostlist = res;
    return 0;
}

krb5_error_code
krb5_free_krbhst (krb5_context context,
		  char **hostlist)
{
    char **p;

    for (p = hostlist; *p; ++p)
	free (*p);
    free (hostlist);
    return 0;
}
