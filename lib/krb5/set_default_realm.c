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

RCSID("$Id$");

/*
 * Convert the config binding in `b' (consisting of strings) to a
 * NULL-terminated list of strings in `list'.  All memory is
 * dynamically allocated.  Return an error code.
 */

static krb5_error_code
config_binding_to_list (const krb5_config_binding *b,
			krb5_realm **list)
{
    int n, i, j;
    const krb5_config_binding *p;

    for (n = 1, p = b; p != NULL; p = p->next)
	++n;
    *list = malloc (n * sizeof(**list));
    if (*list == NULL)
	return ENOMEM;
    for (i = 0; i < n; ++i)
	(*list)[i] = NULL;
    for (i = 0, p = b; p != NULL; ++i, p = p->next) {
	if (p->type != krb5_config_string)
	    continue;
	(*list)[i] = strdup(p->u.string);
	if ((*list)[i] == NULL) {
	    for (j = 0; j < i; ++j)
		free ((*list)[j]);
	    free (*list);
	    return ENOMEM;
	}
    }
    return 0;
}

/*
 * Convert the simple string `s' into a NULL-terminated and freshly allocated 
 * list in `list'.  Return an error code.
 */

static krb5_error_code
string_to_list (const char *s, krb5_realm **list)
{

    *list = malloc (2 * sizeof(**list));
    if (*list == NULL)
	return ENOMEM;
    (*list)[0] = strdup (s);
    if ((*list)[0] == NULL) {
	free (*list);
	return ENOMEM;
    }
    (*list)[1] = NULL;
    return 0;
}

/*
 * Set the knowledge of the default realm(s) in `context'.
 * If realm != NULL, that's the new default realm.
 * Otherwise, the realm(s) are figured out from configuration or DNS.  
 */

krb5_error_code
krb5_set_default_realm(krb5_context context,
		       char *realm)
{
    krb5_error_code ret;
    const char *tmp;
    krb5_realm *realms = NULL;
    const krb5_config_binding *b;

    if (realm == NULL) {
	tmp = krb5_config_get_string (context, NULL,
				      "libdefaults",
				      "default_realm",
				      NULL);
	if (tmp == NULL) {
	    b = krb5_config_get_list (context, NULL,
				      "libdefaults",
				      "default_realm",
				      NULL);
	    if (b == NULL)
		ret = krb5_get_host_realm(context, NULL, &realms);
	    else
		ret = config_binding_to_list (b, &realms);
	} else {
	    ret = string_to_list (tmp, &realms);
	}
    } else {
	ret = string_to_list (realm, &realms);
    }
    if (ret)
	return ret;
    krb5_free_host_realm (context, context->default_realms);
    context->default_realms = realms;
    return 0;
}
