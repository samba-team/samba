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

#include "kadmin_locl.h"
#include <parse_units.h>

RCSID("$Id$");

struct units kdb_attrs[] = {
    { "new-princ", KRB5_KDB_NEW_PRINC },
    { "support-desmd5", KRB5_KDB_SUPPORT_DESMD5 },
    { "pwchange-service", KRB5_KDB_PWCHANGE_SERVICE },
    { "disallow-svr", KRB5_KDB_DISALLOW_SVR },
    { "requires-pw-change", KRB5_KDB_REQUIRES_PWCHANGE },
    { "requires-hw-auth", KRB5_KDB_REQUIRES_HW_AUTH },
    { "requires-pre-auth", KRB5_KDB_REQUIRES_PRE_AUTH },
    { "disallow-all-tix", KRB5_KDB_DISALLOW_ALL_TIX },
    { "disallow-dup-skey", KRB5_KDB_DISALLOW_DUP_SKEY },
    { "disallow-postdated", KRB5_KDB_DISALLOW_POSTDATED },
    { "disallow-forwardable", KRB5_KDB_DISALLOW_FORWARDABLE },
    { "disallow-tgt-based", KRB5_KDB_DISALLOW_TGT_BASED },
    { "disallow-renewable", KRB5_KDB_DISALLOW_RENEWABLE },
    { "disallow-proxiable", KRB5_KDB_DISALLOW_PROXIABLE },
    { NULL }
};

void
timeval2str(time_t t, char *str, size_t len, int include_time)
{
    if(t)
	if(include_time)
	    strftime(str, len, "%Y-%m-%d %H:%M:%S UTC", gmtime(&t));
	else
	    strftime(str, len, "%Y-%m-%d", gmtime(&t));
    else
	snprintf(str, len, "never");
}

void
deltat2str(unsigned t, char *str, size_t len)
{
    if(t)
	unparse_time(t, str, len);
    else
	snprintf(str, len, "unlimited");
}

int
str2deltat(const char *str, unsigned *delta)
{
    int res;

    if(strcasecmp(str, "unlimited") == 0) {
	*delta = 0;
	return 0;
    }
    res = parse_time(str, "day");
    if (res < 0)
	return res;
    else {
	*delta = res;
	return 0;
    }
}

void
attr2str(krb5_flags attributes, char *str, size_t len)
{
    unparse_flags (attributes, kdb_attrs, str, len);
}

int
str2attr(const char *str, krb5_flags *flags)
{
    int res;

    res = parse_flags (str, kdb_attrs, *flags);
    if (res < 0)
	return res;
    else {
	*flags = res;
	return 0;
    }
}

void
get_response(const char *prompt, const char *def, char *buf, size_t len)
{
    char *p;

    printf("%s [%s]:", prompt, def);
    if(fgets(buf, len, stdin) == NULL)
	*buf = '\0';
    p = strchr(buf, '\n');
    if(p)
	*p = '\0';
    if(strcmp(buf, "") == 0)
	strncpy(buf, def, len);
    buf[len-1] = 0;
}

int 
get_deltat(const char *prompt, const char *def, unsigned *delta)
{
    char buf[128];
    get_response(prompt, def, buf, sizeof(buf));
    return str2deltat(buf, delta);
}

static int
edit_time (const char *prompt, krb5_deltat *value, int *mask, int bit)
{
    char buf[1024], resp[1024];

    deltat2str(*value, buf, sizeof(buf));
    for (;;) {
	unsigned tmp;

	get_response(prompt, buf, resp, sizeof(resp));
	if (str2deltat(resp, &tmp) == 0) {
	    *value = tmp;
	    if (tmp)
		*mask |= bit;
	    break;
	} else if(*resp == '?') {
	    print_time_table (stderr);
	} else {
	    fprintf (stderr, "Unable to parse time '%s'\n", resp);
	}
    }
    return 0;
}

static int
edit_attributes (const char *prompt, krb5_flags *attr, int *mask, int bit)
{
    char buf[1024], resp[1024];

    attr2str(*attr, buf, sizeof(buf));
    for (;;) {
	krb5_flags tmp;

	get_response("Attributes", buf, resp, sizeof(resp));
	if (resp[0] == '\0')
	    break;
	else if (str2attr(resp, &tmp) == 0) {
	    *attr = tmp;
	    *mask |= bit;
	    break;
	} else if(*resp == '?') {
	    print_flags_table (kdb_attrs, stderr);
	} else {
	    fprintf (stderr, "Unable to parse '%s'\n", resp);
	}
    }
    return 0;
}

int
edit_entry(kadm5_principal_ent_t ent, int *mask)
{
    edit_time ("Max ticket life", &ent->max_life, mask,
	       KADM5_MAX_LIFE);
    edit_time ("Max renewable life", &ent->max_renewable_life, mask,
	       KADM5_MAX_RLIFE);
    edit_attributes ("Attributes", &ent->attributes, mask,
		     KADM5_ATTRIBUTES);
    return 0;
}

/* loop over all principals matching exp */
int
foreach_principal(const char *exp, 
		  int (*func)(krb5_principal, void*), 
		  void *data)
{
    char **princs;
    int num_princs;
    int i;
    krb5_error_code ret;
    krb5_principal princ_ent;
    ret = kadm5_get_principals(kadm_handle, exp, &princs, &num_princs);
    if(ret)
	return ret;
    for(i = 0; i < num_princs; i++) {
	ret = krb5_parse_name(context, princs[i], &princ_ent);
	if(ret){
	    krb5_warn(context, ret, "krb5_parse_name(%s)", princs[i]);
	    continue;
	}
	ret = (*func)(princ_ent, data);
	krb5_free_principal(context, princ_ent);
	if(ret) {
	    krb5_warn(context, ret, "%s", princs[i]);
	}
    }
    kadm5_free_name_list(kadm_handle, princs, &num_princs);
    return 0;
}

