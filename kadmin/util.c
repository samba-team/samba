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
timeval2str(time_t t, char *str, size_t len)
{
    if(t)
	strftime(str, len, "%Y-%m-%d %H:%M:%S UTC", gmtime(&t));
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

unsigned
str2deltat(const char *str)
{
    if(strcasecmp(str, "unlimited") == 0)
	return 0;
    return parse_time(str, "day");
}

void
attr2str(krb5_flags attributes, char *str, size_t len)
{
    unparse_flags (attributes, kdb_attrs, str, len);
}

krb5_flags
str2attr(const char *str, krb5_flags orig)
{
    int res = parse_flags (str, kdb_attrs, orig);
    if(res == -1)
	return orig; /* XXX */
    return res;
}

void
get_response(const char *prompt, const char *def, char *buf, size_t len)
{
    char *p;
    printf("%s [%s]:", prompt, def);
    fgets(buf, len, stdin);
    p = strchr(buf, '\n');
    if(p) *p = 0;
    if(strcmp(buf, "") == 0)
	strncpy(buf, def, len);
    buf[len-1] = 0;
}

unsigned 
get_deltat(const char *prompt, const char *def)
{
    char buf[128];
    get_response(prompt, def, buf, sizeof(buf));
    return str2deltat(buf);
}

int
edit_entry(kadm5_principal_ent_t ent, int *mask)
{
    char buf[1024], resp[1024];
    
    deltat2str(ent->max_life, buf, sizeof(buf));
    ent->max_life = get_deltat("Max ticket life", buf);
    *mask |= KADM5_MAX_LIFE;

    deltat2str(ent->max_renewable_life, buf, sizeof(buf));
    ent->max_renewable_life = get_deltat("Max renewable life", buf);
    *mask |= KADM5_MAX_RLIFE;
    
    attr2str(ent->attributes, buf, sizeof(buf));
    get_response("Attributes", buf, resp, sizeof(resp));
    ent->attributes = str2attr(resp, ent->attributes);
    *mask |= KADM5_ATTRIBUTES;
    return 0;
}
