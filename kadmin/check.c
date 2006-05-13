/*
 * Copyright (c) 2005 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors 
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

/*
 * Check database for strange configurations on default principals
 */

#include "kadmin_locl.h"
#include "kadmin-commands.h"

RCSID("$Id$");

static int
get_check_entry(const char *name, kadm5_principal_ent_rec *ent)
{
    krb5_error_code ret;
    krb5_principal principal;

    ret = krb5_parse_name(context, name, &principal);
    if (ret) {
	krb5_warn(context, ret, "krb5_unparse_name: %s", name);
	return 1;
    }

    memset(ent, 0, sizeof(*ent));
    ret = kadm5_get_principal(kadm_handle, principal, ent, 0);
    krb5_free_principal(context, principal);
    if(ret) {
	krb5_warn(context, ret, "kadm5_get_principal(%s) failed", name);
	return 1;
    }
    return 0;
}


int
check(void *opt, int argc, char **argv)
{
    kadm5_principal_ent_rec ent;
    krb5_error_code ret;
    char *realm, *p;

    if (argc == 0) {
	ret = krb5_get_default_realm(context, &realm);
	if (ret) {
	    krb5_warn(context, ret, "krb5_get_default_realm");
	    return 1;
	}
    } else {
	realm = strdup(argv[0]);
	if (realm == NULL) {
	    krb5_warnx(context, "malloc");
	    return 1;
	}
    }

    /*
     * Check krbtgt/REALM@REALM
     *
     * For now, just check existance
     */

    if (asprintf(&p, "%s/%s@%s", KRB5_TGS_NAME, realm, realm) == -1) {
	krb5_warn(context, errno, "asprintf");
	return 1;
    }

    ret = get_check_entry(p, &ent);
    if (ret) {
	printf("%s doesn't exist, are you sure %s is a realm in your database",
	       p, realm);
	free(p);
	return 1;
    }
    free(p);    

    kadm5_free_principal_ent(kadm_handle, &ent);

    /*
     * Check kadmin/admin@REALM
     */

    if (asprintf(&p, "kadmin/admin@%s", realm) == -1) {
	krb5_warn(context, errno, "asprintf");
	return 1;
    }

    ret = get_check_entry(p, &ent);
    if (ret) {
	printf("%s doesn't exist, "
	       "there is no way to do remote administration", p);
	free(p);
	return 1;
    }
    free(p);

    kadm5_free_principal_ent(kadm_handle, &ent);

    /*
     * Check kadmin/changepw@REALM
     */

    if (asprintf(&p, "kadmin/changepw@%s", realm) == -1) {
	krb5_warn(context, errno, "asprintf");
	return 1;
    }

    ret = get_check_entry(p, &ent);
    if (ret) {
	printf("%s doesn't exist, "
	       "there is no way to do change password", p);
	free(p);
	return 1;
    }
    free(p);

    kadm5_free_principal_ent(kadm_handle, &ent);


    return 0;
}
