/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "krb5_locl.h"
#include <err.h>

RCSID("$Id$");

static void
test_alname(krb5_context context, krb5_realm realm,
	    const char *user, const char *inst, 
	    const char *localuser)
{
    krb5_principal p;
    char localname[1024];
    krb5_error_code ret;
    char *princ;

    ret = krb5_make_principal(context, &p, realm, user, inst, NULL);
    if (ret)
	krb5_err(context, 1, ret, "krb5_build_principal");

    ret = krb5_unparse_name(context, p, &princ);
    if (ret)
	krb5_err(context, 1, ret, "krb5_unparse_name");

    ret = krb5_aname_to_localname(context, p, sizeof(localname), localname);
    if (ret)
	krb5_err(context, 1, ret, "krb5_aname_to_localname: %s -> %s", princ, localuser);

    krb5_free_principal(context, p);
    free(princ);

    if (strcmp(localname, localuser) != 0)
	errx(1, "compared failed foo != %s", localname);
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    krb5_realm realm;
    char *user;

    setprogname(argv[0]);

    if (argc != 2)
	errx(1, "first argument should be a local user that in root .k5login");

    user = argv[1];

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    ret = krb5_get_default_realm(context, &realm);
    if (ret)
	krb5_err(context, 1, ret, "krb5_get_default_realm");

    test_alname(context, realm, user, NULL, user);
    test_alname(context, realm, user, "root", "root");

    krb5_free_context(context);

    return 0;
}
