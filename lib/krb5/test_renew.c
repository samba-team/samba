/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
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
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "krb5_locl.h"
#include <err.h>

RCSID("$Id: test_keytab.c 18809 2006-10-22 07:11:43Z lha $");


int
main(int argc, char **argv)
{
    krb5_principal client;
    krb5_context context;
    const char *in_tkt_service = NULL;
    krb5_ccache id;
    krb5_error_code ret;
    krb5_creds out;;

    memset(&out, 0, sizeof(out));

    setprogname(argv[0]);

    if (argc > 1)
	in_tkt_service = argv[1];

    ret = krb5_init_context(&context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context");

    ret = krb5_cc_default(context, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default");

    ret = krb5_cc_get_principal(context, id, &client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default");

    ret = krb5_get_renewed_creds(context,
				 &out,
				 client,
				 id,
				 in_tkt_service);

    if(ret)
	krb5_err(context, 1, ret, "krb5_get_kdc_cred");

    krb5_free_creds_contents(context, &out);

    krb5_free_context(context);

    return 0;
}
