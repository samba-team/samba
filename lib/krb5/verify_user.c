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

int
krb5_verify_user(krb5_context context, 
		 krb5_principal principal,
		 krb5_ccache ccache,
		 const char *password,
		 int secure,
		 const char *service)
{
    krb5_error_code ret;
    krb5_creds creds;
    char *realm;
    krb5_enctype *etypes;
    
    memset(&creds, 0, sizeof(creds));
    ret = krb5_copy_principal(context, principal, &creds.client);
    if(ret){
	return ret;
    }
    ret = krb5_get_default_realm(context, &realm);
    if(ret){
	return ret;
    }
    ret = krb5_build_principal(context, &creds.server,
			       strlen(realm),
			       realm,
			       "krbtgt",
			       realm,
			       NULL);
    if(ret){
	return ret;
    }
    
    ret = krb5_get_in_tkt_with_password(context,
					0,
					NULL,
					NULL,
					NULL,
					password, 
					ccache,
					&creds,
					NULL);
    if(ret)
	return ret;
    
    if(secure){
	krb5_auth_context auth_context = NULL;
	krb5_data req;
	
	ret = krb5_mk_req(context, &auth_context, 
			  0, 
			  (char*)service, 
			  NULL,
			  NULL, 
			  ccache,
			  &req);
	if(ret){
	    /* */
	    return ret;
	}
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL;
		    
	ret = krb5_rd_req(context, 
			  &auth_context,
			  &req,
			  NULL,
			  NULL,
			  NULL,
			  NULL);
	
	if(ret){
	    /* */
	    return ret;
	}
	krb5_data_free(&req);
    }
    return 0;
}
