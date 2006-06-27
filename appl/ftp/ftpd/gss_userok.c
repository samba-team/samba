/*
 * Copyright (c) 1998 - 2001 Kungliga Tekniska Högskolan
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

#include "ftpd_locl.h"
#include <gssapi.h>
#include <krb5.h>

RCSID("$Id$");

/* XXX a bit too much of krb5 dependency here... 
   What is the correct way to do this? 
   */

/* XXX sync with gssapi.c */
struct gss_data {
    gss_ctx_id_t context_hdl;
    char *client_name;
    gss_cred_id_t delegated_cred_handle;
};

int gss_userok(void*, char*); /* to keep gcc happy */

int
gss_userok(void *app_data, char *username)
{
    struct gss_data *data = app_data;
    krb5_context context;
    krb5_error_code ret;
    krb5_principal client;
    OM_uint32 minor_status;

    ret = krb5_init_context(&context);
    if (ret)
	return 1;

    ret = krb5_parse_name(context, data->client_name, &client);
    if(ret) {
	krb5_free_context(context);
	return 1;
    }
    ret = krb5_kuserok(context, client, username);
    if (!ret) {
	krb5_free_principal(context, client);
	krb5_free_context(context);
	return 1;
    }
        
    ret = 0;
        
    /* more of krb-depend stuff :-( */
    /* gss_add_cred() ? */
    if (data->delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
	krb5_ccache ccache = NULL; 
	const char* ticketfile;
	struct passwd *kpw;
           
	ret = krb5_cc_gen_new(context, &krb5_fcc_ops, &ccache);
	if (ret)
	    goto fail;
	   
	ticketfile = krb5_cc_get_name(context, ccache);
        
	ret = gss_krb5_copy_ccache(&minor_status,
				   data->delegated_cred_handle,
				   ccache);
	if (ret) {
	    ret = 0;
	    goto fail;
	}
           
	do_destroy_tickets = 1;

	kpw = getpwnam(username);
           
	if (kpw == NULL) {
	    unlink(ticketfile);
	    ret = 1;
	    goto fail;
	}

	chown (ticketfile, kpw->pw_uid, kpw->pw_gid);
           
	if (asprintf(&k5ccname, "FILE:%s", ticketfile) != -1) {
	    esetenv ("KRB5CCNAME", k5ccname, 1);
	}
	afslog(NULL, 1);
    fail:
	if (ccache)
	    krb5_cc_close(context, ccache); 
    }
           
    gss_release_cred(&minor_status, &data->delegated_cred_handle);
    krb5_free_principal(context, client);
    krb5_free_context(context);
    return ret;
}
