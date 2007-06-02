/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
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

#include "ntlm/ntlm.h"

RCSID("$Id$");

/*
 *
 */

struct ntlmkrb5 {
    krb5_context context;
    krb5_ntlm ntlm;
    krb5_realm kerberos_realm;
    krb5_ccache id;
    krb5_data opaque;
    OM_uint32 flags;
    struct ntlm_buf key;
    krb5_data sessionkey;
};

/*
 * Get credential cache that the ntlm code can use to talk to the KDC
 * using the digest API.
 */

static krb5_error_code
get_ccache(krb5_context context, krb5_ccache *id)
{
    krb5_principal principal = NULL;
    krb5_error_code ret;
    krb5_keytab kt;

    *id = NULL;
    
    if (!issuid()) {
	const char *cache;

	cache = getenv("NTLM_ACCEPTOR_CCACHE");
	if (cache) {
	    ret = krb5_cc_resolve(context, cache, id);
	    if (ret)
		goto out;
	    return 0;
	}
    }

    ret = krb5_sname_to_principal(context, NULL, "host", 
				  KRB5_NT_SRV_HST, &principal);
    if (ret)
	goto out;
    
    ret = krb5_cc_cache_match(context, principal, NULL, id);
    if (ret == 0)
	goto out;
    
    /* did not find in default credcache, lets try default keytab */
    ret = krb5_kt_default(context, &kt);
    if (ret)
	goto out;

    /* XXX check in keytab */
#if 0
    {
	krb5_creds cred = NULL;

	ret = krb5_get_init_creds_keytab (context,
					  &cred,
					  principal,
					  kt,
					  NULL,
					  NULL,
					  NULL);
	if (ret)
	    goto out;
	ret = krb5_cc_initialize (context, ccache, cred.client);
	ret = krb5_cc_store_cred (context, ccache, &cred);
	krb5_free_cred_contents (context, &cred);
    }
#endif
    krb5_kt_close(context, kt);
    
out:
    if (principal)
	krb5_free_principal(context, principal);
    return ret;
}

/*
 *
 */

static OM_uint32
kdc_alloc(OM_uint32 *minor, void **ctx)
{
    krb5_error_code ret;
    struct ntlmkrb5 *c;

    c = calloc(1, sizeof(*c));

    ret = krb5_init_context(&c->context);
    if (ret) {
	/* free */
	*minor = ret;
	return GSS_S_FAILURE;
    }

    ret = get_ccache(c->context, &c->id);
    if (ret) {
	/* free */
	*minor = ret;
	return GSS_S_FAILURE;
    }

    ret = krb5_ntlm_alloc(c->context, &c->ntlm);
    if (ret) {
	/* free */
	*minor = ret;
	return GSS_S_FAILURE;
    }

    *ctx = c;

    return GSS_S_COMPLETE;
}

/*
 *
 */

static OM_uint32
kdc_destroy(OM_uint32 *minor, void *ctx)
{
    struct ntlmkrb5 *c = ctx;
    krb5_data_free(&c->opaque);
    krb5_data_free(&c->sessionkey);
    return GSS_S_COMPLETE;
}

/*
 *
 */

static OM_uint32
kdc_type2(OM_uint32 *minor_status,
	  void *ctx,
	  uint32_t flags,
	  const char *hostname,
	  const char *domain,
	  uint32_t *ret_flags,
	  struct ntlm_buf *out)
{
    struct ntlmkrb5 *c = ctx;
    krb5_error_code ret;
    struct ntlm_type2 type2;
    krb5_data challange;
    struct ntlm_buf data;
    krb5_data ti;
    
    memset(&type2, 0, sizeof(type2));
    
    /*
     * Request data for type 2 packet from the KDC.
     */
    ret = krb5_ntlm_init_request(c->context, 
				 c->ntlm,
				 NULL,
				 c->id,
				 flags,
				 hostname,
				 domain);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    /*
     *
     */

    ret = krb5_ntlm_init_get_opaque(c->context, c->ntlm, &c->opaque);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    /*
     *
     */

    ret = krb5_ntlm_init_get_flags(c->context, c->ntlm, &type2.flags);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    *ret_flags = type2.flags;

    ret = krb5_ntlm_init_get_challange(c->context, c->ntlm, &challange);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    if (challange.length != sizeof(type2.challange)) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }
    memcpy(type2.challange, challange.data, sizeof(type2.challange));
    krb5_data_free(&challange);

    ret = krb5_ntlm_init_get_targetname(c->context, c->ntlm,
					&type2.targetname);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    ret = krb5_ntlm_init_get_targetinfo(c->context, c->ntlm, &ti);
    if (ret) {
	free(type2.targetname);
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    type2.targetinfo.data = ti.data;
    type2.targetinfo.length = ti.length;
	
    ret = heim_ntlm_encode_type2(&type2, &data);
    free(type2.targetname);
    krb5_data_free(&ti);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
	
    out->data = data.data;
    out->length = data.length;

    return GSS_S_COMPLETE;
}

/*
 *
 */

static OM_uint32
kdc_type3(OM_uint32 *minor_status,
	  void *ctx,
	  const struct ntlm_type3 *type3,
	  struct ntlm_buf *sessionkey)
{
    struct ntlmkrb5 *c = ctx;
    krb5_error_code ret;

    sessionkey->data = NULL;
    sessionkey->length = 0;

    ret = krb5_ntlm_req_set_flags(c->context, c->ntlm, type3->flags);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_username(c->context, c->ntlm, type3->username);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_targetname(c->context, c->ntlm, 
				       type3->targetname);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_lm(c->context, c->ntlm, 
			       type3->lm.data, type3->lm.length);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_ntlm(c->context, c->ntlm, 
				 type3->ntlm.data, type3->ntlm.length);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_opaque(c->context, c->ntlm, &c->opaque);
    if (ret) goto out;

    if (type3->sessionkey.length) {
	ret = krb5_ntlm_req_set_session(c->context, c->ntlm,
					type3->sessionkey.data,
					type3->sessionkey.length);
	if (ret) goto out;
    }

    /*
     * Verify with the KDC the type3 packet is ok
     */
    ret = krb5_ntlm_request(c->context, 
			    c->ntlm,
			    NULL,
			    c->id);
    if (ret)
	goto out;

    if (krb5_ntlm_rep_get_status(c->context, c->ntlm) != TRUE) {
	ret = EINVAL;
	goto out;
    }

    if (type3->sessionkey.length) {
	ret = krb5_ntlm_rep_get_sessionkey(c->context, 
					   c->ntlm,
					   &c->sessionkey);
	if (ret)
	    goto out;

	sessionkey->data = c->sessionkey.data;
	sessionkey->length = c->sessionkey.length;
    }

    return 0;

 out:
    *minor_status = ret;
    return GSS_S_FAILURE;
}

/*
 *
 */

static void
kdc_free_buffer(struct ntlm_buf *sessionkey)
{
    if (sessionkey->data)
	free(sessionkey->data);
    sessionkey->data = NULL;
    sessionkey->length = 0;
}

/*
 *
 */

struct ntlm_server_interface ntlmsspi_kdc_digest = {
    kdc_alloc,
    kdc_destroy,
    kdc_type2,
    kdc_type3,
    kdc_free_buffer
};
