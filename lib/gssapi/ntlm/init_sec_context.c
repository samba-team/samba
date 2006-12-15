/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

static int
from_file(const char *fn, const char *domain,
	  char **username, char **password)
{	  
    char *str, buf[1024];
    FILE *f;

    f = fopen(fn, "r");
    if (f == NULL)
	return ENOENT;

    while (fgets(buf, sizeof(buf), f) != NULL) {
	char *d, *u, *p;
	buf[strcspn(buf, "\r\n")] = '\0';
	if (buf[0] == '#')
	    continue;
	str = NULL;
	d = strtok_r(buf, ":", &str);
	if (d && strcasecmp(domain, d) != 0)
	    continue;
	u = strtok_r(NULL, ":", &str);
	p = strtok_r(NULL, ":", &str);
	if (u == NULL || p == NULL)
	    continue;
	*username = strdup(u);
	*password = strdup(p);
	memset(buf, 0, sizeof(buf));
	fclose(f);
	return 0;
    }
    memset(buf, 0, sizeof(buf));
    fclose(f);
    return ENOENT;
}

static int
get_userinfo(const char *domain, char **username, char **password)
{
    const char *fn = NULL;

    if (!issuid()) {
	fn = getenv("NTLM_USER_FILE");
	if (fn != NULL && from_file(fn, domain, username, password) == 0)
	    return 0;
    }
    return ENOENT;
}


OM_uint32
_gss_ntlm_init_sec_context
           (OM_uint32 * minor_status,
            const gss_cred_id_t initiator_cred_handle,
            gss_ctx_id_t * context_handle,
            const gss_name_t target_name,
            const gss_OID mech_type,
            OM_uint32 req_flags,
            OM_uint32 time_req,
            const gss_channel_bindings_t input_chan_bindings,
            const gss_buffer_t input_token,
            gss_OID * actual_mech_type,
            gss_buffer_t output_token,
            OM_uint32 * ret_flags,
            OM_uint32 * time_rec
	   )
{
    ntlm_ctx ctx;
    ntlm_name name = (ntlm_name)target_name;

    *minor_status = 0;

    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = 0;
    if (actual_mech_type)
	*actual_mech_type = GSS_C_NO_OID;

    if (*context_handle == GSS_C_NO_CONTEXT) {
	krb5_error_code ret;
	struct ntlm_type1 type1;
	struct ntlm_buf data;
	
	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
	    *minor_status = EINVAL;
	    return GSS_S_FAILURE;
	}
	*context_handle = (gss_ctx_id_t)ctx;

	ret = get_userinfo(name->domain, &ctx->username, &ctx->password);
	if (ret) {
	    _gss_ntlm_delete_sec_context(minor_status, context_handle, NULL);
	    *minor_status = ret;
	    return GSS_S_FAILURE;
	}

	memset(&type1, 0, sizeof(type1));
	
	type1.flags = NTLM_NEG_UNICODE|NTLM_NEG_NTLM;
	type1.domain = name->domain;
	type1.hostname = NULL;
	type1.os[0] = 0;
	type1.os[1] = 0;
	
	ret = heim_ntlm_encode_type1(&type1, &data);
	if (ret) {
	    _gss_ntlm_delete_sec_context(minor_status, context_handle, NULL);
	    *minor_status = ret;
	    return GSS_S_FAILURE;
	}
	
	output_token->value = data.data;
	output_token->length = data.length;
	
	return GSS_S_CONTINUE_NEEDED;
    } else {
	krb5_error_code ret;
	struct ntlm_type2 type2;
	struct ntlm_type3 type3;
	struct ntlm_buf data;

	ctx = (ntlm_ctx)*context_handle;

	data.data = input_token->value;
	data.length = input_token->length;

	ret = heim_ntlm_decode_type2(&data, &type2);
	if (ret) {
	    _gss_ntlm_delete_sec_context(minor_status, context_handle, NULL);
	    *minor_status = ret;
	    return GSS_S_FAILURE;
	}

	/* XXX check that type2.targetinfo matches `target_name´ */

	memset(&type3, 0, sizeof(type3));

	type3.username = ctx->username;
	type3.flags = type2.flags;
	type3.targetname = type2.targetname;
	type3.ws = rk_UNCONST("workstation");

	{
	    struct ntlm_buf key;
	    heim_ntlm_nt_key(ctx->password, &key);
	    memset(ctx->password, 0, strlen(ctx->password));

	    heim_ntlm_calculate_ntlm1(key.data, key.length,
				      type2.challange,
				      &type3.ntlm);
	    free(key.data);
	}

	ret = heim_ntlm_encode_type3(&type3, &data);
	if (ret) {
	    _gss_ntlm_delete_sec_context(minor_status, context_handle, NULL);
	    *minor_status = ret;
	    return GSS_S_FAILURE;
	}

	output_token->length = data.length;
	output_token->value = data.data;

	if (actual_mech_type)
	    *actual_mech_type = GSS_NTLM_MECHANISM;
	if (ret_flags)
	    *ret_flags = ctx->flags;
	if (time_rec)
	    *time_rec = GSS_C_INDEFINITE;

	ctx->status |= STATUS_OPEN;

	return GSS_S_COMPLETE;
    }
}
