/*
 * Copyright (c) 1997 - 2000, 2006 Kungliga Tekniska Högskolan
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

#include "kadm5_locl.h"

RCSID("$Id$");

kadm5_ret_t
kadm5_c_get_principal(void *server_handle,
		      krb5_principal princ,
		      kadm5_principal_ent_t ent,
		      uint32_t mask)
{
    kadm5_client_context *context = server_handle;
    kadm5_ret_t ret;
    krb5_storage *sp;
    unsigned char buf[1024];
    int32_t tmp;
    krb5_data reply;

    ret = _kadm5_connect(server_handle, 0 /* want_write */);
    if (ret)
	return ret;

    krb5_data_zero(&reply);

    sp = krb5_storage_from_mem(buf, sizeof(buf));
    if (sp == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }
    ret = krb5_store_int32(sp, kadm_get);
    if (ret)
	goto out;
    ret = krb5_store_principal(sp, princ);
    if (ret)
	goto out;
    ret = krb5_store_int32(sp, mask);
    if (ret)
	goto out;
    ret = _kadm5_client_send(context, sp);
    if (ret)
	goto out_keep_error;
    ret = _kadm5_client_recv(context, &reply);
    if (ret)
	goto out_keep_error;
    krb5_storage_free(sp);
    sp = krb5_storage_from_data(&reply);
    if (sp == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }
    ret = krb5_ret_int32(sp, &tmp);
    if (ret == 0)
	ret = tmp;

  out:
    krb5_clear_error_message(context->context);

  out_keep_error:
    if (ret == 0)
	ret = kadm5_ret_principal_ent(sp, ent);
    krb5_storage_free(sp);
    krb5_data_free(&reply);
    return ret;
}
