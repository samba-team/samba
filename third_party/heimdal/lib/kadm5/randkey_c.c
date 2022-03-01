/*
 * Copyright (c) 1997 - 1999 Kungliga Tekniska Högskolan
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
kadm5_c_randkey_principal(void *server_handle,
			  krb5_principal princ,
			  krb5_boolean keepold,
			  int n_ks_tuple,
			  krb5_key_salt_tuple *ks_tuple,
			  krb5_keyblock **new_keys,
			  int *n_keys)
{
    kadm5_client_context *context = server_handle;
    kadm5_ret_t ret;
    krb5_storage *sp;
    unsigned char buf[1536];
    int32_t tmp;
    size_t i;
    krb5_data reply;
    krb5_keyblock *k;

    ret = _kadm5_connect(server_handle, 1 /* want_write */);
    if (ret)
	return ret;

    krb5_data_zero(&reply);

    sp = krb5_storage_from_mem(buf, sizeof(buf));
    if (sp == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }

    /*
     * NOTE WELL: This message is extensible.  It currently consists of:
     *
     *  - opcode (kadm_randkey)
     *  - principal name (princ)
     *
     * followed by optional items, each of which must be present if
     * there are any items following them that are also present:
     *
     *  - keepold boolean (whether to delete old kvnos)
     *  - number of key/salt type tuples
     *  - array of {enctype, salttype}
     *
     * Eventually we may add:
     *
     *  - opaque string2key parameters (salt, rounds, ...)
     */
    ret = krb5_store_int32(sp, kadm_randkey);
    if (ret == 0)
        ret = krb5_store_principal(sp, princ);

    if (ret == 0 && (keepold == TRUE || n_ks_tuple > 0))
	ret = krb5_store_uint32(sp, keepold);
    if (ret == 0 && n_ks_tuple > 0)
	ret = krb5_store_uint32(sp, n_ks_tuple);
    for (i = 0; ret == 0 && i < n_ks_tuple; i++) {
	ret = krb5_store_int32(sp, ks_tuple[i].ks_enctype);
        if (ret == 0)
            ret = krb5_store_int32(sp, ks_tuple[i].ks_salttype);
    }
    /* Future extensions go here */
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
    if (ret)
	goto out;

    ret = krb5_ret_int32(sp, &tmp);
    if (ret)
	goto out;
    if (tmp < 0) {
	ret = EOVERFLOW;
	goto out;
    }
    k = calloc(tmp, sizeof(*k));
    if (k == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }
    for (i = 0; ret == 0 && i < tmp; i++) {
	ret = krb5_ret_keyblock(sp, &k[i]);
	if (ret)
	    break;
    }
    if (ret == 0 && n_keys && new_keys) {
	*n_keys = tmp;
	*new_keys = k;
    } else {
	krb5_free_keyblock_contents(context->context, &k[i]);
	for (; i > 0; i--)
	    krb5_free_keyblock_contents(context->context, &k[i - 1]);
	free(k);
    }

  out:
    krb5_clear_error_message(context->context);

  out_keep_error:
    krb5_storage_free(sp);
    krb5_data_free(&reply);
    return ret;
}
