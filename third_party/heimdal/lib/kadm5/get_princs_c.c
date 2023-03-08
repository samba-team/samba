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
kadm5_c_get_principals(void *server_handle,
		       const char *expression,
		       char ***princs,
		       int *count)
{
    kadm5_client_context *context = server_handle;
    kadm5_ret_t ret;
    krb5_storage *sp;
    unsigned char buf[1024];
    int32_t tmp;
    krb5_data reply;
    int i;

    *count = 0;
    *princs = NULL;

    ret = _kadm5_connect(server_handle, 0 /* want_write */);
    if (ret)
	return ret;

    krb5_data_zero(&reply);

    sp = krb5_storage_from_mem(buf, sizeof(buf));
    if (sp == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }
    ret = krb5_store_int32(sp, kadm_get_princs);
    if (ret)
	goto out;
    ret = krb5_store_int32(sp, expression != NULL ? 1 : 0);
    if (ret)
	goto out;
    if (expression) {
	ret = krb5_store_string(sp, expression);
	if (ret)
	    goto out;
    }
    ret = _kadm5_client_send(context, sp);
    if (ret)
	goto out_keep_error;
    ret = _kadm5_client_recv(context, &reply);
    if (ret)
	goto out_keep_error;
    krb5_storage_free(sp);
    sp = krb5_storage_from_data (&reply);
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

    *princs = calloc(tmp + 1, sizeof(**princs));
    if (*princs == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }
    for (i = 0; i < tmp; i++) {
	ret = krb5_ret_string(sp, &(*princs)[i]);
	if (ret)
	    goto out;
    }
    *count = tmp;

  out:
    krb5_clear_error_message(context->context);

  out_keep_error:
    krb5_storage_free(sp);
    krb5_data_free(&reply);
    return ret;
}

kadm5_ret_t
kadm5_c_iter_principals(void *server_handle,
			const char *expression,
			int (*cb)(void *, const char *),
			void *cbdata)
{
    kadm5_client_context *context = server_handle;
    kadm5_ret_t ret;
    krb5_storage *sp;
    unsigned char buf[1024];
    int32_t tmp;
    krb5_data reply;
    size_t i;
    int stop = 0;

    ret = _kadm5_connect(server_handle, 0 /* want_write */);
    if (ret)
	return ret;

    krb5_data_zero(&reply);

    sp = krb5_storage_from_mem(buf, sizeof(buf));
    if (sp == NULL) {
	ret = krb5_enomem(context->context);
	goto out_keep_error;
    }
    ret = krb5_store_int32(sp, kadm_get_princs);
    if (ret)
	goto out;

    /*
     * Our protocol has an int boolean for this operation to indicate whether
     * there's an expression.  What we'll do here is that instead of sending
     * just false or trueish, for online iteration we'll send a number other
     * than 0 or 1 -- a magic value > 0 and < INT_MAX.
     *
     * In response we'll expect multiple replies, each with up to some small
     * number of principal names.  See kadmin/server.c.
     */
    ret = krb5_store_int32(sp, 0x55555555);
    if (ret)
	goto out;
    ret = krb5_store_string(sp, expression ? expression : "");
    if (ret)
        goto out;
    ret = _kadm5_client_send(context, sp);
    if (ret)
	goto out_keep_error;
    ret = _kadm5_client_recv(context, &reply);
    if (ret)
	goto out_keep_error;
    krb5_storage_free(sp);
    sp = krb5_storage_from_data (&reply);
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
        size_t n = -tmp;
        int more = 1;

        /* The server supports online iteration, hooray! */

        while (more) {
            /*
             * We expect any number of chunks, each having `n' names, except
             * the last one would have fewer than `n' (possibly zero, even).
             *
             * After that we expect one more reply with just a final return
             * code.
             */
            krb5_data_free(&reply);
            krb5_storage_free(sp);
            sp = NULL;
            ret = _kadm5_client_recv(context, &reply);
            if (ret == 0 && (sp = krb5_storage_from_data(&reply)) == NULL)
                ret = krb5_enomem(context->context);
            if (ret)
                goto out;

            /* Every chunk begins with a status code */
            ret = krb5_ret_int32(sp, &tmp);
            if (ret == 0)
                ret = tmp;
            if (ret)
                goto out;

            /* We expect up to -tmp principals per reply */
            for (i = 0; i < n; i++) {
                char *princ = NULL;

                ret = krb5_ret_string(sp, &princ);
                if (ret == HEIM_ERR_EOF) {
                    /* This was the last reply */
                    more = 0;
                    ret = 0;
                    break;
                }
                if (ret)
                    goto out;
                if (!stop) {
                    stop = cb(cbdata, princ);
                    if (stop) {
                        /*
                         * Tell the server to stop.
                         *
                         * We use a NOP for this, but with a payload that says
                         * "don't reply to the NOP" just in case the NOP
                         * arrives and is processed _after_ the LISTing has
                         * finished.
                         */
                        krb5_storage_free(sp);
                        if ((sp = krb5_storage_emem()) &&
                            krb5_store_int32(sp, kadm_nop) == 0 &&
                            krb5_store_int32(sp, 0))
                            (void) _kadm5_client_send(context, sp);
                    }
                }
                free(princ);
            }
        }
        /* Get the final result code */
        krb5_data_free(&reply);
        krb5_storage_free(sp);
        sp = NULL;
        ret = _kadm5_client_recv(context, &reply);
        if (ret == 0 && (sp = krb5_storage_from_data(&reply)) == NULL)
            ret = krb5_enomem(context->context);
        if (ret)
            goto out;
        ret = krb5_ret_int32(sp, &tmp);
        if (ret == 0)
            ret = tmp;
        if (!stop) {
            /*
             * Send our "interrupt" after the last chunk if we hand't
             * interrupted already.
             */
            krb5_storage_free(sp);
            if ((sp = krb5_storage_emem()) &&
                krb5_store_int32(sp, kadm_nop) == 0)
                (void) _kadm5_client_send(context, sp);
        }
    } else {
        size_t n = tmp;

        /* Old server -- listing not online */
        for (i = 0; i < n; i++) {
            char *princ = NULL;

            ret = krb5_ret_string(sp, &princ);
            if (ret)
                goto out;
            cb(cbdata, princ);
            free(princ);
        }
    }

out:
    krb5_clear_error_message(context->context);

out_keep_error:
    if (stop)
	ret = stop;
    krb5_storage_free(sp);
    krb5_data_free(&reply);
    return ret;
}
