/*
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska Högskolan
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

struct foreach_data {
    const char *exp;
    char *exp2;
    char **princs;
    size_t nalloced;
    size_t count;
};

static krb5_error_code
add_princ(krb5_context context, struct foreach_data *d, char *princ)
{

    if (d->count == INT_MAX)
        return ERANGE;
    if (d->nalloced == d->count) {
        size_t n = d->nalloced + (d->nalloced >> 1) + 128; /* No O(N^2) pls */
        char **tmp;

        if (SIZE_MAX / sizeof(*tmp) <= n)
            return ERANGE;
        if ((tmp = realloc(d->princs, n * sizeof(*tmp))) == NULL)
            return krb5_enomem(context);
        d->princs = tmp;
        d->nalloced = n;
    }
    d->princs[d->count++] = princ;
    return 0;
}

static krb5_error_code
foreach(krb5_context context, HDB *db, hdb_entry *ent, void *data)
{
    struct foreach_data *d = data;
    char *princ;
    krb5_error_code ret;
    ret = krb5_unparse_name(context, ent->principal, &princ);
    if(ret)
	return ret;
    if(d->exp){
	if(fnmatch(d->exp, princ, 0) == 0 || fnmatch(d->exp2, princ, 0) == 0)
	    ret = add_princ(context, d, princ);
	else
	    free(princ);
    }else{
	ret = add_princ(context, d, princ);
    }
    if(ret)
	free(princ);
    return ret;
}

kadm5_ret_t
kadm5_s_get_principals(void *server_handle,
		       const char *expression,
		       char ***princs,
		       int *count)
{
    struct foreach_data d;
    kadm5_server_context *context = server_handle;
    kadm5_ret_t ret = 0;

    if (!context->keep_open) {
	ret = context->db->hdb_open(context->context, context->db, O_RDONLY, 0);
	if (ret) {
	    krb5_warn(context->context, ret, "opening database");
	    return ret;
	}
    }
    d.exp = expression;
    d.exp2 = NULL;
    if (expression) {
	krb5_realm r;
	int aret;

	ret = krb5_get_default_realm(context->context, &r);
        if (ret == 0) {
            aret = asprintf(&d.exp2, "%s@%s", expression, r);
            free(r);
            if (aret == -1 || d.exp2 == NULL)
                ret = krb5_enomem(context->context);
        }
    }
    d.princs = NULL;
    d.nalloced = 0;
    d.count = 0;
    if (ret == 0)
        ret = hdb_foreach(context->context, context->db, HDB_F_ADMIN_DATA,
                          foreach, &d);

    if (ret == 0)
	ret = add_princ(context->context, &d, NULL);
    if (d.count >= INT_MAX)
        *count = INT_MAX;
    else
        *count = d.count - 1;
    if (ret == 0)
	*princs = d.princs;
    else
	kadm5_free_name_list(context, d.princs, count);
    free(d.exp2);
    if (!context->keep_open)
	context->db->hdb_close(context->context, context->db);
    return _kadm5_error_code(ret);
}

struct foreach_online_data {
    const char *exp;
    char *exp2;
    int (*cb)(void *, const char *);
    void *cbdata;
};

static krb5_error_code
foreach_online(krb5_context context, HDB *db, hdb_entry *ent, void *data)
{
    struct foreach_online_data *d = data;
    krb5_error_code ret;
    char *princ = NULL;

    ret = krb5_unparse_name(context, ent->principal, &princ);
    if (ret == 0) {
        if (!d->exp ||
            fnmatch(d->exp, princ, 0) == 0 || fnmatch(d->exp2, princ, 0) == 0)
            ret = d->cb(d->cbdata, princ);
        free(princ);
    }
    return ret;
}

kadm5_ret_t
kadm5_s_iter_principals(void *server_handle,
			const char *expression,
			int (*cb)(void *, const char *),
			void *cbdata)
{
    struct foreach_online_data d;
    kadm5_server_context *context = server_handle;
    kadm5_ret_t ret = 0;

    if (!context->keep_open) {
	ret = context->db->hdb_open(context->context, context->db, O_RDONLY, 0);
	if (ret) {
	    krb5_warn(context->context, ret, "opening database");
	    return ret;
	}
    }
    d.exp = expression;
    d.exp2 = NULL;
    d.cb = cb;
    d.cbdata = cbdata;
    if (expression) {
	krb5_realm r;
	int aret;

	ret = krb5_get_default_realm(context->context, &r);
        if (ret == 0) {
            aret = asprintf(&d.exp2, "%s@%s", expression, r);
            free(r);
            if (aret == -1 || d.exp2 == NULL)
                ret = krb5_enomem(context->context);
        }
    }
    if (ret == 0)
        ret = hdb_foreach(context->context, context->db, HDB_F_ADMIN_DATA,
                          foreach_online, &d);
    free(d.exp2);
    if (!context->keep_open)
	context->db->hdb_close(context->context, context->db);
    return _kadm5_error_code(ret);
}
