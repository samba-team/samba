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

#define CHECK(e) do { if ((ret = e)) goto out; } while (0)

int
kadm5_some_keys_are_bogus(size_t n_keys, krb5_key_data *keys)
{
    size_t i;

    for (i = 0; i < n_keys; i++) {
	krb5_key_data *key = &keys[i];
	if (key->key_data_length[0] == sizeof(KADM5_BOGUS_KEY_DATA) - 1 &&
	    ct_memcmp(key->key_data_contents[1], KADM5_BOGUS_KEY_DATA,
		      key->key_data_length[0]) == 0)
	    return 1;
    }
    return 0;
}

int
kadm5_all_keys_are_bogus(size_t n_keys, krb5_key_data *keys)
{
    size_t i;

    if (n_keys == 0)
	return 0;

    for (i = 0; i < n_keys; i++) {
	krb5_key_data *key = &keys[i];
	if (key->key_data_length[0] != sizeof(KADM5_BOGUS_KEY_DATA) - 1 ||
	    ct_memcmp(key->key_data_contents[1], KADM5_BOGUS_KEY_DATA,
		      key->key_data_length[0]) != 0)
	    return 0;
    }
    return 1;
}

kadm5_ret_t
kadm5_store_key_data(krb5_storage *sp,
		     krb5_key_data *key)
{
    kadm5_ret_t ret;
    krb5_data c;

    CHECK(krb5_store_int32(sp, key->key_data_ver));
    CHECK(krb5_store_int32(sp, key->key_data_kvno));
    CHECK(krb5_store_int32(sp, key->key_data_type[0]));
    c.length = key->key_data_length[0];
    c.data = key->key_data_contents[0];
    CHECK(krb5_store_data(sp, c));
    CHECK(krb5_store_int32(sp, key->key_data_type[1]));
    c.length = key->key_data_length[1];
    c.data = key->key_data_contents[1];
    CHECK(krb5_store_data(sp, c));

out:
    return ret;
}

kadm5_ret_t
kadm5_store_fake_key_data(krb5_storage *sp,
		          krb5_key_data *key)
{
    kadm5_ret_t ret;
    krb5_data c;

    CHECK(krb5_store_int32(sp, key->key_data_ver));
    CHECK(krb5_store_int32(sp, key->key_data_kvno));
    CHECK(krb5_store_int32(sp, key->key_data_type[0]));

    /*
     * This is the key contents.  We want it to be obvious to the client
     * (if it really did want the keys) that the key won't work.
     * 32-bit keys are no good for any enctype, so that should do.
     * Clients that didn't need keys will ignore this, and clients that
     * did want keys will either fail or they'll, say, create bogus
     * keytab entries that will subsequently fail to be useful.
     */
    c.length = sizeof (KADM5_BOGUS_KEY_DATA) - 1;
    c.data = KADM5_BOGUS_KEY_DATA;
    CHECK(krb5_store_data(sp, c));

    /* This is the salt -- no need to send garbage */
    CHECK(krb5_store_int32(sp, key->key_data_type[1]));
    c.length = key->key_data_length[1];
    c.data = key->key_data_contents[1];
    CHECK(krb5_store_data(sp, c));

out:
    return ret;
}

kadm5_ret_t
kadm5_ret_key_data(krb5_storage *sp,
		   krb5_key_data *key)
{
    kadm5_ret_t ret;
    krb5_data c;
    int32_t tmp;

    ret = krb5_ret_int32(sp, &tmp);
    if (ret == 0) {
        key->key_data_ver = tmp;
        ret = krb5_ret_int32(sp, &tmp);
    }
    if (ret == 0) {
        key->key_data_kvno = tmp;
        ret = krb5_ret_int32(sp, &tmp);
    }
    if (ret == 0) {
        key->key_data_type[0] = tmp;
        ret = krb5_ret_data(sp, &c);
    }
    if (ret == 0) {
        key->key_data_length[0] = c.length;
        key->key_data_contents[0] = c.data;
        ret = krb5_ret_int32(sp, &tmp);
    }
    if (ret == 0) {
        key->key_data_type[1] = tmp;
        ret = krb5_ret_data(sp, &c);
    }
    if (ret == 0) {
        key->key_data_length[1] = c.length;
        key->key_data_contents[1] = c.data;
        return 0;
    }
    return KADM5_FAILURE;
}

kadm5_ret_t
kadm5_store_tl_data(krb5_storage *sp,
		    krb5_tl_data *tl)
{
    kadm5_ret_t ret;
    krb5_data c;

    CHECK(krb5_store_int32(sp, tl->tl_data_type));
    c.length = tl->tl_data_length;
    c.data = tl->tl_data_contents;
    CHECK(krb5_store_data(sp, c));

out:
    return ret;
}

kadm5_ret_t
kadm5_ret_tl_data(krb5_storage *sp,
		  krb5_tl_data *tl)
{
    kadm5_ret_t ret;
    krb5_data c;
    int32_t tmp;

    CHECK(krb5_ret_int32(sp, &tmp));
    tl->tl_data_type = tmp;
    CHECK(krb5_ret_data(sp, &c));
    tl->tl_data_length = c.length;
    tl->tl_data_contents = c.data;

out:
    return ret;
}

static kadm5_ret_t
store_principal_ent(krb5_storage *sp,
		    kadm5_principal_ent_t princ,
		    uint32_t mask, int wkeys)
{
    kadm5_ret_t ret = 0;
    int i;

    if (mask & KADM5_PRINCIPAL)
	CHECK(krb5_store_principal(sp, princ->principal));
    if (mask & KADM5_PRINC_EXPIRE_TIME)
	CHECK(krb5_store_int32(sp, princ->princ_expire_time));
    if (mask & KADM5_PW_EXPIRATION)
	CHECK(krb5_store_int32(sp, princ->pw_expiration));
    if (mask & KADM5_LAST_PWD_CHANGE)
	CHECK(krb5_store_int32(sp, princ->last_pwd_change));
    if (mask & KADM5_MAX_LIFE)
	CHECK(krb5_store_int32(sp, princ->max_life));
    if (mask & KADM5_MOD_NAME) {
	CHECK(krb5_store_int32(sp, princ->mod_name != NULL));
	if(princ->mod_name)
	    CHECK(krb5_store_principal(sp, princ->mod_name));
    }
    if (mask & KADM5_MOD_TIME)
	CHECK(krb5_store_int32(sp, princ->mod_date));
    if (mask & KADM5_ATTRIBUTES)
	CHECK(krb5_store_int32(sp, princ->attributes));
    if (mask & KADM5_KVNO)
	CHECK(krb5_store_int32(sp, princ->kvno));
    if (mask & KADM5_MKVNO)
	CHECK(krb5_store_int32(sp, princ->mkvno));
    if (mask & KADM5_POLICY) {
	CHECK(krb5_store_int32(sp, princ->policy != NULL));
	if(princ->policy)
	    CHECK(krb5_store_string(sp, princ->policy));
    }
    if (mask & KADM5_AUX_ATTRIBUTES)
	CHECK(krb5_store_int32(sp, princ->aux_attributes));
    if (mask & KADM5_MAX_RLIFE)
	CHECK(krb5_store_int32(sp, princ->max_renewable_life));
    if (mask & KADM5_LAST_SUCCESS)
	CHECK(krb5_store_int32(sp, princ->last_success));
    if (mask & KADM5_LAST_FAILED)
	CHECK(krb5_store_int32(sp, princ->last_failed));
    if (mask & KADM5_FAIL_AUTH_COUNT)
	CHECK(krb5_store_int32(sp, princ->fail_auth_count));
    if (mask & KADM5_KEY_DATA) {
	CHECK(krb5_store_int32(sp, princ->n_key_data));
	for(i = 0; i < princ->n_key_data; i++) {
	    if (wkeys)
		CHECK(kadm5_store_key_data(sp, &princ->key_data[i]));
            else
                CHECK(kadm5_store_fake_key_data(sp, &princ->key_data[i]));
	}
    }
    if (mask & KADM5_TL_DATA) {
	krb5_tl_data *tp;

	CHECK(krb5_store_int32(sp, princ->n_tl_data));
	for (tp = princ->tl_data; tp; tp = tp->tl_data_next)
	    CHECK(kadm5_store_tl_data(sp, tp));
    }

out:
    return ret;
}


kadm5_ret_t
kadm5_store_principal_ent(krb5_storage *sp,
			  kadm5_principal_ent_t princ)
{
    return store_principal_ent (sp, princ, ~0, 1);
}

kadm5_ret_t
kadm5_store_principal_ent_nokeys(krb5_storage *sp,
			        kadm5_principal_ent_t princ)
{
    return store_principal_ent (sp, princ, ~0, 0);
}

kadm5_ret_t
kadm5_store_principal_ent_mask(krb5_storage *sp,
			       kadm5_principal_ent_t princ,
			       uint32_t mask)
{
    kadm5_ret_t ret;

    ret = krb5_store_int32(sp, mask);
    if (ret == 0)
        ret = store_principal_ent(sp, princ, mask, 1);
    return ret;
}

static kadm5_ret_t
ret_principal_ent(krb5_storage *sp,
		  kadm5_principal_ent_t princ,
		  uint32_t mask)
{
    kadm5_ret_t ret = 0;
    int i;
    int32_t tmp;

    if (mask & KADM5_PRINCIPAL)
	CHECK(krb5_ret_principal(sp, &princ->principal));

    if (mask & KADM5_PRINC_EXPIRE_TIME) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->princ_expire_time = tmp;
    }
    if (mask & KADM5_PW_EXPIRATION) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->pw_expiration = tmp;
    }
    if (mask & KADM5_LAST_PWD_CHANGE) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->last_pwd_change = tmp;
    }
    if (mask & KADM5_MAX_LIFE) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->max_life = tmp;
    }
    if (mask & KADM5_MOD_NAME) {
	CHECK(krb5_ret_int32(sp, &tmp));
	if(tmp)
	    CHECK(krb5_ret_principal(sp, &princ->mod_name));
	else
	    princ->mod_name = NULL;
    }
    if (mask & KADM5_MOD_TIME) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->mod_date = tmp;
    }
    if (mask & KADM5_ATTRIBUTES) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->attributes = tmp;
    }
    if (mask & KADM5_KVNO) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->kvno = tmp;
    }
    if (mask & KADM5_MKVNO) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->mkvno = tmp;
    }
    if (mask & KADM5_POLICY) {
	CHECK(krb5_ret_int32(sp, &tmp));
	if(tmp)
	    CHECK(krb5_ret_string(sp, &princ->policy));
	else
	    princ->policy = NULL;
    }
    if (mask & KADM5_AUX_ATTRIBUTES) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->aux_attributes = tmp;
    }
    if (mask & KADM5_MAX_RLIFE) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->max_renewable_life = tmp;
    }
    if (mask & KADM5_LAST_SUCCESS) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->last_success = tmp;
    }
    if (mask & KADM5_LAST_FAILED) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->last_failed = tmp;
    }
    if (mask & KADM5_FAIL_AUTH_COUNT) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->fail_auth_count = tmp;
    }
    if (mask & KADM5_KEY_DATA) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->n_key_data = tmp;
	princ->key_data = calloc(princ->n_key_data, sizeof(*princ->key_data));
	if (princ->key_data == NULL && princ->n_key_data != 0)
	    return ENOMEM;
	for(i = 0; i < princ->n_key_data; i++)
	    CHECK(kadm5_ret_key_data(sp, &princ->key_data[i]));
    }
    if (mask & KADM5_TL_DATA) {
	CHECK(krb5_ret_int32(sp, &tmp));
	princ->n_tl_data = tmp;
	princ->tl_data = NULL;
	for(i = 0; i < princ->n_tl_data; i++){
	    krb5_tl_data *tp = malloc(sizeof(*tp));
	    if (tp == NULL) {
                ret = ENOMEM;
                goto out;
            }
	    ret = kadm5_ret_tl_data(sp, tp);
            if (ret == 0) {
                tp->tl_data_next = princ->tl_data;
                princ->tl_data = tp;
            } else {
                free(tp);
                goto out;
            }
	}
    }

out:
    /* Can't free princ here -- we don't have a context */
    return ret;
}

kadm5_ret_t
kadm5_ret_principal_ent(krb5_storage *sp,
			kadm5_principal_ent_t princ)
{
    return ret_principal_ent (sp, princ, ~0);
}

kadm5_ret_t
kadm5_ret_principal_ent_mask(krb5_storage *sp,
			     kadm5_principal_ent_t princ,
			     uint32_t *mask)
{
    kadm5_ret_t ret;
    int32_t tmp;

    ret = krb5_ret_int32 (sp, &tmp);
    if (ret) {
        *mask = 0;
        return ret;
    }
    *mask = tmp;
    return ret_principal_ent (sp, princ, *mask);
}

kadm5_ret_t
_kadm5_marshal_params(krb5_context context,
		      kadm5_config_params *params,
		      krb5_data *out)
{
    kadm5_ret_t ret;

    krb5_storage *sp = krb5_storage_emem();
    if (sp == NULL)
	return krb5_enomem(context);

    ret = krb5_store_int32(sp, params->mask & (KADM5_CONFIG_REALM));
    if (ret == 0 && (params->mask & KADM5_CONFIG_REALM))
	ret = krb5_store_string(sp, params->realm);
    if (ret == 0)
        ret = krb5_storage_to_data(sp, out);
    krb5_storage_free(sp);
    return ret;
}

kadm5_ret_t
_kadm5_unmarshal_params(krb5_context context,
			krb5_data *in,
			kadm5_config_params *params)
{
    kadm5_ret_t ret;
    krb5_storage *sp;
    int32_t mask;

    sp = krb5_storage_from_data(in);
    if (sp == NULL)
	return ENOMEM;

    ret = krb5_ret_int32(sp, &mask);
    if (ret)
	goto out;
    params->mask = mask;

    if(params->mask & KADM5_CONFIG_REALM)
	ret = krb5_ret_string(sp, &params->realm);
 out:
    krb5_storage_free(sp);

    return ret;
}

#ifdef TEST
#include <getarg.h>
#include <krb5-protos.h>
#include <hex.h>

static int version_flag;
static int help_flag;
static int verbose_flag;
static int in_text_flag = 0;
static int in_binary_flag = 0;
static int out_hex_flag = 0;
static int out_binary_flag = 0;
static int must_round_trip_flag = 0;
static char *byteorder_string_in_string;
static char *byteorder_string_out_string;
static struct getargs args[] = {
    { "version", '\0', arg_flag, &version_flag,
        "Version", NULL },
    { "help", '\0', arg_flag, &help_flag,
        "Show this message", NULL },
    { "verbose", 'v', arg_flag, &verbose_flag, NULL, NULL },
    { "in-text", '\0', arg_flag, &in_text_flag,
        "Input is a text \"recipe\"", NULL },
    { "in-binary", '\0', arg_flag, &in_binary_flag,
        "Input is binary", NULL },
    { "out-hex", '\0', arg_flag, &out_hex_flag,
        "Output hex", NULL },
    { "out-binary", '\0', arg_flag, &out_binary_flag,
        "Output binary", NULL },
    { "must-round-trip", '\0', arg_flag, &must_round_trip_flag,
        "Check that encoding and decoding round-trip", NULL },
    { "byte-order-out", '\0', arg_string, &byteorder_string_out_string,
        "Output byte order", "host, network, be, or le" },
    { "byte-order-in", '\0', arg_string, &byteorder_string_in_string,
        "Input byte order", "host, network, packed, be, or le" },
};

#define DO_TYPE1(t, r, s)               \
    if (strcmp(type, #t) == 0) {        \
        t v;                            \
        ret = r(in, &v);                \
        if (ret == 0)                   \
            ret = s(out, v);            \
        return ret;                     \
    }

#define DO_TYPE2(t, r, s)               \
    if (strcmp(type, #t) == 0) {        \
        t v;                            \
        ret = r(in, &v);                \
        if (ret == 0)                   \
            ret = s(out, &v);           \
        return ret;                     \
    }

static krb5_error_code
reencode(const char *type, krb5_storage *in, krb5_storage *out)
{
    krb5_error_code ret;

    krb5_storage_seek(in, 0, SEEK_SET);

    /*
     * TODO: When --verbose print a visual representation of the value.
     *
     *       We have functionality in lib/krb5 for that for krb5_principal and
     *       krb5_address, but not any of the others.  Adding krb5_print_*()
     *       and kadm5_print_*() functions just for this program to use seems
     *       annoying.
     */
    DO_TYPE1(krb5_keyblock, krb5_ret_keyblock, krb5_store_keyblock);
    DO_TYPE1(krb5_principal, krb5_ret_principal, krb5_store_principal);
    DO_TYPE1(krb5_times, krb5_ret_times, krb5_store_times);
    DO_TYPE1(krb5_address, krb5_ret_address, krb5_store_address);
    DO_TYPE1(krb5_addresses, krb5_ret_addrs, krb5_store_addrs);
    DO_TYPE1(krb5_authdata, krb5_ret_authdata, krb5_store_authdata);

    DO_TYPE2(krb5_creds, krb5_ret_creds, krb5_store_creds);
    DO_TYPE2(krb5_key_data, kadm5_ret_key_data, kadm5_store_key_data);
    DO_TYPE2(krb5_tl_data, kadm5_ret_tl_data, kadm5_store_tl_data);
    DO_TYPE2(kadm5_principal_ent_rec, kadm5_ret_principal_ent,
             kadm5_store_principal_ent);

    return ENOTSUP;
}

static krb5_error_code
eval_recipe1(krb5_storage *sp, const char *typ, const char *val)
{
    krb5_error_code ret;
    uint64_t vu = 0;
    int64_t vi = 0;
    int consumed = 0;

    if (strncmp(typ, "int", sizeof("int") - 1) == 0) {
        if (sscanf(val, "%"PRIi64"%n", &vi, &consumed) != 1)
            return EINVAL;
        if (consumed < 1)
            return EINVAL;
        while (isspace(val[consumed]))
            consumed++;
        if (val[consumed] != '\0')
            return EINVAL;
    } else if (strncmp(typ, "uint", sizeof("uint") - 1) == 0) {
        /* There's no equally-useful equivalent of %i for unsigned */
        if (val[0] == '0') {
            if (val[1] == 'x') {
                if (sscanf(val, "%"PRIx64"%n", &vu, &consumed) != 1)
                    return EINVAL;
            } else {
                if (sscanf(val, "%"PRIo64"%n", &vu, &consumed) != 1)
                    return EINVAL;
            }
        } else {
            if (sscanf(val, "%"PRIu64"%n", &vu, &consumed) != 1)
                return EINVAL;
        }
        if (consumed < 1)
            return EINVAL;
        while (isspace(val[consumed]))
            consumed++;
        if (val[consumed] != '\0')
            return EINVAL;
        vi = (int64_t)vu;
    }
#define DO_INTn(n)                                              \
    if (strcmp(typ, "int" #n) == 0) {                           \
        if (n < 64 && vi < INT ## n ## _MIN)                    \
            return EOVERFLOW;                                   \
        if (n < 64 && vi > INT ## n ## _MAX)                    \
            return EOVERFLOW;                                   \
        return krb5_store_int ## n (sp, vi);                    \
    }
    DO_INTn(8);
    DO_INTn(16);
    DO_INTn(32);
    DO_INTn(64);
#define DO_UINTn(n)                                             \
    if (strcmp(typ, "uint" #n) == 0) {                          \
        if (n < 64 && vu > INT ## n ## _MAX)                    \
            return EOVERFLOW;                                   \
        return krb5_store_int ## n (sp, vi);                    \
    }
    DO_UINTn(8);
    DO_UINTn(16);
    DO_UINTn(32);
    DO_UINTn(64);
    if (strcmp(typ, "string") == 0)
        return krb5_store_string(sp, val);
    if (strcmp(typ, "stringz") == 0)
        return krb5_store_stringz(sp, val);
    if (strcmp(typ, "stringnl") == 0)
        return krb5_store_stringnl(sp, val);
    if (strcmp(typ, "data") == 0) {
        ssize_t dsz = strlen(val);
        krb5_data d;

        /*
         * 'data' as in 'krb5_data'.
         *
         * krb5_store_data() stores the length then the data.
         */
        if (krb5_data_alloc(&d, dsz))
            return ENOMEM;
        dsz = hex_decode(val, d.data, d.length);
        if (dsz < 0)
            return EINVAL;
        d.length = dsz;
        ret = krb5_store_data(sp, d);
        krb5_data_free(&d);
        return ret;
    }
    if (strcmp(typ, "rawdata") == 0) {
        ssize_t dsz = strlen(val);
        void *d;

        /* Store the data w/o a length prefix */
        d = malloc(dsz);
        if (d == NULL)
            return ENOMEM;
        dsz = hex_decode(val, d, dsz);
        if (dsz < 0)
            return EINVAL;
        ret = krb5_store_datalen(sp, d, dsz);
        free(d);
        return ret;
    }
    return ENOTSUP;
}

static krb5_storage *
eval_recipe(char *r, int spflags)
{
    krb5_error_code ret;
    krb5_storage *sp;
    unsigned int lineno = 0;
    char *nxt = NULL;
    char *p;

    sp = krb5_storage_emem();
    if (sp == NULL)
        errx(1, "Out of memory");
    krb5_storage_set_flags(sp, spflags);

    for (p = r; p && *p; p = nxt) {
        char *typ;
        char *val;

        lineno++;

        /* Terminate p at \n */
        nxt = p;
        do {
            nxt = strpbrk(nxt, "\r\n");
            if (nxt && *nxt == '\r') {
                if (*(++nxt) != '\n')
                    continue;
            }
            if (nxt && *nxt == '\n') {
                *(nxt++) = '\0';
                break;
            }
        } while (nxt);

        while (isspace(*p))
            p++;
        if (*p == '#') {
            p = nxt;
            continue;
        }
        if (*p == '\0')
            continue;
        typ = p;
        val = strpbrk(p, " \t");
        if (val) {
            *(val++) = '\0';
            while (isspace(*val))
                val++;
        }
        ret = eval_recipe1(sp, typ, val);
        if (ret)
            krb5_err(NULL, 1, ret, "Error at line %u", lineno);
    }
    return sp;
}

static void
usage(int code)
{
    if (code)
        dup2(STDERR_FILENO, STDOUT_FILENO);

    arg_printusage(args, sizeof(args) / sizeof(args[0]), "test_marshall",
                   "Usage: test_marshal [options] TYPE-NAME INPUT-FILE "
                   "[OUTPUT-FILE]\n"
                   "\tText inputs must be of the form:\n\n"
                   "\t\tsimpletype literalvalue\n\n"
                   "\twhere {simpletype} is one of:\n\n"
                   "\t\tint8\n"
                   "\t\tint16\n"
                   "\t\tint32\n"
                   "\t\tint64\n"
                   "\t\tuint8\n"
                   "\t\tuint16\n"
                   "\t\tuint32\n"
                   "\t\tuint64\n"
                   "\t\tstring\n"
                   "\t\tstringz\n"
                   "\t\tstringnl\n"
                   "\t\tdata\n"
                   "\t\trawdata\n\n"
                   "\tand {literalvalue} is as appropriate for the {simpletype}:\n\n"
                   "\t - For int types the value can be decimal, octal, or hexadecimal.\n"
                   "\t - For string types the string ends at the end of the line.\n"
                   "\t - For {data} the value is hex and will be encoded as a 32-bit\n"
                   "\t   length then the raw binary data.\n"
                   "\t - For {rawdata} the value is hex and will be encoded as just the\n"
                   "\t   raw binary data.\n\n"
                   "\tThe {TYPE} must be one of: krb5_keyblock, krb5_principal,\n"
                   "\tkrb5_times, krb5_address, krb5_addresses, krb5_authdata,\n"
                   "\tkrb5_creds, krb5_key_data, krb5_tl_data, or\n"
                   "\tkadm5_principal_ent_rec.\n\n"
                   "Options:\n");
    exit(code);
}

static krb5_flags
byteorder_flags(const char *s)
{
    if (s == NULL)
        return KRB5_STORAGE_BYTEORDER_BE;
    if (strcasecmp(s, "packed") == 0)
        return KRB5_STORAGE_BYTEORDER_PACKED;
    if (strcasecmp(s, "host") == 0)
        return KRB5_STORAGE_BYTEORDER_HOST;
    if (strcasecmp(s, "network") == 0)
        return KRB5_STORAGE_BYTEORDER_BE;
    if (strcasecmp(s, "be") == 0)
        return KRB5_STORAGE_BYTEORDER_BE;
    if (strcasecmp(s, "le") == 0)
        return KRB5_STORAGE_BYTEORDER_LE;
    return 0;
}

/*
 * This program is intended to make fuzzing of krb5_ret_*() and kadm5_ret_*()
 * possible.
 *
 * Inputs are either binary encodings or simplistic textual representations of
 * XDR-ish data structures normally coded with {kadm5,krb5}_{ret,store}_*()
 * functions.
 *
 * A textual representation of these structures looks like:
 *
 *  type value
 *  ..
 *
 * where type is one of char, int32, etc., and where value is an appropriate
 * literal for type.
 */
int
main(int argc, char **argv)
{
    krb5_error_code ret = 0;
    krb5_storage *insp = NULL;
    krb5_storage *insp2 = NULL;
    krb5_storage *outsp = NULL;
    krb5_flags spflags_in = 0;
    krb5_flags spflags_out = 0;
    krb5_data i, i2, o;
    size_t insz = 0;
    char *hexout = NULL;
    char *hexin = NULL;
    char *intxt = NULL;
    void *inbin = NULL;
    int optidx = 0;

    if (getarg(args, sizeof(args)/sizeof(args[0]), argc, argv, &optidx))
        usage(1);

    if (help_flag)
        usage(0);

    argc -= optidx;
    argv += optidx;

    if (argc < 1)
        errx(1, "Missing type name argument");
    if (argc < 2)
        errx(1, "Missing input file argument");
    if (argc > 3)
        errx(1, "Too many arguments");

    if ((in_text_flag && in_binary_flag) ||
        (!in_text_flag && !in_binary_flag))
        errx(1, "One and only one of --in-text and --in-binary must be given");
    if (out_hex_flag && out_binary_flag)
        errx(1, "At most one of --out-text and --out-binary must be given");

    if (!out_hex_flag && !out_binary_flag) {
        if (isatty(STDOUT_FILENO)) {
            warnx("Will output hex because stdout is a terminal");
            out_hex_flag = 1;
        } else {
            warnx("Will output binary");
            out_binary_flag = 1;
        }
    }

    spflags_in  |= byteorder_flags(byteorder_string_in_string);
    spflags_out |= byteorder_flags(byteorder_string_out_string);

    /* Read the input */
    if (in_text_flag)
        errno = rk_undumptext(argv[1], &intxt, NULL);
    else
        errno = rk_undumpdata(argv[1], &inbin, &insz);
    if (errno)
        err(1, "Could not read %s", argv[1]);

    /* If the input is a recipe, evaluate it */
    if (intxt)
        insp = eval_recipe(intxt, spflags_in);
    else
        insp = krb5_storage_from_mem(inbin, insz);
    if (insp == NULL)
        errx(1, "Out of memory");
    krb5_storage_set_flags(insp, spflags_in);

    ret = krb5_storage_to_data(insp, &i);
    if (ret)
        krb5_err(NULL, 1, ret, "Could not check round-tripping");

    if (out_hex_flag) {
        char *hexstr = NULL;

        if (hex_encode(i.data, i.length, &hexstr) == -1)
            err(1, "Could not hex-encode output");
        if (argv[2]) {
            FILE *f;

            f = fopen(argv[2], "w");
            if (f == NULL)
                err(1, "Could not open %s for writing", argv[2]);
            if (fprintf(f, "%s\n", hexstr) < 0 || fclose(f))
                err(1, "Could write to %s", argv[2]);
        } else {
            if (printf("%s\n", hexstr) < 0)
                err(1, "Could not write to stdout");
        }
        free(hexstr);
    } else {
        if (argv[2]) {
            rk_dumpdata(argv[2], i.data, i.length);
        } else {
            if (fwrite(i.data, i.length, 1, stdout) != 1 ||
                fflush(stdout) != 0)
                err(1, "Could not output encoding");
        }
    }

    outsp = krb5_storage_emem();
    if (outsp == NULL)
        errx(1, "Out of memory");
    krb5_storage_set_flags(outsp, spflags_out);

    ret = reencode(argv[0], insp, outsp);
    if (ret)
        krb5_err(NULL, 1, ret, "Could not decode and re-encode");

    if (i.length == o.length && memcmp(i.data, o.data, i.length) == 0) {
        if (verbose_flag)
            fprintf(stderr, "Encoding round-trips!\n");
        goto out;
    }

    ret = krb5_storage_to_data(outsp, &o);
    if (ret)
        krb5_err(NULL, 1, ret, "Out of memory");

    /*
     * The encoding did not round trip.  Sadly kadm5_ret_principal_ent()
     * reverses the TL data list.  So try to re-encode one more time.
     */

    if (strcmp(argv[0], "kadm5_principal_ent_rec") == 0) {
        insp2 = krb5_storage_emem();
        if (insp2 == NULL)
            errx(1, "Out of memory");

        krb5_storage_set_flags(insp2, spflags_in);
        ret = reencode(argv[0], outsp, insp2);
        if (ret == 0)
            ret = krb5_storage_to_data(insp2, &i2);
        if (ret)
            krb5_err(NULL, 1, ret, "Could not decode and re-encode");
        if (i.length == i2.length && memcmp(i.data, i2.data, i.length) == 0) {
            if (verbose_flag)
                fprintf(stderr, "Encoding round-trips!\n");
            goto out;
        }
    }
    if (hex_encode(i.data, i.length, &hexin) < 0)
        errx(1, "Out of memory");
    if (hex_encode(o.data, o.length, &hexout) < 0)
        errx(1, "Out of memory");
    if (must_round_trip_flag) {
        errx(1, "Encoding does not round-trip\n(in:  %s)\n(out: %s)", hexin,
             hexout);
    } else {
        warnx("Encoding does not round-trip\n(in:  %s)\n(out: %s)", hexin,
              hexout);
    }

out:

    free(hexin);
    free(hexout);
    krb5_data_free(&o);
    krb5_data_free(&i);
    krb5_data_free(&i2);
    krb5_storage_free(insp);
    krb5_storage_free(outsp);
    krb5_storage_free(insp2);
    return ret;
}
#endif
