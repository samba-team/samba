/*
 * Copyright (c) 1997-2022 Kungliga Tekniska Högskolan
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

#include "ktutil_locl.h"
#include <heimbase.h>
#include <base64.h>

RCSID("$Id$");

static char *
readstring(const char *prompt, char *buf, size_t len)
{
    printf("%s", prompt);
    if (fgets(buf, len, stdin) == NULL)
	return NULL;
    buf[strcspn(buf, "\r\n")] = '\0';
    return buf;
}

int
kt_add(struct add_options *opt, int argc, char **argv)
{
    krb5_error_code ret;
    krb5_keytab keytab;
    krb5_keytab_entry entry;
    char buf[1024];
    krb5_enctype enctype;

    if((keytab = ktutil_open_keytab()) == NULL)
	return 1;

    memset(&entry, 0, sizeof(entry));
    if(opt->principal_string == NULL) {
	if(readstring("Principal: ", buf, sizeof(buf)) == NULL)
	    return 1;
	opt->principal_string = buf;
    }
    ret = krb5_parse_name(context, opt->principal_string, &entry.principal);
    if(ret) {
	krb5_warn(context, ret, "%s", opt->principal_string);
	goto out;
    }
    if(opt->enctype_string == NULL) {
	if(readstring("Encryption type: ", buf, sizeof(buf)) == NULL) {
	    ret = 1;
	    goto out;
	}
	opt->enctype_string = buf;
    }
    ret = krb5_string_to_enctype(context, opt->enctype_string, &enctype);
    if(ret) {
	int t;
	if(sscanf(opt->enctype_string, "%d", &t) == 1)
	    enctype = t;
	else {
	    krb5_warn(context, ret, "%s", opt->enctype_string);
	    goto out;
	}
    }
    if(opt->kvno_integer == -1) {
	if(readstring("Key version: ", buf, sizeof(buf)) == NULL) {
	    ret = 1;
	    goto out;
	}
	if(sscanf(buf, "%u", &opt->kvno_integer) != 1)
	    goto out;
    }
    if(opt->password_string == NULL && opt->random_flag == 0) {
	if(UI_UTIL_read_pw_string(buf, sizeof(buf), "Password: ",
				  UI_UTIL_FLAG_VERIFY)) {
	    ret = 1;
	    goto out;
	}
	opt->password_string = buf;
    }
    if(opt->password_string) {
	if (opt->hex_flag) {
	    size_t len;
	    void *data;

	    len = (strlen(opt->password_string) + 1) / 2;

	    data = malloc(len);
	    if (data == NULL) {
		krb5_warn(context, ENOMEM, "malloc");
		goto out;
	    }

	    if ((size_t)hex_decode(opt->password_string, data, len) != len) {
		free(data);
		krb5_warn(context, ENOMEM, "hex decode failed");
		goto out;
	    }

	    ret = krb5_keyblock_init(context, enctype,
				     data, len, &entry.keyblock);
	    free(data);
	} else if (!opt->salt_flag) {
	    krb5_salt salt;
	    krb5_data pw;

	    salt.salttype         = KRB5_PW_SALT;
	    salt.saltvalue.data   = NULL;
	    salt.saltvalue.length = 0;
	    pw.data = (void*)opt->password_string;
	    pw.length = strlen(opt->password_string);
	    ret = krb5_string_to_key_data_salt(context, enctype, pw, salt,
					       &entry.keyblock);
        } else {
	    ret = krb5_string_to_key(context, enctype, opt->password_string,
				     entry.principal, &entry.keyblock);
	}
	memset (opt->password_string, 0, strlen(opt->password_string));
    } else {
	ret = krb5_generate_random_keyblock(context, enctype, &entry.keyblock);
    }
    if(ret) {
	krb5_warn(context, ret, "add");
	goto out;
    }
    entry.vno = opt->kvno_integer;
    entry.timestamp = time (NULL);
    ret = krb5_kt_add_entry(context, keytab, &entry);
    if(ret)
	krb5_warn(context, ret, "add");
 out:
    krb5_kt_free_entry(context, &entry);
    if (ret == 0) {
        ret = krb5_kt_close(context, keytab);
        if (ret)
            krb5_warn(context, ret, "Could not write the keytab");
    } else {
        krb5_kt_close(context, keytab);
    }
    return ret != 0;
}

/* We might be reading from a pipe, so we can't use rk_undumpdata() */
static char *
read_file(FILE *f)
{
    size_t alloced;
    size_t len = 0;
    size_t bytes;
    char *res, *end, *p;

    if ((res = malloc(1024)) == NULL)
        err(1, "Out of memory");
    alloced = 1024;

    end = res + alloced;
    p = res;
    do {
        if (p == end) {
            char *tmp;

            if ((tmp = realloc(res, alloced + (alloced > 1))) == NULL)
                err(1, "Out of memory");
            alloced += alloced > 1;
            p = tmp + (p - res);
            res = tmp;
            end = res + alloced;
        }
        bytes = fread(p, 1, end - p, f);
        len += bytes;
        p += bytes;
    } while (bytes && !feof(f) && !ferror(f));

    if (ferror(f))
        errx(1, "Could not read all input");
    if (p == end) {
        char *tmp;

        if ((tmp = strndup(res, len)) == NULL)
            err(1, "Out of memory");
        free(res);
        res = tmp;
    }
    if (strlen(res) != len)
        err(1, "Embedded NULs in input!");
    return res;
}

static void
json2keytab_entry(heim_dict_t d, krb5_keytab kt, size_t idx)
{
    krb5_keytab_entry e;
    krb5_error_code ret;
    heim_object_t v;
    uint64_t u;
    int64_t i;
    char *buf = NULL;

    memset(&e, 0, sizeof(e));

    v = heim_dict_get_value(d, HSTR("timestamp"));
    if (heim_get_tid(v) != HEIM_TID_NUMBER)
        goto bad;
    u = heim_number_get_long(v);
    e.timestamp = u;
    if (u != (uint64_t)e.timestamp)
        goto bad;

    v = heim_dict_get_value(d, HSTR("kvno"));
    if (heim_get_tid(v) != HEIM_TID_NUMBER)
        goto bad;
    i = heim_number_get_long(v);
    e.vno = i;
    if (i != (int64_t)e.vno)
        goto bad;

    v = heim_dict_get_value(d, HSTR("enctype_number"));
    if (heim_get_tid(v) != HEIM_TID_NUMBER)
        goto bad;
    i = heim_number_get_long(v);
    e.keyblock.keytype = i;
    if (i != (int64_t)e.keyblock.keytype)
        goto bad;

    v = heim_dict_get_value(d, HSTR("key"));
    if (heim_get_tid(v) != HEIM_TID_STRING)
        goto bad;
    {
        const char *s = heim_string_get_utf8(v);
        int declen;

        if ((buf = malloc(strlen(s))) == NULL)
            err(1, "Out of memory");
        declen = rk_base64_decode(s, buf);
        if (declen < 0)
            goto bad;
        e.keyblock.keyvalue.data = buf;
        e.keyblock.keyvalue.length = declen;
    }

    v = heim_dict_get_value(d, HSTR("principal"));
    if (heim_get_tid(v) != HEIM_TID_STRING)
        goto bad;
    ret = krb5_parse_name(context, heim_string_get_utf8(v), &e.principal);
    if (ret == 0)
        ret = krb5_kt_add_entry(context, kt, &e);

    /* For now, ignore aliases; besides, they're never set anywhere in-tree */

    if (ret)
        krb5_warn(context, ret,
                  "Could not parse or write keytab entry %lu",
                  (unsigned long)idx);
bad:
    krb5_free_principal(context, e.principal);
}

int
kt_import(void *opt, int argc, char **argv)
{
    krb5_error_code ret;
    krb5_keytab kt;
    heim_object_t o;
    heim_error_t json_err = NULL;
    heim_json_flags_t flags = HEIM_JSON_F_STRICT;
    FILE *f = argc == 0 ? stdin : fopen(argv[0], "r");
    size_t alen, i;
    char *json;

    if (f == NULL)
        err(1, "Could not open file %s", argv[0]);

    json = read_file(f);
    o = heim_json_create(json, 10, flags, &json_err);
    free(json);
    if (o == NULL) {
        if (json_err != NULL) {
            o = heim_error_copy_string(json_err);
            if (o)
                errx(1, "Could not parse JSON: %s", heim_string_get_utf8(o));
        }
        errx(1, "Could not parse JSON");
    }

    if (heim_get_tid(o) != HEIM_TID_ARRAY)
        errx(1, "JSON text must be an array");

    alen = heim_array_get_length(o);
    if (alen == 0)
        errx(1, "Empty JSON array; not overwriting keytab");

    if ((kt = ktutil_open_keytab()) == NULL)
	err(1, "Could not open keytab");

    for (i = 0; i < alen; i++) {
        heim_object_t e = heim_array_get_value(o, i);

        if (heim_get_tid(e) != HEIM_TID_DICT)
            warnx("Element %ld of JSON text array is not an object", (long)i);
        else
            json2keytab_entry(heim_array_get_value(o, i), kt, i);
    }
    ret = krb5_kt_close(context, kt);
    if (ret)
        krb5_warn(context, ret, "Could not write the keytab");
    return ret != 0;
}
