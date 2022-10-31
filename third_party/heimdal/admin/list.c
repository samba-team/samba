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
#include <rtbl.h>

RCSID("$Id$");

static int
do_list(struct list_options *opt, const char *keytab_str)
{
    krb5_error_code ret;
    krb5_keytab keytab;
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;
    rtbl_t table;

    /* XXX specialcase the ANY type */
    if(strncasecmp(keytab_str, "ANY:", 4) == 0) {
	int flag = 0;
	char buf[1024];
	keytab_str += 4;
	ret = 0;
	while (strsep_copy((const char**)&keytab_str, ",",
			   buf, sizeof(buf)) != -1) {
	    if(flag)
		printf("\n");
	    if(do_list(opt, buf))
		ret = 1;
	    flag = 1;
	}
	return ret;
    }

    ret = krb5_kt_resolve(context, keytab_str, &keytab);
    if (ret) {
	krb5_warn(context, ret, "resolving keytab %s", keytab_str);
	return ret;
    }

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if(ret) {
	krb5_warn(context, ret, "krb5_kt_start_seq_get %s", keytab_str);
	krb5_kt_close(context, keytab);
	return ret;
    }

    printf ("%s:\n\n", keytab_str);

    table = rtbl_create();
    rtbl_add_column_by_id(table, 0, "Vno", RTBL_ALIGN_RIGHT);
    rtbl_add_column_by_id(table, 1, "Type", 0);
    rtbl_add_column_by_id(table, 2, "Principal", 0);
    if (opt->timestamp_flag)
	rtbl_add_column_by_id(table, 3, "Date", 0);
    if(opt->keys_flag)
	rtbl_add_column_by_id(table, 4, "Key", 0);
    rtbl_add_column_by_id(table, 5, "Aliases", 0);
    rtbl_set_separator(table, "  ");

    while(krb5_kt_next_entry(context, keytab, &entry, &cursor) == 0){
	char buf[1024], *s;

	snprintf(buf, sizeof(buf), "%d", entry.vno);
	rtbl_add_column_entry_by_id(table, 0, buf);

	ret = krb5_enctype_to_string(context,
				     entry.keyblock.keytype, &s);
	if (ret != 0) {
	    snprintf(buf, sizeof(buf), "unknown (%d)", entry.keyblock.keytype);
	    rtbl_add_column_entry_by_id(table, 1, buf);
	} else {
	    rtbl_add_column_entry_by_id(table, 1, s);
	    free(s);
	}

	krb5_unparse_name_fixed(context, entry.principal, buf, sizeof(buf));
	rtbl_add_column_entry_by_id(table, 2, buf);

	if (opt->timestamp_flag) {
	    krb5_format_time(context, entry.timestamp, buf,
			     sizeof(buf), FALSE);
	    rtbl_add_column_entry_by_id(table, 3, buf);
	}
	if(opt->keys_flag) {
	    size_t i;
	    s = malloc(2 * entry.keyblock.keyvalue.length + 1);
	    if (s == NULL) {
		krb5_warnx(context, "malloc failed");
		ret = ENOMEM;
		goto out;
	    }
	    for(i = 0; i < entry.keyblock.keyvalue.length; i++)
		snprintf(s + 2 * i, 3, "%02x",
			 ((unsigned char*)entry.keyblock.keyvalue.data)[i]);
	    rtbl_add_column_entry_by_id(table, 4, s);
	    free(s);
	}
	if (entry.aliases) {
	    unsigned int i;
	    struct rk_strpool *p = NULL;

	    for (i = 0; i< entry.aliases->len; i++) {
		krb5_unparse_name_fixed(context, &entry.aliases->val[i],
                                        buf, sizeof(buf));
		p = rk_strpoolprintf(p, "%s%s", buf,
                                     i + 1 < entry.aliases->len ? ", " : "");

	    }
	    rtbl_add_column_entry_by_id(table, 5, (s = rk_strpoolcollect(p)));
            free(s);
	}

	krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    rtbl_format(table, stdout);

out:
    rtbl_destroy(table);

    krb5_kt_close(context, keytab);
    return ret;
}

static int
do_list1_json(struct list_options *opt,
              const char *keytab_str,
              heim_array_t a)
{
    krb5_error_code ret;
    krb5_keytab keytab;
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;

    ret = krb5_kt_resolve(context, keytab_str, &keytab);
    if (ret) {
	krb5_warn(context, ret, "resolving keytab %s", keytab_str);
	return ret;
    }

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if(ret) {
	krb5_warn(context, ret, "krb5_kt_start_seq_get %s", keytab_str);
	krb5_kt_close(context, keytab);
	return ret;
    }

    //if (opt->timestamp_flag)
    //if (opt->keys_flag)

    while (krb5_kt_next_entry(context, keytab, &entry, &cursor) == 0) {
        heim_dict_t d = heim_dict_create(5);
        heim_object_t o;
	char *s;

        heim_array_append_value(a, d);
        heim_dict_set_value(d, HSTR("keytab"),
                            o = heim_string_create(keytab_str)); heim_release(o);
        heim_dict_set_value(d, HSTR("kvno"), o = heim_number_create(entry.vno));
        heim_release(o);
        heim_dict_set_value(d, HSTR("enctype_number"),
                            o = heim_number_create(entry.keyblock.keytype));
        heim_release(o);
        heim_dict_set_value(d, HSTR("flags"),
                            o = heim_number_create(entry.flags));
        heim_release(o);
	ret = krb5_enctype_to_string(context, entry.keyblock.keytype, &s);
	if (ret == 0) {
            heim_dict_set_value(d, HSTR("enctype"), o = heim_string_create(s));
            heim_release(o);
            free(s);
	}
        heim_dict_set_value(d, HSTR("timestamp"),
                            o = heim_number_create(entry.timestamp));
        heim_release(o);

	ret = krb5_unparse_name(context, entry.principal, &s);
        if (ret)
            krb5_err(context, 1, ret, "Could not format principal");
        heim_dict_set_value(d, HSTR("principal"), o = heim_string_create(s));
        heim_release(o);
        free(s);

	if (opt->keys_flag) {
            o = heim_data_create(entry.keyblock.keyvalue.data,
                                 entry.keyblock.keyvalue.length);
            heim_dict_set_value(d, HSTR("key"), o);
            heim_release(o);
	}
	if (entry.aliases) {
            heim_array_t aliases = heim_array_create();
	    unsigned int i;

	    for (i = 0; i< entry.aliases->len; i++) {
		ret = krb5_unparse_name(context, &entry.aliases->val[i], &s);
                if (ret)
                    krb5_err(context, 1, ret, "Could not format principal");
                heim_array_append_value(aliases, o = heim_string_create(s));
                heim_release(o);
                free(s);
	    }
            heim_dict_set_value(d, HSTR("aliases"), aliases);
            heim_release(aliases);
            free(s);
	}

	krb5_kt_free_entry(context, &entry);
        heim_release(d);
    }

    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    krb5_kt_close(context, keytab);
    return ret;
}

static int
do_list_json(struct list_options *opt, const char *keytab_str)
{
    krb5_error_code ret = 0;
    heim_json_flags_t flags =
        (HEIM_JSON_F_STRICT | HEIM_JSON_F_INDENT2 | HEIM_JSON_F_NO_DATA_DICT) &
        ~HEIM_JSON_F_NO_DATA;
    heim_array_t a = heim_array_create();
    heim_string_t s;

    /*
     * Special-case the ANY: keytab type.  What do we get from this?  We get to
     * include the actual keytab name for each entry in its JSON
     * representation.  Otherwise there would be no point because the ANY:
     * keytab type iterates all the keytabs it joins.
     *
     * Why strncasecmp() though?  Because do_list() uses it, though it arguably
     * never should have.
     */
    if (strncasecmp(keytab_str, "ANY:", 4) == 0) {
	char buf[1024];

	keytab_str += 4;
	ret = 0;
	while (strsep_copy((const char**)&keytab_str, ",",
			   buf, sizeof(buf)) != -1) {
	    if (do_list1_json(opt, buf, a))
		ret = 1;
	}
    } else {
        ret = do_list1_json(opt, keytab_str, a);
    }

    s = heim_json_copy_serialize(a, flags, NULL);
    printf("%s", heim_string_get_utf8(s));
    heim_release(a);
    heim_release(s);
    return ret;
}

int
kt_list(struct list_options *opt, int argc, char **argv)
{
    krb5_error_code ret;
    char kt[1024];

    if(verbose_flag)
	opt->timestamp_flag = 1;

    if (keytab_string == NULL) {
	if((ret = krb5_kt_default_name(context, kt, sizeof(kt))) != 0) {
	    krb5_warn(context, ret, "getting default keytab name");
	    return 1;
	}
	keytab_string = kt;
    }
    if (opt->json_flag)
        return do_list_json(opt, keytab_string) != 0;
    return do_list(opt, keytab_string) != 0;
}
