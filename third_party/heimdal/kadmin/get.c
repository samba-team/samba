/*
 * Copyright (c) 1997-2006 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"
#include "kadmin-commands.h"
#include <parse_units.h>
#include <rtbl.h>

static struct field_name {
    const char *fieldname;
    unsigned int fieldvalue;
    unsigned int subvalue;
    uint32_t extra_mask;
    const char *default_header;
    const char *def_longheader;
    unsigned int flags;
} field_names[] = {
    { "principal", KADM5_PRINCIPAL, 0, 0, "Principal", "Principal", 0 },
    { "princ_expire_time", KADM5_PRINC_EXPIRE_TIME, 0, 0, "Expiration", "Principal expires", 0 },
    { "pw_expiration", KADM5_PW_EXPIRATION, 0, 0, "PW-exp", "Password expires", 0 },
    { "last_pwd_change", KADM5_LAST_PWD_CHANGE, 0, 0, "PW-change", "Last password change", 0 },
    { "max_life", KADM5_MAX_LIFE, 0, 0, "Max life", "Max ticket life", 0 },
    { "max_rlife", KADM5_MAX_RLIFE, 0, 0, "Max renew", "Max renewable life", 0 },
    { "mod_time", KADM5_MOD_TIME, 0, 0, "Mod time", "Last modified", 0 },
    { "mod_name", KADM5_MOD_NAME, 0, 0, "Modifier", "Modifier", 0 },
    { "attributes", KADM5_ATTRIBUTES, 0, 0, "Attributes", "Attributes", 0 },
    { "kvno", KADM5_KVNO, 0, 0, "Kvno", "Kvno", RTBL_ALIGN_RIGHT  },
    { "mkvno", KADM5_MKVNO, 0, 0, "Mkvno", "Mkvno", RTBL_ALIGN_RIGHT },
    { "last_success", KADM5_LAST_SUCCESS, 0, 0, "Last login", "Last successful login", 0 },
    { "last_failed", KADM5_LAST_FAILED, 0, 0, "Last fail", "Last failed login", 0 },
    { "fail_auth_count", KADM5_FAIL_AUTH_COUNT, 0, 0, "Fail count", "Failed login count", RTBL_ALIGN_RIGHT },
    { "policy", KADM5_POLICY, 0, 0, "Policy", "Policy", 0 },
    { "keytypes", KADM5_KEY_DATA, 0, KADM5_PRINCIPAL | KADM5_KVNO, "Keytypes", "Keytypes", 0 },
    { "server-keytypes", KADM5_TL_DATA, KRB5_TL_ETYPES, 0, "Server keytypes", "Supported keytypes (servers)", 0 },
    { "password", KADM5_TL_DATA, KRB5_TL_PASSWORD, KADM5_KEY_DATA, "Password", "Password", 0 },
    { "pkinit-acl", KADM5_TL_DATA, KRB5_TL_PKINIT_ACL, 0, "PK-INIT ACL", "PK-INIT ACL", 0 },
    { "aliases", KADM5_TL_DATA, KRB5_TL_ALIASES, 0, "Aliases", "Aliases", 0 },
    { "hist-kvno-diff-clnt", KADM5_TL_DATA, KRB5_TL_HIST_KVNO_DIFF_CLNT, 0, "Clnt hist keys", "Historic keys allowed for client", 0 },
    { "hist-kvno-diff-svc", KADM5_TL_DATA, KRB5_TL_HIST_KVNO_DIFF_SVC, 0, "Svc hist keys", "Historic keys allowed for service", 0 },
    { NULL, 0, 0, 0, NULL, NULL, 0 }
};

struct field_info {
    struct field_name *ff;
    char *header;
    struct field_info *next;
};

struct get_entry_data {
    void (*format)(struct get_entry_data*, kadm5_principal_ent_t);
    rtbl_t table;
    uint32_t mask;
    uint32_t extra_mask;
    struct field_info *chead, **ctail;
    const char *krb5_config_fname;
    void *kadm_handle;
    uint32_t n;
    int upto;
};

static int
add_column(struct get_entry_data *data, struct field_name *ff, const char *header)
{
    struct field_info *f = malloc(sizeof(*f));
    if (f == NULL)
	return ENOMEM;
    f->ff = ff;
    if(header)
	f->header = strdup(header);
    else
	f->header = NULL;
    f->next = NULL;
    *data->ctail = f;
    data->ctail = &f->next;
    data->mask |= ff->fieldvalue;
    data->extra_mask |= ff->extra_mask;
    if(data->table != NULL)
	rtbl_add_column_by_id(data->table, ff->fieldvalue,
			      header ? header : ff->default_header, ff->flags);
    return 0;
}

/*
 * return 0 iff `salt' actually is the same as the current salt in `k'
 */

static int
cmp_salt (const krb5_salt *salt, const krb5_key_data *k)
{
    if (salt->salttype != (size_t)k->key_data_type[1])
	return 1;
    if (salt->saltvalue.length != (size_t)k->key_data_length[1])
	return 1;
    return memcmp (salt->saltvalue.data, k->key_data_contents[1],
		   salt->saltvalue.length);
}

static void
format_keytype(krb5_key_data *k, krb5_salt *def_salt, char *buf, size_t buf_len)
{
    krb5_error_code ret;
    char *s;
    int aret;

    buf[0] = '\0';
    ret = krb5_enctype_to_string (context,
				  k->key_data_type[0],
				  &s);
    if (ret) {
	aret = asprintf (&s, "unknown(%d)", k->key_data_type[0]);
	if (aret == -1)
	    return;	/* Nothing to do here, we have no way to pass the err */
    }
    strlcpy(buf, s, buf_len);
    free(s);

    strlcat(buf, "(", buf_len);

    ret = krb5_salttype_to_string (context,
				   k->key_data_type[0],
				   k->key_data_type[1],
				   &s);
    if (ret) {
	aret = asprintf (&s, "unknown(%d)", k->key_data_type[1]);
	if (aret == -1)
	    return;	/* Again, nothing else to do... */
    }
    strlcat(buf, s, buf_len);
    free(s);

    aret = 0;
    if (cmp_salt(def_salt, k) == 0)
	s = strdup("");
    else if(k->key_data_length[1] == 0)
	s = strdup("()");
    else
	aret = asprintf (&s, "(%.*s)", k->key_data_length[1],
			 (char *)k->key_data_contents[1]);
    if (aret == -1 || s == NULL)
	return;		/* Again, nothing else we can do... */
    strlcat(buf, s, buf_len);
    free(s);
    aret = asprintf (&s, "[%d]", k->key_data_kvno);
    if (aret == -1)
	return;
    strlcat(buf, ")", buf_len);

    strlcat(buf, s, buf_len);
    free(s);
}

static int
is_special_file(const char *fname)
{
#ifdef WIN32
    if (strcasecmp(fname, "con") == 0 || strcasecmp(fname, "nul") == 0 ||
        strcasecmp(fname, "aux") == 0 || strcasecmp(fname, "prn") == 0)
        return 1;
    if ((strncasecmp(fname, "com", sizeof("com") - 1) == 0  ||
         strncasecmp(fname, "lpt", sizeof("lpt") - 1) == 0) &&
        fname[sizeof("lpt")] >= '0' && fname[sizeof("lpt")] <= '9' &&
        fname[sizeof("lpt") + 1] == '\0')
        return 1;
#else
    if (strncmp(fname, "/dev/", sizeof("/dev/") - 1) == 0)
        return 1;
#endif
    return 0;
}

static char *
write_krb5_config(krb5_tl_data *tl,
                  const char *fn,
                  uint32_t i)
{
    char *s = NULL;
    FILE *f = NULL;

    if (fn == NULL)
        return NULL;
    if (i == 0 || is_special_file(fn))
        s = strdup(fn);
    else if (asprintf(&s, "%s-%u", fn, i) == -1)
        s = NULL;
    if (s == NULL)
        krb5_err(context, 1, errno, "Out of memory");

    /* rk_dumpdata() doesn't allow error checking :( */
    if ((f = fopen(s, "w")) &&
        fwrite(tl->tl_data_contents, tl->tl_data_length, 1, f) != 1)
        krb5_warn(context, errno, "Could not write to %s", fn);
    if (f && fclose(f))
        krb5_warn(context, errno, "Could not write to %s", fn);
    return s;
}

static void
format_field(struct get_entry_data *data,
             kadm5_principal_ent_t princ,
             unsigned int field,
	     unsigned int subfield,
             char *buf,
             size_t buf_len,
             int condensed)
{
    switch(field) {
    case KADM5_PRINCIPAL:
	if(condensed)
	    krb5_unparse_name_fixed_short(context, princ->principal, buf, buf_len);
	else
	    krb5_unparse_name_fixed(context, princ->principal, buf, buf_len);
	break;

    case KADM5_PRINC_EXPIRE_TIME:
	time_t2str(princ->princ_expire_time, buf, buf_len, !condensed);
	break;

    case KADM5_PW_EXPIRATION:
	time_t2str(princ->pw_expiration, buf, buf_len, !condensed);
	break;

    case KADM5_LAST_PWD_CHANGE:
	time_t2str(princ->last_pwd_change, buf, buf_len, !condensed);
	break;

    case KADM5_MAX_LIFE:
	deltat2str(princ->max_life, buf, buf_len);
	break;

    case KADM5_MAX_RLIFE:
	deltat2str(princ->max_renewable_life, buf, buf_len);
	break;

    case KADM5_MOD_TIME:
	time_t2str(princ->mod_date, buf, buf_len, !condensed);
	break;

    case KADM5_MOD_NAME:
	if (princ->mod_name == NULL)
	    strlcpy(buf, "unknown", buf_len);
	else if(condensed)
	    krb5_unparse_name_fixed_short(context, princ->mod_name, buf, buf_len);
	else
	    krb5_unparse_name_fixed(context, princ->mod_name, buf, buf_len);
	break;
    case KADM5_ATTRIBUTES:
	attributes2str (princ->attributes, buf, buf_len);
	break;
    case KADM5_KVNO:
	snprintf(buf, buf_len, "%d", princ->kvno);
	break;
    case KADM5_MKVNO:
	/* XXX libkadm5srv decrypts the keys, so mkvno is always 0. */
	strlcpy(buf, "unknown", buf_len);
	break;
    case KADM5_LAST_SUCCESS:
	time_t2str(princ->last_success, buf, buf_len, !condensed);
	break;
    case KADM5_LAST_FAILED:
	time_t2str(princ->last_failed, buf, buf_len, !condensed);
	break;
    case KADM5_FAIL_AUTH_COUNT:
	snprintf(buf, buf_len, "%d", princ->fail_auth_count);
	break;
    case KADM5_POLICY:
	if(princ->policy != NULL)
	    strlcpy(buf, princ->policy, buf_len);
	else
	    strlcpy(buf, "none", buf_len);
	break;
    case KADM5_KEY_DATA:{
	krb5_salt def_salt;
	int i;
	char buf2[1024];
	krb5_get_pw_salt (context, princ->principal, &def_salt);

	*buf = '\0';
	for (i = 0; i < princ->n_key_data; ++i) {
	    format_keytype(&princ->key_data[i], &def_salt, buf2, sizeof(buf2));
	    if(i > 0)
		strlcat(buf, ", ", buf_len);
	    strlcat(buf, buf2, buf_len);
	}
	krb5_free_salt (context, def_salt);
	break;
    }
    case KADM5_TL_DATA: {
	krb5_tl_data *tl;

	for (tl = princ->tl_data; tl != NULL; tl = tl->tl_data_next)
	    if ((unsigned)tl->tl_data_type == subfield)
		break;
	if (tl == NULL) {
	    strlcpy(buf, "", buf_len);
	    break;
	}

	switch (subfield) {
	case KRB5_TL_PASSWORD:
	    snprintf(buf, buf_len, "\"%.*s\"",
		     (int)tl->tl_data_length,
		     (const char *)tl->tl_data_contents);
	    break;
	case KRB5_TL_ETYPES: {
            HDB_EncTypeList etypes;
	    size_t i, size;
            char *str;
	    int ret;

            ret = decode_HDB_EncTypeList(tl->tl_data_contents,
                                         tl->tl_data_length,
                                         &etypes, &size);
	    if (ret) {
		snprintf(buf, buf_len, "failed to decode server etypes");
		break;
	    }
            buf[0] = '\0';
            for (i = 0; i < etypes.len; i++) {
                ret = krb5_enctype_to_string(context, etypes.val[i], &str);
                if (ret == 0) {
                    if (i)
                        strlcat(buf, ",", buf_len);
                    strlcat(buf, str, buf_len);
		    krb5_xfree(str);
                }
            }
            free_HDB_EncTypeList(&etypes);
            break;
        }
	case KRB5_TL_PKINIT_ACL: {
	    HDB_Ext_PKINIT_acl acl;
	    size_t size;
	    int ret;
	    size_t i;

	    ret = decode_HDB_Ext_PKINIT_acl(tl->tl_data_contents,
					    tl->tl_data_length,
					    &acl,
					    &size);
	    if (ret) {
		snprintf(buf, buf_len, "failed to decode ACL");
		break;
	    }

	    buf[0] = '\0';
	    for (i = 0; i < acl.len; i++) {
		strlcat(buf, "subject: ", buf_len);
		strlcat(buf, acl.val[i].subject, buf_len);
		if (acl.val[i].issuer) {
		    strlcat(buf, " issuer:", buf_len);
		    strlcat(buf, *acl.val[i].issuer, buf_len);
		}
		if (acl.val[i].anchor) {
		    strlcat(buf, " anchor:", buf_len);
		    strlcat(buf, *acl.val[i].anchor, buf_len);
		}
		if (i + 1 < acl.len)
		    strlcat(buf, ", ", buf_len);
	    }
	    free_HDB_Ext_PKINIT_acl(&acl);
	    break;
	}
	case KRB5_TL_KRB5_CONFIG: {
            char *fname;

            fname = write_krb5_config(tl, data->krb5_config_fname, data->n);
            if (fname) {
                strlcat(buf, fname, buf_len);
                free(fname);
            }
	    break;
	}
	case KRB5_TL_ALIASES: {
	    HDB_Ext_Aliases alias;
	    size_t size;
	    int ret;
	    size_t i;

	    ret = decode_HDB_Ext_Aliases(tl->tl_data_contents,
					 tl->tl_data_length,
					 &alias,
					 &size);
	    if (ret) {
		snprintf(buf, buf_len, "failed to decode alias");
		break;
	    }
	    buf[0] = '\0';
	    for (i = 0; i < alias.aliases.len; i++) {
		char *p;
		ret = krb5_unparse_name(context, &alias.aliases.val[i], &p);
		if (ret)
		    break;
		if (i > 0)
		    strlcat(buf, " ", buf_len);
		strlcat(buf, p, buf_len);
		free(p);
	    }
	    free_HDB_Ext_Aliases(&alias);
	    break;
	}
	default:
	    snprintf(buf, buf_len, "unknown type %d", subfield);
	    break;
	}
	break;
    }
    default:
	strlcpy(buf, "<unknown>", buf_len);
	break;
    }
}

static void
print_entry_short(struct get_entry_data *data, kadm5_principal_ent_t princ)
{
    char buf[1024];
    struct field_info *f;

    for(f = data->chead; f != NULL; f = f->next) {
        format_field(data, princ, f->ff->fieldvalue, f->ff->subvalue, buf,
                     sizeof(buf), 1);
	rtbl_add_column_entry_by_id(data->table, f->ff->fieldvalue, buf);
    }
}

static void
print_entry_long(struct get_entry_data *data, kadm5_principal_ent_t princ)
{
    char buf[1024];
    struct field_info *f;
    int width = 0;

    for(f = data->chead; f != NULL; f = f->next) {
	int w = strlen(f->header ? f->header : f->ff->def_longheader);
	if(w > width)
	    width = w;
    }
    for(f = data->chead; f != NULL; f = f->next) {
        format_field(data, princ, f->ff->fieldvalue, f->ff->subvalue, buf,
                     sizeof(buf), 0);
	printf("%*s: %s\n", width, f->header ? f->header : f->ff->def_longheader, buf);
    }
    printf("\n");
}

static int
do_get_entry(krb5_principal principal, void *data)
{
    kadm5_principal_ent_rec princ;
    krb5_error_code ret;
    struct get_entry_data *e = data;

    if (e->upto == 0)
        return EINTR;
    if (e->upto > 0)
        e->upto--;

    memset(&princ, 0, sizeof(princ));
    ret = kadm5_get_principal(e->kadm_handle, principal,
			      &princ,
			      e->mask | e->extra_mask);
    if (ret == 0) {
        (e->format)(e, &princ);
        kadm5_free_principal_ent(e->kadm_handle, &princ);
    }

    e->n++;
    return ret;
}

static void
free_columns(struct get_entry_data *data)
{
    struct field_info *f, *next;
    for(f = data->chead; f != NULL; f = next) {
	free(f->header);
	next = f->next;
	free(f);
    }
    data->chead = NULL;
    data->ctail = &data->chead;
}

static int
setup_columns(struct get_entry_data *data, const char *column_info)
{
    char buf[1024], *q;
    char *field, *header;
    struct field_name *f;

    while(strsep_copy(&column_info, ",", buf, sizeof(buf)) != -1) {
	q = buf;
	field = strsep(&q, "=");
	header = strsep(&q, "=");
	for(f = field_names; f->fieldname != NULL; f++) {
	    if(strcasecmp(field, f->fieldname) == 0) {
		add_column(data, f, header);
		break;
	    }
	}
	if(f->fieldname == NULL) {
	    krb5_warnx(context, "unknown field name \"%s\"", field);
	    free_columns(data);
	    return -1;
	}
    }
    return 0;
}

static int
do_list_entry(krb5_principal principal, void *data)
{
    char buf[1024];
    int *upto = data;
    krb5_error_code ret;

    if (*upto == 0)
        return EINTR;
    if (*upto > 0)
        (*upto)--;

    ret = krb5_unparse_name_fixed_short(context, principal, buf, sizeof(buf));
    if (ret != 0)
        return ret;
    printf("%s\n", buf);
    return 0;
}

static int
listit(const char *funcname, int upto, int argc, char **argv)
{
    int i;
    krb5_error_code ret, saved_ret = 0;

    for (i = 0; i < argc; i++) {
	ret = foreach_principal(argv[i], do_list_entry, funcname, &upto);
        if (saved_ret == 0 && ret != 0)
            saved_ret = ret;
    }
    return saved_ret != 0;
}

#define DEFAULT_COLUMNS_SHORT "principal,princ_expire_time,pw_expiration,last_pwd_change,max_life,max_rlife"
#define DEFAULT_COLUMNS_LONG "principal,princ_expire_time,pw_expiration,last_pwd_change,max_life,max_rlife,kvno,mkvno,last_success,last_failed,fail_auth_count,mod_time,mod_name,attributes,server-keytypes,keytypes,pkinit-acl,aliases"

static int
getit(struct get_options *opt, const char *name, int argc, char **argv)
{
    int i;
    krb5_error_code ret;
    struct get_entry_data data;

    if(opt->long_flag == -1 && (opt->short_flag == 1 || opt->terse_flag == 1))
	opt->long_flag = 0;
    if(opt->short_flag == -1 && (opt->long_flag == 1 || opt->terse_flag == 1))
	opt->short_flag = 0;
    if(opt->terse_flag == -1 && (opt->long_flag == 1 || opt->short_flag == 1))
	opt->terse_flag = 0;
    if(opt->long_flag == 0 && opt->short_flag == 0 && opt->terse_flag == 0)
	opt->short_flag = 1;

    if (opt->terse_flag)
        return listit(name, opt->upto_integer, argc, argv);

    data.kadm_handle = NULL;
    ret = kadm5_dup_context(kadm_handle, &data.kadm_handle);
    if (ret)
        krb5_err(context, 1, ret, "Could not duplicate kadmin connection");
    data.table = NULL;
    data.chead = NULL;
    data.ctail = &data.chead;
    data.mask = 0;
    data.extra_mask = 0;
    data.krb5_config_fname = opt->krb5_config_file_string;
    data.upto = opt->upto_integer;
    data.n = 0;

    if(opt->short_flag) {
	data.table = rtbl_create();
	rtbl_set_separator(data.table, "  ");
	data.format = print_entry_short;
    } else
	data.format = print_entry_long;
    if(opt->column_info_string == NULL) {
	if(opt->long_flag)
	    ret = setup_columns(&data, DEFAULT_COLUMNS_LONG);
	else
	    ret = setup_columns(&data, DEFAULT_COLUMNS_SHORT);
    } else
	ret = setup_columns(&data, opt->column_info_string);

    if(ret != 0) {
	if(data.table != NULL)
	    rtbl_destroy(data.table);
	return 0;
    }

    for(i = 0; i < argc; i++)
	ret = foreach_principal(argv[i], do_get_entry, name, &data);

    kadm5_destroy(data.kadm_handle);

    if(data.table != NULL) {
	rtbl_format(data.table, stdout);
	rtbl_destroy(data.table);
    }
    free_columns(&data);
    return ret != 0;
}

int
get_entry(struct get_options *opt, int argc, char **argv)
{
    return getit(opt, "get", argc, argv);
}

int
list_princs(struct list_options *opt, int argc, char **argv)
{
    struct get_options get_opt;

    if(sizeof(struct get_options) != sizeof(struct list_options)) {
	krb5_warnx(context, "programmer error: sizeof(struct get_options) != sizeof(struct list_options)");
	return 0;
    }
    memset(&get_opt, 0, sizeof(get_opt));
    get_opt.long_flag = opt->long_flag;
    get_opt.short_flag = opt->short_flag;
    get_opt.terse_flag = opt->terse_flag;
    get_opt.column_info_string = opt->column_info_string;
    get_opt.upto_integer = opt->upto_integer;
    return getit(&get_opt, "list", argc, argv);
}
