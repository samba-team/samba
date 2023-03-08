/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

void
add_tl(kadm5_principal_ent_rec *princ, int type, krb5_data *data)
{
    krb5_tl_data *tl, **ptl;

    tl = ecalloc(1, sizeof(*tl));
    tl->tl_data_next = NULL;
    tl->tl_data_type = type;
    tl->tl_data_length = data->length;
    tl->tl_data_contents = data->data;

    if (tl->tl_data_length < 0 || data->length != (size_t)tl->tl_data_length)
        errx(1, "TL data overflow");

    princ->n_tl_data++;
    ptl = &princ->tl_data;
    while (*ptl != NULL)
	ptl = &(*ptl)->tl_data_next;
    *ptl = tl;

    return;
}

/*
 * Find a TL data of type KRB5_TL_EXTENSION that has an extension of type
 * `etype' in it.
 */
krb5_tl_data *
get_tl(kadm5_principal_ent_rec *princ, int type)
{
    krb5_tl_data *tl = princ->tl_data;

    while (tl && tl->tl_data_type != type)
        tl = tl->tl_data_next;
    return tl;
}

static void
add_constrained_delegation(krb5_context contextp,
			   kadm5_principal_ent_rec *princ,
			   struct getarg_strings *strings)
{
    krb5_error_code ret;
    HDB_extension ext;
    krb5_data buf;
    size_t size = 0;

    memset(&ext, 0, sizeof(ext));
    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_allowed_to_delegate_to;

    if (strings->num_strings == 1 && strings->strings[0][0] == '\0') {
	ext.data.u.allowed_to_delegate_to.val = NULL;
	ext.data.u.allowed_to_delegate_to.len = 0;
    } else {
	krb5_principal p;
	int i;

	ext.data.u.allowed_to_delegate_to.val =
	    calloc(strings->num_strings,
		   sizeof(ext.data.u.allowed_to_delegate_to.val[0]));
	ext.data.u.allowed_to_delegate_to.len = strings->num_strings;

	for (i = 0; i < strings->num_strings; i++) {
	    ret = krb5_parse_name(contextp, strings->strings[i], &p);
	    if (ret)
		abort();
	    ret = copy_Principal(p, &ext.data.u.allowed_to_delegate_to.val[i]);
	    if (ret)
		abort();
	    krb5_free_principal(contextp, p);
	}
    }

    ASN1_MALLOC_ENCODE(HDB_extension, buf.data, buf.length,
		       &ext, &size, ret);
    free_HDB_extension(&ext);
    if (ret)
	abort();
    if (buf.length != size)
	abort();

    add_tl(princ, KRB5_TL_EXTENSION, &buf);
}

static void
add_aliases(krb5_context contextp, kadm5_principal_ent_rec *princ,
	    struct getarg_strings *strings)
{
    krb5_error_code ret = 0;
    HDB_extension ext;
    krb5_data buf;
    krb5_principal p;
    size_t size = 0;
    int i;

    memset(&ext, 0, sizeof(ext));
    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_aliases;
    ext.data.u.aliases.case_insensitive = 0;

    if (strings->num_strings == 1 && strings->strings[0][0] == '\0') {
	ext.data.u.aliases.aliases.val = NULL;
	ext.data.u.aliases.aliases.len = 0;
    } else {
	ext.data.u.aliases.aliases.val =
	    calloc(strings->num_strings,
		   sizeof(ext.data.u.aliases.aliases.val[0]));
	ext.data.u.aliases.aliases.len = strings->num_strings;

	for (i = 0; ret == 0 && i < strings->num_strings; i++) {
	    ret = krb5_parse_name(contextp, strings->strings[i], &p);
            if (ret)
                krb5_err(contextp, 1, ret, "Could not parse alias %s",
                         strings->strings[i]);
            if (ret == 0)
                ret = copy_Principal(p, &ext.data.u.aliases.aliases.val[i]);
            if (ret)
                krb5_err(contextp, 1, ret, "Could not copy parsed alias %s",
                         strings->strings[i]);
	    krb5_free_principal(contextp, p);
	}
    }

    ASN1_MALLOC_ENCODE(HDB_extension, buf.data, buf.length,
		       &ext, &size, ret);
    free_HDB_extension(&ext);
    if (ret)
	abort();
    if (buf.length != size)
	abort();

    add_tl(princ, KRB5_TL_EXTENSION, &buf);
}

static void
add_pkinit_acl(krb5_context contextp, kadm5_principal_ent_rec *princ,
	       struct getarg_strings *strings)
{
    krb5_error_code ret;
    HDB_extension ext;
    krb5_data buf;
    size_t size = 0;
    int i;

    memset(&ext, 0, sizeof(ext));
    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_pkinit_acl;
    ext.data.u.aliases.case_insensitive = 0;

    if (strings->num_strings == 1 && strings->strings[0][0] == '\0') {
	ext.data.u.pkinit_acl.val = NULL;
	ext.data.u.pkinit_acl.len = 0;
    } else {
	ext.data.u.pkinit_acl.val =
	    calloc(strings->num_strings,
		   sizeof(ext.data.u.pkinit_acl.val[0]));
	ext.data.u.pkinit_acl.len = strings->num_strings;

	for (i = 0; i < strings->num_strings; i++) {
	    ext.data.u.pkinit_acl.val[i].subject = estrdup(strings->strings[i]);
	}
    }

    ASN1_MALLOC_ENCODE(HDB_extension, buf.data, buf.length,
		       &ext, &size, ret);
    free_HDB_extension(&ext);
    if (ret)
	abort();
    if (buf.length != size)
	abort();

    add_tl(princ, KRB5_TL_EXTENSION, &buf);
}

static krb5_error_code
add_etypes(krb5_context contextp,
           kadm5_principal_ent_rec *princ,
	   struct getarg_strings *strings)
{
    krb5_error_code ret = 0;
    HDB_EncTypeList etypes;
    krb5_data buf;
    size_t i, size;

    etypes.len = strings->num_strings;
    if ((etypes.val = calloc(strings->num_strings,
                             sizeof(etypes.val[0]))) == NULL)
        krb5_err(contextp, 1, ret, "Out of memory");

    for (i = 0; i < strings->num_strings; i++) {
        krb5_enctype etype;

        ret = krb5_string_to_enctype(contextp, strings->strings[i], &etype);
        if (ret) {
            krb5_warn(contextp, ret, "Could not parse enctype %s",
                      strings->strings[i]);
            free(etypes.val);
            return ret;
        }
        etypes.val[i] = etype;
    }

    if (ret == 0) {
        ASN1_MALLOC_ENCODE(HDB_EncTypeList, buf.data, buf.length,
                           &etypes, &size, ret);
    }
    if (ret || buf.length != size)
        abort();
    add_tl(princ, KRB5_TL_ETYPES, &buf);
    free(etypes.val);
    return 0;
}

static void
add_kvno_diff(krb5_context contextp, kadm5_principal_ent_rec *princ,
	      int is_svc_diff, krb5_kvno kvno_diff)
{
    krb5_error_code ret;
    HDB_extension ext;
    krb5_data buf;
    size_t size = 0;

    if (kvno_diff < 0)
	return;
    if (kvno_diff > 2048)
	kvno_diff = 2048;

    ext.mandatory = 0;
    if (is_svc_diff) {
	ext.data.element = choice_HDB_extension_data_hist_kvno_diff_svc;
	ext.data.u.hist_kvno_diff_svc = (unsigned int)kvno_diff;
    } else {
	ext.data.element = choice_HDB_extension_data_hist_kvno_diff_clnt;
	ext.data.u.hist_kvno_diff_clnt = (unsigned int)kvno_diff;
    }
    ASN1_MALLOC_ENCODE(HDB_extension, buf.data, buf.length,
		       &ext, &size, ret);
    if (ret)
	abort();
    if (buf.length != size)
	abort();

    add_tl(princ, KRB5_TL_EXTENSION, &buf);
}

static void
add_krb5_config(kadm5_principal_ent_rec *princ, const char *fname)
{
    HDB_extension ext;
    krb5_data buf;
    size_t size;
    int ret;

    memset(&ext, 0, sizeof(ext));
    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_krb5_config;

    if ((ret = rk_undumpdata(fname,
                             &ext.data.u.krb5_config.data,
                             &ext.data.u.krb5_config.length))) {
        krb5_warn(context, ret, "Could not read %s", fname);
        return;
    }

    ASN1_MALLOC_ENCODE(HDB_extension, buf.data, buf.length,
		       &ext, &size, ret);
    free_HDB_extension(&ext);
    if (ret)
	abort();
    if (buf.length != size)
	abort();
    add_tl(princ, KRB5_TL_EXTENSION, &buf);
}

struct mod_data {
    struct modify_namespace_key_rotation_options *opt_ns_kr;
    struct modify_namespace_options *opt_ns;
    struct modify_options *opt;
    void *kadm_handle;
};

static int
do_mod_entry(krb5_principal principal, void *data)
{
    krb5_error_code ret;
    kadm5_principal_ent_rec princ;
    int mask = 0;
    struct mod_data *m = data;
    struct modify_options *e = m->opt;

    memset (&princ, 0, sizeof(princ));
    ret = kadm5_get_principal(m->kadm_handle, principal, &princ,
			      KADM5_PRINCIPAL | KADM5_ATTRIBUTES |
			      KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
			      KADM5_PRINC_EXPIRE_TIME |
			      KADM5_PW_EXPIRATION);
    if(ret)
	return ret;

    if(e->max_ticket_life_string ||
       e->max_renewable_life_string ||
       e->expiration_time_string ||
       e->pw_expiration_time_string ||
       e->attributes_string ||
       e->policy_string ||
       e->kvno_integer != -1 ||
       e->service_enctypes_strings.num_strings ||
       e->constrained_delegation_strings.num_strings ||
       e->alias_strings.num_strings ||
       e->pkinit_acl_strings.num_strings ||
       e->krb5_config_file_string ||
       e->hist_kvno_diff_clnt_integer != -1 ||
       e->hist_kvno_diff_svc_integer != -1) {
	ret = set_entry(context, &princ, &mask,
			e->max_ticket_life_string,
			e->max_renewable_life_string,
			e->expiration_time_string,
			e->pw_expiration_time_string,
			e->attributes_string,
			e->policy_string);
	if(e->kvno_integer != -1) {
	    princ.kvno = e->kvno_integer;
	    mask |= KADM5_KVNO;
	}
	if (e->constrained_delegation_strings.num_strings) {
	    add_constrained_delegation(context, &princ,
				       &e->constrained_delegation_strings);
	    mask |= KADM5_TL_DATA;
	}
	if (e->alias_strings.num_strings) {
	    add_aliases(context, &princ, &e->alias_strings);
	    mask |= KADM5_TL_DATA;
	}
	if (e->pkinit_acl_strings.num_strings) {
	    add_pkinit_acl(context, &princ, &e->pkinit_acl_strings);
	    mask |= KADM5_TL_DATA;
	}
        if (e->service_enctypes_strings.num_strings) {
            ret = add_etypes(context, &princ, &e->service_enctypes_strings);
	    mask |= KADM5_TL_DATA;
        }
	if (e->hist_kvno_diff_clnt_integer != -1) {
	    add_kvno_diff(context, &princ, 0, e->hist_kvno_diff_clnt_integer);
	    mask |= KADM5_TL_DATA;
	}
	if (e->hist_kvno_diff_svc_integer != -1) {
	    add_kvno_diff(context, &princ, 1, e->hist_kvno_diff_svc_integer);
	    mask |= KADM5_TL_DATA;
	}
        if (e->krb5_config_file_string) {
            add_krb5_config(&princ, e->krb5_config_file_string);
	    mask |= KADM5_TL_DATA;
        }
    } else
	ret = edit_entry(&princ, &mask, NULL, 0);
    if(ret == 0) {
	ret = kadm5_modify_principal(m->kadm_handle, &princ, mask);
	if(ret)
	    krb5_warn(context, ret, "kadm5_modify_principal");
    }

    kadm5_free_principal_ent(m->kadm_handle, &princ);
    return ret;
}

int
mod_entry(struct modify_options *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    struct mod_data data;
    int i;

    data.kadm_handle = NULL;
    data.opt_ns_kr = NULL;
    data.opt_ns = NULL;
    data.opt = opt;

    ret = kadm5_dup_context(kadm_handle, &data.kadm_handle);
    for (i = 0; ret == 0 && i < argc; i++)
	ret = foreach_principal(argv[i], do_mod_entry, "mod", &data);
    if (data.kadm_handle)
        kadm5_destroy(data.kadm_handle);
    return ret != 0;
}

static int
do_mod_ns_entry(krb5_principal principal, void *data)
{
    krb5_error_code ret;
    kadm5_principal_ent_rec princ;
    int mask = 0;
    struct mod_data *m = data;
    struct modify_namespace_options *e = m->opt_ns;

    memset (&princ, 0, sizeof(princ));
    ret = kadm5_get_principal(m->kadm_handle, principal, &princ,
			      KADM5_PRINCIPAL | KADM5_ATTRIBUTES |
			      KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
			      KADM5_PRINC_EXPIRE_TIME |
			      KADM5_PW_EXPIRATION);
    if(ret)
	return ret;

    if(e->max_ticket_life_string ||
       e->max_renewable_life_string ||
       e->attributes_string ||
       e->enctypes_strings.num_strings ||
       e->krb5_config_file_string) {
        ret = set_entry(context, &princ, &mask, e->max_ticket_life_string,
                        e->max_renewable_life_string, NULL, NULL,
                        e->attributes_string, NULL);
        if (e->enctypes_strings.num_strings) {
            ret = add_etypes(context, &princ, &e->enctypes_strings);
	    mask |= KADM5_TL_DATA;
        }
        if (e->krb5_config_file_string) {
            add_krb5_config(&princ, e->krb5_config_file_string);
	    mask |= KADM5_TL_DATA;
        }
    } else
	ret = edit_entry(&princ, &mask, NULL, 0);
    if(ret == 0) {
	ret = kadm5_modify_principal(m->kadm_handle, &princ, mask);
	if(ret)
	    krb5_warn(context, ret, "kadm5_modify_principal");
    }

    kadm5_free_principal_ent(m->kadm_handle, &princ);
    return ret;
}

int
modify_namespace(struct modify_namespace_options *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    struct mod_data data;
    int i;

    data.kadm_handle = NULL;
    data.opt_ns_kr = NULL;
    data.opt_ns = opt;
    data.opt = NULL;

    ret = kadm5_dup_context(kadm_handle, &data.kadm_handle);
    for (i = 0; ret == 0 && i < argc; i++)
	ret = foreach_principal(argv[i], do_mod_ns_entry, "mod_ns", &data);
    if (data.kadm_handle)
        kadm5_destroy(data.kadm_handle);
    return ret != 0;
}

#if 0
struct modify_namespace_key_rotation_options {
    int force_flag;
    int keep_base_key_flag;
    char* revoke_old_string;
    char* new_key_rotation_epoch_string;
    char* new_key_rotation_period_string;
};
#endif

static int
princ2kstuple(kadm5_principal_ent_rec *princ, 
              unsigned int kvno,
              krb5_key_salt_tuple **kstuple,
              size_t *nkstuple)
{
    krb5_error_code ret = 0;
    HDB_EncTypeList etypes;
    krb5_tl_data *tl;
    size_t i;

    *kstuple = 0;
    *nkstuple = 0;
    etypes.len = 0;
    etypes.val = 0;
    for (tl = princ->tl_data; tl; tl = tl->tl_data_next) {
        if (tl->tl_data_type != KRB5_TL_ETYPES || tl->tl_data_length < 0)
            continue;
        ret = decode_HDB_EncTypeList(tl->tl_data_contents, tl->tl_data_length,
                                     &etypes, NULL);
        if (ret)
            break;
        *nkstuple = etypes.len;
        *kstuple = ecalloc(etypes.len, sizeof(kstuple[0][0]));
        for (i = 0; i < etypes.len; i++) {
            (*kstuple)[i].ks_enctype = etypes.val[i];
            (*kstuple)[i].ks_salttype = 0;
        }
        return 0;
    }
    if (princ->n_key_data > 0) {
        *kstuple = ecalloc(1, sizeof(kstuple[0][0]));
        *nkstuple = 1;
        for (i = 0; i < princ->n_key_data; i++) {
            if (princ->key_data->key_data_kvno == kvno) {
                (*kstuple)[0].ks_enctype = princ->key_data->key_data_type[0];
                (*kstuple)[0].ks_salttype = princ->key_data->key_data_type[1];
                return 0;
            }
        }
    }
    krb5_warnx(context, "Could not determine what enctypes to generate "
               "keys for; recreate namespace?");
    return EINVAL;
}

static int
randkey_kr(kadm5_principal_ent_rec *princ,
           unsigned int old_kvno,
           unsigned int kvno)
{
    krb5_key_salt_tuple *kstuple = 0;
    krb5_error_code ret = 0;
    size_t nkstuple = 0;

    /*
     * We might be using kadm5clnt, so we'll use kadm5_randkey_principal_3(),
     * which will generate new keys on the server side.  This allows a race,
     * but it will be detected by the key rotation update checks in lib/kadm5
     * and lib/hdb.
     */
    ret = princ2kstuple(princ, old_kvno, &kstuple, &nkstuple);
    if (ret == 0)
        ret = kadm5_randkey_principal_3(kadm_handle, princ->principal, 1,
                                        nkstuple, kstuple, NULL, NULL);
    free(kstuple);
    return ret;
}

static int
do_mod_ns_kr(krb5_principal principal, void *data)
{
    krb5_error_code ret;
    kadm5_principal_ent_rec princ;
    struct modify_namespace_key_rotation_options *e = data;
    HDB_Ext_KeyRotation existing;
    HDB_Ext_KeyRotation new_kr;
    HDB_extension ext;
    KeyRotation new_krs[3];
    krb5_tl_data *tl;
    krb5_data d;
    time_t now = time(NULL);
    size_t size;
    int freeit = 0;

    d.data = 0;
    d.length = 0;
    new_kr.len = 0;
    new_kr.val = new_krs;
    ext.mandatory = 0;
    ext.data.element = choice_HDB_extension_data_key_rotation;
    ext.data.u.key_rotation.len = 0;
    ext.data.u.key_rotation.val = 0;
    existing.len = 0;
    existing.val = 0;
    memset(&new_krs, 0, sizeof(new_krs));
    memset(&princ, 0, sizeof(princ));

    if (e->force_flag || e->revoke_old_string) {
        krb5_warnx(context, "--force and --revoke-old not implemented yet");
        return ENOTSUP;
    }

    ret = kadm5_get_principal(kadm_handle, principal, &princ,
			      KADM5_PRINCIPAL | KADM5_KVNO |
                              KADM5_KEY_DATA | KADM5_TL_DATA);
    if (ret == 0) {
        freeit = 1;
        for (tl = princ.tl_data; tl; tl = tl->tl_data_next) {
            if (tl->tl_data_type != KRB5_TL_KRB5_CONFIG)
                continue;
            ret = decode_HDB_Ext_KeyRotation(tl->tl_data_contents,
                                             tl->tl_data_length, &existing, NULL);
            if (ret) {
                krb5_warn(context, ret, "unable to decode existing key "
                          "rotation schedule");
                kadm5_free_principal_ent(kadm_handle, &princ);
                return ret;
            }
        }
        if (!existing.len) {
            krb5_warnx(context, "no key rotation schedule; "
                      "re-create namespace?");
            kadm5_free_principal_ent(kadm_handle, &princ);
            return EINVAL;
        }
    }

    if (ret) {
        krb5_warn(context, ret, "No such namespace");
        kadm5_free_principal_ent(kadm_handle, &princ);
        return ret;
    }

    if (existing.len > 1)
        new_kr.val[1] = existing.val[0];
    if (existing.len > 2)
        new_kr.val[2] = existing.val[1];
    new_kr.val[0].flags = existing.val[0].flags;
    new_kr.val[0].base_kvno = princ.kvno + 2; /* XXX Compute better */
    new_kr.val[0].base_key_kvno = existing.val[0].base_key_kvno + 1;
    if (e->new_key_rotation_epoch_string) {
        if ((ret = str2time_t(e->new_key_rotation_epoch_string,
                              &new_kr.val[0].epoch)))
            krb5_warn(context, ret, "Invalid epoch specification: %s",
                      e->new_key_rotation_epoch_string);
    } else {
        new_kr.val[0].epoch = existing.val[0].epoch +
            existing.val[0].period * (princ.kvno - new_kr.val[0].base_kvno);
    }
    if (ret == 0 && e->new_key_rotation_period_string) {
        time_t t;

        if ((ret = str2time_t(e->new_key_rotation_period_string, &t)))
            krb5_warn(context, ret, "Invalid period specification: %s",
                      e->new_key_rotation_period_string);
        else
            new_kr.val[0].period = t;
    } else {
        new_kr.val[0].period = existing.val[0].period +
            existing.val[0].period * (princ.kvno - new_kr.val[0].base_kvno);
    }
    if (new_kr.val[0].epoch < now) {
        krb5_warnx(context, "New epoch cannot be in the past");
        ret = EINVAL;
    }
    if (new_kr.val[0].epoch < 30) {
        krb5_warnx(context, "New period cannot be less than 30s");
        ret = EINVAL;
    }
    if (ret == 0)
        ret = randkey_kr(&princ, princ.kvno, new_kr.val[0].base_key_kvno);
    ext.data.u.key_rotation = new_kr;
    if (ret == 0)
        ASN1_MALLOC_ENCODE(HDB_extension, d.data, d.length,
                           &ext, &size, ret);
    if (ret == 0)
        add_tl(&princ, KRB5_TL_EXTENSION, &d);
    if (ret == 0) {
	ret = kadm5_modify_principal(kadm_handle, &princ,
                                     KADM5_PRINCIPAL | KADM5_TL_DATA);
	if (ret)
	    krb5_warn(context, ret, "Could not update namespace");
    }

    krb5_data_free(&d);
    free_HDB_Ext_KeyRotation(&existing);
    if (freeit)
        kadm5_free_principal_ent(kadm_handle, &princ);
    return ret;
}

int
modify_ns_kr(struct modify_namespace_key_rotation_options *opt,
             int argc,
             char **argv)
{
    krb5_error_code ret = 0;
    struct mod_data data;
    int i;

    data.kadm_handle = NULL;
    data.opt_ns_kr = opt;
    data.opt_ns = NULL;
    data.opt = NULL;

    ret = kadm5_dup_context(kadm_handle, &data.kadm_handle);
    for (i = 0; ret == 0 && i < argc; i++)
	ret = foreach_principal(argv[i], do_mod_ns_kr, "mod_ns", opt);
    if (data.kadm_handle)
        kadm5_destroy(data.kadm_handle);
    return ret != 0;
}

#define princ_realm(P) ((P)->realm)
#define princ_num_comp(P) ((P)->name.name_string.len)
#define princ_ncomp(P, N) ((P)->name.name_string.val[(N)])

static int
princ_cmp(const void *a, const void *b)
{
    krb5_const_principal pa = a;
    krb5_const_principal pb = b;
    size_t i;
    int r;

    r = strcmp(princ_realm(pa), princ_realm(pb));
    if (r == 0)
        r = princ_num_comp(pa) - princ_num_comp(pb);
    for (i = 0; r == 0 && i < princ_num_comp(pa); i++)
        r = strcmp(princ_ncomp(pa, i), princ_ncomp(pb, i));
    return r;
}

/* Sort and remove dups */
static void
uniq(HDB_Ext_Aliases *a)
{
    size_t i = 0;

    qsort(a->aliases.val, a->aliases.len, sizeof(a->aliases.val[0]),
          princ_cmp);

    /* While there are at least two principals left to look at... */
    while (i + 1 < a->aliases.len) {
        if (princ_cmp(&a->aliases.val[i], &a->aliases.val[i + 1])) {
            /* ...if they are different, increment i and loop */
            i++;
            continue;
        }
        /* ...else drop the one on the right and loop w/o incrementing i */
        free_Principal(&a->aliases.val[i + 1]);
        if (i + 2 < a->aliases.len)
            memmove(&a->aliases.val[i + 1],
                    &a->aliases.val[i + 2],
                    sizeof(a->aliases.val[i + 1]) * (a->aliases.len - (i + 2)));
        a->aliases.len--;
    }
}

int
add_alias(void *opt, int argc, char **argv)
{
    kadm5_principal_ent_rec princ;
    krb5_error_code ret;
    krb5_principal p = NULL;
    HDB_Ext_Aliases *a;
    HDB_extension ext;
    krb5_tl_data *tl = NULL;
    krb5_data d;
    size_t i;

    memset(&princ, 0, sizeof(princ));
    krb5_data_zero(&d);

    if (argc < 2) {
        krb5_warnx(context, "Principal not given");
        return 1;
    }
    ret = krb5_parse_name(context, argv[0], &p);
    if (ret) {
        krb5_warn(context, ret, "Invalid principal: %s", argv[0]);
        return 1;
    }

    ret = kadm5_get_principal(kadm_handle, p, &princ,
			      KADM5_PRINCIPAL_NORMAL_MASK | KADM5_TL_DATA);
    if (ret) {
	krb5_warn(context, ret, "Principal not found %s", argv[0]);
        return 1;
    }
    krb5_free_principal(context, p);
    p = NULL;

    a = &ext.data.u.aliases;
    a->case_insensitive = 0;
    a->aliases.len = 0;
    a->aliases.val = 0;
    if ((tl = get_tl(&princ, KRB5_TL_ALIASES))) {
        ret = decode_HDB_Ext_Aliases(tl->tl_data_contents, tl->tl_data_length,
                                     a, NULL);
        if (ret) {
            kadm5_free_principal_ent(kadm_handle, &princ);
            krb5_warn(context, ret, "Principal has invalid aliases extension "
                      "contents: %s", argv[0]);
            return 1;
        }
    }

    argv++;
    argc--;

    a->aliases.val = realloc(a->aliases.val,
                            sizeof(a->aliases.val[0]) * (a->aliases.len + argc));
    if (a->aliases.val == NULL)
        krb5_err(context, 1, errno, "Out of memory");
    for (i = 0; ret == 0 && i < argc; i++) {
        ret = krb5_parse_name(context, argv[i], &p);
        if (ret) {
            krb5_warn(context, ret, "krb5_parse_name");
            break;
        }
        ret = copy_Principal(p, &a->aliases.val[a->aliases.len]);
        krb5_free_principal(context, p);
        if (ret == 0)
            a->aliases.len++;
    }
    uniq(a);

    ext.data.element = choice_HDB_extension_data_aliases;
    ext.mandatory = 0;
    if (ret == 0)
        ASN1_MALLOC_ENCODE(HDB_extension, d.data, d.length, &ext, &i, ret);
    free_HDB_extension(&ext);
    if (ret == 0) {
        int16_t len = d.length;

        if (len < 0 || d.length != (size_t)len) {
            krb5_warnx(context, "Too many aliases; does not fit in 32767 bytes");
            ret = EOVERFLOW;
        }
    }
    if (ret == 0) {
        add_tl(&princ, KRB5_TL_EXTENSION, &d);
        krb5_data_zero(&d);
        ret = kadm5_modify_principal(kadm_handle, &princ,
                                     KADM5_PRINCIPAL | KADM5_TL_DATA);
        if (ret)
            krb5_warn(context, ret, "kadm5_modify_principal");
    }

    kadm5_free_principal_ent(kadm_handle, &princ);
    krb5_data_free(&d);
    return ret == 0 ? 0 : 1;
}
