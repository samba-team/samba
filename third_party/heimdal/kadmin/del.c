/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

static int
do_del_entry(krb5_principal principal, void *data)
{
    return kadm5_delete_principal(data, principal);
}

int
del_entry(void *opt, int argc, char **argv)
{
    int i;
    krb5_error_code ret = 0;
    void *dup_kadm_handle = NULL;

    ret = kadm5_dup_context(kadm_handle, &dup_kadm_handle);

    for (i = 0; ret == 0 && i < argc; i++)
	ret = foreach_principal(argv[i], do_del_entry, "del", dup_kadm_handle);

    if (dup_kadm_handle)
        kadm5_destroy(dup_kadm_handle);
    return ret != 0;
}

static int
do_del_ns_entry(krb5_principal nsp, void *data)
{
    krb5_error_code ret;
    krb5_principal p = NULL;
    const char *comp0 = krb5_principal_get_comp_string(context, nsp, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, nsp, 1);

    if (krb5_principal_get_num_comp(context, nsp) != 2) {
        char *unsp = NULL;

        ret = krb5_unparse_name(context, nsp, &unsp);
        krb5_warn(context, ret,
                  "Not a valid namespace name (component count is not 2): %s",
                  unsp ? unsp : "<out of memory>");
        free(unsp);
        return EINVAL;
    }

    ret = krb5_make_principal(context, &p,
                              krb5_principal_get_realm(context, nsp),
                              "WELLKNOWN", HDB_WK_NAMESPACE, NULL);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, p, 2, comp0);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, p, 3, comp1);
    if (ret == 0)
        ret = kadm5_delete_principal(kadm_handle, p);
    krb5_free_principal(context, p);
    return ret;
}

int
del_namespace(void *opt, int argc, char **argv)
{
    int i;
    krb5_error_code ret = 0;
    void *dup_kadm_handle = NULL;

    ret = kadm5_dup_context(kadm_handle, &dup_kadm_handle);
    for (i = 0; ret == 0 && i < argc; i++)
        ret = foreach_principal(argv[i], do_del_ns_entry, "del_ns",
                                dup_kadm_handle);
    if (dup_kadm_handle)
        kadm5_destroy(dup_kadm_handle);
    return ret != 0;
}

int
del_alias(void *opt, int argc, char **argv)
{
    krb5_error_code ret;
    size_t i;


    if (argc < 1) {
        krb5_warnx(context, "No aliases given");
        return 1;
    }

    for (; argc; argc--, argv++) {
        kadm5_principal_ent_rec princ;
        krb5_principal p;
        HDB_Ext_Aliases *a;
        HDB_extension ext;
        krb5_tl_data *tl;
        krb5_data d;

        if ((ret = krb5_parse_name(context, argv[0], &p))) {
            krb5_warn(context, ret, "Invalid principal: %s", argv[0]);
            return 1;
        }

        memset(&princ, 0, sizeof(princ));
        ret = kadm5_get_principal(kadm_handle, p, &princ,
                                  KADM5_PRINCIPAL_NORMAL_MASK | KADM5_TL_DATA);
        if (ret) {
            krb5_warn(context, ret, "Principal alias not found %s", argv[0]);
            continue;
        }

        if (krb5_principal_compare(context, p, princ.principal)) {
            krb5_warn(context, ret, "Not deleting principal %s because it is "
                      "not an alias; use 'delete' to delete the principal",
                      argv[0]);
            continue;
        }

        a = &ext.data.u.aliases;
        a->case_insensitive = 0;
        a->aliases.len = 0;
        a->aliases.val = 0;
        if ((tl = get_tl(&princ, KRB5_TL_ALIASES)) == NULL) {
            krb5_warnx(context, "kadm5_get_principal() found principal %s but "
                       "not its aliases", argv[0]);
            kadm5_free_principal_ent(kadm_handle, &princ);
            krb5_free_principal(context, p);
            return 1;
        }

        ret = decode_HDB_Ext_Aliases(tl->tl_data_contents, tl->tl_data_length,
                                     a, NULL);
        if (ret) {
            krb5_warn(context, ret, "Principal alias list could not be decoded");
            kadm5_free_principal_ent(kadm_handle, &princ);
            krb5_free_principal(context, p);
            return 1;
        }

        /*
         * Remove alias, but also, don't assume it appears only once in aliases
         * list.
         */
        i = 0;
        while (i < a->aliases.len) {
            if (!krb5_principal_compare(context, p, &a->aliases.val[i])) {
                i++;
                continue;
            }
            free_Principal(&a->aliases.val[i]);
            if (i + 1 < a->aliases.len)
                memmove(&a->aliases.val[i],
                        &a->aliases.val[i + 1],
                        sizeof(a->aliases.val[i]) * (a->aliases.len - (i + 1)));
            if (a->aliases.len)
                a->aliases.len--;
            continue;
        }

        krb5_data_zero(&d);
        ext.data.element = choice_HDB_extension_data_aliases;
        ext.mandatory = 0;
        if (ret == 0)
            ASN1_MALLOC_ENCODE(HDB_extension, d.data, d.length, &ext, &i, ret);
        free_HDB_Ext_Aliases(a);
        if (ret == 0) {
            int16_t len = d.length;

            if (len < 0 || d.length != (size_t)len) {
                krb5_warnx(context, "Too many aliases; does not fit in 32767 bytes");
                ret = EOVERFLOW;
            } else  {
                add_tl(&princ, KRB5_TL_EXTENSION, &d);
                krb5_data_zero(&d);
            }
        }
        if (ret == 0) {
            ret = kadm5_modify_principal(kadm_handle, &princ,
                                         KADM5_PRINCIPAL | KADM5_TL_DATA);
            if (ret)
                krb5_warn(context, ret, "kadm5_modify_principal");
        }

        kadm5_free_principal_ent(kadm_handle, &princ);
        krb5_free_principal(context, p);
        krb5_data_free(&d);
        p = NULL;
    }

    return ret == 0 ? 0 : 1;
}
