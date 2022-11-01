/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"

static int
name_type_ok(krb5_context context,
             krb5_kdc_configuration *config,
             krb5_const_principal principal)
{
    int nt = krb5_principal_get_type(context, principal);

    if (!krb5_principal_is_krbtgt(context, principal))
        return 1;
    if (nt == KRB5_NT_SRV_INST || nt == KRB5_NT_UNKNOWN)
        return 1;
    if (config->strict_nametypes == 0)
        return 1;
    return 0;
}

struct timeval _kdc_now;

static krb5_error_code
synthesize_hdb_close(krb5_context context, struct HDB *db)
{
    (void) context;
    (void) db;
    return 0;
}

/*
 * Synthesize an HDB entry suitable for PKINIT and GSS preauth.
 */
static krb5_error_code
synthesize_client(krb5_context context,
                  krb5_kdc_configuration *config,
                  krb5_const_principal princ,
                  HDB **db,
                  hdb_entry **h)
{
    static HDB null_db;
    krb5_error_code ret;
    hdb_entry *e;

    /* Hope this works! */
    null_db.hdb_destroy = synthesize_hdb_close;
    null_db.hdb_close = synthesize_hdb_close;
    if (db)
        *db = &null_db;

    ret = (e = calloc(1, sizeof(*e))) ? 0 : krb5_enomem(context);
    if (ret == 0) {
        e->flags.client = 1;
        e->flags.immutable = 1;
        e->flags.virtual = 1;
        e->flags.synthetic = 1;
        e->flags.do_not_store = 1;
        e->kvno = 1;
        e->keys.len = 0;
        e->keys.val = NULL;
        e->created_by.time = time(NULL);
        e->modified_by = NULL;
        e->valid_start = NULL;
        e->valid_end = NULL;
        e->pw_end = NULL;
        e->etypes = NULL;
        e->generation = NULL;
        e->extensions = NULL;
    }
    if (ret == 0)
        ret = (e->max_renew = calloc(1, sizeof(*e->max_renew))) ?
            0 : krb5_enomem(context);
    if (ret == 0)
        ret = (e->max_life = calloc(1, sizeof(*e->max_life))) ?
            0 : krb5_enomem(context);
    if (ret == 0)
        ret = krb5_copy_principal(context, princ, &e->principal);
    if (ret == 0)
        ret = krb5_copy_principal(context, princ, &e->created_by.principal);
    if (ret == 0) {
        /*
         * We can't check OCSP in the TGS path, so we can't let tickets for
         * synthetic principals live very long.
         */
        *(e->max_renew) = config->synthetic_clients_max_renew;
        *(e->max_life) = config->synthetic_clients_max_life;
        *h = e;
    } else if (e) {
        hdb_free_entry(context, &null_db, e);
    }
    return ret;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
_kdc_db_fetch(krb5_context context,
	      krb5_kdc_configuration *config,
	      krb5_const_principal principal,
	      unsigned flags,
	      krb5uint32 *kvno_ptr,
	      HDB **db,
	      hdb_entry **h)
{
    hdb_entry *ent = NULL;
    krb5_error_code ret = HDB_ERR_NOENTRY;
    int i;
    unsigned kvno = 0;
    krb5_principal enterprise_principal = NULL;
    krb5_const_principal princ;

    *h = NULL;

    if (!name_type_ok(context, config, principal))
        return HDB_ERR_NOENTRY;

    flags |= HDB_F_DECRYPT;
    if (kvno_ptr != NULL && *kvno_ptr != 0) {
	kvno = *kvno_ptr;
	flags |= HDB_F_KVNO_SPECIFIED;
    } else {
	flags |= HDB_F_ALL_KVNOS;
    }

    ent = calloc(1, sizeof (*ent));
    if (ent == NULL)
        return krb5_enomem(context);

    if (principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
        if (principal->name.name_string.len != 1) {
            ret = KRB5_PARSE_MALFORMED;
            krb5_set_error_message(context, ret,
                                   "malformed request: "
                                   "enterprise name with %d name components",
                                   principal->name.name_string.len);
            goto out;
        }
        ret = krb5_parse_name(context, principal->name.name_string.val[0],
                              &enterprise_principal);
        if (ret)
            goto out;
    }

    for (i = 0; i < config->num_db; i++) {
	HDB *curdb = config->db[i];

        if (db)
            *db = curdb;

	ret = curdb->hdb_open(context, curdb, O_RDONLY, 0);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_log(context, config, 0, "Failed to open database: %s", msg);
	    krb5_free_error_message(context, msg);
	    continue;
	}

        princ = principal;
        if (!(curdb->hdb_capability_flags & HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL) && enterprise_principal)
            princ = enterprise_principal;

        ret = hdb_fetch_kvno(context, curdb, princ, flags, 0, 0, kvno, ent);
	curdb->hdb_close(context, curdb);

        if (ret == HDB_ERR_NOENTRY)
            continue; /* Check the other databases */

        /*
         * This is really important, because errors like
         * HDB_ERR_NOT_FOUND_HERE (used to indicate to Samba that
         * the RODC on which this code is running does not have
         * the key we need, and so a proxy to the KDC is required)
         * have specific meaning, and need to be propogated up.
         */
        break;
    }

    switch (ret) {
    case HDB_ERR_WRONG_REALM:
    case 0:
        /*
         * the ent->entry.principal just contains hints for the client
         * to retry. This is important for enterprise principal routing
         * between trusts.
         */
        *h = ent;
        ent = NULL;
        break;

    case HDB_ERR_NOENTRY:
        if (db)
            *db = NULL;
        if ((flags & HDB_F_GET_CLIENT) && (flags & HDB_F_SYNTHETIC_OK) &&
            config->synthetic_clients) {
            ret = synthesize_client(context, config, principal, db, h);
            if (ret) {
                krb5_set_error_message(context, ret, "could not synthesize "
                                       "HDB client principal entry");
                ret = HDB_ERR_NOENTRY;
                krb5_prepend_error_message(context, ret, "no such entry found in hdb");
            }
        } else {
            krb5_set_error_message(context, ret, "no such entry found in hdb");
        }
        break;

    default:
        if (db)
            *db = NULL;
        break;
    }

out:
    krb5_free_principal(context, enterprise_principal);
    free(ent);
    return ret;
}

KDC_LIB_FUNCTION void KDC_LIB_CALL
_kdc_free_ent(krb5_context context, HDB *db, hdb_entry *ent)
{
    hdb_free_entry (context, db, ent);
    free (ent);
}

/*
 * Use the order list of preferred encryption types and sort the
 * available keys and return the most preferred key.
 */

krb5_error_code
_kdc_get_preferred_key(krb5_context context,
		       krb5_kdc_configuration *config,
		       hdb_entry *h,
		       const char *name,
		       krb5_enctype *enctype,
		       Key **key)
{
    krb5_error_code ret;
    int i;

    if (config->use_strongest_server_key) {
	const krb5_enctype *p = krb5_kerberos_enctypes(context);

	for (i = 0; p[i] != ETYPE_NULL; i++) {
	    if (krb5_enctype_valid(context, p[i]) != 0 &&
		!_kdc_is_weak_exception(h->principal, p[i]))
		continue;
	    ret = hdb_enctype2key(context, h, NULL, p[i], key);
	    if (ret != 0)
		continue;
	    if (enctype != NULL)
		*enctype = p[i];
	    return 0;
	}
    } else {
	*key = NULL;

	for (i = 0; i < h->keys.len; i++) {
	    if (krb5_enctype_valid(context, h->keys.val[i].key.keytype) != 0 &&
		!_kdc_is_weak_exception(h->principal, h->keys.val[i].key.keytype))
		continue;
	    ret = hdb_enctype2key(context, h, NULL,
				  h->keys.val[i].key.keytype, key);
	    if (ret != 0)
		continue;
	    if (enctype != NULL)
		*enctype = (*key)->key.keytype;
	    return 0;
	}
    }

    krb5_set_error_message(context, ret = KRB5KDC_ERR_ETYPE_NOSUPP,
			   "No valid kerberos key found for %s", name);
    return ret;
}

krb5_error_code
_kdc_verify_checksum(krb5_context context,
		     krb5_crypto crypto,
		     krb5_key_usage usage,
		     const krb5_data *data,
		     Checksum *cksum)
{
    krb5_error_code ret;

    ret = krb5_verify_checksum(context, crypto, usage,
			       data->data, data->length,
			       cksum);
    if (ret == KRB5_PROG_SUMTYPE_NOSUPP)
	ret = KRB5KDC_ERR_SUMTYPE_NOSUPP;

    return ret;
}

/*
 * Returns TRUE if a PAC should be included in ticket authorization data.
 *
 * Per [MS-KILE] 3.3.5.3, PACs are always included for TGTs; for service
 * tickets, policy is governed by whether the client explicitly requested
 * a PAC be omitted when requesting a TGT, or if the no-auth-data-reqd
 * flag is set on the service principal entry.
 */

krb5_boolean
_kdc_include_pac_p(astgs_request_t r)
{
    return TRUE;
}

/*
 * Notify the HDB backend and KDC plugin of the audited event.
 */

krb5_error_code
_kdc_audit_request(astgs_request_t r)
{
    krb5_error_code ret;
    struct HDB *hdb;

    ret = _kdc_plugin_audit(r);
    if (ret == 0 &&
	(hdb = r->clientdb ? r->clientdb : r->config->db[0]) &&
	hdb->hdb_audit)
	ret = hdb->hdb_audit(r->context, hdb, r->client, (hdb_request_t)r);

    return ret;
}
