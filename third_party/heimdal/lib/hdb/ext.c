/*
 * Copyright (c) 2004 - 2005 Kungliga Tekniska Högskolan
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

#include "hdb_locl.h"
#include <der.h>

krb5_error_code
hdb_entry_check_mandatory(krb5_context context, const hdb_entry *ent)
{
    size_t i;

    if (ent->extensions == NULL)
	return 0;

    /*
     * check for unknown extensions and if they where tagged mandatory
     */

    for (i = 0; i < ent->extensions->len; i++) {
	if (ent->extensions->val[i].data.element !=
	    choice_HDB_extension_data_asn1_ellipsis)
	    continue;
	if (ent->extensions->val[i].mandatory) {
	    krb5_set_error_message(context, HDB_ERR_MANDATORY_OPTION,
				   "Principal have unknown "
				   "mandatory extension");
	    return HDB_ERR_MANDATORY_OPTION;
	}
    }
    return 0;
}

HDB_extension *
hdb_find_extension(const hdb_entry *entry, int type)
{
    size_t i;

    if (entry->extensions == NULL)
	return NULL;

    for (i = 0; i < entry->extensions->len; i++)
	if (entry->extensions->val[i].data.element == (unsigned)type)
	    return &entry->extensions->val[i];
    return NULL;
}

/*
 * Replace the extension `ext' in `entry'. Make a copy of the
 * extension, so the caller must still free `ext' on both success and
 * failure. Returns 0 or error code.
 */

krb5_error_code
hdb_replace_extension(krb5_context context,
		      hdb_entry *entry,
		      const HDB_extension *ext)
{
    HDB_extension *ext2;
    int ret;

    ext2 = NULL;

    if (entry->extensions == NULL) {
	entry->extensions = calloc(1, sizeof(*entry->extensions));
	if (entry->extensions == NULL) {
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
    } else if (ext->data.element != choice_HDB_extension_data_asn1_ellipsis) {
	ext2 = hdb_find_extension(entry, ext->data.element);
    } else {
	/*
	 * This is an unknown extension, and we are asked to replace a
	 * possible entry in `entry' that is of the same type. This
	 * might seem impossible, but ASN.1 CHOICE comes to our
	 * rescue. The first tag in each branch in the CHOICE is
	 * unique, so just find the element in the list that have the
	 * same tag was we are putting into the list.
	 */
	Der_class replace_class, list_class;
	Der_type replace_type, list_type;
	unsigned int replace_tag, list_tag;
	size_t size;
	size_t i;

	ret = der_get_tag(ext->data.u.asn1_ellipsis.data,
			  ext->data.u.asn1_ellipsis.length,
			  &replace_class, &replace_type, &replace_tag,
			  &size);
	if (ret) {
	    krb5_set_error_message(context, ret, "hdb: failed to decode "
				   "replacement hdb extension");
	    return ret;
	}

	for (i = 0; i < entry->extensions->len; i++) {
	    HDB_extension *ext3 = &entry->extensions->val[i];

	    if (ext3->data.element != choice_HDB_extension_data_asn1_ellipsis)
		continue;

	    ret = der_get_tag(ext3->data.u.asn1_ellipsis.data,
			      ext3->data.u.asn1_ellipsis.length,
			      &list_class, &list_type, &list_tag,
			      &size);
	    if (ret) {
		krb5_set_error_message(context, ret, "hdb: failed to decode "
				       "present hdb extension");
		return ret;
	    }

	    if (MAKE_TAG(replace_class,replace_type,replace_type) ==
		MAKE_TAG(list_class,list_type,list_type)) {
		ext2 = ext3;
		break;
	    }
	}
    }

    if (ext2) {
	free_HDB_extension(ext2);
	ret = copy_HDB_extension(ext, ext2);
	if (ret)
	    krb5_set_error_message(context, ret, "hdb: failed to copy replacement "
				   "hdb extension");
	return ret;
    }

    return add_HDB_extensions(entry->extensions, ext);
}

krb5_error_code
hdb_clear_extension(krb5_context context,
		    hdb_entry *entry,
		    int type)
{
    size_t i;

    if (entry->extensions == NULL)
	return 0;

    for (i = 0; i < entry->extensions->len; ) {
	if (entry->extensions->val[i].data.element == (unsigned)type)
            (void) remove_HDB_extensions(entry->extensions, i);
        else
            i++;
    }
    if (entry->extensions->len == 0) {
	free(entry->extensions->val);
	free(entry->extensions);
	entry->extensions = NULL;
    }

    return 0;
}


krb5_error_code
hdb_entry_get_pkinit_acl(const hdb_entry *entry, const HDB_Ext_PKINIT_acl **a)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry, choice_HDB_extension_data_pkinit_acl);
    if (ext)
	*a = &ext->data.u.pkinit_acl;
    else
	*a = NULL;

    return 0;
}

krb5_error_code
hdb_entry_get_pkinit_hash(const hdb_entry *entry, const HDB_Ext_PKINIT_hash **a)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry, choice_HDB_extension_data_pkinit_cert_hash);
    if (ext)
	*a = &ext->data.u.pkinit_cert_hash;
    else
	*a = NULL;

    return 0;
}

krb5_error_code
hdb_entry_get_pkinit_cert(const hdb_entry *entry, const HDB_Ext_PKINIT_cert **a)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry, choice_HDB_extension_data_pkinit_cert);
    if (ext)
	*a = &ext->data.u.pkinit_cert;
    else
	*a = NULL;

    return 0;
}

krb5_error_code
hdb_entry_get_krb5_config(const hdb_entry *entry, heim_octet_string *c)
{
    const HDB_extension *ext;

    c->data = NULL;
    c->length = 0;
    ext = hdb_find_extension(entry, choice_HDB_extension_data_krb5_config);
    if (ext)
	*c = ext->data.u.krb5_config;
    return 0;
}

krb5_error_code
hdb_entry_set_krb5_config(krb5_context context,
                          hdb_entry *entry,
                          heim_octet_string *s)
{
    HDB_extension ext;

    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_last_pw_change;
    /* hdb_replace_extension() copies this, so no need to copy it here */
    ext.data.u.krb5_config = *s;
    return hdb_replace_extension(context, entry, &ext);
}

krb5_error_code
hdb_entry_get_pw_change_time(const hdb_entry *entry, time_t *t)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry, choice_HDB_extension_data_last_pw_change);
    if (ext)
	*t = ext->data.u.last_pw_change;
    else
	*t = 0;

    return 0;
}

krb5_error_code
hdb_entry_set_pw_change_time(krb5_context context,
			     hdb_entry *entry,
			     time_t t)
{
    HDB_extension ext;

    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_last_pw_change;
    if (t == 0)
	t = time(NULL);
    ext.data.u.last_pw_change = t;

    return hdb_replace_extension(context, entry, &ext);
}

int
hdb_entry_get_password(krb5_context context, HDB *db,
		       const hdb_entry *entry, char **p)
{
    HDB_extension *ext;
    char *str;
    int ret;

    ext = hdb_find_extension(entry, choice_HDB_extension_data_password);
    if (ext) {
	heim_utf8_string xstr;
	heim_octet_string pw;

	if (db->hdb_master_key_set && ext->data.u.password.mkvno) {
	    hdb_master_key key;

	    key = _hdb_find_master_key(ext->data.u.password.mkvno,
				       db->hdb_master_key);

	    if (key == NULL) {
		krb5_set_error_message(context, HDB_ERR_NO_MKEY,
				       "master key %d missing",
				       *ext->data.u.password.mkvno);
		return HDB_ERR_NO_MKEY;
	    }

	    ret = _hdb_mkey_decrypt(context, key, HDB_KU_MKEY,
				    ext->data.u.password.password.data,
				    ext->data.u.password.password.length,
				    &pw);
	} else {
	    ret = der_copy_octet_string(&ext->data.u.password.password, &pw);
	}
	if (ret) {
	    krb5_clear_error_message(context);
	    return ret;
	}

	xstr = pw.data;
	if (xstr[pw.length - 1] != '\0') {
	    krb5_set_error_message(context, EINVAL, "malformed password");
	    return EINVAL;
	}

	*p = strdup(xstr);

	der_free_octet_string(&pw);
	if (*p == NULL) {
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
	return 0;
    }

    ret = krb5_unparse_name(context, entry->principal, &str);
    if (ret == 0) {
	krb5_set_error_message(context, ENOENT,
			       "no password attribute for %s", str);
	free(str);
    } else
	krb5_clear_error_message(context);

    return ENOENT;
}

int
hdb_entry_set_password(krb5_context context, HDB *db,
		       hdb_entry *entry, const char *p)
{
    HDB_extension ext;
    hdb_master_key key;
    int ret;

    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_password;

    if (db->hdb_master_key_set) {

	key = _hdb_find_master_key(NULL, db->hdb_master_key);
	if (key == NULL) {
	    krb5_set_error_message(context, HDB_ERR_NO_MKEY,
				   "hdb_entry_set_password: "
				   "failed to find masterkey");
	    return HDB_ERR_NO_MKEY;
	}

	ret = _hdb_mkey_encrypt(context, key, HDB_KU_MKEY,
				p, strlen(p) + 1,
				&ext.data.u.password.password);
	if (ret)
	    return ret;

	ext.data.u.password.mkvno =
	    malloc(sizeof(*ext.data.u.password.mkvno));
	if (ext.data.u.password.mkvno == NULL) {
	    free_HDB_extension(&ext);
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
	*ext.data.u.password.mkvno = _hdb_mkey_version(key);

    } else {
	ext.data.u.password.mkvno = NULL;

	ret = krb5_data_copy(&ext.data.u.password.password,
			     p, strlen(p) + 1);
	if (ret) {
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    free_HDB_extension(&ext);
	    return ret;
	}
    }

    ret = hdb_replace_extension(context, entry, &ext);

    free_HDB_extension(&ext);

    return ret;
}

int
hdb_entry_clear_password(krb5_context context, hdb_entry *entry)
{
    return hdb_clear_extension(context, entry,
			       choice_HDB_extension_data_password);
}

krb5_error_code
hdb_entry_get_ConstrainedDelegACL(const hdb_entry *entry,
				  const HDB_Ext_Constrained_delegation_acl **a)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry,
			     choice_HDB_extension_data_allowed_to_delegate_to);
    if (ext)
	*a = &ext->data.u.allowed_to_delegate_to;
    else
	*a = NULL;

    return 0;
}

krb5_error_code
hdb_entry_get_aliases(const hdb_entry *entry, const HDB_Ext_Aliases **a)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry, choice_HDB_extension_data_aliases);
    if (ext)
	*a = &ext->data.u.aliases;
    else
	*a = NULL;

    return 0;
}

unsigned int
hdb_entry_get_kvno_diff_clnt(const hdb_entry *entry)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry,
			     choice_HDB_extension_data_hist_kvno_diff_clnt);
    if (ext)
	return ext->data.u.hist_kvno_diff_clnt;
    return 1;
}

krb5_error_code
hdb_entry_set_kvno_diff_clnt(krb5_context context, hdb_entry *entry,
			     unsigned int diff)
{
    HDB_extension ext;

    if (diff > 16384)
	return EINVAL;
    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_hist_kvno_diff_clnt;
    ext.data.u.hist_kvno_diff_clnt = diff;
    return hdb_replace_extension(context, entry, &ext);
}

krb5_error_code
hdb_entry_clear_kvno_diff_clnt(krb5_context context, hdb_entry *entry)
{
    return hdb_clear_extension(context, entry,
			       choice_HDB_extension_data_hist_kvno_diff_clnt);
}

unsigned int
hdb_entry_get_kvno_diff_svc(const hdb_entry *entry)
{
    const HDB_extension *ext;

    ext = hdb_find_extension(entry,
			     choice_HDB_extension_data_hist_kvno_diff_svc);
    if (ext)
	return ext->data.u.hist_kvno_diff_svc;
    return 1024; /* max_life effectively provides a better default */
}

krb5_error_code
hdb_entry_set_kvno_diff_svc(krb5_context context, hdb_entry *entry,
			    unsigned int diff)
{
    HDB_extension ext;

    if (diff > 16384)
	return EINVAL;
    ext.mandatory = FALSE;
    ext.data.element = choice_HDB_extension_data_hist_kvno_diff_svc;
    ext.data.u.hist_kvno_diff_svc = diff;
    return hdb_replace_extension(context, entry, &ext);
}

krb5_error_code
hdb_entry_clear_kvno_diff_svc(krb5_context context, hdb_entry *entry)
{
    return hdb_clear_extension(context, entry,
			       choice_HDB_extension_data_hist_kvno_diff_svc);
}

krb5_error_code
hdb_set_last_modified_by(krb5_context context, hdb_entry *entry,
                         krb5_principal modby, time_t modtime)
{
    krb5_error_code ret;
    Event *old_ev;
    Event *ev;

    old_ev = entry->modified_by;

    ev = calloc(1, sizeof (*ev));
    if (!ev)
        return ENOMEM;
    if (modby)
        ret = krb5_copy_principal(context, modby, &ev->principal);
    else
        ret = krb5_parse_name(context, "root/admin", &ev->principal);
    if (ret) {
        free(ev);
        return ret;
    }
    ev->time = modtime;
    if (!ev->time)
        time(&ev->time);

    entry->modified_by = ev;
    if (old_ev)
        free_Event(old_ev);
    return 0;
}

krb5_error_code
hdb_entry_get_key_rotation(krb5_context context,
	                   const hdb_entry *entry,
                           const HDB_Ext_KeyRotation **kr)
{
    HDB_extension *ext =
        hdb_find_extension(entry, choice_HDB_extension_data_key_rotation);

    *kr = ext ? &ext->data.u.key_rotation : NULL;
    return 0;
}

krb5_error_code
hdb_validate_key_rotation(krb5_context context,
                          const KeyRotation *past_kr,
                          const KeyRotation *new_kr)
{
    unsigned int last_kvno;

    if (new_kr->period < 1) {
        krb5_set_error_message(context, EINVAL,
                               "Key rotation periods must be non-zero "
                               "and positive");
        return EINVAL;
    }
    if (new_kr->base_key_kvno < 1 || new_kr->base_kvno < 1) {
        krb5_set_error_message(context, EINVAL,
                               "Key version number zero not allowed "
                               "for key rotation");
        return EINVAL;
    }
    if (!past_kr)
        return 0;

    if (past_kr->base_key_kvno == new_kr->base_key_kvno) {
        /*
         * The new base keys can be the same as the old, but must have
         * different kvnos.  (Well, not must must.  It's a convention for now.)
         */
        krb5_set_error_message(context, EINVAL,
                               "Base key version numbers for KRs must differ");
        return EINVAL;
    }
    if (new_kr->epoch - past_kr->epoch <= 0) {
        krb5_set_error_message(context, EINVAL,
                               "New key rotation periods must start later "
                               "than existing ones");
        return EINVAL;
    }

    last_kvno = 1 + ((new_kr->epoch - past_kr->epoch) / past_kr->period);
    if (new_kr->base_kvno <= last_kvno) {
        krb5_set_error_message(context, EINVAL,
                               "New key rotation base kvno must be larger "
                               "the last kvno for the current key "
                               "rotation (%u)", last_kvno);
        return EINVAL;
    }
    return 0;
}

static int
kr_eq(const KeyRotation *a, const KeyRotation *b)
{
    return !!(
        a->epoch == b->epoch &&
        a->period == b->period &&
        a->base_kvno == b->base_kvno &&
        a->base_key_kvno == b->base_key_kvno &&
        KeyRotationFlags2int(a->flags) == KeyRotationFlags2int(b->flags)
    );
}

krb5_error_code
hdb_validate_key_rotations(krb5_context context,
                           const HDB_Ext_KeyRotation *existing,
                           const HDB_Ext_KeyRotation *krs)
{
    krb5_error_code ret = 0;
    size_t added = 0;
    size_t i;

    if ((!existing || !existing->len) && (!krs || !krs->len))
        return 0; /* Nothing to do; weird */

    /*
     * HDB_Ext_KeyRotation has to have 1..3 elements, and this is enforced by
     * the ASN.1 compiler and the code it generates.  Nonetheless we'll check
     * that there's not zero elements.
     */
    if ((!krs || !krs->len)) {
        /*
         * NOTE: We can clear this on concrete principals with virtual keys
         *       though.  The caller can check for that case.
         */
        krb5_set_error_message(context, EINVAL,
                               "Cannot clear key rotation metadata on "
                               "virtual principal namespaces");
        ret = EINVAL;
    }

    /* Validate the new KRs by themselves */
    for (i = 0; ret == 0 && i < krs->len; i++) {
        ret = hdb_validate_key_rotation(context,
                                        i+1 < krs->len ? &krs->val[i+1] : 0,
                                        &krs->val[i]);
    }
    if (ret || !existing || !existing->len)
        return ret;

    if (existing->len == krs->len) {
        /* Check for no change */
        for (i = 0; i < krs->len; i++)
            if (!kr_eq(&existing->val[i], &krs->val[i]))
                break;
        if (i == krs->len)
            return 0; /* No change */
    }

    /*
     * Check that new KRs make sense in the context of the previous KRs.
     *
     * Permitted changes:
     *
     *  - add one new KR in front
     *  - drop old KRs
     *
     * Start by checking if we're adding a KR, then go on to check for dropped
     * KRs and/or last KR alteration.
     */
    if (existing->val[0].epoch == krs->val[0].epoch ||
        existing->val[0].base_kvno == krs->val[0].base_kvno) {
        if (!kr_eq(&existing->val[0], &krs->val[0])) {
            krb5_set_error_message(context, EINVAL,
                                   "Key rotation change not sensible");
            ret = EINVAL;
        }
        /* Key rotation *not* added */
    } else {
        /* Key rotation added; check it first */
        ret = hdb_validate_key_rotation(context,
                                        &existing->val[0],
                                        &krs->val[0]);
        added = 1;
    }
    for (i = 0; ret == 0 && i < existing->len && i + added < krs->len; i++)
        if (!kr_eq(&existing->val[i], &krs->val[i + added]))
            krb5_set_error_message(context, ret = EINVAL,
                                   "Only last key rotation may be truncated");
    return ret;
}

/* XXX We need a function to "revoke" the past */

/**
 * This function adds a KeyRotation value to an entry, validating the
 * change.  One of `entry' and `krs' must be NULL, and the other non-NULL, and
 * whichever is given will be altered.
 *
 * @param context Context
 * @param entry An HDB entry
 * @param krs A key rotation extension for hdb_entry
 * @param kr A new KeyRotation value
 *
 * @return Zero on success, an error otherwise.
 */
krb5_error_code
hdb_entry_add_key_rotation(krb5_context context,
                           hdb_entry *entry,
                           HDB_Ext_KeyRotation *krs,
                           const KeyRotation *kr)
{
    krb5_error_code ret;
    HDB_extension new_ext;
    HDB_extension *ext = &new_ext;
    KeyRotation tmp;
    size_t i, sz;

    if (kr->period < 1) {
        krb5_set_error_message(context, EINVAL,
                               "Key rotation period cannot be zero");
        return EINVAL;
    }

    new_ext.mandatory = TRUE;
    new_ext.data.element = choice_HDB_extension_data_key_rotation;
    new_ext.data.u.key_rotation.len = 0;
    new_ext.data.u.key_rotation.val = 0;

    if (entry && krs)
        return EINVAL;

    if (entry) {
        ext = hdb_find_extension(entry, choice_HDB_extension_data_key_rotation);
        if (!ext)
            ext = &new_ext;
    } else {
        const KeyRotation *prev_kr = &krs->val[0];
        unsigned int last_kvno = 0;

        if (kr->epoch - prev_kr->epoch <= 0) {
            krb5_set_error_message(context, EINVAL,
                                   "New key rotation periods must start later "
                                   "than existing ones");
            return EINVAL;
        }

        if (kr->base_kvno <= prev_kr->base_kvno ||
            kr->base_kvno - prev_kr->base_kvno <=
                (last_kvno = 1 +
                 ((kr->epoch - prev_kr->epoch) / prev_kr->period))) {
            krb5_set_error_message(context, EINVAL,
                                   "New key rotation base kvno must be larger "
                                   "the last kvno for the current key "
                                   "rotation (%u)", last_kvno);
            return EINVAL;
        }
    }

    /* First, append */
    ret = add_HDB_Ext_KeyRotation(&ext->data.u.key_rotation, kr);
    if (ret)
        return ret;

    /* Rotate new to front */
    tmp = ext->data.u.key_rotation.val[ext->data.u.key_rotation.len - 1];
    sz = sizeof(ext->data.u.key_rotation.val[0]);
    memmove(&ext->data.u.key_rotation.val[1], &ext->data.u.key_rotation.val[0],
            (ext->data.u.key_rotation.len - 1) * sz);
    ext->data.u.key_rotation.val[0] = tmp;

    /* Drop too old entries */
    for (i = 3; i < ext->data.u.key_rotation.len; i++)
        free_KeyRotation(&ext->data.u.key_rotation.val[i]);
    ext->data.u.key_rotation.len =
        ext->data.u.key_rotation.len > 3 ? 3 : ext->data.u.key_rotation.len;

    if (ext != &new_ext)
        return 0;

    /* Install new extension */
    if (ret == 0 && entry)
        ret = hdb_replace_extension(context, entry, ext);
    free_HDB_extension(&new_ext);
    return ret;
}
