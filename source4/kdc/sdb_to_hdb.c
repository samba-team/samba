/*
   Unix SMB/CIFS implementation.

   Database Glue between Samba and the KDC

   Copyright (C) Guenther Deschner <gd@samba.org> 2014
   Copyright (C) Andreas Schneider <asn@samba.org> 2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.


   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "hdb_asn1.h"
#include <hdb.h>
#include <krb5.h>
#include <hx_locl.h>
#include "rfc2459_asn1.h"
#include "sdb.h"
#include "sdb_hdb.h"
#include "lib/krb5_wrap/krb5_samba.h"
#include "librpc/gen_ndr/security.h"
#include "kdc/samba_kdc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

static void sdb_flags_to_hdb_flags(const struct SDBFlags *s,
				   HDBFlags *h)
{
	SMB_ASSERT(sizeof(struct SDBFlags) == sizeof(HDBFlags));

	h->initial = s->initial;
	h->forwardable = s->forwardable;
	h->proxiable = s->proxiable;
	h->renewable = s->renewable;
	h->postdate = s->postdate;
	h->server = s->server;
	h->client = s->client;
	h->invalid = s->invalid;
	h->require_preauth = s->require_preauth;
	h->change_pw = s->change_pw;
	h->require_hwauth = s->require_hwauth;
	h->ok_as_delegate = s->ok_as_delegate;
	h->user_to_user = s->user_to_user;
	h->immutable = s->immutable;
	h->trusted_for_delegation = s->trusted_for_delegation;
	h->allow_kerberos4 = s->allow_kerberos4;
	h->allow_digest = s->allow_digest;
	h->locked_out = s->locked_out;
	h->require_pwchange = s->require_pwchange;
	h->materialize = s->materialize;
	h->virtual_keys = s->virtual_keys;
	h->virtual = s->virtual;
	h->synthetic = s->synthetic;
	h->no_auth_data_reqd = s->no_auth_data_reqd;
	h->auth_data_reqd = s->auth_data_reqd;
	h->_unused25 = s->_unused25;
	h->_unused26 = s->_unused26;
	h->_unused27 = s->_unused27;
	h->_unused28 = s->_unused28;
	h->_unused29 = s->_unused29;
	h->force_canonicalize = s->force_canonicalize;
	h->do_not_store = s->do_not_store;
}

static int sdb_salt_to_Salt(const struct sdb_salt *s, Salt *h)
{
	int ret;

	*h = (struct Salt) {};

	h->type = s->type;
	ret = smb_krb5_copy_data_contents(&h->salt, s->salt.data, s->salt.length);
	if (ret != 0) {
		free_Salt(h);
		return ENOMEM;
	}

	return 0;
}

static int sdb_key_to_Key(const struct sdb_key *s, Key *h)
{
	int rc;

	*h = (struct Key) {};

	h->key.keytype = s->key.keytype;
	rc = smb_krb5_copy_data_contents(&h->key.keyvalue,
					 s->key.keyvalue.data,
					 s->key.keyvalue.length);
	if (rc != 0) {
		goto error_nomem;
	}

	if (s->salt != NULL) {
		h->salt = malloc(sizeof(Salt));
		if (h->salt == NULL) {
			goto error_nomem;
		}

		rc = sdb_salt_to_Salt(s->salt,
				      h->salt);
		if (rc != 0) {
			goto error_nomem;
		}
	}

	return 0;

error_nomem:
	free_Key(h);
	return ENOMEM;
}

static int sdb_keys_to_Keys(const struct sdb_keys *s, Keys *h)
{
	int ret, i;

	*h = (struct Keys) {};

	if (s->val != NULL) {
		h->val = malloc(s->len * sizeof(Key));
		if (h->val == NULL) {
			return ENOMEM;
		}
		for (i = 0; i < s->len; i++) {
			ret = sdb_key_to_Key(&s->val[i],
					     &h->val[i]);
			if (ret != 0) {
				free_Keys(h);
				return ENOMEM;
			}

			++h->len;
		}
	}

	return 0;
}

static int sdb_keys_to_HistKeys(krb5_context context,
				const struct sdb_keys *s,
				krb5_kvno kvno,
				hdb_entry *h)
{
	unsigned int i;

	for (i = 0; i < s->len; i++) {
		Key k = { 0, };
		int ret;

		ret = sdb_key_to_Key(&s->val[i], &k);
		if (ret != 0) {
			return ENOMEM;
		}
		ret = hdb_add_history_key(context, h, kvno, &k);
		free_Key(&k);
		if (ret != 0) {
			return ENOMEM;
		}
	}

	return 0;
}

static int sdb_event_to_Event(krb5_context context,
			      const struct sdb_event *s, Event *h)
{
	int ret;

	*h = (struct Event) {};

	if (s->principal != NULL) {
		ret = krb5_copy_principal(context,
					  s->principal,
					  &h->principal);
		if (ret != 0) {
			free_Event(h);
			return ret;
		}
	}
	h->time = s->time;

	return 0;
}


/**
* @brief Convert a sdb_pub_key to a HDB_Ext_KeyTrust_val
*
* @param s[in]     A public key in sdb
* @param h[in,out] The HDb_Ext_KeyTrust_val to populate
*
* @return 0 no error
*         >0 an error occurred
*/
static int sdb_pub_key_to_hdb_key_trust_val(const struct sdb_pub_key *s,
					    struct HDB_Ext_KeyTrust_val *h)
{
	krb5_error_code ret;
	SubjectPublicKeyInfo spki = {};
	RSAPublicKey rsa = {};
	krb5_data buf = {};
	AlgorithmIdentifier alg = {};
	HEIM_ANY parameters = {};
	uint8_t none[] = {0x05, 0x00};
	size_t size = 0;

	rsa.publicExponent.length = s->exponent.length;
	rsa.publicExponent.data = s->exponent.data;
	rsa.publicExponent.negative = 0;

	rsa.modulus.length = s->modulus.length;
	rsa.modulus.data = s->modulus.data;
	rsa.modulus.negative = 0;

	ASN1_MALLOC_ENCODE(
		RSAPublicKey, buf.data , buf.length, &rsa, &size, ret);
	if (ret != 0) {
		goto out;
	}

	spki.subjectPublicKey.data = buf.data;
	/*
	 * The public key length is in bits, but the buffer len is in bytes
	 * so need to convert it to bits.
	 */
	spki.subjectPublicKey.length = buf.length * 8;

	ret = der_copy_oid(ASN1_OID_ID_PKCS1_RSAENCRYPTION, &alg.algorithm);
	if (ret != 0) {
		goto out1;
	}
	parameters.data = &none;
	parameters.length = sizeof(none);
	alg.parameters = &parameters;
	spki.algorithm = alg;

	/*
	 * This will be freed when sdb_pub_keys_to_hdb calls
	 * free_HDB_Ext_KeyTrust
	 */
	ASN1_MALLOC_ENCODE(SubjectPublicKeyInfo,
		    h->pub_key.data,
		    h->pub_key.length,
		    &spki,
		    &size,
		    ret);
	if (ret != 0) {
		goto out2;
	}

out2:
	der_free_oid(&alg.algorithm);
out1:
        der_free_octet_string(&buf);
out:
	return ret;
}

/**
* @brief Convert any public keys for key trust authentication.
*
* @param s[in]  The public keys that can be used for authentication
* @param h[out] The converted public keys
* @return  0 if there are no errors
*         >0 an error occurred
*/
static int sdb_pub_keys_to_hdb_ext(const struct sdb_pub_keys *s,
				   HDB_Ext_KeyTrust *h)
{
	int ret, i;
	*h = (struct HDB_Ext_KeyTrust) {};

	if (s->keys != NULL) {
		h->val = malloc(s->len * sizeof(heim_octet_string));
		if (h->val == NULL) {
			return ENOMEM;
		}
		for (i = 0; i < s->len; i++) {
			ret = sdb_pub_key_to_hdb_key_trust_val(
				&s->keys[i], &h->val[i]);
			if (ret != 0) {
				free_HDB_Ext_KeyTrust(h);
				return ret;
			}
			h->len++;
		}
	}
	return 0;
}

int sdb_entry_to_hdb_entry(krb5_context context,
			   const struct sdb_entry *s,
			   hdb_entry *h)
{
	struct samba_kdc_entry *ske = s->skdc_entry;
	struct HDB_Ext_KeyTrust kt = {};
	unsigned int i;
	int rc;

	*h = (hdb_entry) {};

	if (s->principal != NULL) {
		rc = krb5_copy_principal(context,
					 s->principal,
					 &h->principal);
		if (rc != 0) {
			return rc;
		}
	}

	h->kvno = s->kvno;

	rc = sdb_keys_to_Keys(&s->keys, &h->keys);
	if (rc != 0) {
		goto error;
	}

	if (h->kvno > 1) {
		rc = sdb_keys_to_HistKeys(context,
					  &s->old_keys,
					  h->kvno - 1,
					  h);
		if (rc != 0) {
			goto error;
		}
	}

	if (h->kvno > 2) {
		rc = sdb_keys_to_HistKeys(context,
					  &s->older_keys,
					  h->kvno - 2,
					  h);
		if (rc != 0) {
			goto error;
		}
	}

	rc = sdb_event_to_Event(context,
				 &s->created_by,
				 &h->created_by);
	if (rc != 0) {
		goto error;
	}

	if (s->modified_by) {
		h->modified_by = malloc(sizeof(Event));
		if (h->modified_by == NULL) {
			rc = ENOMEM;
			goto error;
		}

		rc = sdb_event_to_Event(context,
					 s->modified_by,
					 h->modified_by);
		if (rc != 0) {
			goto error;
		}
	}

	if (s->valid_start != NULL) {
		h->valid_start = malloc(sizeof(KerberosTime));
		if (h->valid_start == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->valid_start = *s->valid_start;
	}

	if (s->valid_end != NULL) {
		h->valid_end = malloc(sizeof(KerberosTime));
		if (h->valid_end == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->valid_end = *s->valid_end;
	}

	if (s->pw_end != NULL) {
		h->pw_end = malloc(sizeof(KerberosTime));
		if (h->pw_end == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->pw_end = *s->pw_end;
	}

	if (s->max_life != NULL) {
		h->max_life = malloc(sizeof(*h->max_life));
		if (h->max_life == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->max_life = *s->max_life;
	}

	if (s->max_renew != NULL) {
		h->max_renew = malloc(sizeof(*h->max_renew));
		if (h->max_renew == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->max_renew = *s->max_renew;
	}

	sdb_flags_to_hdb_flags(&s->flags, &h->flags);

	if (s->etypes != NULL) {
		h->etypes = malloc(sizeof(*h->etypes));
		if (h->etypes == NULL) {
			rc = ENOMEM;
			goto error;
		}

		h->etypes->len = s->etypes->len;

		h->etypes->val = calloc(h->etypes->len, sizeof(int));
		if (h->etypes->val == NULL) {
			rc = ENOMEM;
			goto error;
		}

		for (i = 0; i < h->etypes->len; i++) {
			h->etypes->val[i] = s->etypes->val[i];
		}
	}

	if (s->session_etypes != NULL) {
		h->session_etypes = malloc(sizeof(*h->session_etypes));
		if (h->session_etypes == NULL) {
			rc = ENOMEM;
			goto error;
		}

		h->session_etypes->len = s->session_etypes->len;

		h->session_etypes->val = calloc(h->session_etypes->len, sizeof(*h->session_etypes->val));
		if (h->session_etypes->val == NULL) {
			rc = ENOMEM;
			goto error;
		}

		for (i = 0; i < h->session_etypes->len; ++i) {
			h->session_etypes->val[i] = s->session_etypes->val[i];
		}
	}

	rc = sdb_pub_keys_to_hdb_ext(&s->pub_keys, &kt);
	if (rc != 0) {
		goto error;
	}
	if (kt.len > 0) {
		HDB_extension ext = {};
		ext.mandatory = FALSE;
		ext.data.element = choice_HDB_extension_data_key_trust;
		ext.data.u.key_trust = kt;
		rc = hdb_replace_extension(context, h, &ext);
		free_HDB_Ext_KeyTrust(&kt);
		if (rc != 0) {
			goto error;
		}
	}

	h->context = ske;
	if (ske != NULL) {
		ske->kdc_entry = h;
	}
	return 0;
error:
	free_hdb_entry(h);
	return rc;
}
