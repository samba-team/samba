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
#include "system/kerberos.h"
#include "sdb.h"
#include "samba_kdc.h"
#include "lib/krb5_wrap/krb5_samba.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

void sdb_key_free(struct sdb_key *k)
{
	if (k == NULL) {
		return;
	}

	/*
	 * Passing NULL as the Kerberos context is intentional here, as
	 * both Heimdal and MIT libraries don't use the context when
	 * clearing the keyblocks.
	 */
	krb5_free_keyblock_contents(NULL, &k->key);

	if (k->salt) {
		smb_krb5_free_data_contents(NULL, &k->salt->salt);
		SAFE_FREE(k->salt);
	}

	ZERO_STRUCTP(k);
}

void sdb_keys_free(struct sdb_keys *keys)
{
	unsigned int i;

	if (keys == NULL) {
		return;
	}

	for (i = 0; i < keys->len; i++) {
		sdb_key_free(&keys->val[i]);
	}

	SAFE_FREE(keys->val);
	ZERO_STRUCTP(keys);
}

/**
 * @brief free the memory allocated to a sdb_key structure.
 *
 * @param[in,out] keys sdb_key to be freed, will be zeroed on return
 */
void sdb_pub_key_free(struct sdb_pub_key *k)
{
	if (k == NULL) {
		return;
	}

	SAFE_FREE(k->exponent.data);
	SAFE_FREE(k->modulus.data);

	ZERO_STRUCTP(k);
}

/**
 * @brief free the memory allocated to a sdb_pub_keys structure.
 *
 * @param[in,out] keys sdb_pub_keys to be freed, will be zeroed on return
 */
void sdb_pub_keys_free(struct sdb_pub_keys *keys)
{
	unsigned int i;

	if (keys == NULL) {
		return;
	}

	for (i = 0; i < keys->len; i++) {
		sdb_pub_key_free(&keys->keys[i]);
	}

	SAFE_FREE(keys->keys);
	ZERO_STRUCTP(keys);
}

/**
 * @brief free the memory allocated to a sdb certificate mapping structure.
 *
 * @param[in,out] m mapping to be freed, will be zeroed on return
 */
void sdb_certificate_mapping_free(struct sdb_certificate_mapping *m)
{
	if (m == NULL) {
		return;
	}

	SAFE_FREE(m->subject_name.data);
	SAFE_FREE(m->issuer_name.data);
	SAFE_FREE(m->serial_number.data);
	SAFE_FREE(m->ski.data);
	SAFE_FREE(m->public_key.data);
	SAFE_FREE(m->rfc822.data);

	ZERO_STRUCTP(m);
}
/**
 *
 * @brief free the memory allocated to a sdb certificate mappings structure.
 *
 * @param[in,out] m mappings to be freed, will be zeroed on return
 */
void sdb_certificate_mappings_free(struct sdb_certificate_mappings *m)
{
	unsigned int i;

	if (m == NULL) {
		return;
	}

	for (i = 0; i < m->len; i++) {
		sdb_certificate_mapping_free(&m->mappings[i]);
	}

	SAFE_FREE(m->mappings);
	ZERO_STRUCTP(m);
}

void sdb_entry_free(struct sdb_entry *s)
{
	if (s->skdc_entry != NULL) {
		s->skdc_entry->db_entry = NULL;
		TALLOC_FREE(s->skdc_entry);
	}

	/*
	 * Passing NULL as the Kerberos context is intentional here, as both
	 * Heimdal and MIT libraries don't use the context when clearing the
	 * principals.
	 */
	krb5_free_principal(NULL, s->principal);

	sdb_keys_free(&s->keys);
	sdb_pub_keys_free(&s->pub_keys);
	sdb_certificate_mappings_free(&s->mappings);

	if (s->etypes != NULL) {
		SAFE_FREE(s->etypes->val);
	}
	SAFE_FREE(s->etypes);
	sdb_keys_free(&s->old_keys);
	sdb_keys_free(&s->older_keys);
	if (s->session_etypes != NULL) {
		SAFE_FREE(s->session_etypes->val);
	}
	SAFE_FREE(s->session_etypes);
	krb5_free_principal(NULL, s->created_by.principal);
	if (s->modified_by) {
		krb5_free_principal(NULL, s->modified_by->principal);
	}
	SAFE_FREE(s->valid_start);
	SAFE_FREE(s->valid_end);
	SAFE_FREE(s->pw_end);
	SAFE_FREE(s->max_life);
	SAFE_FREE(s->max_renew);

	ZERO_STRUCTP(s);
}

/* Set the etypes of an sdb_entry based on its available current keys. */
krb5_error_code sdb_entry_set_etypes(struct sdb_entry *s)
{
	if (s->keys.val != NULL) {
		unsigned i;

		s->etypes = malloc(sizeof(*s->etypes));
		if (s->etypes == NULL) {
			return ENOMEM;
		}

		s->etypes->len = s->keys.len;

		s->etypes->val = calloc(s->etypes->len, sizeof(*s->etypes->val));
		if (s->etypes->val == NULL) {
			SAFE_FREE(s->etypes);
			return ENOMEM;
		}

		for (i = 0; i < s->etypes->len; i++) {
			const struct sdb_key *k = &s->keys.val[i];

			s->etypes->val[i] = KRB5_KEY_TYPE(&(k->key));
		}
	}

	return 0;
}

/*
 * Set the session etypes of a server sdb_entry based on its etypes, forcing in
 * strong etypes as desired.
 */
krb5_error_code sdb_entry_set_session_etypes(struct sdb_entry *s,
					     bool add_aes256,
					     bool add_aes128,
					     bool add_rc4)
{
	unsigned len = 0;

	if (add_aes256) {
		/* Reserve space for AES256 */
		len += 1;
	}

	if (add_aes128) {
		/* Reserve space for AES128 */
		len += 1;
	}

	if (add_rc4) {
		/* Reserve space for RC4. */
		len += 1;
	}

	if (len != 0) {
		unsigned j = 0;

		s->session_etypes = malloc(sizeof(*s->session_etypes));
		if (s->session_etypes == NULL) {
			return ENOMEM;
		}

		/* session_etypes must be sorted in order of strength, with preferred etype first. */

		s->session_etypes->val = calloc(len, sizeof(*s->session_etypes->val));
		if (s->session_etypes->val == NULL) {
			SAFE_FREE(s->session_etypes);
			return ENOMEM;
		}

		if (add_aes256) {
			/* Add AES256 */
			s->session_etypes->val[j++] = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		}

		if (add_aes128) {
			/* Add AES128. */
			s->session_etypes->val[j++] = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		}

		if (add_rc4) {
			/* Add RC4. */
			s->session_etypes->val[j++] = ENCTYPE_ARCFOUR_HMAC;
		}

		s->session_etypes->len = j;
	}

	return 0;
}
