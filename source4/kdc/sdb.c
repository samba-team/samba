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

	for (i=0; i < keys->len; i++) {
		sdb_key_free(&keys->val[i]);
	}

	SAFE_FREE(keys->val);
	ZERO_STRUCTP(keys);
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
	sdb_keys_free(&s->old_keys);
	sdb_keys_free(&s->older_keys);
	krb5_free_principal(NULL, s->created_by.principal);
	if (s->modified_by) {
		krb5_free_principal(NULL, s->modified_by->principal);
	}
	SAFE_FREE(s->valid_start);
	SAFE_FREE(s->valid_end);
	SAFE_FREE(s->pw_end);

	ZERO_STRUCTP(s);
}

struct SDBFlags int2SDBFlags(unsigned n)
{
	struct SDBFlags flags;

	memset(&flags, 0, sizeof(flags));

	flags.initial = (n >> 0) & 1;
	flags.forwardable = (n >> 1) & 1;
	flags.proxiable = (n >> 2) & 1;
	flags.renewable = (n >> 3) & 1;
	flags.postdate = (n >> 4) & 1;
	flags.server = (n >> 5) & 1;
	flags.client = (n >> 6) & 1;
	flags.invalid = (n >> 7) & 1;
	flags.require_preauth = (n >> 8) & 1;
	flags.change_pw = (n >> 9) & 1;
	flags.require_hwauth = (n >> 10) & 1;
	flags.ok_as_delegate = (n >> 11) & 1;
	flags.user_to_user = (n >> 12) & 1;
	flags.immutable = (n >> 13) & 1;
	flags.trusted_for_delegation = (n >> 14) & 1;
	flags.allow_kerberos4 = (n >> 15) & 1;
	flags.allow_digest = (n >> 16) & 1;
	flags.locked_out = (n >> 17) & 1;
	flags.do_not_store = (n >> 31) & 1;
	return flags;
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
					     bool add_strong_aes_etypes,
					     bool force_rc4)
{
	if (s->etypes != NULL) {
		unsigned i;
		unsigned j = 0;
		unsigned len = s->etypes->len;

		s->session_etypes = malloc(sizeof(*s->session_etypes));
		if (s->session_etypes == NULL) {
			return ENOMEM;
		}

		if (add_strong_aes_etypes) {
			/* Reserve space for AES256 and AES128. */
			len += 2;
		}

		if (force_rc4) {
			/* Reserve space for RC4. */
			len += 1;
		}

		/* session_etypes must be sorted in order of strength, with preferred etype first. */

		s->session_etypes->val = calloc(len, sizeof(*s->session_etypes->val));
		if (s->session_etypes->val == NULL) {
			return ENOMEM;
		}

		if (add_strong_aes_etypes) {
			/* Add AES256 and AES128. */
			s->session_etypes->val[j++] = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
			s->session_etypes->val[j++] = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		}

		if (force_rc4) {
			/* Add RC4. */
			s->session_etypes->val[j++] = ENCTYPE_ARCFOUR_HMAC;
		}

		for (i = 0; i < s->etypes->len; ++i) {
			const krb5_enctype etype = s->etypes->val[i];

			if (add_strong_aes_etypes &&
			    (etype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 ||
			     etype == ENCTYPE_AES128_CTS_HMAC_SHA1_96))
			{
				/*
				 * Skip AES256 and AES128, for we've
				 * already added them.
				 */
				continue;
			}

			if (force_rc4 && etype == ENCTYPE_ARCFOUR_HMAC) {
				/* Skip RC4, for we've already added it. */
				continue;
			}

			s->session_etypes->val[j++] = etype;
		}

		s->session_etypes->len = j;
	}

	return 0;
}
