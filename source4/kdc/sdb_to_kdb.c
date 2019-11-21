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
#include <kdb.h>
#include "sdb.h"
#include "sdb_kdb.h"
#include "kdc/samba_kdc.h"
#include "lib/krb5_wrap/krb5_samba.h"

static int SDBFlags_to_kflags(const struct SDBFlags *s,
			      krb5_flags *k)
{
	*k = 0;

	if (s->initial) {
		*k |= KRB5_KDB_DISALLOW_TGT_BASED;
	}
	/* The forwardable and proxiable flags are set according to client and
	 * server attributes. */
	if (!s->forwardable) {
		*k |= KRB5_KDB_DISALLOW_FORWARDABLE;
	}
	if (!s->proxiable) {
		*k |= KRB5_KDB_DISALLOW_PROXIABLE;
	}
	if (s->renewable) {
		;
	}
	if (s->postdate) {
		;
	}
	if (s->server) {
		;
	}
	if (s->client) {
		;
	}
	if (s->invalid) {
		*k |= KRB5_KDB_DISALLOW_ALL_TIX;
	}
	if (s->require_preauth) {
		*k |= KRB5_KDB_REQUIRES_PRE_AUTH;
	}
	if (s->change_pw) {
		*k |= KRB5_KDB_PWCHANGE_SERVICE;
	}
	if (s->require_hwauth) {
		*k |= KRB5_KDB_REQUIRES_HW_AUTH;
	}
	if (s->ok_as_delegate) {
		*k |= KRB5_KDB_OK_AS_DELEGATE;
	}
	if (s->user_to_user) {
		;
	}
	if (s->immutable) {
		;
	}
	if (s->trusted_for_delegation) {
		*k |= KRB5_KDB_OK_TO_AUTH_AS_DELEGATE;
	}
	if (s->allow_kerberos4) {
		;
	}
	if (s->allow_digest) {
		;
	}

	return 0;
}

static int sdb_event_to_kmod(krb5_context context,
			     const struct sdb_event *s,
			     krb5_db_entry *k)
{
	krb5_error_code ret;
	krb5_principal principal = NULL;

	if (s->principal != NULL) {
		ret = krb5_copy_principal(context,
					  s->principal,
					  &principal);
		if (ret != 0) {
			return ret;
		}
	}

	ret = krb5_dbe_update_mod_princ_data(context,
					     k, s->time,
					     principal);

	krb5_free_principal(context, principal);

	return ret;
}

/* sets up salt on the 2nd array position */

static int sdb_salt_to_krb5_key_data(const struct sdb_salt *s,
				     krb5_key_data *k)
{
	switch (s->type) {
#if 0
	/* for now use the special mechanism where the MIT KDC creates the salt
	 * on its own */
	case 3: /* FIXME KRB5_PW_SALT */
		k->key_data_type[1] = KRB5_KDB_SALTTYPE_NORMAL;
		break;
	/*
	case hdb_afs3_salt:
		k->key_data_type[1] = KRB5_KDB_SALTTYPE_AFS3;
		break;
	*/
#endif
	default:
		k->key_data_type[1] = KRB5_KDB_SALTTYPE_SPECIAL;
		break;
	}

	k->key_data_contents[1] = malloc(s->salt.length);
	if (k->key_data_contents[1] == NULL) {
		return ENOMEM;
	}
	memcpy(k->key_data_contents[1],
	       s->salt.data,
	       s->salt.length);
	k->key_data_length[1] = s->salt.length;

	return 0;
}

static int sdb_key_to_krb5_key_data(const struct sdb_key *s,
				    int kvno,
				    krb5_key_data *k)
{
	int ret = 0;

	ZERO_STRUCTP(k);

	k->key_data_ver = KRB5_KDB_V1_KEY_DATA_ARRAY;
	k->key_data_kvno = kvno;

	k->key_data_type[0] = KRB5_KEY_TYPE(&s->key);
	k->key_data_length[0] = KRB5_KEY_LENGTH(&s->key);
	k->key_data_contents[0] = malloc(k->key_data_length[0]);
	if (k->key_data_contents[0] == NULL) {
		return ENOMEM;
	}

	memcpy(k->key_data_contents[0],
	       KRB5_KEY_DATA(&s->key),
	       k->key_data_length[0]);

	if (s->salt != NULL) {
		ret = sdb_salt_to_krb5_key_data(s->salt, k);
		if (ret) {
			memset(k->key_data_contents[0], 0, k->key_data_length[0]);
			free(k->key_data_contents[0]);
		}
	}

	return ret;
}

static void free_krb5_db_entry(krb5_context context,
			       krb5_db_entry *k)
{
	krb5_tl_data *tl_data_next = NULL;
	krb5_tl_data *tl_data = NULL;
	int i, j;

	if (k == NULL) {
		return;
	}

	krb5_free_principal(context, k->princ);

	for (tl_data = k->tl_data; tl_data; tl_data = tl_data_next) {
		tl_data_next = tl_data->tl_data_next;
		if (tl_data->tl_data_contents != NULL) {
			free(tl_data->tl_data_contents);
		}
		free(tl_data);
	}

	if (k->key_data != NULL) {
		for (i = 0; i < k->n_key_data; i++) {
			for (j = 0; j < k->key_data[i].key_data_ver; j++) {
				if (k->key_data[i].key_data_length[j] != 0) {
					if (k->key_data[i].key_data_contents[j] != NULL) {
						memset(k->key_data[i].key_data_contents[j], 0, k->key_data[i].key_data_length[j]);
						free(k->key_data[i].key_data_contents[j]);
					}
				}
				k->key_data[i].key_data_contents[j] = NULL;
				k->key_data[i].key_data_length[j] = 0;
				k->key_data[i].key_data_type[j] = 0;
			}
		}
		free(k->key_data);
	}

	ZERO_STRUCTP(k);
}

static int sdb_entry_ex_to_krb5_db_entry(krb5_context context,
					 const struct sdb_entry *s,
					 krb5_db_entry *k)
{
	krb5_error_code ret;
	int i;

	k->magic = KRB5_KDB_MAGIC_NUMBER;
	k->len = KRB5_KDB_V1_BASE_LENGTH;

	ret = krb5_copy_principal(context,
				  s->principal,
				  &k->princ);
	if (ret) {
		free_krb5_db_entry(context, k);
		return ret;
	}

	ret = SDBFlags_to_kflags(&s->flags,
				 &k->attributes);
	if (ret) {
		free_krb5_db_entry(context, k);
		return ret;
	}

	if (s->max_life != NULL) {
		k->max_life = *s->max_life;
	}
	if (s->max_renew != NULL) {
		k->max_renewable_life = *s->max_renew;
	}
	if (s->valid_end != NULL) {
		k->expiration = *s->valid_end;
	}
	if (s->pw_end != NULL) {
		k->pw_expiration = *s->pw_end;
	}

	/* last_success */
	/* last_failed */
	/* fail_auth_count */
	/* n_tl_data */

	/*
	 * If we leave early when looking up the realm, we do not have all
	 * information about a principal. We need to construct a db entry
	 * with minimal information, so skip this part.
	 */
	if (s->created_by.time != 0) {
		ret = sdb_event_to_kmod(context,
					s->modified_by ? s->modified_by : &s->created_by,
					k);
		if (ret) {
			free_krb5_db_entry(context, k);
			return ret;
		}
	}

	/* FIXME: TODO HDB Extensions */

	if (s->keys.len > 0) {
		k->key_data = malloc(s->keys.len * sizeof(krb5_key_data));
		if (k->key_data == NULL) {
			free_krb5_db_entry(context, k);
			return ret;
		}

		for (i=0; i < s->keys.len; i++) {
			ret = sdb_key_to_krb5_key_data(&s->keys.val[i],
						       s->kvno,
						       &k->key_data[i]);
			if (ret) {
				free_krb5_db_entry(context, k);
				return ret;
			}

			k->n_key_data++;
		}
	}

	return 0;
}

static int samba_kdc_kdb_entry_destructor(struct samba_kdc_entry *p)
{
	krb5_db_entry *entry_ex = p->entry_ex;
	krb5_error_code ret;
	krb5_context context;

	if (entry_ex->e_data != NULL) {
		struct samba_kdc_entry *skdc_entry;

		skdc_entry = talloc_get_type(entry_ex->e_data,
					     struct samba_kdc_entry);
		talloc_set_destructor(skdc_entry, NULL);
		entry_ex->e_data = NULL;
	}

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		return ret;
	}

	krb5_db_free_principal(context, entry_ex);
	krb5_free_context(context);

	return 0;
}

int sdb_entry_ex_to_kdb_entry_ex(krb5_context context,
				 const struct sdb_entry_ex *s,
				 krb5_db_entry *k)
{
	ZERO_STRUCTP(k);

	if (s->ctx != NULL) {
		struct samba_kdc_entry *skdc_entry;

		skdc_entry = talloc_get_type(s->ctx, struct samba_kdc_entry);

		k->e_data	= (void *)skdc_entry;

		talloc_set_destructor(skdc_entry,
				      samba_kdc_kdb_entry_destructor);
	}

	return sdb_entry_ex_to_krb5_db_entry(context, &s->entry, k);
}
