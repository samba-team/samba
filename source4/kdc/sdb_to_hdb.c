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
#include <hdb.h>
#include "sdb.h"
#include "sdb_hdb.h"
#include "lib/krb5_wrap/krb5_samba.h"
#include "kdc/samba_kdc.h"

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
	h->_unused18 = s->_unused18;
	h->_unused19 = s->_unused19;
	h->_unused20 = s->_unused20;
	h->_unused21 = s->_unused21;
	h->_unused22 = s->_unused22;
	h->_unused23 = s->_unused23;
	h->_unused24 = s->_unused24;
	h->_unused25 = s->_unused25;
	h->_unused26 = s->_unused26;
	h->_unused27 = s->_unused27;
	h->_unused28 = s->_unused28;
	h->_unused29 = s->_unused29;
	h->_unused30 = s->_unused30;
	h->do_not_store = s->do_not_store;
}

static int sdb_salt_to_Salt(const struct sdb_salt *s, Salt *h)
{
	int ret;

	h->type = s->type;
	ret = smb_krb5_copy_data_contents(&h->salt, s->salt.data, s->salt.length);
	if (ret != 0) {
		free_Salt(h);
		return ENOMEM;
	}
	h->opaque = NULL;

	return 0;
}

static int sdb_key_to_Key(const struct sdb_key *s, Key *h)
{
	int rc;

	if (s->mkvno != NULL) {
		h->mkvno = malloc(sizeof(unsigned int));
		if (h->mkvno == NULL) {
			goto error_nomem;
		}
		*h->mkvno = *s->mkvno;
	} else {
		h->mkvno = NULL;
	}

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
	} else {
		h->salt = NULL;
	}

	return 0;

error_nomem:
	free_Key(h);
	return ENOMEM;
}

static int sdb_keys_to_Keys(const struct sdb_keys *s, Keys *h)
{
	int ret, i;

	h->len = s->len;
	if (s->val != NULL) {
		h->val = malloc(h->len * sizeof(Key));
		if (h->val == NULL) {
			return ENOMEM;
		}
		for (i = 0; i < h->len; i++) {
			ret = sdb_key_to_Key(&s->val[i],
					     &h->val[i]);
			if (ret != 0) {
				free_Keys(h);
				return ENOMEM;
			}
		}
	} else {
		h->val = NULL;
	}

	return 0;
}

static int sdb_event_to_Event(krb5_context context,
			      const struct sdb_event *s, Event *h)
{
	int ret;

	if (s->principal != NULL) {
		ret = krb5_copy_principal(context,
					  s->principal,
					  &h->principal);
		if (ret != 0) {
			free_Event(h);
			return ret;
		}
	} else {
		h->principal = NULL;
	}
	h->time = s->time;

	return 0;
}


static int sdb_entry_to_hdb_entry(krb5_context context,
				  const struct sdb_entry *s,
				  struct hdb_entry *h)
{
	unsigned int i;
	int rc;

	ZERO_STRUCTP(h);

	rc = krb5_copy_principal(context,
				 s->principal,
				 &h->principal);
	if (rc != 0) {
		return rc;
	}

	h->kvno = s->kvno;

	rc = sdb_keys_to_Keys(&s->keys, &h->keys);
	if (rc != 0) {
		goto error;
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
	} else {
		h->modified_by = NULL;
	}

	if (s->valid_start != NULL) {
		h->valid_start = malloc(sizeof(KerberosTime));
		if (h->valid_start == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->valid_start = *s->valid_start;
	} else {
		h->valid_start = NULL;
	}

	if (s->valid_end != NULL) {
		h->valid_end = malloc(sizeof(KerberosTime));
		if (h->valid_end == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->valid_end = *s->valid_end;
	} else {
		h->valid_end = NULL;
	}

	if (s->pw_end != NULL) {
		h->pw_end = malloc(sizeof(KerberosTime));
		if (h->pw_end == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->pw_end = *s->pw_end;
	} else {
		h->pw_end = NULL;
	}

	if (s->max_life != NULL) {
		h->max_life = malloc(sizeof(unsigned int));
		if (h->max_life == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->max_life = *s->max_life;
	} else {
		h->max_life = NULL;
	}

	if (s->max_renew != NULL) {
		h->max_renew = malloc(sizeof(unsigned int));
		if (h->max_renew == NULL) {
			rc = ENOMEM;
			goto error;
		}
		*h->max_renew = *s->max_renew;
	} else {
		h->max_renew = NULL;
	}

	sdb_flags_to_hdb_flags(&s->flags, &h->flags);

	h->etypes = NULL;
	if (h->keys.val != NULL) {
		h->etypes = malloc(sizeof(*h->etypes));
		if (h->etypes == NULL) {
			rc = ENOMEM;
			goto error;
		}

		h->etypes->len = s->keys.len;

		h->etypes->val = calloc(h->etypes->len, sizeof(int));
		if (h->etypes->val == NULL) {
			rc = ENOMEM;
			goto error;
		}

		for (i = 0; i < h->etypes->len; i++) {
			Key k = h->keys.val[i];

			h->etypes->val[i] = KRB5_KEY_TYPE(&(k.key));
		}
	}

	h->generation = NULL;
	h->extensions = NULL; /* really sure ? FIXME */

	return 0;
error:
	free_hdb_entry(h);
	return rc;
}

static int samba_kdc_hdb_entry_destructor(struct samba_kdc_entry *p)
{
	struct hdb_entry_ex *entry_ex = p->entry_ex;
	free_hdb_entry(&entry_ex->entry);

	return 0;
}

static void samba_kdc_free_hdb_entry(krb5_context context,
				     struct hdb_entry_ex *entry_ex)
{
	/* this function is called only from hdb_free_entry().
	 * Make sure we neutralize the destructor or we will
	 * get a double free later when hdb_free_entry() will
	 * try to call free_hdb_entry() */
	talloc_set_destructor(entry_ex->ctx, NULL);

	/* now proceed to free the talloc part */
	talloc_free(entry_ex->ctx);
}

int sdb_entry_ex_to_hdb_entry_ex(krb5_context context,
				 const struct sdb_entry_ex *s,
				 struct hdb_entry_ex *h)
{
	struct samba_kdc_entry *skdc_entry;

	ZERO_STRUCTP(h);

	if (s->ctx != NULL) {
		skdc_entry = talloc_get_type(s->ctx, struct samba_kdc_entry);

		h->ctx		= skdc_entry;
		h->free_entry	= samba_kdc_free_hdb_entry;

		talloc_set_destructor(skdc_entry,
				      samba_kdc_hdb_entry_destructor);
	}

	return sdb_entry_to_hdb_entry(context, &s->entry, &h->entry);
}
