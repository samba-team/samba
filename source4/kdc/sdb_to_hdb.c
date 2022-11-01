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
	h->_unused24 = s->_unused24;
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

	ZERO_STRUCTP(h);

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

int sdb_entry_to_hdb_entry(krb5_context context,
			   const struct sdb_entry *s,
			   hdb_entry *h)
{
	struct samba_kdc_entry *ske = s->skdc_entry;
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

	h->session_etypes = NULL;
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

	h->context = ske;
	if (ske != NULL) {
		ske->kdc_entry = h;
	}
	return 0;
error:
	free_hdb_entry(h);
	return rc;
}
