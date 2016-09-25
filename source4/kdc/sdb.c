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
#include "lib/krb5_wrap/krb5_samba.h"

void sdb_free_entry(struct sdb_entry_ex *ent)
{
	struct sdb_key *k;
	size_t i;

	if (ent->free_entry) {
		(*ent->free_entry)(ent);
	}

	for (i = 0; i < ent->entry.keys.len; i++) {
		k = &ent->entry.keys.val[i];

		/*
		 * Passing NULL as the Kerberos context is intentional here, as
		 * both Heimdal and MIT libraries don't use the context when
		 * clearing the keyblocks.
		 */
		krb5_free_keyblock_contents(NULL, &k->key);
	}

	free_sdb_entry(&ent->entry);
}

static void free_sdb_key(struct sdb_key *k)
{
	if (k == NULL) {
		return;
	}

	if (k->mkvno) {
		free(k->mkvno);
	}

	/* keyblock not alloced */

	if (k->salt) {
		smb_krb5_free_data_contents(NULL, &k->salt->salt);
	}

	ZERO_STRUCTP(k);
}

void free_sdb_entry(struct sdb_entry *s)
{
	unsigned int i;

	/*
	 * Passing NULL as the Kerberos context is intentional here, as both
	 * Heimdal and MIT libraries don't use the context when clearing the
	 * principals.
	 */
	krb5_free_principal(NULL, s->principal);

	if (s->keys.len) {
		for (i=0; i < s->keys.len; i++) {
			free_sdb_key(&s->keys.val[i]);
		}
		free(s->keys.val);
	}
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
