/*
   Unix SMB/CIFS implementation.

   Samba KDB plugin for MIT Kerberos

   Copyright (c) 2010      Simo Sorce <idra@samba.org>.
   Copyright (c) 2014      Andreas Schneider <asn@samba.org>

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

#include <profile.h>
#include <kdb.h>

#include "kdc/mit_samba.h"
#include "kdb_samba.h"

krb5_error_code kdb_samba_fetch_master_key(krb5_context context,
					   krb5_principal name,
					   krb5_keyblock *key,
					   krb5_kvno *kvno,
					   char *db_args)
{
	return 0;
}

krb5_error_code kdb_samba_fetch_master_key_list(krb5_context context,
						krb5_principal mname,
						const krb5_keyblock *key,
						krb5_keylist_node **mkeys_list)
{
	krb5_keylist_node *mkey;

	/*
	 * NOTE: samba does not support master keys
	 *       so just return a dummy key
	 */
	mkey = calloc(1, sizeof(krb5_keylist_node));
	if (mkey == NULL) {
		return ENOMEM;
	}

	mkey->keyblock.magic = KV5M_KEYBLOCK;
	mkey->keyblock.enctype = ENCTYPE_UNKNOWN;
	mkey->kvno = 1;

	*mkeys_list = mkey;

	return 0;
}
