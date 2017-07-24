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

krb5_error_code kdb_samba_dbekd_decrypt_key_data(krb5_context context,
						 const krb5_keyblock *mkey,
						 const krb5_key_data *key_data,
						 krb5_keyblock *kkey,
						 krb5_keysalt *keysalt)
{
	/*
	 * NOTE: Samba doesn't use a master key, so we will just copy
	 * the contents around untouched.
	 */
	ZERO_STRUCTP(kkey);

	kkey->magic = KV5M_KEYBLOCK;
	kkey->enctype = key_data->key_data_type[0];
	kkey->contents = malloc(key_data->key_data_length[0]);
	if (kkey->contents == NULL) {
		return ENOMEM;
	}
	memcpy(kkey->contents,
	       key_data->key_data_contents[0],
	       key_data->key_data_length[0]);
	kkey->length = key_data->key_data_length[0];

	if (keysalt != NULL) {
		keysalt->type = key_data->key_data_type[1];
		keysalt->data.data = malloc(key_data->key_data_length[1]);
		if (keysalt->data.data == NULL) {
			free(kkey->contents);
			return ENOMEM;
		}
		memcpy(keysalt->data.data,
		       key_data->key_data_contents[1],
		       key_data->key_data_length[1]);
		keysalt->data.length = key_data->key_data_length[1];
	}

	return 0;
}

krb5_error_code kdb_samba_dbekd_encrypt_key_data(krb5_context context,
						 const krb5_keyblock *mkey,
						 const krb5_keyblock *kkey,
						 const krb5_keysalt *keysalt,
						 int keyver,
						 krb5_key_data *key_data)
{
	/*
	 * NOTE: samba doesn't use a master key, so we will just copy
	 * the contents around untouched.
	 */

	ZERO_STRUCTP(key_data);

	key_data->key_data_ver = KRB5_KDB_V1_KEY_DATA_ARRAY;
	key_data->key_data_kvno = keyver;
	key_data->key_data_type[0] = kkey->enctype;
	key_data->key_data_contents[0] = malloc(kkey->length);
	if (key_data->key_data_contents[0] == NULL) {
		return ENOMEM;
	}
	memcpy(key_data->key_data_contents[0],
	       kkey->contents,
	       kkey->length);
	key_data->key_data_length[0] = kkey->length;

	if (keysalt != NULL) {
		key_data->key_data_type[1] = keysalt->type;
		key_data->key_data_contents[1] = malloc(keysalt->data.length);
		if (key_data->key_data_contents[1] == NULL) {
			free(key_data->key_data_contents[0]);
			return ENOMEM;
		}
		memcpy(key_data->key_data_contents[1],
		       keysalt->data.data,
		       keysalt->data.length);
		key_data->key_data_length[1] = keysalt->data.length;
	}

	return 0;
}
