/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "auth/kerberos/kerberos.h"
#include <hdb.h>
#include "kdc/samba_kdc.h"
#include "kdc/pac-glue.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "auth/kerberos/pac_utils.h"
#include "kdc/kdc-glue.h"

int kdc_check_pac(krb5_context context,
		  DATA_BLOB srv_sig,
		  struct PAC_SIGNATURE_DATA *kdc_sig,
		  struct hdb_entry_ex *ent)
{
	krb5_enctype etype;
	int ret;
	krb5_keyblock keyblock;
	Key *key;

	if (kdc_sig->type == CKSUMTYPE_HMAC_MD5) {
		etype = ENCTYPE_ARCFOUR_HMAC;
	} else {
		ret = krb5_cksumtype_to_enctype(context,
						kdc_sig->type,
						&etype);
		if (ret != 0) {
			return ret;
		}
	}

#if HDB_ENCTYPE2KEY_TAKES_KEYSET
	ret = hdb_enctype2key(context, &ent->entry, NULL, etype, &key);
#else
	ret = hdb_enctype2key(context, &ent->entry, etype, &key);
#endif

	if (ret != 0) {
		return ret;
	}

	keyblock = key->key;

	return check_pac_checksum(srv_sig, kdc_sig,
				 context, &keyblock);
}
