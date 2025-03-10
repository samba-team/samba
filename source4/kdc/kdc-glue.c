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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

int kdc_check_pac(krb5_context context,
		  DATA_BLOB srv_sig,
		  struct PAC_SIGNATURE_DATA *kdc_sig,
		  hdb_entry *ent)
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

	ret = hdb_enctype2key(context, ent, NULL, etype, &key);

	if (ret != 0) {
		return ret;
	}

	keyblock = key->key;

	return check_pac_checksum(srv_sig, kdc_sig,
				 context, &keyblock);
}

struct samba_kdc_entry_pac samba_kdc_get_device_pac(const astgs_request_t r)
{
	const hdb_entry *device = kdc_request_get_armor_client(r);
	struct samba_kdc_entry *device_skdc_entry = NULL;
	const hdb_entry *device_krbtgt = kdc_request_get_armor_server(r);
	const struct samba_kdc_entry *device_krbtgt_skdc_entry = NULL;
	const krb5_const_pac device_pac = kdc_request_get_armor_pac(r);

	if (device_pac == NULL) {
		return samba_kdc_entry_pac(NULL, NULL, NULL);
	}

	/*
	 * If we have a armor_pac we also have armor_server,
	 * otherwise we can't decrypt the ticket and get to
	 * the pac.
	 */
	device_krbtgt_skdc_entry = talloc_get_type_abort(device_krbtgt->context,
							 struct samba_kdc_entry);

	/*
	 * The armor ticket might be from a different
	 * domain, so we may not have a local db entry
	 * for the device.
	 */
	if (device != NULL) {
		device_skdc_entry = talloc_get_type_abort(device->context,
							  struct samba_kdc_entry);
	}

	return samba_kdc_entry_pac(device_pac,
				   device_skdc_entry,
				   device_krbtgt_skdc_entry);
}
