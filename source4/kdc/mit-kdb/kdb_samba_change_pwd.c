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

krb5_error_code kdb_samba_change_pwd(krb5_context context,
				     krb5_keyblock *master_key,
				     krb5_key_salt_tuple *ks_tuple,
				     int ks_tuple_count, char *passwd,
				     int new_kvno, krb5_boolean keepold,
				     krb5_db_entry *db_entry)
{
	struct mit_samba_context *mit_ctx;
	krb5_error_code code;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	code = mit_samba_kpasswd_change_password(mit_ctx, passwd, db_entry);
	if (code != 0) {
		goto cleanup;
	}

cleanup:

	return code;
}
