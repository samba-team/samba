/* 
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "kdc/kdc.h"

 krb5_error_code samba_get_pac(krb5_context context, 
			      struct krb5_kdc_configuration *config,
			      krb5_principal client, 
			      krb5_keyblock *keyblock, 
			      krb5_data *pac) 
{
	krb5_error_code ret;
	NTSTATUS nt_status;
	struct auth_serversupplied_info *server_info;
	char *username, *p;
	const char *realm;
	TALLOC_CTX *mem_ctx = talloc_named(config, 0, "samba_get_pac context");
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = krb5_unparse_name(context, client, &username);

	if (ret != 0) {
		krb5_set_error_string(context, "get pac: could not parse principal");
		krb5_warnx(context, "get pac: could not parse principal");
		talloc_free(mem_ctx);
		return ret;
	}

	/* parse the principal name */
	realm = krb5_principal_get_realm(context, client);
	username = talloc_strdup(mem_ctx, username);
	p = strchr(username, '@');
	if (p) {
		p[0] = '\0';
	}


	nt_status = sam_get_server_info(mem_ctx, username, realm, 
					data_blob(NULL, 0), data_blob(NULL, 0),
					&server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		talloc_free(mem_ctx);
		return EINVAL;
	}

	ret = kerberos_encode_pac(mem_ctx, server_info, 
				  context, 
				  keyblock,
				  pac);

	talloc_free(mem_ctx);
	
	return ret;
}
