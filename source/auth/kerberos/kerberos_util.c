/* 
   Unix SMB/CIFS implementation.

   Kerberos utility functions for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004

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
#include "system/kerberos.h"
#include "system/time.h"
#include "system/network.h"
#include "auth/kerberos/kerberos.h"
#include "auth/auth.h"

struct principal_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_principal principal;
};

struct ccache_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_ccache ccache;
};

struct keytab_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_keytab keytab;
};

static int free_principal(void *ptr) {
	struct principal_container *pc = ptr;
	/* current heimdal - 0.6.3, which we need anyway, fixes segfaults here */
	krb5_free_principal(pc->smb_krb5_context->krb5_context, pc->principal);

	return 0;
}

krb5_error_code salt_principal_from_credentials(TALLOC_CTX *parent_ctx, 
						struct cli_credentials *machine_account, 
						struct smb_krb5_context *smb_krb5_context,
						krb5_principal *salt_princ)
{
	krb5_error_code ret;
	char *machine_username;
	char *salt_body;
	char *lower_realm;
	struct principal_container *mem_ctx = talloc(parent_ctx, struct principal_container);
	if (!mem_ctx) {
		return ENOMEM;
	}
	
	machine_username = talloc_strdup(mem_ctx, cli_credentials_get_username(machine_account));

	if (!machine_username) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	if (machine_username[strlen(machine_username)-1] == '$') {
		machine_username[strlen(machine_username)-1] = '\0';
	}
	lower_realm = strlower_talloc(mem_ctx, cli_credentials_get_realm(machine_account));
	if (!lower_realm) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	salt_body = talloc_asprintf(mem_ctx, "%s.%s", machine_username, 
				    lower_realm);
	if (!salt_body) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}
	
	ret = krb5_make_principal(smb_krb5_context->krb5_context, salt_princ, 
				  cli_credentials_get_realm(machine_account), 
				  "host", salt_body, NULL);

	if (ret != 0) {
		mem_ctx->smb_krb5_context = talloc_reference(mem_ctx, smb_krb5_context);
		mem_ctx->principal = *salt_princ;
		talloc_set_destructor(mem_ctx, free_principal);
	}
	return ret;
}

static int free_ccache(void *ptr) {
	struct ccache_container *ccc = ptr;
	/* current heimdal - 0.6.3, which we need anyway, fixes segfaults here */
	krb5_cc_close(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

/**
 * Return a freshly allocated ccache (destroyed by destructor on child
 * of parent_ctx), for a given set of client credentials 
 */

 NTSTATUS kinit_to_ccache(TALLOC_CTX *parent_ctx,
			  struct cli_credentials *credentials,
			  struct smb_krb5_context *smb_krb5_context,
			  krb5_ccache *ccache,
			  const char **ccache_name) 
{
	krb5_error_code ret;
	const char *password;
	char *ccache_string;
	time_t kdc_time = 0;
	struct ccache_container *mem_ctx = talloc(parent_ctx, struct ccache_container);

	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	password = cli_credentials_get_password(credentials);
	
	/* this string should be unique */
	ccache_string = talloc_asprintf(mem_ctx, "MEMORY:%s_%s", 
					cli_credentials_get_principal(credentials, mem_ctx), 
					generate_random_str(mem_ctx, 16));
	
	ret = krb5_cc_resolve(smb_krb5_context->krb5_context, ccache_string, ccache);
	if (ret) {
		DEBUG(1,("failed to generate a new krb5 ccache (%s): %s\n", 
			 ccache_string,
			 error_message(ret)));
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	mem_ctx->smb_krb5_context = talloc_reference(mem_ctx, smb_krb5_context);
	mem_ctx->ccache = *ccache;

	talloc_set_destructor(mem_ctx, free_ccache);
	ret = kerberos_kinit_password_cc(smb_krb5_context->krb5_context, *ccache, 
					 cli_credentials_get_principal(credentials, mem_ctx), 
					 password, NULL, &kdc_time);
	
	/* cope with ticket being in the future due to clock skew */
	if ((unsigned)kdc_time > time(NULL)) {
		time_t t = time(NULL);
		int time_offset =(unsigned)kdc_time-t;
		DEBUG(4,("Advancing clock by %d seconds to cope with clock skew\n", time_offset));
		krb5_set_real_time(smb_krb5_context->krb5_context, t + time_offset + 1, 0);
	}
	
	if (ret == KRB5KRB_AP_ERR_SKEW || ret == KRB5_KDCREP_SKEW) {
		DEBUG(1,("kinit for %s failed (%s)\n", 
			 cli_credentials_get_principal(credentials, mem_ctx), 
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_TIME_DIFFERENCE_AT_DC;
	}
	if (ret) {
		DEBUG(1,("kinit for %s failed (%s)\n", 
			 cli_credentials_get_principal(credentials, mem_ctx), 
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	} 
	*ccache_name = ccache_string;

	return NT_STATUS_OK;
}

static int free_keytab(void *ptr) {
	struct keytab_container *ktc = ptr;
	krb5_kt_close(ktc->smb_krb5_context->krb5_context, ktc->keytab);

	return 0;
}

 NTSTATUS create_memory_keytab(TALLOC_CTX *parent_ctx,
			       struct cli_credentials *machine_account,
			       struct smb_krb5_context *smb_krb5_context,
			       krb5_keytab *keytab) 
{
	krb5_error_code ret;
	const char *password_s;
	krb5_data password;
	int i;
	struct keytab_container *mem_ctx = talloc(parent_ctx, struct keytab_container);
	krb5_enctype *enctypes;
	krb5_principal salt_princ;
	
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	password_s = talloc_strdup(mem_ctx, cli_credentials_get_password(machine_account));
	if (!password_s) {
		DEBUG(1, ("create_memory_keytab: Could not obtain password for our local machine account!\n"));
		talloc_free(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	password.data = password_s;
	password.length = strlen(password_s);
	
	/* this string should be unique */
	
	ret = krb5_kt_resolve(smb_krb5_context->krb5_context, "MEMORY_WILDCARD:", keytab);
	if (ret) {
		DEBUG(1,("failed to generate a new krb5 keytab: %s\n", 
			 error_message(ret)));
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	mem_ctx->smb_krb5_context = talloc_reference(mem_ctx, smb_krb5_context);
	mem_ctx->keytab = *keytab;

	talloc_set_destructor(mem_ctx, free_keytab);

	ret = salt_principal_from_credentials(mem_ctx, machine_account, 
					      smb_krb5_context, 
					      &salt_princ);
	if (ret) {
		DEBUG(1,("create_memory_keytab: maksing salt principal failed (%s)\n",
			 error_message(ret)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = get_kerberos_allowed_etypes(smb_krb5_context->krb5_context, 
					  &enctypes);
	if (ret) {
		DEBUG(1,("create_memory_keytab: getting encrption types failed (%s)\n",
			 error_message(ret)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0; enctypes[i]; i++) {
		krb5_keytab_entry entry;
		ret = create_kerberos_key_from_string(smb_krb5_context->krb5_context, 
						      salt_princ, &password, &entry.keyblock, enctypes[i]);
		if (ret) {
			return NT_STATUS_INTERNAL_ERROR;
		}

                entry.principal = salt_princ;
                entry.vno       = 0 /* replace with real kvno */;
		ret = krb5_kt_add_entry(smb_krb5_context->krb5_context, *keytab, &entry);
		if (ret) {
			DEBUG(1, ("Failed to add entry for %s to keytab: %s",
				  cli_credentials_get_principal(machine_account, mem_ctx), 
				  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			return NT_STATUS_INTERNAL_ERROR;
		}
		
		krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &entry.keyblock);
	}

	free_kerberos_etypes(smb_krb5_context->krb5_context, enctypes);

	return NT_STATUS_OK;
}
