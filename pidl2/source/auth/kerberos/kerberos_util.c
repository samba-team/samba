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

struct ccache_container {
	krb5_context krb5_context;
	krb5_ccache ccache;
} ccache_container;

#if 0
static int free_ccache(void *ptr) {
	struct ccache_container *ccc = ptr;
	/* current heimdal - 0.6.3, which we need anyway, fixes segfaults here */
	krb5_cc_close(ccc->krb5_context, ccc->ccache);

	return 0;
}
#endif

/**
 * Return a freshly allocated ccache (destroyed by destructor on child
 * of parent_ctx), for a given set of client credentials 
 */

 NTSTATUS kinit_to_ccache(TALLOC_CTX *parent_ctx,
			  struct cli_credentials *credentials,
			  krb5_context context,
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
	
	ret = krb5_cc_resolve(context, ccache_string, ccache);
	if (ret) {
		DEBUG(1,("failed to generate a new krb5 keytab (%s): %s\n", 
			 ccache_string,
			 error_message(ret)));
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	mem_ctx->krb5_context = context;
	mem_ctx->ccache = *ccache;

#if 0
	talloc_set_destructor(mem_ctx, free_ccache);
#endif
	ret = kerberos_kinit_password_cc(context, *ccache, 
					 cli_credentials_get_principal(credentials, mem_ctx), 
					 password, NULL, &kdc_time);
	
	/* cope with ticket being in the future due to clock skew */
	if ((unsigned)kdc_time > time(NULL)) {
		time_t t = time(NULL);
		int time_offset =(unsigned)kdc_time-t;
		DEBUG(4,("Advancing clock by %d seconds to cope with clock skew\n", time_offset));
		krb5_set_real_time(context, t + time_offset + 1, 0);
	}
	
	if (ret == KRB5KRB_AP_ERR_SKEW || ret == KRB5_KDCREP_SKEW) {
		DEBUG(1,("kinit for %s failed (%s)\n", 
			 cli_credentials_get_principal(credentials, mem_ctx), 
			 smb_get_krb5_error_message(context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_TIME_DIFFERENCE_AT_DC;
	}
	if (ret) {
		DEBUG(1,("kinit for %s failed (%s)\n", 
			 cli_credentials_get_principal(credentials, mem_ctx), 
			 smb_get_krb5_error_message(context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	} 
	*ccache_name = ccache_string;

	return NT_STATUS_OK;
}
