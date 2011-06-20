/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Nalin Dahyabhai 2004.
   Copyright (C) Jeremy Allison 2004.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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

#ifdef HAVE_KRB5

/*
  simulate a kinit, putting the tgt in the given credentials cache. 
  Orignally by remus@snapserver.com
 
  This version is built to use a keyblock, rather than needing the
  original password.

  The impersonate_principal is the principal if NULL, or the principal to impersonate

  The target_service defaults to the krbtgt if NULL, but could be kpasswd/realm or the local service (if we are doing s4u2self)
*/
 krb5_error_code kerberos_kinit_keyblock_cc(krb5_context ctx, krb5_ccache cc, 
					    krb5_principal principal, krb5_keyblock *keyblock,
					    const char *target_service,
					    krb5_get_init_creds_opt *krb_options,
					    time_t *expire_time, time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_creds my_creds;

	if ((code = krb5_get_init_creds_keyblock(ctx, &my_creds, principal, keyblock,
						 0, target_service, krb_options))) {
		return code;
	}
	
	if ((code = krb5_cc_initialize(ctx, cc, principal))) {
		krb5_free_cred_contents(ctx, &my_creds);
		return code;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		krb5_free_cred_contents(ctx, &my_creds);
		return code;
	}
	
	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) my_creds.times.starttime;
	}

	krb5_free_cred_contents(ctx, &my_creds);
	
	return 0;
}

/*
  simulate a kinit, putting the tgt in the given credentials cache. 
  Orignally by remus@snapserver.com

  The impersonate_principal is the principal if NULL, or the principal to impersonate

  The target_service defaults to the krbtgt if NULL, but could be kpasswd/realm or the local service (if we are doing s4u2self)

*/
 krb5_error_code kerberos_kinit_password_cc(krb5_context ctx, krb5_ccache store_cc,
					    krb5_principal init_principal,
					    const char *init_password,
					    krb5_principal impersonate_principal,
					    const char *target_service,
					    krb5_get_init_creds_opt *krb_options,
					    time_t *expire_time, time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_get_creds_opt options;
	krb5_principal store_principal;
	krb5_creds store_creds;
	const char *self_service = target_service;

	/*
	 * If we are not impersonating, then get this ticket for the
	 * target service, otherwise a krbtgt, and get the next ticket
	 * for the target
	 */
	code = krb5_get_init_creds_password(ctx, &store_creds,
					    init_principal,
					    init_password,
					    NULL, NULL,
					    0,
					    impersonate_principal ? NULL : target_service,
					    krb_options);
	if (code != 0) {
		return code;
	}

	store_principal = init_principal;

	if (impersonate_principal) {
		krb5_ccache tmp_cc;
		krb5_creds *s4u2self_creds;
		krb5_principal self_princ;
		const char *self_realm;

		/*
		 * As we do not want to expose our TGT in the
		 * krb5_ccache, which is also holds the impersonated creds.
		 *
		 * Some low level krb5/gssapi function might use the TGT
		 * identity and let the client act as our machine account.
		 *
		 * We need to avoid that and use a temporary krb5_ccache
		 * in order to pass our TGT to the krb5_get_creds() function.
		 */
		code = krb5_cc_new_unique(ctx, NULL, NULL, &tmp_cc);
		if (code != 0) {
			krb5_free_cred_contents(ctx, &store_creds);
			return code;
		}

		code = krb5_cc_initialize(ctx, tmp_cc, store_creds.client);
		if (code != 0) {
			krb5_cc_destroy(ctx, tmp_cc);
			krb5_free_cred_contents(ctx, &store_creds);
			return code;
		}

		code = krb5_cc_store_cred(ctx, tmp_cc, &store_creds);
		krb5_free_cred_contents(ctx, &store_creds);
		if (code != 0) {
			krb5_cc_destroy(ctx, tmp_cc);
			return code;
		}

		/*
		 * For S4U2Self we need our own service principal,
		 * which belongs to our own realm (available on
		 * our client principal.
		 */
		self_realm = krb5_principal_get_realm(ctx, init_principal);

		code = krb5_parse_name(ctx, self_service, &self_princ);
		if (code != 0) {
			krb5_cc_destroy(ctx, tmp_cc);
			return code;
		}

		code = krb5_principal_set_realm(ctx, self_princ, self_realm);
		if (code != 0) {
			krb5_free_principal(ctx, self_princ);
			krb5_cc_destroy(ctx, tmp_cc);
			return code;
		}

		code = krb5_get_creds_opt_alloc(ctx, &options);
		if (code != 0) {
			krb5_free_principal(ctx, self_princ);
			krb5_cc_destroy(ctx, tmp_cc);
			return code;
		}

		code = krb5_get_creds_opt_set_impersonate(ctx, options,
							  impersonate_principal);
		if (code != 0) {
			krb5_get_creds_opt_free(ctx, options);
			krb5_free_principal(ctx, self_princ);
			krb5_cc_destroy(ctx, tmp_cc);
			return code;
		}

		code = krb5_get_creds(ctx, options, tmp_cc,
				      self_princ, &s4u2self_creds);
		krb5_get_creds_opt_free(ctx, options);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		if (code != 0) {
			return code;
		}

		/*
		 * Now make sure we store the impersonated principal
		 * and creds instead of the TGT related stuff
		 * in the krb5_ccache of the caller.
		 */
		code = krb5_copy_creds_contents(ctx, s4u2self_creds, &store_creds);
		krb5_free_creds(ctx, s4u2self_creds);
		if (code != 0) {
			return code;
		}

		/*
		 * It's important to store the principal the KDC
		 * returned, as otherwise the caller would not find
		 * the S4U2Self ticket in the krb5_ccache lookup.
		 */
		store_principal = store_creds.client;
	}

	code = krb5_cc_initialize(ctx, store_cc, store_principal);
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		return code;
	}

	code = krb5_cc_store_cred(ctx, store_cc, &store_creds);
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		return code;
	}

	if (expire_time) {
		*expire_time = (time_t) store_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) store_creds.times.starttime;
	}

	krb5_free_cred_contents(ctx, &store_creds);

	return 0;
}


#endif
