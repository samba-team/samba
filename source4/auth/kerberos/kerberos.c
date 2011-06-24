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

  The self_service, should be the local service (for S4U2Self if impersonate_principal is given).

  The target_service defaults to the krbtgt if NULL, but could be kpasswd/realm or a remote service (for S4U2Proxy)

*/
 krb5_error_code kerberos_kinit_password_cc(krb5_context ctx, krb5_ccache store_cc,
					    krb5_principal init_principal,
					    const char *init_password,
					    krb5_principal impersonate_principal,
					    const char *self_service,
					    const char *target_service,
					    krb5_get_init_creds_opt *krb_options,
					    time_t *expire_time, time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_get_creds_opt options;
	krb5_principal store_principal;
	krb5_creds store_creds;
	krb5_creds *s4u2self_creds;
	Ticket s4u2self_ticket;
	size_t s4u2self_ticketlen;
	krb5_creds *s4u2proxy_creds;
	krb5_principal self_princ;
	bool s4u2proxy;
	krb5_principal target_princ;
	krb5_ccache tmp_cc;
	const char *self_realm;
	krb5_principal blacklist_principal = NULL;
	krb5_principal whitelist_principal = NULL;

	if (impersonate_principal && self_service == NULL) {
		return EINVAL;
	}

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

	if (impersonate_principal == NULL) {
		goto store;
	}

	/*
	 * We are trying S4U2Self now:
	 *
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
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	/*
	 * we need to remember the client principal of our
	 * TGT and make sure the KDC does not return this
	 * in the impersonated tickets. This can happen
	 * if the KDC does not support S4U2Self and S4U2Proxy.
	 */
	blacklist_principal = store_creds.client;
	store_creds.client = NULL;
	krb5_free_cred_contents(ctx, &store_creds);

	/*
	 * Check if we also need S4U2Proxy or if S4U2Self is
	 * enough in order to get a ticket for the target.
	 */
	if (target_service == NULL) {
		s4u2proxy = false;
	} else if (strcmp(target_service, self_service) == 0) {
		s4u2proxy = false;
	} else {
		s4u2proxy = true;
	}

	/*
	 * For S4U2Self we need our own service principal,
	 * which belongs to our own realm (available on
	 * our client principal).
	 */
	self_realm = krb5_principal_get_realm(ctx, init_principal);

	code = krb5_parse_name(ctx, self_service, &self_princ);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_principal_set_realm(ctx, self_princ, self_realm);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds_opt_alloc(ctx, &options);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	if (s4u2proxy) {
		/*
		 * If we want S4U2Proxy, we need the forwardable flag
		 * on the S4U2Self ticket.
		 */
		krb5_get_creds_opt_set_options(ctx, options, KRB5_GC_FORWARDABLE);
	}

	code = krb5_get_creds_opt_set_impersonate(ctx, options,
						  impersonate_principal);
	if (code != 0) {
		krb5_get_creds_opt_free(ctx, options);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds(ctx, options, tmp_cc,
			      self_princ, &s4u2self_creds);
	krb5_get_creds_opt_free(ctx, options);
	krb5_free_principal(ctx, self_princ);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	if (!s4u2proxy) {
		krb5_cc_destroy(ctx, tmp_cc);

		/*
		 * Now make sure we store the impersonated principal
		 * and creds instead of the TGT related stuff
		 * in the krb5_ccache of the caller.
		 */
		code = krb5_copy_creds_contents(ctx, s4u2self_creds,
						&store_creds);
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
		goto store;
	}

	/*
	 * We are trying S4U2Proxy:
	 *
	 * We need the ticket from the S4U2Self step
	 * and our TGT in order to get the delegated ticket.
	 */
	code = decode_Ticket((const uint8_t *)s4u2self_creds->ticket.data,
			     s4u2self_creds->ticket.length,
			     &s4u2self_ticket,
			     &s4u2self_ticketlen);
	if (code != 0) {
		krb5_free_creds(ctx, s4u2self_creds);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	/*
	 * we need to remember the client principal of the
	 * S4U2Self stage and as it needs to match the one we
	 * will get for the S4U2Proxy stage. We need this
	 * in order to detect KDCs which does not support S4U2Proxy.
	 */
	whitelist_principal = s4u2self_creds->client;
	s4u2self_creds->client = NULL;
	krb5_free_creds(ctx, s4u2self_creds);

	/*
	 * For S4U2Proxy we also got a target service principal,
	 * which also belongs to our own realm (available on
	 * our client principal).
	 */
	code = krb5_parse_name(ctx, target_service, &target_princ);
	if (code != 0) {
		free_Ticket(&s4u2self_ticket);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_principal_set_realm(ctx, target_princ, self_realm);
	if (code != 0) {
		free_Ticket(&s4u2self_ticket);
		krb5_free_principal(ctx, target_princ);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds_opt_alloc(ctx, &options);
	if (code != 0) {
		free_Ticket(&s4u2self_ticket);
		krb5_free_principal(ctx, target_princ);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	krb5_get_creds_opt_set_options(ctx, options, KRB5_GC_FORWARDABLE);
	krb5_get_creds_opt_set_options(ctx, options, KRB5_GC_CONSTRAINED_DELEGATION);

	code = krb5_get_creds_opt_set_ticket(ctx, options, &s4u2self_ticket);
	free_Ticket(&s4u2self_ticket);
	if (code != 0) {
		krb5_get_creds_opt_free(ctx, options);
		krb5_free_principal(ctx, target_princ);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds(ctx, options, tmp_cc,
			      target_princ, &s4u2proxy_creds);
	krb5_get_creds_opt_free(ctx, options);
	krb5_free_principal(ctx, target_princ);
	krb5_cc_destroy(ctx, tmp_cc);
	if (code != 0) {
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		return code;
	}

	/*
	 * Now make sure we store the impersonated principal
	 * and creds instead of the TGT related stuff
	 * in the krb5_ccache of the caller.
	 */
	code = krb5_copy_creds_contents(ctx, s4u2proxy_creds,
					&store_creds);
	krb5_free_creds(ctx, s4u2proxy_creds);
	if (code != 0) {
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		return code;
	}

	/*
	 * It's important to store the principal the KDC
	 * returned, as otherwise the caller would not find
	 * the S4U2Self ticket in the krb5_ccache lookup.
	 */
	store_principal = store_creds.client;

 store:
	if (blacklist_principal &&
	    krb5_principal_compare(ctx, store_creds.client, blacklist_principal)) {
		char *sp = NULL;
		char *ip = NULL;

		code = krb5_unparse_name(ctx, blacklist_principal, &sp);
		if (code != 0) {
			sp = NULL;
		}
		code = krb5_unparse_name(ctx, impersonate_principal, &ip);
		if (code != 0) {
			ip = NULL;
		}
		DEBUG(1, ("kerberos_kinit_password_cc: "
			  "KDC returned self principal[%s] while impersonating [%s]\n",
			  sp?sp:"<no memory>",
			  ip?ip:"<no memory>"));

		SAFE_FREE(sp);
		SAFE_FREE(ip);

		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_cred_contents(ctx, &store_creds);
		return KRB5_FWD_BAD_PRINCIPAL;
	}
	if (blacklist_principal) {
		krb5_free_principal(ctx, blacklist_principal);
	}

	if (whitelist_principal &&
	    !krb5_principal_compare(ctx, store_creds.client, whitelist_principal)) {
		char *sp = NULL;
		char *ep = NULL;

		code = krb5_unparse_name(ctx, store_creds.client, &sp);
		if (code != 0) {
			sp = NULL;
		}
		code = krb5_unparse_name(ctx, whitelist_principal, &ep);
		if (code != 0) {
			ep = NULL;
		}
		DEBUG(1, ("kerberos_kinit_password_cc: "
			  "KDC returned wrong principal[%s] we expected [%s]\n",
			  sp?sp:"<no memory>",
			  ep?ep:"<no memory>"));

		SAFE_FREE(sp);
		SAFE_FREE(ep);

		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_cred_contents(ctx, &store_creds);
		return KRB5_FWD_BAD_PRINCIPAL;
	}
	if (whitelist_principal) {
		krb5_free_principal(ctx, whitelist_principal);
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
