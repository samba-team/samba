/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Nalin Dahyabhai 2004.
   Copyright (C) Jeremy Allison 2004.

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
#include "libcli/auth/kerberos.h"
#include "system/time.h"
#include "secrets.h"

#ifdef HAVE_KRB5

#define LIBADS_CCACHE_NAME "MEMORY:libads"

/*
  we use a prompter to avoid a crash bug in the kerberos libs when 
  dealing with empty passwords
  this prompter is just a string copy ...
*/
static krb5_error_code 
kerb_prompter(krb5_context ctx, void *data,
	       const char *name,
	       const char *banner,
	       int num_prompts,
	       krb5_prompt prompts[])
{
	if (num_prompts == 0) return 0;

	memset(prompts[0].reply->data, '\0', prompts[0].reply->length);
	if (prompts[0].reply->length > 0) {
		if (data) {
			strncpy(prompts[0].reply->data, data, prompts[0].reply->length-1);
			prompts[0].reply->length = strlen(prompts[0].reply->data);
		} else {
			prompts[0].reply->length = 0;
		}
	}
	return 0;
}

/*
  simulate a kinit, putting the tgt in the given credentials cache. 
  Orignally by remus@snapserver.com
*/
 int kerberos_kinit_password_cc(krb5_context ctx, krb5_ccache cc, 
			       const char *principal, const char *password, 
			       time_t *expire_time, time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_principal me;
	krb5_creds my_creds;
	krb5_get_init_creds_opt options;

	if ((code = krb5_parse_name(ctx, principal, &me))) {
		return code;
	}

	krb5_get_init_creds_opt_init(&options);

	if ((code = krb5_get_init_creds_password(ctx, &my_creds, me, password, 
						 kerb_prompter, 
						 NULL, 0, NULL, &options))) {
		krb5_free_principal(ctx, me);
		return code;
	}
	
	if ((code = krb5_cc_initialize(ctx, cc, me))) {
		krb5_free_cred_contents(ctx, &my_creds);
		krb5_free_principal(ctx, me);
		return code;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		krb5_free_cred_contents(ctx, &my_creds);
		krb5_free_principal(ctx, me);
		return code;
	}
	
	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) my_creds.times.starttime;
	}

	krb5_free_cred_contents(ctx, &my_creds);
	krb5_free_principal(ctx, me);
	
	return 0;
}

/*
  simulate a kinit, putting the tgt in the given credentials cache. 
  If cache_name == NULL place in default cache location.

  Orignally by remus@snapserver.com
*/
int kerberos_kinit_password(const char *principal,
			    const char *password,
			    int time_offset,
			    time_t *expire_time,
			    const char *cache_name,
			    time_t *kdc_time)
{
	int code;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;

	if ((code = krb5_init_context(&ctx)))
		return code;

	if (time_offset != 0) {
		krb5_set_real_time(ctx, time(NULL) + time_offset, 0);
	}
	
	if ((code = krb5_cc_resolve(ctx, cache_name ?
				    cache_name : krb5_cc_default_name(ctx), &cc))) {
		krb5_free_context(ctx);
		return code;
	}

	code = kerberos_kinit_password_cc(ctx, cc, principal, password, expire_time, kdc_time);
	
	krb5_cc_close(ctx, cc);
	krb5_free_context(ctx);

	return code;
}

/* run kinit to setup our ccache */
int ads_kinit_password(ADS_STRUCT *ads)
{
	char *s;
	int ret;

	if (asprintf(&s, "%s@%s", ads->auth.user_name, ads->auth.realm) == -1) {
		return KRB5_CC_NOMEM;
	}

	if (!ads->auth.password) {
		return KRB5_LIBOS_CANTREADPWD;
	}
	
	ret = kerberos_kinit_password(s, ads->auth.password, ads->auth.time_offset,
			&ads->auth.expire, NULL, NULL);

	if (ret) {
		DEBUG(0,("kerberos_kinit_password %s failed: %s\n", 
			 s, error_message(ret)));
	}
	free(s);
	return ret;
}

int ads_kdestroy(const char *cc_name)
{
	krb5_error_code code;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;

	if ((code = krb5_init_context (&ctx))) {
		DEBUG(3, ("ads_kdestroy: kdb5_init_context failed: %s\n", 
			error_message(code)));
		return code;
	}
  
	if (!cc_name) {
		if ((code = krb5_cc_default(ctx, &cc))) {
			krb5_free_context(ctx);
			return code;
		}
	} else {
		if ((code = krb5_cc_resolve(ctx, cc_name, &cc))) {
			DEBUG(3, ("ads_kdestroy: krb5_cc_resolve failed: %s\n",
				  error_message(code)));
			krb5_free_context(ctx);
			return code;
		}
	}

	if ((code = krb5_cc_destroy (ctx, cc))) {
		DEBUG(3, ("ads_kdestroy: krb5_cc_destroy failed: %s\n", 
			error_message(code)));
	}

	krb5_free_context (ctx);
	return code;
}

/************************************************************************
 Routine to fetch the salting principal for a service.  Active
 Directory may use a non-obvious principal name to generate the salt
 when it determines the key to use for encrypting tickets for a service,
 and hopefully we detected that when we joined the domain.
 ************************************************************************/

static char *kerberos_secrets_fetch_salting_principal(const char *service, int enctype)
{
	char *ret = NULL;

#if 0
	asprintf(&key, "%s/%s/enctype=%d", SECRETS_SALTING_PRINCIPAL, service, enctype);
	if (!key) {
		return NULL;
	}
	ret = (char *)secrets_fetch(key, NULL);
	SAFE_FREE(key);
#endif
	return ret;
}

/************************************************************************
 Routine to get the salting principal for this service.  Active
 Directory may use a non-obvious principal name to generate the salt
 when it determines the key to use for encrypting tickets for a service,
 and hopefully we detected that when we joined the domain.
 Caller must free if return is not null.
 ************************************************************************/

krb5_principal kerberos_fetch_salt_princ_for_host_princ(krb5_context context,
							krb5_principal host_princ,
							int enctype)
{
	char *unparsed_name = NULL, *salt_princ_s = NULL;
	krb5_principal ret_princ = NULL;

	if (krb5_unparse_name(context, host_princ, &unparsed_name) != 0) {
		return (krb5_principal)NULL;
	}

	if ((salt_princ_s = kerberos_secrets_fetch_salting_principal(unparsed_name, enctype)) == NULL) {
		krb5_free_unparsed_name(context, unparsed_name);
		return (krb5_principal)NULL;
	}

	if (krb5_parse_name(context, salt_princ_s, &ret_princ) != 0) {
		krb5_free_unparsed_name(context, unparsed_name);
		SAFE_FREE(salt_princ_s);
		return (krb5_principal)NULL;
	}
	krb5_free_unparsed_name(context, unparsed_name);
	SAFE_FREE(salt_princ_s);
	return ret_princ;
}

/************************************************************************
 Routine to set the salting principal for this service.  Active
 Directory may use a non-obvious principal name to generate the salt
 when it determines the key to use for encrypting tickets for a service,
 and hopefully we detected that when we joined the domain.
 Setting principal to NULL deletes this entry.
 ************************************************************************/

 BOOL kerberos_secrets_store_salting_principal(const char *service,
					      int enctype,
					      const char *principal)
{
	char *key = NULL;
	BOOL ret = False;
	krb5_context context = NULL;
	krb5_principal princ = NULL;
	char *princ_s = NULL;
	char *unparsed_name = NULL;

	krb5_init_context(&context);
	if (!context) {
		return False;
	}
	if (strchr_m(service, '@')) {
		asprintf(&princ_s, "%s", service);
	} else {
		asprintf(&princ_s, "%s@%s", service, lp_realm());
	}

	if (krb5_parse_name(context, princ_s, &princ) != 0) {
		goto out;
		
	}
	if (krb5_unparse_name(context, princ, &unparsed_name) != 0) {
		goto out;
	}

	asprintf(&key, "%s/%s/enctype=%d", SECRETS_SALTING_PRINCIPAL, unparsed_name, enctype);
	if (!key)  {
		goto out;
	}

#if 0
	if ((principal != NULL) && (strlen(principal) > 0)) {
		ret = secrets_store(key, principal, strlen(principal) + 1);
	} else {
		ret = secrets_delete(key);
	}
#endif 

 out:

	SAFE_FREE(key);
	SAFE_FREE(princ_s);

	if (unparsed_name) {
		krb5_free_unparsed_name(context, unparsed_name);
	}
	if (context) {
		krb5_free_context(context);
	}

	return ret;
}

/************************************************************************
 Routine to get initial credentials as a service ticket for the local machine.
 Returns a buffer initialized with krb5_mk_req_extended.
 ************************************************************************/

static krb5_error_code get_service_ticket(krb5_context ctx,
					krb5_ccache ccache,
					const char *service_principal,
					int enctype,
					krb5_data *p_outbuf)
{
	krb5_creds creds, *new_creds = NULL;
	char *service_s = NULL;
	char *machine_account = NULL, *password = NULL;
	krb5_data in_data;
	krb5_auth_context auth_context = NULL;
	krb5_error_code err = 0;

	ZERO_STRUCT(creds);

	asprintf(&machine_account, "%s$@%s", lp_netbios_name(), lp_realm());
	if (machine_account == NULL) {
		goto out;
	}
	password = secrets_fetch_machine_password(lp_workgroup());
	if (password == NULL) {
		goto out;
	}
	if ((err = kerberos_kinit_password(machine_account, password, 0, NULL, LIBADS_CCACHE_NAME, NULL)) != 0) {
		DEBUG(0,("get_service_ticket: kerberos_kinit_password %s@%s failed: %s\n", 
			machine_account,
			lp_realm(),
			error_message(err)));
		goto out;
	}

	/* Ok - the above call has gotten a TGT. Now we need to get a service
	   ticket to ourselves. */

	/* Set up the enctype and client and server principal fields for krb5_get_credentials. */
	kerberos_set_creds_enctype(&creds, enctype);

	if ((err = krb5_cc_get_principal(ctx, ccache, &creds.client))) {
		DEBUG(3, ("get_service_ticket: krb5_cc_get_principal failed: %s\n", 
			error_message(err)));
		goto out;
	}

	if (strchr_m(service_principal, '@')) {
		asprintf(&service_s, "%s", service_principal);
	} else {
		asprintf(&service_s, "%s@%s", service_principal, lp_realm());
	}

	if ((err = krb5_parse_name(ctx, service_s, &creds.server))) {
		DEBUG(0,("get_service_ticket: krb5_parse_name %s failed: %s\n", 
			service_s, error_message(err)));
		goto out;
	}

	if ((err = krb5_get_credentials(ctx, 0, ccache, &creds, &new_creds))) {
		DEBUG(5,("get_service_ticket: krb5_get_credentials for %s enctype %d failed: %s\n", 
			service_s, enctype, error_message(err)));
		goto out;
	}

	memset(&in_data, '\0', sizeof(in_data));
	if ((err = krb5_mk_req_extended(ctx, &auth_context, 0, &in_data,
			new_creds, p_outbuf)) != 0) {
		DEBUG(0,("get_service_ticket: krb5_mk_req_extended failed: %s\n", 
			error_message(err)));
		goto out;
	}

 out:

	if (auth_context) {
		krb5_auth_con_free(ctx, auth_context);
	}
	if (new_creds) {
		krb5_free_creds(ctx, new_creds);
	}
	if (creds.server) {
		krb5_free_principal(ctx, creds.server);
	}
	if (creds.client) {
		krb5_free_principal(ctx, creds.client);
	}

	SAFE_FREE(service_s);
	SAFE_FREE(password);
	SAFE_FREE(machine_account);
	return err;
}

/************************************************************************
 Check if the machine password can be used in conjunction with the salting_principal
 to generate a key which will successfully decrypt the AP_REQ already
 gotten as a message to the local machine.
 ************************************************************************/

static BOOL verify_service_password(krb5_context ctx,
				    int enctype,
				    const char *salting_principal,
				    krb5_data *in_data)
{
	BOOL ret = False;
	krb5_principal salting_kprinc = NULL;
	krb5_ticket *ticket = NULL;
	krb5_keyblock key;
	krb5_data passdata;
	char *salting_s = NULL;
	char *machine_account = NULL, *password = NULL;
	krb5_auth_context auth_context = NULL;
	krb5_error_code err;

	memset(&passdata, '\0', sizeof(passdata));
	memset(&key, '\0', sizeof(key));

	asprintf(&machine_account, "%s$@%s", lp_netbios_name(), lp_realm());
	if (machine_account == NULL) {
		goto out;
	}
	password = secrets_fetch_machine_password(lp_workgroup());
	if (password == NULL) {
		goto out;
	}

	if (strchr_m(salting_principal, '@')) {
		asprintf(&salting_s, "%s", salting_principal);
	} else {
		asprintf(&salting_s, "%s@%s", salting_principal, lp_realm());
	}

	if ((err = krb5_parse_name(ctx, salting_s, &salting_kprinc))) {
		DEBUG(0,("verify_service_password: krb5_parse_name %s failed: %s\n", 
			salting_s, error_message(err)));
		goto out;
	}

	passdata.length = strlen(password);
	passdata.data = (char*)password;
	if ((err = create_kerberos_key_from_string_direct(ctx, salting_kprinc, &passdata, &key, enctype))) {
		DEBUG(0,("verify_service_password: create_kerberos_key_from_string %d failed: %s\n",
			enctype, error_message(err)));
		goto out;
	}

	if ((err = krb5_auth_con_init(ctx, &auth_context)) != 0) {
		DEBUG(0,("verify_service_password: krb5_auth_con_init failed %s\n", error_message(err)));
		goto out;
	}

	if ((err = krb5_auth_con_setuseruserkey(ctx, auth_context, &key)) != 0) {
		DEBUG(0,("verify_service_password: krb5_auth_con_setuseruserkey failed %s\n", error_message(err)));
		goto out;
	}

	if (!(err = krb5_rd_req(ctx, &auth_context, in_data, NULL, NULL, NULL, &ticket))) {
		DEBUG(10,("verify_service_password: decrypted message with enctype %u salt %s!\n",
				(unsigned int)enctype, salting_s));
		ret = True;
	}

 out:

	memset(&passdata, 0, sizeof(passdata));
	krb5_free_keyblock_contents(ctx, &key);
	if (ticket != NULL) {
		krb5_free_ticket(ctx, ticket);
	}
	if (salting_kprinc) {
		krb5_free_principal(ctx, salting_kprinc);
	}
	SAFE_FREE(salting_s);
	SAFE_FREE(password);
	SAFE_FREE(machine_account);
	return ret;
}

/************************************************************************
 *
 * From the current draft of kerberos-clarifications:
 *
 *     It is not possible to reliably generate a user's key given a pass
 *     phrase without contacting the KDC, since it will not be known
 *     whether alternate salt or parameter values are required.
 *
 * And because our server has a password, we have this exact problem.  We
 * make multiple guesses as to which principal name provides the salt which
 * the KDC is using.
 *
 ************************************************************************/

static void kerberos_derive_salting_principal_for_enctype(const char *service_principal,
							  krb5_context ctx,
							  krb5_ccache ccache,
							  krb5_enctype enctype,
							  krb5_enctype *enctypes)
{
	char *salting_principals[3] = {NULL, NULL, NULL}, *second_principal = NULL;
	krb5_error_code err = 0;
	krb5_data outbuf;
	int i, j;

	memset(&outbuf, '\0', sizeof(outbuf));

	/* Check that the service_principal is useful. */
	if ((service_principal == NULL) || (strlen(service_principal) == 0)) {
		return;
	}

	/* Generate our first guess -- the principal as-given. */
	asprintf(&salting_principals[0], "%s", service_principal);
	if ((salting_principals[0] == NULL) || (strlen(salting_principals[0]) == 0)) {
		return;
	}

	/* Generate our second guess -- the computer's principal, as Win2k3. */
	asprintf(&second_principal, "host/%s.%s", lp_netbios_name(), lp_realm());
	if (second_principal != NULL) {
		strlower_m(second_principal);
		asprintf(&salting_principals[1], "%s@%s", second_principal, lp_realm());
		SAFE_FREE(second_principal);
	}
	if ((salting_principals[1] == NULL) || (strlen(salting_principals[1]) == 0)) {
		goto out;
	}

	/* Generate our third guess -- the computer's principal, as Win2k. */
	asprintf(&second_principal, "HOST/%s", lp_netbios_name());
	if (second_principal != NULL) {
		strlower_m(second_principal + 5);
		asprintf(&salting_principals[2], "%s@%s",
			second_principal, lp_realm());
		SAFE_FREE(second_principal);
	}
	if ((salting_principals[2] == NULL) || (strlen(salting_principals[2]) == 0)) {
		goto out;
	}

	/* Get a service ticket for ourselves into our memory ccache. */
	/* This will commonly fail if there is no principal by that name (and we're trying
	   many names). So don't print a debug 0 error. */

	if ((err = get_service_ticket(ctx, ccache, service_principal, enctype, &outbuf)) != 0) {
		DEBUG(3, ("verify_service_password: get_service_ticket failed: %s\n", 
			error_message(err)));
		goto out;
	}

	/* At this point we have a message to ourselves, salted only the KDC knows how. We
	   have to work out what that salting is. */

	/* Try and find the correct salting principal. */
	for (i = 0; i < sizeof(salting_principals) / sizeof(salting_principals[i]); i++) {
		if (verify_service_password(ctx, enctype, salting_principals[i], &outbuf)) {
			break;
		}
	}

	/* If we failed to get a match, return. */
	if (i >= sizeof(salting_principals) / sizeof(salting_principals[i])) {
		goto out;
	}

	/* If we succeeded, store the principal for use for all enctypes which
	 * share the same cipher and string-to-key function.  Doing this here
	 * allows servers which just pass a keytab to krb5_rd_req() to work
	 * correctly. */
	for (j = 0; enctypes[j] != 0; j++) {
		if (enctype != enctypes[j]) {
			/* If this enctype isn't compatible with the one which
			 * we used, skip it. */

			if (!kerberos_compatible_enctypes(ctx, enctypes[j], enctype))
				continue;
		}
		/* If the principal which gives us the proper salt is the one
		 * which we would normally guess, don't bother noting anything
		 * in the secrets tdb. */
		if (strcmp(service_principal, salting_principals[i]) != 0) {
			kerberos_secrets_store_salting_principal(service_principal,
								enctypes[j],
								salting_principals[i]);
		}
	}

 out :

	kerberos_free_data_contents(ctx, &outbuf);
	SAFE_FREE(salting_principals[0]);
	SAFE_FREE(salting_principals[1]);
	SAFE_FREE(salting_principals[2]);
	SAFE_FREE(second_principal);
}

/************************************************************************
 Go through all the possible enctypes for this principal.
 ************************************************************************/

static void kerberos_derive_salting_principal_direct(krb5_context context,
					krb5_ccache ccache,
					krb5_enctype *enctypes,
					char *service_principal)
{
	int i;

	/* Try for each enctype separately, because the rules are
	 * different for different enctypes. */
	for (i = 0; enctypes[i] != 0; i++) {
		/* Delete secrets entry first. */
		kerberos_secrets_store_salting_principal(service_principal, 0, NULL);
#ifdef ENCTYPE_ARCFOUR_HMAC
		if (enctypes[i] == ENCTYPE_ARCFOUR_HMAC) {
			/* Of course this'll always work, so just save
			 * ourselves the effort. */
			continue;
		}
#endif
		/* Try to figure out what's going on with this
		 * principal. */
		kerberos_derive_salting_principal_for_enctype(service_principal,
								context,
								ccache,
								enctypes[i],
								enctypes);
	}
}

/************************************************************************
 Wrapper function for the above.
 ************************************************************************/

BOOL kerberos_derive_salting_principal(char *service_principal)
{
	krb5_context context = NULL;
	krb5_enctype *enctypes = NULL;
	krb5_ccache ccache = NULL;
	krb5_error_code ret = 0;

	initialize_krb5_error_table();
	if ((ret = krb5_init_context(&context)) != 0) {
		DEBUG(1,("kerberos_derive_cifs_salting_principals: krb5_init_context failed. %s\n",
			error_message(ret)));
		return False;
	}
	if ((ret = get_kerberos_allowed_etypes(context, &enctypes)) != 0) {
		DEBUG(1,("kerberos_derive_cifs_salting_principals: get_kerberos_allowed_etypes failed. %s\n",
			error_message(ret)));
		goto out;
	}

	if ((ret = krb5_cc_resolve(context, LIBADS_CCACHE_NAME, &ccache)) != 0) {
		DEBUG(3, ("get_service_ticket: krb5_cc_resolve for %s failed: %s\n", 
			LIBADS_CCACHE_NAME, error_message(ret)));
		goto out;
	}

	kerberos_derive_salting_principal_direct(context, ccache, enctypes, service_principal);

  out: 
	if (enctypes) {
		free_kerberos_etypes(context, enctypes);
	}
	if (ccache) {
		krb5_cc_destroy(context, ccache);
	}
	if (context) {
		krb5_free_context(context);
	}

	return ret ? False : True;
}

/************************************************************************
 Core function to try and determine what salt is being used for any keytab
 keys.
 ************************************************************************/

BOOL kerberos_derive_cifs_salting_principals(void)
{
	fstring my_fqdn;
	char *service = NULL;
	krb5_context context = NULL;
	krb5_enctype *enctypes = NULL;
	krb5_ccache ccache = NULL;
	krb5_error_code ret = 0;
	BOOL retval = False;

	initialize_krb5_error_table();
	if ((ret = krb5_init_context(&context)) != 0) {
		DEBUG(1,("kerberos_derive_cifs_salting_principals: krb5_init_context failed. %s\n",
			error_message(ret)));
		return False;
	}
	if ((ret = get_kerberos_allowed_etypes(context, &enctypes)) != 0) {
		DEBUG(1,("kerberos_derive_cifs_salting_principals: get_kerberos_allowed_etypes failed. %s\n",
			error_message(ret)));
		goto out;
	}

	if ((ret = krb5_cc_resolve(context, LIBADS_CCACHE_NAME, &ccache)) != 0) {
		DEBUG(3, ("get_service_ticket: krb5_cc_resolve for %s failed: %s\n", 
			LIBADS_CCACHE_NAME, error_message(ret)));
		goto out;
	}

	if (asprintf(&service, "%s$", lp_netbios_name()) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}
	if (asprintf(&service, "cifs/%s", lp_netbios_name()) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}
	if (asprintf(&service, "host/%s", lp_netbios_name()) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}
	if (asprintf(&service, "cifs/%s.%s", lp_netbios_name(), lp_realm()) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}
	if (asprintf(&service, "host/%s.%s", lp_netbios_name(), lp_realm()) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}
	name_to_fqdn(my_fqdn, lp_netbios_name());
	if (asprintf(&service, "cifs/%s", my_fqdn) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}
	if (asprintf(&service, "host/%s", my_fqdn) != -1) {
		strlower_m(service);
		kerberos_derive_salting_principal_direct(context, ccache, enctypes, service);
		SAFE_FREE(service);
	}

	retval = True;

  out: 
	if (enctypes) {
		free_kerberos_etypes(context, enctypes);
	}
	if (ccache) {
		krb5_cc_destroy(context, ccache);
	}
	if (context) {
		krb5_free_context(context);
	}
	return retval;
}
#endif
