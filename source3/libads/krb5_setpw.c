/* 
   Unix SMB/CIFS implementation.
   krb5 set password implementation
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001 (remuskoos@yahoo.com)
   
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
#include "smb_krb5.h"
#include "libads/kerberos_proto.h"
#include "../lib/util/asn1.h"

#ifdef HAVE_KRB5

/* Those are defined by kerberos-set-passwd-02.txt and are probably
 * not supported by M$ implementation */
#define KRB5_KPASSWD_POLICY_REJECT		8
#define KRB5_KPASSWD_BAD_PRINCIPAL		9
#define KRB5_KPASSWD_ETYPE_NOSUPP		10

/*
 * we've got to be able to distinguish KRB_ERRORs from other
 * requests - valid response for CHPW v2 replies.
 */

static krb5_error_code kpasswd_err_to_krb5_err(krb5_error_code res_code)
{
	switch (res_code) {
	case KRB5_KPASSWD_ACCESSDENIED:
		return KRB5KDC_ERR_BADOPTION;
	case KRB5_KPASSWD_INITIAL_FLAG_NEEDED:
		return KRB5KDC_ERR_BADOPTION;
		/* return KV5M_ALT_METHOD; MIT-only define */
	case KRB5_KPASSWD_ETYPE_NOSUPP:
		return KRB5KDC_ERR_ETYPE_NOSUPP;
	case KRB5_KPASSWD_BAD_PRINCIPAL:
		return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	case KRB5_KPASSWD_POLICY_REJECT:
	case KRB5_KPASSWD_SOFTERROR:
		return KRB5KDC_ERR_POLICY;
	default:
		return KRB5KRB_ERR_GENERIC;
	}
}

ADS_STATUS ads_krb5_set_password(const char *kdc_host, const char *principal,
				 const char *newpw, int time_offset)
{

	ADS_STATUS aret;
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_principal princ = NULL;
	krb5_ccache ccache = NULL;
	int result_code;
	krb5_data result_code_string = { 0 };
	krb5_data result_string = { 0 };

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		return ADS_ERROR_KRB5(ret);
	}

	if (principal) {
		ret = smb_krb5_parse_name(context, principal, &princ);
		if (ret) {
			krb5_free_context(context);
			DEBUG(1, ("Failed to parse %s (%s)\n", principal,
				  error_message(ret)));
			return ADS_ERROR_KRB5(ret);
		}
	}

	if (time_offset != 0) {
		krb5_set_real_time(context, time(NULL) + time_offset, 0);
	}

	ret = krb5_cc_default(context, &ccache);
	if (ret) {
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		DEBUG(1,("Failed to get default creds (%s)\n", error_message(ret)));
		return ADS_ERROR_KRB5(ret);
	}

	ret = krb5_set_password_using_ccache(context,
					     ccache,
					     discard_const_p(char, newpw),
					     princ,
					     &result_code,
					     &result_code_string,
					     &result_string);
	if (ret) {
		DEBUG(1, ("krb5_set_password failed (%s)\n", error_message(ret)));
		aret = ADS_ERROR_KRB5(ret);
		goto done;
	}

	if (result_code != KRB5_KPASSWD_SUCCESS) {
		ret = kpasswd_err_to_krb5_err(result_code);
		DEBUG(1, ("krb5_set_password failed (%s)\n", error_message(ret)));
		aret = ADS_ERROR_KRB5(ret);
		goto done;
	}

	aret = ADS_SUCCESS;

 done:
	smb_krb5_free_data_contents(context, &result_code_string);
	smb_krb5_free_data_contents(context, &result_string);
	krb5_free_principal(context, princ);
	krb5_cc_close(context, ccache);
	krb5_free_context(context);

	return aret;
}

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

	memset(prompts[0].reply->data, 0, prompts[0].reply->length);
	if (prompts[0].reply->length > 0) {
		if (data) {
			strncpy((char *)prompts[0].reply->data,
				(const char *)data,
				prompts[0].reply->length-1);
			prompts[0].reply->length = strlen((const char *)prompts[0].reply->data);
		} else {
			prompts[0].reply->length = 0;
		}
	}
	return 0;
}

static ADS_STATUS ads_krb5_chg_password(const char *kdc_host,
					const char *principal,
					const char *oldpw,
					const char *newpw,
					int time_offset)
{
	ADS_STATUS aret;
	krb5_error_code ret;
	krb5_context context = NULL;
	krb5_principal princ;
	krb5_get_init_creds_opt *opts = NULL;
	krb5_creds creds;
	char *chpw_princ = NULL, *password;
	char *realm = NULL;
	int result_code;
	krb5_data result_code_string = { 0 };
	krb5_data result_string = { 0 };
	smb_krb5_addresses *addr = NULL;

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		return ADS_ERROR_KRB5(ret);
	}

	if ((ret = smb_krb5_parse_name(context, principal, &princ))) {
		krb5_free_context(context);
		DEBUG(1,("Failed to parse %s (%s)\n", principal, error_message(ret)));
		return ADS_ERROR_KRB5(ret);
	}

	ret = krb5_get_init_creds_opt_alloc(context, &opts);
	if (ret != 0) {
		krb5_free_context(context);
		DBG_WARNING("krb5_get_init_creds_opt_alloc failed: %s\n",
			    error_message(ret));
		return ADS_ERROR_KRB5(ret);
	}

	krb5_get_init_creds_opt_set_tkt_life(opts, 5 * 60);
	krb5_get_init_creds_opt_set_renew_life(opts, 0);
	krb5_get_init_creds_opt_set_forwardable(opts, 0);
	krb5_get_init_creds_opt_set_proxiable(opts, 0);
#ifdef SAMBA4_USES_HEIMDAL
	krb5_get_init_creds_opt_set_win2k(context, opts, true);
	krb5_get_init_creds_opt_set_canonicalize(context, opts, true);
#else /* MIT */
#if 0
	/*
	 * FIXME
	 *
	 * Due to an upstream MIT Kerberos bug, this feature is not
	 * not working. Affection versions (2019-10-09): <= 1.17
	 *
	 * Reproducer:
	 * kinit -C aDmInIsTrAtOr@ACME.COM -S kadmin/changepw@ACME.COM
	 *
	 * This is NOT a problem if the service is a krbtgt.
	 *
	 * https://bugzilla.samba.org/show_bug.cgi?id=14155
	 */
	krb5_get_init_creds_opt_set_canonicalize(opts, true);
#endif
#endif /* MIT */

	/* note that heimdal will fill in the local addresses if the addresses
	 * in the creds_init_opt are all empty and then later fail with invalid
	 * address, sending our local netbios krb5 address - just like windows
	 * - avoids this - gd */
	ret = smb_krb5_gen_netbios_krb5_address(&addr, lp_netbios_name());
	if (ret) {
		krb5_free_principal(context, princ);
		krb5_get_init_creds_opt_free(context, opts);
		krb5_free_context(context);
		return ADS_ERROR_KRB5(ret);
	}
	krb5_get_init_creds_opt_set_address_list(opts, addr->addrs);

	realm = smb_krb5_principal_get_realm(NULL, context, princ);

	/* We have to obtain an INITIAL changepw ticket for changing password */
	if (asprintf(&chpw_princ, "kadmin/changepw@%s", realm) == -1) {
		krb5_free_principal(context, princ);
		krb5_get_init_creds_opt_free(context, opts);
		smb_krb5_free_addresses(context, addr);
		krb5_free_context(context);
		TALLOC_FREE(realm);
		DEBUG(1, ("ads_krb5_chg_password: asprintf fail\n"));
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	TALLOC_FREE(realm);
	password = SMB_STRDUP(oldpw);
	ret = krb5_get_init_creds_password(context, &creds, princ, password,
					   kerb_prompter, NULL,
					   0, chpw_princ, opts);
	krb5_get_init_creds_opt_free(context, opts);
	smb_krb5_free_addresses(context, addr);
	SAFE_FREE(chpw_princ);
	SAFE_FREE(password);

	if (ret) {
		if (ret == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
			DEBUG(1,("Password incorrect while getting initial ticket"));
		} else {
			DEBUG(1,("krb5_get_init_creds_password failed (%s)\n", error_message(ret)));
		}
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		return ADS_ERROR_KRB5(ret);
	}

	ret = krb5_set_password(context,
				&creds,
				discard_const_p(char, newpw),
				NULL,
				&result_code,
				&result_code_string,
				&result_string);

	if (ret) {
		DEBUG(1, ("krb5_change_password failed (%s)\n", error_message(ret)));
		aret = ADS_ERROR_KRB5(ret);
		goto done;
	}

	if (result_code != KRB5_KPASSWD_SUCCESS) {
		ret = kpasswd_err_to_krb5_err(result_code);
		DEBUG(1, ("krb5_change_password failed (%s)\n", error_message(ret)));
		aret = ADS_ERROR_KRB5(ret);
		goto done;
	}

	aret = ADS_SUCCESS;

 done:
	smb_krb5_free_data_contents(context, &result_code_string);
	smb_krb5_free_data_contents(context, &result_string);
	krb5_free_principal(context, princ);
	krb5_free_context(context);

	return aret;
}

ADS_STATUS kerberos_set_password(const char *kpasswd_server,
				 const char *auth_principal,
				 const char *auth_password,
				 const char *target_principal,
				 const char *new_password, int time_offset)
{
	int ret;

	if ((ret = kerberos_kinit_password(auth_principal, auth_password, time_offset, NULL))) {
		DEBUG(1,("Failed kinit for principal %s (%s)\n", auth_principal, error_message(ret)));
		return ADS_ERROR_KRB5(ret);
	}

	if (!strcmp(auth_principal, target_principal)) {
		return ads_krb5_chg_password(kpasswd_server, target_principal,
					     auth_password, new_password,
					     time_offset);
	} else {
		return ads_krb5_set_password(kpasswd_server, target_principal,
					     new_password, time_offset);
	}
}

#endif
