/*
 *  Unix SMB/CIFS implementation.
 *  libnet Join Support
 *  Copyright (C) Gerald (Jerry) Carter 2006
 *  Copyright (C) Guenther Deschner 2007-2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "ads.h"
#include "librpc/gen_ndr/ndr_libnet_join.h"
#include "libnet/libnet_join.h"
#include "libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "rpc_client/init_samr.h"
#include "../librpc/gen_ndr/ndr_lsa_c.h"
#include "rpc_client/cli_lsarpc.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "rpc_client/cli_netlogon.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_reg.h"
#include "../libds/common/flags.h"
#include "secrets.h"
#include "rpc_client/init_lsa.h"
#include "rpc_client/cli_pipe.h"
#include "../libcli/security/security.h"
#include "passdb.h"
#include "libsmb/libsmb.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/param/loadparm.h"
#include "libcli/auth/netlogon_creds_cli.h"
#include "auth/credentials/credentials.h"
#include "krb5_env.h"

/****************************************************************
****************************************************************/

#define LIBNET_JOIN_DUMP_CTX(ctx, r, f) \
	do { \
		char *str = NULL; \
		str = NDR_PRINT_FUNCTION_STRING(ctx, libnet_JoinCtx, f, r); \
		DEBUG(1,("libnet_Join:\n%s", str)); \
		TALLOC_FREE(str); \
	} while (0)

#define LIBNET_JOIN_IN_DUMP_CTX(ctx, r) \
	LIBNET_JOIN_DUMP_CTX(ctx, r, NDR_IN | NDR_SET_VALUES)
#define LIBNET_JOIN_OUT_DUMP_CTX(ctx, r) \
	LIBNET_JOIN_DUMP_CTX(ctx, r, NDR_OUT)

#define LIBNET_UNJOIN_DUMP_CTX(ctx, r, f) \
	do { \
		char *str = NULL; \
		str = NDR_PRINT_FUNCTION_STRING(ctx, libnet_UnjoinCtx, f, r); \
		DEBUG(1,("libnet_Unjoin:\n%s", str)); \
		TALLOC_FREE(str); \
	} while (0)

#define LIBNET_UNJOIN_IN_DUMP_CTX(ctx, r) \
	LIBNET_UNJOIN_DUMP_CTX(ctx, r, NDR_IN | NDR_SET_VALUES)
#define LIBNET_UNJOIN_OUT_DUMP_CTX(ctx, r) \
	LIBNET_UNJOIN_DUMP_CTX(ctx, r, NDR_OUT)

/****************************************************************
****************************************************************/

static void libnet_join_set_error_string(TALLOC_CTX *mem_ctx,
					 struct libnet_JoinCtx *r,
					 const char *format, ...)
					 PRINTF_ATTRIBUTE(3,4);

static void libnet_join_set_error_string(TALLOC_CTX *mem_ctx,
					 struct libnet_JoinCtx *r,
					 const char *format, ...)
{
	va_list args;

	if (r->out.error_string) {
		return;
	}

	va_start(args, format);
	r->out.error_string = talloc_vasprintf(mem_ctx, format, args);
	va_end(args);
}

/****************************************************************
****************************************************************/

static void libnet_unjoin_set_error_string(TALLOC_CTX *mem_ctx,
					   struct libnet_UnjoinCtx *r,
					   const char *format, ...)
					   PRINTF_ATTRIBUTE(3,4);

static void libnet_unjoin_set_error_string(TALLOC_CTX *mem_ctx,
					   struct libnet_UnjoinCtx *r,
					   const char *format, ...)
{
	va_list args;

	if (r->out.error_string) {
		return;
	}

	va_start(args, format);
	r->out.error_string = talloc_vasprintf(mem_ctx, format, args);
	va_end(args);
}

#ifdef HAVE_ADS

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_connect_ads(const char *dns_domain_name,
				     const char *netbios_domain_name,
				     const char *dc_name,
				     const char *user_name,
				     const char *password,
				     const char *ccname,
				     ADS_STRUCT **ads)
{
	ADS_STATUS status;
	ADS_STRUCT *my_ads = NULL;
	char *cp;

	my_ads = ads_init(dns_domain_name,
			  netbios_domain_name,
			  dc_name);
	if (!my_ads) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	if (user_name) {
		SAFE_FREE(my_ads->auth.user_name);
		my_ads->auth.user_name = SMB_STRDUP(user_name);
		if ((cp = strchr_m(my_ads->auth.user_name, '@'))!=0) {
			*cp++ = '\0';
			SAFE_FREE(my_ads->auth.realm);
			my_ads->auth.realm = smb_xstrdup(cp);
			if (!strupper_m(my_ads->auth.realm)) {
				ads_destroy(&my_ads);
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}
		}
	}

	if (password) {
		SAFE_FREE(my_ads->auth.password);
		my_ads->auth.password = SMB_STRDUP(password);
	}

	if (ccname != NULL) {
		SAFE_FREE(my_ads->auth.ccache_name);
		my_ads->auth.ccache_name = SMB_STRDUP(ccname);
		setenv(KRB5_ENV_CCNAME, my_ads->auth.ccache_name, 1);
	}

	status = ads_connect_user_creds(my_ads);
	if (!ADS_ERR_OK(status)) {
		ads_destroy(&my_ads);
		return status;
	}

	*ads = my_ads;
	return ADS_SUCCESS;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_connect_ads(TALLOC_CTX *mem_ctx,
					  struct libnet_JoinCtx *r,
					  bool use_machine_creds)
{
	ADS_STATUS status;
	const char *username;
	const char *password;
	const char *ccname = NULL;

	if (use_machine_creds) {
		if (r->in.machine_name == NULL ||
		    r->in.machine_password == NULL) {
			return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}
		username = talloc_asprintf(mem_ctx, "%s$",
					   r->in.machine_name);
		if (username == NULL) {
			return ADS_ERROR(LDAP_NO_MEMORY);
		}
		password = r->in.machine_password;
		ccname = "MEMORY:libnet_join_machine_creds";
	} else {
		username = r->in.admin_account;
		password = r->in.admin_password;

		/*
		 * when r->in.use_kerberos is set to allow "net ads join -k" we
		 * may not override the provided credential cache - gd
		 */

		if (!r->in.use_kerberos) {
			ccname = "MEMORY:libnet_join_user_creds";
		}
	}

	status = libnet_connect_ads(r->out.dns_domain_name,
				    r->out.netbios_domain_name,
				    r->in.dc_name,
				    username,
				    password,
				    ccname,
				    &r->in.ads);
	if (!ADS_ERR_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to connect to AD: %s",
			ads_errstr(status));
		return status;
	}

	if (!r->out.netbios_domain_name) {
		r->out.netbios_domain_name = talloc_strdup(mem_ctx,
							   r->in.ads->server.workgroup);
		ADS_ERROR_HAVE_NO_MEMORY(r->out.netbios_domain_name);
	}

	if (!r->out.dns_domain_name) {
		r->out.dns_domain_name = talloc_strdup(mem_ctx,
						       r->in.ads->config.realm);
		ADS_ERROR_HAVE_NO_MEMORY(r->out.dns_domain_name);
	}

	r->out.domain_is_ad = true;

	return ADS_SUCCESS;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_connect_ads_user(TALLOC_CTX *mem_ctx,
					       struct libnet_JoinCtx *r)
{
	return libnet_join_connect_ads(mem_ctx, r, false);
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_connect_ads_machine(TALLOC_CTX *mem_ctx,
						  struct libnet_JoinCtx *r)
{
	return libnet_join_connect_ads(mem_ctx, r, true);
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_unjoin_connect_ads(TALLOC_CTX *mem_ctx,
					    struct libnet_UnjoinCtx *r)
{
	ADS_STATUS status;

	status = libnet_connect_ads(r->in.domain_name,
				    r->in.domain_name,
				    r->in.dc_name,
				    r->in.admin_account,
				    r->in.admin_password,
				    NULL,
				    &r->in.ads);
	if (!ADS_ERR_OK(status)) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"failed to connect to AD: %s",
			ads_errstr(status));
	}

	return status;
}

/****************************************************************
 join a domain using ADS (LDAP mods)
****************************************************************/

static ADS_STATUS libnet_join_precreate_machine_acct(TALLOC_CTX *mem_ctx,
						     struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	const char *attrs[] = { "dn", NULL };
	bool moved = false;

	status = ads_check_ou_dn(mem_ctx, r->in.ads, &r->in.account_ou);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	status = ads_search_dn(r->in.ads, &res, r->in.account_ou, attrs);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (ads_count_replies(r->in.ads, res) != 1) {
		ads_msgfree(r->in.ads, res);
		return ADS_ERROR_LDAP(LDAP_NO_SUCH_OBJECT);
	}

	ads_msgfree(r->in.ads, res);

	/* Attempt to create the machine account and bail if this fails.
	   Assume that the admin wants exactly what they requested */

	status = ads_create_machine_acct(r->in.ads,
					 r->in.machine_name,
					 r->in.account_ou,
					 r->in.desired_encryption_types);

	if (ADS_ERR_OK(status)) {
		DEBUG(1,("machine account creation created\n"));
		return status;
	} else  if ((status.error_type == ENUM_ADS_ERROR_LDAP) &&
		    (status.err.rc == LDAP_ALREADY_EXISTS)) {
		status = ADS_SUCCESS;
	}

	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("machine account creation failed\n"));
		return status;
	}

	status = ads_move_machine_acct(r->in.ads,
				       r->in.machine_name,
				       r->in.account_ou,
				       &moved);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("failure to locate/move pre-existing "
			"machine account\n"));
		return status;
	}

	DEBUG(1,("The machine account %s the specified OU.\n",
		moved ? "was moved into" : "already exists in"));

	return status;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_unjoin_remove_machine_acct(TALLOC_CTX *mem_ctx,
						    struct libnet_UnjoinCtx *r)
{
	ADS_STATUS status;

	if (!r->in.ads) {
		status = libnet_unjoin_connect_ads(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			libnet_unjoin_set_error_string(mem_ctx, r,
				"failed to connect to AD: %s",
				ads_errstr(status));
			return status;
		}
	}

	status = ads_leave_realm(r->in.ads, r->in.machine_name);
	if (!ADS_ERR_OK(status)) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"failed to leave realm: %s",
			ads_errstr(status));
		return status;
	}

	return ADS_SUCCESS;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_find_machine_acct(TALLOC_CTX *mem_ctx,
						struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	char *dn = NULL;

	if (!r->in.machine_name) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_find_machine_acct(r->in.ads,
				       &res,
				       r->in.machine_name);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (ads_count_replies(r->in.ads, res) != 1) {
		status = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	dn = ads_get_dn(r->in.ads, mem_ctx, res);
	if (!dn) {
		status = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	r->out.dn = talloc_strdup(mem_ctx, dn);
	if (!r->out.dn) {
		status = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	if (!ads_pull_uint32(r->in.ads, res, "msDS-SupportedEncryptionTypes",
			     &r->out.set_encryption_types)) {
		r->out.set_encryption_types = 0;
	}

 done:
	ads_msgfree(r->in.ads, res);
	TALLOC_FREE(dn);

	return status;
}

static ADS_STATUS libnet_join_get_machine_spns(TALLOC_CTX *mem_ctx,
					       struct libnet_JoinCtx *r,
					       char ***spn_array,
					       size_t *num_spns)
{
	ADS_STATUS status;

	if (r->in.machine_name == NULL) {
		return ADS_ERROR_SYSTEM(EINVAL);
	}

	status = ads_get_service_principal_names(mem_ctx,
						 r->in.ads,
						 r->in.machine_name,
						 spn_array,
						 num_spns);

	return status;
}

/****************************************************************
 Set a machines dNSHostName and servicePrincipalName attributes
****************************************************************/

static ADS_STATUS libnet_join_set_machine_spn(TALLOC_CTX *mem_ctx,
					      struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	ADS_MODLIST mods;
	fstring my_fqdn;
	const char **spn_array = NULL;
	size_t num_spns = 0;
	char *spn = NULL;
	bool ok;
	const char **netbios_aliases = NULL;

	/* Find our DN */

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	status = libnet_join_get_machine_spns(mem_ctx,
					      r,
					      discard_const_p(char **, &spn_array),
					      &num_spns);
	if (!ADS_ERR_OK(status)) {
		DEBUG(5, ("Retrieving the servicePrincipalNames failed.\n"));
	}

	/* Windows only creates HOST/shortname & HOST/fqdn. */

	spn = talloc_asprintf(mem_ctx, "HOST/%s", r->in.machine_name);
	if (!spn) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}
	if (!strupper_m(spn)) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	ok = ads_element_in_array(spn_array, num_spns, spn);
	if (!ok) {
		ok = add_string_to_array(spn_array, spn,
					 &spn_array, &num_spns);
		if (!ok) {
			return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		}
	}

	if (!name_to_fqdn(my_fqdn, r->in.machine_name)
	    || (strchr(my_fqdn, '.') == NULL)) {
		fstr_sprintf(my_fqdn, "%s.%s", r->in.machine_name,
			     r->out.dns_domain_name);
	}

	if (!strlower_m(my_fqdn)) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	if (!strequal(my_fqdn, r->in.machine_name)) {
		spn = talloc_asprintf(mem_ctx, "HOST/%s", my_fqdn);
		if (!spn) {
			return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		}

		ok = ads_element_in_array(spn_array, num_spns, spn);
		if (!ok) {
			ok = add_string_to_array(spn_array, spn,
						 &spn_array, &num_spns);
			if (!ok) {
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}
		}
	}

	netbios_aliases = lp_netbios_aliases();
	if (netbios_aliases != NULL) {
		for (; *netbios_aliases != NULL; netbios_aliases++) {
			/*
			 * Add HOST/NETBIOSNAME
			 */
			spn = talloc_asprintf(mem_ctx, "HOST/%s", *netbios_aliases);
			if (spn == NULL) {
				TALLOC_FREE(spn);
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}
			if (!strupper_m(spn)) {
				TALLOC_FREE(spn);
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}

			ok = ads_element_in_array(spn_array, num_spns, spn);
			if (ok) {
				TALLOC_FREE(spn);
				continue;
			}
			ok = add_string_to_array(spn_array, spn,
						 &spn_array, &num_spns);
			if (!ok) {
				TALLOC_FREE(spn);
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}
			TALLOC_FREE(spn);

			/*
			 * Add HOST/netbiosname.domainname
			 */
			if (r->out.dns_domain_name == NULL) {
				continue;
			}
			fstr_sprintf(my_fqdn, "%s.%s",
				     *netbios_aliases,
				     r->out.dns_domain_name);

			spn = talloc_asprintf(mem_ctx, "HOST/%s", my_fqdn);
			if (spn == NULL) {
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}

			ok = ads_element_in_array(spn_array, num_spns, spn);
			if (ok) {
				TALLOC_FREE(spn);
				continue;
			}
			ok = add_string_to_array(spn_array, spn,
						 &spn_array, &num_spns);
			if (!ok) {
				TALLOC_FREE(spn);
				return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
			}
			TALLOC_FREE(spn);
		}
	}

	/* make sure to NULL terminate the array */
	spn_array = talloc_realloc(mem_ctx, spn_array, const char *, num_spns + 1);
	if (spn_array == NULL) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}
	spn_array[num_spns] = NULL;

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	/* fields of primary importance */

	status = ads_mod_str(mem_ctx, &mods, "dNSHostName", my_fqdn);
	if (!ADS_ERR_OK(status)) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	status = ads_mod_strlist(mem_ctx, &mods, "servicePrincipalName",
				 spn_array);
	if (!ADS_ERR_OK(status)) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	return ads_gen_mod(r->in.ads, r->out.dn, mods);
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_set_machine_upn(TALLOC_CTX *mem_ctx,
					      struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	ADS_MODLIST mods;

	if (!r->in.create_upn) {
		return ADS_SUCCESS;
	}

	/* Find our DN */

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (!r->in.upn) {
		const char *realm = r->out.dns_domain_name;

		/* in case we are about to generate a keytab during the join
		 * make sure the default upn we create is usable with kinit -k.
		 * gd */

		if (USE_KERBEROS_KEYTAB) {
			realm = talloc_strdup_upper(mem_ctx,
						    r->out.dns_domain_name);
		}

		if (!realm) {
			return ADS_ERROR(LDAP_NO_MEMORY);
		}

		r->in.upn = talloc_asprintf(mem_ctx,
					    "host/%s@%s",
					    r->in.machine_name,
					    realm);
		if (!r->in.upn) {
			return ADS_ERROR(LDAP_NO_MEMORY);
		}
	}

	/* now do the mods */

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	/* fields of primary importance */

	status = ads_mod_str(mem_ctx, &mods, "userPrincipalName", r->in.upn);
	if (!ADS_ERR_OK(status)) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	return ads_gen_mod(r->in.ads, r->out.dn, mods);
}


/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_set_os_attributes(TALLOC_CTX *mem_ctx,
						struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	ADS_MODLIST mods;
	char *os_sp = NULL;

	if (!r->in.os_name || !r->in.os_version ) {
		return ADS_SUCCESS;
	}

	/* Find our DN */

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	/* now do the mods */

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	if (r->in.os_servicepack) {
		/*
		 * if blank string then leave os_sp equal to NULL to force
		 * attribute delete (LDAP_MOD_DELETE)
		 */
		if (!strequal(r->in.os_servicepack,"")) {
			os_sp = talloc_strdup(mem_ctx, r->in.os_servicepack);
		}
	} else {
		os_sp = talloc_asprintf(mem_ctx, "Samba %s",
					samba_version_string());
	}
	if (!os_sp && !strequal(r->in.os_servicepack,"")) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	/* fields of primary importance */

	status = ads_mod_str(mem_ctx, &mods, "operatingSystem",
			     r->in.os_name);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	status = ads_mod_str(mem_ctx, &mods, "operatingSystemVersion",
			     r->in.os_version);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	status = ads_mod_str(mem_ctx, &mods, "operatingSystemServicePack",
			     os_sp);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	return ads_gen_mod(r->in.ads, r->out.dn, mods);
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_set_etypes(TALLOC_CTX *mem_ctx,
					 struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	ADS_MODLIST mods;
	const char *etype_list_str;

	etype_list_str = talloc_asprintf(mem_ctx, "%d",
					 r->in.desired_encryption_types);
	if (!etype_list_str) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	/* Find our DN */

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (r->in.desired_encryption_types == r->out.set_encryption_types) {
		return ADS_SUCCESS;
	}

	/* now do the mods */

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_mod_str(mem_ctx, &mods, "msDS-SupportedEncryptionTypes",
			     etype_list_str);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	status = ads_gen_mod(r->in.ads, r->out.dn, mods);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	r->out.set_encryption_types = r->in.desired_encryption_types;

	return ADS_SUCCESS;
}

/****************************************************************
****************************************************************/

static bool libnet_join_create_keytab(TALLOC_CTX *mem_ctx,
				      struct libnet_JoinCtx *r)
{
	if (!USE_SYSTEM_KEYTAB) {
		return true;
	}

	if (ads_keytab_create_default(r->in.ads) != 0) {
		return false;
	}

	return true;
}

/****************************************************************
****************************************************************/

static bool libnet_join_derive_salting_principal(TALLOC_CTX *mem_ctx,
						 struct libnet_JoinCtx *r)
{
	uint32_t domain_func;
	ADS_STATUS status;
	const char *salt = NULL;
	char *std_salt = NULL;

	status = ads_domain_func_level(r->in.ads, &domain_func);
	if (!ADS_ERR_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to determine domain functional level: %s",
			ads_errstr(status));
		return false;
	}

	/* go ahead and setup the default salt */

	std_salt = kerberos_standard_des_salt();
	if (!std_salt) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to obtain standard DES salt");
		return false;
	}

	salt = talloc_strdup(mem_ctx, std_salt);
	if (!salt) {
		return false;
	}

	SAFE_FREE(std_salt);

	/* if it's a Windows functional domain, we have to look for the UPN */

	if (domain_func == DS_DOMAIN_FUNCTION_2000) {
		char *upn;

		upn = ads_get_upn(r->in.ads, mem_ctx,
				  r->in.machine_name);
		if (upn) {
			salt = talloc_strdup(mem_ctx, upn);
			if (!salt) {
				return false;
			}
		}
	}

	r->out.krb5_salt = salt;
	return true;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_post_processing_ads_modify(TALLOC_CTX *mem_ctx,
							 struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	bool need_etype_update = false;

	if (!r->in.ads) {
		status = libnet_join_connect_ads_user(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			return status;
		}
	}

	status = libnet_join_set_machine_spn(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"Failed to set machine spn: %s\n"
			"Do you have sufficient permissions to create machine "
			"accounts?",
			ads_errstr(status));
		return status;
	}

	status = libnet_join_set_os_attributes(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to set machine os attributes: %s",
			ads_errstr(status));
		return status;
	}

	status = libnet_join_set_machine_upn(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to set machine upn: %s",
			ads_errstr(status));
		return status;
	}

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (r->in.desired_encryption_types != r->out.set_encryption_types) {
		uint32_t func_level = 0;

		status = ads_domain_func_level(r->in.ads, &func_level);
		if (!ADS_ERR_OK(status)) {
			libnet_join_set_error_string(mem_ctx, r,
				"failed to query domain controller functional level: %s",
				ads_errstr(status));
			return status;
		}

		if (func_level >= DS_DOMAIN_FUNCTION_2008) {
			need_etype_update = true;
		}
	}

	if (need_etype_update) {
		/*
		 * We need to reconnect as machine account in order
		 * to update msDS-SupportedEncryptionTypes reliable
		 */

		if (r->in.ads->auth.ccache_name != NULL) {
			ads_kdestroy(r->in.ads->auth.ccache_name);
		}

		ads_destroy(&r->in.ads);

		status = libnet_join_connect_ads_machine(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			libnet_join_set_error_string(mem_ctx, r,
				"Failed to connect as machine account: %s",
				ads_errstr(status));
			return status;
		}

		status = libnet_join_set_etypes(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			libnet_join_set_error_string(mem_ctx, r,
				"failed to set machine kerberos encryption types: %s",
				ads_errstr(status));
			return status;
		}
	}

	if (!libnet_join_derive_salting_principal(mem_ctx, r)) {
		return ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	}

	return ADS_SUCCESS;
}

static ADS_STATUS libnet_join_post_processing_ads_sync(TALLOC_CTX *mem_ctx,
							struct libnet_JoinCtx *r)
{
	if (!libnet_join_create_keytab(mem_ctx, r)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to create kerberos keytab");
		return ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	}

	return ADS_SUCCESS;
}
#endif /* HAVE_ADS */

/****************************************************************
 Store the machine password and domain SID
****************************************************************/

static bool libnet_join_joindomain_store_secrets(TALLOC_CTX *mem_ctx,
						 struct libnet_JoinCtx *r)
{
	NTSTATUS status;

	status = secrets_store_JoinCtx(r);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("secrets_store_JoinCtx() failed %s\n",
			nt_errstr(status));
		return false;
	}

	return true;
}

/****************************************************************
 Connect dc's IPC$ share
****************************************************************/

static NTSTATUS libnet_join_connect_dc_ipc(const char *dc,
					   const char *user,
					   const char *domain,
					   const char *pass,
					   bool use_kerberos,
					   struct cli_state **cli)
{
	int flags = 0;

	if (use_kerberos) {
		flags |= CLI_FULL_CONNECTION_USE_KERBEROS;
	}

	if (use_kerberos && pass) {
		flags |= CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS;
	}

	return cli_full_connection(cli, NULL,
				   dc,
				   NULL, 0,
				   "IPC$", "IPC",
				   user,
				   domain,
				   pass,
				   flags,
				   SMB_SIGNING_IPC_DEFAULT);
}

/****************************************************************
 Lookup domain dc's info
****************************************************************/

static NTSTATUS libnet_join_lookup_dc_rpc(TALLOC_CTX *mem_ctx,
					  struct libnet_JoinCtx *r,
					  struct cli_state **cli)
{
	struct rpc_pipe_client *pipe_hnd = NULL;
	struct policy_handle lsa_pol;
	NTSTATUS status, result;
	union lsa_PolicyInformation *info = NULL;
	struct dcerpc_binding_handle *b;
	const char *account = r->in.admin_account;
	const char *domain = r->in.admin_domain;
	const char *password = r->in.admin_password;
	bool use_kerberos = r->in.use_kerberos;

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_UNSECURE) {
		account = "";
		domain = "";
		password = NULL;
		use_kerberos = false;
	}

	status = libnet_join_connect_dc_ipc(r->in.dc_name,
					    account,
					    domain,
					    password,
					    use_kerberos,
					    cli);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = cli_rpc_pipe_open_noauth(*cli, &ndr_table_lsarpc,
					  &pipe_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Error connecting to LSA pipe. Error was %s\n",
			nt_errstr(status)));
		goto done;
	}

	b = pipe_hnd->binding_handle;

	status = rpccli_lsa_open_policy(pipe_hnd, mem_ctx, true,
					SEC_FLAG_MAXIMUM_ALLOWED, &lsa_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dcerpc_lsa_QueryInfoPolicy2(b, mem_ctx,
					     &lsa_pol,
					     LSA_POLICY_INFO_DNS,
					     &info,
					     &result);
	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {
		r->out.domain_is_ad = true;
		r->out.netbios_domain_name = info->dns.name.string;
		r->out.dns_domain_name = info->dns.dns_domain.string;
		r->out.forest_name = info->dns.dns_forest.string;
		r->out.domain_guid = info->dns.domain_guid;
		r->out.domain_sid = dom_sid_dup(mem_ctx, info->dns.sid);
		NT_STATUS_HAVE_NO_MEMORY(r->out.domain_sid);
	}

	if (!NT_STATUS_IS_OK(status)) {
		status = dcerpc_lsa_QueryInfoPolicy(b, mem_ctx,
						    &lsa_pol,
						    LSA_POLICY_INFO_ACCOUNT_DOMAIN,
						    &info,
						    &result);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		if (!NT_STATUS_IS_OK(result)) {
			status = result;
			goto done;
		}

		r->out.netbios_domain_name = info->account_domain.name.string;
		r->out.domain_sid = dom_sid_dup(mem_ctx, info->account_domain.sid);
		NT_STATUS_HAVE_NO_MEMORY(r->out.domain_sid);
	}

	dcerpc_lsa_Close(b, mem_ctx, &lsa_pol, &result);
	TALLOC_FREE(pipe_hnd);

 done:
	return status;
}

/****************************************************************
 Do the domain join unsecure
****************************************************************/

static NTSTATUS libnet_join_joindomain_rpc_unsecure(TALLOC_CTX *mem_ctx,
						    struct libnet_JoinCtx *r,
						    struct cli_state *cli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *authenticate_pipe = NULL;
	struct rpc_pipe_client *passwordset_pipe = NULL;
	struct cli_credentials *cli_creds;
	struct netlogon_creds_cli_context *netlogon_creds = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	uint32_t netlogon_flags = 0;
	size_t len = 0;
	bool ok;
	DATA_BLOB new_trust_blob = data_blob_null;
	NTSTATUS status;

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_netlogon,
					  &authenticate_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (!r->in.machine_password) {
		int security = r->in.ads ? SEC_ADS : SEC_DOMAIN;

		r->in.machine_password = trust_pw_new_value(mem_ctx,
						r->in.secure_channel_type,
						security);
		if (r->in.machine_password == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	cli_creds = cli_credentials_init(talloc_tos());
	if (cli_creds == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_username(cli_creds, r->out.account_name,
				     CRED_SPECIFIED);
	cli_credentials_set_domain(cli_creds, r->in.domain_name,
				   CRED_SPECIFIED);
	cli_credentials_set_realm(cli_creds, "", CRED_SPECIFIED);
	cli_credentials_set_secure_channel_type(cli_creds,
						r->in.secure_channel_type);

	/* according to WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED */
	cli_credentials_set_password(cli_creds, r->in.admin_password,
				     CRED_SPECIFIED);

	status = rpccli_create_netlogon_creds_ctx(
		cli_creds, authenticate_pipe->desthost, r->in.msg_ctx,
		frame, &netlogon_creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_setup_netlogon_creds(
		cli, NCACN_NP, netlogon_creds, true /* force_reauth */,
		cli_creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(netlogon_creds, frame, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	netlogon_flags = creds->negotiate_flags;
	TALLOC_FREE(creds);

	if (netlogon_flags & NETLOGON_NEG_AUTHENTICATED_RPC) {
		status = cli_rpc_pipe_open_schannel_with_creds(cli,
							       &ndr_table_netlogon,
							       NCACN_NP,
							       netlogon_creds,
							       &passwordset_pipe);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	} else {
		passwordset_pipe = authenticate_pipe;
	}

	len = strlen(r->in.machine_password);
	ok = convert_string_talloc(frame, CH_UNIX, CH_UTF16,
				   r->in.machine_password, len,
				   (void **)&new_trust_blob.data,
				   &new_trust_blob.length);
	if (!ok) {
		status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_ServerPasswordSet(netlogon_creds,
						      passwordset_pipe->binding_handle,
						      &new_trust_blob,
						      NULL); /* new_version */
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/****************************************************************
 Do the domain join
****************************************************************/

static NTSTATUS libnet_join_joindomain_rpc(TALLOC_CTX *mem_ctx,
					   struct libnet_JoinCtx *r,
					   struct cli_state *cli)
{
	struct rpc_pipe_client *pipe_hnd = NULL;
	struct policy_handle sam_pol, domain_pol, user_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL, result;
	char *acct_name;
	struct lsa_String lsa_acct_name;
	uint32_t user_rid;
	uint32_t acct_flags = ACB_WSTRUST;
	struct samr_Ids user_rids;
	struct samr_Ids name_types;
	union samr_UserInfo user_info;
	struct dcerpc_binding_handle *b = NULL;
	unsigned int old_timeout = 0;

	DATA_BLOB session_key = data_blob_null;
	struct samr_CryptPassword crypt_pwd;
	struct samr_CryptPasswordEx crypt_pwd_ex;

	ZERO_STRUCT(sam_pol);
	ZERO_STRUCT(domain_pol);
	ZERO_STRUCT(user_pol);

	switch (r->in.secure_channel_type) {
	case SEC_CHAN_WKSTA:
		acct_flags = ACB_WSTRUST;
		break;
	case SEC_CHAN_BDC:
		acct_flags = ACB_SVRTRUST;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!r->in.machine_password) {
		int security = r->in.ads ? SEC_ADS : SEC_DOMAIN;

		r->in.machine_password = trust_pw_new_value(mem_ctx,
						r->in.secure_channel_type,
						security);
		NT_STATUS_HAVE_NO_MEMORY(r->in.machine_password);
	}

	/* Open the domain */

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_samr,
					  &pipe_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Error connecting to SAM pipe. Error was %s\n",
			nt_errstr(status)));
		goto done;
	}

	b = pipe_hnd->binding_handle;

	status = cli_get_session_key(mem_ctx, pipe_hnd, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Error getting session_key of SAM pipe. Error was %s\n",
			nt_errstr(status)));
		goto done;
	}

	status = dcerpc_samr_Connect2(b, mem_ctx,
				      pipe_hnd->desthost,
				      SAMR_ACCESS_ENUM_DOMAINS
				      | SAMR_ACCESS_LOOKUP_DOMAIN,
				      &sam_pol,
				      &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	status = dcerpc_samr_OpenDomain(b, mem_ctx,
					&sam_pol,
					SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1
					| SAMR_DOMAIN_ACCESS_CREATE_USER
					| SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					r->out.domain_sid,
					&domain_pol,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	/* Create domain user */

	acct_name = talloc_asprintf(mem_ctx, "%s$", r->in.machine_name);
	if (!strlower_m(acct_name)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	init_lsa_String(&lsa_acct_name, acct_name);

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE) {
		uint32_t access_desired =
			SEC_GENERIC_READ | SEC_GENERIC_WRITE | SEC_GENERIC_EXECUTE |
			SEC_STD_WRITE_DAC | SEC_STD_DELETE |
			SAMR_USER_ACCESS_SET_PASSWORD |
			SAMR_USER_ACCESS_GET_ATTRIBUTES |
			SAMR_USER_ACCESS_SET_ATTRIBUTES;
		uint32_t access_granted = 0;

		DEBUG(10,("Creating account with desired access mask: %d\n",
			access_desired));

		status = dcerpc_samr_CreateUser2(b, mem_ctx,
						 &domain_pol,
						 &lsa_acct_name,
						 acct_flags,
						 access_desired,
						 &user_pol,
						 &access_granted,
						 &user_rid,
						 &result);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		status = result;
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {

			DEBUG(10,("Creation of workstation account failed: %s\n",
				nt_errstr(status)));

			/* If NT_STATUS_ACCESS_DENIED then we have a valid
			   username/password combo but the user does not have
			   administrator access. */

			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
				libnet_join_set_error_string(mem_ctx, r,
					"User specified does not have "
					"administrator privileges");
			}

			goto done;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			if (!(r->in.join_flags &
			      WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED)) {
				goto done;
			}
		}

		/* We *must* do this.... don't ask... */

		if (NT_STATUS_IS_OK(status)) {
			dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);
		}
	}

	status = dcerpc_samr_LookupNames(b, mem_ctx,
					 &domain_pol,
					 1,
					 &lsa_acct_name,
					 &user_rids,
					 &name_types,
					 &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}
	if (user_rids.count != 1) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}
	if (name_types.count != 1) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}

	if (name_types.ids[0] != SID_NAME_USER) {
		DEBUG(0,("%s is not a user account (type=%d)\n",
			acct_name, name_types.ids[0]));
		status = NT_STATUS_INVALID_WORKSTATION;
		goto done;
	}

	user_rid = user_rids.ids[0];

	/* Open handle on user */

	status = dcerpc_samr_OpenUser(b, mem_ctx,
				      &domain_pol,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_pol,
				      &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	/* Fill in the additional account flags now */

	acct_flags |= ACB_PWNOEXP;

	/* Set account flags on machine account */
	ZERO_STRUCT(user_info.info16);
	user_info.info16.acct_flags = acct_flags;

	status = dcerpc_samr_SetUserInfo2(b, mem_ctx,
					  &user_pol,
					  UserControlInformation,
					  &user_info,
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_samr_DeleteUser(b, mem_ctx,
				       &user_pol,
				       &result);

		libnet_join_set_error_string(mem_ctx, r,
			"Failed to set account flags for machine account (%s)\n",
			nt_errstr(status));
		goto done;
	}

	if (!NT_STATUS_IS_OK(result)) {
		status = result;

		dcerpc_samr_DeleteUser(b, mem_ctx,
				       &user_pol,
				       &result);

		libnet_join_set_error_string(mem_ctx, r,
			"Failed to set account flags for machine account (%s)\n",
			nt_errstr(status));
		goto done;
	}

	/* Set password on machine account - first try level 26 */

	/*
	 * increase the timeout as password filter modules on the DC
	 * might delay the operation for a significant amount of time
	 */
	old_timeout = rpccli_set_timeout(pipe_hnd, 600000);

	init_samr_CryptPasswordEx(r->in.machine_password,
				  &session_key,
				  &crypt_pwd_ex);

	user_info.info26.password = crypt_pwd_ex;
	user_info.info26.password_expired = PASS_DONT_CHANGE_AT_NEXT_LOGON;

	status = dcerpc_samr_SetUserInfo2(b, mem_ctx,
					  &user_pol,
					  UserInternal5InformationNew,
					  &user_info,
					  &result);

	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_ENUM_VALUE_OUT_OF_RANGE)) {

		/* retry with level 24 */

		init_samr_CryptPassword(r->in.machine_password,
					&session_key,
					&crypt_pwd);

		user_info.info24.password = crypt_pwd;
		user_info.info24.password_expired = PASS_DONT_CHANGE_AT_NEXT_LOGON;

		status = dcerpc_samr_SetUserInfo2(b, mem_ctx,
						  &user_pol,
						  UserInternal5Information,
						  &user_info,
						  &result);
	}

	old_timeout = rpccli_set_timeout(pipe_hnd, old_timeout);

	if (!NT_STATUS_IS_OK(status)) {

		dcerpc_samr_DeleteUser(b, mem_ctx,
				       &user_pol,
				       &result);

		libnet_join_set_error_string(mem_ctx, r,
			"Failed to set password for machine account (%s)\n",
			nt_errstr(status));
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;

		dcerpc_samr_DeleteUser(b, mem_ctx,
				       &user_pol,
				       &result);

		libnet_join_set_error_string(mem_ctx, r,
			"Failed to set password for machine account (%s)\n",
			nt_errstr(status));
		goto done;
	}

	status = NT_STATUS_OK;

 done:
	if (!pipe_hnd) {
		return status;
	}

	data_blob_clear_free(&session_key);

	if (is_valid_policy_hnd(&sam_pol)) {
		dcerpc_samr_Close(b, mem_ctx, &sam_pol, &result);
	}
	if (is_valid_policy_hnd(&domain_pol)) {
		dcerpc_samr_Close(b, mem_ctx, &domain_pol, &result);
	}
	if (is_valid_policy_hnd(&user_pol)) {
		dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);
	}
	TALLOC_FREE(pipe_hnd);

	return status;
}

/****************************************************************
****************************************************************/

NTSTATUS libnet_join_ok(struct messaging_context *msg_ctx,
			const char *netbios_domain_name,
			const char *dc_name,
			const bool use_kerberos)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct cli_credentials *cli_creds = NULL;
	struct netlogon_creds_cli_context *netlogon_creds = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	uint32_t netlogon_flags = 0;
	NTSTATUS status;
	int flags = 0;

	if (!dc_name) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!secrets_init()) {
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	status = pdb_get_trust_credentials(netbios_domain_name, NULL,
					   frame, &cli_creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/* we don't want any old password */
	cli_credentials_set_old_password(cli_creds, NULL, CRED_SPECIFIED);

	if (use_kerberos) {
		cli_credentials_set_kerberos_state(cli_creds,
				CRED_MUST_USE_KERBEROS);
	}

	status = cli_full_connection_creds(&cli, NULL,
					   dc_name,
					   NULL, 0,
					   "IPC$", "IPC",
					   cli_creds,
					   flags,
					   SMB_SIGNING_IPC_DEFAULT);

	if (!NT_STATUS_IS_OK(status)) {
		status = cli_full_connection(&cli, NULL,
					     dc_name,
					     NULL, 0,
					     "IPC$", "IPC",
					     "",
					     NULL,
					     "",
					     0,
					     SMB_SIGNING_IPC_DEFAULT);
	}

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_create_netlogon_creds_ctx(cli_creds,
						  dc_name,
						  msg_ctx,
						  frame,
						  &netlogon_creds);
	if (!NT_STATUS_IS_OK(status)) {
		cli_shutdown(cli);
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_setup_netlogon_creds(cli, NCACN_NP,
					     netlogon_creds,
					     true, /* force_reauth */
					     cli_creds);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("connect_to_domain_password_server: "
			 "unable to open the domain client session to "
			 "machine %s. Flags[0x%08X] Error was : %s.\n",
			 dc_name, (unsigned)netlogon_flags,
			 nt_errstr(status)));
		cli_shutdown(cli);
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(netlogon_creds,
					talloc_tos(),
					&creds);
	if (!NT_STATUS_IS_OK(status)) {
		cli_shutdown(cli);
		TALLOC_FREE(frame);
		return status;
	}
	netlogon_flags = creds->negotiate_flags;
	TALLOC_FREE(creds);

	if (!(netlogon_flags & NETLOGON_NEG_AUTHENTICATED_RPC)) {
		cli_shutdown(cli);
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	status = cli_rpc_pipe_open_schannel_with_creds(
		cli, &ndr_table_netlogon, NCACN_NP,
		netlogon_creds, &netlogon_pipe);

	TALLOC_FREE(netlogon_pipe);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("libnet_join_ok: failed to open schannel session "
			"on netlogon pipe to server %s for domain %s. "
			"Error was %s\n",
			smbXcli_conn_remote_name(cli->conn),
			netbios_domain_name, nt_errstr(status)));
		cli_shutdown(cli);
		TALLOC_FREE(frame);
		return status;
	}

	cli_shutdown(cli);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static WERROR libnet_join_post_verify(TALLOC_CTX *mem_ctx,
				      struct libnet_JoinCtx *r)
{
	NTSTATUS status;

	status = libnet_join_ok(r->in.msg_ctx,
				r->out.netbios_domain_name,
				r->in.dc_name,
				r->in.use_kerberos);
	if (!NT_STATUS_IS_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to verify domain membership after joining: %s",
			get_friendly_nt_error_msg(status));
		return WERR_NERR_SETUPNOTJOINED;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static bool libnet_join_unjoindomain_remove_secrets(TALLOC_CTX *mem_ctx,
						    struct libnet_UnjoinCtx *r)
{
	/*
	 * TODO: use values from 'struct libnet_UnjoinCtx' ?
	 */
	return secrets_delete_machine_password_ex(lp_workgroup(), lp_realm());
}

/****************************************************************
****************************************************************/

static NTSTATUS libnet_join_unjoindomain_rpc(TALLOC_CTX *mem_ctx,
					     struct libnet_UnjoinCtx *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;
	struct policy_handle sam_pol, domain_pol, user_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL, result;
	char *acct_name;
	uint32_t user_rid;
	struct lsa_String lsa_acct_name;
	struct samr_Ids user_rids;
	struct samr_Ids name_types;
	union samr_UserInfo *info = NULL;
	struct dcerpc_binding_handle *b = NULL;

	ZERO_STRUCT(sam_pol);
	ZERO_STRUCT(domain_pol);
	ZERO_STRUCT(user_pol);

	status = libnet_join_connect_dc_ipc(r->in.dc_name,
					    r->in.admin_account,
					    r->in.admin_domain,
					    r->in.admin_password,
					    r->in.use_kerberos,
					    &cli);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* Open the domain */

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_samr,
					  &pipe_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Error connecting to SAM pipe. Error was %s\n",
			nt_errstr(status)));
		goto done;
	}

	b = pipe_hnd->binding_handle;

	status = dcerpc_samr_Connect2(b, mem_ctx,
				      pipe_hnd->desthost,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      &sam_pol,
				      &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	status = dcerpc_samr_OpenDomain(b, mem_ctx,
					&sam_pol,
					SEC_FLAG_MAXIMUM_ALLOWED,
					r->in.domain_sid,
					&domain_pol,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	/* Create domain user */

	acct_name = talloc_asprintf(mem_ctx, "%s$", r->in.machine_name);
	if (!strlower_m(acct_name)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	init_lsa_String(&lsa_acct_name, acct_name);

	status = dcerpc_samr_LookupNames(b, mem_ctx,
					 &domain_pol,
					 1,
					 &lsa_acct_name,
					 &user_rids,
					 &name_types,
					 &result);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}
	if (user_rids.count != 1) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}
	if (name_types.count != 1) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}

	if (name_types.ids[0] != SID_NAME_USER) {
		DEBUG(0, ("%s is not a user account (type=%d)\n", acct_name,
			name_types.ids[0]));
		status = NT_STATUS_INVALID_WORKSTATION;
		goto done;
	}

	user_rid = user_rids.ids[0];

	/* Open handle on user */

	status = dcerpc_samr_OpenUser(b, mem_ctx,
				      &domain_pol,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_pol,
				      &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto done;
	}

	/* Get user info */

	status = dcerpc_samr_QueryUserInfo(b, mem_ctx,
					   &user_pol,
					   16,
					   &info,
					   &result);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);
		goto done;
	}

	/* now disable and setuser info */

	info->info16.acct_flags |= ACB_DISABLED;

	status = dcerpc_samr_SetUserInfo(b, mem_ctx,
					 &user_pol,
					 16,
					 info,
					 &result);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);
		goto done;
	}
	status = result;
	dcerpc_samr_Close(b, mem_ctx, &user_pol, &result);

done:
	if (pipe_hnd && b) {
		if (is_valid_policy_hnd(&domain_pol)) {
			dcerpc_samr_Close(b, mem_ctx, &domain_pol, &result);
		}
		if (is_valid_policy_hnd(&sam_pol)) {
			dcerpc_samr_Close(b, mem_ctx, &sam_pol, &result);
		}
		TALLOC_FREE(pipe_hnd);
	}

	if (cli) {
		cli_shutdown(cli);
	}

	return status;
}

/****************************************************************
****************************************************************/

static WERROR do_join_modify_vals_config(struct libnet_JoinCtx *r)
{
	WERROR werr = WERR_OK;
	sbcErr err;
	struct smbconf_ctx *ctx;

	err = smbconf_init_reg(r, &ctx, NULL);
	if (!SBC_ERROR_IS_OK(err)) {
		werr = WERR_SERVICE_DOES_NOT_EXIST;
		goto done;
	}

	if (!(r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE)) {

		err = smbconf_set_global_parameter(ctx, "security", "user");
		if (!SBC_ERROR_IS_OK(err)) {
			werr = WERR_SERVICE_DOES_NOT_EXIST;
			goto done;
		}

		err = smbconf_set_global_parameter(ctx, "workgroup",
						   r->in.domain_name);
		if (!SBC_ERROR_IS_OK(err)) {
			werr = WERR_SERVICE_DOES_NOT_EXIST;
			goto done;
		}

		smbconf_delete_global_parameter(ctx, "realm");
		goto done;
	}

	err = smbconf_set_global_parameter(ctx, "security", "domain");
	if (!SBC_ERROR_IS_OK(err)) {
		werr = WERR_SERVICE_DOES_NOT_EXIST;
		goto done;
	}

	err = smbconf_set_global_parameter(ctx, "workgroup",
					   r->out.netbios_domain_name);
	if (!SBC_ERROR_IS_OK(err)) {
		werr = WERR_SERVICE_DOES_NOT_EXIST;
		goto done;
	}

	if (r->out.domain_is_ad) {
		err = smbconf_set_global_parameter(ctx, "security", "ads");
		if (!SBC_ERROR_IS_OK(err)) {
			werr = WERR_SERVICE_DOES_NOT_EXIST;
			goto done;
		}

		err = smbconf_set_global_parameter(ctx, "realm",
						   r->out.dns_domain_name);
		if (!SBC_ERROR_IS_OK(err)) {
			werr = WERR_SERVICE_DOES_NOT_EXIST;
			goto done;
		}
	}

 done:
	smbconf_shutdown(ctx);
	return werr;
}

/****************************************************************
****************************************************************/

static WERROR do_unjoin_modify_vals_config(struct libnet_UnjoinCtx *r)
{
	WERROR werr = WERR_OK;
	sbcErr err;
	struct smbconf_ctx *ctx;

	err = smbconf_init_reg(r, &ctx, NULL);
	if (!SBC_ERROR_IS_OK(err)) {
		werr = WERR_SERVICE_DOES_NOT_EXIST;
		goto done;
	}

	if (r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {

		err = smbconf_set_global_parameter(ctx, "security", "user");
		if (!SBC_ERROR_IS_OK(err)) {
			werr = WERR_SERVICE_DOES_NOT_EXIST;
			goto done;
		}

		err = smbconf_delete_global_parameter(ctx, "workgroup");
		if (!SBC_ERROR_IS_OK(err)) {
			werr = WERR_SERVICE_DOES_NOT_EXIST;
			goto done;
		}

		smbconf_delete_global_parameter(ctx, "realm");
	}

 done:
	smbconf_shutdown(ctx);
	return werr;
}

/****************************************************************
****************************************************************/

static WERROR do_JoinConfig(struct libnet_JoinCtx *r)
{
	WERROR werr;

	if (!W_ERROR_IS_OK(r->out.result)) {
		return r->out.result;
	}

	if (!r->in.modify_config) {
		return WERR_OK;
	}

	werr = do_join_modify_vals_config(r);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	lp_load_global(get_dyn_CONFIGFILE());

	r->out.modified_config = true;
	r->out.result = werr;

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnet_unjoin_config(struct libnet_UnjoinCtx *r)
{
	WERROR werr;

	if (!W_ERROR_IS_OK(r->out.result)) {
		return r->out.result;
	}

	if (!r->in.modify_config) {
		return WERR_OK;
	}

	werr = do_unjoin_modify_vals_config(r);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	lp_load_global(get_dyn_CONFIGFILE());

	r->out.modified_config = true;
	r->out.result = werr;

	return werr;
}

/****************************************************************
****************************************************************/

static bool libnet_parse_domain_dc(TALLOC_CTX *mem_ctx,
				   const char *domain_str,
				   const char **domain_p,
				   const char **dc_p)
{
	char *domain = NULL;
	char *dc = NULL;
	const char *p = NULL;

	if (!domain_str || !domain_p || !dc_p) {
		return false;
	}

	p = strchr_m(domain_str, '\\');

	if (p != NULL) {
		domain = talloc_strndup(mem_ctx, domain_str,
					 PTR_DIFF(p, domain_str));
		dc = talloc_strdup(mem_ctx, p+1);
		if (!dc) {
			return false;
		}
	} else {
		domain = talloc_strdup(mem_ctx, domain_str);
		dc = NULL;
	}
	if (!domain) {
		return false;
	}

	*domain_p = domain;

	if (!*dc_p && dc) {
		*dc_p = dc;
	}

	return true;
}

/****************************************************************
****************************************************************/

static WERROR libnet_join_pre_processing(TALLOC_CTX *mem_ctx,
					 struct libnet_JoinCtx *r)
{
	if (!r->in.domain_name) {
		libnet_join_set_error_string(mem_ctx, r,
			"No domain name defined");
		return WERR_INVALID_PARAMETER;
	}

	if (strlen(r->in.machine_name) > 15) {
		libnet_join_set_error_string(mem_ctx, r,
			"Our netbios name can be at most 15 chars long, "
                         "\"%s\" is %u chars long\n",
                         r->in.machine_name,
			 (unsigned int)strlen(r->in.machine_name));
		return WERR_INVALID_PARAMETER;
        }

	r->out.account_name = talloc_asprintf(mem_ctx, "%s$",
				       r->in.machine_name);
	if (r->out.account_name == NULL) {
		libnet_join_set_error_string(mem_ctx, r,
			"Unable to construct r->out.account_name");
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (!libnet_parse_domain_dc(mem_ctx, r->in.domain_name,
				    &r->in.domain_name,
				    &r->in.dc_name)) {
		libnet_join_set_error_string(mem_ctx, r,
			"Failed to parse domain name");
		return WERR_INVALID_PARAMETER;
	}

	if (!r->in.admin_domain) {
		char *admin_domain = NULL;
		char *admin_account = NULL;
		bool ok;

		ok = split_domain_user(mem_ctx,
				       r->in.admin_account,
				       &admin_domain,
				       &admin_account);
		if (!ok) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		if (admin_domain != NULL) {
			r->in.admin_domain = admin_domain;
		} else {
			r->in.admin_domain = r->in.domain_name;
		}
		r->in.admin_account = admin_account;
	}

	if (!secrets_init()) {
		libnet_join_set_error_string(mem_ctx, r,
			"Unable to open secrets database");
		return WERR_CAN_NOT_COMPLETE;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static void libnet_join_add_dom_rids_to_builtins(struct dom_sid *domain_sid)
{
	NTSTATUS status;

	/* Try adding dom admins to builtin\admins. Only log failures. */
	status = create_builtin_administrators(domain_sid);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PROTOCOL_UNREACHABLE)) {
		DEBUG(10,("Unable to auto-add domain administrators to "
			  "BUILTIN\\Administrators during join because "
			  "winbindd must be running.\n"));
	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("Failed to auto-add domain administrators to "
			  "BUILTIN\\Administrators during join: %s\n",
			  nt_errstr(status)));
	}

	/* Try adding dom users to builtin\users. Only log failures. */
	status = create_builtin_users(domain_sid);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PROTOCOL_UNREACHABLE)) {
		DEBUG(10,("Unable to auto-add domain users to BUILTIN\\users "
			  "during join because winbindd must be running.\n"));
	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("Failed to auto-add domain administrators to "
			  "BUILTIN\\Administrators during join: %s\n",
			  nt_errstr(status)));
	}
}

/****************************************************************
****************************************************************/

static WERROR libnet_join_post_processing(TALLOC_CTX *mem_ctx,
					  struct libnet_JoinCtx *r)
{
	WERROR werr;

	if (!W_ERROR_IS_OK(r->out.result)) {
		return r->out.result;
	}

	if (!(r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE)) {
		werr = do_JoinConfig(r);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		return WERR_OK;
	}

#ifdef HAVE_ADS
	if (r->out.domain_is_ad &&
	    !(r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_UNSECURE)) {
		ADS_STATUS ads_status;

		ads_status  = libnet_join_post_processing_ads_modify(mem_ctx, r);
		if (!ADS_ERR_OK(ads_status)) {
			return WERR_GEN_FAILURE;
		}
	}
#endif /* HAVE_ADS */

	saf_join_store(r->out.netbios_domain_name, r->in.dc_name);
	if (r->out.dns_domain_name) {
		saf_join_store(r->out.dns_domain_name, r->in.dc_name);
	}

	if (!libnet_join_joindomain_store_secrets(mem_ctx, r)) {
		return WERR_NERR_SETUPNOTJOINED;
	}

	werr = do_JoinConfig(r);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

#ifdef HAVE_ADS
	if (r->out.domain_is_ad &&
	    !(r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_UNSECURE)) {
		ADS_STATUS ads_status;

		ads_status  = libnet_join_post_processing_ads_sync(mem_ctx, r);
		if (!ADS_ERR_OK(ads_status)) {
			return WERR_GEN_FAILURE;
		}
	}
#endif /* HAVE_ADS */

	libnet_join_add_dom_rids_to_builtins(r->out.domain_sid);

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static int libnet_destroy_JoinCtx(struct libnet_JoinCtx *r)
{
	if (r->in.ads) {
		ads_destroy(&r->in.ads);
	}

	return 0;
}

/****************************************************************
****************************************************************/

static int libnet_destroy_UnjoinCtx(struct libnet_UnjoinCtx *r)
{
	if (r->in.ads) {
		ads_destroy(&r->in.ads);
	}

	return 0;
}

/****************************************************************
****************************************************************/

WERROR libnet_init_JoinCtx(TALLOC_CTX *mem_ctx,
			   struct libnet_JoinCtx **r)
{
	struct libnet_JoinCtx *ctx;

	ctx = talloc_zero(mem_ctx, struct libnet_JoinCtx);
	if (!ctx) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	talloc_set_destructor(ctx, libnet_destroy_JoinCtx);

	ctx->in.machine_name = talloc_strdup(mem_ctx, lp_netbios_name());
	W_ERROR_HAVE_NO_MEMORY(ctx->in.machine_name);

	ctx->in.secure_channel_type = SEC_CHAN_WKSTA;

	ctx->in.desired_encryption_types = ENC_CRC32 |
					   ENC_RSA_MD5 |
					   ENC_RC4_HMAC_MD5;
#ifdef HAVE_ENCTYPE_AES128_CTS_HMAC_SHA1_96
	ctx->in.desired_encryption_types |= ENC_HMAC_SHA1_96_AES128;
#endif
#ifdef HAVE_ENCTYPE_AES256_CTS_HMAC_SHA1_96
	ctx->in.desired_encryption_types |= ENC_HMAC_SHA1_96_AES256;
#endif

	*r = ctx;

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR libnet_init_UnjoinCtx(TALLOC_CTX *mem_ctx,
			     struct libnet_UnjoinCtx **r)
{
	struct libnet_UnjoinCtx *ctx;

	ctx = talloc_zero(mem_ctx, struct libnet_UnjoinCtx);
	if (!ctx) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	talloc_set_destructor(ctx, libnet_destroy_UnjoinCtx);

	ctx->in.machine_name = talloc_strdup(mem_ctx, lp_netbios_name());
	W_ERROR_HAVE_NO_MEMORY(ctx->in.machine_name);

	*r = ctx;

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR libnet_join_check_config(TALLOC_CTX *mem_ctx,
				       struct libnet_JoinCtx *r)
{
	bool valid_security = false;
	bool valid_workgroup = false;
	bool valid_realm = false;
	bool ignored_realm = false;

	/* check if configuration is already set correctly */

	valid_workgroup = strequal(lp_workgroup(), r->out.netbios_domain_name);

	switch (r->out.domain_is_ad) {
		case false:
			valid_security = (lp_security() == SEC_DOMAIN)
				|| (lp_server_role() == ROLE_DOMAIN_PDC)
				|| (lp_server_role() == ROLE_DOMAIN_BDC);
			if (valid_workgroup && valid_security) {
				/* nothing to be done */
				return WERR_OK;
			}
			break;
		case true:
			valid_realm = strequal(lp_realm(), r->out.dns_domain_name);
			switch (lp_security()) {
			case SEC_DOMAIN:
				if (!valid_realm && lp_winbind_rpc_only()) {
					valid_realm = true;
					ignored_realm = true;
				}

				FALL_THROUGH;
			case SEC_ADS:
				valid_security = true;
			}

			if (valid_workgroup && valid_realm && valid_security) {
				if (ignored_realm && !r->in.modify_config)
				{
					libnet_join_set_error_string(mem_ctx, r,
						"Warning: ignoring realm when "
						"joining AD domain with "
						"'security=domain' and "
						"'winbind rpc only = yes'. "
						"(realm set to '%s', "
						"should be '%s').", lp_realm(),
						r->out.dns_domain_name);
				}
				/* nothing to be done */
				return WERR_OK;
			}
			break;
	}

	/* check if we are supposed to manipulate configuration */

	if (!r->in.modify_config) {

		char *wrong_conf = talloc_strdup(mem_ctx, "");

		if (!valid_workgroup) {
			wrong_conf = talloc_asprintf_append(wrong_conf,
				"\"workgroup\" set to '%s', should be '%s'",
				lp_workgroup(), r->out.netbios_domain_name);
			W_ERROR_HAVE_NO_MEMORY(wrong_conf);
		}

		if (!valid_realm) {
			wrong_conf = talloc_asprintf_append(wrong_conf,
				"\"realm\" set to '%s', should be '%s'",
				lp_realm(), r->out.dns_domain_name);
			W_ERROR_HAVE_NO_MEMORY(wrong_conf);
		}

		if (!valid_security) {
			const char *sec = NULL;
			switch (lp_security()) {
			case SEC_USER:  sec = "user"; break;
			case SEC_DOMAIN: sec = "domain"; break;
			case SEC_ADS: sec = "ads"; break;
			}
			wrong_conf = talloc_asprintf_append(wrong_conf,
				"\"security\" set to '%s', should be %s",
				sec, r->out.domain_is_ad ?
				"either 'domain' or 'ads'" : "'domain'");
			W_ERROR_HAVE_NO_MEMORY(wrong_conf);
		}

		libnet_join_set_error_string(mem_ctx, r,
			"Invalid configuration (%s) and configuration modification "
			"was not requested", wrong_conf);
		return WERR_CAN_NOT_COMPLETE;
	}

	/* check if we are able to manipulate configuration */

	if (!lp_config_backend_is_registry()) {
		libnet_join_set_error_string(mem_ctx, r,
			"Configuration manipulation requested but not "
			"supported by backend");
		return WERR_NOT_SUPPORTED;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR libnet_DomainJoin(TALLOC_CTX *mem_ctx,
				struct libnet_JoinCtx *r)
{
	NTSTATUS status;
	WERROR werr;
	struct cli_state *cli = NULL;
#ifdef HAVE_ADS
	ADS_STATUS ads_status;
#endif /* HAVE_ADS */
	const char *pre_connect_realm = NULL;
	const char *numeric_dcip = NULL;
	const char *sitename = NULL;

	/* Before contacting a DC, we can securely know
	 * the realm only if the user specifies it.
	 */
	if (r->in.use_kerberos &&
	    r->in.domain_name_type == JoinDomNameTypeDNS) {
		pre_connect_realm = r->in.domain_name;
	}

	if (!r->in.dc_name) {
		struct netr_DsRGetDCNameInfo *info;
		const char *dc;
		uint32_t name_type_flags = 0;
		if (r->in.domain_name_type == JoinDomNameTypeDNS) {
			name_type_flags = DS_IS_DNS_NAME;
		} else if (r->in.domain_name_type == JoinDomNameTypeNBT) {
			name_type_flags = DS_IS_FLAT_NAME;
		}
		status = dsgetdcname(mem_ctx,
				     r->in.msg_ctx,
				     r->in.domain_name,
				     NULL,
				     NULL,
				     DS_FORCE_REDISCOVERY |
				     DS_DIRECTORY_SERVICE_REQUIRED |
				     DS_WRITABLE_REQUIRED |
				     DS_RETURN_DNS_NAME |
				     name_type_flags,
				     &info);
		if (!NT_STATUS_IS_OK(status)) {
			libnet_join_set_error_string(mem_ctx, r,
				"failed to find DC for domain %s - %s",
				r->in.domain_name,
				get_friendly_nt_error_msg(status));
			return WERR_NERR_DCNOTFOUND;
		}

		dc = strip_hostname(info->dc_unc);
		r->in.dc_name = talloc_strdup(mem_ctx, dc);
		W_ERROR_HAVE_NO_MEMORY(r->in.dc_name);

		if (info->dc_address == NULL || info->dc_address[0] != '\\' ||
		    info->dc_address[1] != '\\') {
			DBG_ERR("ill-formed DC address '%s'\n",
				info->dc_address);
			return WERR_NERR_DCNOTFOUND;
		}

		numeric_dcip = info->dc_address + 2;
		sitename = info->dc_site_name;
		/* info goes out of scope but the memory stays
		   allocated on the talloc context */
	}

	if (pre_connect_realm != NULL) {
		struct sockaddr_storage ss = {0};

		if (numeric_dcip != NULL) {
			if (!interpret_string_addr(&ss, numeric_dcip,
						   AI_NUMERICHOST)) {
				DBG_ERR(
				    "cannot parse IP address '%s' of DC '%s'\n",
				    numeric_dcip, r->in.dc_name);
				return WERR_NERR_DCNOTFOUND;
			}
		} else {
			if (!interpret_string_addr(&ss, r->in.dc_name, 0)) {
				DBG_WARNING(
				    "cannot resolve IP address of DC '%s'\n",
				    r->in.dc_name);
				return WERR_NERR_DCNOTFOUND;
			}
		}

		/* The domain parameter is only used as modifier
		 * to krb5.conf file name. .JOIN is is not a valid
		 * NetBIOS name so it cannot clash with another domain
		 * -- Uri.
		 */
		create_local_private_krb5_conf_for_domain(
		    pre_connect_realm, ".JOIN", sitename, &ss);
	}

	status = libnet_join_lookup_dc_rpc(mem_ctx, r, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to lookup DC info for domain '%s' over rpc: %s",
			r->in.domain_name, get_friendly_nt_error_msg(status));
		return ntstatus_to_werror(status);
	}

	werr = libnet_join_check_config(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

#ifdef HAVE_ADS

	if (r->out.domain_is_ad) {
		create_local_private_krb5_conf_for_domain(
			r->out.dns_domain_name, r->out.netbios_domain_name,
			sitename, smbXcli_conn_remote_sockaddr(cli->conn));
	}

	if (r->out.domain_is_ad &&
	    !(r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_UNSECURE)) {

		const char *initial_account_ou = r->in.account_ou;

		/*
		 * we want to create the msDS-SupportedEncryptionTypes attribute
		 * as early as possible so always try an LDAP create as the user
		 * first. We copy r->in.account_ou because it may be changed
		 * during the machine pre-creation.
		 */

		ads_status = libnet_join_connect_ads_user(mem_ctx, r);
		if (!ADS_ERR_OK(ads_status)) {
			return WERR_NERR_DEFAULTJOINREQUIRED;
		}

		ads_status = libnet_join_precreate_machine_acct(mem_ctx, r);
		if (ADS_ERR_OK(ads_status)) {

			/*
			 * LDAP object create succeeded, now go to the rpc
			 * password set routines
			 */

			r->in.join_flags &= ~WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE;
			goto rpc_join;
		}

		if (initial_account_ou != NULL) {
			libnet_join_set_error_string(mem_ctx, r,
				"failed to precreate account in ou %s: %s",
				r->in.account_ou,
				ads_errstr(ads_status));
			return WERR_NERR_DEFAULTJOINREQUIRED;
		}

		DEBUG(5, ("failed to precreate account in ou %s: %s",
			r->in.account_ou, ads_errstr(ads_status)));
	}
 rpc_join:

#endif /* HAVE_ADS */

	if ((r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_UNSECURE) &&
	    (r->in.join_flags & WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED)) {
		status = libnet_join_joindomain_rpc_unsecure(mem_ctx, r, cli);
	} else {
		status = libnet_join_joindomain_rpc(mem_ctx, r, cli);
	}
	if (!NT_STATUS_IS_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to join domain '%s' over rpc: %s",
			r->in.domain_name, get_friendly_nt_error_msg(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			return WERR_NERR_SETUPALREADYJOINED;
		}
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnet_join_rollback(TALLOC_CTX *mem_ctx,
				   struct libnet_JoinCtx *r)
{
	WERROR werr;
	struct libnet_UnjoinCtx *u = NULL;

	werr = libnet_init_UnjoinCtx(mem_ctx, &u);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	u->in.debug		= r->in.debug;
	u->in.dc_name		= r->in.dc_name;
	u->in.domain_name	= r->in.domain_name;
	u->in.admin_account	= r->in.admin_account;
	u->in.admin_password	= r->in.admin_password;
	u->in.modify_config	= r->in.modify_config;
	u->in.use_kerberos	= r->in.use_kerberos;
	u->in.unjoin_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE;

	werr = libnet_Unjoin(mem_ctx, u);
	TALLOC_FREE(u);

	return werr;
}

/****************************************************************
****************************************************************/

WERROR libnet_Join(TALLOC_CTX *mem_ctx,
		   struct libnet_JoinCtx *r)
{
	WERROR werr;

	if (r->in.debug) {
		LIBNET_JOIN_IN_DUMP_CTX(mem_ctx, r);
	}

	ZERO_STRUCT(r->out);

	werr = libnet_join_pre_processing(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		werr = libnet_DomainJoin(mem_ctx, r);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}

	werr = libnet_join_post_processing(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		werr = libnet_join_post_verify(mem_ctx, r);
		if (!W_ERROR_IS_OK(werr)) {
			libnet_join_rollback(mem_ctx, r);
		}
	}

 done:
	r->out.result = werr;

	if (r->in.debug) {
		LIBNET_JOIN_OUT_DUMP_CTX(mem_ctx, r);
	}
	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnet_DomainUnjoin(TALLOC_CTX *mem_ctx,
				  struct libnet_UnjoinCtx *r)
{
	NTSTATUS status;

	if (!r->in.domain_sid) {
		struct dom_sid sid;
		if (!secrets_fetch_domain_sid(lp_workgroup(), &sid)) {
			libnet_unjoin_set_error_string(mem_ctx, r,
				"Unable to fetch domain sid: are we joined?");
			return WERR_NERR_SETUPNOTJOINED;
		}
		r->in.domain_sid = dom_sid_dup(mem_ctx, &sid);
		W_ERROR_HAVE_NO_MEMORY(r->in.domain_sid);
	}

	if (!(r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE) && 
	    !r->in.delete_machine_account) {
		libnet_join_unjoindomain_remove_secrets(mem_ctx, r);
		return WERR_OK;
	}

	if (!r->in.dc_name) {
		struct netr_DsRGetDCNameInfo *info;
		const char *dc;
		status = dsgetdcname(mem_ctx,
				     r->in.msg_ctx,
				     r->in.domain_name,
				     NULL,
				     NULL,
				     DS_DIRECTORY_SERVICE_REQUIRED |
				     DS_WRITABLE_REQUIRED |
				     DS_RETURN_DNS_NAME,
				     &info);
		if (!NT_STATUS_IS_OK(status)) {
			libnet_unjoin_set_error_string(mem_ctx, r,
				"failed to find DC for domain %s - %s",
				r->in.domain_name,
				get_friendly_nt_error_msg(status));
			return WERR_NERR_DCNOTFOUND;
		}

		dc = strip_hostname(info->dc_unc);
		r->in.dc_name = talloc_strdup(mem_ctx, dc);
		W_ERROR_HAVE_NO_MEMORY(r->in.dc_name);
	}

#ifdef HAVE_ADS
	/* for net ads leave, try to delete the account.  If it works, 
	   no sense in disabling.  If it fails, we can still try to 
	   disable it. jmcd */

	if (r->in.delete_machine_account) {
		ADS_STATUS ads_status;
		ads_status = libnet_unjoin_connect_ads(mem_ctx, r);
		if (ADS_ERR_OK(ads_status)) {
			/* dirty hack */
			r->out.dns_domain_name = 
				talloc_strdup(mem_ctx,
					      r->in.ads->server.realm);
			ads_status = 
				libnet_unjoin_remove_machine_acct(mem_ctx, r);
		}
		if (!ADS_ERR_OK(ads_status)) {
			libnet_unjoin_set_error_string(mem_ctx, r,
				"failed to remove machine account from AD: %s",
				ads_errstr(ads_status));
		} else {
			r->out.deleted_machine_account = true;
			W_ERROR_HAVE_NO_MEMORY(r->out.dns_domain_name);
			libnet_join_unjoindomain_remove_secrets(mem_ctx, r);
			return WERR_OK;
		}
	}
#endif /* HAVE_ADS */

	/* The WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE flag really means 
	   "disable".  */
	if (r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE) {
		status = libnet_join_unjoindomain_rpc(mem_ctx, r);
		if (!NT_STATUS_IS_OK(status)) {
			libnet_unjoin_set_error_string(mem_ctx, r,
				"failed to disable machine account via rpc: %s",
				get_friendly_nt_error_msg(status));
			if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
				return WERR_NERR_SETUPNOTJOINED;
			}
			return ntstatus_to_werror(status);
		}

		r->out.disabled_machine_account = true;
	}

	/* If disable succeeded or was not requested at all, we 
	   should be getting rid of our end of things */

	libnet_join_unjoindomain_remove_secrets(mem_ctx, r);

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR libnet_unjoin_pre_processing(TALLOC_CTX *mem_ctx,
					   struct libnet_UnjoinCtx *r)
{
	if (!r->in.domain_name) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"No domain name defined");
		return WERR_INVALID_PARAMETER;
	}

	if (!libnet_parse_domain_dc(mem_ctx, r->in.domain_name,
				    &r->in.domain_name,
				    &r->in.dc_name)) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"Failed to parse domain name");
		return WERR_INVALID_PARAMETER;
	}

	if (IS_DC) {
		return WERR_NERR_SETUPDOMAINCONTROLLER;
	}

	if (!r->in.admin_domain) {
		char *admin_domain = NULL;
		char *admin_account = NULL;
		bool ok;

		ok = split_domain_user(mem_ctx,
				       r->in.admin_account,
				       &admin_domain,
				       &admin_account);
		if (!ok) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		if (admin_domain != NULL) {
			r->in.admin_domain = admin_domain;
		} else {
			r->in.admin_domain = r->in.domain_name;
		}
		r->in.admin_account = admin_account;
	}

	if (!secrets_init()) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"Unable to open secrets database");
		return WERR_CAN_NOT_COMPLETE;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR libnet_unjoin_post_processing(TALLOC_CTX *mem_ctx,
					    struct libnet_UnjoinCtx *r)
{
	saf_delete(r->out.netbios_domain_name);
	saf_delete(r->out.dns_domain_name);

	return libnet_unjoin_config(r);
}

/****************************************************************
****************************************************************/

WERROR libnet_Unjoin(TALLOC_CTX *mem_ctx,
		     struct libnet_UnjoinCtx *r)
{
	WERROR werr;

	if (r->in.debug) {
		LIBNET_UNJOIN_IN_DUMP_CTX(mem_ctx, r);
	}

	werr = libnet_unjoin_pre_processing(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		werr = libnet_DomainUnjoin(mem_ctx, r);
		if (!W_ERROR_IS_OK(werr)) {
			libnet_unjoin_config(r);
			goto done;
		}
	}

	werr = libnet_unjoin_post_processing(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

 done:
	r->out.result = werr;

	if (r->in.debug) {
		LIBNET_UNJOIN_OUT_DUMP_CTX(mem_ctx, r);
	}

	return werr;
}
