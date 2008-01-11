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
#include "libnet/libnet_join.h"
#include "libnet/libnet_proto.h"

/****************************************************************
****************************************************************/

static void libnet_join_set_error_string(TALLOC_CTX *mem_ctx,
					 struct libnet_JoinCtx *r,
					 const char *format, ...)
{
	va_list args;
	char *tmp = NULL;

	va_start(args, format);
	tmp = talloc_vasprintf(mem_ctx, format, args);
	va_end(args);

	TALLOC_FREE(r->out.error_string);
	r->out.error_string = tmp;
}

/****************************************************************
****************************************************************/

static void libnet_unjoin_set_error_string(TALLOC_CTX *mem_ctx,
					   struct libnet_UnjoinCtx *r,
					   const char *format, ...)
{
	va_list args;
	char *tmp = NULL;

	va_start(args, format);
	tmp = talloc_vasprintf(mem_ctx, format, args);
	va_end(args);

	TALLOC_FREE(r->out.error_string);
	r->out.error_string = tmp;
}

#ifdef HAVE_LDAP

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_connect_ads(const char *dns_domain_name,
				     const char *netbios_domain_name,
				     const char *dc_name,
				     const char *user_name,
				     const char *password,
				     ADS_STRUCT **ads)
{
	ADS_STATUS status;
	ADS_STRUCT *my_ads = NULL;

	my_ads = ads_init(dns_domain_name,
			  netbios_domain_name,
			  dc_name);
	if (!my_ads) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	if (user_name) {
		SAFE_FREE(my_ads->auth.user_name);
		my_ads->auth.user_name = SMB_STRDUP(user_name);
	}

	if (password) {
		SAFE_FREE(my_ads->auth.password);
		my_ads->auth.password = SMB_STRDUP(password);
	}

	status = ads_connect(my_ads);
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
					  struct libnet_JoinCtx *r)
{
	ADS_STATUS status;

	if (r->in.ads) {
		ads_destroy(&r->in.ads);
	}

	status = libnet_connect_ads(r->in.domain_name,
				    r->in.domain_name,
				    r->in.dc_name,
				    r->in.admin_account,
				    r->in.admin_password,
				    &r->in.ads);
	if (!ADS_ERR_OK(status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to connect to AD: %s",
			ads_errstr(status));
	}

	return status;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_unjoin_connect_ads(TALLOC_CTX *mem_ctx,
					    struct libnet_UnjoinCtx *r)
{
	ADS_STATUS status;

	if (r->in.ads) {
		ads_destroy(&r->in.ads);
	}

	status = libnet_connect_ads(r->in.domain_name,
				    r->in.domain_name,
				    r->in.dc_name,
				    r->in.admin_account,
				    r->in.admin_password,
				    &r->in.ads);
	if (!ADS_ERR_OK(status)) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"failed to connect to AD: %s",
			ads_errstr(status));
	}

	return status;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_precreate_machine_acct(TALLOC_CTX *mem_ctx,
						     struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	const char *attrs[] = { "dn", NULL };

	status = ads_search_dn(r->in.ads, &res, r->in.account_ou, attrs);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (ads_count_replies(r->in.ads, res) != 1) {
		ads_msgfree(r->in.ads, res);
		return ADS_ERROR_LDAP(LDAP_NO_SUCH_OBJECT);
	}

	status = ads_create_machine_acct(r->in.ads,
					 r->in.machine_name,
					 r->in.account_ou);
	ads_msgfree(r->in.ads, res);

	if ((status.error_type == ENUM_ADS_ERROR_LDAP) &&
	    (status.err.rc == LDAP_ALREADY_EXISTS)) {
		status = ADS_SUCCESS;
	}

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

	dn = ads_get_dn(r->in.ads, res);
	if (!dn) {
		status = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	TALLOC_FREE(r->out.dn);
	r->out.dn = talloc_strdup(mem_ctx, dn);
	if (!r->out.dn) {
		status = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

 done:
	ads_msgfree(r->in.ads, res);
	ads_memfree(r->in.ads, dn);

	return status;
}

/****************************************************************
****************************************************************/

static ADS_STATUS libnet_join_set_machine_spn(TALLOC_CTX *mem_ctx,
					      struct libnet_JoinCtx *r)
{
	ADS_STATUS status;
	ADS_MODLIST mods;
	fstring my_fqdn;
	const char *spn_array[3] = {NULL, NULL, NULL};
	char *spn = NULL;

	if (!r->in.ads) {
		status = libnet_join_connect_ads(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			return status;
		}
	}

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	spn = talloc_asprintf(mem_ctx, "HOST/%s", r->in.machine_name);
	if (!spn) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}
	strupper_m(spn);
	spn_array[0] = spn;

	if (name_to_fqdn(my_fqdn, r->in.machine_name) &&
	    !strequal(my_fqdn, r->in.machine_name)) {

		strlower_m(my_fqdn);
		spn = talloc_asprintf(mem_ctx, "HOST/%s", my_fqdn);
		if (!spn) {
			return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		}
		spn_array[1] = spn;
	}

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

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

	if (!r->in.ads) {
		status = libnet_join_connect_ads(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			return status;
		}
	}

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (!r->in.upn) {
		r->in.upn = talloc_asprintf(mem_ctx,
					    "host/%s@%s",
					    r->in.machine_name,
					    r->out.dns_domain_name);
		if (!r->in.upn) {
			return ADS_ERROR(LDAP_NO_MEMORY);
		}
	}

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

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

	if (!r->in.ads) {
		status = libnet_join_connect_ads(mem_ctx, r);
		if (!ADS_ERR_OK(status)) {
			return status;
		}
	}

	status = libnet_join_find_machine_acct(mem_ctx, r);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	mods = ads_init_mods(mem_ctx);
	if (!mods) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	os_sp = talloc_asprintf(mem_ctx, "Samba %s", SAMBA_VERSION_STRING);
	if (!os_sp) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

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

#endif /* HAVE_LDAP */

/****************************************************************
****************************************************************/

static bool libnet_join_create_keytab(TALLOC_CTX *mem_ctx,
				      struct libnet_JoinCtx *r)
{
	if (!lp_use_kerberos_keytab()) {
		return true;
	}
#ifdef HAVE_KRB5
	if (!ads_keytab_create_default(r->in.ads)) {
		return false;
	}
#endif /* HAVE_KRB5 */
	return true;
}

#ifdef HAVE_KRB5

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
			"Failed to determine domain functional level!");
		return false;
	}

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

	return kerberos_secrets_store_des_salt(salt);
}

#endif /* HAVE_KRB5 */

/****************************************************************
****************************************************************/

static bool libnet_join_joindomain_store_secrets(TALLOC_CTX *mem_ctx,
						 struct libnet_JoinCtx *r)
{
	if (!secrets_store_domain_sid(r->out.netbios_domain_name,
				      r->out.domain_sid))
	{
		return false;
	}

	if (!secrets_store_machine_password(r->in.machine_password,
					    r->out.netbios_domain_name,
					    SEC_CHAN_WKSTA))
	{
		return false;
	}

	return true;
}

/****************************************************************
****************************************************************/

static NTSTATUS libnet_join_joindomain_rpc(TALLOC_CTX *mem_ctx,
					   struct libnet_JoinCtx *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND sam_pol, domain_pol, user_pol, lsa_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	const char *const_acct_name;
	uint32 user_rid;
	uint32 num_rids, *name_types, *user_rids;
	uint32 flags = 0x3e8;
	uint32 acb_info = ACB_WSTRUST;
	uint32 fields_present;
	uchar pwbuf[532];
	SAM_USERINFO_CTR ctr;
	SAM_USER_INFO_25 p25;
	const int infolevel = 25;
	struct MD5Context md5ctx;
	uchar md5buffer[16];
	DATA_BLOB digested_session_key;
	uchar md4_trust_password[16];

	if (!r->in.machine_password) {
		r->in.machine_password = talloc_strdup(mem_ctx, generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH));
		NT_STATUS_HAVE_NO_MEMORY(r->in.machine_password);
	}

	status = cli_full_connection(&cli, NULL,
				     r->in.dc_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     r->in.admin_account,
				     NULL,
				     r->in.admin_password,
				     0,
				     Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_LSARPC, &status);
	if (!pipe_hnd) {
		goto done;
	}

	status = rpccli_lsa_open_policy(pipe_hnd, mem_ctx, True,
					SEC_RIGHTS_MAXIMUM_ALLOWED, &lsa_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_lsa_query_info_policy2(pipe_hnd, mem_ctx, &lsa_pol,
					       12,
					       &r->out.netbios_domain_name,
					       &r->out.dns_domain_name,
					       NULL,
					       NULL,
					       &r->out.domain_sid);

	if (NT_STATUS_IS_OK(status)) {
		r->out.domain_is_ad = true;
	}

	if (!NT_STATUS_IS_OK(status)) {
		status = rpccli_lsa_query_info_policy(pipe_hnd, mem_ctx, &lsa_pol,
						      5,
						      &r->out.netbios_domain_name,
						      &r->out.domain_sid);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	rpccli_lsa_Close(pipe_hnd, mem_ctx, &lsa_pol);
	cli_rpc_pipe_close(pipe_hnd);

	pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status);
	if (!pipe_hnd) {
		goto done;
	}

	status = rpccli_samr_connect(pipe_hnd, mem_ctx,
				     SEC_RIGHTS_MAXIMUM_ALLOWED, &sam_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_samr_open_domain(pipe_hnd, mem_ctx, &sam_pol,
					 SEC_RIGHTS_MAXIMUM_ALLOWED,
					 r->out.domain_sid,
					 &domain_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	acct_name = talloc_asprintf(mem_ctx, "%s$", r->in.machine_name);
	strlower_m(acct_name);
	const_acct_name = acct_name;

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE) {
		status = rpccli_samr_create_dom_user(pipe_hnd, mem_ctx,
						     &domain_pol,
						     acct_name, ACB_WSTRUST,
						     0xe005000b, &user_pol,
						     &user_rid);
		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			if (!(r->in.join_flags & WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED)) {
				goto done;
			}
		}

		if (NT_STATUS_IS_OK(status)) {
			rpccli_samr_close(pipe_hnd, mem_ctx, &user_pol);
		}
	}

	status = rpccli_samr_lookup_names(pipe_hnd, mem_ctx,
					  &domain_pol, flags, 1,
					  &const_acct_name,
					  &num_rids, &user_rids, &name_types);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (name_types[0] != SID_NAME_USER) {
		status = NT_STATUS_INVALID_WORKSTATION;
		goto done;
	}

	user_rid = user_rids[0];

	status = rpccli_samr_open_user(pipe_hnd, mem_ctx, &domain_pol,
				       SEC_RIGHTS_MAXIMUM_ALLOWED, user_rid,
				       &user_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	E_md4hash(r->in.machine_password, md4_trust_password);
	encode_pw_buffer(pwbuf, r->in.machine_password, STR_UNICODE);

	generate_random_buffer((uint8*)md5buffer, sizeof(md5buffer));
	digested_session_key = data_blob_talloc(mem_ctx, 0, 16);

	MD5Init(&md5ctx);
	MD5Update(&md5ctx, md5buffer, sizeof(md5buffer));
	MD5Update(&md5ctx, cli->user_session_key.data,
		  cli->user_session_key.length);
	MD5Final(digested_session_key.data, &md5ctx);

	SamOEMhashBlob(pwbuf, sizeof(pwbuf), &digested_session_key);
	memcpy(&pwbuf[516], md5buffer, sizeof(md5buffer));

	acb_info |= ACB_PWNOEXP;
#if 0
	if ( dom_type == ND_TYPE_AD ) {
#if !defined(ENCTYPE_ARCFOUR_HMAC)
		acb_info |= ACB_USE_DES_KEY_ONLY;
#endif
		;;
	}
#endif
	ZERO_STRUCT(ctr);
	ZERO_STRUCT(p25);

	fields_present = ACCT_NT_PWD_SET | ACCT_LM_PWD_SET | ACCT_FLAGS;
	init_sam_user_info25P(&p25, fields_present, acb_info, (char *)pwbuf);

	ctr.switch_value = infolevel;
	ctr.info.id25    = &p25;

	status = rpccli_samr_set_userinfo2(pipe_hnd, mem_ctx, &user_pol,
					   infolevel, &cli->user_session_key,
					   &ctr);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	rpccli_samr_close(pipe_hnd, mem_ctx, &user_pol);
	cli_rpc_pipe_close(pipe_hnd);

	status = NT_STATUS_OK;
 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return status;
}

/****************************************************************
****************************************************************/

static bool libnet_join_unjoindomain_remove_secrets(TALLOC_CTX *mem_ctx,
						    struct libnet_UnjoinCtx *r)
{
	if (!secrets_delete_machine_password_ex(lp_workgroup())) {
		return false;
	}

	if (!secrets_delete_domain_sid(lp_workgroup())) {
		return false;
	}

	return true;
}

/****************************************************************
****************************************************************/

static NTSTATUS libnet_join_unjoindomain_rpc(TALLOC_CTX *mem_ctx,
					     struct libnet_UnjoinCtx *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND sam_pol, domain_pol, user_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	uint32 flags = 0x3e8;
	const char *const_acct_name;
	uint32 user_rid;
	uint32 num_rids, *name_types, *user_rids;
	SAM_USERINFO_CTR ctr, *qctr = NULL;
	SAM_USER_INFO_16 p16;

	status = cli_full_connection(&cli, NULL,
				     r->in.dc_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     r->in.admin_account,
				     NULL,
				     r->in.admin_password,
				     0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status);
	if (!pipe_hnd) {
		goto done;
	}

	status = rpccli_samr_connect(pipe_hnd, mem_ctx,
				     SEC_RIGHTS_MAXIMUM_ALLOWED, &sam_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_samr_open_domain(pipe_hnd, mem_ctx, &sam_pol,
					 SEC_RIGHTS_MAXIMUM_ALLOWED,
					 r->in.domain_sid,
					 &domain_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	acct_name = talloc_asprintf(mem_ctx, "%s$", r->in.machine_name);
	strlower_m(acct_name);
	const_acct_name = acct_name;

	status = rpccli_samr_lookup_names(pipe_hnd, mem_ctx,
					  &domain_pol, flags, 1,
					  &const_acct_name,
					  &num_rids, &user_rids, &name_types);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (name_types[0] != SID_NAME_USER) {
		status = NT_STATUS_INVALID_WORKSTATION;
		goto done;
	}

	user_rid = user_rids[0];

	status = rpccli_samr_open_user(pipe_hnd, mem_ctx, &domain_pol,
				       SEC_RIGHTS_MAXIMUM_ALLOWED,
				       user_rid, &user_pol);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_samr_query_userinfo(pipe_hnd, mem_ctx,
					    &user_pol, 16, &qctr);
	if (!NT_STATUS_IS_OK(status)) {
		rpccli_samr_close(pipe_hnd, mem_ctx, &user_pol);
		goto done;
	}

	ZERO_STRUCT(ctr);
	ctr.switch_value = 16;
	ctr.info.id16 = &p16;

	p16.acb_info = qctr->info.id16->acb_info | ACB_DISABLED;

	status = rpccli_samr_set_userinfo2(pipe_hnd, mem_ctx, &user_pol, 16,
					   &cli->user_session_key, &ctr);

	rpccli_samr_close(pipe_hnd, mem_ctx, &user_pol);

done:
	if (pipe_hnd) {
		rpccli_samr_close(pipe_hnd, mem_ctx, &domain_pol);
		rpccli_samr_close(pipe_hnd, mem_ctx, &sam_pol);
		cli_rpc_pipe_close(pipe_hnd);
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
	WERROR werr;

	if (!(r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE)) {

		werr = libnet_conf_set_global_parameter("security", "user");
		W_ERROR_NOT_OK_RETURN(werr);

		werr = libnet_conf_set_global_parameter("workgroup",
							r->in.domain_name);
		return werr;
	}

	werr = libnet_conf_set_global_parameter("security", "domain");
	W_ERROR_NOT_OK_RETURN(werr);

	werr = libnet_conf_set_global_parameter("workgroup",
						r->out.netbios_domain_name);
	W_ERROR_NOT_OK_RETURN(werr);

	if (r->out.domain_is_ad) {
		werr = libnet_conf_set_global_parameter("security", "ads");
		W_ERROR_NOT_OK_RETURN(werr);

		werr = libnet_conf_set_global_parameter("realm",
						       r->out.dns_domain_name);
		W_ERROR_NOT_OK_RETURN(werr);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR do_unjoin_modify_vals_config(struct libnet_UnjoinCtx *r)
{
	WERROR werr = WERR_OK;

	if (r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {

		werr = libnet_conf_set_global_parameter("security", "user");
		W_ERROR_NOT_OK_RETURN(werr);
	}

	libnet_conf_delete_parameter(GLOBAL_NAME, "realm");

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

	r->out.modified_config = true;
	r->out.result = werr;

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR do_UnjoinConfig(struct libnet_UnjoinCtx *r)
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

	r->out.modified_config = true;
	r->out.result = werr;

	return werr;
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
		return WERR_NOMEM;
	}

	talloc_set_destructor(ctx, libnet_destroy_JoinCtx);

	ctx->in.machine_name = talloc_strdup(mem_ctx, global_myname());
	W_ERROR_HAVE_NO_MEMORY(ctx->in.machine_name);

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
		return WERR_NOMEM;
	}

	talloc_set_destructor(ctx, libnet_destroy_UnjoinCtx);

	ctx->in.machine_name = talloc_strdup(mem_ctx, global_myname());
	W_ERROR_HAVE_NO_MEMORY(ctx->in.machine_name);

	*r = ctx;

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR libnet_DomainJoin(TALLOC_CTX *mem_ctx,
				struct libnet_JoinCtx *r)
{
	NTSTATUS status;
#ifdef HAVE_LDAP
	ADS_STATUS ads_status;

	if (r->in.account_ou) {
		ads_status = libnet_join_connect_ads(mem_ctx, r);
		if (!ADS_ERR_OK(ads_status)) {
			return WERR_GENERAL_FAILURE;
		}
		ads_status = libnet_join_precreate_machine_acct(mem_ctx, r);
		if (!ADS_ERR_OK(ads_status)) {
			libnet_join_set_error_string(mem_ctx, r,
				"failed to precreate account in ou %s: %s",
				r->in.account_ou,
				ads_errstr(ads_status));
			return WERR_GENERAL_FAILURE;
		}

		r->in.join_flags &= ~WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE;
	}
#endif /* HAVE_LDAP */
	status = libnet_join_joindomain_rpc(mem_ctx, r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			return WERR_SETUP_ALREADY_JOINED;
		}
		return ntstatus_to_werror(status);
	}

	if (!libnet_join_joindomain_store_secrets(mem_ctx, r)) {
		return WERR_SETUP_NOT_JOINED;
	}

#ifdef HAVE_LDAP
	ads_status = libnet_join_set_machine_spn(mem_ctx, r);
	if (!ADS_ERR_OK(ads_status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to set machine spn: %s",
			ads_errstr(ads_status));
		return WERR_GENERAL_FAILURE;
	}

	ads_status = libnet_join_set_os_attributes(mem_ctx, r);
	if (!ADS_ERR_OK(ads_status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to set machine os attributes: %s",
			ads_errstr(ads_status));
		return WERR_GENERAL_FAILURE;
	}

	ads_status = libnet_join_set_machine_upn(mem_ctx, r);
	if (!ADS_ERR_OK(ads_status)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to set machine upn: %s",
			ads_errstr(ads_status));
		return WERR_GENERAL_FAILURE;
	}

#ifdef HAVE_KRB5
	if (!libnet_join_derive_salting_principal(mem_ctx, r)) {
		return WERR_GENERAL_FAILURE;
	}
#endif /* HAVE_KRB5 */

#endif /* HAVE_LDAP */
	if (!libnet_join_create_keytab(mem_ctx, r)) {
		libnet_join_set_error_string(mem_ctx, r,
			"failed to create kerberos keytab");
		return WERR_GENERAL_FAILURE;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR libnet_Join(TALLOC_CTX *mem_ctx,
		   struct libnet_JoinCtx *r)
{
	WERROR werr;

	if (!r->in.domain_name) {
		return WERR_INVALID_PARAM;
	}

	if (r->in.modify_config && !lp_include_registry_globals()) {
		return WERR_NOT_SUPPORTED;
	}

	if (IS_DC) {
		return WERR_SETUP_DOMAIN_CONTROLLER;
	}

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		werr = libnet_DomainJoin(mem_ctx, r);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	}

	werr = do_JoinConfig(r);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnet_DomainUnjoin(TALLOC_CTX *mem_ctx,
				  struct libnet_UnjoinCtx *r)
{
	NTSTATUS status;

	status = libnet_join_unjoindomain_rpc(mem_ctx, r);
	if (!NT_STATUS_IS_OK(status)) {
		libnet_unjoin_set_error_string(mem_ctx, r,
			"failed to unjoin domain: %s",
			nt_errstr(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
			return WERR_SETUP_NOT_JOINED;
		}
		return ntstatus_to_werror(status);
	}

#ifdef HAVE_LDAP
	if (r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE) {
		ADS_STATUS ads_status;
		libnet_unjoin_connect_ads(mem_ctx, r);
		ads_status = libnet_unjoin_remove_machine_acct(mem_ctx, r);
		if (!ADS_ERR_OK(ads_status)) {
			libnet_unjoin_set_error_string(mem_ctx, r,
				"failed to remove machine account from AD: %s",
				ads_errstr(ads_status));
		}
	}
#endif /* HAVE_LDAP */
	libnet_join_unjoindomain_remove_secrets(mem_ctx, r);

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR libnet_Unjoin(TALLOC_CTX *mem_ctx,
		     struct libnet_UnjoinCtx *r)
{
	WERROR werr;

	if (r->in.modify_config && !lp_include_registry_globals()) {
		return WERR_NOT_SUPPORTED;
	}

	if (r->in.unjoin_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		werr = libnet_DomainUnjoin(mem_ctx, r);
		if (!W_ERROR_IS_OK(werr)) {
			do_UnjoinConfig(r);
			return werr;
		}
	}

	werr = do_UnjoinConfig(r);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return werr;
}
