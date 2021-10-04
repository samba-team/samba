/*
   Unix SMB/CIFS implementation.

   Winbind daemon - pam auth funcions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett 2001-2002
   Copyright (C) Guenther Deschner 2005

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
#include "winbindd.h"
#include "libsmb/namequery.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_samr.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "rpc_client/cli_netlogon.h"
#include "smb_krb5.h"
#include "../libcli/security/security.h"
#include "ads.h"
#include "../librpc/gen_ndr/krb5pac.h"
#include "passdb/machine_sid.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/kerberos/pac_utils.h"
#include "auth/gensec/gensec.h"
#include "librpc/crypto/gse_krb5.h"
#include "lib/afs/afs_funcs.h"
#include "libsmb/samlogon_cache.h"
#include "rpc_client/util_netlogon.h"
#include "param/param.h"
#include "messaging/messaging.h"
#include "lib/crypto/gnutls_helpers.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#define LOGON_KRB5_FAIL_CLOCK_SKEW	0x02000000

static NTSTATUS append_info3_as_txt(TALLOC_CTX *mem_ctx,
				    struct winbindd_response *resp,
				    uint16_t validation_level,
				    union netr_Validation *validation)
{
	struct netr_SamInfo3 *info3 = NULL;
	char *ex = NULL;
	uint32_t i;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *frame = talloc_stackframe();

	status = map_validation_to_info3(frame,
					 validation_level,
					 validation,
					 &info3);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	resp->data.auth.info3.logon_time =
		nt_time_to_unix(info3->base.logon_time);
	resp->data.auth.info3.logoff_time =
		nt_time_to_unix(info3->base.logoff_time);
	resp->data.auth.info3.kickoff_time =
		nt_time_to_unix(info3->base.kickoff_time);
	resp->data.auth.info3.pass_last_set_time =
		nt_time_to_unix(info3->base.last_password_change);
	resp->data.auth.info3.pass_can_change_time =
		nt_time_to_unix(info3->base.allow_password_change);
	resp->data.auth.info3.pass_must_change_time =
		nt_time_to_unix(info3->base.force_password_change);

	resp->data.auth.info3.logon_count = info3->base.logon_count;
	resp->data.auth.info3.bad_pw_count = info3->base.bad_password_count;

	resp->data.auth.info3.user_rid = info3->base.rid;
	resp->data.auth.info3.group_rid = info3->base.primary_gid;
	sid_to_fstring(resp->data.auth.info3.dom_sid, info3->base.domain_sid);

	resp->data.auth.info3.num_groups = info3->base.groups.count;
	resp->data.auth.info3.user_flgs = info3->base.user_flags;

	resp->data.auth.info3.acct_flags = info3->base.acct_flags;
	resp->data.auth.info3.num_other_sids = info3->sidcount;

	fstrcpy(resp->data.auth.info3.user_name,
		info3->base.account_name.string);
	fstrcpy(resp->data.auth.info3.full_name,
		info3->base.full_name.string);
	fstrcpy(resp->data.auth.info3.logon_script,
		info3->base.logon_script.string);
	fstrcpy(resp->data.auth.info3.profile_path,
		info3->base.profile_path.string);
	fstrcpy(resp->data.auth.info3.home_dir,
		info3->base.home_directory.string);
	fstrcpy(resp->data.auth.info3.dir_drive,
		info3->base.home_drive.string);

	fstrcpy(resp->data.auth.info3.logon_srv,
		info3->base.logon_server.string);
	fstrcpy(resp->data.auth.info3.logon_dom,
		info3->base.logon_domain.string);

	resp->data.auth.validation_level = validation_level;
	if (validation_level == 6) {
		fstrcpy(resp->data.auth.info6.dns_domainname,
			validation->sam6->dns_domainname.string);
		fstrcpy(resp->data.auth.info6.principal_name,
			validation->sam6->principal_name.string);
	}

	ex = talloc_strdup(frame, "");
	if (ex == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	for (i=0; i < info3->base.groups.count; i++) {
		ex = talloc_asprintf_append_buffer(ex, "0x%08X:0x%08X\n",
						   info3->base.groups.rids[i].rid,
						   info3->base.groups.rids[i].attributes);
		if (ex == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	for (i=0; i < info3->sidcount; i++) {
		struct dom_sid_buf sidbuf;

		ex = talloc_asprintf_append_buffer(
			ex,
			"%s:0x%08X\n",
			dom_sid_str_buf(info3->sids[i].sid, &sidbuf),
			info3->sids[i].attributes);
		if (ex == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	resp->length += talloc_get_size(ex);
	resp->extra_data.data = talloc_move(mem_ctx, &ex);

	status = NT_STATUS_OK;
out:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS append_info3_as_ndr(TALLOC_CTX *mem_ctx,
				    struct winbindd_response *resp,
				    struct netr_SamInfo3 *info3)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, info3,
				       (ndr_push_flags_fn_t)ndr_push_netr_SamInfo3);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,("append_info3_as_ndr: failed to append\n"));
		return ndr_map_error2ntstatus(ndr_err);
	}

	resp->extra_data.data = blob.data;
	resp->length += blob.length;

	return NT_STATUS_OK;
}

static NTSTATUS append_unix_username(TALLOC_CTX *mem_ctx,
				     struct winbindd_response *resp,
				     const struct netr_SamInfo3 *info3,
				     const char *name_domain,
				     const char *name_user)
{
	/* We've been asked to return the unix username, per
	   'winbind use default domain' settings and the like */

	const char *nt_username, *nt_domain, *unix_username;

	nt_domain = talloc_strdup(mem_ctx, info3->base.logon_domain.string);
	if (!nt_domain) {
		/* If the server didn't give us one, just use the one
		 * we sent them */
		nt_domain = name_domain;
	}

	nt_username = talloc_strdup(mem_ctx, info3->base.account_name.string);
	if (!nt_username) {
		/* If the server didn't give us one, just use the one
		 * we sent them */
		nt_username = name_user;
	}

	unix_username = fill_domain_username_talloc(mem_ctx,
						    nt_domain,
						    nt_username,
						    true);
	if (unix_username == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fstrcpy(resp->data.auth.unix_username, unix_username);

	DEBUG(5, ("Setting unix username to [%s]\n",
		  resp->data.auth.unix_username));

	return NT_STATUS_OK;
}

static NTSTATUS append_afs_token(TALLOC_CTX *mem_ctx,
				 struct winbindd_response *resp,
				 const struct netr_SamInfo3 *info3,
				 const char *name_domain,
				 const char *name_user)
{
	char *afsname = NULL;
	char *cell;
	char *token;

	afsname = talloc_strdup(mem_ctx, lp_afs_username_map());
	if (afsname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	afsname = talloc_string_sub(mem_ctx,
				    lp_afs_username_map(),
				    "%D", name_domain);
	afsname = talloc_string_sub(mem_ctx, afsname,
				    "%u", name_user);
	afsname = talloc_string_sub(mem_ctx, afsname,
				    "%U", name_user);

	{
		struct dom_sid user_sid;
		struct dom_sid_buf sidstr;

		sid_compose(&user_sid, info3->base.domain_sid,
			    info3->base.rid);
		afsname = talloc_string_sub(
			mem_ctx,
			afsname,
			"%s",
			dom_sid_str_buf(&user_sid, &sidstr));
	}

	if (afsname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!strlower_m(afsname)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10, ("Generating token for user %s\n", afsname));

	cell = strchr(afsname, '@');

	if (cell == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*cell = '\0';
	cell += 1;

	token = afs_createtoken_str(afsname, cell);
	if (token == NULL) {
		return NT_STATUS_OK;
	}
	resp->extra_data.data = talloc_strdup(mem_ctx, token);
	if (resp->extra_data.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	resp->length += strlen((const char *)resp->extra_data.data)+1;

	return NT_STATUS_OK;
}

static NTSTATUS check_info3_in_group(struct netr_SamInfo3 *info3,
				     const char *group_sid)
/**
 * Check whether a user belongs to a group or list of groups.
 *
 * @param mem_ctx talloc memory context.
 * @param info3 user information, including group membership info.
 * @param group_sid One or more groups , separated by commas.
 *
 * @return NT_STATUS_OK on success,
 *    NT_STATUS_LOGON_FAILURE if the user does not belong,
 *    or other NT_STATUS_IS_ERR(status) for other kinds of failure.
 */
{
	struct dom_sid *require_membership_of_sid;
	uint32_t num_require_membership_of_sid;
	char *req_sid;
	const char *p;
	struct dom_sid sid;
	size_t i;
	struct security_token *token;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	/* Parse the 'required group' SID */

	if (!group_sid || !group_sid[0]) {
		/* NO sid supplied, all users may access */
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	token = talloc_zero(talloc_tos(), struct security_token);
	if (token == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	num_require_membership_of_sid = 0;
	require_membership_of_sid = NULL;

	p = group_sid;

	while (next_token_talloc(talloc_tos(), &p, &req_sid, ",")) {
		if (!string_to_sid(&sid, req_sid)) {
			DEBUG(0, ("check_info3_in_group: could not parse %s "
				  "as a SID!", req_sid));
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = add_sid_to_array(talloc_tos(), &sid,
					  &require_membership_of_sid,
					  &num_require_membership_of_sid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("add_sid_to_array failed\n"));
			TALLOC_FREE(frame);
			return status;
		}
	}

	status = sid_array_from_info3(talloc_tos(), info3,
				      &token->sids,
				      &token->num_sids,
				      true);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (!NT_STATUS_IS_OK(status = add_aliases(get_global_sam_sid(),
						  token))
	    || !NT_STATUS_IS_OK(status = add_aliases(&global_sid_Builtin,
						     token))) {
		DEBUG(3, ("could not add aliases: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	security_token_debug(DBGC_CLASS, 10, token);

	for (i=0; i<num_require_membership_of_sid; i++) {
		struct dom_sid_buf buf;
		DEBUG(10, ("Checking SID %s\n",
			   dom_sid_str_buf(&require_membership_of_sid[i],
					   &buf)));
		if (nt_token_check_sid(&require_membership_of_sid[i],
				       token)) {
			DEBUG(10, ("Access ok\n"));
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
	}

	/* Do not distinguish this error from a wrong username/pw */

	TALLOC_FREE(frame);
	return NT_STATUS_LOGON_FAILURE;
}

struct winbindd_domain *find_auth_domain(uint8_t flags,
					 const char *domain_name)
{
	struct winbindd_domain *domain;

	if (IS_DC) {
		domain = find_domain_from_name_noinit(domain_name);
		if (domain == NULL) {
			DEBUG(3, ("Authentication for domain [%s] refused "
				  "as it is not a trusted domain\n",
				  domain_name));
			return NULL;
		}

		if (domain->secure_channel_type != SEC_CHAN_NULL) {
			return domain;
		}

		return domain->routing_domain;
	}

	if (strequal(domain_name, get_global_sam_name())) {
		return find_domain_from_name_noinit(domain_name);
	}

	if (lp_winbind_use_krb5_enterprise_principals()) {
		/*
		 * If we use enterprise principals
		 * we always go trough our primary domain
		 * and follow the WRONG_REALM replies.
		 */
		flags &= ~WBFLAG_PAM_CONTACT_TRUSTDOM;
	}

	/* we can auth against trusted domains */
	if (flags & WBFLAG_PAM_CONTACT_TRUSTDOM) {
		domain = find_domain_from_name_noinit(domain_name);
		if (domain == NULL) {
			DEBUG(3, ("Authentication for domain [%s] skipped "
				  "as it is not a trusted domain\n",
				  domain_name));
		} else {
			return domain;
		}
	}

	return find_our_domain();
}

static void fake_password_policy(struct winbindd_response *r,
				 const struct netr_SamBaseInfo *bi)
{
	NTTIME min_password_age;
	NTTIME max_password_age;

	if (bi->allow_password_change > bi->last_password_change) {
		min_password_age = bi->allow_password_change -
				   bi->last_password_change;
	} else {
		min_password_age = 0;
	}

	if (bi->force_password_change > bi->last_password_change) {
		max_password_age = bi->force_password_change -
				   bi->last_password_change;
	} else {
		max_password_age = 0;
	}

	r->data.auth.policy.min_length_password = 0;
	r->data.auth.policy.password_history = 0;
	r->data.auth.policy.password_properties = 0;
	r->data.auth.policy.expire =
		nt_time_to_unix_abs(&max_password_age);
	r->data.auth.policy.min_passwordage =
		nt_time_to_unix_abs(&min_password_age);
}

static void fill_in_password_policy(struct winbindd_response *r,
				    const struct samr_DomInfo1 *p)
{
	r->data.auth.policy.min_length_password =
		p->min_password_length;
	r->data.auth.policy.password_history =
		p->password_history_length;
	r->data.auth.policy.password_properties =
		p->password_properties;
	r->data.auth.policy.expire	=
		nt_time_to_unix_abs((const NTTIME *)&(p->max_password_age));
	r->data.auth.policy.min_passwordage =
		nt_time_to_unix_abs((const NTTIME *)&(p->min_password_age));
}

static NTSTATUS fillup_password_policy(struct winbindd_domain *domain,
				       struct winbindd_response *response)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct samr_DomInfo1 password_policy;

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(5,("fillup_password_policy: No inbound trust to "
			 "contact domain %s\n", domain->name));
		status = NT_STATUS_NOT_SUPPORTED;
		goto done;
	}

	status = wb_cache_password_policy(domain, talloc_tos(),
					  &password_policy);
	if (NT_STATUS_IS_ERR(status)) {
		goto done;
	}

	fill_in_password_policy(response, &password_policy);

done:
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS get_max_bad_attempts_from_lockout_policy(struct winbindd_domain *domain,
							 TALLOC_CTX *mem_ctx,
							 uint16_t *lockout_threshold)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct samr_DomInfo12 lockout_policy;

	*lockout_threshold = 0;

	status = wb_cache_lockout_policy(domain, mem_ctx, &lockout_policy);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	*lockout_threshold = lockout_policy.lockout_threshold;

	return NT_STATUS_OK;
}

static NTSTATUS get_pwd_properties(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32_t *password_properties)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct samr_DomInfo1 password_policy;

	*password_properties = 0;

	status = wb_cache_password_policy(domain, mem_ctx, &password_policy);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	*password_properties = password_policy.password_properties;

	return NT_STATUS_OK;
}

#ifdef HAVE_KRB5

static const char *generate_krb5_ccache(TALLOC_CTX *mem_ctx,
					const char *type,
					uid_t uid,
					const char **user_ccache_file)
{
	/* accept FILE and WRFILE as krb5_cc_type from the client and then
	 * build the full ccname string based on the user's uid here -
	 * Guenther*/

	const char *gen_cc = NULL;

	if (uid != -1) {
		if (strequal(type, "FILE")) {
			gen_cc = talloc_asprintf(
				mem_ctx, "FILE:/tmp/krb5cc_%d", uid);
		}
		if (strequal(type, "WRFILE")) {
			gen_cc = talloc_asprintf(
				mem_ctx, "WRFILE:/tmp/krb5cc_%d", uid);
		}
		if (strequal(type, "KEYRING")) {
			gen_cc = talloc_asprintf(
				mem_ctx, "KEYRING:persistent:%d", uid);
		}
		if (strequal(type, "KCM")) {
			gen_cc = talloc_asprintf(mem_ctx,
						 "KCM:%d",
						 uid);
		}

		if (strnequal(type, "FILE:/", 6) ||
		    strnequal(type, "WRFILE:/", 8) ||
		    strnequal(type, "DIR:/", 5)) {

			/* we allow only one "%u" substitution */

			char *p;

			p = strchr(type, '%');
			if (p != NULL) {

				p++;

				if (p != NULL && *p == 'u' && strchr(p, '%') == NULL) {
					char uid_str[sizeof("18446744073709551615")];

					snprintf(uid_str, sizeof(uid_str), "%u", uid);

					gen_cc = talloc_string_sub2(mem_ctx,
							type,
							"%u",
							uid_str,
							/* remove_unsafe_characters */
							false,
							/* replace_once */
							true,
							/* allow_trailing_dollar */
							false);
				}
			}
		}
	}

	*user_ccache_file = gen_cc;

	if (gen_cc == NULL) {
		gen_cc = talloc_strdup(mem_ctx, "MEMORY:winbindd_pam_ccache");
	}
  	if (gen_cc == NULL) {
		DEBUG(0,("out of memory\n"));
		return NULL;
	}

	DEBUG(10, ("using ccache: %s%s\n", gen_cc,
		   (*user_ccache_file == NULL) ? " (internal)":""));

	return gen_cc;
}

#endif

uid_t get_uid_from_request(struct winbindd_request *request)
{
	uid_t uid;

	uid = request->data.auth.uid;

	if (uid == (uid_t)-1) {
		DEBUG(1,("invalid uid: '%u'\n", (unsigned int)uid));
		return -1;
	}
	return uid;
}

/**********************************************************************
 Authenticate a user with a clear text password using Kerberos and fill up
 ccache if required
 **********************************************************************/

static NTSTATUS winbindd_raw_kerberos_login(TALLOC_CTX *mem_ctx,
					    struct winbindd_domain *domain,
					    const char *user,
					    const char *pass,
					    const char *krb5_cc_type,
					    uid_t uid,
					    struct netr_SamInfo6 **info6,
					    fstring krb5ccname)
{
#ifdef HAVE_KRB5
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	krb5_error_code krb5_ret;
	const char *cc = NULL;
	const char *principal_s = NULL;
	const char *service = NULL;
	char *realm = NULL;
	fstring name_namespace, name_domain, name_user;
	time_t ticket_lifetime = 0;
	time_t renewal_until = 0;
	ADS_STRUCT *ads;
	time_t time_offset = 0;
	const char *user_ccache_file;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct PAC_UPN_DNS_INFO *upn_dns_info = NULL;
	struct PAC_DATA *pac_data = NULL;
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	const char *local_service;
	uint32_t i;
	struct netr_SamInfo6 *info6_copy = NULL;
	bool ok;

	*info6 = NULL;

	if (domain->alt_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* 1st step:
	 * prepare a krb5_cc_cache string for the user */

	if (uid == -1) {
		DEBUG(0,("no valid uid\n"));
	}

	cc = generate_krb5_ccache(mem_ctx,
				  krb5_cc_type,
				  uid,
				  &user_ccache_file);
	if (cc == NULL) {
		return NT_STATUS_NO_MEMORY;
	}


	/* 2nd step:
	 * get kerberos properties */

	if (domain->private_data) {
		ads = (ADS_STRUCT *)domain->private_data;
		time_offset = ads->auth.time_offset;
	}


	/* 3rd step:
	 * do kerberos auth and setup ccache as the user */

	ok = parse_domain_user(user, name_namespace, name_domain, name_user);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	realm = talloc_strdup(mem_ctx, domain->alt_name);
	if (realm == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!strupper_m(realm)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (lp_winbind_use_krb5_enterprise_principals() &&
	    name_namespace[0] != '\0')
	{
		principal_s = talloc_asprintf(mem_ctx,
					      "%s@%s@%s",
					      name_user,
					      name_namespace,
					      realm);
	} else {
		principal_s = talloc_asprintf(mem_ctx,
					      "%s@%s",
					      name_user,
					      realm);
	}
	if (principal_s == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	service = talloc_asprintf(mem_ctx, "%s/%s@%s", KRB5_TGS_NAME, realm, realm);
	if (service == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	local_service = talloc_asprintf(mem_ctx, "%s$@%s",
					lp_netbios_name(), lp_realm());
	if (local_service == NULL) {
		return NT_STATUS_NO_MEMORY;
	}


	/* if this is a user ccache, we need to act as the user to let the krb5
	 * library handle the chown, etc. */

	/************************ ENTERING NON-ROOT **********************/

	if (user_ccache_file != NULL) {
		set_effective_uid(uid);
		DEBUG(10,("winbindd_raw_kerberos_login: uid is %d\n", uid));
	}

	result = kerberos_return_pac(mem_ctx,
				     principal_s,
				     pass,
				     time_offset,
				     &ticket_lifetime,
				     &renewal_until,
				     cc,
				     true,
				     true,
				     WINBINDD_PAM_AUTH_KRB5_RENEW_TIME,
				     NULL,
				     local_service,
				     &pac_data_ctr);
	if (user_ccache_file != NULL) {
		gain_root_privilege();
	}

	/************************ RETURNED TO ROOT **********************/

	if (!NT_STATUS_IS_OK(result)) {
		goto failed;
	}

	if (pac_data_ctr == NULL) {
		goto failed;
	}

	pac_data = pac_data_ctr->pac_data;
	if (pac_data == NULL) {
		goto failed;
	}

	for (i=0; i < pac_data->num_buffers; i++) {

		if (pac_data->buffers[i].type == PAC_TYPE_LOGON_INFO) {
			logon_info = pac_data->buffers[i].info->logon_info.info;
			continue;
		}

		if (pac_data->buffers[i].type == PAC_TYPE_UPN_DNS_INFO) {
			upn_dns_info = &pac_data->buffers[i].info->upn_dns_info;
			continue;
		}
	}

	if (logon_info == NULL) {
		DEBUG(10,("Missing logon_info in ticket of %s\n",
			principal_s));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10,("winbindd_raw_kerberos_login: winbindd validated ticket of %s\n",
		principal_s));

	result = create_info6_from_pac(mem_ctx, logon_info,
				       upn_dns_info, &info6_copy);
	if (!NT_STATUS_IS_OK(result)) {
		goto failed;
	}

	/* if we had a user's ccache then return that string for the pam
	 * environment */

	if (user_ccache_file != NULL) {

		fstrcpy(krb5ccname, user_ccache_file);

		result = add_ccache_to_list(principal_s,
					    cc,
					    service,
					    user,
					    pass,
					    realm,
					    uid,
					    time(NULL),
					    ticket_lifetime,
					    renewal_until,
					    false);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("winbindd_raw_kerberos_login: failed to add ccache to list: %s\n",
				nt_errstr(result)));
		}
	} else {

		/* need to delete the memory cred cache, it is not used anymore */

		krb5_ret = ads_kdestroy(cc);
		if (krb5_ret) {
			DEBUG(3,("winbindd_raw_kerberos_login: "
				 "could not destroy krb5 credential cache: "
				 "%s\n", error_message(krb5_ret)));
		}

	}
	*info6 = info6_copy;
	return NT_STATUS_OK;

failed:
	/*
	 * Do not delete an existing valid credential cache, if the user
	 * e.g. enters a wrong password
	 */
	if ((strequal(krb5_cc_type, "FILE") || strequal(krb5_cc_type, "WRFILE"))
	    && user_ccache_file != NULL) {
		return result;
	}

	/* we could have created a new credential cache with a valid tgt in it
	 * but we werent able to get or verify the service ticket for this
	 * local host and therefor didn't get the PAC, we need to remove that
	 * cache entirely now */

	krb5_ret = ads_kdestroy(cc);
	if (krb5_ret) {
		DEBUG(3,("winbindd_raw_kerberos_login: "
			 "could not destroy krb5 credential cache: "
			 "%s\n", error_message(krb5_ret)));
	}

	if (!NT_STATUS_IS_OK(remove_ccache(user))) {
		DEBUG(3,("winbindd_raw_kerberos_login: "
			  "could not remove ccache for user %s\n",
			user));
	}

	return result;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif /* HAVE_KRB5 */
}

/****************************************************************
****************************************************************/

bool check_request_flags(uint32_t flags)
{
	uint32_t flags_edata = WBFLAG_PAM_AFS_TOKEN |
			       WBFLAG_PAM_INFO3_TEXT |
			       WBFLAG_PAM_INFO3_NDR;

	if ( ( (flags & flags_edata) == WBFLAG_PAM_AFS_TOKEN) ||
	     ( (flags & flags_edata) == WBFLAG_PAM_INFO3_NDR) ||
	     ( (flags & flags_edata) == WBFLAG_PAM_INFO3_TEXT)||
	      !(flags & flags_edata) ) {
		return true;
	}

	DEBUG(1, ("check_request_flags: invalid request flags[0x%08X]\n",
		  flags));

	return false;
}

/****************************************************************
****************************************************************/

NTSTATUS append_auth_data(TALLOC_CTX *mem_ctx,
			  struct winbindd_response *resp,
			  uint32_t request_flags,
			  uint16_t validation_level,
			  union netr_Validation *validation,
			  const char *name_domain,
			  const char *name_user)
{
	struct netr_SamInfo3 *info3 = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	result = map_validation_to_info3(talloc_tos(),
					 validation_level,
					 validation,
					 &info3);
	if (!NT_STATUS_IS_OK(result)) {
		goto out;
	}

	if (request_flags & WBFLAG_PAM_USER_SESSION_KEY) {
		memcpy(resp->data.auth.user_session_key,
		       info3->base.key.key,
		       sizeof(resp->data.auth.user_session_key)
		       /* 16 */);
	}

	if (request_flags & WBFLAG_PAM_LMKEY) {
		memcpy(resp->data.auth.first_8_lm_hash,
		       info3->base.LMSessKey.key,
		       sizeof(resp->data.auth.first_8_lm_hash)
		       /* 8 */);
	}

	if (request_flags & WBFLAG_PAM_UNIX_NAME) {
		result = append_unix_username(mem_ctx, resp,
					      info3, name_domain, name_user);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("Failed to append Unix Username: %s\n",
				nt_errstr(result)));
			goto out;
		}
	}

	/* currently, anything from here on potentially overwrites extra_data. */

	if (request_flags & WBFLAG_PAM_INFO3_NDR) {
		result = append_info3_as_ndr(mem_ctx, resp, info3);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("Failed to append INFO3 (NDR): %s\n",
				nt_errstr(result)));
			goto out;
		}
	}

	if (request_flags & WBFLAG_PAM_INFO3_TEXT) {
		result = append_info3_as_txt(mem_ctx, resp,
					     validation_level,
					     validation);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("Failed to append INFO3 (TXT): %s\n",
				nt_errstr(result)));
			goto out;
		}
	}

	if (request_flags & WBFLAG_PAM_AFS_TOKEN) {
		result = append_afs_token(mem_ctx, resp,
					  info3, name_domain, name_user);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("Failed to append AFS token: %s\n",
				nt_errstr(result)));
			goto out;
		}
	}

	result = NT_STATUS_OK;
out:
	TALLOC_FREE(info3);
	return result;
}

static NTSTATUS winbindd_dual_pam_auth_cached(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state,
					      struct netr_SamInfo3 **info3)
{
	NTSTATUS result = NT_STATUS_LOGON_FAILURE;
	uint16_t max_allowed_bad_attempts;
	fstring name_namespace, name_domain, name_user;
	struct dom_sid sid;
	enum lsa_SidType type;
	uchar new_nt_pass[NT_HASH_LEN];
	const uint8_t *cached_nt_pass;
	const uint8_t *cached_salt;
	struct netr_SamInfo3 *my_info3;
	time_t kickoff_time, must_change_time;
	bool password_good = false;
	bool ok;
#ifdef HAVE_KRB5
	struct winbindd_tdc_domain *tdc_domain = NULL;
#endif

	*info3 = NULL;

	ZERO_STRUCTP(info3);

	DEBUG(10,("winbindd_dual_pam_auth_cached\n"));

	/* Parse domain and username */

	ok = parse_domain_user(state->request->data.auth.user,
			       name_namespace,
			       name_domain,
			       name_user);
	if (!ok) {
		DBG_DEBUG("parse_domain_user failed\n");
		return NT_STATUS_NO_SUCH_USER;
	}

	if (!lookup_cached_name(name_namespace,
				name_domain,
				name_user,
				&sid,
				&type)) {
		DEBUG(10,("winbindd_dual_pam_auth_cached: no such user in the cache\n"));
		return NT_STATUS_NO_SUCH_USER;
	}

	if (type != SID_NAME_USER) {
		DEBUG(10,("winbindd_dual_pam_auth_cached: not a user (%s)\n", sid_type_lookup(type)));
		return NT_STATUS_LOGON_FAILURE;
	}

	result = winbindd_get_creds(domain,
				    state->mem_ctx,
				    &sid,
				    &my_info3,
				    &cached_nt_pass,
				    &cached_salt);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("winbindd_dual_pam_auth_cached: failed to get creds: %s\n", nt_errstr(result)));
		return result;
	}

	*info3 = my_info3;

	E_md4hash(state->request->data.auth.pass, new_nt_pass);

	dump_data_pw("new_nt_pass", new_nt_pass, NT_HASH_LEN);
	dump_data_pw("cached_nt_pass", cached_nt_pass, NT_HASH_LEN);
	if (cached_salt) {
		dump_data_pw("cached_salt", cached_salt, NT_HASH_LEN);
	}

	if (cached_salt) {
		/* In this case we didn't store the nt_hash itself,
		   but the MD5 combination of salt + nt_hash. */
		uchar salted_hash[NT_HASH_LEN];
		gnutls_hash_hd_t hash_hnd = NULL;
		int rc;

		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}

		rc = gnutls_hash(hash_hnd, cached_salt, 16);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		rc = gnutls_hash(hash_hnd, new_nt_pass, 16);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		gnutls_hash_deinit(hash_hnd, salted_hash);

		password_good = (memcmp(cached_nt_pass, salted_hash,
					NT_HASH_LEN) == 0);
	} else {
		/* Old cached cred - direct store of nt_hash (bad bad bad !). */
		password_good = (memcmp(cached_nt_pass, new_nt_pass,
					NT_HASH_LEN) == 0);
	}

	if (password_good) {

		/* User *DOES* know the password, update logon_time and reset
		 * bad_pw_count */

		my_info3->base.user_flags |= NETLOGON_CACHED_ACCOUNT;

		if (my_info3->base.acct_flags & ACB_AUTOLOCK) {
			return NT_STATUS_ACCOUNT_LOCKED_OUT;
		}

		if (my_info3->base.acct_flags & ACB_DISABLED) {
			return NT_STATUS_ACCOUNT_DISABLED;
		}

		if (my_info3->base.acct_flags & ACB_WSTRUST) {
			return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
		}

		if (my_info3->base.acct_flags & ACB_SVRTRUST) {
			return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
		}

		if (my_info3->base.acct_flags & ACB_DOMTRUST) {
			return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
		}

		if (!(my_info3->base.acct_flags & ACB_NORMAL)) {
			DEBUG(0,("winbindd_dual_pam_auth_cached: whats wrong with that one?: 0x%08x\n",
				my_info3->base.acct_flags));
			return NT_STATUS_LOGON_FAILURE;
		}

		kickoff_time = nt_time_to_unix(my_info3->base.kickoff_time);
		if (kickoff_time != 0 && time(NULL) > kickoff_time) {
			return NT_STATUS_ACCOUNT_EXPIRED;
		}

		must_change_time = nt_time_to_unix(my_info3->base.force_password_change);
		if (must_change_time != 0 && must_change_time < time(NULL)) {
			/* we allow grace logons when the password has expired */
			my_info3->base.user_flags |= NETLOGON_GRACE_LOGON;
			/* return NT_STATUS_PASSWORD_EXPIRED; */
			goto success;
		}

#ifdef HAVE_KRB5
		if ((state->request->flags & WBFLAG_PAM_KRB5) &&
		    ((tdc_domain = wcache_tdc_fetch_domain(state->mem_ctx, name_domain)) != NULL) &&
		    ((tdc_domain->trust_type & LSA_TRUST_TYPE_UPLEVEL) ||
		    /* used to cope with the case winbindd starting without network. */
		    !strequal(tdc_domain->domain_name, tdc_domain->dns_name))) {

			uid_t uid = -1;
			const char *cc = NULL;
			char *realm = NULL;
			const char *principal_s = NULL;
			const char *service = NULL;
			const char *user_ccache_file;

			if (domain->alt_name == NULL) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			uid = get_uid_from_request(state->request);
			if (uid == -1) {
				DEBUG(0,("winbindd_dual_pam_auth_cached: invalid uid\n"));
				return NT_STATUS_INVALID_PARAMETER;
			}

			cc = generate_krb5_ccache(state->mem_ctx,
						state->request->data.auth.krb5_cc_type,
						state->request->data.auth.uid,
						&user_ccache_file);
			if (cc == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			realm = talloc_strdup(state->mem_ctx, domain->alt_name);
			if (realm == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			if (!strupper_m(realm)) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			principal_s = talloc_asprintf(state->mem_ctx, "%s@%s", name_user, realm);
			if (principal_s == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			service = talloc_asprintf(state->mem_ctx, "%s/%s@%s", KRB5_TGS_NAME, realm, realm);
			if (service == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			if (user_ccache_file != NULL) {

				fstrcpy(state->response->data.auth.krb5ccname,
					user_ccache_file);

				result = add_ccache_to_list(principal_s,
							    cc,
							    service,
							    state->request->data.auth.user,
							    state->request->data.auth.pass,
							    realm,
							    uid,
							    time(NULL),
							    time(NULL) + lp_winbind_cache_time(),
							    time(NULL) + WINBINDD_PAM_AUTH_KRB5_RENEW_TIME,
							    true);

				if (!NT_STATUS_IS_OK(result)) {
					DEBUG(10,("winbindd_dual_pam_auth_cached: failed "
						"to add ccache to list: %s\n",
						nt_errstr(result)));
				}
			}
		}
#endif /* HAVE_KRB5 */
 success:
		/* FIXME: we possibly should handle logon hours as well (does xp when
		 * offline?) see auth/auth_sam.c:sam_account_ok for details */

		unix_to_nt_time(&my_info3->base.logon_time, time(NULL));
		my_info3->base.bad_password_count = 0;

		result = winbindd_update_creds_by_info3(domain,
							state->request->data.auth.user,
							state->request->data.auth.pass,
							my_info3);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(1,("winbindd_dual_pam_auth_cached: failed to update creds: %s\n",
				nt_errstr(result)));
			return result;
		}

		return NT_STATUS_OK;

	}

	/* User does *NOT* know the correct password, modify info3 accordingly, but only if online */
	if (domain->online == false) {
		goto failed;
	}

	/* failure of this is not critical */
	result = get_max_bad_attempts_from_lockout_policy(domain, state->mem_ctx, &max_allowed_bad_attempts);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("winbindd_dual_pam_auth_cached: failed to get max_allowed_bad_attempts. "
			  "Won't be able to honour account lockout policies\n"));
	}

	/* increase counter */
	my_info3->base.bad_password_count++;

	if (max_allowed_bad_attempts == 0) {
		goto failed;
	}

	/* lockout user */
	if (my_info3->base.bad_password_count >= max_allowed_bad_attempts) {

		uint32_t password_properties;

		result = get_pwd_properties(domain, state->mem_ctx, &password_properties);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("winbindd_dual_pam_auth_cached: failed to get password properties.\n"));
		}

		if ((my_info3->base.rid != DOMAIN_RID_ADMINISTRATOR) ||
		    (password_properties & DOMAIN_PASSWORD_LOCKOUT_ADMINS)) {
			my_info3->base.acct_flags |= ACB_AUTOLOCK;
		}
	}

failed:
	result = winbindd_update_creds_by_info3(domain,
						state->request->data.auth.user,
						NULL,
						my_info3);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("winbindd_dual_pam_auth_cached: failed to update creds %s\n",
			nt_errstr(result)));
	}

	return NT_STATUS_LOGON_FAILURE;
}

static NTSTATUS winbindd_dual_pam_auth_kerberos(struct winbindd_domain *domain,
						struct winbindd_cli_state *state,
						struct netr_SamInfo6 **info6)
{
	struct winbindd_domain *contact_domain;
	fstring name_namespace, name_domain, name_user;
	NTSTATUS result;
	bool ok;

	DEBUG(10,("winbindd_dual_pam_auth_kerberos\n"));

	/* Parse domain and username */

	ok = parse_domain_user(state->request->data.auth.user,
			       name_namespace,
			       name_domain,
			       name_user);
	if (!ok) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* what domain should we contact? */

	if (lp_winbind_use_krb5_enterprise_principals()) {
		contact_domain = find_auth_domain(0, name_namespace);
	} else {
		contact_domain = find_domain_from_name(name_namespace);
	}
	if (contact_domain == NULL) {
		DEBUG(3, ("Authentication for domain for [%s] -> [%s]\\[%s] failed as %s is not a trusted domain\n",
			  state->request->data.auth.user, name_domain, name_user, name_namespace));
		result = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	if (contact_domain->initialized &&
	    contact_domain->active_directory) {
	    	goto try_login;
	}

	if (!contact_domain->initialized) {
		init_dc_connection(contact_domain, false);
	}

	if (!contact_domain->active_directory) {
		DEBUG(3,("krb5 auth requested but domain (%s) is not Active Directory\n",
		      contact_domain->name));
		return NT_STATUS_INVALID_LOGON_TYPE;
	}
try_login:
	result = winbindd_raw_kerberos_login(
		state->mem_ctx, contact_domain,
		state->request->data.auth.user,
		state->request->data.auth.pass,
		state->request->data.auth.krb5_cc_type,
		get_uid_from_request(state->request),
		info6, state->response->data.auth.krb5ccname);
done:
	return result;
}

static NTSTATUS winbindd_dual_auth_passdb(TALLOC_CTX *mem_ctx,
					  uint32_t logon_parameters,
					  const char *domain,
					  const char *user,
					  const uint64_t logon_id,
					  const char *client_name,
					  const int client_pid,
					  const DATA_BLOB *challenge,
					  const DATA_BLOB *lm_resp,
					  const DATA_BLOB *nt_resp,
					  const struct tsocket_address *remote,
					  const struct tsocket_address *local,
					  bool interactive,
					  uint8_t *pauthoritative,
					  struct netr_SamInfo3 **pinfo3)
{
	struct auth_context *auth_context;
	struct auth_serversupplied_info *server_info;
	struct auth_usersupplied_info *user_info = NULL;
	struct netr_SamInfo3 *info3;
	NTSTATUS status;
	bool ok;
	TALLOC_CTX *frame = talloc_stackframe();

	/*
	 * We are authoritative by default
	 */
	*pauthoritative = 1;

	status = make_user_info(frame, &user_info, user, user, domain, domain,
				lp_netbios_name(), remote, local,
				"winbind",
				lm_resp, nt_resp, NULL, NULL,
				NULL, AUTH_PASSWORD_RESPONSE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("make_user_info failed: %s\n", nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	user_info->logon_parameters = logon_parameters;
	user_info->logon_id = logon_id;
	user_info->auth_description = talloc_asprintf(
		frame, "PASSDB, %s, %d", client_name, client_pid);
	if (user_info->auth_description == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* We don't want any more mapping of the username */
	user_info->mapped_state = True;

	/* We don't want to come back to winbindd or to do PAM account checks */
	user_info->flags |= USER_INFO_INFO3_AND_NO_AUTHZ;

	if (interactive) {
		user_info->flags |= USER_INFO_INTERACTIVE_LOGON;
	}

	status = make_auth3_context_for_winbind(frame, &auth_context);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("make_auth3_context_for_winbind failed: %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	ok = auth3_context_set_challenge(auth_context,
					 challenge->data, "fixed");
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_check_ntlm_password(mem_ctx,
					  auth_context,
					  user_info,
					  &server_info,
					  pauthoritative);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (info3 == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = serverinfo_to_SamInfo3(server_info, info3);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		TALLOC_FREE(info3);
		DEBUG(0, ("serverinfo_to_SamInfo3 failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	*pinfo3 = info3;
	DEBUG(10, ("Authenticaticating user %s\\%s returned %s\n", domain,
		   user, nt_errstr(status)));
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS winbind_samlogon_retry_loop(struct winbindd_domain *domain,
					    TALLOC_CTX *mem_ctx,
					    uint32_t logon_parameters,
					    const char *username,
					    const char *password,
					    const char *domainname,
					    const char *workstation,
					    const uint64_t logon_id,
					    bool plaintext_given,
					    const uint8_t chal[8],
					    DATA_BLOB lm_response,
					    DATA_BLOB nt_response,
					    bool interactive,
					    uint8_t *authoritative,
					    uint32_t *flags,
					    uint16_t *_validation_level,
					    union netr_Validation **_validation)
{
	int attempts = 0;
	int netr_attempts = 0;
	bool retry = false;
	NTSTATUS result;
	enum netr_LogonInfoClass logon_type_i;
	enum netr_LogonInfoClass logon_type_n;
	uint16_t validation_level = UINT16_MAX;
	union netr_Validation *validation = NULL;

	do {
		struct rpc_pipe_client *netlogon_pipe;
		struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;

		retry = false;

		result = cm_connect_netlogon_secure(domain, &netlogon_pipe,
						    &netlogon_creds_ctx);

		if (NT_STATUS_EQUAL(result,
				    NT_STATUS_CANT_ACCESS_DOMAIN_INFO)) {
			/*
			 * This means we don't have a trust account.
			 */
			*authoritative = 0;
			result = NT_STATUS_NO_SUCH_USER;
			break;
		}

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3,("Could not open handle to NETLOGON pipe "
				 "(error: %s, attempts: %d)\n",
				  nt_errstr(result), netr_attempts));

			/* After the first retry always close the connection */
			if (netr_attempts > 0) {
				DEBUG(3, ("This is again a problem for this "
					  "particular call, forcing the close "
					  "of this connection\n"));
				invalidate_cm_connection(domain);
			}

			/* After the second retry failover to the next DC */
			if (netr_attempts > 1) {
				/*
				 * If the netlogon server is not reachable then
				 * it is possible that the DC is rebuilding
				 * sysvol and shutdown netlogon for that time.
				 * We should failover to the next dc.
				 */
				DEBUG(3, ("This is the third problem for this "
					  "particular call, adding DC to the "
					  "negative cache list: %s %s\n", domain->name, domain->dcname));
				add_failed_connection_entry(domain->name,
							    domain->dcname,
							    result);
				saf_delete(domain->name);
			}

			/* Only allow 3 retries */
			if (netr_attempts < 3) {
				DEBUG(3, ("The connection to netlogon "
					  "failed, retrying\n"));
				netr_attempts++;
				retry = true;
				continue;
			}
			return result;
		}

		logon_type_i = NetlogonInteractiveInformation;
		logon_type_n = NetlogonNetworkInformation;
		if (domain->domain_trust_attribs & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
			logon_type_i = NetlogonInteractiveTransitiveInformation;
			logon_type_n = NetlogonNetworkTransitiveInformation;
		}

		if (domain->domain_trust_attribs & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			logon_type_i = NetlogonInteractiveTransitiveInformation;
			logon_type_n = NetlogonNetworkTransitiveInformation;
		}

		if (domain->domain_trust_attribs & LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE) {
			logon_type_i = NetlogonInteractiveInformation;
			logon_type_n = NetlogonNetworkInformation;
		}

		if (domain->domain_trust_attribs & LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) {
			logon_type_i = NetlogonInteractiveInformation;
			logon_type_n = NetlogonNetworkInformation;
		}

		netr_attempts = 0;
		if (plaintext_given) {
			result = rpccli_netlogon_password_logon(
				netlogon_creds_ctx,
				netlogon_pipe->binding_handle,
				mem_ctx,
				logon_parameters,
				domainname,
				username,
				password,
				workstation,
				logon_id,
				logon_type_i,
				authoritative,
				flags,
				&validation_level,
				&validation);
		} else if (interactive) {
			result = rpccli_netlogon_interactive_logon(
				netlogon_creds_ctx,
				netlogon_pipe->binding_handle,
				mem_ctx,
				logon_parameters,
				username,
				domainname,
				workstation,
				logon_id,
				lm_response,
				nt_response,
				logon_type_i,
				authoritative,
				flags,
				&validation_level,
				&validation);
		} else {
			result = rpccli_netlogon_network_logon(
				netlogon_creds_ctx,
				netlogon_pipe->binding_handle,
				mem_ctx,
				logon_parameters,
				username,
				domainname,
				workstation,
				logon_id,
				chal,
				lm_response,
				nt_response,
				logon_type_n,
				authoritative,
				flags,
				&validation_level,
				&validation);
		}

		/*
		 * we increment this after the "feature negotiation"
		 * for can_do_samlogon_ex and can_do_validation6
		 */
		attempts += 1;

		/* We have to try a second time as cm_connect_netlogon
		   might not yet have noticed that the DC has killed
		   our connection. */

		if (!rpccli_is_connected(netlogon_pipe)) {
			retry = true;
			continue;
		}

		/* if we get access denied, a possible cause was that we had
		   an open connection to the DC, but someone changed our
		   machine account password out from underneath us using 'net
		   rpc changetrustpw' */

		if ( NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) ) {
			DEBUG(1,("winbind_samlogon_retry_loop: sam_logon returned "
				 "ACCESS_DENIED.  Maybe the DC has Restrict "
				 "NTLM set or the trust account "
				"password was changed and we didn't know it. "
				 "Killing connections to domain %s\n",
				domainname));
			invalidate_cm_connection(domain);
			retry = true;
		}

		if (NT_STATUS_EQUAL(result, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
			/*
			 * Got DCERPC_FAULT_OP_RNG_ERROR for SamLogon
			 * (no Ex). This happens against old Samba
			 * DCs, if LogonSamLogonEx() fails with an error
			 * e.g. NT_STATUS_NO_SUCH_USER or NT_STATUS_WRONG_PASSWORD.
			 *
			 * The server will log something like this:
			 * api_net_sam_logon_ex: Failed to marshall NET_R_SAM_LOGON_EX.
			 *
			 * This sets the whole connection into a fault_state mode
			 * and all following request get NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE.
			 *
			 * This also happens to our retry with LogonSamLogonWithFlags()
			 * and LogonSamLogon().
			 *
			 * In order to recover from this situation, we need to
			 * drop the connection.
			 */
			invalidate_cm_connection(domain);
			result = NT_STATUS_LOGON_FAILURE;
			break;
		}

	} while ( (attempts < 2) && retry );

	if (NT_STATUS_EQUAL(result, NT_STATUS_IO_TIMEOUT)) {
		DEBUG(3,("winbind_samlogon_retry_loop: sam_network_logon(ex) "
				"returned NT_STATUS_IO_TIMEOUT after the retry. "
				"Killing connections to domain %s\n",
			domainname));
		invalidate_cm_connection(domain);
	}

	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	*_validation_level = validation_level;
	*_validation = validation;
	return NT_STATUS_OK;
}

static NTSTATUS nt_dual_auth_passdb(TALLOC_CTX *mem_ctx,
				    fstring name_user,
				    fstring name_domain,
				    const char *pass,
				    uint64_t logon_id,
				    const char *client_name,
				    const int client_pid,
				    const struct tsocket_address *remote,
				    const struct tsocket_address *local,
				    uint8_t *authoritative,
				    struct netr_SamInfo3 **info3)
{
	unsigned char local_nt_response[24];
	uchar chal[8];
	DATA_BLOB chal_blob;
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;

	/* do password magic */

	generate_random_buffer(chal, sizeof(chal));
	chal_blob = data_blob_const(chal, sizeof(chal));

	if (lp_client_ntlmv2_auth()) {
		DATA_BLOB server_chal;
		DATA_BLOB names_blob;
		server_chal = data_blob_const(chal, 8);

		/* note that the 'workgroup' here is for the local
		   machine.  The 'server name' must match the
		   'workstation' passed to the actual SamLogon call.
		*/
		names_blob = NTLMv2_generate_names_blob(mem_ctx,
							lp_netbios_name(),
							lp_workgroup());

		if (!SMBNTLMv2encrypt(mem_ctx, name_user, name_domain,
				      pass, &server_chal, &names_blob,
				      &lm_resp, &nt_resp, NULL, NULL)) {
			data_blob_free(&names_blob);
			DEBUG(0, ("SMBNTLMv2encrypt() failed!\n"));
			return NT_STATUS_NO_MEMORY;
		}
		data_blob_free(&names_blob);
	} else {
		int rc;
		lm_resp = data_blob_null;

		rc = SMBNTencrypt(pass, chal, local_nt_response);
		if (rc != 0) {
			DEBUG(0, ("SMBNTencrypt() failed!\n"));
			return gnutls_error_to_ntstatus(rc,
				    NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}

		nt_resp = data_blob_talloc(mem_ctx, local_nt_response,
					   sizeof(local_nt_response));
	}

	return winbindd_dual_auth_passdb(talloc_tos(), 0, name_domain,
					 name_user, logon_id, client_name,
					 client_pid, &chal_blob, &lm_resp,
					 &nt_resp, remote, local,
					 true, /* interactive */
					 authoritative, info3);
}

static NTSTATUS winbindd_dual_pam_auth_samlogon(
	TALLOC_CTX *mem_ctx,
	struct winbindd_domain *domain,
	const char *user,
	const char *pass,
	uint64_t logon_id,
	const char *client_name,
	const int client_pid,
	uint32_t request_flags,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	uint16_t *_validation_level,
	union netr_Validation **_validation)
{
	fstring name_namespace, name_domain, name_user;
	NTSTATUS result;
	uint8_t authoritative = 1;
	uint32_t flags = 0;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	struct netr_SamBaseInfo *base_info = NULL;
	bool ok;

	DEBUG(10,("winbindd_dual_pam_auth_samlogon\n"));

	/* Parse domain and username */

	ok = parse_domain_user(user, name_namespace, name_domain, name_user);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * We check against domain->name instead of
	 * name_domain, as find_auth_domain() ->
	 * find_domain_from_name_noinit() already decided
	 * that we are in a child for the correct domain.
	 *
	 * name_domain can also be lp_realm()
	 * we need to check against domain->name.
	 */
	if (strequal(domain->name, get_global_sam_name())) {
		struct netr_SamInfo3 *info3 = NULL;

		result = nt_dual_auth_passdb(mem_ctx, name_user, name_domain,
					     pass, logon_id, client_name,
					     client_pid, remote, local,
					     &authoritative, &info3);

		/*
		 * We need to try the remote NETLOGON server if this is
		 * not authoritative (for example on the RODC).
		 */
		if (authoritative != 0) {
			if (NT_STATUS_IS_OK(result)) {
				result = map_info3_to_validation(
						mem_ctx,
						info3,
						&validation_level,
						&validation);
				TALLOC_FREE(info3);
				if (!NT_STATUS_IS_OK(result)) {
					goto done;
				}
			}

			goto done;
		}
	}

	/* check authentication loop */

	result = winbind_samlogon_retry_loop(domain,
					     mem_ctx,
					     0,
					     name_user,
					     pass,
					     name_domain,
					     lp_netbios_name(),
					     logon_id,
					     true, /* plaintext_given */
					     NULL,
					     data_blob_null, data_blob_null,
					     true, /* interactive */
					     &authoritative,
					     &flags,
					     &validation_level,
					     &validation);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* handle the case where a NT4 DC does not fill in the acct_flags in
	 * the samlogon reply info3. When accurate info3 is required by the
	 * caller, we look up the account flags ourselves - gd */

	switch (validation_level) {
	case 3:
		base_info = &validation->sam3->base;
		break;
	case 6:
		base_info = &validation->sam6->base;
		break;
	default:
		DBG_ERR("Bad validation level %d", (int)validation_level);
		result = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	if ((request_flags & WBFLAG_PAM_INFO3_TEXT) &&
	    (base_info->acct_flags == 0))
	{
		struct rpc_pipe_client *samr_pipe;
		struct policy_handle samr_domain_handle, user_pol;
		union samr_UserInfo *info = NULL;
		NTSTATUS status_tmp, result_tmp;
		uint32_t acct_flags;
		struct dcerpc_binding_handle *b;

		status_tmp = cm_connect_sam(domain, mem_ctx, false,
					    &samr_pipe, &samr_domain_handle);

		if (!NT_STATUS_IS_OK(status_tmp)) {
			DEBUG(3, ("could not open handle to SAMR pipe: %s\n",
				nt_errstr(status_tmp)));
			goto done;
		}

		b = samr_pipe->binding_handle;

		status_tmp = dcerpc_samr_OpenUser(b, mem_ctx,
						  &samr_domain_handle,
						  MAXIMUM_ALLOWED_ACCESS,
						  base_info->rid,
						  &user_pol,
						  &result_tmp);

		if (!NT_STATUS_IS_OK(status_tmp)) {
			DEBUG(3, ("could not open user handle on SAMR pipe: %s\n",
				nt_errstr(status_tmp)));
			goto done;
		}
		if (!NT_STATUS_IS_OK(result_tmp)) {
			DEBUG(3, ("could not open user handle on SAMR pipe: %s\n",
				nt_errstr(result_tmp)));
			goto done;
		}

		status_tmp = dcerpc_samr_QueryUserInfo(b, mem_ctx,
						       &user_pol,
						       16,
						       &info,
						       &result_tmp);

		if (any_nt_status_not_ok(status_tmp, result_tmp,
					 &status_tmp)) {
			DEBUG(3, ("could not query user info on SAMR pipe: %s\n",
				nt_errstr(status_tmp)));
			dcerpc_samr_Close(b, mem_ctx, &user_pol, &result_tmp);
			goto done;
		}

		acct_flags = info->info16.acct_flags;

		if (acct_flags == 0) {
			dcerpc_samr_Close(b, mem_ctx, &user_pol, &result_tmp);
			goto done;
		}

		base_info->acct_flags = acct_flags;

		DEBUG(10,("successfully retrieved acct_flags 0x%x\n", acct_flags));

		dcerpc_samr_Close(b, mem_ctx, &user_pol, &result_tmp);
	}

done:
	if (NT_STATUS_IS_OK(result)) {
		*_validation_level = validation_level;
		*_validation = validation;
	}
	return result;
}

/*
 * @brief build a tsocket_address for the remote address of the supplied socket
 *
 */
static struct tsocket_address *get_remote_address(TALLOC_CTX *mem_ctx, int sock)
{
	struct sockaddr_storage st = {0};
	struct sockaddr *sar = (struct sockaddr *)&st;
	socklen_t sa_len = sizeof(st);
	struct tsocket_address *remote = NULL;
	int ret = 0;

	ret = getpeername(sock, sar, &sa_len);
	if (ret != 0) {
		DBG_ERR("getpeername failed - %s", strerror(errno));
		return NULL;
	}
	ret = tsocket_address_bsd_from_sockaddr(mem_ctx, sar, sa_len, &remote);
	if (ret != 0) {
		DBG_ERR("tsocket_address_bsd_from_sockaddr failed - %s",
			strerror(errno));
		return NULL;
	}
	return remote;
}

/*
 * @brief build a tsocket_address for the local address of the supplied socket
 *
 */
static struct tsocket_address *get_local_address(TALLOC_CTX *mem_ctx, int sock)
{
	struct sockaddr_storage st = {0};
	struct sockaddr *sar = (struct sockaddr *)&st;
	socklen_t sa_len = sizeof(st);
	struct tsocket_address *local = NULL;
	int ret = 0;

	ret = getsockname(sock, sar, &sa_len);
	if (ret != 0) {
		DBG_ERR("getsockname failed - %s", strerror(errno));
		return NULL;
	}
	ret = tsocket_address_bsd_from_sockaddr(mem_ctx, sar, sa_len, &local);
	if (ret != 0) {
		DBG_ERR("tsocket_address_bsd_from_sockaddr failed - %s",
			strerror(errno));
		return NULL;
	}
	return local;
}

/*
 * @brief generate an authentication message in the logs.
 *
 */
static void log_authentication(
	TALLOC_CTX *mem_ctx,
	const struct winbindd_domain *domain,
	const struct winbindd_cli_state *state,
	const struct timeval start_time,
	const uint64_t logon_id,
	const char *command,
	const char *user_name,
	const char *domain_name,
	const char *workstation,
	const DATA_BLOB lm_resp,
	const DATA_BLOB nt_resp,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	NTSTATUS result)
{

	struct auth_usersupplied_info *ui = NULL;
	struct dom_sid *sid = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct imessaging_context *msg_ctx = NULL;

	ui = talloc_zero(mem_ctx, struct auth_usersupplied_info);
	ui->logon_id = logon_id;
	ui->service_description = "winbind";
	ui->password.response.nt.length = nt_resp.length;
	ui->password.response.nt.data = nt_resp.data;
	ui->password.response.lanman.length = lm_resp.length;
	ui->password.response.lanman.data = lm_resp.data;
	if (nt_resp.length == 0 && lm_resp.length == 0) {
		ui->password_state = AUTH_PASSWORD_PLAIN;
	} else {
		ui->password_state = AUTH_PASSWORD_RESPONSE;
	}
	/*
	 * In the event of a failure ui->auth_description will be null,
	 * the logging code handles this correctly so it can be ignored.
	 */
	ui->auth_description = talloc_asprintf(
		ui,
		"%s, %s, %d",
		command,
		state->request->client_name,
		state->pid);
	if (ui->auth_description == NULL) {
		DBG_ERR("OOM Unable to create auth_description");
	}
	ui->client.account_name = user_name;
	ui->client.domain_name = domain_name;
	ui->workstation_name = workstation;
	ui->remote_host = remote;
	ui->local_host = local;

	sid = dom_sid_parse_talloc(
	    ui, state->response->data.auth.info3.dom_sid);
	if (sid != NULL) {
		sid_append_rid(sid, state->response->data.auth.info3.user_rid);
	}

	if (lp_auth_event_notification()) {
		lp_ctx = loadparm_init_s3(ui, loadparm_s3_helpers());
		msg_ctx = imessaging_client_init(
		    ui, lp_ctx, global_event_context());
	}
	log_authentication_event(
	    msg_ctx,
	    lp_ctx,
	    &start_time,
	    ui,
	    result,
	    state->response->data.auth.info3.logon_dom,
	    state->response->data.auth.info3.user_name,
	    sid);
	TALLOC_FREE(ui);
}

enum winbindd_result winbindd_dual_pam_auth(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	NTSTATUS result = NT_STATUS_LOGON_FAILURE;
	NTSTATUS krb5_result = NT_STATUS_OK;
	fstring name_namespace, name_domain, name_user;
	char *mapped_user;
	fstring domain_user;
	uint16_t validation_level = UINT16_MAX;
	union netr_Validation *validation = NULL;
	NTSTATUS name_map_status = NT_STATUS_UNSUCCESSFUL;
	bool ok;
	uint64_t logon_id = 0;
	const struct timeval start_time = timeval_current();
	const struct tsocket_address *remote = NULL;
	const struct tsocket_address *local = NULL;

	/* Ensure null termination */
	state->request->data.auth.user[sizeof(state->request->data.auth.user)-1]='\0';

	/* Ensure null termination */
	state->request->data.auth.pass[sizeof(state->request->data.auth.pass)-1]='\0';

	/*
	 * Generate a logon_id for this session.
	 */
	logon_id = generate_random_u64();
	remote = get_remote_address(state->mem_ctx, state->sock);
	local = get_local_address(state->mem_ctx, state->sock);
	DEBUG(3, ("[%5lu]: dual pam auth %s\n", (unsigned long)state->pid,
		  state->request->data.auth.user));

	/* Parse domain and username */

	name_map_status = normalize_name_unmap(state->mem_ctx,
					       state->request->data.auth.user,
					       &mapped_user);

	/* If the name normalization didn't actually do anything,
	   just use the original name */

	if (!NT_STATUS_IS_OK(name_map_status) &&
	    !NT_STATUS_EQUAL(name_map_status, NT_STATUS_FILE_RENAMED))
	{
		mapped_user = state->request->data.auth.user;
	}

	ok = parse_domain_user(mapped_user,
			       name_namespace,
			       name_domain,
			       name_user);
	if (!ok) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto process_result;
	}

	if ( mapped_user != state->request->data.auth.user ) {
		fstr_sprintf( domain_user, "%s%c%s", name_domain,
			*lp_winbind_separator(),
			name_user );
		strlcpy( state->request->data.auth.user, domain_user,
			     sizeof(state->request->data.auth.user));
	}

	if (!domain->online) {
		result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		if (domain->startup) {
			/* Logons are very important to users. If we're offline and
			   we get a request within the first 30 seconds of startup,
			   try very hard to find a DC and go online. */

			DEBUG(10,("winbindd_dual_pam_auth: domain: %s offline and auth "
				"request in startup mode.\n", domain->name ));

			winbindd_flush_negative_conn_cache(domain);
			result = init_dc_connection(domain, false);
		}
	}

	DEBUG(10,("winbindd_dual_pam_auth: domain: %s last was %s\n", domain->name, domain->online ? "online":"offline"));

	/* Check for Kerberos authentication */
	if (domain->online && (state->request->flags & WBFLAG_PAM_KRB5)) {
		struct netr_SamInfo6 *info6 = NULL;

		result = winbindd_dual_pam_auth_kerberos(domain, state, &info6);
		/* save for later */
		krb5_result = result;

		if (NT_STATUS_IS_OK(result)) {
			DEBUG(10,("winbindd_dual_pam_auth_kerberos succeeded\n"));

			result = map_info6_to_validation(state->mem_ctx,
							 info6,
							 &validation_level,
							 &validation);
			TALLOC_FREE(info6);
			if (!NT_STATUS_IS_OK(result)) {
				DBG_ERR("map_info6_to_validation failed\n");
				goto done;
			}
			goto process_result;
		}

		DBG_DEBUG("winbindd_dual_pam_auth_kerberos failed: %s\n",
			  nt_errstr(result));

		if (NT_STATUS_EQUAL(result, NT_STATUS_NO_LOGON_SERVERS) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_IO_TIMEOUT) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
			DEBUG(10,("winbindd_dual_pam_auth_kerberos setting domain to offline\n"));
			set_domain_offline( domain );
			goto cached_logon;
		}

		/* there are quite some NT_STATUS errors where there is no
		 * point in retrying with a samlogon, we explictly have to take
		 * care not to increase the bad logon counter on the DC */

		if (NT_STATUS_EQUAL(result, NT_STATUS_ACCOUNT_DISABLED) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_ACCOUNT_EXPIRED) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_ACCOUNT_LOCKED_OUT) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_INVALID_LOGON_HOURS) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_INVALID_WORKSTATION) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_LOGON_FAILURE) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_NO_SUCH_USER) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_PASSWORD_EXPIRED) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_PASSWORD_MUST_CHANGE) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_WRONG_PASSWORD)) {
			goto done;
		}

		if (state->request->flags & WBFLAG_PAM_FALLBACK_AFTER_KRB5) {
			DEBUG(3,("falling back to samlogon\n"));
			goto sam_logon;
		} else {
			goto cached_logon;
		}
	}

sam_logon:
	/* Check for Samlogon authentication */
	if (domain->online) {
		struct netr_SamBaseInfo *base_info = NULL;

		result = winbindd_dual_pam_auth_samlogon(
			state->mem_ctx, domain,
			state->request->data.auth.user,
			state->request->data.auth.pass,
			logon_id,
			state->request->client_name,
			state->pid,
			state->request->flags,
			remote,
			local,
			&validation_level,
			&validation);

		if (NT_STATUS_IS_OK(result)) {
			DEBUG(10,("winbindd_dual_pam_auth_samlogon succeeded\n"));

			switch (validation_level) {
			case 3:
				base_info = &validation->sam3->base;
				break;
			case 6:
				base_info = &validation->sam6->base;
				break;
			default:
				DBG_ERR("Bad validation level %d\n",
					validation_level);
				result = NT_STATUS_INTERNAL_ERROR;
				goto done;
			}

			/* add the Krb5 err if we have one */
			if ( NT_STATUS_EQUAL(krb5_result, NT_STATUS_TIME_DIFFERENCE_AT_DC ) ) {
				base_info->user_flags |= LOGON_KRB5_FAIL_CLOCK_SKEW;
			}

			goto process_result;
		}

		DEBUG(10,("winbindd_dual_pam_auth_samlogon failed: %s\n",
			  nt_errstr(result)));

		if (NT_STATUS_EQUAL(result, NT_STATUS_NO_LOGON_SERVERS) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_IO_TIMEOUT) ||
		    NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND))
		{
			DEBUG(10,("winbindd_dual_pam_auth_samlogon setting domain to offline\n"));
			set_domain_offline( domain );
			goto cached_logon;
		}

		if (domain->online) {
			/* We're still online - fail. */
			goto done;
		}
	}

cached_logon:
	/* Check for Cached logons */
	if (!domain->online && (state->request->flags & WBFLAG_PAM_CACHED_LOGIN) &&
	    lp_winbind_offline_logon()) {
		struct netr_SamInfo3 *info3 = NULL;

		result = winbindd_dual_pam_auth_cached(domain, state, &info3);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10,("winbindd_dual_pam_auth_cached failed: %s\n", nt_errstr(result)));
			goto done;
		}
		DEBUG(10,("winbindd_dual_pam_auth_cached succeeded\n"));

		result = map_info3_to_validation(state->mem_ctx,
						 info3,
						 &validation_level,
						 &validation);
		TALLOC_FREE(info3);
		if (!NT_STATUS_IS_OK(result)) {
			DBG_ERR("map_info3_to_validation failed\n");
			goto done;
		}
	}

process_result:

	if (NT_STATUS_IS_OK(result)) {
		struct dom_sid user_sid;
		TALLOC_CTX *base_ctx = NULL;
		struct netr_SamBaseInfo *base_info = NULL;
		struct netr_SamInfo3 *info3 = NULL;

		switch (validation_level) {
		case 3:
			base_ctx = validation->sam3;
			base_info = &validation->sam3->base;
			break;
		case 6:
			base_ctx = validation->sam6;
			base_info = &validation->sam6->base;
			break;
		default:
			result = NT_STATUS_INTERNAL_ERROR;
			goto done;
		}

		sid_compose(&user_sid, base_info->domain_sid, base_info->rid);

		if (base_info->full_name.string == NULL) {
			struct netr_SamInfo3 *cached_info3;

			cached_info3 = netsamlogon_cache_get(state->mem_ctx,
							     &user_sid);
			if (cached_info3 != NULL &&
			    cached_info3->base.full_name.string != NULL) {
				base_info->full_name.string = talloc_strdup(
					base_ctx,
					cached_info3->base.full_name.string);
				if (base_info->full_name.string == NULL) {
					result = NT_STATUS_NO_MEMORY;
					goto done;
				}
			} else {

				/* this might fail so we don't check the return code */
				wcache_query_user_fullname(domain,
						base_ctx,
						&user_sid,
						&base_info->full_name.string);
			}
		}

		result = map_validation_to_info3(talloc_tos(),
						 validation_level,
						 validation,
						 &info3);
		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}

		wcache_invalidate_samlogon(find_domain_from_name(name_domain),
					   &user_sid);
		netsamlogon_cache_store(name_user, info3);

		/* save name_to_sid info as early as possible (only if
		   this is our primary domain so we don't invalidate
		   the cache entry by storing the seq_num for the wrong
		   domain). */
		if ( domain->primary ) {
			cache_name2sid(domain, name_domain, name_user,
				       SID_NAME_USER, &user_sid);
		}

		/* Check if the user is in the right group */

		result = check_info3_in_group(
			info3,
			state->request->data.auth.require_membership_of_sid);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3, ("User %s is not in the required group (%s), so plaintext authentication is rejected\n",
				  state->request->data.auth.user,
				  state->request->data.auth.require_membership_of_sid));
			goto done;
		}

		if (!is_allowed_domain(info3->base.logon_domain.string)) {
			DBG_NOTICE("Authentication failed for user [%s] "
				   "from firewalled domain [%s]\n",
				   info3->base.account_name.string,
				   info3->base.logon_domain.string);
			result = NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
			goto done;
		}

		result = append_auth_data(state->mem_ctx, state->response,
					  state->request->flags,
					  validation_level,
					  validation,
					  name_domain, name_user);
		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}

		if ((state->request->flags & WBFLAG_PAM_CACHED_LOGIN)
		    && lp_winbind_offline_logon()) {

			result = winbindd_store_creds(domain,
						      state->request->data.auth.user,
						      state->request->data.auth.pass,
						      info3);
		}

		if (state->request->flags & WBFLAG_PAM_GET_PWD_POLICY) {
			/*
			 * WBFLAG_PAM_GET_PWD_POLICY is not used within
			 * any Samba caller anymore.
			 *
			 * We just fake this based on the effective values
			 * for the user, for legacy callers.
			 */
			fake_password_policy(state->response, &info3->base);
		}

		result = NT_STATUS_OK;
	}

done:
	/* give us a more useful (more correct?) error code */
	if ((NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) ||
	    (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))) {
		result = NT_STATUS_NO_LOGON_SERVERS;
	}

	/*
	 * Here we don't alter
	 * state->response->data.auth.authoritative based
	 * on the servers response
	 * as we don't want a fallback to the local sam
	 * for interactive PAM logons
	 */
	set_auth_errors(state->response, result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, ("Plain-text authentication for user %s returned %s (PAM: %d)\n",
	      state->request->data.auth.user,
	      state->response->data.auth.nt_status_string,
	      state->response->data.auth.pam_error));

	/*
	 * Log the winbind pam authentication, the logon_id will tie this to
	 * any of the logons invoked from this request.
	 */
	log_authentication(
	    state->mem_ctx,
	    domain,
	    state,
	    start_time,
	    logon_id,
	    "PAM_AUTH",
	    name_user,
	    name_domain,
	    NULL,
	    data_blob_null,
	    data_blob_null,
	    remote,
	    local,
	    result);

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

NTSTATUS winbind_dual_SamLogon(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       bool interactive,
			       uint32_t logon_parameters,
			       const char *name_user,
			       const char *name_domain,
			       const char *workstation,
			       const uint64_t logon_id,
			       const char* client_name,
			       const int client_pid,
			       const uint8_t chal[8],
			       DATA_BLOB lm_response,
			       DATA_BLOB nt_response,
			       const struct tsocket_address *remote,
			       const struct tsocket_address *local,
			       uint8_t *authoritative,
			       bool skip_sam,
			       uint32_t *flags,
			       uint16_t *_validation_level,
			       union netr_Validation **_validation)
{
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	NTSTATUS result;

	/*
	 * We check against domain->name instead of
	 * name_domain, as find_auth_domain() ->
	 * find_domain_from_name_noinit() already decided
	 * that we are in a child for the correct domain.
	 *
	 * name_domain can also be lp_realm()
	 * we need to check against domain->name.
	 */
	if (!skip_sam && strequal(domain->name, get_global_sam_name())) {
		DATA_BLOB chal_blob = data_blob_const(
			chal, 8);
		struct netr_SamInfo3 *info3 = NULL;

		result = winbindd_dual_auth_passdb(
			talloc_tos(),
			logon_parameters,
			name_domain, name_user,
			logon_id,
			client_name,
			client_pid,
			&chal_blob, &lm_response, &nt_response,
			remote,
			local,
			interactive,
			authoritative,
			&info3);
		if (NT_STATUS_IS_OK(result)) {
			result = map_info3_to_validation(mem_ctx,
							 info3,
							 &validation_level,
							 &validation);
			TALLOC_FREE(info3);
			if (!NT_STATUS_IS_OK(result)) {
				goto done;
			}
		}

		/*
		 * We need to try the remote NETLOGON server if this is
		 * not authoritative.
		 */
		if (*authoritative != 0) {
			*flags = 0;
			goto process_result;
		}
	}

	result = winbind_samlogon_retry_loop(domain,
					     mem_ctx,
					     logon_parameters,
					     name_user,
					     NULL, /* password */
					     name_domain,
					     /* Bug #3248 - found by Stefan Burkei. */
					     workstation, /* We carefully set this above so use it... */
					     logon_id,
					     false, /* plaintext_given */
					     chal,
					     lm_response,
					     nt_response,
					     interactive,
					     authoritative,
					     flags,
					     &validation_level,
					     &validation);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

process_result:

	if (NT_STATUS_IS_OK(result)) {
		struct dom_sid user_sid;
		TALLOC_CTX *base_ctx = NULL;
		struct netr_SamBaseInfo *base_info = NULL;
		struct netr_SamInfo3 *info3 = NULL;

		switch (validation_level) {
		case 3:
			base_ctx = validation->sam3;
			base_info = &validation->sam3->base;
			break;
		case 6:
			base_ctx = validation->sam6;
			base_info = &validation->sam6->base;
			break;
		default:
			result = NT_STATUS_INTERNAL_ERROR;
			goto done;
		}

		sid_compose(&user_sid, base_info->domain_sid, base_info->rid);

		if (base_info->full_name.string == NULL) {
			struct netr_SamInfo3 *cached_info3;

			cached_info3 = netsamlogon_cache_get(mem_ctx,
							     &user_sid);
			if (cached_info3 != NULL &&
			    cached_info3->base.full_name.string != NULL)
			{
				base_info->full_name.string = talloc_strdup(
					base_ctx,
					cached_info3->base.full_name.string);
			} else {

				/* this might fail so we don't check the return code */
				wcache_query_user_fullname(domain,
						base_ctx,
						&user_sid,
						&base_info->full_name.string);
			}
		}

		result = map_validation_to_info3(talloc_tos(),
						 validation_level,
						 validation,
						 &info3);
		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}
		wcache_invalidate_samlogon(find_domain_from_name(name_domain),
					   &user_sid);
		netsamlogon_cache_store(name_user, info3);
		TALLOC_FREE(info3);
	}

done:

	/* give us a more useful (more correct?) error code */
	if ((NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) ||
	    (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))) {
		result = NT_STATUS_NO_LOGON_SERVERS;
	}

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2,
	      ("NTLM CRAP authentication for user [%s]\\[%s] returned %s\n",
	       name_domain,
	       name_user,
	       nt_errstr(result)));

	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	*_validation_level = validation_level;
	*_validation = validation;
	return NT_STATUS_OK;
}

enum winbindd_result winbindd_dual_pam_auth_crap(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state)
{
	NTSTATUS result;
	const char *name_user = NULL;
	const char *name_domain = NULL;
	const char *workstation;
	uint64_t logon_id = 0;
	uint8_t authoritative = 1;
	uint32_t flags = 0;
	uint16_t validation_level;
	union netr_Validation *validation = NULL;
	DATA_BLOB lm_resp = { 0 }, nt_resp = { 0 };
	const struct timeval start_time = timeval_current();
	const struct tsocket_address *remote = NULL;
	const struct tsocket_address *local = NULL;

	/* This is child-only, so no check for privileged access is needed
	   anymore */

	/* Ensure null termination */
	state->request->data.auth_crap.user[sizeof(state->request->data.auth_crap.user)-1]=0;
	state->request->data.auth_crap.domain[sizeof(state->request->data.auth_crap.domain)-1]=0;

	name_user = state->request->data.auth_crap.user;
	name_domain = state->request->data.auth_crap.domain;
	workstation = state->request->data.auth_crap.workstation;
	logon_id = generate_random_u64();
	remote = get_remote_address(state->mem_ctx, state->sock);
	local = get_local_address(state->mem_ctx, state->sock);

	DEBUG(3, ("[%5lu]: pam auth crap domain: %s user: %s\n", (unsigned long)state->pid,
		  name_domain, name_user));

	if (state->request->data.auth_crap.lm_resp_len > sizeof(state->request->data.auth_crap.lm_resp)
		|| state->request->data.auth_crap.nt_resp_len > sizeof(state->request->data.auth_crap.nt_resp)) {
		if (!(state->request->flags & WBFLAG_BIG_NTLMV2_BLOB) ||
		     state->request->extra_len != state->request->data.auth_crap.nt_resp_len) {
			DEBUG(0, ("winbindd_pam_auth_crap: invalid password length %u/%u\n",
				  state->request->data.auth_crap.lm_resp_len,
				  state->request->data.auth_crap.nt_resp_len));
			result = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}
	}

	lm_resp = data_blob_talloc(state->mem_ctx, state->request->data.auth_crap.lm_resp,
					state->request->data.auth_crap.lm_resp_len);

	if (state->request->flags & WBFLAG_BIG_NTLMV2_BLOB) {
		nt_resp = data_blob_talloc(state->mem_ctx,
					   state->request->extra_data.data,
					   state->request->data.auth_crap.nt_resp_len);
	} else {
		nt_resp = data_blob_talloc(state->mem_ctx,
					   state->request->data.auth_crap.nt_resp,
					   state->request->data.auth_crap.nt_resp_len);
	}

	result = winbind_dual_SamLogon(domain,
				       state->mem_ctx,
				       false, /* interactive */
				       state->request->data.auth_crap.logon_parameters,
				       name_user,
				       name_domain,
				       /* Bug #3248 - found by Stefan Burkei. */
				       workstation, /* We carefully set this above so use it... */
				       logon_id,
				       state->request->client_name,
				       state->request->pid,
				       state->request->data.auth_crap.chal,
				       lm_resp,
				       nt_resp,
				       remote,
				       local,
				       &authoritative,
				       false,
				       &flags,
				       &validation_level,
				       &validation);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (NT_STATUS_IS_OK(result)) {
		struct netr_SamInfo3 *info3 = NULL;

		result = map_validation_to_info3(state->mem_ctx,
						 validation_level,
						 validation,
						 &info3);
		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}

		/* Check if the user is in the right group */
		result = check_info3_in_group(
			info3,
			state->request->data.auth_crap.require_membership_of_sid);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3, ("User %s is not in the required group (%s), so "
				  "crap authentication is rejected\n",
				  state->request->data.auth_crap.user,
				  state->request->data.auth_crap.require_membership_of_sid));
			goto done;
		}

		if (!is_allowed_domain(info3->base.logon_domain.string)) {
			DBG_NOTICE("Authentication failed for user [%s] "
				   "from firewalled domain [%s]\n",
				   info3->base.account_name.string,
				   info3->base.logon_domain.string);
			result = NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
			goto done;
		}

		result = append_auth_data(state->mem_ctx, state->response,
					  state->request->flags,
					  validation_level,
					  validation,
					  name_domain, name_user);
		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}
	}

done:

	if (state->request->flags & WBFLAG_PAM_NT_STATUS_SQUASH) {
		result = nt_status_squash(result);
	}

	set_auth_errors(state->response, result);
	state->response->data.auth.authoritative = authoritative;

	/*
	 * Log the winbind pam authentication, the logon_id will tie this to
	 * any of the logons invoked from this request.
	 */
	log_authentication(
	    state->mem_ctx,
	    domain,
	    state,
	    start_time,
	    logon_id,
	    "NTLM_AUTH",
	    name_user,
	    name_domain,
	    workstation,
	    lm_resp,
            nt_resp,
	    remote,
	    local,
	    result);

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

enum winbindd_result winbindd_dual_pam_chauthtok(struct winbindd_domain *contact_domain,
						 struct winbindd_cli_state *state)
{
	char *oldpass;
	char *newpass = NULL;
	struct policy_handle dom_pol;
	struct rpc_pipe_client *cli = NULL;
	bool got_info = false;
	struct samr_DomInfo1 *info = NULL;
	struct userPwdChangeFailureInformation *reject = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	fstring namespace, domain, user;
	struct dcerpc_binding_handle *b = NULL;
	bool ok;

	ZERO_STRUCT(dom_pol);

	DEBUG(3, ("[%5lu]: dual pam chauthtok %s\n", (unsigned long)state->pid,
		  state->request->data.auth.user));

	ok = parse_domain_user(state->request->data.chauthtok.user,
			       namespace,
			       domain,
			       user);
	if (!ok) {
		goto done;
	}

	if (!is_allowed_domain(domain)) {
		DBG_NOTICE("Authentication failed for user [%s] "
			   "from firewalled domain [%s]\n",
			   user, domain);
		result = NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
		goto done;
	}

	/* Change password */

	oldpass = state->request->data.chauthtok.oldpass;
	newpass = state->request->data.chauthtok.newpass;

	/* Initialize reject reason */
	state->response->data.auth.reject_reason = Undefined;

	/* Get sam handle */

	result = cm_connect_sam(contact_domain, state->mem_ctx, true, &cli,
				&dom_pol);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("could not get SAM handle on DC for %s\n", domain));
		goto done;
	}

	b = cli->binding_handle;

	result = rpccli_samr_chgpasswd_user3(cli, state->mem_ctx,
					     user,
					     newpass,
					     oldpass,
					     &info,
					     &reject);

 	/* Windows 2003 returns NT_STATUS_PASSWORD_RESTRICTION */

	if (NT_STATUS_EQUAL(result, NT_STATUS_PASSWORD_RESTRICTION) ) {

		fill_in_password_policy(state->response, info);

		state->response->data.auth.reject_reason =
			reject->extendedFailureReason;

		got_info = true;
	}

	/* atm the pidl generated rpccli_samr_ChangePasswordUser3 function will
	 * return with NT_STATUS_BUFFER_TOO_SMALL for w2k dcs as w2k just
	 * returns with 4byte error code (NT_STATUS_NOT_SUPPORTED) which is too
	 * short to comply with the samr_ChangePasswordUser3 idl - gd */

	/* only fallback when the chgpasswd_user3 call is not supported */
	if (NT_STATUS_EQUAL(result, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE) ||
	    NT_STATUS_EQUAL(result, NT_STATUS_NOT_SUPPORTED) ||
	    NT_STATUS_EQUAL(result, NT_STATUS_BUFFER_TOO_SMALL) ||
	    NT_STATUS_EQUAL(result, NT_STATUS_NOT_IMPLEMENTED)) {

		DEBUG(10,("Password change with chgpasswd_user3 failed with: %s, retrying chgpasswd_user2\n",
			nt_errstr(result)));

		result = rpccli_samr_chgpasswd_user2(cli, state->mem_ctx, user, newpass, oldpass);

		/* Windows 2000 returns NT_STATUS_ACCOUNT_RESTRICTION.
		   Map to the same status code as Windows 2003. */

		if ( NT_STATUS_EQUAL(NT_STATUS_ACCOUNT_RESTRICTION, result ) ) {
			result = NT_STATUS_PASSWORD_RESTRICTION;
		}
	}

done:

	if (NT_STATUS_IS_OK(result)
	    && (state->request->flags & WBFLAG_PAM_CACHED_LOGIN)
	    && lp_winbind_offline_logon()) {
		result = winbindd_update_creds_by_name(contact_domain, user,
						       newpass);
		/* Again, this happens when we login from gdm or xdm
		 * and the password expires, *BUT* cached crendentials
		 * doesn't exist. winbindd_update_creds_by_name()
		 * returns NT_STATUS_NO_SUCH_USER.
		 * This is not a failure.
		 * --- BoYang
		 * */
		if (NT_STATUS_EQUAL(result, NT_STATUS_NO_SUCH_USER)) {
			result = NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(10, ("Failed to store creds: %s\n",
				   nt_errstr(result)));
			goto process_result;
		}
	}

	if (!NT_STATUS_IS_OK(result) && !got_info && contact_domain) {

		NTSTATUS policy_ret;

		policy_ret = fillup_password_policy(
			contact_domain, state->response);

		/* failure of this is non critical, it will just provide no
		 * additional information to the client why the change has
		 * failed - Guenther */

		if (!NT_STATUS_IS_OK(policy_ret)) {
			DEBUG(10,("Failed to get password policies: %s\n", nt_errstr(policy_ret)));
			goto process_result;
		}
	}

process_result:

	if (strequal(contact_domain->name, get_global_sam_name())) {
		/* FIXME: internal rpc pipe does not cache handles yet */
		if (b) {
			if (is_valid_policy_hnd(&dom_pol)) {
				NTSTATUS _result;
				dcerpc_samr_Close(b, state->mem_ctx, &dom_pol, &_result);
			}
			TALLOC_FREE(cli);
		}
	}

	set_auth_errors(state->response, result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2,
	      ("Password change for user [%s]\\[%s] returned %s (PAM: %d)\n",
	       domain,
	       user,
	       state->response->data.auth.nt_status_string,
	       state->response->data.auth.pam_error));

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

enum winbindd_result winbindd_dual_pam_logoff(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state)
{
	NTSTATUS result = NT_STATUS_NOT_SUPPORTED;

	DEBUG(3, ("[%5lu]: pam dual logoff %s\n", (unsigned long)state->pid,
		state->request->data.logoff.user));

	if (!(state->request->flags & WBFLAG_PAM_KRB5)) {
		result = NT_STATUS_OK;
		goto process_result;
	}

	if (state->request->data.logoff.krb5ccname[0] == '\0') {
		result = NT_STATUS_OK;
		goto process_result;
	}

#ifdef HAVE_KRB5

	if (state->request->data.logoff.uid == (uid_t)-1) {
		DEBUG(0,("winbindd_pam_logoff: invalid uid\n"));
		goto process_result;
	}

	/* what we need here is to find the corresponding krb5 ccache name *we*
	 * created for a given username and destroy it */

	if (!ccache_entry_exists(state->request->data.logoff.user)) {
		result = NT_STATUS_OK;
		DEBUG(10,("winbindd_pam_logoff: no entry found.\n"));
		goto process_result;
	}

	if (!ccache_entry_identical(state->request->data.logoff.user,
					state->request->data.logoff.uid,
					state->request->data.logoff.krb5ccname)) {
		DEBUG(0,("winbindd_pam_logoff: cached entry differs.\n"));
		goto process_result;
	}

	result = remove_ccache(state->request->data.logoff.user);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("winbindd_pam_logoff: failed to remove ccache: %s\n",
			nt_errstr(result)));
		goto process_result;
	}

	/*
	 * Remove any mlock'ed memory creds in the child
	 * we might be using for krb5 ticket renewal.
	 */

	winbindd_delete_memory_creds(state->request->data.logoff.user);

#else
	result = NT_STATUS_NOT_SUPPORTED;
#endif

process_result:


	set_auth_errors(state->response, result);

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* Change user password with auth crap*/

enum winbindd_result winbindd_dual_pam_chng_pswd_auth_crap(struct winbindd_domain *domainSt, struct winbindd_cli_state *state)
{
	NTSTATUS result;
	DATA_BLOB new_nt_password;
	DATA_BLOB old_nt_hash_enc;
	DATA_BLOB new_lm_password;
	DATA_BLOB old_lm_hash_enc;
	fstring  namespace, domain, user;
	struct policy_handle dom_pol;
	struct winbindd_domain *contact_domain = domainSt;
	struct rpc_pipe_client *cli = NULL;
	struct dcerpc_binding_handle *b = NULL;

	ZERO_STRUCT(dom_pol);

	/* Ensure null termination */
	state->request->data.chng_pswd_auth_crap.user[
		sizeof(state->request->data.chng_pswd_auth_crap.user)-1]=0;
	state->request->data.chng_pswd_auth_crap.domain[
		sizeof(state->request->data.chng_pswd_auth_crap.domain)-1]=0;
	domain[0] = '\0';
	namespace[0] = '\0';
	user[0] = '\0';

	DEBUG(3, ("[%5lu]: pam change pswd auth crap domain: %s user: %s\n",
		  (unsigned long)state->pid,
		  state->request->data.chng_pswd_auth_crap.domain,
		  state->request->data.chng_pswd_auth_crap.user));

	if (lp_winbind_offline_logon()) {
		DEBUG(0,("Refusing password change as winbind offline logons are enabled. "));
		DEBUGADD(0,("Changing passwords here would risk inconsistent logons\n"));
		result = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	if (*state->request->data.chng_pswd_auth_crap.domain) {
		fstrcpy(domain,state->request->data.chng_pswd_auth_crap.domain);
	} else {
		bool ok;

		ok = parse_domain_user(state->request->data.chng_pswd_auth_crap.user,
				       namespace,
				       domain,
				       user);
		if (!ok) {
			result = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

		if(!*domain) {
			DEBUG(3,("no domain specified with username (%s) - "
				 "failing auth\n",
				 state->request->data.chng_pswd_auth_crap.user));
			result = NT_STATUS_NO_SUCH_USER;
			goto done;
		}
	}

	if (!*domain && lp_winbind_use_default_domain()) {
		fstrcpy(domain,lp_workgroup());
	}

	if (!is_allowed_domain(domain)) {
		DBG_NOTICE("Authentication failed for user [%s] "
			   "from firewalled domain [%s]\n",
			   state->request->data.chng_pswd_auth_crap.user,
			   domain);
		result = NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
		goto done;
	}

	if(!*user) {
		fstrcpy(user, state->request->data.chng_pswd_auth_crap.user);
	}

	DEBUG(3, ("[%5lu]: pam auth crap domain: %s user: %s\n",
		  (unsigned long)state->pid, domain, user));

	/* Change password */
	new_nt_password = data_blob_const(
		state->request->data.chng_pswd_auth_crap.new_nt_pswd,
		state->request->data.chng_pswd_auth_crap.new_nt_pswd_len);

	old_nt_hash_enc = data_blob_const(
		state->request->data.chng_pswd_auth_crap.old_nt_hash_enc,
		state->request->data.chng_pswd_auth_crap.old_nt_hash_enc_len);

	if(state->request->data.chng_pswd_auth_crap.new_lm_pswd_len > 0)	{
		new_lm_password = data_blob_const(
			state->request->data.chng_pswd_auth_crap.new_lm_pswd,
			state->request->data.chng_pswd_auth_crap.new_lm_pswd_len);

		old_lm_hash_enc = data_blob_const(
			state->request->data.chng_pswd_auth_crap.old_lm_hash_enc,
			state->request->data.chng_pswd_auth_crap.old_lm_hash_enc_len);
	} else {
		new_lm_password = data_blob_null;
		old_lm_hash_enc = data_blob_null;
	}

	/* Get sam handle */

	result = cm_connect_sam(contact_domain, state->mem_ctx, true, &cli, &dom_pol);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("could not get SAM handle on DC for %s\n", domain));
		goto done;
	}

	b = cli->binding_handle;

	result = rpccli_samr_chng_pswd_auth_crap(
		cli, state->mem_ctx, user, new_nt_password, old_nt_hash_enc,
		new_lm_password, old_lm_hash_enc);

 done:

	if (strequal(contact_domain->name, get_global_sam_name())) {
		/* FIXME: internal rpc pipe does not cache handles yet */
		if (b) {
			if (is_valid_policy_hnd(&dom_pol)) {
				NTSTATUS _result;
				dcerpc_samr_Close(b, state->mem_ctx, &dom_pol, &_result);
			}
			TALLOC_FREE(cli);
		}
	}

	set_auth_errors(state->response, result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2,
	      ("Password change for user [%s]\\[%s] returned %s (PAM: %d)\n",
	       domain, user,
	       state->response->data.auth.nt_status_string,
	       state->response->data.auth.pam_error));

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

#ifdef HAVE_KRB5
static NTSTATUS extract_pac_vrfy_sigs(TALLOC_CTX *mem_ctx, DATA_BLOB pac_blob,
				      struct PAC_DATA **p_pac_data)
{
	krb5_context krbctx = NULL;
	krb5_error_code k5ret;
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(entry);
	ZERO_STRUCT(cursor);

	k5ret = smb_krb5_init_context_common(&krbctx);
	if (k5ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(k5ret));
		status = krb5_to_nt_status(k5ret);
		goto out;
	}

	k5ret =  gse_krb5_get_server_keytab(krbctx, &keytab);
	if (k5ret) {
		DEBUG(1, ("Failed to get keytab: %s\n",
			  error_message(k5ret)));
		status = krb5_to_nt_status(k5ret);
		goto out_free;
	}

	k5ret = krb5_kt_start_seq_get(krbctx, keytab, &cursor);
	if (k5ret) {
		DEBUG(1, ("Failed to start seq: %s\n",
			  error_message(k5ret)));
		status = krb5_to_nt_status(k5ret);
		goto out_keytab;
	}

	k5ret = krb5_kt_next_entry(krbctx, keytab, &entry, &cursor);
	while (k5ret == 0) {
		status = kerberos_decode_pac(mem_ctx,
					     pac_blob,
					     krbctx,
					     NULL, /* krbtgt_keyblock */
					     KRB5_KT_KEY(&entry), /* service_keyblock */
					     NULL, /* client_principal */
					     0, /* tgs_authtime */
					     p_pac_data);
		if (NT_STATUS_IS_OK(status)) {
			break;
		}
		k5ret = smb_krb5_kt_free_entry(krbctx, &entry);
		k5ret = krb5_kt_next_entry(krbctx, keytab, &entry, &cursor);
	}

	k5ret = krb5_kt_end_seq_get(krbctx, keytab, &cursor);
	if (k5ret) {
		DEBUG(1, ("Failed to end seq: %s\n",
			  error_message(k5ret)));
	}
out_keytab:
	k5ret = krb5_kt_close(krbctx, keytab);
	if (k5ret) {
		DEBUG(1, ("Failed to close keytab: %s\n",
			  error_message(k5ret)));
	}
out_free:
	krb5_free_context(krbctx);
out:
	return status;
}

NTSTATUS winbindd_pam_auth_pac_verify(struct winbindd_cli_state *state,
				      bool *p_is_trusted,
				      uint16_t *p_validation_level,
				      union netr_Validation **p_validation)
{
	struct winbindd_request *req = state->request;
	DATA_BLOB pac_blob;
	struct PAC_DATA *pac_data = NULL;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct PAC_UPN_DNS_INFO *upn_dns_info = NULL;
	struct netr_SamInfo6 *info6 = NULL;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	struct netr_SamInfo3 *info3_copy = NULL;
	NTSTATUS result;
	bool is_trusted = false;
	uint32_t i;

	*p_is_trusted = false;
	*p_validation_level = 0;
	*p_validation = NULL;

	pac_blob = data_blob_const(req->extra_data.data, req->extra_len);
	result = extract_pac_vrfy_sigs(state->mem_ctx, pac_blob, &pac_data);
	if (NT_STATUS_IS_OK(result)) {
		is_trusted = true;
	}
	if (NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED)) {
		/* Try without signature verification */
		result = kerberos_decode_pac(state->mem_ctx,
					     pac_blob,
					     NULL, /* krb5_context */
					     NULL, /* krbtgt_keyblock */
					     NULL, /* service_keyblock */
					     NULL, /* client_principal */
					     0, /* tgs_authtime */
					     &pac_data);
	}
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("Error during PAC signature verification: %s\n",
			  nt_errstr(result)));
		return result;
	}

	for (i=0; i < pac_data->num_buffers; i++) {
		if (pac_data->buffers[i].type == PAC_TYPE_LOGON_INFO) {
			logon_info = pac_data->buffers[i].info->logon_info.info;
			continue;
		}
		if (pac_data->buffers[i].type == PAC_TYPE_UPN_DNS_INFO) {
			upn_dns_info = &pac_data->buffers[i].info->upn_dns_info;
			continue;
		}
	}

	result = create_info6_from_pac(state->mem_ctx,
				       logon_info,
				       upn_dns_info,
				       &info6);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (!is_allowed_domain(info6->base.logon_domain.string)) {
		DBG_NOTICE("Authentication failed for user [%s] "
			   "from firewalled domain [%s]\n",
			   info6->base.account_name.string,
			   info6->base.logon_domain.string);
		return NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
	}

	result = map_info6_to_validation(state->mem_ctx,
					 info6,
					 &validation_level,
					 &validation);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	result = map_validation_to_info3(state->mem_ctx,
					 validation_level,
					 validation,
					 &info3_copy);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (is_trusted) {
		/*
		 * Signature verification succeeded, we can
		 * trust the PAC and prime the netsamlogon
		 * and name2sid caches. DO NOT DO THIS
		 * in the signature verification failed
		 * code path.
		 */
		struct winbindd_domain *domain = NULL;

		netsamlogon_cache_store(NULL, info3_copy);

		/*
		 * We're in the parent here, so find the child
		 * pointer from the PAC domain name.
		 */
		domain = find_lookup_domain_from_name(
				info3_copy->base.logon_domain.string);
		if (domain && domain->primary ) {
			struct dom_sid user_sid;
			struct dom_sid_buf buf;

			sid_compose(&user_sid,
				info3_copy->base.domain_sid,
				info3_copy->base.rid);

			cache_name2sid_trusted(domain,
				info3_copy->base.logon_domain.string,
				info3_copy->base.account_name.string,
				SID_NAME_USER,
				&user_sid);

			DBG_INFO("PAC for user %s\\%s SID %s primed cache\n",
				info3_copy->base.logon_domain.string,
				info3_copy->base.account_name.string,
				dom_sid_str_buf(&user_sid, &buf));
		}
	}

	*p_is_trusted = is_trusted;
	*p_validation_level = validation_level;
	*p_validation = validation;
	return NT_STATUS_OK;
}
#else /* HAVE_KRB5 */
NTSTATUS winbindd_pam_auth_pac_verify(struct winbindd_cli_state *state,
				      bool *p_is_trusted,
				      uint16_t *p_validation_level,
				      union netr_Validation **p_validation);
{

	*p_is_trusted = false;
	*p_validation_level = 0;
	*p_validation = NULL;
	return NT_STATUS_NO_SUCH_USER;
}
#endif /* HAVE_KRB5 */
