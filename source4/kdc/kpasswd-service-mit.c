/*
   Unix SMB/CIFS implementation.

   Samba kpasswd implementation

   Copyright (c) 2016      Andreas Schneider <asn@samba.org>

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
#include "smbd/service_task.h"
#include "param/param.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "kdc/kdc-server.h"
#include "kdc/kpasswd_glue.h"
#include "kdc/kpasswd-service.h"
#include "kdc/kpasswd-helper.h"

#define RFC3244_VERSION 0xff80

krb5_error_code decode_krb5_setpw_req(const krb5_data *code,
				      krb5_data **password_out,
				      krb5_principal *target_out);

static krb5_error_code kpasswd_change_password(struct kdc_server *kdc,
					       TALLOC_CTX *mem_ctx,
					       struct auth_session_info *session_info,
					       DATA_BLOB *password,
					       DATA_BLOB *kpasswd_reply,
					       const char **error_string)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	enum samPwdChangeReason reject_reason;
	const char *reject_string = NULL;
	struct samr_DomInfo1 *dominfo;
	bool ok;

	status = samdb_kpasswd_change_password(mem_ctx,
					       kdc->task->lp_ctx,
					       kdc->task->event_ctx,
					       kdc->samdb,
					       session_info,
					       password,
					       &reject_reason,
					       &dominfo,
					       &reject_string,
					       &result);
	if (!NT_STATUS_IS_OK(status)) {
		ok = kpasswd_make_error_reply(mem_ctx,
					      KRB5_KPASSWD_ACCESSDENIED,
					      reject_string,
					      kpasswd_reply);
		if (!ok) {
			*error_string = "Failed to create reply";
			return KRB5_KPASSWD_HARDERROR;
		}
		/* We want to send an an authenticated packet. */
		return 0;
	}

	ok = kpasswd_make_pwchange_reply(mem_ctx,
					 result,
					 reject_reason,
					 dominfo,
					 kpasswd_reply);
	if (!ok) {
		*error_string = "Failed to create reply";
		return KRB5_KPASSWD_HARDERROR;
	}

	return 0;
}

static krb5_error_code kpasswd_set_password(struct kdc_server *kdc,
					    TALLOC_CTX *mem_ctx,
					    struct auth_session_info *session_info,
					    DATA_BLOB *decoded_data,
					    DATA_BLOB *kpasswd_reply,
					    const char **error_string)
{
	krb5_context context = kdc->smb_krb5_context->krb5_context;
	krb5_data k_dec_data;
	krb5_data *k_clear_data;
	krb5_principal target_principal;
	krb5_error_code code;
	DATA_BLOB password;
	char *target_realm = NULL;
	char *target_name = NULL;
	char *target_principal_string = NULL;
	bool is_service_principal = false;
	bool ok;
	size_t num_components;
	enum samPwdChangeReason reject_reason = SAM_PWD_CHANGE_NO_ERROR;
	struct samr_DomInfo1 *dominfo = NULL;
	NTSTATUS status;

	k_dec_data.length = decoded_data->length;
	k_dec_data.data   = (char *)decoded_data->data;

	code = decode_krb5_setpw_req(&k_dec_data,
				     &k_clear_data,
				     &target_principal);
	if (code != 0) {
		DBG_WARNING("decode_krb5_setpw_req failed: %s\n",
			    error_message(code));
		ok = kpasswd_make_error_reply(mem_ctx,
					      KRB5_KPASSWD_MALFORMED,
					      "Failed to decode packet",
					      kpasswd_reply);
		if (!ok) {
			*error_string = "Failed to create reply";
			return KRB5_KPASSWD_HARDERROR;
		}
		return 0;
	}

	ok = convert_string_talloc_handle(mem_ctx,
					  lpcfg_iconv_handle(kdc->task->lp_ctx),
					  CH_UTF8,
					  CH_UTF16,
					  (const char *)k_clear_data->data,
					  k_clear_data->length,
					  (void **)&password.data,
					  &password.length);
	krb5_free_data(context, k_clear_data);
	if (!ok) {
		DBG_WARNING("String conversion failed\n");
		*error_string = "String conversion failed";
		return KRB5_KPASSWD_HARDERROR;
	}

	target_realm = smb_krb5_principal_get_realm(
		mem_ctx, context, target_principal);
	code = krb5_unparse_name_flags(context,
				       target_principal,
				       KRB5_PRINCIPAL_UNPARSE_NO_REALM,
				       &target_name);
	if (code != 0) {
		DBG_WARNING("Failed to parse principal\n");
		*error_string = "String conversion failed";
		return KRB5_KPASSWD_HARDERROR;
	}

	if ((target_name != NULL && target_realm == NULL) ||
	    (target_name == NULL && target_realm != NULL)) {
		krb5_free_principal(context, target_principal);
		TALLOC_FREE(target_realm);
		SAFE_FREE(target_name);

		ok = kpasswd_make_error_reply(mem_ctx,
					      KRB5_KPASSWD_MALFORMED,
					      "Realm and principal must be "
					      "both present, or neither "
					      "present",
					      kpasswd_reply);
		if (!ok) {
			*error_string = "Failed to create reply";
			return KRB5_KPASSWD_HARDERROR;
		}
		return 0;
	}

	if (target_name != NULL && target_realm != NULL) {
		TALLOC_FREE(target_realm);
		SAFE_FREE(target_name);
	} else {
		krb5_free_principal(context, target_principal);
		TALLOC_FREE(target_realm);
		SAFE_FREE(target_name);

		return kpasswd_change_password(kdc,
					       mem_ctx,
					       session_info,
					       &password,
					       kpasswd_reply,
					       error_string);
	}

	num_components = krb5_princ_size(context, target_principal);
	if (num_components >= 2) {
		is_service_principal = true;
		code = krb5_unparse_name_flags(context,
					       target_principal,
					       KRB5_PRINCIPAL_UNPARSE_SHORT,
					       &target_principal_string);
	} else {
		code = krb5_unparse_name(context,
					 target_principal,
					 &target_principal_string);
	}
	krb5_free_principal(context, target_principal);
	if (code != 0) {
		ok = kpasswd_make_error_reply(mem_ctx,
					      KRB5_KPASSWD_MALFORMED,
					      "Failed to parse principal",
					      kpasswd_reply);
		if (!ok) {
			*error_string = "Failed to create reply";
			return KRB5_KPASSWD_HARDERROR;
		}
	}

	status = kpasswd_samdb_set_password(mem_ctx,
					    kdc->task->event_ctx,
					    kdc->task->lp_ctx,
					    session_info,
					    is_service_principal,
					    target_principal_string,
					    &password,
					    &reject_reason,
					    &dominfo);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("kpasswd_samdb_set_password failed - %s\n",
			nt_errstr(status));
	}

	ok = kpasswd_make_pwchange_reply(mem_ctx,
					 status,
					 reject_reason,
					 dominfo,
					 kpasswd_reply);
	if (!ok) {
		*error_string = "Failed to create reply";
		return KRB5_KPASSWD_HARDERROR;
	}

	return 0;
}

krb5_error_code kpasswd_handle_request(struct kdc_server *kdc,
				       TALLOC_CTX *mem_ctx,
				       struct gensec_security *gensec_security,
				       uint16_t verno,
				       DATA_BLOB *decoded_data,
				       DATA_BLOB *kpasswd_reply,
				       const char **error_string)
{
	struct auth_session_info *session_info;
	NTSTATUS status;

	status = gensec_session_info(gensec_security,
				     mem_ctx,
				     &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		*error_string = talloc_asprintf(mem_ctx,
						"gensec_session_info failed - "
						"%s",
						nt_errstr(status));
		return KRB5_KPASSWD_HARDERROR;
	}

	switch(verno) {
	case 1: {
		DATA_BLOB password;
		bool ok;

		ok = convert_string_talloc_handle(mem_ctx,
						  lpcfg_iconv_handle(kdc->task->lp_ctx),
						  CH_UTF8,
						  CH_UTF16,
						  (const char *)decoded_data->data,
						  decoded_data->length,
						  (void **)&password.data,
						  &password.length);
		if (!ok) {
			*error_string = "String conversion failed!";
			DBG_WARNING("%s\n", *error_string);
			return KRB5_KPASSWD_HARDERROR;
		}

		return kpasswd_change_password(kdc,
					       mem_ctx,
					       session_info,
					       &password,
					       kpasswd_reply,
					       error_string);
	}
	case RFC3244_VERSION: {
		return kpasswd_set_password(kdc,
					    mem_ctx,
					    session_info,
					    decoded_data,
					    kpasswd_reply,
					    error_string);
	}
	default:
		return KRB5_KPASSWD_BAD_VERSION;
	}

	return 0;
}
