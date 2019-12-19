/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005
   Copyright (C) Guenther Deschner 2005,2007,2008

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#ifdef HAVE_KRB5

#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "librpc/gen_ndr/auth.h"
#include "auth/common_auth.h"
#include "auth/kerberos/pac_utils.h"

krb5_error_code check_pac_checksum(DATA_BLOB pac_data,
					  struct PAC_SIGNATURE_DATA *sig,
					  krb5_context context,
					  const krb5_keyblock *keyblock)
{
	krb5_error_code ret;
	krb5_checksum cksum;
	krb5_keyusage usage = 0;
	krb5_boolean checksum_valid = false;
	krb5_data input;

	switch (sig->type) {
	case CKSUMTYPE_HMAC_MD5:
		/* ignores the key type */
		break;
	case CKSUMTYPE_HMAC_SHA1_96_AES_256:
		if (KRB5_KEY_TYPE(keyblock) != ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
			return EINVAL;
		}
		/* ok */
		break;
	case CKSUMTYPE_HMAC_SHA1_96_AES_128:
		if (KRB5_KEY_TYPE(keyblock) != ENCTYPE_AES128_CTS_HMAC_SHA1_96) {
			return EINVAL;
		}
		/* ok */
		break;
	default:
		DEBUG(2,("check_pac_checksum: Checksum Type %d is not supported\n",
			(int)sig->type));
		return EINVAL;
	}

#ifdef HAVE_CHECKSUM_IN_KRB5_CHECKSUM /* Heimdal */
	cksum.cksumtype	= (krb5_cksumtype)sig->type;
	cksum.checksum.length	= sig->signature.length;
	cksum.checksum.data	= sig->signature.data;
#else /* MIT */
	cksum.checksum_type	= (krb5_cksumtype)sig->type;
	cksum.length		= sig->signature.length;
	cksum.contents		= sig->signature.data;
#endif

#ifdef HAVE_KRB5_KU_OTHER_CKSUM /* Heimdal */
	usage = KRB5_KU_OTHER_CKSUM;
#elif defined(HAVE_KRB5_KEYUSAGE_APP_DATA_CKSUM) /* MIT */
	usage = KRB5_KEYUSAGE_APP_DATA_CKSUM;
#else
#error UNKNOWN_KRB5_KEYUSAGE
#endif

	input.data = (char *)pac_data.data;
	input.length = pac_data.length;

	ret = krb5_c_verify_checksum(context,
				     keyblock,
				     usage,
				     &input,
				     &cksum,
				     &checksum_valid);
	if (!checksum_valid) {
		ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	}
	if (ret){
		DEBUG(2,("check_pac_checksum: PAC Verification failed: %s (%d)\n",
			error_message(ret), ret));
		return ret;
	}

	return ret;
}

/**
* @brief Decode a blob containing a NDR encoded PAC structure
*
* @param mem_ctx	  - The memory context
* @param pac_data_blob	  - The data blob containing the NDR encoded data
* @param context	  - The Kerberos Context
* @param service_keyblock - The Service Key used to verify the checksum
* @param client_principal - The client principal
* @param tgs_authtime     - The ticket timestamp
* @param pac_data_out	  - [out] The decoded PAC
*
* @return - A NTSTATUS error code
*/
NTSTATUS kerberos_decode_pac(TALLOC_CTX *mem_ctx,
			     DATA_BLOB pac_data_blob,
			     krb5_context context,
			     const krb5_keyblock *krbtgt_keyblock,
			     const krb5_keyblock *service_keyblock,
			     krb5_const_principal client_principal,
			     time_t tgs_authtime,
			     struct PAC_DATA **pac_data_out)
{
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	krb5_error_code ret;
	DATA_BLOB modified_pac_blob;

	NTTIME tgs_authtime_nttime;
	int i;

	struct PAC_SIGNATURE_DATA *srv_sig_ptr = NULL;
	struct PAC_SIGNATURE_DATA *kdc_sig_ptr = NULL;
	struct PAC_SIGNATURE_DATA *srv_sig_wipe = NULL;
	struct PAC_SIGNATURE_DATA *kdc_sig_wipe = NULL;
	struct PAC_LOGON_NAME *logon_name = NULL;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct PAC_DATA *pac_data = NULL;
	struct PAC_DATA_RAW *pac_data_raw = NULL;

	DATA_BLOB *srv_sig_blob = NULL;
	DATA_BLOB *kdc_sig_blob = NULL;

	bool bool_ret;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (pac_data_out) {
		*pac_data_out = NULL;
	}

	pac_data = talloc(tmp_ctx, struct PAC_DATA);
	pac_data_raw = talloc(tmp_ctx, struct PAC_DATA_RAW);
	kdc_sig_wipe = talloc(tmp_ctx, struct PAC_SIGNATURE_DATA);
	srv_sig_wipe = talloc(tmp_ctx, struct PAC_SIGNATURE_DATA);
	if (!pac_data_raw || !pac_data || !kdc_sig_wipe || !srv_sig_wipe) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_pull_struct_blob(&pac_data_blob, pac_data, pac_data,
		       (ndr_pull_flags_fn_t)ndr_pull_PAC_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	if (pac_data->num_buffers < 4) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0,("less than 4 PAC buffers\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ndr_err = ndr_pull_struct_blob(
				&pac_data_blob, pac_data_raw, pac_data_raw,
				(ndr_pull_flags_fn_t)ndr_pull_PAC_DATA_RAW);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	if (pac_data_raw->num_buffers < 4) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0,("less than 4 PAC buffers\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pac_data->num_buffers != pac_data_raw->num_buffers) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0, ("misparse! PAC_DATA has %d buffers while "
			  "PAC_DATA_RAW has %d\n", pac_data->num_buffers,
			  pac_data_raw->num_buffers));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i=0; i < pac_data->num_buffers; i++) {
		struct PAC_BUFFER *data_buf = &pac_data->buffers[i];
		struct PAC_BUFFER_RAW *raw_buf = &pac_data_raw->buffers[i];

		if (data_buf->type != raw_buf->type) {
			DEBUG(0, ("misparse! PAC_DATA buffer %d has type "
				  "%d while PAC_DATA_RAW has %d\n", i,
				  data_buf->type, raw_buf->type));
			talloc_free(tmp_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}
		switch (data_buf->type) {
		case PAC_TYPE_LOGON_INFO:
			if (!data_buf->info) {
				break;
			}
			logon_info = data_buf->info->logon_info.info;
			break;
		case PAC_TYPE_SRV_CHECKSUM:
			if (!data_buf->info) {
				break;
			}
			srv_sig_ptr = &data_buf->info->srv_cksum;
			srv_sig_blob = &raw_buf->info->remaining;
			break;
		case PAC_TYPE_KDC_CHECKSUM:
			if (!data_buf->info) {
				break;
			}
			kdc_sig_ptr = &data_buf->info->kdc_cksum;
			kdc_sig_blob = &raw_buf->info->remaining;
			break;
		case PAC_TYPE_LOGON_NAME:
			logon_name = &data_buf->info->logon_name;
			break;
		default:
			break;
		}
	}

	if (!logon_info) {
		DEBUG(0,("PAC no logon_info\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!logon_name) {
		DEBUG(0,("PAC no logon_name\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!srv_sig_ptr || !srv_sig_blob) {
		DEBUG(0,("PAC no srv_key\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!kdc_sig_ptr || !kdc_sig_blob) {
		DEBUG(0,("PAC no kdc_key\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Find and zero out the signatures,
	 * as required by the signing algorithm */

	/* We find the data blobs above,
	 * now we parse them to get at the exact portion we should zero */
	ndr_err = ndr_pull_struct_blob(
			kdc_sig_blob, kdc_sig_wipe, kdc_sig_wipe,
			(ndr_pull_flags_fn_t)ndr_pull_PAC_SIGNATURE_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the KDC signature: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	ndr_err = ndr_pull_struct_blob(
			srv_sig_blob, srv_sig_wipe, srv_sig_wipe,
			(ndr_pull_flags_fn_t)ndr_pull_PAC_SIGNATURE_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the SRV signature: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	/* Now zero the decoded structure */
	memset(kdc_sig_wipe->signature.data,
		'\0', kdc_sig_wipe->signature.length);
	memset(srv_sig_wipe->signature.data,
		'\0', srv_sig_wipe->signature.length);

	/* and reencode, back into the same place it came from */
	ndr_err = ndr_push_struct_blob(
			kdc_sig_blob, pac_data_raw, kdc_sig_wipe,
			(ndr_push_flags_fn_t)ndr_push_PAC_SIGNATURE_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't repack the KDC signature: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}
	ndr_err = ndr_push_struct_blob(
			srv_sig_blob, pac_data_raw, srv_sig_wipe,
			(ndr_push_flags_fn_t)ndr_push_PAC_SIGNATURE_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't repack the SRV signature: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	/* push out the whole structure, but now with zero'ed signatures */
	ndr_err = ndr_push_struct_blob(
			&modified_pac_blob, pac_data_raw, pac_data_raw,
			(ndr_push_flags_fn_t)ndr_push_PAC_DATA_RAW);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't repack the RAW PAC: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	if (service_keyblock) {
		/* verify by service_key */
		ret = check_pac_checksum(modified_pac_blob, srv_sig_ptr,
					 context,
					 service_keyblock);
		if (ret) {
			DEBUG(5, ("PAC Decode: Failed to verify the service "
				  "signature: %s\n", error_message(ret)));
			return NT_STATUS_ACCESS_DENIED;
		}

		if (krbtgt_keyblock) {
			/* verify the service key checksum by krbtgt_key */
			ret = check_pac_checksum(srv_sig_ptr->signature, kdc_sig_ptr,
						 context, krbtgt_keyblock);
			if (ret) {
				DEBUG(1, ("PAC Decode: Failed to verify the KDC signature: %s\n",
					  smb_get_krb5_error_message(context, ret, tmp_ctx)));
				talloc_free(tmp_ctx);
				return NT_STATUS_ACCESS_DENIED;
			}
		}
	}

	if (tgs_authtime) {
		/* Convert to NT time, so as not to loose accuracy in comparison */
		unix_to_nt_time(&tgs_authtime_nttime, tgs_authtime);

		if (tgs_authtime_nttime != logon_name->logon_time) {
			DEBUG(2, ("PAC Decode: "
				  "Logon time mismatch between ticket and PAC!\n"));
			DEBUG(2, ("PAC Decode: PAC: %s\n",
				  nt_time_string(tmp_ctx, logon_name->logon_time)));
			DEBUG(2, ("PAC Decode: Ticket: %s\n",
				  nt_time_string(tmp_ctx, tgs_authtime_nttime)));
			talloc_free(tmp_ctx);
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (client_principal) {
		char *client_principal_string;
		ret = krb5_unparse_name_flags(context, client_principal,
					      KRB5_PRINCIPAL_UNPARSE_NO_REALM|KRB5_PRINCIPAL_UNPARSE_DISPLAY,
					      &client_principal_string);
		if (ret) {
			DEBUG(2, ("Could not unparse name from ticket to match with name from PAC: [%s]:%s\n",
				  logon_name->account_name, error_message(ret)));
			talloc_free(tmp_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		bool_ret = strcmp(client_principal_string, logon_name->account_name) == 0;

		if (!bool_ret) {
			DEBUG(2, ("Name in PAC [%s] does not match principal name "
				  "in ticket [%s]\n",
				  logon_name->account_name,
				  client_principal_string));
			SAFE_FREE(client_principal_string);
			talloc_free(tmp_ctx);
			return NT_STATUS_ACCESS_DENIED;
		}
		SAFE_FREE(client_principal_string);

	}

	DEBUG(3,("Found account name from PAC: %s [%s]\n",
		 logon_info->info3.base.account_name.string,
		 logon_info->info3.base.full_name.string));

	DEBUG(10,("Successfully validated Kerberos PAC\n"));

	if (DEBUGLEVEL >= 10) {
		const char *s;
		s = NDR_PRINT_STRUCT_STRING(tmp_ctx, PAC_DATA, pac_data);
		if (s) {
			DEBUGADD(10,("%s\n", s));
		}
	}

	if (pac_data_out) {
		*pac_data_out = talloc_steal(mem_ctx, pac_data);
	}

	return NT_STATUS_OK;
}

NTSTATUS kerberos_pac_logon_info(TALLOC_CTX *mem_ctx,
				 DATA_BLOB blob,
				 krb5_context context,
				 const krb5_keyblock *krbtgt_keyblock,
				 const krb5_keyblock *service_keyblock,
				 krb5_const_principal client_principal,
				 time_t tgs_authtime,
				 struct PAC_LOGON_INFO **logon_info)
{
	NTSTATUS nt_status;
	struct PAC_DATA *pac_data;
	int i;
	nt_status = kerberos_decode_pac(mem_ctx,
					blob,
					context,
					krbtgt_keyblock,
					service_keyblock,
					client_principal,
					tgs_authtime,
					&pac_data);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	*logon_info = NULL;
	for (i=0; i < pac_data->num_buffers; i++) {
		if (pac_data->buffers[i].type != PAC_TYPE_LOGON_INFO) {
			continue;
		}
		*logon_info = pac_data->buffers[i].info->logon_info.info;
	}
	if (!*logon_info) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_OK;
}

static NTSTATUS auth4_context_fetch_PAC_DATA_CTR(
				struct auth4_context *auth_ctx,
				TALLOC_CTX *mem_ctx,
				struct smb_krb5_context *smb_krb5_context,
				DATA_BLOB *pac_blob,
				const char *princ_name,
				const struct tsocket_address *remote_address,
				uint32_t session_info_flags,
				struct auth_session_info **session_info)
{
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	NTSTATUS status;

	if (pac_blob == NULL) {
		return NT_STATUS_NO_IMPERSONATION_TOKEN;
	}

	pac_data_ctr = talloc_zero(mem_ctx, struct PAC_DATA_CTR);
	if (pac_data_ctr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	status = kerberos_decode_pac(pac_data_ctr,
				     *pac_blob,
				     NULL,
				     NULL,
				     NULL,
				     NULL,
				     0,
				     &pac_data_ctr->pac_data);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	pac_data_ctr->pac_blob = data_blob_talloc(pac_data_ctr,
						  pac_blob->data,
						  pac_blob->length);
	if (pac_data_ctr->pac_blob.length != pac_blob->length) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	*session_info = talloc_zero(mem_ctx, struct auth_session_info);
	if (*session_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	TALLOC_FREE(auth_ctx->private_data);
	auth_ctx->private_data = talloc_move(auth_ctx, &pac_data_ctr);

	return NT_STATUS_OK;

fail:
	TALLOC_FREE(pac_data_ctr);

	return status;
}

struct auth4_context *auth4_context_for_PAC_DATA_CTR(TALLOC_CTX *mem_ctx)
{
	struct auth4_context *auth_ctx = NULL;

	auth_ctx = talloc_zero(mem_ctx, struct auth4_context);
	if (auth_ctx == NULL) {
		return NULL;
	}
	auth_ctx->generate_session_info_pac = auth4_context_fetch_PAC_DATA_CTR;

	return auth_ctx;
}

struct PAC_DATA_CTR *auth4_context_get_PAC_DATA_CTR(struct auth4_context *auth_ctx,
						    TALLOC_CTX *mem_ctx)
{
	struct PAC_DATA_CTR *p = NULL;
	SMB_ASSERT(auth_ctx->generate_session_info_pac == auth4_context_fetch_PAC_DATA_CTR);
	p = talloc_get_type_abort(auth_ctx->private_data, struct PAC_DATA_CTR);
	auth_ctx->private_data = NULL;
	return talloc_move(mem_ctx, &p);
}

#endif
