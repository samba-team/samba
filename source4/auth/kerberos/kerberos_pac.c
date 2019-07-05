/*
   Unix SMB/CIFS implementation.

   Create and parse the krb5 PAC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005,2008
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005

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
#include "auth/auth.h"
#include "auth/kerberos/kerberos.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include <ldb.h>
#include "auth/auth_sam_reply.h"
#include "auth/credentials/credentials.h"
#include "auth/kerberos/kerberos_util.h"
#include "auth/kerberos/pac_utils.h"

 krb5_error_code kerberos_encode_pac(TALLOC_CTX *mem_ctx,
				    struct PAC_DATA *pac_data,
				    krb5_context context,
				    const krb5_keyblock *krbtgt_keyblock,
				    const krb5_keyblock *service_keyblock,
				    DATA_BLOB *pac)
{
	NTSTATUS nt_status;
	krb5_error_code ret;
	enum ndr_err_code ndr_err;
	DATA_BLOB zero_blob = data_blob(NULL, 0);
	DATA_BLOB tmp_blob = data_blob(NULL, 0);
	struct PAC_SIGNATURE_DATA *kdc_checksum = NULL;
	struct PAC_SIGNATURE_DATA *srv_checksum = NULL;
	uint32_t i;

	/* First, just get the keytypes filled in (and lengths right, eventually) */
	for (i=0; i < pac_data->num_buffers; i++) {
		if (pac_data->buffers[i].type != PAC_TYPE_KDC_CHECKSUM) {
			continue;
		}
		kdc_checksum = &pac_data->buffers[i].info->kdc_cksum,
		ret = smb_krb5_make_pac_checksum(mem_ctx,
						 &zero_blob,
						 context,
						 krbtgt_keyblock,
						 &kdc_checksum->type,
						 &kdc_checksum->signature);
		if (ret) {
			DEBUG(2, ("making krbtgt PAC checksum failed: %s\n",
				  smb_get_krb5_error_message(context, ret, mem_ctx)));
			talloc_free(pac_data);
			return ret;
		}
	}

	for (i=0; i < pac_data->num_buffers; i++) {
		if (pac_data->buffers[i].type != PAC_TYPE_SRV_CHECKSUM) {
			continue;
		}
		srv_checksum = &pac_data->buffers[i].info->srv_cksum;
		ret = smb_krb5_make_pac_checksum(mem_ctx,
						 &zero_blob,
						 context,
						 service_keyblock,
						 &srv_checksum->type,
						 &srv_checksum->signature);
		if (ret) {
			DEBUG(2, ("making service PAC checksum failed: %s\n",
				  smb_get_krb5_error_message(context, ret, mem_ctx)));
			talloc_free(pac_data);
			return ret;
		}
	}

	if (!kdc_checksum) {
		DEBUG(2, ("Invalid PAC constructed for signing, no KDC checksum present!"));
		return EINVAL;
	}
	if (!srv_checksum) {
		DEBUG(2, ("Invalid PAC constructed for signing, no SRV checksum present!"));
		return EINVAL;
	}

	/* But wipe out the actual signatures */
	memset(kdc_checksum->signature.data, '\0', kdc_checksum->signature.length);
	memset(srv_checksum->signature.data, '\0', srv_checksum->signature.length);

	ndr_err = ndr_push_struct_blob(&tmp_blob, mem_ctx,
				       pac_data,
				       (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC (presig) push failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	/* Then sign the result of the previous push, where the sig was zero'ed out */
	ret = smb_krb5_make_pac_checksum(mem_ctx,
					 &tmp_blob,
					 context,
					 service_keyblock,
					 &srv_checksum->type,
					 &srv_checksum->signature);

	if (ret) {
		DBG_WARNING("making krbtgt PAC srv_checksum failed: %s\n",
			    smb_get_krb5_error_message(context, ret, mem_ctx));
		talloc_free(pac_data);
		return ret;
	}

	/* Then sign Server checksum */
	ret = smb_krb5_make_pac_checksum(mem_ctx,
					 &srv_checksum->signature,
					 context,
					 krbtgt_keyblock,
					 &kdc_checksum->type,
					 &kdc_checksum->signature);
	if (ret) {
		DBG_WARNING("making krbtgt PAC kdc_checksum failed: %s\n",
			    smb_get_krb5_error_message(context, ret, mem_ctx));
		talloc_free(pac_data);
		return ret;
	}

	/* And push it out again, this time to the world.  This relies on determanistic pointer values */
	ndr_err = ndr_push_struct_blob(&tmp_blob, mem_ctx,
				       pac_data,
				       (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC (final) push failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	*pac = tmp_blob;

	return ret;
}


 krb5_error_code kerberos_create_pac(TALLOC_CTX *mem_ctx,
				     struct auth_user_info_dc *user_info_dc,
				     krb5_context context,
				     const krb5_keyblock *krbtgt_keyblock,
				     const krb5_keyblock *service_keyblock,
				     krb5_principal client_principal,
				     time_t tgs_authtime,
				     DATA_BLOB *pac)
{
	NTSTATUS nt_status;
	krb5_error_code ret;
	struct PAC_DATA *pac_data = talloc(mem_ctx, struct PAC_DATA);
	struct netr_SamInfo3 *sam3;
	union PAC_INFO *u_LOGON_INFO;
	struct PAC_LOGON_INFO *LOGON_INFO;
	union PAC_INFO *u_LOGON_NAME;
	struct PAC_LOGON_NAME *LOGON_NAME;
	union PAC_INFO *u_KDC_CHECKSUM;
	union PAC_INFO *u_SRV_CHECKSUM;

	char *name;

	enum {
		PAC_BUF_LOGON_INFO = 0,
		PAC_BUF_LOGON_NAME = 1,
		PAC_BUF_SRV_CHECKSUM = 2,
		PAC_BUF_KDC_CHECKSUM = 3,
		PAC_BUF_NUM_BUFFERS = 4
	};

	if (!pac_data) {
		return ENOMEM;
	}

	pac_data->num_buffers = PAC_BUF_NUM_BUFFERS;
	pac_data->version = 0;

	pac_data->buffers = talloc_array(pac_data,
					 struct PAC_BUFFER,
					 pac_data->num_buffers);
	if (!pac_data->buffers) {
		talloc_free(pac_data);
		return ENOMEM;
	}

	/* LOGON_INFO */
	u_LOGON_INFO = talloc_zero(pac_data->buffers, union PAC_INFO);
	if (!u_LOGON_INFO) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	pac_data->buffers[PAC_BUF_LOGON_INFO].type = PAC_TYPE_LOGON_INFO;
	pac_data->buffers[PAC_BUF_LOGON_INFO].info = u_LOGON_INFO;

	/* LOGON_NAME */
	u_LOGON_NAME = talloc_zero(pac_data->buffers, union PAC_INFO);
	if (!u_LOGON_NAME) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	pac_data->buffers[PAC_BUF_LOGON_NAME].type = PAC_TYPE_LOGON_NAME;
	pac_data->buffers[PAC_BUF_LOGON_NAME].info = u_LOGON_NAME;
	LOGON_NAME = &u_LOGON_NAME->logon_name;

	/* SRV_CHECKSUM */
	u_SRV_CHECKSUM = talloc_zero(pac_data->buffers, union PAC_INFO);
	if (!u_SRV_CHECKSUM) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	pac_data->buffers[PAC_BUF_SRV_CHECKSUM].type = PAC_TYPE_SRV_CHECKSUM;
	pac_data->buffers[PAC_BUF_SRV_CHECKSUM].info = u_SRV_CHECKSUM;

	/* KDC_CHECKSUM */
	u_KDC_CHECKSUM = talloc_zero(pac_data->buffers, union PAC_INFO);
	if (!u_KDC_CHECKSUM) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	pac_data->buffers[PAC_BUF_KDC_CHECKSUM].type = PAC_TYPE_KDC_CHECKSUM;
	pac_data->buffers[PAC_BUF_KDC_CHECKSUM].info = u_KDC_CHECKSUM;

	/* now the real work begins... */

	LOGON_INFO = talloc_zero(u_LOGON_INFO, struct PAC_LOGON_INFO);
	if (!LOGON_INFO) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	nt_status = auth_convert_user_info_dc_saminfo3(LOGON_INFO, user_info_dc, &sam3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	u_LOGON_INFO->logon_info.info		= LOGON_INFO;
	LOGON_INFO->info3 = *sam3;

	ret = krb5_unparse_name_flags(context, client_principal,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM |
				      KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				      &name);
	if (ret) {
		return ret;
	}
	LOGON_NAME->account_name	= talloc_strdup(LOGON_NAME, name);
	free(name);
	/*
	  this logon_time field is absolutely critical. This is what
	  caused all our PAC troubles :-)
	*/
	unix_to_nt_time(&LOGON_NAME->logon_time, tgs_authtime);

	ret = kerberos_encode_pac(mem_ctx,
				  pac_data,
				  context,
				  krbtgt_keyblock,
				  service_keyblock,
				  pac);
	talloc_free(pac_data);
	return ret;
}

krb5_error_code kerberos_pac_to_user_info_dc(TALLOC_CTX *mem_ctx,
					     krb5_pac pac,
					     krb5_context context,
					     struct auth_user_info_dc **user_info_dc,
					     struct PAC_SIGNATURE_DATA *pac_srv_sig,
					     struct PAC_SIGNATURE_DATA *pac_kdc_sig)
{
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	krb5_error_code ret;

	DATA_BLOB pac_logon_info_in, pac_srv_checksum_in, pac_kdc_checksum_in;
	krb5_data k5pac_logon_info_in, k5pac_srv_checksum_in, k5pac_kdc_checksum_in;
	DATA_BLOB pac_upn_dns_info_in;
	krb5_data k5pac_upn_dns_info_in;

	union PAC_INFO info;
	union PAC_INFO _upn_dns_info;
	const struct PAC_UPN_DNS_INFO *upn_dns_info = NULL;
	struct auth_user_info_dc *user_info_dc_out;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (!tmp_ctx) {
		return ENOMEM;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_LOGON_INFO, &k5pac_logon_info_in);
	if (ret != 0) {
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	pac_logon_info_in = data_blob_const(k5pac_logon_info_in.data, k5pac_logon_info_in.length);

	ndr_err = ndr_pull_union_blob(&pac_logon_info_in, tmp_ctx, &info,
				      PAC_TYPE_LOGON_INFO,
				      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
	smb_krb5_free_data_contents(context, &k5pac_logon_info_in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
		talloc_free(tmp_ctx);
		return EINVAL;
	}
	if (info.logon_info.info == NULL) {
		DEBUG(0,("can't parse the PAC LOGON_INFO: missing info pointer\n"));
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_UPN_DNS_INFO,
				  &k5pac_upn_dns_info_in);
	if (ret == ENOENT) {
		ZERO_STRUCT(k5pac_upn_dns_info_in);
		ret = 0;
	}
	if (ret != 0) {
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	pac_upn_dns_info_in = data_blob_const(k5pac_upn_dns_info_in.data,
					      k5pac_upn_dns_info_in.length);

	if (pac_upn_dns_info_in.length != 0) {
		ndr_err = ndr_pull_union_blob(&pac_upn_dns_info_in, tmp_ctx,
					      &_upn_dns_info,
					      PAC_TYPE_UPN_DNS_INFO,
					      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
		smb_krb5_free_data_contents(context, &k5pac_upn_dns_info_in);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("can't parse the PAC UPN_DNS_INFO: %s\n",
				 nt_errstr(nt_status)));
			talloc_free(tmp_ctx);
			return EINVAL;
		}
		upn_dns_info = &_upn_dns_info.upn_dns_info;
	}

	/* Pull this right into the normal auth sysstem structures */
	nt_status = make_user_info_dc_pac(mem_ctx,
					 info.logon_info.info,
					 upn_dns_info,
					 &user_info_dc_out);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	if (pac_srv_sig) {
		ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_SRV_CHECKSUM, &k5pac_srv_checksum_in);
		if (ret != 0) {
			talloc_free(tmp_ctx);
			return ret;
		}

		pac_srv_checksum_in = data_blob_const(k5pac_srv_checksum_in.data, k5pac_srv_checksum_in.length);

		ndr_err = ndr_pull_struct_blob(&pac_srv_checksum_in, pac_srv_sig,
					       pac_srv_sig,
					       (ndr_pull_flags_fn_t)ndr_pull_PAC_SIGNATURE_DATA);
		smb_krb5_free_data_contents(context, &k5pac_srv_checksum_in);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("can't parse the KDC signature: %s\n",
				 nt_errstr(nt_status)));
			return EINVAL;
		}
	}

	if (pac_kdc_sig) {
		ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_KDC_CHECKSUM, &k5pac_kdc_checksum_in);
		if (ret != 0) {
			talloc_free(tmp_ctx);
			return ret;
		}

		pac_kdc_checksum_in = data_blob_const(k5pac_kdc_checksum_in.data, k5pac_kdc_checksum_in.length);

		ndr_err = ndr_pull_struct_blob(&pac_kdc_checksum_in, pac_kdc_sig,
					       pac_kdc_sig,
					       (ndr_pull_flags_fn_t)ndr_pull_PAC_SIGNATURE_DATA);
		smb_krb5_free_data_contents(context, &k5pac_kdc_checksum_in);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("can't parse the KDC signature: %s\n",
				 nt_errstr(nt_status)));
			return EINVAL;
		}
	}
	*user_info_dc = user_info_dc_out;

	return 0;
}


NTSTATUS kerberos_pac_blob_to_user_info_dc(TALLOC_CTX *mem_ctx,
					   DATA_BLOB pac_blob,
					   krb5_context context,
					   struct auth_user_info_dc **user_info_dc,
					   struct PAC_SIGNATURE_DATA *pac_srv_sig,
					   struct PAC_SIGNATURE_DATA *pac_kdc_sig)
{
	krb5_error_code ret;
	krb5_pac pac;
	ret = krb5_pac_parse(context,
			     pac_blob.data, pac_blob.length,
			     &pac);
	if (ret) {
		return map_nt_error_from_unix_common(ret);
	}


	ret = kerberos_pac_to_user_info_dc(mem_ctx, pac, context, user_info_dc, pac_srv_sig, pac_kdc_sig);
	krb5_pac_free(context, pac);
	if (ret) {
		return map_nt_error_from_unix_common(ret);
	}
	return NT_STATUS_OK;
}
