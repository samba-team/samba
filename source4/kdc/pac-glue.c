/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "../libds/common/flags.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"
#include "auth/auth_sam_reply.h"
#include "kdc/kdc.h"
#include "param/param.h"

NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       struct smb_iconv_convenience *ic,
				       struct auth_serversupplied_info *info,
				       DATA_BLOB *pac_data)
{
	struct netr_SamInfo3 *info3;
	union PAC_INFO pac_info;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_info);

	nt_status = auth_convert_server_info_saminfo3(mem_ctx, info, &info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	pac_info.logon_info.info = talloc_zero(mem_ctx, struct PAC_LOGON_INFO);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	pac_info.logon_info.info->info3 = *info3;

	ndr_err = ndr_push_union_blob(pac_data, mem_ctx, ic, &pac_info,
				      PAC_TYPE_LOGON_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
}

krb5_error_code samba_make_krb5_pac(krb5_context context,
				    DATA_BLOB *pac_blob,
				    krb5_pac *pac)
{
	krb5_data pac_data;
	krb5_error_code ret;

	ret = krb5_data_copy(&pac_data, pac_blob->data, pac_blob->length);
	if (ret != 0) {
		return ret;
	}

	ret = krb5_pac_init(context, pac);
	if (ret != 0) {
		krb5_data_free(&pac_data);
		return ret;
	}

	ret = krb5_pac_add_buffer(context, *pac, PAC_TYPE_LOGON_INFO, &pac_data);
	krb5_data_free(&pac_data);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

bool samba_princ_needs_pac(struct hdb_entry_ex *princ)
{

	struct hdb_samba4_private *p = talloc_get_type(princ->ctx, struct hdb_samba4_private);
	unsigned int userAccountControl;


	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(p->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		return false;
	}

	return true;
}

NTSTATUS samba_kdc_get_pac_blob(TALLOC_CTX *mem_ctx,
				struct hdb_entry_ex *client,
				DATA_BLOB **_pac_blob)
{
	struct hdb_samba4_private *p = talloc_get_type(client->ctx, struct hdb_samba4_private);
	struct auth_serversupplied_info *server_info;
	DATA_BLOB *pac_blob;
	NTSTATUS nt_status;

	/* The user account may be set not to want the PAC */
	if ( ! samba_princ_needs_pac(client)) {
		*_pac_blob = NULL;
		return NT_STATUS_OK;
	}

	pac_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (!pac_blob) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = authsam_make_server_info(mem_ctx, p->samdb,
					     lp_netbios_name(p->lp_ctx),
					     lp_sam_name(p->lp_ctx),
					     p->realm_dn,
					     p->msg,
					     data_blob(NULL, 0),
					     data_blob(NULL, 0),
					     &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx,
						  p->iconv_convenience,
						  server_info, pac_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	*_pac_blob = pac_blob;
	return NT_STATUS_OK;
}

NTSTATUS samba_kdc_update_pac_blob(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   struct smb_iconv_convenience *ic,
				   krb5_pac *pac, DATA_BLOB *pac_blob)
{
	struct auth_serversupplied_info *server_info;
	krb5_error_code ret;
	NTSTATUS nt_status;

	ret = kerberos_pac_to_server_info(mem_ctx, ic, *pac,
					  context, &server_info);
	if (ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx, ic,
						  server_info, pac_blob);

	return nt_status;
}

void samba_kdc_build_edata_reply(TALLOC_CTX *tmp_ctx, krb5_data *e_data,
				 NTSTATUS nt_status)
{
	PA_DATA pa;
	unsigned char *buf;
	size_t len;
	krb5_error_code ret = 0;

	if (!e_data)
		return;

	pa.padata_type		= KRB5_PADATA_PW_SALT;
	pa.padata_value.length	= 12;
	pa.padata_value.data	= malloc(pa.padata_value.length);
	if (!pa.padata_value.data) {
		e_data->length = 0;
		e_data->data = NULL;
		return;
	}

	SIVAL(pa.padata_value.data, 0, NT_STATUS_V(nt_status));
	SIVAL(pa.padata_value.data, 4, 0);
	SIVAL(pa.padata_value.data, 8, 1);

	ASN1_MALLOC_ENCODE(PA_DATA, buf, len, &pa, &len, ret);
	free(pa.padata_value.data);

	e_data->data   = buf;
	e_data->length = len;

	return;
}

