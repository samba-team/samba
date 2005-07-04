/* 
   Unix SMB/CIFS implementation.

   Create and parse the krb5 PAC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005

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
#include "system/time.h"
#include "system/network.h"
#include "auth/auth.h"
#include "auth/kerberos/kerberos.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "auth/auth.h"

static NTSTATUS check_pac_checksum(TALLOC_CTX *mem_ctx, 
				   DATA_BLOB pac_data,
				   struct PAC_SIGNATURE_DATA *sig,
				   krb5_context context,
				   krb5_keyblock *keyblock)
{
	krb5_error_code ret;
	krb5_crypto crypto;
	Checksum cksum;

	cksum.cksumtype		= (CKSUMTYPE)sig->type;
	cksum.checksum.length	= sizeof(sig->signature);
	cksum.checksum.data	= sig->signature;


	ret = krb5_crypto_init(context,
			       keyblock,
			       0,
			       &crypto);
	if (ret) {
		DEBUG(0,("krb5_crypto_init() failed\n"));
		return NT_STATUS_FOOBAR;
	}
	ret = krb5_verify_checksum(context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   pac_data.data,
				   pac_data.length,
				   &cksum);
	if (ret) {
		DEBUG(2, ("PAC Verification failed: %s\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
	}

	krb5_crypto_destroy(context, crypto);

	if (ret) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

 NTSTATUS kerberos_decode_pac(TALLOC_CTX *mem_ctx,
			     struct PAC_LOGON_INFO **logon_info_out,
			     DATA_BLOB blob,
			     struct smb_krb5_context *smb_krb5_context,
			     krb5_keyblock *keyblock)
{
	NTSTATUS status;
	struct PAC_SIGNATURE_DATA srv_sig;
	struct PAC_SIGNATURE_DATA *srv_sig_ptr = NULL;
	struct PAC_SIGNATURE_DATA kdc_sig;
	struct PAC_SIGNATURE_DATA *kdc_sig_ptr = NULL;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct PAC_DATA pac_data;
	DATA_BLOB modified_pac_blob = data_blob_talloc(mem_ctx, blob.data, blob.length);
	int i;

	status = ndr_pull_struct_blob(&blob, mem_ctx, &pac_data,
					(ndr_pull_flags_fn_t)ndr_pull_PAC_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("can't parse the PAC\n"));
		return status;
	}

	if (pac_data.num_buffers < 3) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0,("less than 3 PAC buffers\n"));
		return NT_STATUS_FOOBAR;
	}

	for (i=0; i < pac_data.num_buffers; i++) {
		switch (pac_data.buffers[i].type) {
			case PAC_TYPE_LOGON_INFO:
				if (!pac_data.buffers[i].info) {
					break;
				}
				logon_info = pac_data.buffers[i].info->logon_info.i;
				break;
			case PAC_TYPE_SRV_CHECKSUM:
				if (!pac_data.buffers[i].info) {
					break;
				}
				srv_sig_ptr = &pac_data.buffers[i].info->srv_cksum;
				srv_sig = pac_data.buffers[i].info->srv_cksum;
				break;
			case PAC_TYPE_KDC_CHECKSUM:
				if (!pac_data.buffers[i].info) {
					break;
				}
				kdc_sig_ptr = &pac_data.buffers[i].info->kdc_cksum;
				kdc_sig = pac_data.buffers[i].info->kdc_cksum;
				break;
			case PAC_TYPE_LOGON_NAME:
				break;
			default:
				break;
		}
	}

	if (!logon_info) {
		DEBUG(0,("PAC no logon_info\n"));
		return NT_STATUS_FOOBAR;
	}

	if (!srv_sig_ptr) {
		DEBUG(0,("PAC no srv_key\n"));
		return NT_STATUS_FOOBAR;
	}

	if (!kdc_sig_ptr) {
		DEBUG(0,("PAC no kdc_key\n"));
		return NT_STATUS_FOOBAR;
	}

	memset(&modified_pac_blob.data[modified_pac_blob.length - 20],
	       '\0', 16);
	memset(&modified_pac_blob.data[modified_pac_blob.length - 44],
	       '\0', 16);

	/* verify by service_key */
	status = check_pac_checksum(mem_ctx, 
				    modified_pac_blob, &srv_sig, 
				    smb_krb5_context->krb5_context, keyblock);
	
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	DEBUG(0,("account_name: %s [%s]\n",
		 logon_info->info3.base.account_name.string, 
		 logon_info->info3.base.full_name.string));
	*logon_info_out = logon_info;

	return status;
}

static krb5_error_code make_pac_checksum(TALLOC_CTX *mem_ctx, 
					 DATA_BLOB pac_data,
					 struct PAC_SIGNATURE_DATA *sig,
					 krb5_context context,
					 krb5_keyblock *keyblock)
{
	krb5_error_code ret;
	krb5_crypto crypto;
	Checksum cksum;


	ret = krb5_crypto_init(context,
			       keyblock,
			       0,
			       &crypto);
	if (ret) {
		DEBUG(0,("krb5_crypto_init() failed\n"));
		return ret;
	}
	ret = krb5_create_checksum(context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   0,
				   pac_data.data,
				   pac_data.length,
				   &cksum);
	if (ret) {
		DEBUG(2, ("PAC Verification failed: %s\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
	}

	krb5_crypto_destroy(context, crypto);

	if (ret) {
		return ret;
	}

	sig->type = cksum.cksumtype;
	if (cksum.checksum.length == sizeof(sig->signature)) {
		memcpy(sig->signature, cksum.checksum.data, sizeof(sig->signature));
	}

	return 0;
}

 krb5_error_code kerberos_encode_pac(TALLOC_CTX *mem_ctx,
				     struct auth_serversupplied_info *server_info,
				     krb5_context context,
				     krb5_keyblock *krbtgt_keyblock,
				     krb5_keyblock *server_keyblock,
				     DATA_BLOB *pac)
{
	NTSTATUS nt_status;
	DATA_BLOB zero_blob = data_blob(NULL, 0);
	DATA_BLOB tmp_blob = data_blob(NULL, 0);
	DATA_BLOB server_checksum_blob;
	krb5_error_code ret;
	struct PAC_DATA *pac_data = talloc(mem_ctx, struct PAC_DATA);
	struct netr_SamBaseInfo *sam;
	struct timeval tv = timeval_current();
	union PAC_INFO *u_LOGON_INFO;
	struct PAC_LOGON_INFO *LOGON_INFO;
	union PAC_INFO *u_LOGON_NAME;
	struct PAC_LOGON_NAME *LOGON_NAME;
	union PAC_INFO *u_KDC_CHECKSUM;
	struct PAC_SIGNATURE_DATA *KDC_CHECKSUM;
	union PAC_INFO *u_SRV_CHECKSUM;
	struct PAC_SIGNATURE_DATA *SRV_CHECKSUM;

	enum {
		PAC_BUF_LOGON_INFO = 0,
		PAC_BUF_LOGON_NAME = 1,
		PAC_BUF_KDC_CHECKSUM = 2,
		PAC_BUF_SRV_CHECKSUM = 3,
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

	/* KDC_CHECKSUM */
	u_KDC_CHECKSUM = talloc_zero(pac_data->buffers, union PAC_INFO);
	if (!u_KDC_CHECKSUM) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	pac_data->buffers[PAC_BUF_KDC_CHECKSUM].type = PAC_TYPE_KDC_CHECKSUM;
	pac_data->buffers[PAC_BUF_KDC_CHECKSUM].info = u_KDC_CHECKSUM;
	KDC_CHECKSUM = &u_KDC_CHECKSUM->kdc_cksum;

	/* SRV_CHECKSUM */
	u_SRV_CHECKSUM = talloc_zero(pac_data->buffers, union PAC_INFO);
	if (!u_SRV_CHECKSUM) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	pac_data->buffers[PAC_BUF_SRV_CHECKSUM].type = PAC_TYPE_SRV_CHECKSUM;
	pac_data->buffers[PAC_BUF_SRV_CHECKSUM].info = u_SRV_CHECKSUM;
	SRV_CHECKSUM = &u_SRV_CHECKSUM->srv_cksum;

	/* now the real work begins... */

	LOGON_INFO = talloc_zero(u_LOGON_INFO, struct PAC_LOGON_INFO);
	if (!LOGON_INFO) {
		talloc_free(pac_data);
		return ENOMEM;
	}
	nt_status = auth_convert_server_info_sambaseinfo(LOGON_INFO, server_info, &sam);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	u_LOGON_INFO->logon_info.unknown[0]	= 0x00081001;
	u_LOGON_INFO->logon_info.unknown[1]	= 0xCCCCCCCC;
	u_LOGON_INFO->logon_info.unknown[2]	= 0x000001C8;
	u_LOGON_INFO->logon_info.unknown[3]	= 0x00000000;
	u_LOGON_INFO->logon_info.i		= LOGON_INFO;
	LOGON_INFO->info3.base = *sam;

	LOGON_NAME->account_name	= server_info->account_name;
	LOGON_NAME->logon_time		= timeval_to_nttime(&tv);



	/* First, just get the keytypes filled in (and lengths right, eventually) */
	ret = make_pac_checksum(mem_ctx, zero_blob, KDC_CHECKSUM, context, krbtgt_keyblock);
	if (ret) {
		DEBUG(2, ("making krbtgt PAC checksum failed: %s\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		talloc_free(pac_data);
		return ret;
	}

	ret = make_pac_checksum(mem_ctx, zero_blob, SRV_CHECKSUM, context, server_keyblock);
	if (ret) {
		DEBUG(2, ("making server PAC checksum failed: %s\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		talloc_free(pac_data);
		return ret;
	}

	/* But wipe out the actual signatures */
	ZERO_STRUCT(KDC_CHECKSUM->signature);
	ZERO_STRUCT(SRV_CHECKSUM->signature);

	nt_status = ndr_push_struct_blob(&tmp_blob, mem_ctx, pac_data,
					 (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("PAC (presig) push failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	/* Then sign the result of the previous push, where the sig was zero'ed out */
	ret = make_pac_checksum(mem_ctx, tmp_blob, SRV_CHECKSUM,
				context, server_keyblock);

	/* Push the Server checksum out */
	nt_status = ndr_push_struct_blob(&server_checksum_blob, mem_ctx, SRV_CHECKSUM,
					 (ndr_push_flags_fn_t)ndr_push_PAC_SIGNATURE_DATA);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("PAC_SIGNATURE push failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	/* Then sign Server checksum */
	ret = make_pac_checksum(mem_ctx, server_checksum_blob, KDC_CHECKSUM, context, krbtgt_keyblock);
	if (ret) {
		DEBUG(2, ("making krbtgt PAC checksum failed: %s\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		talloc_free(pac_data);
		return ret;
	}

	/* And push it out again, this time to the world.  This relies on determanistic pointer values */
	nt_status = ndr_push_struct_blob(&tmp_blob, mem_ctx, pac_data,
					 (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("PAC (final) push failed: %s\n", nt_errstr(nt_status)));
		talloc_free(pac_data);
		return EINVAL;
	}

	*pac = tmp_blob;

	talloc_free(pac_data);
	return ret;
}

