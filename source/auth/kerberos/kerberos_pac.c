/* 
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
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
#include "auth/kerberos/kerberos.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "auth/auth.h"

static NTSTATUS kerberos_pac_checksum(TALLOC_CTX *mem_ctx, 
				      DATA_BLOB pac_data,
				      struct PAC_SIGNATURE_DATA *sig,
				      struct smb_krb5_context *smb_krb5_context,
				      krb5_keyblock *keyblock,
				      uint32_t keyusage)
{
	krb5_error_code ret;
	krb5_crypto crypto;
	Checksum cksum;

	cksum.cksumtype		= (CKSUMTYPE)sig->type;
	cksum.checksum.length	= sizeof(sig->signature);
	cksum.checksum.data	= sig->signature;


	ret = krb5_crypto_init(smb_krb5_context->krb5_context,
			       keyblock,
			       0,
			       &crypto);
	if (ret) {
		DEBUG(0,("krb5_crypto_init() failed\n"));
		return NT_STATUS_FOOBAR;
	}
	ret = krb5_verify_checksum(smb_krb5_context->krb5_context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   pac_data.data,
				   pac_data.length,
				   &cksum);
	if (ret) {
		DEBUG(2, ("PAC Verification failed: %s\n", 
			  smb_get_krb5_error_message(smb_krb5_context->krb5_context, ret, mem_ctx)));
	}

	krb5_crypto_destroy(smb_krb5_context->krb5_context, crypto);

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
				logon_info = &pac_data.buffers[i].info->logon_info;
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
			case PAC_TYPE_UNKNOWN_10:
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

	/* verify by servie_key */
	status = kerberos_pac_checksum(mem_ctx, 
				       modified_pac_blob, &srv_sig, 
				       smb_krb5_context, keyblock, 0);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	DEBUG(0,("account_name: %s [%s]\n",
		 logon_info->info3.base.account_name.string, 
		 logon_info->info3.base.full_name.string));
	*logon_info_out = logon_info;

	return status;
}

