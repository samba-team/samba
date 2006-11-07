/* 
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#include "kdc/kdc.h"
#include "dsdb/common/flags.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"

struct krb5_dh_moduli;
struct _krb5_krb_auth_data;

#include "heimdal/lib/krb5/krb5_locl.h"

/* Given the right private pointer from hdb_ldb, get a PAC from the attached ldb messages */
static krb5_error_code samba_get_pac(krb5_context context, 
				     struct hdb_ldb_private *private,
				     krb5_principal client, 
				     krb5_keyblock *krbtgt_keyblock, 
				     krb5_keyblock *server_keyblock, 
				     time_t tgs_authtime,
				     krb5_data *pac)
{
	krb5_error_code ret;
	NTSTATUS nt_status;
	struct auth_serversupplied_info *server_info;
	DATA_BLOB tmp_blob;
	TALLOC_CTX *mem_ctx = talloc_named(private, 0, "samba_get_pac context");

	if (!mem_ctx) {
		return ENOMEM;
	}

	nt_status = authsam_make_server_info(mem_ctx, private->samdb, 
					     private->msg, 
					     private->realm_ref_msg,
					     data_blob(NULL, 0),
					     data_blob(NULL, 0),
					     &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return ENOMEM;
	}

	ret = kerberos_create_pac(mem_ctx, server_info, 
				  context, 
				  krbtgt_keyblock,
				  server_keyblock,
				  client,
				  tgs_authtime,
				  &tmp_blob);

	if (ret) {
		DEBUG(1, ("PAC encoding failed: %s\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		talloc_free(mem_ctx);
		return ret;
	}

	ret = krb5_data_copy(pac, tmp_blob.data, tmp_blob.length);
	talloc_free(mem_ctx);
	return ret;
}

/* Wrap the PAC in the right ASN.1.  Will always free 'pac', on success or failure */
static krb5_error_code wrap_pac(krb5_context context, krb5_data *pac, AuthorizationData **out) 
{
	krb5_error_code ret;

	unsigned char *buf;
	size_t buf_size;
	size_t len;
	
	AD_IF_RELEVANT if_relevant;
	AuthorizationData *auth_data;

	if_relevant.len = 1;
	if_relevant.val = malloc(sizeof(*if_relevant.val));
	if (!if_relevant.val) {
		krb5_data_free(pac);
		*out = NULL;
		return ENOMEM;
	}

	if_relevant.val[0].ad_type = KRB5_AUTHDATA_WIN2K_PAC;
	if_relevant.val[0].ad_data.data = NULL;
	if_relevant.val[0].ad_data.length = 0;
	
	/* pac.data will be freed with this */
	if_relevant.val[0].ad_data.data = pac->data;
	if_relevant.val[0].ad_data.length = pac->length;
	
	ASN1_MALLOC_ENCODE(AuthorizationData, buf, buf_size, &if_relevant, &len, ret);
	free_AuthorizationData(&if_relevant);
	if (ret) {
		*out = NULL;
		return ret;
	}		
	
	auth_data = malloc(sizeof(*auth_data));
	if (!auth_data) {
		free(buf);
		*out = NULL;
		return ret;
	}		
	auth_data->len = 1;
	auth_data->val = malloc(sizeof(*auth_data->val));
	if (!auth_data->val) {
		free(buf);
		free(auth_data);
		*out = NULL;
		return ret;
	}
	auth_data->val[0].ad_type = KRB5_AUTHDATA_IF_RELEVANT;
	auth_data->val[0].ad_data.length = len;
	auth_data->val[0].ad_data.data = buf;

	*out = auth_data;
	return 0;
}


/* Given a hdb_entry, create a PAC out of the private data 

   Don't create it if the client has the UF_NO_AUTH_DATA_REQUIRED bit
   set, or if they specificaly asked not to get it.
*/

krb5_error_code hdb_ldb_authz_data_as_req(krb5_context context, struct hdb_entry_ex *entry_ex, 
					   METHOD_DATA* pa_data_seq,
					   time_t authtime,
					   EncryptionKey *tgtkey,
					   EncryptionKey *sessionkey,
					   AuthorizationData **out)
{
	krb5_error_code ret;
	int i;
	krb5_data pac;
	krb5_boolean pac_wanted = TRUE;
	unsigned int userAccountControl;
	struct PA_PAC_REQUEST pac_request;
	struct hdb_ldb_private *private = talloc_get_type(entry_ex->ctx, struct hdb_ldb_private);
	
	/* The user account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(private->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		*out = NULL;
		return 0;
	}

	/* The user may not want a PAC */
	for (i=0; i<pa_data_seq->len; i++) {
		if (pa_data_seq->val[i].padata_type == KRB5_PADATA_PA_PAC_REQUEST) {
			ret = decode_PA_PAC_REQUEST(pa_data_seq->val[i].padata_value.data, 
						    pa_data_seq->val[i].padata_value.length, 
						    &pac_request, NULL);
			if (ret == 0) {
				pac_wanted = !!pac_request.include_pac;
			}
			free_PA_PAC_REQUEST(&pac_request);
			break;
		}
	}

	if (!pac_wanted) {
		*out = NULL;
		return 0;
	}	

	/* Get PAC from Samba */
	ret = samba_get_pac(context,
			    private,
			    entry_ex->entry.principal,
			    tgtkey,
			    tgtkey,
			    authtime,
			    &pac);

	if (ret) {
		*out = NULL;
		return ret;
	}
	
	return wrap_pac(context, &pac, out);
}

/* Resign (and reform, including possibly new groups) a PAC */

krb5_error_code hdb_ldb_authz_data_tgs_req(krb5_context context, struct hdb_entry_ex *entry_ex, 
					    krb5_principal client, 
					    AuthorizationData *in, 
					    time_t authtime,
					    EncryptionKey *tgtkey,
					    EncryptionKey *servicekey,
					    EncryptionKey *sessionkey,
					    AuthorizationData **out)
{
	NTSTATUS nt_status;
	krb5_error_code ret;

	unsigned int userAccountControl;

	struct hdb_ldb_private *private = talloc_get_type(entry_ex->ctx, struct hdb_ldb_private);
	krb5_data k5pac_in, k5pac_out;
	DATA_BLOB pac_in, pac_out;

	struct PAC_LOGON_INFO *logon_info;
	union netr_Validation validation;
	struct auth_serversupplied_info *server_info_out;

	krb5_boolean found = FALSE;
	TALLOC_CTX *mem_ctx;
	
	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(private->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		*out = NULL;
		return 0;
	}

	ret = _krb5_find_type_in_ad(context, KRB5_AUTHDATA_WIN2K_PAC,
				    &k5pac_in, &found, sessionkey, in);
	if (ret || !found) {
		*out = NULL;
		return 0;
	}

	mem_ctx = talloc_new(private);
	if (!mem_ctx) {
		krb5_data_free(&k5pac_in);
		*out = NULL;
		return ENOMEM;
	}

	pac_in = data_blob_talloc(mem_ctx, k5pac_in.data, k5pac_in.length);
	krb5_data_free(&k5pac_in);
	if (!pac_in.data) {
		talloc_free(mem_ctx);
		*out = NULL;
		return ENOMEM;
	}
		
	/* Parse the PAC again, for the logon info */
	nt_status = kerberos_pac_logon_info(mem_ctx, &logon_info,
					    pac_in,
					    context,
					    tgtkey, 
					    tgtkey, 
					    client, authtime, 
					    &ret);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Failed to parse PAC in TGT: %s/%s\n", 
			  nt_errstr(nt_status), error_message(ret)));
		talloc_free(mem_ctx);
		*out = NULL;
		return ret;
	}

	/* Pull this right into the normal auth sysstem structures */
	validation.sam3 = &logon_info->info3;
	nt_status = make_server_info_netlogon_validation(mem_ctx,
							 "",
							 3, &validation,
							 &server_info_out); 
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		*out = NULL;
		return ENOMEM;
	}

	/* And make a new PAC, possibly containing new groups */
	ret = kerberos_create_pac(mem_ctx, 
				  server_info_out,
				  context,
				  tgtkey,
				  servicekey,
				  client,
				  authtime,
				  &pac_out);

	if (ret != 0) {
		talloc_free(mem_ctx);
		*out = NULL;
		return ret;
	}

	ret = krb5_data_copy(&k5pac_out, pac_out.data, pac_out.length);
	if (ret != 0) {
		talloc_free(mem_ctx);
		*out = NULL;
		return ret;
	}

	return wrap_pac(context, &k5pac_out, out);
}

/* Given an hdb entry (and in particular it's private member), consult
 * the account_ok routine in auth/auth_sam.c for consistancy */

krb5_error_code hdb_ldb_check_client_access(krb5_context context, hdb_entry_ex *entry_ex, 
					    HostAddresses *addresses)
{
	krb5_error_code ret;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx = talloc_new(entry_ex->ctx);
	struct hdb_ldb_private *private = talloc_get_type(entry_ex->ctx, struct hdb_ldb_private);
	char *name, *workstation = NULL;
	int i;

	if (!tmp_ctx) {
		return ENOMEM;
	}
	
	ret = krb5_unparse_name(context, entry_ex->entry.principal, &name);
	if (ret != 0) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (addresses) {
		for (i=0; i < addresses->len; i++) {
			if (addresses->val->addr_type == KRB5_ADDRESS_NETBIOS) {
				workstation = talloc_strndup(tmp_ctx, addresses->val->address.data, MIN(addresses->val->address.length, 15));
				if (workstation) {
					break;
				}
			}
		}
	}

	/* Strip space padding */
	if (workstation) {
		i = MIN(strlen(workstation), 15);
		for (; i > 0 && workstation[i - 1] == ' '; i--) {
			workstation[i - 1] = '\0';
		}
	}

	nt_status = authsam_account_ok(tmp_ctx, 
				       private->samdb, 
				       MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT,
				       private->msg,
				       private->realm_ref_msg,
				       workstation,
				       name);
	free(name);

	/* TODO:  Need a more complete mapping of NTSTATUS to krb5kdc errors */

	if (!NT_STATUS_IS_OK(nt_status)) {
		return KRB5KDC_ERR_POLICY;
	}
	return 0;
}

