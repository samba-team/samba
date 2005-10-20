/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Luke Howard 2003   
   Copyright (C) Guenther Deschner 2003
   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "system/network.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "asn_1.h"
#include "lib/ldb/include/ldb.h"
#include "secrets.h"

#ifdef HAVE_KRB5

DATA_BLOB unwrap_pac(TALLOC_CTX *mem_ctx, DATA_BLOB *auth_data)
{
	DATA_BLOB out;
	DATA_BLOB pac_contents = data_blob(NULL, 0);
	struct asn1_data data;
	int data_type;
	if (!auth_data->length) {
		return data_blob(NULL, 0);
	}

	asn1_load(&data, *auth_data);
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_CONTEXT(0));
	asn1_read_Integer(&data, &data_type);
	asn1_end_tag(&data);
	asn1_start_tag(&data, ASN1_CONTEXT(1));
	asn1_read_OctetString(&data, &pac_contents);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_free(&data);

	out = data_blob_talloc(mem_ctx, pac_contents.data, pac_contents.length);

	data_blob_free(&pac_contents);

	return out;
}

/**********************************************************************************
 Verify an incoming ticket and parse out the principal name and 
 authorization_data if available.
***********************************************************************************/

 NTSTATUS ads_verify_ticket(TALLOC_CTX *mem_ctx, 
			    struct smb_krb5_context *smb_krb5_context,
			    krb5_auth_context *auth_context,
			    struct cli_credentials *machine_account,
			    const char *service, 
			    const DATA_BLOB *enc_ticket, 
			    krb5_ticket **tkt,
			    DATA_BLOB *ap_rep,
			    krb5_keyblock **keyblock)
{
	krb5_keyblock *local_keyblock;
	krb5_data packet;
	int ret;
	krb5_flags ap_req_options = 0;
	krb5_principal server;

	struct keytab_container *keytab_container;

	/* This whole process is far more complex than I would
           like. We have to go through all this to allow us to store
           the secret internally, instead of using /etc/krb5.keytab */

	/*
	 * TODO: Actually hook in the replay cache in Heimdal, then
	 * re-add calls to setup a replay cache here, in our private
	 * directory.  This will eventually prevent replay attacks
	 */

	packet.length = enc_ticket->length;
	packet.data = (krb5_pointer)enc_ticket->data;

	ret = cli_credentials_get_keytab(machine_account, &keytab_container);
	if (ret) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ret = principal_from_credentials(mem_ctx, machine_account, smb_krb5_context, 
					 &server);
	if (ret == 0) {
		ret = krb5_rd_req_return_keyblock(smb_krb5_context->krb5_context, auth_context, &packet,
						  server,
						  keytab_container->keytab, &ap_req_options, tkt,
						  &local_keyblock);
	}

	if (ret) {
		DEBUG(3,("ads_secrets_verify_ticket: failed to decrypt with error %s\n",
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, ret, mem_ctx)));
		return NT_STATUS_LOGON_FAILURE;
	}
	*keyblock = local_keyblock;

	if (ap_req_options & AP_OPTS_MUTUAL_REQUIRED) {
		krb5_data packet_out;
		ret = krb5_mk_rep(smb_krb5_context->krb5_context, *auth_context, &packet_out);
		if (ret) {
			krb5_free_ticket(smb_krb5_context->krb5_context, *tkt);
			
			DEBUG(3,("ads_verify_ticket: Failed to generate mutual authentication reply (%s)\n",
				 smb_get_krb5_error_message(smb_krb5_context->krb5_context, ret, mem_ctx)));
			return NT_STATUS_LOGON_FAILURE;
		}
		
		*ap_rep = data_blob_talloc(mem_ctx, packet_out.data, packet_out.length);
		krb5_free_data_contents(smb_krb5_context->krb5_context, &packet_out);
	} else {
		*ap_rep = data_blob(NULL, 0);
	}

	return NT_STATUS_OK;
}

#endif /* HAVE_KRB5 */
