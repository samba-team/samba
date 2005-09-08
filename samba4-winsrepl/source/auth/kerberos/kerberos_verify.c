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
#include "pstring.h"

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
 Try to verify a ticket using the system keytab... the system keytab has kvno -1 entries, so
 it's more like what microsoft does... see comment in utils/net_ads.c in the
 ads_keytab_add_entry function for details.
***********************************************************************************/

static krb5_error_code ads_keytab_verify_ticket(TALLOC_CTX *mem_ctx, krb5_context context, 
						krb5_auth_context *auth_context,
						const char *service,
						const krb5_data *p_packet, 
						krb5_flags *ap_req_options,
						krb5_ticket **pp_tkt,
						krb5_keyblock **keyblock)
{
	krb5_error_code ret = 0;
	krb5_keytab keytab = NULL;
	krb5_kt_cursor kt_cursor;
	krb5_keytab_entry kt_entry;
	char *valid_princ_formats[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	char *entry_princ_s = NULL;
	const char *my_name, *my_fqdn;
	int i;
	int number_matched_principals = 0;
	const char *last_error_message;

	/* Generate the list of principal names which we expect
	 * clients might want to use for authenticating to the file
	 * service.  We allow name$,{host,service}/{name,fqdn,name.REALM}.
	 * (where service is specified by the caller) */

	my_name = lp_netbios_name();

	my_fqdn = name_to_fqdn(mem_ctx, my_name);

	asprintf(&valid_princ_formats[0], "%s$@%s", my_name, lp_realm());
	asprintf(&valid_princ_formats[1], "host/%s@%s", my_name, lp_realm());
	asprintf(&valid_princ_formats[2], "host/%s@%s", my_fqdn, lp_realm());
	asprintf(&valid_princ_formats[3], "host/%s.%s@%s", my_name, lp_realm(), lp_realm());
	asprintf(&valid_princ_formats[4], "%s/%s@%s", service, my_name, lp_realm());
	asprintf(&valid_princ_formats[5], "%s/%s@%s", service, my_fqdn, lp_realm());
	asprintf(&valid_princ_formats[6], "%s/%s.%s@%s", service, my_name, lp_realm(), lp_realm());

	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(kt_cursor);

	ret = krb5_kt_default(context, &keytab);
	if (ret) {
		last_error_message = smb_get_krb5_error_message(context, ret, mem_ctx);
		DEBUG(1, ("ads_keytab_verify_ticket: krb5_kt_default failed (%s)\n", 
			  last_error_message));
		goto out;
	}

	/* Iterate through the keytab.  For each key, if the principal
	 * name case-insensitively matches one of the allowed formats,
	 * try verifying the ticket using that principal. */

	ret = krb5_kt_start_seq_get(context, keytab, &kt_cursor);
	if (ret == KRB5_KT_END || ret == ENOENT ) {
		last_error_message = smb_get_krb5_error_message(context, ret, mem_ctx);
	} else if (ret) {
		last_error_message = smb_get_krb5_error_message(context, ret, mem_ctx);
		DEBUG(1, ("ads_keytab_verify_ticket: krb5_kt_start_seq_get failed (%s)\n", 
			  last_error_message));
	} else {
		ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN; /* Pick an error... */
		last_error_message = "No principals in Keytab";
		while (ret && (krb5_kt_next_entry(context, keytab, &kt_entry, &kt_cursor) == 0)) {
			krb5_error_code upn_ret;
			upn_ret = krb5_unparse_name(context, kt_entry.principal, &entry_princ_s);
			if (upn_ret) {
				last_error_message = smb_get_krb5_error_message(context, ret, mem_ctx);
				DEBUG(1, ("ads_keytab_verify_ticket: krb5_unparse_name failed (%s)\n", 
					  last_error_message));
				ret = upn_ret;
				break;
			}
			for (i = 0; i < ARRAY_SIZE(valid_princ_formats); i++) {
				if (!strequal(entry_princ_s, valid_princ_formats[i])) {
					continue;
				}

				number_matched_principals++;
				*pp_tkt = NULL;
				ret = krb5_rd_req_return_keyblock(context, auth_context, p_packet, 
								  kt_entry.principal, keytab, 
								  ap_req_options, pp_tkt, keyblock);
				if (ret) {
					last_error_message = smb_get_krb5_error_message(context, ret, mem_ctx);
					DEBUG(10, ("ads_keytab_verify_ticket: krb5_rd_req(%s) failed: %s\n",
						   entry_princ_s, last_error_message));
				} else {
					DEBUG(3,("ads_keytab_verify_ticket: krb5_rd_req succeeded for principal %s\n",
						 entry_princ_s));
					break;
				}
			}

			/* Free the name we parsed. */
			krb5_free_unparsed_name(context, entry_princ_s);
			entry_princ_s = NULL;

			/* Free the entry we just read. */
			smb_krb5_kt_free_entry(context, &kt_entry);
			ZERO_STRUCT(kt_entry);
		}
		krb5_kt_end_seq_get(context, keytab, &kt_cursor);
	}

	ZERO_STRUCT(kt_cursor);

  out:

	if (ret) {
		if (!number_matched_principals) {
			DEBUG(3, ("ads_keytab_verify_ticket: no keytab principals matched expected file service name.\n"));
		} else {
			DEBUG(3, ("ads_keytab_verify_ticket: krb5_rd_req failed for all %d matched keytab principals\n",
				number_matched_principals));
		}
		DEBUG(3, ("ads_keytab_verify_ticket: last error: %s\n", last_error_message));
	}

	if (entry_princ_s) {
		krb5_free_unparsed_name(context, entry_princ_s);
	}

	{
		krb5_keytab_entry zero_kt_entry;
		ZERO_STRUCT(zero_kt_entry);
		if (memcmp(&zero_kt_entry, &kt_entry, sizeof(krb5_keytab_entry))) {
			smb_krb5_kt_free_entry(context, &kt_entry);
		}
	}

	{
		krb5_kt_cursor zero_csr;
		ZERO_STRUCT(zero_csr);
		if ((memcmp(&kt_cursor, &zero_csr, sizeof(krb5_kt_cursor)) != 0) && keytab) {
			krb5_kt_end_seq_get(context, keytab, &kt_cursor);
		}
	}

	if (keytab) {
		krb5_kt_close(context, keytab);
	}

	return ret;
}

/**********************************************************************************
 Verify an incoming ticket and parse out the principal name and 
 authorization_data if available.
***********************************************************************************/

 NTSTATUS ads_verify_ticket(TALLOC_CTX *mem_ctx, 
			    struct smb_krb5_context *smb_krb5_context,
			    krb5_auth_context *auth_context,
			    const char *realm, const char *service, 
			    const DATA_BLOB *enc_ticket, 
			    krb5_ticket **tkt,
			    DATA_BLOB *ap_rep,
			    krb5_keyblock **keyblock)
{
	krb5_keyblock *local_keyblock;
	krb5_data packet;
	krb5_principal salt_princ;
	int ret;
	krb5_flags ap_req_options = 0;

	NTSTATUS creds_nt_status, status;
	struct cli_credentials *machine_account;

	machine_account = cli_credentials_init(mem_ctx);
	cli_credentials_set_conf(machine_account);
	creds_nt_status = cli_credentials_set_machine_account(machine_account);
	
	if (!NT_STATUS_IS_OK(creds_nt_status)) {
		DEBUG(3, ("Could not obtain machine account credentials from the local database\n"));
		talloc_free(machine_account);
		machine_account = NULL;
	} else {
		ret = salt_principal_from_credentials(mem_ctx, machine_account, 
						      smb_krb5_context, 
						      &salt_princ);
		if (ret) {
			DEBUG(1,("ads_verify_ticket: maksing salt principal failed (%s)\n",
				 error_message(ret)));
			return NT_STATUS_INTERNAL_ERROR;
		}
	}
	
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

	ret = ads_keytab_verify_ticket(mem_ctx, smb_krb5_context->krb5_context, auth_context, 
				       service, &packet, &ap_req_options, tkt, &local_keyblock);
	if (ret && machine_account) {
		krb5_keytab keytab;
		krb5_principal server;
		status = create_memory_keytab(mem_ctx, machine_account, smb_krb5_context, 
					      &keytab);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		ret = principal_from_credentials(mem_ctx, machine_account, smb_krb5_context, 
						 &server);
		if (ret == 0) {
			ret = krb5_rd_req_return_keyblock(smb_krb5_context->krb5_context, auth_context, &packet,
							  server,
							  keytab, &ap_req_options, tkt,
							  &local_keyblock);
		}
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
