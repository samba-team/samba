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
#include "system/kerberos.h"
#include "libcli/auth/kerberos.h"
#include "asn_1.h"
#include "lib/ldb/include/ldb.h"
#include "secrets.h"
#include "pstring.h"

#ifdef HAVE_KRB5

#if !defined(HAVE_KRB5_PRINC_COMPONENT)
const krb5_data *krb5_princ_component(krb5_context, krb5_principal, int );
#endif
static DATA_BLOB unwrap_pac(TALLOC_CTX *mem_ctx, DATA_BLOB *auth_data)
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
						krb5_auth_context auth_context,
						const char *service,
						const DATA_BLOB *ticket, krb5_data *p_packet, 
						krb5_ticket **pp_tkt,
						krb5_keyblock *keyblock)
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
	 * service.  We allow name$,{host,cifs}/{name,fqdn,name.REALM}. */

	my_name = lp_netbios_name();

	my_fqdn = name_to_fqdn(mem_ctx, my_name);

	asprintf(&valid_princ_formats[0], "%s$@%s", my_name, lp_realm());
	asprintf(&valid_princ_formats[1], "host/%s@%s", my_name, lp_realm());
	asprintf(&valid_princ_formats[2], "host/%s@%s", my_fqdn, lp_realm());
	asprintf(&valid_princ_formats[3], "host/%s.%s@%s", my_name, lp_realm(), lp_realm());
	asprintf(&valid_princ_formats[4], "cifs/%s@%s", my_name, lp_realm());
	asprintf(&valid_princ_formats[5], "cifs/%s@%s", my_fqdn, lp_realm());
	asprintf(&valid_princ_formats[6], "cifs/%s.%s@%s", my_name, lp_realm(), lp_realm());

	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(kt_cursor);

	ret = krb5_kt_default(context, &keytab);
	if (ret) {
		DEBUG(1, ("ads_keytab_verify_ticket: krb5_kt_default failed (%s)\n", 
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		goto out;
	}

	/* Iterate through the keytab.  For each key, if the principal
	 * name case-insensitively matches one of the allowed formats,
	 * try verifying the ticket using that principal. */

	ret = krb5_kt_start_seq_get(context, keytab, &kt_cursor);
	if (ret) {
		last_error_message = smb_get_krb5_error_message(context, ret, mem_ctx);
		DEBUG(1, ("ads_keytab_verify_ticket: krb5_kt_start_seq_get failed (%s)\n", 
			  last_error_message));
		goto out;
	}
  
	ret = krb5_kt_start_seq_get(context, keytab, &kt_cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN; /* Pick an error... */
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
				p_packet->length = ticket->length;
				p_packet->data = (krb5_pointer)ticket->data;
				*pp_tkt = NULL;
				ret = krb5_rd_req(context, &auth_context, p_packet, kt_entry.principal, keytab, NULL, pp_tkt);
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
 Try to verify a ticket using the secrets.tdb.
***********************************************************************************/

static krb5_error_code ads_secrets_verify_ticket(TALLOC_CTX *mem_ctx, krb5_context context, 
						 krb5_auth_context auth_context,
						 krb5_principal host_princ,
						 const DATA_BLOB *ticket, krb5_data *p_packet, 
						 krb5_ticket **pp_tkt,
						 krb5_keyblock *keyblock)
{
	krb5_error_code ret = 0;
	krb5_error_code our_ret;
	krb5_data password;
	krb5_enctype *enctypes = NULL;
	int i;
	const struct ldb_val *password_v;
	struct ldb_context *ldb;
	int ldb_ret;
	struct ldb_message **msgs;
	const char *base_dn = SECRETS_PRIMARY_DOMAIN_DN;
	const char *attrs[] = {
		"secret",
		NULL
	};
	
	ZERO_STRUCTP(keyblock);

	/* Local secrets are stored in secrets.ldb */
	ldb = secrets_db_connect(mem_ctx);
	if (!ldb) {
		return ENOENT;
	}

	/* search for the secret record */
	ldb_ret = gendb_search(ldb,
			       mem_ctx, base_dn, &msgs, attrs,
			       SECRETS_PRIMARY_REALM_FILTER,
			       lp_realm());
	if (ldb_ret == 0) {
		DEBUG(1, ("Could not find domain join record for %s\n",
			  lp_realm()));
		return ENOENT;
	} else if (ldb_ret != 1) {
		DEBUG(1, ("Found %d records matching cn=%s under DN %s\n", ldb_ret, 
			  lp_realm(), base_dn));
		return ENOENT;
	}

	password_v = ldb_msg_find_ldb_val(msgs[0], "secret");

	password.data = password_v->data;
	password.length = password_v->length;

	/* CIFS doesn't use addresses in tickets. This would break NAT. JRA */

	if ((ret = get_kerberos_allowed_etypes(context, &enctypes))) {
		DEBUG(1,("ads_secrets_verify_ticket: krb5_get_permitted_enctypes failed (%s)\n", 
			 error_message(ret)));
		return ret;
	}

	p_packet->length = ticket->length;
	p_packet->data = (krb5_pointer)ticket->data;

	/* We need to setup a auth context with each possible encoding type in turn. */

	ret =  KRB5_BAD_ENCTYPE;
	for (i=0;enctypes[i];i++) {
		krb5_keyblock *key = NULL;

		if (!(key = malloc_p(krb5_keyblock))) {
			break;
		}
	
		if (create_kerberos_key_from_string(context, host_princ, &password, key, enctypes[i])) {
			SAFE_FREE(key);
			continue;
		}

		krb5_auth_con_setuseruserkey(context, auth_context, key);

		krb5_free_keyblock(context, key);

		our_ret = krb5_rd_req(context, &auth_context, p_packet, 
				      NULL,
				      NULL, NULL, pp_tkt);
		if (!our_ret) {
	
			DEBUG(10,("ads_secrets_verify_ticket: enc type [%u] decrypted message !\n",
				  (unsigned int)enctypes[i] ));
			ret = our_ret;
			break;
		}
	
		DEBUG((our_ret != KRB5_BAD_ENCTYPE) ? 3 : 10,
				("ads_secrets_verify_ticket: enc type [%u] failed to decrypt with error %s\n",
				 (unsigned int)enctypes[i], smb_get_krb5_error_message(context, our_ret, mem_ctx)));

		if (our_ret !=  KRB5_BAD_ENCTYPE) {
			ret = our_ret;
		}
	}

	free_kerberos_etypes(context, enctypes);

	return ret;
}

/**********************************************************************************
 Verify an incoming ticket and parse out the principal name and 
 authorization_data if available.
***********************************************************************************/

 NTSTATUS ads_verify_ticket(TALLOC_CTX *mem_ctx, 
			    krb5_context context,
			    krb5_auth_context auth_context,
			    const char *realm, const char *service, 
			    const DATA_BLOB *ticket, 
			    char **principal, DATA_BLOB *auth_data,
			    DATA_BLOB *ap_rep,
			    krb5_keyblock *keyblock)
{
	NTSTATUS sret = NT_STATUS_LOGON_FAILURE;
	krb5_data packet;
	krb5_ticket *tkt = NULL;
	krb5_rcache rcache = NULL;
	int ret;

	krb5_principal host_princ = NULL;
	char *host_princ_s = NULL;
	BOOL got_replay_mutex = False;

	char *malloc_principal;

	ZERO_STRUCT(packet);
	ZERO_STRUCTP(auth_data);
	ZERO_STRUCTP(ap_rep);

	/* This whole process is far more complex than I would
           like. We have to go through all this to allow us to store
           the secret internally, instead of using /etc/krb5.keytab */

	asprintf(&host_princ_s, "%s$", lp_netbios_name());
	strlower_m(host_princ_s);
	ret = krb5_parse_name(context, host_princ_s, &host_princ);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_parse_name(%s) failed (%s)\n",
			 host_princ_s, error_message(ret)));
		goto out;
	}


	/* Lock a mutex surrounding the replay as there is no locking in the MIT krb5
	 * code surrounding the replay cache... */

	if (!grab_server_mutex("replay cache mutex")) {
		DEBUG(1,("ads_verify_ticket: unable to protect replay cache with mutex.\n"));
		goto out;
	}

	got_replay_mutex = True;

	/*
	 * JRA. We must set the rcache here. This will prevent replay attacks.
	 */

	ret = krb5_get_server_rcache(context, krb5_princ_component(context, host_princ, 0), &rcache);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_get_server_rcache failed (%s)\n", error_message(ret)));
		goto out;
	}

	ret = krb5_auth_con_setrcache(context, auth_context, rcache);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_auth_con_setrcache failed (%s)\n", error_message(ret)));
		goto out;
	}

	ret = ads_keytab_verify_ticket(mem_ctx, context, auth_context, 
				       service, ticket, &packet, &tkt, keyblock);
	if (ret) {
		DEBUG(10, ("ads_secrets_verify_ticket: using host principal: [%s]\n", host_princ_s));
		ret = ads_secrets_verify_ticket(mem_ctx, context, auth_context,
						host_princ, ticket, 
						&packet, &tkt, keyblock);
	}

	release_server_mutex();
	got_replay_mutex = False;

	if (ret) {
		DEBUG(3,("ads_verify_ticket: krb5_rd_req with auth failed (%s)\n", 
			 smb_get_krb5_error_message(context, ret, mem_ctx)));
		goto out;
	}

	ret = krb5_mk_rep(context, auth_context, &packet);
	if (ret) {
		DEBUG(3,("ads_verify_ticket: Failed to generate mutual authentication reply (%s)\n",
			 smb_get_krb5_error_message(context, ret, mem_ctx)));
		goto out;
	}

	*ap_rep = data_blob_talloc(mem_ctx, packet.data, packet.length);
	SAFE_FREE(packet.data);
	packet.length = 0;

#if 0
	file_save("/tmp/ticket.dat", ticket->data, ticket->length);
#endif

	*auth_data = get_auth_data_from_tkt(mem_ctx, tkt);

	*auth_data = unwrap_pac(mem_ctx, auth_data);

#if 0
	if (tkt->enc_part2) {
		file_save("/tmp/authdata.dat",
			  tkt->enc_part2->authorization_data[0]->contents,
			  tkt->enc_part2->authorization_data[0]->length);
	}
#endif

	if ((ret = krb5_unparse_name(context, get_principal_from_tkt(tkt),
				     &malloc_principal))) {
		DEBUG(3,("ads_verify_ticket: krb5_unparse_name failed (%s)\n", 
			 smb_get_krb5_error_message(context, ret, mem_ctx)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	*principal = talloc_strdup(mem_ctx, malloc_principal);
	SAFE_FREE(malloc_principal);
	if (!principal) {
		DEBUG(3,("ads_verify_ticket: talloc_strdup() failed\n"));
		sret = NT_STATUS_NO_MEMORY;
		goto out;
	}

	sret = NT_STATUS_OK;

 out:

	if (got_replay_mutex) {
		release_server_mutex();
	}

	if (!NT_STATUS_IS_OK(sret)) {
		data_blob_free(auth_data);
	}

	if (!NT_STATUS_IS_OK(sret)) {
		data_blob_free(ap_rep);
	}

	if (host_princ) {
		krb5_free_principal(context, host_princ);
	}

	if (tkt != NULL) {
		krb5_free_ticket(context, tkt);
	}

	SAFE_FREE(host_princ_s);

	return sret;
}

#endif /* HAVE_KRB5 */
