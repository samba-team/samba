/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Luke Howard 2003   
   Copyright (C) Guenther Deschner 2003
   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003
   
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
	BOOL auth_ok = False;
	krb5_keytab keytab = NULL;
	char *my_fqdn;
	fstring my_name;
	fstring my_Fqdn, my_NAME;
	char *p_fqdn;
	char *host_princ_s[18];
	krb5_principal host_princ;
	int i;

	ret = krb5_kt_default(context, &keytab);
	if (ret) {
		DEBUG(1, ("ads_keytab_verify_ticket: krb5_kt_default failed (%s)\n", error_message(ret)));
		goto out;
	}

	/* Generate the list of principal names which we expect clients might
	 * want to use for authenticating to the file service. */

	fstrcpy(my_name, lp_netbios_name());
	strlower_m(my_name);

	fstrcpy(my_NAME, lp_netbios_name());
	strupper_m(my_NAME);

	my_fqdn = name_to_fqdn(mem_ctx, lp_netbios_name());
	strlower_m(my_fqdn);

	p_fqdn = strchr_m(my_fqdn, '.');
	fstrcpy(my_Fqdn, my_NAME);
	if (p_fqdn) {
		fstrcat(my_Fqdn, p_fqdn);
	}

        asprintf(&host_princ_s[0], "%s$@%s", my_name, lp_realm());
        asprintf(&host_princ_s[1], "%s$@%s", my_NAME, lp_realm());
        asprintf(&host_princ_s[2], "host/%s@%s", my_name, lp_realm());
        asprintf(&host_princ_s[3], "host/%s@%s", my_NAME, lp_realm());
        asprintf(&host_princ_s[4], "host/%s@%s", my_fqdn, lp_realm());
        asprintf(&host_princ_s[5], "host/%s@%s", my_Fqdn, lp_realm());
        asprintf(&host_princ_s[6], "HOST/%s@%s", my_name, lp_realm());
        asprintf(&host_princ_s[7], "HOST/%s@%s", my_NAME, lp_realm());
        asprintf(&host_princ_s[8], "HOST/%s@%s", my_fqdn, lp_realm());
        asprintf(&host_princ_s[9], "HOST/%s@%s", my_Fqdn, lp_realm());
        asprintf(&host_princ_s[10], "%s/%s@%s", service, my_name, lp_realm());
        asprintf(&host_princ_s[11], "%s/%s@%s", service, my_NAME, lp_realm());
        asprintf(&host_princ_s[12], "%s/%s@%s", service, my_fqdn, lp_realm());
        asprintf(&host_princ_s[13], "%s/%s@%s", service, my_Fqdn, lp_realm());
        asprintf(&host_princ_s[14], "%s/%s@%s", strupper_talloc(mem_ctx, service), my_name, lp_realm());
        asprintf(&host_princ_s[15], "%s/%s@%s", strupper_talloc(mem_ctx, service), my_NAME, lp_realm());
        asprintf(&host_princ_s[16], "%s/%s@%s", strupper_talloc(mem_ctx, service), my_fqdn, lp_realm());
        asprintf(&host_princ_s[17], "%s/%s@%s", strupper_talloc(mem_ctx, service), my_Fqdn, lp_realm());

	/* Now try to verify the ticket using the key associated with each of
	 * the principals which we think clients will expect us to be
	 * participating as. */
	for (i = 0; i < sizeof(host_princ_s) / sizeof(host_princ_s[0]); i++) {
		host_princ = NULL;
		ret = krb5_parse_name(context, host_princ_s[i], &host_princ);
		if (ret) {
			DEBUG(1, ("ads_keytab_verify_ticket: krb5_parse_name(%s) failed (%s)\n",
				host_princ_s[i], error_message(ret)));
			goto out;
		}
		p_packet->length = ticket->length;
		p_packet->data = (krb5_pointer)ticket->data;
		*pp_tkt = NULL;
		ret = krb5_rd_req(context, &auth_context, p_packet, host_princ, keytab, NULL, pp_tkt);
		krb5_free_principal(context, host_princ);
		if (ret) {
			DEBUG(0, ("krb5_rd_req(%s) failed: %s\n", host_princ_s[i], error_message(ret)));
		} else {
			DEBUG(10,("krb5_rd_req succeeded for principal %s\n", host_princ_s[i]));
			auth_ok = True;
			break;
                }
	}

	for (i = 0; i < sizeof(host_princ_s) / sizeof(host_princ_s[0]); i++) {
		SAFE_FREE(host_princ_s[i]);
	}

  out:

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
	char *password_s = NULL;
	krb5_data password;
	krb5_enctype *enctypes = NULL;
	int i;

	ZERO_STRUCTP(keyblock);

	if (!secrets_init()) {
		DEBUG(1,("ads_secrets_verify_ticket: secrets_init failed\n"));
		return KRB5_KT_END;
	}

	password_s = secrets_fetch_machine_password(lp_workgroup());
	if (!password_s) {
		DEBUG(1,("ads_secrets_verify_ticket: failed to fetch machine password\n"));
		return KRB5_KT_END;
	}

	password.data = password_s;
	password.length = strlen(password_s);

	/* CIFS doesn't use addresses in tickets. This would break NAT. JRA */

	if ((ret = get_kerberos_allowed_etypes(context, &enctypes))) {
		DEBUG(1,("ads_secrets_verify_ticket: krb5_get_permitted_enctypes failed (%s)\n", 
			 error_message(ret)));
		goto out;
	}

	p_packet->length = ticket->length;
	p_packet->data = (krb5_pointer)ticket->data;

	ret = KRB5_BAD_ENCTYPE;
	/* We need to setup a auth context with each possible encoding type in turn. */
	for (i=0;enctypes[i];i++) {
		krb5_error_code our_ret;
		our_ret = create_kerberos_key_from_string(context, host_princ, &password, keyblock, enctypes[i]);
		if (our_ret) {
			ret = our_ret;
			continue;
		}

		krb5_auth_con_setuseruserkey(context, auth_context, keyblock);

		our_ret = krb5_rd_req(context, &auth_context, p_packet, 
					NULL,
					NULL, NULL, pp_tkt);
		if (!our_ret) {
			DEBUG(10,("ads_secrets_verify_ticket: enc type [%u] decrypted message !\n",
				(unsigned int)enctypes[i] ));
			ret = our_ret;
			break;
		}

		krb5_free_keyblock_contents(context, keyblock);

		DEBUG((our_ret != KRB5_BAD_ENCTYPE) ? 3 : 10,
				("ads_secrets_verify_ticket: enc type [%u] failed to decrypt with error %s\n",
				(unsigned int)enctypes[i], error_message(our_ret)));

		if (our_ret !=  KRB5_BAD_ENCTYPE) {
			ret = our_ret;
		}
	}

 out:

	free_kerberos_etypes(context, enctypes);
	SAFE_FREE(password_s);

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
			 error_message(ret)));
		goto out;
	}

	ret = krb5_mk_rep(context, auth_context, &packet);
	if (ret) {
		DEBUG(3,("ads_verify_ticket: Failed to generate mutual authentication reply (%s)\n",
			error_message(ret)));
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
			 error_message(ret)));
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
