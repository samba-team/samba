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

#ifdef HAVE_KRB5

/*
  verify an incoming ticket and parse out the principal name and 
  authorization_data if available 
*/
NTSTATUS ads_verify_ticket(const char *realm, const DATA_BLOB *ticket, 
			   char **principal, DATA_BLOB *auth_data,
			   DATA_BLOB *ap_rep,
			   DATA_BLOB *session_key)
{
	NTSTATUS sret = NT_STATUS_LOGON_FAILURE;
	krb5_context context = NULL;
	krb5_auth_context auth_context = NULL;
	krb5_data packet;
	krb5_ticket *tkt = NULL;
	krb5_rcache rcache = NULL;
	int ret, i;
	krb5_keyblock *key = NULL;

	krb5_principal host_princ;
	char *host_princ_s = NULL;
	BOOL free_host_princ = False;
	BOOL got_replay_mutex = False;

	fstring myname;
	char *password_s = NULL;
	krb5_data password;
	krb5_enctype *enctypes = NULL;
#if 0
	krb5_address local_addr;
	krb5_address remote_addr;
#endif
	BOOL auth_ok = False;

	ZERO_STRUCT(packet);
	ZERO_STRUCT(password);
	ZERO_STRUCTP(auth_data);
	ZERO_STRUCTP(ap_rep);

	if (!secrets_init()) {
		DEBUG(1,("ads_verify_ticket: secrets_init failed\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	password_s = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);
	if (!password_s) {
		DEBUG(1,("ads_verify_ticket: failed to fetch machine password\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	password.data = password_s;
	password.length = strlen(password_s);

	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_init_context failed (%s)\n", error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	ret = krb5_set_default_realm(context, realm);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_set_default_realm failed (%s)\n", error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	/* This whole process is far more complex than I would
           like. We have to go through all this to allow us to store
           the secret internally, instead of using /etc/krb5.keytab */

	ret = krb5_auth_con_init(context, &auth_context);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_auth_con_init failed (%s)\n", error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	fstrcpy(myname, global_myname());
	strlower_m(myname);
	asprintf(&host_princ_s, "HOST/%s@%s", myname, lp_realm());
	ret = krb5_parse_name(context, host_princ_s, &host_princ);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_parse_name(%s) failed (%s)\n",
					host_princ_s, error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	free_host_princ = True;

	/*
	 * JRA. We must set the rcache here. This will prevent replay attacks.
	 */

	ret = krb5_get_server_rcache(context, krb5_princ_component(context, host_princ, 0), &rcache);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_get_server_rcache failed (%s)\n", error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	ret = krb5_auth_con_setrcache(context, auth_context, rcache);
	if (ret) {
		DEBUG(1,("ads_verify_ticket: krb5_auth_con_setrcache failed (%s)\n", error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	/* CIFS doesn't use addresses in tickets. This would breat NAT. JRA */

	if ((ret = get_kerberos_allowed_etypes(context, &enctypes))) {
		DEBUG(1,("ads_verify_ticket: krb5_get_permitted_enctypes failed (%s)\n", 
			 error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	/* Lock a mutex surrounding the replay as there is no locking in the MIT krb5
	 * code surrounding the replay cache... */

	if (!grab_server_mutex("replay cache mutex")) {
		DEBUG(1,("ads_verify_ticket: unable to protect replay cache with mutex.\n"));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	got_replay_mutex = True;

	/* We need to setup a auth context with each possible encoding type in turn. */
	for (i=0;enctypes[i];i++) {
		if (!(key = (krb5_keyblock *)malloc(sizeof(*key)))) {
			sret = NT_STATUS_NO_MEMORY;
			goto out;
		}
	
		if (create_kerberos_key_from_string(context, host_princ, &password, key, enctypes[i])) {
			continue;
		}

		krb5_auth_con_setuseruserkey(context, auth_context, key);

		krb5_free_keyblock(context, key);

		packet.length = ticket->length;
		packet.data = (krb5_pointer)ticket->data;

		if (!(ret = krb5_rd_req(context, &auth_context, &packet, 
					NULL,
					NULL, NULL, &tkt))) {
			DEBUG(10,("ads_verify_ticket: enc type [%u] decrypted message !\n",
				(unsigned int)enctypes[i] ));
			auth_ok = True;
			break;
		}
	
		DEBUG((ret != KRB5_BAD_ENCTYPE) ? 3 : 10,
				("ads_verify_ticket: enc type [%u] failed to decrypt with error %s\n",
				(unsigned int)enctypes[i], error_message(ret)));
	}

	release_server_mutex();
	got_replay_mutex = False;

	if (!auth_ok) {
		DEBUG(3,("ads_verify_ticket: krb5_rd_req with auth failed (%s)\n", 
			 error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	ret = krb5_mk_rep(context, auth_context, &packet);
	if (ret) {
		DEBUG(3,("ads_verify_ticket: Failed to generate mutual authentication reply (%s)\n",
			error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	*ap_rep = data_blob(packet.data, packet.length);
	free(packet.data);

	get_krb5_smb_session_key(context, auth_context, session_key, True);
	dump_data_pw("SMB session key (from ticket)\n", session_key->data, session_key->length);

#if 0
	file_save("/tmp/ticket.dat", ticket->data, ticket->length);
#endif

	get_auth_data_from_tkt(auth_data, tkt);

	{
		TALLOC_CTX *ctx = talloc_init("pac data");
		decode_pac_data(auth_data, ctx);
		talloc_destroy(ctx);
	}

#if 0
	if (tkt->enc_part2) {
		file_save("/tmp/authdata.dat",
			  tkt->enc_part2->authorization_data[0]->contents,
			  tkt->enc_part2->authorization_data[0]->length);
	}
#endif

	if ((ret = krb5_unparse_name(context, get_principal_from_tkt(tkt),
				     principal))) {
		DEBUG(3,("ads_verify_ticket: krb5_unparse_name failed (%s)\n", 
			 error_message(ret)));
		sret = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	sret = NT_STATUS_OK;

 out:

	if (got_replay_mutex)
		release_server_mutex();

	if (!NT_STATUS_IS_OK(sret))
		data_blob_free(auth_data);

	if (!NT_STATUS_IS_OK(sret))
		data_blob_free(ap_rep);

	if (free_host_princ)
		krb5_free_principal(context, host_princ);

	if (tkt != NULL)
		krb5_free_ticket(context, tkt);
	free_kerberos_etypes(context, enctypes);
	SAFE_FREE(password_s);
	SAFE_FREE(host_princ_s);

	if (auth_context)
		krb5_auth_con_free(context, auth_context);

	if (context)
		krb5_free_context(context);

	return sret;
}

#endif /* HAVE_KRB5 */
