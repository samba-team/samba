/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Luke Howard 2003   
   
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
NTSTATUS ads_verify_ticket(ADS_STRUCT *ads, const DATA_BLOB *ticket, 
			   char **principal, DATA_BLOB *auth_data,
			   DATA_BLOB *ap_rep,
			   uint8 session_key[16])
{
	krb5_context context;
	krb5_auth_context auth_context = NULL;
	krb5_keytab keytab = NULL;
	krb5_data packet;
	krb5_ticket *tkt = NULL;
	int ret, i;
	krb5_keyblock * key;
	krb5_principal host_princ;
	char *host_princ_s;
	fstring myname;
	char *password_s;
	krb5_data password;
	krb5_enctype *enctypes = NULL;
	BOOL auth_ok = False;

	if (!secrets_init()) {
		DEBUG(1,("secrets_init failed\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	password_s = secrets_fetch_machine_password();
	if (!password_s) {
		DEBUG(1,("failed to fetch machine password\n"));
		return NT_STATUS_LOGON_FAILURE;
	}

	password.data = password_s;
	password.length = strlen(password_s);

	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("krb5_init_context failed (%s)\n", error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	ret = krb5_set_default_realm(context, ads->auth.realm);
	if (ret) {
		DEBUG(1,("krb5_set_default_realm failed (%s)\n", error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	/* this whole process is far more complex than I would
           like. We have to go through all this to allow us to store
           the secret internally, instead of using /etc/krb5.keytab */
	ret = krb5_auth_con_init(context, &auth_context);
	if (ret) {
		DEBUG(1,("krb5_auth_con_init failed (%s)\n", error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	fstrcpy(myname, global_myname());
	strlower(myname);
	asprintf(&host_princ_s, "HOST/%s@%s", myname, lp_realm());
	ret = krb5_parse_name(context, host_princ_s, &host_princ);
	if (ret) {
		DEBUG(1,("krb5_parse_name(%s) failed (%s)\n", host_princ_s, error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	if (!(key = (krb5_keyblock *)malloc(sizeof(*key)))) {
		return NT_STATUS_NO_MEMORY;
	}
	
	if ((ret = get_kerberos_allowed_etypes(context, &enctypes))) {
		DEBUG(1,("krb5_get_permitted_enctypes failed (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	/* we need to setup a auth context with each possible encoding type in turn */
	for (i=0;enctypes[i];i++) {
		if (create_kerberos_key_from_string(context, host_princ, &password, key, enctypes[i])) {
			continue;
		}

		krb5_auth_con_setuseruserkey(context, auth_context, key);

		packet.length = ticket->length;
		packet.data = (krb5_pointer)ticket->data;

		if (!(ret = krb5_rd_req(context, &auth_context, &packet, 
				       NULL, keytab, NULL, &tkt))) {
			free_kerberos_etypes(context, enctypes);
			auth_ok = True;
			break;
		}
	}

	if (!auth_ok) {
		DEBUG(3,("krb5_rd_req with auth failed (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	ret = krb5_mk_rep(context, auth_context, &packet);
	if (ret) {
		DEBUG(3,("Failed to generate mutual authentication reply (%s)\n",
			error_message(ret)));
		krb5_auth_con_free(context, auth_context);
		return NT_STATUS_LOGON_FAILURE;
	}

	*ap_rep = data_blob(packet.data, packet.length);
	free(packet.data);

	krb5_get_smb_session_key(context, auth_context, session_key);
	DEBUG(0,("SMB session key (from ticket) follows:\n"));
	dump_data(0, session_key, 16);

#if 0
	file_save("/tmp/ticket.dat", ticket->data, ticket->length);
#endif

	get_auth_data_from_tkt(auth_data, tkt);

#if 0
	if (tkt->enc_part2) {
		file_save("/tmp/authdata.dat",
			  tkt->enc_part2->authorization_data[0]->contents,
			  tkt->enc_part2->authorization_data[0]->length);
#endif

	if ((ret = krb5_unparse_name(context, get_principal_from_tkt(tkt),
				     principal))) {
		DEBUG(3,("krb5_unparse_name failed (%s)\n", 
			 error_message(ret)));
		data_blob_free(auth_data);
		data_blob_free(ap_rep);
		krb5_auth_con_free(context, auth_context);
		return NT_STATUS_LOGON_FAILURE;
	}

	krb5_auth_con_free(context, auth_context);

	return NT_STATUS_OK;
}

#endif /* HAVE_KRB5 */
