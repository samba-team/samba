/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   
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
  simulate a kinit, putting the tgt in the default cache location
  remus@snapserver.com
*/
int kerberos_kinit_password(const char *principal, const char *password)
{
	krb5_context ctx;
	krb5_error_code code = 0;
	krb5_ccache cc;
	krb5_principal me;
	krb5_creds my_creds;
	
	if ((code = krb5_init_context(&ctx)))
		return code;
	
	if ((code = krb5_cc_default(ctx, &cc))) {
		krb5_free_context(ctx);
		return code;
	}
	
	if ((code = krb5_parse_name(ctx, principal, &me))) {
		krb5_free_context(ctx);	
		return code;
	}
	
	if ((code = krb5_get_init_creds_password(ctx, &my_creds, me, password, NULL, 
						NULL, 0, NULL, NULL))) {
		krb5_free_principal(ctx, me);
		krb5_free_context(ctx);		
		return code;
	}
	
	if ((code = krb5_cc_initialize(ctx, cc, me))) {
		krb5_free_cred_contents(ctx, &my_creds);
		krb5_free_principal(ctx, me);
		krb5_free_context(ctx);		
		return code;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		krb5_cc_close(ctx, cc);
		krb5_free_cred_contents(ctx, &my_creds);
		krb5_free_principal(ctx, me);
		krb5_free_context(ctx);		
		return code;
	}
	
	krb5_cc_close(ctx, cc);
	krb5_free_cred_contents(ctx, &my_creds);
	krb5_free_principal(ctx, me);
	krb5_free_context(ctx);		
	
	return 0;
}



/* run kinit to setup our ccache */
int ads_kinit_password(ADS_STRUCT *ads)
{
	char *s;
	int ret;
	extern pstring global_myname;
	fstring myname;
	fstrcpy(myname, global_myname);
	strlower(myname);
	asprintf(&s, "HOST/%s@%s", global_myname, ads->realm);
	ret = kerberos_kinit_password(s, ads->password);
	free(s);
	if (ret) {
		DEBUG(1,("kerberos_kinit_password failed: %s\n", error_message(ret)));
	}
	return ret;
}

/*
  verify an incoming ticket and parse out the principal name and 
  authorization_data if available 
*/
NTSTATUS ads_verify_ticket(ADS_STRUCT *ads, const DATA_BLOB *ticket, 
			   char **principal, DATA_BLOB *auth_data)
{
	krb5_context context;
	krb5_auth_context auth_context = NULL;
	krb5_keytab keytab = NULL;
	krb5_data packet;
	krb5_ticket *tkt = NULL;
	krb5_data salt;
	krb5_encrypt_block eblock;
	int ret;
	krb5_keyblock * key;
	krb5_principal host_princ;
	char *host_princ_s;
	extern pstring global_myname;
	fstring myname;
	char *password_s;
	krb5_data password;

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

	ret = krb5_set_default_realm(context, ads->realm);
	if (ret) {
		DEBUG(1,("krb5_set_default_realm failed (%s)\n", error_message(ret)));
		ads_destroy(&ads);
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

	fstrcpy(myname, global_myname);
	strlower(myname);
	asprintf(&host_princ_s, "HOST/%s@%s", myname, lp_realm());
	ret = krb5_parse_name(context, host_princ_s, &host_princ);
	if (ret) {
		DEBUG(1,("krb5_parse_name(%s) failed (%s)\n", host_princ_s, error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	ret = krb5_principal2salt(context, host_princ, &salt);
	if (ret) {
		DEBUG(1,("krb5_principal2salt failed (%s)\n", error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}
    
	if (!(key = (krb5_keyblock *)malloc(sizeof(*key)))) {
		return NT_STATUS_NO_MEMORY;
	}
	
	krb5_use_enctype(context, &eblock, ENCTYPE_DES_CBC_MD5);
	
	ret = krb5_string_to_key(context, &eblock, key, &password, &salt);
	if (ret) {
		DEBUG(1,("krb5_string_to_key failed (%s)\n", error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	krb5_auth_con_setuseruserkey(context, auth_context, key);

	packet.length = ticket->length;
	packet.data = (krb5_pointer)ticket->data;

#if 0
	file_save("/tmp/ticket.dat", ticket->data, ticket->length);
#endif

	if ((ret = krb5_rd_req(context, &auth_context, &packet, 
			       NULL, keytab, NULL, &tkt))) {
		DEBUG(3,("krb5_rd_req with auth failed (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	if (tkt->enc_part2) {
		*auth_data = data_blob(tkt->enc_part2->authorization_data[0]->contents,
				       tkt->enc_part2->authorization_data[0]->length);
	}

#if 0
	if (tkt->enc_part2) {
		file_save("/tmp/authdata.dat", 
			  tkt->enc_part2->authorization_data[0]->contents,
			  tkt->enc_part2->authorization_data[0]->length);
	}
#endif

	if ((ret = krb5_unparse_name(context, tkt->enc_part2->client, principal))) {
		DEBUG(3,("krb5_unparse_name failed (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_LOGON_FAILURE;
	}

	return NT_STATUS_OK;
}

#endif
