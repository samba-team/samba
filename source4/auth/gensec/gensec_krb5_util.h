/* See gensec_krb5_util.c for the license */

krb5_error_code smb_rd_req_return_stuff(krb5_context context, 
					krb5_auth_context *auth_context,
					const krb5_data *inbuf,
					krb5_keytab keytab, 
					krb5_principal acceptor_principal,
					krb5_data *outbuf, 
					krb5_ticket **ticket, 
					krb5_keyblock **keyblock);
