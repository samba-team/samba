
 krb5_error_code samba_get_pac(krb5_context context, 
			      struct krb5_kdc_configuration *config,
			      krb5_principal client, 
			      krb5_keyblock *krbtgt_keyblock, 
			      krb5_keyblock *server_keyblock, 
			       krb5_data *pac);
