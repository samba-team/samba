krb5_error_code
krb5_cc_resolve (krb5_context context,
		 char *residual,
		 krb5_ccache *id);

char *
krb5_cc_get_name (krb5_context context,
		  krb5_ccache id);

char *
krb5_cc_default_name (krb5_context context);

krb5_error_code
krb5_cc_default (krb5_context context,
		 krb5_ccache *id);

krb5_error_code
krb5_cc_initialize (krb5_context context,
		    krb5_ccache id,
		    krb5_principal primary_principal);

krb5_error_code
krb5_cc_destroy (krb5_context context,
		 krb5_ccache id);

krb5_error_code
krb5_cc_close (krb5_context context,
	       krb5_ccache id);

krb5_error_code
krb5_cc_store_cred (krb5_context context,
		    krb5_ccache id,
		    krb5_creds *creds);

krb5_error_code
krb5_cc_retrieve_cred (krb5_context context,
		       krb5_ccache id,
		       krb5_flags whichfields,
		       krb5_creds *mcreds,
		       krb5_creds *creds);

krb5_error_code
krb5_cc_get_principal (krb5_context context,
		       krb5_ccache id,
		       krb5_principal *principal);

krb5_error_code
krb5_cc_get_first (krb5_context context,
		   krb5_ccache id,
		   krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_get_next (krb5_context context,
		  krb5_ccache id,
		  krb5_creds *creds,
		  krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_end_get (krb5_context context,
		 krb5_ccache id,
		 krb5_cc_cursor *cursor);

krb5_error_code
krb5_cc_remove_cred (krb5_context context,
		     krb5_ccache id,
		     krb5_flags which,
		     krb5_creds *cred);

krb5_error_code
krb5_cc_set_flags (krb5_context context,
		   krb5_ccache id,
		   krb5_flags flags);
