#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_sendauth(krb5_context context,
	      krb5_auth_context auth_context,
	      krb5_pointer fd,
	      char *appl_version,
	      krb5_principal client,
	      krb5_principal server,
	      krb5_flags ap_req_options,
	      krb5_data *in_data,
	      krb5_creds *in_creds,
	      krb5_ccache ccache,
	      /*krb5_error*/ void **error,
	      /*krb5_ap_rep_enc_part*/ void **rep_result,
	      krb5_creds **out_creds)
{
}
