/* 
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
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
  we can't use krb5_mk_req because w2k wants the service to be in a particular format
*/
static krb5_error_code krb5_mk_req2(krb5_context context, 
				    krb5_auth_context *auth_context, 
				    const krb5_flags ap_req_options,
				    const char *principal,
				    krb5_ccache ccache, 
				    krb5_data *outbuf)
{
	krb5_error_code 	  retval;
	krb5_principal	  server;
	krb5_creds 		* credsp;
	krb5_creds 		  creds;
	krb5_data in_data;
	
	retval = krb5_parse_name(context, principal, &server);
	if (retval) {
		DEBUG(1,("Failed to parse principal %s\n", principal));
		return retval;
	}
	
	/* obtain ticket & session key */
	memset((char *)&creds, 0, sizeof(creds));
	if ((retval = krb5_copy_principal(context, server, &creds.server))) {
		DEBUG(1,("krb5_copy_principal failed (%s)\n", 
			 error_message(retval)));
		goto cleanup_princ;
	}
	
	if ((retval = krb5_cc_get_principal(context, ccache, &creds.client))) {
		DEBUG(1,("krb5_cc_get_principal failed (%s)\n", 
			 error_message(retval)));
		goto cleanup_creds;
	}

	if ((retval = krb5_get_credentials(context, 0,
					   ccache, &creds, &credsp))) {
		DEBUG(1,("krb5_get_credentials failed for %s (%s)\n", 
			 principal, error_message(retval)));
		goto cleanup_creds;
	}

	in_data.length = 0;
	retval = krb5_mk_req_extended(context, auth_context, ap_req_options, 
				      &in_data, credsp, outbuf);
	if (retval) {
		DEBUG(1,("krb5_mk_req_extended failed (%s)\n", 
			 error_message(retval)));
	}
	
	krb5_free_creds(context, credsp);

cleanup_creds:
	krb5_free_cred_contents(context, &creds);

cleanup_princ:
	krb5_free_principal(context, server);

	return retval;
}

/*
  get a kerberos5 ticket for the given service 
*/
DATA_BLOB krb5_get_ticket(char *principal)
{
	krb5_error_code retval;
	krb5_data packet;
	krb5_ccache ccdef;
	krb5_context context;
	krb5_auth_context auth_context = NULL;
	DATA_BLOB ret;
	krb5_enctype enc_types[] = {ENCTYPE_DES_CBC_MD5, ENCTYPE_NULL};

	retval = krb5_init_context(&context);
	if (retval) {
		DEBUG(1,("krb5_init_context failed (%s)\n", 
			 error_message(retval)));
		goto failed;
	}

	if ((retval = krb5_cc_default(context, &ccdef))) {
		DEBUG(1,("krb5_cc_default failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	if ((retval = krb5_set_default_tgs_ktypes(context, enc_types))) {
		DEBUG(1,("krb5_set_default_tgs_ktypes failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	if ((retval = krb5_mk_req2(context, 
				   &auth_context, 
				   0, 
				   principal,
				   ccdef, &packet))) {
		goto failed;
	}

	ret = data_blob(packet.data, packet.length);
/* Hmm, heimdal dooesn't have this - what's the correct call? */
/* 	krb5_free_data_contents(context, &packet); */
	krb5_free_context(context);
	return ret;

failed:
	krb5_free_context(context);
	return data_blob(NULL, 0);
}


#else /* HAVE_KRB5 */
 /* this saves a few linking headaches */
 DATA_BLOB krb5_get_ticket(char *principal)
 {
	 DEBUG(0,("NO KERBEROS SUPPORT\n"));
	 return data_blob(NULL, 0);
 }
#endif
