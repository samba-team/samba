#include <krb5_locl.h>
#include <krb5_error.h>

/*
 *
 */

krb5_error_code
krb5_get_credentials (krb5_context context,
		      krb5_flags options,
		      krb5_ccache ccache,
		      krb5_creds *in_creds,
		      krb5_creds *out_creds)
{
  return 17;
}
#if 0

     krb5_error_code err;
     Tgs_Req a;
     krb5_kdc_rep rep;
     krb5_data req, resp;
     char buf[BUFSIZ];
     int i;
     Buffer buffer;

     /*
      * XXX - Check if cred found in ccache
      */

     /*
      * Prepare Tgs_Req.
      */

     err = krb5_get_default_in_tkt_etypes (context, &a.etypes);
     if (err)
	  return err;
     a.num_etypes = 1;

     err = krb5_get_all_client_addrs (&a.addrs);
     if (err)
	  return err;

     a.pvno = 5;
     a.msg_type = KRB_TGS_REQ;
     memset (&a.kdc_options, 0, sizeof(a.kdc_options));
     /* a.kdc_options */
     a.realm.length = 0;
     krb5_data_copy (&a.realm, in_creds->server->realm.data,
		     in_creds->server->realm.length);
     krb5_copy_principal (context, in_creds->server, &a.sname);
     a.till = in_creds->times.endtime;
     a.nonce = 17;
     a.cname = NULL;

     /*
      * Encode
      */

     req.length = der_put_as_req (buf + sizeof (buf) - 1, &a);
     req.data   = buf + sizeof(buf) - req.length;

     for (i = 0; i < a.addrs.number; ++i)
	  krb5_data_free (&a.addrs.addrs[i].address);
     free (a.addrs.addrs);

     /*
      * Send and receive
      */

     err = krb5_sendto_kdc (context, &req, &a.realm, &resp);
     if (err) {
	  return err;
     }
     buf_init (&buffer, resp.data, resp.length);
     if (der_get_tgs_rep (&buffer, &rep) == -1) {
	  return ASN1_PARSE_ERROR;
     }


}
#endif
