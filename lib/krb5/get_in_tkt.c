#include "krb5_locl.h"

static krb5_error_code
krb5_get_salt (krb5_principal princ,
	       krb5_data realm,
	       krb5_data *salt)
{
     size_t len;
     int i;
     krb5_error_code err;
     char *p;
     
     len = realm->len;
     for (i = 0; i < princ->ncomp; ++i)
	  len += princ->comp[i].length;
     err = krb5_alloc (salt, len);
     if (err)
	  return err;
     p = salt->data;
     strncpy (p, realm->data, realm->len);
     p += realm->len;
     for (i = 0; i < princ->cnomp; ++i) {
	  strncpy (p, princ->comp[i].data, princ->comp[i].length);
	  p += princ->comp[i].length;
     }
     return 0;
}

/*
 *
 */

krb5_error_code
krb5_get_in_tkt(krb5_context context,
		krb5_flags options,
		krb5_address *const *addrs,
		const krb5_enctype *etypes,
		const krb5_preauthtype *ptypes,
		krb5_key_proc key_proc,
		krb5_const_pointer keyseed,
		krb5_decrypt_proc decrypt_proc,
		krb5_const_pointer decryptarg,
		krb5_creds *creds,
		krb5_ccache ccache,
		krb5_kdc_rep **ret_as_reply)
{
     As_Req a;
     Kdc_Rep rep;
     krb5_principal server;
     krb5_data req, resp;
     char buf[BUFSIZ];
     Buffer buf;
     krb5_data salt;
     krb5_keyblock *key;

     server.type = KRB_NT_SRV_INST;
     server.ncomp = 2;
     server.comp = malloc (sizeof(*server.comp) * server.ncomp);
     server.comp[0] = string_make ("krbtgt");
     server.comp[1] = creds->client.realm;

     a.pvno = 5;
     a.msg_type = KRB_AS_REQ;
/* a.kdc_options */
     a.cname = &creds->client;
     a.sname = &server;
     a.realm = creds->client.realm;
     a.till  = creds->times.endtime;
     a.nonce = 17;
     if (etypes)
	  a.etypes = etypes;
     else
	  a.etypes = context->etypes;
     if (addrs)
	  a.addresses = addrs;
     else
	  a.addresses = krb5_get_all_client_addrs ();
     
     req.data = buf;

     req.len = der_put_as_req (req.data + sizeof(buf) - 1, &a);
     string_free (server.comp[0]);
     free (server.comp);
     if (addrs == NULL)
	  free (a.addresses);

     err = krb5_sendto_kdc (context, &req, a.realm, &resp);
     if (err) {
	  return err;
     }
     buf_init (&buffer, resp.data, resp.len);
     if (der_get_as_rep (&buffer, &rep) == -1) {
	  return ASN1_PARSE_ERROR;
     }
     err = krb5_get_salt (creds->client, creds->client.realm, &salt);
     if (err)
	  return err;
     err = (*key_proc)(context, b.enc_part.etype, salt, keyseed, &key);
     krb5_data_free (&salt);
     if (err)
	  return err;
     
     err = (*decrypt_proc)(context, key, decryptarg, &rep);
     memset (&key.contents.data, 0, key.contents.length);
     krb5_data_free (&key.contents);
     if (err)
	  return err;
}
