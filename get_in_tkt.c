#include "krb5_locl.h"
#include <krb5_error.h>
#include <d.h>
#include <k5_der.h>

static krb5_error_code
krb5_get_salt (krb5_principal princ,
	       krb5_data realm,
	       krb5_data *salt)
{
     size_t len;
     int i;
     krb5_error_code err;
     char *p;
     
     len = realm.length;
     for (i = 0; i < princ->ncomp; ++i)
	  len += princ->comp[i].length;
     err = krb5_data_alloc (salt, len);
     if (err)
	  return err;
     p = salt->data;
     strncpy (p, realm.data, realm.length);
     p += realm.length;
     for (i = 0; i < princ->ncomp; ++i) {
	  strncpy (p, princ->comp[i].data, princ->comp[i].length);
	  p += princ->comp[i].length;
     }
     return 0;
}

static krb5_error_code
decrypt_tkt (krb5_context context,
	     const krb5_keyblock *key,
	     krb5_const_pointer decrypt_arg,
	     krb5_kdc_rep *dec_rep)
{
     des_key_schedule sched;
     char *buf;
     Buffer buffer;

     des_set_key (key->contents.data, sched);
     buf = malloc (dec_rep->enc_part.cipher.length);
     if (buf == NULL)
	  return ENOMEM;
     des_cbc_encrypt ((des_cblock *)dec_rep->enc_part.cipher.data,
		      (des_cblock *)buf,
		      dec_rep->enc_part.cipher.length,
		      sched,
		      key->contents.data,
		      DES_DECRYPT);
				/* XXX: Check CRC */
     buf_init (&buffer, buf + 12, dec_rep->enc_part.cipher.length - 12);
     if (der_get_enctgsreppart (&buffer, &dec_rep->enc_part2) == -1) {
	  free (buf);
	  return ASN1_PARSE_ERROR;
     }
     free (buf);
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
     krb5_error_code err;
     As_Req a;
     krb5_kdc_rep rep;
     krb5_data req, resp;
     char buf[BUFSIZ];
     Buffer buffer;
     krb5_data salt;
     krb5_keyblock *key;

     a.pvno = 5;
     a.msg_type = KRB_AS_REQ;
     memset (&a.kdc_options, 0, sizeof(a.kdc_options));
/* a.kdc_options */
     a.cname = creds->client;
     a.sname = creds->server;
     a.realm = creds->client->realm;
     a.till  = creds->times.endtime;
     a.nonce = 17;
     if (etypes)
	  a.etypes = etypes;
     else {
	  err = krb5_get_default_in_tkt_etypes (context, &a.etypes);
	  if (err)
	       return err;
	  a.num_etypes = 1;
     }
     if (addrs){
     } else {
	  err = krb5_get_all_client_addrs (&a.addrs);
	  if (err)
	       return err;
     }
     
     req.length = der_put_as_req (buf + sizeof(buf) - 1, &a);
     req.data   = buf + sizeof(buf) - req.length;
     if (addrs == NULL) {
	  int i;

	  for (i = 0; i < a.addrs.number; ++i)
	       krb5_data_free (&a.addrs.addrs[i].address);
	  free (a.addrs.addrs);
     }

     err = krb5_sendto_kdc (context, &req, &a.realm, &resp);
     if (err) {
	  return err;
     }
     buf_init (&buffer, resp.data, resp.length);
     if (der_get_as_rep (&buffer, &rep) == -1) {
	  return ASN1_PARSE_ERROR;
     }
     krb5_data_free (&rep.realm);
     krb5_principal_free (rep.cname);
     creds->ticket.kvno  = rep.ticket.kvno;
     creds->ticket.etype = rep.ticket.etype;
     creds->ticket.enc_part.length = 0;
     creds->ticket.enc_part.data   = NULL;
     krb5_data_copy (&creds->ticket.enc_part,
		     rep.ticket.enc_part.data,
		     rep.ticket.enc_part.length);
     krb5_data_free (&rep.ticket.enc_part);

     krb5_copy_principal (context,
			  rep.ticket.sprinc,
			  &creds->ticket.sprinc);
     krb5_free_principal (rep.ticket.sprinc);

     salt.length = 0;
     salt.data = NULL;
     err = krb5_get_salt (creds->client, creds->client->realm, &salt);
     if (err)
	  return err;
     err = (*key_proc)(context, rep.enc_part.etype, &salt, keyseed, &key);
     krb5_data_free (&salt);
     if (err)
	  return err;
     
     if (decrypt_proc == NULL)
	  decrypt_proc = decrypt_tkt;

     err = (*decrypt_proc)(context, key, decryptarg, &rep);
     memset (key->contents.data, 0, key->contents.length);
     krb5_data_free (&key->contents);
     free (key);
     if (rep.enc_part2.key_expiration)
	  free (rep.enc_part2.key_expiration);
     if (rep.enc_part2.starttime) {
	  creds->times.starttime = *rep.enc_part2.starttime;
	  free (rep.enc_part2.starttime);
     } else
	  creds->times.starttime = rep.enc_part2.authtime;
     if (rep.enc_part2.renew_till) {
	  creds->times.renew_till = *rep.enc_part2.renew_till;
	  free (rep.enc_part2.renew_till);
     } else
	  creds->times.renew_till = rep.enc_part2.endtime;
     creds->times.authtime = rep.enc_part2.authtime;
     creds->times.endtime  = rep.enc_part2.endtime;
     if (rep.enc_part2.req.values)
	  free (rep.enc_part2.req.values);
     if (rep.enc_part2.caddr.addrs) {
	  int i;

	  for (i = 0; i < rep.enc_part2.caddr.number; ++i) {
	       krb5_data_free (&rep.enc_part2.caddr.addrs[i].address);
	  }
	  free (rep.enc_part2.caddr.addrs);
     }
     krb5_principal_free (rep.enc_part2.sname);
     krb5_data_free (&rep.enc_part2.srealm);
	  
     if (err)
	  return err;

     creds->session.contents.length = 0;
     creds->session.contents.data   = NULL;
     creds->session.keytype = rep.enc_part2.key.keytype;
     err = krb5_data_copy (&creds->session.contents,
			   rep.enc_part2.key.contents.data,
			   rep.enc_part2.key.contents.length);
     memset (rep.enc_part2.key.contents.data, 0,
	     rep.enc_part2.key.contents.length);
     krb5_data_free (&rep.enc_part2.key.contents);

     if (err)
	  return err;

     return krb5_cc_store_cred (context, ccache, creds);
}
