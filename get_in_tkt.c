#include "krb5_locl.h"
#include <krb5_error.h>

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
     int i;
     int len = dec_rep->part1.enc_part.cipher.length;

     des_set_key (key->contents.data, sched);
     buf = malloc (len);
     if (buf == NULL)
	  return ENOMEM;
     des_cbc_encrypt ((des_cblock *)dec_rep->part1.enc_part.cipher.data,
		      (des_cblock *)buf,
		      len,
		      sched,
		      key->contents.data,
		      DES_DECRYPT);
				/* XXX: Check CRC */

     i = decode_EncTGSRepPart(buf + 12, len - 12, &dec_rep->part2);
     free (buf);
     if (i < 0)
       return ASN1_PARSE_ERROR;
     return 0;
}

/*
 *
 */

krb5_error_code
krb5_principal2principalname (PrincipalName *p,
			      krb5_principal from)
{
  int i;

  p->name_type = from->type;
  p->name_string.len = from->ncomp;
  p->name_string.val = malloc(from->ncomp * sizeof(*p->name_string.val));
  for (i = 0; i < from->ncomp; ++i) {
    int len = from->comp[i].length;
    p->name_string.val[i] = malloc(len + 1);
    strncpy (p->name_string.val[i], from->comp[i].data, len);
    p->name_string.val[i][len] = '\0';
  }
  return 0;
}

krb5_error_code
principalname2krb5_principal (krb5_principal p,
			      PrincipalName from,
			      krb5_data realm)
{
  int i;

  p = malloc (sizeof(*p));
  p->type = from.name_type;
  p->ncomp = from.name_string.len;
  p->comp = malloc (p->ncomp * sizeof(*p->comp));
  for (i = 0; i < p->ncomp; ++i) {
    int len = strlen(from.name_string.val[i]) + 1;
    p->comp[i].length = len;
    p->comp[i].data = strdup(from.name_string.val[i]);
  }
  p->realm = realm;
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
     AS_REQ a;
     krb5_kdc_rep rep;
     krb5_data req, resp;
     char buf[BUFSIZ];
     krb5_data salt;
     krb5_keyblock *key;

     a.pvno = 5;
     a.msg_type = krb_as_req;
     memset (&a.req_body.kdc_options, 0, sizeof(a.req_body.kdc_options));
/* a.kdc_options */
     a.req_body.cname = malloc(sizeof(*a.req_body.cname));
     a.req_body.sname = malloc(sizeof(*a.req_body.sname));
     krb5_principal2principalname (a.req_body.cname, creds->client);
     krb5_principal2principalname (a.req_body.sname, creds->server);
     a.req_body.realm = malloc(creds->client->realm.length + 1);
     strncpy (a.req_body.realm, creds->client->realm.data,
	      creds->client->realm.length);
     a.req_body.realm[creds->client->realm.length] = '\0';

     a.req_body.till  = creds->times.endtime;
     a.req_body.nonce = 17;
     if (etypes)
       abort ();
     else {
	  err = krb5_get_default_in_tkt_etypes (context,
						&a.req_body.etype.val);
	  if (err)
	       return err;
	  a.req_body.etype.len = 1;
     }
     if (addrs){
     } else {
          a.req_body.addresses = malloc(sizeof(*a.req_body.addresses));

	  err = krb5_get_all_client_addrs (a.req_body.addresses);
	  if (err)
	       return err;
     }
     a.req_body.enc_authorization_data = NULL;
     a.req_body.additional_tickets = NULL;
     a.padata = NULL;

     req.length = encode_AS_REQ (buf + sizeof(buf) - 1,
				 sizeof(buf),
				 &a);
     if (req.length < 0)
       return ASN1_PARSE_ERROR;
     req.data = buf + sizeof(buf) - req.length;
     if (addrs == NULL) {
	  int i;

	  for (i = 0; i < a.req_body.addresses->len; ++i)
	       krb5_data_free (&a.req_body.addresses->val[i].address);
	  free (a.req_body.addresses->val);
     }

     err = krb5_sendto_kdc (context, &req, &creds->client->realm, &resp);
     if (err) {
	  return err;
     }
     if(decode_AS_REP(resp.data, resp.length, &rep.part1) < 0)
       return ASN1_PARSE_ERROR;

     free (rep.part1.crealm);
     /*     krb5_principal_free (rep.part1.cname);*/
     creds->ticket.kvno  = rep.part1.ticket.tkt_vno;
     creds->ticket.etype = rep.part1.enc_part.etype;
     creds->ticket.enc_part.length = 0;
     creds->ticket.enc_part.data   = NULL;
     krb5_data_copy (&creds->ticket.enc_part,
		     rep.part1.ticket.enc_part.cipher.data,
		     rep.part1.ticket.enc_part.cipher.length);
     krb5_data_free (&rep.part1.ticket.enc_part.cipher);

     principalname2krb5_principal (creds->ticket.sprinc,
				   rep.part1.ticket.sname,
				   creds->client->realm);
     /*     krb5_free_principal (rep.part1.ticket.sprinc);*/

     salt.length = 0;
     salt.data = NULL;
     err = krb5_get_salt (creds->client, creds->client->realm, &salt);
     if (err)
	  return err;
     err = (*key_proc)(context, rep.part1.enc_part.etype, &salt,
		       keyseed, &key);
     krb5_data_free (&salt);
     if (err)
	  return err;
     
     if (decrypt_proc == NULL)
	  decrypt_proc = decrypt_tkt;

     err = (*decrypt_proc)(context, key, decryptarg, &rep);
     if (err)
       return err;
     memset (key->contents.data, 0, key->contents.length);
     krb5_data_free (&key->contents);
     free (key);
     if (rep.part2.key_expiration)
	  free (rep.part2.key_expiration);
     if (rep.part2.starttime) {
	  creds->times.starttime = *rep.part2.starttime;
	  free (rep.part2.starttime);
     } else
	  creds->times.starttime = rep.part2.authtime;
     if (rep.part2.renew_till) {
	  creds->times.renew_till = *rep.part2.renew_till;
	  free (rep.part2.renew_till);
     } else
	  creds->times.renew_till = rep.part2.endtime;
     creds->times.authtime = rep.part2.authtime;
     creds->times.endtime  = rep.part2.endtime;
#if 0 /* What? */
     if (rep.part2.req.values)
	  free (rep.part2.req.values);
#endif
#if 0
     if (rep.part2.caddr.addrs) {
	  int i;

	  for (i = 0; i < rep.part2.caddr.number; ++i) {
	       krb5_data_free (&rep.part2.caddr.addrs[i].address);
	  }
	  free (rep.part2.caddr.addrs);
     }
     krb5_principal_free (rep.part2.sname);
     krb5_data_free (&rep.part2.srealm);
#endif
	  
     if (err)
	  return err;

     creds->session.contents.length = 0;
     creds->session.contents.data   = NULL;
     creds->session.keytype = rep.part2.key.keytype;
     err = krb5_data_copy (&creds->session.contents,
			   rep.part2.key.keyvalue.data,
			   rep.part2.key.keyvalue.length);
     memset (rep.part2.key.keyvalue.data, 0,
	     rep.part2.key.keyvalue.length);
     krb5_data_free (&rep.part2.key.keyvalue);

     if (err)
	  return err;

     return krb5_cc_store_cred (context, ccache, creds);
}
