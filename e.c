#include <krb5_locl.h>
#include <d.h>
#include <k5_der.h>

int
der_get_principalname (Buffer *b, krb5_principal *p)
{
     Identifier i;
     int cur, max;
     char *str;
     int len;

     *p = malloc(sizeof(**p));
     if (*p == NULL)
	  return -1;
     (*p)->ncomp = 0;

     if (matchid3 (b, &i, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	  return -1;
     getdata (b, &i, &(*p)->type);
     if (matchcontextid3 (b, &i, UNIV, CONS, UT_Sequence, 1) == NULL)
	  return -1;
     cur = 0;
     max = 1;
     (*p)->comp = malloc(sizeof(*(*p)->comp) * max);
     while (matchid3 (b, &i, UNIV, PRIM, UT_GeneralString)) {
	  if (cur >= max) {
	       max *= 2;
	       (*p)->comp = realloc ((*p)->comp, sizeof(*(*p)->comp) * max);
	  }
	  getdata (b, &i, &(*p)->comp[cur++]);
     }
     (*p)->ncomp = cur;
     return buf_length (b);
}

int
der_get_encrypteddata (Buffer *b, EncryptedData *e)
{
     Identifier i0, i1, i;
     int len;

     if (matchid3 (b, &i0, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	  return -1;
     getdata (b, &i, &e->etype);
     getid (b, &i);
     if (i.tag == 1) {
	  int kvno;

	  if (matchid3 (b, &i, UNIV, PRIM, UT_Integer) == NULL)
	       return -1;
	  getdata (b, &i, &kvno);
	  e->kvno = malloc (sizeof (int));
	  *(e->kvno) = kvno;
     } else
	  e->kvno = NULL;
     if (matchid3 (b, &i1, CONTEXT, CONS, 2) == NULL)
	  return -1;
     if (matchid3 (b, &i, UNIV, PRIM, UT_OctetString) == NULL)
	  return -1;
     getdata (b, &i, &e->cipher);
     getzeros (b, i1.len);
     getzeros (b, i0.len);
     return buf_length (b);
}

int
der_get_ticket (Buffer *b, krb5_ticket *t)
{
     Identifier i0, i1, i;
     EncryptedData e;
     Buffer tmp;
     int len;
     int tkt_vno;

     if (matchid3 (b, &i0, APPL, CONS, APPL_TICKET) == NULL)
	  return -1;
     if (matchid3 (b, &i1, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	  return -1;
     getdata (b, &i, &tkt_vno);
     if (tkt_vno != 5)
	  return -1;
     t->sprinc = malloc (sizeof (*t->sprinc));
     if (t->sprinc == NULL)
	  return -1;
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_GeneralString, 1) == NULL)
	  return -1;
     getdata (b, &i, &t->sprinc->realm);
     if (matchid3 (b, &i, CONTEXT, CONS, 2) == NULL)
	  return -1;
     buf_derive(b, &tmp, i.len);
     len = der_get_principalname (&tmp, &t->sprinc);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     if (matchid3 (b, &i, CONTEXT, CONS, 3) == NULL)
	  return -1;
     buf_derive (b, &tmp, i.len);
     len = der_get_encrypteddata (&tmp, &e);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     getzeros (b, i1.len);
     getzeros (b, i0.len);
     t->kvno  = *e.kvno;
     t->etype = e.etype;
     t->enc_part = e.cipher;
     return buf_length (b);
}

int
der_get_kdc_rep (Buffer *b, int msg, krb5_kdc_rep *k)
{
     Identifier i, i0;
     Buffer tmp;
     int len;

     if (matchid3 (b, &i0, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	  return -1;

     getdata (b, &i, &k->pvno);
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 1) == NULL)
	  return -1;
     getdata (b, &i, &k->msg_type);
     if (k->msg_type != msg)
	  return -1;
     getid (b, &i);
     if (i.tag == 2)
	  abort ();		/* XXX */
     if (i.tag != 3)
	  return -1;
     if (matchid3 (b, &i, UNIV, PRIM, UT_GeneralString) == NULL)
	  return -1;
     getdata (b, &i, &k->realm);
     if (matchid3 (b, &i, CONTEXT, CONS, 4) == NULL)
	  return -1;
     buf_derive(b, &tmp, i.len);
     len = der_get_principalname (&tmp, &k->cname);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     if (matchid3 (b, &i, CONTEXT, CONS, 5) == NULL)
	  return -1;
     buf_derive(b, &tmp, i.len);
     len = der_get_ticket (&tmp, &k->ticket);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     if (matchid3 (b, &i, CONTEXT, CONS, 6) == NULL)
	  return -1;
     buf_derive(b, &tmp, i.len);
     len = der_get_encrypteddata (&tmp, &k->enc_part);
     if(len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     getzeros (b, i0.len);
     return buf_length (b);
}

static int
der_get_kdc_rep_msg (Buffer *b, int msg, krb5_kdc_rep *a)
{
     Identifier i;

     if (matchid3(b, &i, APPL, CONS, msg) == NULL)
	  return -1;
     return der_get_kdc_rep (b, msg, a);
}

int
der_get_as_rep (Buffer *b, As_Rep *a)
{
     return der_get_kdc_rep_msg (b, KRB_AS_REP, a);
}

int
der_get_tgs_rep (Buffer *b, Tgs_Rep *a)
{
     return der_get_kdc_rep_msg (b, KRB_TGS_REP, a);
}

int
der_get_encryptionkey (Buffer *b, krb5_keyblock *k)
{
     Identifier i;

     if (matchid3 (b, &i, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	  return -1;
     getdata (b, &i, &k->keytype);
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_OctetString, 1) == NULL)
	  return -1;
     getdata (b, &i, &k->contents);
     return buf_length (b);
}

int
der_get_hostaddresses (Buffer *b, krb5_addresses *h)
{
     Identifier i;
     int cur, max;

     if (matchid3 (b, &i, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     cur = 0;
     max = 1;
     h->addrs = malloc (sizeof (*h->addrs));
     while (matchid3 (b, &i, UNIV, CONS, UT_Sequence)) {
	  if (cur >= max) {
	       max *= 2;
	       h->addrs = realloc (h->addrs, sizeof(*h->addrs) * max);
	  }
	  if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	       return -1;
	  getdata (b, &i, &h->addrs[cur].type);
	  if (matchcontextid3 (b, &i, UNIV, PRIM, UT_OctetString, 1) == NULL)
	       return -1;
	  getdata (b, &i, &h->addrs[cur].address);
	  ++cur;
     }
     h->number = cur;
     return buf_length (b);
}

int
der_get_lastreq (Buffer *b, LastReq *l)
{
     Identifier i;
     int cur, max;
     
     if (matchid3 (b, &i, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     cur = 0;
     max = 1;
     l->values = malloc (sizeof(*l->values));
     while (matchid3 (b, &i, UNIV, CONS, UT_Sequence)) {
	  if (cur >= max) {
	       max *= 2;
	       l->values = realloc (l->values, sizeof (*l->values) * max);
	  }
	  if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 0) == NULL)
	       return -1;
	  getdata (b, &i, &l->values[cur].lr_type);
	  if (matchcontextid3 (b, &i, UNIV, PRIM, UT_GeneralizedTime, 1) == NULL)
	       return -1;
	  getdata (b, &i, &l->values[cur].lr_value);
	  ++cur;
     }
     l->number = cur;
     return buf_length (b);
}

int
der_get_ticketflags (Buffer *b, TicketFlags *t)
{
     Identifier i;

     return buf_bytesleft (b);
}

int
der_get_enckdcreppart (Buffer *b, int msg, EncKdcRepPart *a)
{
     Identifier i;
     Buffer tmp;
     int len;

     if (matchid3 (b, &i, UNIV, CONS, UT_Sequence) == NULL)
	  return -1;
     if (matchid3 (b, &i, CONTEXT, CONS, 0) == NULL)
	  return -1;
     buf_derive (b, &tmp, i.len);
     len = der_get_encryptionkey (&tmp, &a->key);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     if (matchid3 (b, &i, CONTEXT, CONS, 1) == NULL)
	  return -1;
     buf_derive (b, &tmp, i.len);
     len = der_get_lastreq (&tmp, &a->req);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_Integer, 2) == NULL)
	  return -1;
     getdata (b, &i, &a->nonce);
     getid (b, &i);
     if (i.tag == 3) {
	  if (matchid3 (b, &i, UNIV, PRIM, UT_GeneralizedTime) == NULL)
	       return NULL;

	  a->key_expiration = malloc (sizeof(*a->key_expiration));
	  getdata (b, &i, a->key_expiration);
	  getid (b, &i);
     } else
	  a->key_expiration = NULL;
     if (i.tag != 4)
	  return NULL;
     buf_derive (b, &tmp, i.len);
     len = der_get_ticketflags (&tmp, &a->flags);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     if (matchcontextid3 (b, &i, UNIV, PRIM, UT_GeneralizedTime, 5) == NULL)
	  return NULL;
     getdata (b, &i, &a->authtime);
     getid (b, &i);
     if (i.tag == 6) {
	  if (matchid3 (b, &i, UNIV, PRIM, UT_GeneralizedTime) == NULL)
	       return NULL;

	  a->starttime = malloc (sizeof(*a->starttime));
	  getdata (b, &i, a->starttime);
	  getid (b, &i);
     } else
	  a->starttime = NULL;
     if (i.tag != 7)
	  return NULL;
     if (matchid3 (b, &i, UNIV, PRIM, UT_GeneralizedTime) == NULL)
	  return NULL;
     getdata (b, &i, &a->endtime);
     getid (b, &i);
     if (i.tag == 8) {
	  if (matchid3 (b, &i, UNIV, PRIM, UT_GeneralizedTime) == NULL)
	       return NULL;

	  a->renew_till = malloc (sizeof(*a->renew_till));
	  getdata (b, &i, a->renew_till);
	  getid (b, &i);
     } else
	  a->renew_till = NULL;
     if (i.tag != 9)
	  return NULL;
     if (matchid3 (b, &i, UNIV, PRIM, UT_GeneralString) == NULL)
	  return NULL;
     getdata (b, &i, &a->srealm);
     if (matchid3 (b, &i, CONTEXT, CONS, 10) == NULL)
	  return NULL;
     buf_derive(b, &tmp, i.len);
     len = der_get_principalname (&tmp, &a->sname);
     if (len == -1)
	  return -1;
     buf_advance (b, len);
     getzeros (b, i.len);
     getid (b, &i);
     if (i.tag == 11) {
	  buf_derive (b, &tmp, i.len);
	  len = der_get_hostaddresses (&tmp, &a->caddr);
	  if (len == -1)
	       return -1;
	  buf_advance (b, len);
	  getzeros (b, i.len);
     } else
	  a->caddr.number = 0;
     return buf_length (b);
}

static int
der_get_enckdcreppart_msg (Buffer *b, int msg, EncKdcRepPart *a)
{
     Identifier i;

     if (matchid3 (b, &i, APPL, CONS, msg) == NULL)
	  return -1;
     return der_get_enckdcreppart (b, msg, a);
}

int
der_get_encasreppart (Buffer *b, EncASRepPart *a)
{
     return der_get_enckdcreppart_msg (b, KRB_ENCASREPPART, a);
}

int
der_get_enctgsreppart (Buffer *b, EncTGSRepPart *a)
{
     return der_get_enckdcreppart_msg (b, KRB_ENCKDCREPPART, a);
}
