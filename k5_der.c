#include <krb5_locl.h>
#include <k5_der.h>

static void
time2generalizedtime (krb5_data *s, time_t t)
{
     struct tm *tm;

     s->data = malloc(16);
     s->length = 15;
     tm = gmtime (&t);
     sprintf (s->data, "%04d%02d%02d%02d%02d%02dZ", tm->tm_year + 1900,
	      tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
	      tm->tm_sec);
}

unsigned
der_put_context_etypes (unsigned char *ptr, int tag,
			krb5_enctype *etypes, unsigned num_etypes)
{
     unsigned char *p = ptr;
     int i;

     for (i = num_etypes - 1; i >= 0; --i)
	  p -= der_put_type_and_value (p, UT_Integer, &etypes[i]);
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     p -= der_put_type (p, CONTEXT, CONS, tag, ptr - p);
     return ptr - p;
}

unsigned
der_put_context_principalname (unsigned char *ptr, int tag,
			       krb5_principal name)
{
     unsigned char *p = ptr;
     int i;

     if (name == NULL)
	  return 0;
     for (i = name->ncomp - 1; i >= 0; --i)
	  p -= der_put_type_and_value (p, UT_GeneralString,
				       &name->comp[i]);
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     p -= der_put_type (p, CONTEXT, CONS, 1, ptr - p);
     p -= der_put_context (p, 0, UT_Integer, &name->type);
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     p -= der_put_type (p, CONTEXT, CONS, tag, ptr - p);
     return ptr - p;
}

unsigned
der_put_context_kdcoptions (unsigned char *ptr, int tag, KdcOptions *k)
{
     unsigned char *p = ptr;
     /* XXX */
     
     *p-- = '\0';
     *p-- = '\0';
     *p-- = '\0';
     *p-- = '\0';
     *p-- = '\0';
     *p-- = 5;
     *p-- = 3;
     p -= der_put_type (p, CONTEXT, CONS, tag, ptr - p);
     return ptr - p;
}

unsigned
der_put_context_hostaddresses (unsigned char *ptr, int tag,
			       krb5_addresses addrs)
{
     unsigned char *p = ptr;
     int i;
     
     for(i = addrs.number - 1; i >= 0; --i) {
	  p -= der_put_context (p, 1, UT_OctetString,
				&addrs.addrs[i].address);
	  p -= der_put_context (p, 0, UT_Integer,
				&addrs.addrs[i].type);
     }
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     p -= der_put_type (p, CONTEXT, CONS, tag, ptr - p);
     return ptr - p;
}

unsigned
der_put_kdc_req_body (unsigned char *ptr, Kdc_Req *k)
{
     unsigned char *p = ptr;

     /* additional-tickets[11] SEQUENCE OF Ticket OPTIONAL */
     /* enc-authorization-data[10] EncryptedData OPTIONAL */
     p -= der_put_context_hostaddresses (p, 9, k->addrs);
     /* addresses[9] HostAddresses OPTIONAL */
     p -= der_put_context_etypes (p, 8, k->etypes, k->num_etypes);
     p -= der_put_context (p, 7, UT_Integer, &k->nonce);
     /* rtime[6] KerberosTime OPTIONAL */
     {
	  krb5_data t;

	  time2generalizedtime (&t, k->till);
	  p -= der_put_context (p, 5, UT_GeneralizedTime, &t);
	  string_free (t);
     }
     /* from[4] KerberosTime OPTIONAL */
     p -= der_put_context_principalname (p, 3, k->sname);
     p -= der_put_context (p, 2, UT_GeneralString, &k->realm);
     p -= der_put_context_principalname (p, 1, k->cname);
     p -= der_put_context_kdcoptions (p, 0, &k->kdc_options);
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     return ptr - p;
}

unsigned
der_put_kdc_req (unsigned char *ptr, int msg_type, Kdc_Req *k)
{
     unsigned char *p = ptr;

     p -= der_put_kdc_req_body (p, k);
     p -= der_put_type (p, CONTEXT, CONS, 4, ptr - p);
     /* padata[3] SEQUENCE OF PA-DATA OPTIONAL */
     p -= der_put_context (p, 2, UT_Integer, &k->msg_type);
     p -= der_put_context (p, 1, UT_Integer, &k->pvno);
     p -= der_put_type (p, UNIV, CONS, UT_Sequence, ptr - p);
     return ptr - p;
}

unsigned
der_put_as_req (unsigned char *ptr, As_Req *a)
{
     unsigned char *p = ptr;

     p -= der_put_kdc_req (p, a->msg_type, a);
     p -= der_put_type (p, APPL, CONS, a->msg_type, ptr - p);
     return ptr - p;
}

#if 0

/*
 * Get functions
 */

int
der_get_principalname (unsigned char *ptr, Principalname *name)
{
     unsigned char *p = ptr;
     unsigned char *p0;
     int tlen, tlen2;

     len = der_match_type (p, UNIV, CONS, UT_Sequence, &tlen);
     if (len < 0)
	  return len;
     else
	  p += len;
     p0 = p;
     len = der_match_context (p, 0, UT_Integer, &name->name_type);
     if (len < 0)
	  return len;
     else
	  p += len;
     len = der_match_type (p, CONTEXT, CONS, 1, &tlen2);
     if (len < 0)
	  return len;
     else
	  p =+ len;
     len = der_match_type ()
     while(p < p0 + tlen) {
     }


     return ptr - p;
}

int
der_get_kdc_rep (unsigned char *ptr, unsigned mylen, int msg_type,
		 krb5_kdc_rep *k)
{
     unsigned char *p = ptr;
     unsigned tlen, slen;
     int len;
     unsigned kvno, msg1;
     unsigned tag;
     int type;
	  
     len = der_match_type (p, UNIV, CONS, UT_Sequence, &tlen);
     if (len < 0)
	  return len;
     else
	  p += len;
     len = der_match_context (p, 0, UT_Integer, &kvno);
     if (len < 0)
	  return len;
     else
	  p += len;
     if (kvno != 5)
	  return -1;
     len = der_match_context (p, 1, UT_Integer, &msg1);
     if (len < 0)
	  return len;
     else
	  p += len;
     if (msg1 != msg_type)
	  return -1;
     len = der_get_context (p, &tag, &type, &tlen);
     if (len < 0)
	  return len;
     else
	  p += len;
     if (tag == 2)
	  abort ();		/* XXX */
     else if (tag == 3) {
	  p += der_get_val (p, UT_GeneralString, tlen, &k->realm);
     }
     len = der_get_context (p, &tag, &type, &tlen);
     if (len < 0)
	  return len;
     else
	  p += len;
     der_get_principalname
     return p - ptr;
}

int
der_get_as_rep (unsigned char *ptr, As_Rep *a)
{
     unsigned char *p = ptr;
     int len;
     unsigned tlen;

     len = der_match_type (p, APPL, CONS, KRB_AS_REP, &tlen);
     if(len < 0)
	  return len;
     else
	  p += len;
     len = der_get_kdc_rep (p, tlen, KRB_AS_REP, a);
     if (len < 0)
	  return len;
     else
	  p += len;
     
     return p - ptr;
}

#endif

