#include <malloc.h>
#include <string.h>
#include <der.h>

/*
 * Functions for parsing DER
 */

unsigned
der_get_length (unsigned char *ptr, unsigned *res)
{
     unsigned char *p = ptr;
     unsigned char c;

     c = *p++;
     if (c < 0x80) {
	  *res = c;
	  return 1;
     } else {
	  c &= 0x7F;
	  *res = 0;
	  while (c--)
	       *res = *res * 0x100 + *p++;
	  return p - ptr;
     }
}

unsigned
der_get_tag (unsigned char *ptr, Der_class *class, Der_type *type,
	     unsigned *tag)
{
     unsigned char *p = ptr;
     unsigned char o1;

     o1 = *p++;
     *class = o1 >> 6;
     *type  = (o1 >> 5) & 1;
     *tag = o1 & 0x1F;
     if (*tag == 0x1F) {
	  do {
	       o1 = *p++;
	       *tag = *tag * 0x80 + (o1 & 0x7F);
	  } while( o1 & 0x80);
     }
     return p - ptr;
}

unsigned
der_get_integer (unsigned char *ptr, int len, void *v)
{
     unsigned char *p = ptr;
     unsigned *res = v;

     *res = 0;
     while(len--)
	  *res = *res * 0x100 + *p++;
     return p - ptr;
}

unsigned
der_get_octetstring (unsigned char *ptr, int len, void *v)
{
     unsigned char *p = ptr;
     krb5_data *res = v;

     res->data = malloc(len + 1);
     res->len = len;
     memcpy (*res, p, len);
     (*res)[len] = '\0';
     p += len;

     return p - ptr;
}

static unsigned (*get_univ_funcs[])(unsigned char *, int len, void *val) = {
     NULL,			/*  0 */
     NULL,			/*  1 */
     der_get_integer,		/*  2 */
     NULL,			/*  3 */
     der_get_octetstring,	/*  4 */
     NULL,			/*  5 */
     NULL,			/*  6 */
     NULL,			/*  7 */
     NULL,			/*  8 */
     NULL,			/*  9 */
     NULL,			/* 10 */
     NULL,			/* 11 */
     NULL,			/* 12 */
     NULL,			/* 13 */
     NULL,			/* 14 */
     NULL,			/* 15 */
     NULL,			/* 16 */
     NULL,			/* 17 */
     NULL,			/* 18 */
     NULL,			/* 19 */
     NULL,			/* 20 */
     NULL,			/* 21 */
     NULL,			/* 22 */
     NULL,			/* 23 */
     der_get_octetstring,	/* 24 */
     NULL,			/* 25 */
     NULL,			/* 26 */
     der_get_octetstring,	/* 27 */
};

unsigned
der_get_val (unsigned char *ptr, int type, int len, void *val)
{
     return (*(get_univ_funcs[type]))(ptr, len, val);
}

unsigned
der_get_type (unsigned char *ptr, Der_class *class, Der_type *type,
	      unsigned *tag, unsigned *len)
{
     unsigned char *p = ptr;

     return p - ptr;
}

int
der_match_type (unsigned char **ptr, Der_class class, Der_type type,
		unsigned tag, unsigned *len)
{
     unsigned char *p = ptr;
     Der_class c1;
     Der_type t1;
     unsigned tag1;

     p += der_get_tag (p, &c1, &t1, &tag1);
     if (c1 != class || t1 != type || tag != tag1)
	  return -1;
     p += der_get_length (p, len);
     
     return p - ptr;
}

int
der_get_context (unsigned char *ptr, unsigned *tag, unsigned *type,
		 unsigned *len)
{
     unsigned char *p = ptr;
     Der_class class;
     Der_type foo;

     p += der_get_tag (p, &class, &foo, tag);
     if (class != CONTEXT || foo != CONS )
	  return -1;
     p += der_get_length (p, len);
     p += der_get_tag (p, &class, &foo, type);
     if (class != UNIV || foo != PRIM)
	  return -1;
     p += der_get_length (p, len);

     return p - ptr;
}

int
der_match_context (unsigned char *ptr, unsigned tag, int type, void *arg)
{
     unsigned char *p = ptr;
     int len;
     int tlen;

     len = der_match_type (p, CONTEXT, CONS, tag, &tlen);
     if (len < 0)
	  return len;
     else
	  p += len;
     len = der_match_type (p, UNIV, PRIM, type, &tlen);
     if (len < 0)
	  return len;
     else
	  p += len;

     p += der_get_val (p, type, tlen, arg);

     return p - ptr;
}
