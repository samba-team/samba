#include <krb5_locl.h>
#include <der.h>

/*
 * Functions for generating DER
 */

/*
 * All these functions generate the data backwards starting at `ptr'
 * and return the length.
 */

unsigned
der_put_integer (unsigned char *ptr, void *v)
{
     unsigned char *p = ptr;
     unsigned i = *(int *)v;

     if (i) {
	  while(i) {
	       *p-- = i % 0x100;
	       i /= 0x100;
	  }
	  return ptr - p;
     } else {
	  *p = 0;
	  return 1;
     }
}

unsigned
der_put_length (unsigned char *ptr, unsigned len)
{
     unsigned char *p = ptr;

     if (len < 0x80) {
	  *p = len;
	  return 1;
     } else {
	  unsigned q;

	  q = der_put_integer (p, &len);
	  p -= q;
	  *p = 0x80 | q;
	  return q + 1;
     }
}

unsigned
der_put_octetstring (unsigned char *ptr, void *v)
{
     unsigned char *p = ptr;
     krb5_data *str = (krb5_data *)v;
     int len = str->length;

     p -= len;
     memcpy (p + 1, str->data, len);

     return ptr - p;
}

unsigned
der_put_tag (unsigned char *ptr, Der_class class, Der_type type, unsigned tag)
{
     unsigned char o1;
     unsigned char *p = ptr;

     o1 = (class << 6) | (type << 5);
     if (tag < 0x1F)
	  o1 |= tag;
     else {
	  o1 |= 0x1F;
	  *p-- = tag % 0x80;
	  tag /= 0x80;
	  while(tag) {
	       *p-- = 0x80 | (tag % 0x80);
	       tag /= 0x80;
	  }
     }
     *p-- = o1;
     return ptr - p;
}

unsigned
der_put_type (unsigned char *ptr, Der_class class, Der_type type,
	      unsigned tag, unsigned len)
{
     unsigned char *p = ptr;

     p -= der_put_length (p, len);
     p -= der_put_tag (p, class, type, tag);
     return ptr - p;
}

static unsigned (*put_univ_funcs[])(unsigned char *, void *val) = {
     NULL,			/*  0 */
     NULL,			/*  1 */
     der_put_integer,		/*  2 */
     NULL,			/*  3 */
     der_put_octetstring,	/*  4 */
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
     der_put_octetstring,	/* 24 */
     NULL,			/* 25 */
     NULL,			/* 26 */
     der_put_octetstring,	/* 27 */
};

unsigned
der_put_val (unsigned char *ptr, int type, void *val)
{
     return (*(put_univ_funcs[type]))(ptr, val);
}

unsigned
der_put_type_and_value (unsigned char *ptr, int type, void *val)
{
     unsigned char *p = ptr;

     p -= der_put_val (p, type, val);
     p -= der_put_type (p, UNIV, PRIM, type, ptr - p);
     return ptr - p;
}

unsigned
der_put_context (unsigned char *ptr, int tag, int type, void *val)
{
     unsigned char *p = ptr;

     p -= der_put_type_and_value (p, type, val);
     p -= der_put_type (p, CONTEXT, CONS, tag, ptr - p);
     return ptr - p;
}
