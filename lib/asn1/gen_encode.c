#include "asn1_locl.h"

RCSID("$Id$");

static void
encode_primitive (char *typename, char *name)
{
    fprintf (codefile,
	     "e = encode_%s(p, len, %s, &l);\n"
	     "BACK;\n",
	     typename,
	     name);
}

static void
encode_type (char *name, Type *t)
{
  switch (t->type) {
  case TType:
#if 0
    encode_type (name, t->symbol->type);
#endif
    fprintf (codefile,
	     "e = encode_%s(p, len, %s, &l);\n"
	     "BACK;\n",
	     t->symbol->gen_name, name);
    break;
  case TInteger:
    encode_primitive ("integer", name);
    break;
  case TOctetString:
    encode_primitive ("octet_string", name);
    break;
  case TBitString: {
    Member *m;
    int pos;
    int rest;
    int tag = -1;

    if (t->members == NULL)
      break;

    fprintf (codefile, "{\n"
	     "unsigned char c = 0;\n");
    pos = t->members->prev->val;
    /* fix for buggy MIT (and OSF?) code */
    if (pos > 31)
	abort ();
    /*
     * It seems that if we do not always set pos to 31 here, the MIT
     * code will do the wrong thing.
     *
     * I hate ASN.1 (and DER), but I hate it even more when everybody
     * has to screw it up differently.
     */
    pos = 31;
    rest = 7 - (pos % 8);

    for (m = t->members->prev; m && tag != m->val; m = m->prev) {
      while (m->val / 8 < pos / 8) {
	fprintf (codefile,
		 "*p-- = c; len--; ret++;\n"
		 "c = 0;\n");
	pos -= 8;
      }
      fprintf (codefile,
	       "if(%s->%s) c |= 1<<%d;\n", name, m->gen_name,
	       7 - m->val % 8);

      if (tag == -1)
	tag = m->val;
    }

    fprintf (codefile, 
	     "*p-- = c;\n"
	     "*p-- = %d;\n"
	     "len -= 2;\n"
	     "ret += 2;\n"
	     "}\n\n"
	     "e = der_put_length_and_tag (p, len, ret, UNIV, PRIM,"
	     "UT_BitString, &l);\n"
	     "BACK;\n",
	     rest);
    break;
  }
  case TSequence: {
    Member *m;
    int tag = -1;

    if (t->members == NULL)
      break;

    for (m = t->members->prev; m && tag != m->val; m = m->prev) {
      char *s;

      asprintf (&s, "%s(%s)->%s", m->optional ? "" : "&", name, m->gen_name);
      if (m->optional)
	fprintf (codefile,
		 "if(%s)\n",
		 s);
#if 1
      fprintf (codefile, "{\n"
	       "int oldret = ret;\n"
	       "ret = 0;\n");
#endif
      encode_type (s, m->type);
      fprintf (codefile,
	       "e = der_put_length_and_tag (p, len, ret, CONTEXT, CONS, "
	       "%d, &l);\n"
	       "BACK;\n",
	       m->val);
#if 1
      fprintf (codefile,
	       "ret += oldret;\n"
	       "}\n");
#endif
      if (tag == -1)
	tag = m->val;
      free (s);
    }
    fprintf (codefile,
	     "e = der_put_length_and_tag (p, len, ret, UNIV, CONS, UT_Sequence, &l);\n"
	     "BACK;\n");
    break;
  }
  case TSequenceOf: {
    char *n;

    fprintf (codefile,
	     "for(i = (%s)->len - 1; i >= 0; --i) {\n"
#if 1
	     "int oldret = ret;\n"
	     "ret = 0;\n",
#else
	     ,
#endif
	     name);
    asprintf (&n, "&(%s)->val[i]", name);
    encode_type (n, t->subtype);
    fprintf (codefile,
#if 1
	     "ret += oldret;\n"
#endif
	     "}\n"
	     "e = der_put_length_and_tag (p, len, ret, UNIV, CONS, UT_Sequence, &l);\n"
	     "BACK;\n");
    free (n);
    break;
  }
  case TGeneralizedTime:
    encode_primitive ("generalized_time", name);
    break;
  case TGeneralString:
    encode_primitive ("general_string", name);
    break;
  case TApplication:
    encode_type (name, t->subtype);
    fprintf (codefile,
	     "e = der_put_length_and_tag (p, len, ret, APPL, CONS, %d, &l);\n"
	     "BACK;\n",
	     t->application);
    break;
  default:
    abort ();
  }
}

void
generate_type_encode (Symbol *s)
{
  fprintf (headerfile,
	   "int encode_%s(unsigned char *, size_t, %s *, size_t *);\n",
	   s->gen_name, s->gen_name);

  fprintf (codefile, "#define BACK if (e) return e; p -= l; len -= l; ret += l\n\n");


  fprintf (codefile, "int\n"
	   "encode_%s(unsigned char *p, size_t len, %s *data, size_t *size)\n"
	   "{\n",
	   s->gen_name, s->gen_name);

  switch (s->type->type) {
  case TInteger:
    fprintf (codefile, "return encode_integer (p, len, data, size);\n");
    break;
  case TOctetString:
    fprintf (codefile, "return encode_octet_string (p, len, data, size);\n");
    break;
  case TGeneralizedTime:
    fprintf (codefile, "return encode_generalized_time (p, len, data, size);\n");
    break;
  case TGeneralString:
    fprintf (codefile, "return encode_general_string (p, len, data, size);\n");
    break;
  case TBitString:
  case TSequence:
  case TSequenceOf:
  case TApplication:
  case TType:
    fprintf (codefile,
	     "size_t ret = 0;\n"
	     "size_t l;\n"
	     "int i, e;\n\n");
    
    encode_type ("data", s->type);
    fprintf (codefile, "*size = ret;\n"
	     "return 0;\n");
    break;
  default:
    abort ();
  }
  fprintf (codefile, "}\n\n");
}
