#include "asn1_locl.h"

RCSID("$Id$");

static void
decode_primitive (char *typename, char *name)
{
    fprintf (codefile,
	     "l = decode_%s(p, len, %s);\n"
	     "FORW;\n",
	     typename,
	     name);
}

static void
decode_type (char *name, Type *t)
{
  switch (t->type) {
  case TType:
#if 0
    decode_type (name, t->symbol->type);
#endif
    fprintf (codefile,
	     "l = decode_%s(p, len, %s);\n"
	     "FORW;\n",
	     t->symbol->gen_name, name);
    break;
  case TInteger:
    decode_primitive ("integer", name);
    break;
  case TOctetString:
    decode_primitive ("octet_string", name);
    break;
  case TBitString: {
    Member *m;
    int tag = -1;
    int pos;

    fprintf (codefile,
	     "l = der_match_tag_and_length (p, len, UNIV, PRIM, UT_BitString,"
	     "&reallen);\n"
	     "FORW;\n"
	     "if(len < reallen)\n"
	     "return -1;\n"
	     "p++;\n"
	     "len--;\n"
	     "reallen--;\n"
	     "ret++;\n");
    pos = 0;
    for (m = t->members; m && tag != m->val; m = m->next) {
      while (m->val / 8 > pos / 8) {
	fprintf (codefile,
		 "p++; len--; reallen--; ret++;\n");
	pos += 8;
      }
      fprintf (codefile,
	       "%s->%s = (*p >> %d) & 1;\n",
	       name, m->gen_name, 7 - m->val % 8);
      if (tag == -1)
	tag = m->val;
    }
    fprintf (codefile,
	     "p += reallen; len -= reallen; ret += reallen;\n");
    break;
  }
  case TSequence: {
    Member *m;
    int tag = -1;

    if (t->members == NULL)
      break;

    fprintf (codefile,
	     "l = der_match_tag_and_length (p, len, UNIV, CONS, UT_Sequence,"
	     "&reallen);\n"
	     "FORW;\n"
	     "{\n"
	     "int dce_fix;\n"
	     "if((dce_fix = fix_dce(reallen, &len)) < 0)\n"
	     "return -1;\n");

    for (m = t->members; m && tag != m->val; m = m->next) {
      char *s = malloc(2 + strlen(name) + 1 + strlen(m->gen_name) + 3);

      sprintf (s, "%s(%s)->%s", m->optional ? "" : "&", name, m->gen_name);
      fprintf (codefile, "{\n"
	       "int newlen, oldlen;\n\n"
	       "l = der_match_tag (p, len, CONTEXT, CONS, %d);\n",
	       m->val);
      fprintf (codefile,
	       "if(l >= 0) {\n"
	       "p += l;\n"
	       "len -= l;\n"
	       "ret += l;\n"
	       "l = der_get_length (p, len, &newlen);\n"
	       "FORW;\n"
	       "{\n"
	       
	       "int dce_fix;\n"
	       "oldlen = len;\n"
	       "if((dce_fix = fix_dce(newlen, &len)) < 0)"
	       "return -1;\n");
      if (m->optional)
	fprintf (codefile,
		 "%s = malloc(sizeof(*%s));\n",
		 s, s);
      decode_type (s, m->type);
      fprintf (codefile,
	       "if(dce_fix){\n"
	       "l = der_match_tag_and_length (p, len, 0, 0, 0, &reallen);\n"
	       "FORW;\n"
	       "}else \n"
	       "len = oldlen - newlen;\n"
	       "}\n"
	       "}\n"
	       "else {\n");
      if(m->optional)
	fprintf (codefile,
		 "%s = NULL;\n"
		 "}\n", s);
      else
	fprintf (codefile,
		 "return l;\n"
		 "}\n");
      fprintf (codefile,
		 "}\n");
      if (tag == -1)
	tag = m->val;
      free (s);
    }
    fprintf(codefile,
	    "if(dce_fix){\n"
	    "l = der_match_tag_and_length (p, len, 0, 0, 0, &reallen);\n"
	    "FORW;\n"
	    "}\n"
	    "}\n");

    break;
  }
  case TSequenceOf: {
    char *n = malloc(2*strlen(name) + 20);

    fprintf (codefile,
	     "l = der_match_tag_and_length (p, len, UNIV, CONS, UT_Sequence,"
	     "&reallen);\n"
	     "FORW;\n"
	     "if(len < reallen)\n"
	     "return -1;\n"
	     "len = reallen;\n");

    fprintf (codefile,
	     "(%s)->len = 0;\n"
	     "(%s)->val = NULL;\n"
	     "while(len > 0) {\n"
	     "(%s)->len++;\n"
	     "(%s)->val = realloc((%s)->val, sizeof(*((%s)->val)) * (%s)->len);\n",
	     name, name, name, name, name, name, name);
    sprintf (n, "&(%s)->val[(%s)->len-1]", name, name);
    decode_type (n, t->subtype);
    fprintf (codefile, 
	     "}\n");
    free (n);
    break;
  }
  case TGeneralizedTime:
    decode_primitive ("generalized_time", name);
    break;
  case TGeneralString:
    decode_primitive ("general_string", name);
    break;
  case TApplication:
    fprintf (codefile,
	     "l = der_match_tag_and_length (p, len, APPL, CONS, %d, &reallen);\n"
	     "FORW;\n"
	     "{\n"
	     "int dce_fix;\n"
	     "if((dce_fix = fix_dce(reallen, &len)) < 0)\n"
	     "return -1;\n", 
	     t->application);
    decode_type (name, t->subtype);
    fprintf(codefile,
	    "if(dce_fix){\n"
	    "l = der_match_tag_and_length (p, len, 0, 0, 0, &reallen);\n"
	    "FORW;\n"
	    "}\n"
	    "}\n");

    break;
  default :
    abort ();
  }
}

void
generate_type_decode (Symbol *s)
{
  fprintf (headerfile,
	   "int decode_%s(unsigned char *, int, %s *);\n",
	   s->gen_name, s->gen_name);

  fprintf (codefile, "#define FORW "
	   "if(l < 0)"
	   "return l;"
	   "p += l;"
	   "len -= l;"
	   "ret += l\n\n");


  fprintf (codefile, "int\n"
	   "decode_%s(unsigned char *p, int len, %s *data)\n"
	   "{\n",
	   s->gen_name, s->gen_name);

  switch (s->type->type) {
  case TInteger:
    fprintf (codefile, "return decode_integer (p, len, data);\n");
    break;
  case TOctetString:
    fprintf (codefile, "return decode_octet_string (p, len, data);\n");
    break;
  case TGeneralizedTime:
    fprintf (codefile, "return decode_generalized_time (p, len, data);\n");
    break;
  case TGeneralString:
    fprintf (codefile, "return decode_general_string (p, len, data);\n");
    break;
  case TBitString:
  case TSequence:
  case TSequenceOf:
  case TApplication:
  case TType:
    fprintf (codefile,
	     "int ret = 0, reallen;\n"
	     "int l, i;\n\n");
    
    decode_type ("data", s->type);
    fprintf (codefile, "return ret;\n");
    break;
  default:
    abort ();
  }
  fprintf (codefile, "}\n\n");
}

#if 0
static void
generate_type_decode (Symbol *s)
{
  fprintf (headerfile,
	   "int decode_%s(unsigned char *, int, %s *);\n",
	   s->gen_name, s->gen_name);

  fprintf (codefile, "int\n"
	   "decode_%s(unsigned char *p, int len, %s *data)\n"
	   "{\n"
	   "int ret = 0, reallen;\n"
	   "int l, i;\n\n",
	   s->gen_name, s->gen_name);

  decode_type ("data", s->type);
  fprintf (codefile, "return ret;\n"
	   "}\n\n");
}
#endif

