/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "der.h"
#include "gen.h"

FILE *headerfile, *codefile;

#define STEM "asn1"

void
init_generate (char *filename)
{
    headerfile = fopen (STEM ".h", "w");
    fprintf (headerfile,
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n",
	     filename);
    codefile = fopen (STEM ".c", "w");
    fprintf (codefile, 
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n"
	     "#include <stdio.h>\n"
	     "#include <stdlib.h>\n"
	     "#include <time.h>\n"
	     "#include <der.h>\n"
	     "#include <" STEM ".h>\n\n",
	     filename);
}

void
close_generate ()
{
  fclose (headerfile);
  fclose (codefile);
}

void
generate_constant (Symbol *s)
{
  fprintf (headerfile, "static const int %s = %d;\n\n",
	   s->gen_name, s->constant);
}

static void
define_type (char *name, Type *t)
{
  switch (t->type) {
  case TType:
    fprintf (headerfile, "%s %s;\n", t->symbol->gen_name, name);
    break;
  case TInteger:
    fprintf (headerfile, "int %s;\n", name);
    break;
  case TOctetString:
    fprintf (headerfile, "krb5_data %s;\n", name);
    break;
  case TBitString: {
    Member *m;
    Type i;
    int tag = -1;

    i.type = TInteger;
    fprintf (headerfile, "struct {\n");
    for (m = t->members; m && m->val != tag; m = m->next) {
      char *n = malloc(strlen(m->gen_name) + 3);
      strcpy (n, m->gen_name);
      strcat (n, ":1");
      define_type (n, &i);
      free (n);
      if (tag == -1)
	tag = m->val;
    }
    fprintf (headerfile, "} %s;\n\n", name);
    break;
  }
  case TSequence: {
    Member *m;
    int tag = -1;

    fprintf (headerfile, "struct {\n");
    for (m = t->members; m && m->val != tag; m = m->next) {
      if (m->optional) {
	char *n = malloc(strlen(m->gen_name) + 2);

	*n = '*';
	strcpy (n+1, m->gen_name);
	define_type (n, m->type);
	free (n);
      } else
	define_type (m->gen_name, m->type);
      if (tag == -1)
	tag = m->val;
    }
    fprintf (headerfile, "} %s;\n\n", name);
    break;
  }
  case TSequenceOf: {
    Type i;

    i.type = TInteger;
    i.application = 0;

    fprintf (headerfile, "struct {\n");
    define_type ("len", &i);
    define_type ("*val", t->subtype);
    fprintf (headerfile, "} %s;\n\n", name);
    break;
  }
  case TGeneralizedTime:
    fprintf (headerfile, "time_t %s;\n", name);
    break;
  case TGeneralString:
    fprintf (headerfile, "char *%s;\n", name);
    break;
  case TApplication:
    define_type (name, t->subtype);
    break;
  default:
    abort ();
  }
}

static void
generate_type_header (Symbol *s)
{
  fprintf (headerfile, "typedef ");
  define_type (s->gen_name, s->type);
  fprintf (headerfile, "\n");
}

static void
encode_primitive (char *typename, char *name)
{
    fprintf (codefile,
	     "l = encode_%s(p, len, %s);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n",
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
	     "l = encode_%s(p, len, %s);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n",
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
	       m->val % 8);

      if (tag == -1)
	tag = m->val;
    }

    fprintf (codefile, 
	     "*p-- = c;\n"
	     "*p-- = %d;\n"
	     "len -= 2;\n"
	     "ret += 2;\n"
	     "}\n\n"
	     "l = der_put_length (p, len, ret);\n"
	     "if(l < 0)\n"
	     "  return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n"
	     "l = der_put_tag (p, len, UNIV, PRIM, UT_BitString);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n",
	     rest);
    break;
  }
  case TSequence: {
    Member *m;
    int tag = -1;

    if (t->members == NULL)
      break;

    for (m = t->members->prev; m && tag != m->val; m = m->prev) {
      char *s = malloc(2 + strlen(name) + 1 + strlen(m->gen_name) + 3);

      sprintf (s, "%s(%s)->%s", m->optional ? "" : "&", name, m->gen_name);
      if (m->optional)
	fprintf (codefile,
		 "if(%s)\n",
		 s);
      fprintf (codefile, "{\n"
	       "int oldret = ret;\n"
	       "ret = 0;\n");
      encode_type (s, m->type);
      fprintf (codefile,
	       "l = der_put_length (p, len, ret);\n"
	       "if (l < 0)\n"
	       "return l;\n"
	       "p -= l;\n"
	       "len -= l;\n"
	       "ret += l;\n\n"
	       "l = der_put_tag (p, len, CONTEXT, CONS, %d);\n"
	       "if(l < 0)\n"
	       "return l;\n"
	       "p -= l;\n"
	       "len -= l;\n"
	       "ret += l;\n\n",
	       m->val);
      fprintf (codefile,
	       "ret += oldret;\n"
	       "}\n");
      if (tag == -1)
	tag = m->val;
      free (s);
    }
    fprintf (codefile,
	     "l = der_put_length (p, len, ret);\n"
	     "if(l < 0)\n"
	     "  return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n"
	     "l = der_put_tag (p, len, UNIV, CONS, UT_Sequence);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n");
    break;
  }
  case TSequenceOf: {
    char *n = malloc(strlen(name) + 12);

    fprintf (codefile,
	     "for(i = (%s)->len - 1; i >= 0; --i) {\n"
	     "int oldret = ret;\n"
	     "ret = 0;\n",
	     name);
    sprintf (n, "&(%s)->val[i]", name);
    encode_type (n, t->subtype);
    fprintf (codefile,
	     "ret += oldret;\n"
	     "}\n"
	     "l = der_put_length (p, len, ret);\n"
	     "if(l < 0)\n"
	     "  return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n"
	     "l = der_put_tag (p, len, UNIV, CONS, UT_Sequence);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n");
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
	     "l = der_put_length (p, len, ret);\n"
	     "if(l < 0)\n"
	     "  return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n"
	     "l = der_put_tag (p, len, APPL, CONS, %d);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p -= l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n",
	     t->application);
    break;
  default:
    abort ();
  }
}

static void
generate_type_encode (Symbol *s)
{
  fprintf (headerfile,
	   "int encode_%s(unsigned char *, int, void *);\n",
	   s->gen_name);

  fprintf (codefile, "int\n"
	   "encode_%s(unsigned char *p, int len, void *d)\n"
	   "{\n"
	   "%s *data = (%s *)d;\n"
	   "int ret = 0;\n"
	   "int l, i;\n\n",
	   s->gen_name, s->gen_name, s->gen_name);

  encode_type ("data", s->type);
  fprintf (codefile, "return ret;\n"
	   "}\n\n");
}

static void
decode_primitive (char *typename, char *name)
{
    fprintf (codefile,
	     "l = decode_%s(p, len, %s);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n",
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
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n\n",
	     t->symbol->gen_name, name);
    break;
  case TInteger:
    decode_primitive ("integer", name);
    break;
  case TOctetString:
    decode_primitive ("octet_string", name);
    break;
  case TBitString:
    /* XXX */
    fprintf (codefile,
	     "l = der_match_tag (p, len, UNIV, PRIM, UT_BitString);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "l = der_get_length (p, len, &reallen);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "if(len < reallen)\n"
	     "return -1;\n"
	     "p += reallen;\n"
	     "len -= reallen;\n"
	     "ret += reallen;\n");
    break;
  case TSequence: {
    Member *m;
    int tag = -1;

    if (t->members == NULL)
      break;

    fprintf (codefile,
	     "l = der_match_tag (p, len, UNIV, CONS, UT_Sequence);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "l = der_get_length (p, len, &reallen);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "{\n"
	     "int dce_fix = 0;\n"
	     "if(reallen == 0)\n"
	     "dce_fix = 1;\n"
	     "if(!dce_fix && len < reallen)\n"
	     "return -1;\n"
	     "if(!dce_fix)\n"
	     "len = reallen;\n");

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
	       "if(l < 0)\n"
	       "return l;\n"
	       "p += l;\n"
	       "len -= l;\n"
	       "ret += l;\n"
	     "{\n"
	     "int dce_fix = 0;\n"
	     "if(newlen == 0)\n"
	     "dce_fix = 1;\n"
	     "if(!dce_fix && len < newlen)\n"
	     "return -1;\n"
	       "oldlen = len;\n"
	     "if(!dce_fix)\n"
	     "len = newlen;\n");
      if (m->optional)
	fprintf (codefile,
		 "%s = malloc(sizeof(*%s));\n",
		 s, s);
      decode_type (s, m->type);
      fprintf (codefile,
	    "if(dce_fix){\n"
	    "l = der_match_tag (p, len, 0, 0, 0);\n"
	    "if(l < 0) return l;\n"
	    "p += l;\n"
	    "len -= l;\n"
	    "ret += l;\n"
	    "l = der_get_length(p, len, &reallen);\n"
	    "if(l < 0)\n"
	    "return l;\n"
	    "p += l;\n"
	    "len -= l;\n"
	    "ret += l;\n"
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
	    "l = der_match_tag (p, len, 0, 0, 0);\n"
	    "if(l < 0) return l;\n"
	    "p += l;\n"
	    "len -= l;\n"
	    "ret += l;\n"
	    "l = der_get_length(p, len, &reallen);\n"
	    "if(l < 0)\n"
	    "return l;\n"
	    "p += l;\n"
	    "len -= l;\n"
	    "ret += l;\n"
	    "}\n"
	    "}\n");

    break;
  }
  case TSequenceOf: {
    char *n = malloc(2*strlen(name) + 20);

    fprintf (codefile,
	     "l = der_match_tag (p, len, UNIV, CONS, UT_Sequence);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "l = der_get_length (p, len, &reallen);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
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
	     "l = der_match_tag (p, len, APPL, CONS, %d);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "l = der_get_length(p, len, &reallen);\n"
	     "if(l < 0)\n"
	     "return l;\n"
	     "p += l;\n"
	     "len -= l;\n"
	     "ret += l;\n"
	     "{\n"
	     "int dce_fix = 0;\n"
	     "if(reallen == 0)\n"
	     "dce_fix = 1;\n"
	     "if(!dce_fix && len < reallen)\n"
	     "return -1;\n"
	     "if(!dce_fix)\n"
	     "len = reallen;\n",
	     t->application);
    decode_type (name, t->subtype);
    fprintf(codefile,
	    "if(dce_fix){\n"
	    "l = der_match_tag (p, len, 0, 0, 0);\n"
	    "if(l < 0) return l;\n"
	    "p += l;\n"
	    "len -= l;\n"
	    "ret += l;\n"
	    "l = der_get_length(p, len, &reallen);\n"
	    "if(l < 0)\n"
	    "return l;\n"
	    "p += l;\n"
	    "len -= l;\n"
	    "ret += l;\n"
	    "}\n"
	    "}\n");

    break;
  default :
    abort ();
  }
}

static void
generate_type_decode (Symbol *s)
{
  fprintf (headerfile,
	   "int decode_%s(unsigned char *, int, void *);\n",
	   s->gen_name);

  fprintf (codefile, "int\n"
	   "decode_%s(unsigned char *p, int len, void *d)\n"
	   "{\n"
	   "%s *data = (%s *)d;\n"
	   "int ret = 0, reallen;\n"
	   "int l, i;\n\n",
	   s->gen_name, s->gen_name, s->gen_name);

  decode_type ("data", s->type);
  fprintf (codefile, "return ret;\n"
	   "}\n\n");
}

void
generate_type (Symbol *s)
{
  generate_type_header (s);
  generate_type_encode (s);
  generate_type_decode (s);
}
