#include "asn1_locl.h"

RCSID("$Id$");

static void
length_primitive (char *typename, char *name, char *variable)
{
    fprintf (codefile, "%s += length_%s(%s);\n", variable, typename, name);
}

static void
length_type (char *name, Type *t, char *variable)
{
  switch (t->type) {
  case TType:
#if 0
      length_type (name, t->symbol->type);
#endif
      fprintf (codefile, "%s += length_%s(%s);\n",
	       variable, t->symbol->gen_name, name);
      break;
  case TInteger:
      length_primitive ("integer", name, variable);
      break;
  case TOctetString:
      length_primitive ("octet_string", name, variable);
      break;
  case TBitString: {
      /*
       * XXX - Hope this is correct
       * look at TBitString case in `encode_type'
       */
      fprintf (codefile, "%s += 7;\n", variable);
      break;
  }
  case TSequence: {
      Member *m;
      int tag = -1;

      if (t->members == NULL)
	  break;
      
      for (m = t->members; m && tag != m->val; m = m->next) {
	  char *s = malloc(2 + strlen(name) + 1 + strlen(m->gen_name) + 3);

	  sprintf (s, "%s(%s)->%s", m->optional ? "" : "&", name, m->gen_name);
	  if (m->optional)
	      fprintf (codefile, "if(%s)", s);
	  fprintf (codefile, "{\n"
		   "int oldret = %s;\n"
		   "%s = 0;\n", variable, variable);
	  length_type (s, m->type, "ret");
	  fprintf (codefile, "%s += 1 + length_len(%s) + oldret;\n",
		   variable, variable);
	  fprintf (codefile, "}\n");
	  if (tag == -1)
	      tag = m->val;
	  free (s);
      }
      fprintf (codefile,
	       "%s += 1 + length_len(%s);\n", variable, variable);
      break;
  }
  case TSequenceOf: {
      char *n = malloc(2*strlen(name) + 20);

      fprintf (codefile,
	       "{\n"
	       "int oldret = %s;\n"
	       "%s = 0;\n", variable, variable);

      fprintf (codefile, "while((%s)->len){\n", name);
      sprintf (n, "&(%s)->val[(%s)->len-1]", name, name);
      length_type(n, t->subtype, variable);
      fprintf(codefile, 
	      "(%s)->len--;\n"
	      "}\n",
	      name);
      fprintf (codefile,
	       "%s += 1 + length_len(%s) + oldret;\n"
	       "}\n", variable, variable);
      free(n);
      break;
  }
  case TGeneralizedTime:
      length_primitive ("generalized_time", name, variable);
      break;
  case TGeneralString:
      length_primitive ("general_string", name, variable);
      break;
  case TApplication:
      length_type (name, t->subtype, variable);
      fprintf (codefile, "ret += 1 + length_len (ret);\n");
      break;
  default :
      abort ();
  }
}

void
generate_type_length (Symbol *s)
{
  fprintf (headerfile,
	   "size_t length_%s(%s *);\n",
	   s->gen_name, s->gen_name);

  fprintf (codefile,
	   "size_t\n"
	   "length_%s(%s *data)\n"
	   "{\n"
	   "size_t ret = 0;\n",
	   s->gen_name, s->gen_name);

  length_type ("data", s->type, "ret");
  fprintf (codefile, "return ret;\n}\n\n");
}

