#include "asn1_locl.h"

RCSID("$Id$");

static void
free_primitive (char *typename, char *name)
{
    fprintf (codefile, "free_%s(%s);\n", typename, name);
}

static void
free_type (char *name, Type *t)
{
  switch (t->type) {
  case TType:
#if 0
      free_type (name, t->symbol->type);
#endif
      fprintf (codefile, "free_%s(%s);\n", t->symbol->gen_name, name);
      break;
  case TInteger:
      break;
  case TOctetString:
      free_primitive ("octet_string", name);
      break;
  case TBitString: {
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
	  if(m->optional)
	      fprintf(codefile, "if(%s) {\n", s);
	  free_type (s, m->type);
	  if(m->optional)
	      fprintf(codefile, 
		      "free(%s);\n"
		      "}\n",s);
	  if (tag == -1)
	      tag = m->val;
	  free (s);
      }
      break;
  }
  case TSequenceOf: {
      char *n = malloc(2*strlen(name) + 20);

      fprintf (codefile, "while((%s)->len){\n", name);
      sprintf (n, "&(%s)->val[(%s)->len-1]", name, name);
      free_type(n, t->subtype);
      fprintf(codefile, 
	      "(%s)->len--;\n"
	      "}\n",
	      name);
      fprintf(codefile,
	      "free((%s)->val);\n", name);
      free(n);
      break;
  }
  case TGeneralizedTime:
      break;
  case TGeneralString:
      free_primitive ("general_string", name);
      break;
  case TApplication:
      free_type (name, t->subtype);
      break;
  default :
      abort ();
  }
}

void
generate_type_free (Symbol *s)
{
  fprintf (headerfile,
	   "void free_%s(%s *);\n",
	   s->gen_name, s->gen_name);

  fprintf (codefile, "void\n"
	   "free_%s(%s *data)\n"
	   "{\n",
	   s->gen_name, s->gen_name);

  free_type ("data", s->type);
  fprintf (codefile, "}\n\n");
}

