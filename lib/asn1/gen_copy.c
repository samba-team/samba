#include "asn1_locl.h"

RCSID("$Id$");

static void
copy_primitive (char *typename, char *from, char *to)
{
    fprintf (codefile, "copy_%s(%s, %s);\n", typename, from, to);
}

static void
copy_type (char *from, char *to, Type *t)
{
  switch (t->type) {
  case TType:
#if 0
      copy_type (from, to, t->symbol->type);
#endif
      fprintf (codefile, "copy_%s(%s, %s);\n", t->symbol->gen_name, from, to);
      break;
  case TInteger:
      fprintf(codefile, "*(%s) = *(%s);\n", to, from);
      break;
  case TOctetString:
      copy_primitive ("octet_string", from, to);
      break;
  case TBitString: {
      fprintf(codefile, "*(%s) = *(%s);\n", to, from);
      break;
  }
  case TSequence: {
      Member *m;
      int tag = -1;

      if (t->members == NULL)
	  break;
      
      for (m = t->members; m && tag != m->val; m = m->next) {
	  char *f = malloc(2 + strlen(from) + 1 + strlen(m->gen_name) + 3);
	  char *t = malloc(2 + strlen(to) + 1 + strlen(m->gen_name) + 3);

	  sprintf (f, "%s(%s)->%s", m->optional ? "" : "&", from, m->gen_name);
	  sprintf (t, "%s(%s)->%s", m->optional ? "" : "&", to, m->gen_name);
	  if(m->optional){
	      fprintf(codefile, "if(%s) {\n", f);
	      fprintf(codefile, "%s = malloc(sizeof(*%s));\n", t, t);
	  }
	  copy_type (f, t, m->type);
	  if(m->optional){
	      fprintf(codefile, "}else\n");
	      fprintf(codefile, "%s = NULL;\n", t);
	  }
	  if (tag == -1)
	      tag = m->val;
	  free (f);
	  free (t);
      }
      break;
  }
  case TSequenceOf: {
      char *f = malloc(strlen(from) + strlen(to) + 17);
      char *T = malloc(strlen(to) + strlen(to) + 17);

      fprintf (codefile, "(%s)->val = "
	       "malloc((%s)->len * sizeof(*(%s)->val));\n", 
	       to, from, to);
      fprintf(codefile, "for((%s)->len = 0; (%s)->len < (%s)->len; (%s)->len++){\n", to, to, from, to);
      sprintf(f, "&(%s)->val[(%s)->len]", from, to);
      sprintf(T, "&(%s)->val[(%s)->len]", to, to);
      copy_type(f, T, t->subtype);
      fprintf(codefile, "}\n");
      free(f);
      free(T);
      break;
  }
  case TGeneralizedTime:
      fprintf(codefile, "*(%s) = *(%s);\n", to, from);
      break;
  case TGeneralString:
      copy_primitive ("general_string", from, to);
      break;
  case TApplication:
      copy_type (from, to, t->subtype);
      break;
  default :
      abort ();
  }
}

void
generate_type_copy (Symbol *s)
{
  fprintf (headerfile,
	   "void copy_%s(%s *, %s *);\n",
	   s->gen_name, s->gen_name, s->gen_name);

  fprintf (codefile, "void\n"
	   "copy_%s(%s *from, %s *to)\n"
	   "{\n",
	   s->gen_name, s->gen_name, s->gen_name);

  copy_type ("from", "to", s->type);
  fprintf (codefile, "}\n\n");
}

