#include "asn1_locl.h"

RCSID("$Id$");

FILE *headerfile, *codefile, *logfile;

#define STEM "asn1"

static char *orig_filename;

void
init_generate (char *filename)
{
    orig_filename = filename;
    headerfile = fopen (STEM ".h", "w");
    if (headerfile == NULL) {
	fprintf (stderr, "Could not open " STEM ".h" "\n");
	exit (1);
    }
    fprintf (headerfile,
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n",
	     filename);
    logfile = fopen(STEM "_files", "w");
    if (logfile == NULL) {
	fprintf (stderr, "Could not open " STEM "_files" "\n");
	exit (1);
    }
}

void
close_generate ()
{
  fclose (headerfile);
  fprintf (logfile, "\n");
  fclose (logfile);
}

void
generate_constant (Symbol *s)
{
  fprintf (headerfile, "enum { %s = %d };\n\n",
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
    fprintf (headerfile, "unsigned %s;\n", name);
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


void
generate_type (Symbol *s)
{
    char *filename = malloc(strlen(STEM) + strlen(s->gen_name) + 4);
    sprintf(filename, "%s_%s.x", STEM, s->gen_name);
    codefile = fopen (filename, "w");
    if (codefile == NULL) {
	fprintf (stderr, "Could not create %s\n", filename);
	exit (1);
    }
    fprintf(logfile, "%s ", filename);
    free(filename);
    fprintf (codefile, 
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n"
	     "#include <stdio.h>\n"
	     "#include <stdlib.h>\n"
	     "#include <time.h>\n"
	     "#include <der.h>\n"
	     "#include <" STEM ".h>\n\n",
	     orig_filename);
    generate_type_header (s);
    generate_type_encode (s);
    generate_type_decode (s);
    generate_type_free (s);
    generate_type_length (s);
    generate_type_copy (s);
    fprintf(headerfile, "\n\n");
    fclose(codefile);
}
