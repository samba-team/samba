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
    fprintf (headerfile, 
	     "#ifndef __" STEM "_h__\n"
	     "#define __" STEM "_h__\n\n");
    fprintf (headerfile, 
	     "#include <stddef.h>\n"
	     "#include <time.h>\n\n");
    fprintf (headerfile,
	     "typedef struct {\n"
	     "  size_t length;\n"
	     "  void *data;\n"
	     "} octet_string;\n\n");
    fprintf (headerfile,
#if 0
	     "typedef struct {\n"
	     "  size_t length;\n"
	     "  char *data;\n"
	     "} general_string;\n\n"
#else
	     "typedef char *general_string;\n\n"
#endif
	     );
    logfile = fopen(STEM "_files", "w");
    if (logfile == NULL) {
	fprintf (stderr, "Could not open " STEM "_files" "\n");
	exit (1);
    }
}

void
close_generate ()
{
    fprintf (headerfile, "#endif /* __" STEM "_h__ */\n");

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
space(int level)
{
    while(level-- > 0)
	fprintf(headerfile, "  ");
}

static void
define_asn1 (int level, Type *t)
{
    switch (t->type) {
    case TType:
	space(level);
	fprintf (headerfile, "%s", t->symbol->name);
	break;
    case TInteger:
	space(level);
	fprintf (headerfile, "INTEGER");
	break;
    case TOctetString:
	space(level);
	fprintf (headerfile, "OCTET STRING");
	break;
    case TBitString: {
	Member *m;
	Type i;
	int tag = -1;

	i.type = TInteger;
	space(level);
	fprintf (headerfile, "BIT STRING {\n");
	for (m = t->members; m && m->val != tag; m = m->next) {
	    if (tag == -1)
		tag = m->val;
	    space(level + 1);
	    fprintf (headerfile, "%s(%d)%s\n", m->name, m->val, 
		     m->next->val == tag?"":",");

	}
	space(level);
	fprintf (headerfile, "}");
	break;
    }
    case TSequence: {
	Member *m;
	int tag = -1;

	space(level);
	fprintf (headerfile, "SEQUENCE {\n");
	for (m = t->members; m && m->val != tag; m = m->next) {
	    if (tag == -1)
		tag = m->val;
	    space(level + 1);
	    fprintf (headerfile, "%s[%d] ", m->name, m->val);
	    if(strlen(m->name) < 16)
		fprintf (headerfile, "%*s", 16 - strlen(m->name), "");
	    define_asn1(level + 1, m->type);
	    if(m->optional)
		fprintf(headerfile, " OPTIONAL");
	    if(m->next->val != tag)
		fprintf (headerfile, ",");
	    fprintf (headerfile, "\n");
	}
	space(level);
	fprintf (headerfile, "}");
	break;
    }
    case TSequenceOf: {
	space(level);
	fprintf (headerfile, "SEQUENCE OF ");
	define_asn1 (0, t->subtype);
	break;
    }
    case TGeneralizedTime:
	space(level);
	fprintf (headerfile, "GeneralizedTime");
	break;
    case TGeneralString:
	space(level);
	fprintf (headerfile, "GeneralString");
	break;
    case TApplication:
	fprintf (headerfile, "[APPLICATION %d] ", t->application);
	define_asn1 (level, t->subtype);
	break;
    default:
	abort ();
    }
}

static void
define_type (int level, char *name, Type *t)
{
    switch (t->type) {
    case TType:
	space(level);
	fprintf (headerfile, "%s %s;\n", t->symbol->gen_name, name);
	break;
    case TInteger:
	space(level);
	fprintf (headerfile, "unsigned %s;\n", name);
	break;
    case TOctetString:
	space(level);
	fprintf (headerfile, "octet_string %s;\n", name);
	break;
    case TBitString: {
	Member *m;
	Type i;
	int tag = -1;

	i.type = TInteger;
	space(level);
	fprintf (headerfile, "struct {\n");
	for (m = t->members; m && m->val != tag; m = m->next) {
	    char *n = malloc(strlen(m->gen_name) + 3);
	    strcpy (n, m->gen_name);
	    strcat (n, ":1");
	    define_type (level + 1, n, &i);
	    free (n);
	    if (tag == -1)
		tag = m->val;
	}
	space(level);
	fprintf (headerfile, "} %s;\n\n", name);
	break;
    }
    case TSequence: {
	Member *m;
	int tag = -1;

	space(level);
	fprintf (headerfile, "struct {\n");
	for (m = t->members; m && m->val != tag; m = m->next) {
	    if (m->optional) {
		char *n = malloc(strlen(m->gen_name) + 2);

		*n = '*';
		strcpy (n+1, m->gen_name);
		define_type (level + 1, n, m->type);
		free (n);
	    } else
		define_type (level + 1, m->gen_name, m->type);
	    if (tag == -1)
		tag = m->val;
	}
	space(level);
	fprintf (headerfile, "} %s;\n", name);
	break;
    }
    case TSequenceOf: {
	Type i;

	i.type = TInteger;
	i.application = 0;

	space(level);
	fprintf (headerfile, "struct {\n");
	define_type (level + 1, "len", &i);
	define_type (level + 1, "*val", t->subtype);
	space(level);
	fprintf (headerfile, "} %s;\n", name);
	break;
    }
    case TGeneralizedTime:
	space(level);
	fprintf (headerfile, "time_t %s;\n", name);
	break;
    case TGeneralString:
	space(level);
	fprintf (headerfile, "general_string %s;\n", name);
	break;
    case TApplication:
	define_type (level, name, t->subtype);
	break;
    default:
	abort ();
    }
}

static void
generate_type_header (Symbol *s)
{
    fprintf (headerfile, "/*\n");
    fprintf (headerfile, "%s ::= ", s->name);
    define_asn1 (0, s->type);
    fprintf (headerfile, "\n*/\n\n");

    fprintf (headerfile, "typedef ");
    define_type (0, s->gen_name, s->type);

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
	     "#include \"libasn1.h\"\n\n"
#if 0
	     "#include <stdio.h>\n"
	     "#include <stdlib.h>\n"
	     "#include <time.h>\n"
	     "#include <" STEM ".h>\n\n"
	     "#include <asn1_err.h>\n"
	     "#include <der.h>\n"
#endif
	     ,orig_filename);
    generate_type_header (s);
    generate_type_encode (s);
    generate_type_decode (s);
    generate_type_free (s);
    generate_type_length (s);
    generate_type_copy (s);
    generate_type_maybe (s);
    fprintf(headerfile, "\n\n");
    fclose(codefile);
}
