#include "gen_locl.h"

RCSID("$Id$");

void
generate_type_maybe (Symbol *s)
{
    fprintf (headerfile,
	     "int maybe_%s(unsigned char *, size_t);\n",
	     s->gen_name);

    fprintf (codefile, "int\n"
	     "maybe_%s(unsigned char *p, size_t len)\n"
	     "{\n    "
	     "size_t size;\n    ",
	     s->gen_name);
  
    switch (s->type->type) {
    case TInteger:
	fprintf (codefile, "return der_match_tag (p, len, UNIV, "
		 "PRIM, UT_Integer, &size) == 0;\n");
	break;
    case TOctetString:
	fprintf (codefile, "return der_match_tag (p, len, UNIV, "
		 "PRIM, UT_OctetString, &size) == 0;\n");
	break;
    case TGeneralizedTime:
	fprintf (codefile, "return der_match_tag (p, len, UNIV, "
		 "PRIM, UT_GeneralizedTime, &size) == 0;\n");
	break;
    case TGeneralString:
	fprintf (codefile, "return der_match_tag (p, len, UNIV, "
		 "PRIM, UT_GeneralString, &size) == 0;\n");
	break;
    case TBitString:
	fprintf (codefile, "return der_match_tag (p, len, UNIV, "
		 "PRIM, UT_BitString, &size) == 0;\n");
	break;
	
    case TSequence:
    case TSequenceOf:
	fprintf (codefile, "return der_match_tag (p, len, UNIV, "
		 "CONS, UT_Sequence, &size) == 0;\n");
	break;
    case TApplication:
	fprintf (codefile, "return der_match_tag (p, len, APPL, "
		 "CONS, %d, &size) == 0;\n", s->type->application);
	break;
    case TType:
	fprintf (codefile, "return maybe_%s(p, len) == 0;\n", 
		 s->type->symbol->gen_name);
	break;
    default:
	abort ();
    }
    fprintf (codefile, "}\n\n");
}

