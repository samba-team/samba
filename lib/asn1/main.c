#include "asn1_locl.h"

RCSID("$Id$");

extern FILE *yyin;

int
main(int argc, char **argv)
{
  int ret;
  char *name;

  if (argc == 1) {
    name = "stdin";
    yyin = stdin;
  } else {
    name = argv[1];
    yyin = fopen (name, "r");
  }

  init_generate (name);
  initsym ();
  ret = yyparse ();
  close_generate ();
  return ret;
}
