/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "symbol.h"

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
