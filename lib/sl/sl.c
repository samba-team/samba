/*
 * Copyright (c) 1995, 1996 Kungliga Tekniska Högskolan (Royal Institute
 * of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Kungliga Tekniska
 *      Högskolan and its contributors.
 * 
 * 4. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include "sl_locl.h"

static SL_cmd *
sl_match (SL_cmd *cmds, char *cmd, int exactp)
{
  SL_cmd *c, *current = NULL, *partial_cmd;
  int partial_match = 0;

  for (c = cmds; c->name; ++c) {
    if (c->func)
      current = c;
    if (strcmp (cmd, c->name) == 0)
      return current;
    else if (strncmp (cmd, c->name, strlen(cmd)) == 0 &&
	     partial_cmd != current) {
      ++partial_match;
      partial_cmd = current;
    }
  }
  if (partial_match == 1 && !exactp)
    return partial_cmd;
  else
    return NULL;
}

void
sl_help (SL_cmd *cmds, int argc, char **argv)
{
  SL_cmd *c;

  if (argc == 1) {
    for (c = cmds; c->name; ++c)
      printf ("%s\t%s\n", c->name, c->usage ? c->usage : "");
  } else { 
    c = sl_match (cmds, argv[1], 0);
    if (c == NULL)
      printf ("No such command: %s. Try \"help\" for a list of all commands\n",
	      argv[1]);
    else {
      printf ("%s\t%s", c->name, c->usage);
      if((++c)->name && c->func == NULL) {
	printf ("\nSynonyms:");
	while (c->name && c->func == NULL)
	  printf ("\t%s", (c++)->name);
      }
      printf ("\n");
    }
  }
}

int
sl_loop (SL_cmd *cmds, char *prompt)
{
  char buf[BUFSIZ];
  int count;
  char *ptr[17];
  int i;

  for (;;) {
    char *p;
    char **a = ptr;
    SL_cmd *c;

    printf ("%s", prompt);
    fflush (stdout);
    if(fgets (buf, sizeof(buf), stdin) == NULL)
      break;

    if (buf[strlen(buf) - 1] == '\n')
      buf[strlen(buf) - 1] = '\0';
    p = buf;
    count = 0;
    for (;;) {
      while (*p == ' ' || *p == '\t')
	p++;
      if (*p == '\0')
	break;
      *a++ = p;
      ++count;
      while (*p != '\0' && *p != ' ' && *p != '\t')
	p++;
      if (*p == '\0')
	break;
      *p++ = '\0';
    }
    c = sl_match (cmds, ptr[0], 0);
    if (c)
      (*c->func)(count, ptr);
    else
      printf ("Unrecognized command: %s\n", ptr[0]);
  }
  return 0;
}

