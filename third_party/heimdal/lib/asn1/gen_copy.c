/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * 3. Neither the name of the Institute nor the names of its contributors
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

#include "gen_locl.h"

RCSID("$Id$");

static int used_fail;

static void
copy_primitive (const char *typename, const char *from, const char *to)
{
    fprintf (codefile, "if(der_copy_%s(%s, %s)) goto fail;\n",
	     typename, from, to);
    used_fail++;
}

static void
copy_type (const char *from, const char *to, const Type *t, int preserve)
{
    switch (t->type) {
    case TType:
#if 0
	copy_type (from, to, t->symbol->type, preserve);
#endif
	fprintf (codefile, "if(copy_%s(%s, %s)) goto fail;\n",
		 t->symbol->gen_name, from, to);
	used_fail++;
	break;
    case TInteger:
	if (t->range == NULL && t->members == NULL) {
	    copy_primitive ("heim_integer", from, to);
	    break;
	}
        HEIM_FALLTHROUGH;
    case TBoolean:
    case TEnumerated :
	fprintf(codefile, "*(%s) = *(%s);\n", to, from);
	break;
    case TOctetString:
	copy_primitive ("octet_string", from, to);
	break;
    case TBitString:
	if (HEIM_TAILQ_EMPTY(t->members))
	    copy_primitive ("bit_string", from, to);
	else
	    fprintf(codefile, "*(%s) = *(%s);\n", to, from);
	break;
    case TSet:
    case TSequence:
    case TChoice: {
	Member *m, *have_ellipsis = NULL;

	if(t->members == NULL)
	    break;

	if ((t->type == TSequence || t->type == TChoice) && preserve) {
	    fprintf(codefile,
		    "{ int ret;\n"
		    "ret = der_copy_octet_string(&(%s)->_save, &(%s)->_save);\n"
		    "if (ret) goto fail;\n"
		    "}\n",
		    from, to);
	    used_fail++;
	}

	if(t->type == TChoice) {
	    fprintf(codefile, "(%s)->element = (%s)->element;\n", to, from);
	    fprintf(codefile, "switch((%s)->element) {\n", from);
	}

	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    char *fs;
	    char *ts;

	    if (m->ellipsis) {
		have_ellipsis = m;
		continue;
	    }

	    if(t->type == TChoice)
		fprintf(codefile, "case %s:\n", m->label);

	    if (asprintf (&fs, "%s(%s)->%s%s",
			  m->optional ? "" : "&", from,
			  t->type == TChoice ? "u." : "", m->gen_name) < 0)
		errx(1, "malloc");
	    if (fs == NULL)
		errx(1, "malloc");
	    if (asprintf (&ts, "%s(%s)->%s%s",
			  m->optional ? "" : "&", to,
			  t->type == TChoice ? "u." : "", m->gen_name) < 0)
		errx(1, "malloc");
	    if (ts == NULL)
		errx(1, "malloc");
	    if(m->optional){
		fprintf(codefile, "if(%s) {\n", fs);
		fprintf(codefile, "%s = calloc(1, sizeof(*%s));\n", ts, ts);
		fprintf(codefile, "if(%s == NULL) goto fail;\n", ts);
		used_fail++;
	    }
	    copy_type (fs, ts, m->type, FALSE);
	    if(m->optional){
		fprintf(codefile, "}else\n");
		fprintf(codefile, "%s = NULL;\n", ts);
	    }
	    free (fs);
	    free (ts);
	    if(t->type == TChoice)
		fprintf(codefile, "break;\n");
	}
	if(t->type == TChoice) {
	    if (have_ellipsis) {
		fprintf(codefile, "case %s: {\n"
			"int ret;\n"
			"ret=der_copy_octet_string(&(%s)->u.%s, &(%s)->u.%s);\n"
			"if (ret) goto fail;\n"
			"break;\n"
			"}\n",
			have_ellipsis->label,
			from, have_ellipsis->gen_name,
			to, have_ellipsis->gen_name);
		used_fail++;
	    }
	    fprintf(codefile, "}\n");
	}
	break;
    }
    case TSetOf:
    case TSequenceOf: {
	char *f = NULL, *T = NULL;

	fprintf (codefile, "if(((%s)->val = "
		 "calloc(1, (%s)->len * sizeof(*(%s)->val))) == NULL && (%s)->len != 0)\n",
		 to, from, to, from);
	fprintf (codefile, "goto fail;\n");
	used_fail++;
	fprintf(codefile,
		"for((%s)->len = 0; (%s)->len < (%s)->len; (%s)->len++){\n",
		to, to, from, to);
	if (asprintf(&f, "&(%s)->val[(%s)->len]", from, to) < 0)
	    errx(1, "malloc");
	if (f == NULL)
	    errx(1, "malloc");
	if (asprintf(&T, "&(%s)->val[(%s)->len]", to, to) < 0)
	    errx(1, "malloc");
	if (T == NULL)
	    errx(1, "malloc");
	copy_type(f, T, t->subtype, FALSE);
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
    case TTeletexString:
	copy_primitive ("general_string", from, to);
	break;
    case TUTCTime:
	fprintf(codefile, "*(%s) = *(%s);\n", to, from);
	break;
    case TUTF8String:
	copy_primitive ("utf8string", from, to);
	break;
    case TPrintableString:
	copy_primitive ("printable_string", from, to);
	break;
    case TIA5String:
	copy_primitive ("ia5_string", from, to);
	break;
    case TBMPString:
	copy_primitive ("bmp_string", from, to);
	break;
    case TUniversalString:
	copy_primitive ("universal_string", from, to);
	break;
    case TVisibleString:
	copy_primitive ("visible_string", from, to);
	break;
    case TTag:
	copy_type (from, to, t->subtype, preserve);
	break;
    case TOID:
	copy_primitive ("oid", from, to);
	break;
    case TNull:
	break;
    default :
	abort ();
    }
}

void
generate_type_copy (const Symbol *s)
{
  struct decoration deco;
  ssize_t more_deco = -1;
  int preserve = preserve_type(s->name) ? TRUE : FALSE;
  int save_used_fail = used_fail;

  used_fail = 0;

  fprintf (codefile, "int ASN1CALL\n"
	   "copy_%s(const %s *from, %s *to)\n"
	   "{\n"
	   "memset(to, 0, sizeof(*to));\n",
	   s->gen_name, s->gen_name, s->gen_name);
  copy_type ("from", "to", s->type, preserve);
  while (decorate_type(s->gen_name, &deco, &more_deco)) {
      if (deco.ext && deco.copy_function_name == NULL) {
          /* Decorated with field of external type but no copy function */
          if (deco.ptr)
              fprintf(codefile, "(to)->%s = 0;\n", deco.field_name);
          else
              fprintf(codefile, "memset(&(to)->%s, 0, sizeof((to)->%s));\n",
                      deco.field_name, deco.field_name);
      } else if (deco.ext) {
          /* Decorated with field of external type w/ copy function */
          if (deco.ptr) {
              fprintf(codefile, "if (from->%s) {\n", deco.field_name);
              fprintf(codefile, "(to)->%s = calloc(1, sizeof(*(to)->%s));\n",
                      deco.field_name, deco.field_name);
              fprintf(codefile, "if (%s((from)->%s, (to)->%s)) goto fail;\n",
                      deco.copy_function_name, deco.field_name, deco.field_name);
              fprintf(codefile, "}\n");
          } else {
              fprintf(codefile, "if (%s(&(from)->%s, &(to)->%s)) goto fail;\n",
                      deco.copy_function_name, deco.field_name, deco.field_name);
          }
      } else if (deco.opt) {
          /* Decorated with optional field of ASN.1 type */
          fprintf(codefile, "if (from->%s) {\n", deco.field_name);
          fprintf(codefile, "(to)->%s = calloc(1, sizeof(*(to)->%s));\n", deco.field_name, deco.field_name);
          fprintf(codefile, "if (copy_%s((from)->%s, (to)->%s)) goto fail;\n", deco.field_type, deco.field_name, deco.field_name);
          fprintf(codefile, "}\n");
      } else {
          /* Decorated with required field of ASN.1 type */
          fprintf(codefile, "if (copy_%s(&(from)->%s, &(to)->%s)) goto fail;\n", deco.field_type, deco.field_name, deco.field_name);
      }
      used_fail++;
      free(deco.field_type);
  }
  fprintf (codefile, "return 0;\n");

  if (used_fail)
      fprintf (codefile, "fail:\n"
	       "free_%s(to);\n"
	       "return ENOMEM;\n",
	       s->gen_name);

  fprintf(codefile,
	  "}\n\n");
  used_fail = save_used_fail;
}

