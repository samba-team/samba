/*
 * Copyright (c) 1997, 1999, 2000, 2003 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

static FILE *
get_code_file(void)
{
    if (!one_code_file && template_flag && templatefile)
        return templatefile;
    return codefile;
}

static void
generate_2int (const Type *t, const char *gen_name)
{
    Member *m;

    fprintf (headerfile,
	     "uint64_t %s2int(%s);\n",
	     gen_name, gen_name);

    fprintf (get_code_file(),
	     "uint64_t %s2int(%s f)\n"
	     "{\n"
	     "uint64_t r = 0;\n",
	     gen_name, gen_name);

    HEIM_TAILQ_FOREACH(m, t->members, members) {
	fprintf (get_code_file(), "if(f.%s) r |= (1ULL << %d);\n",
		 m->gen_name, (int)m->val);
    }
    fprintf (get_code_file(), "return r;\n"
	     "}\n\n");
}

static void
generate_int2 (const Type *t, const char *gen_name)
{
    Member *m;

    fprintf (headerfile,
	     "%s int2%s(uint64_t);\n",
	     gen_name, gen_name);

    fprintf (get_code_file(),
	     "%s int2%s(uint64_t n)\n"
	     "{\n"
	     "\t%s flags;\n\n"
	     "\tmemset(&flags, 0, sizeof(flags));\n\n",
	     gen_name, gen_name, gen_name);

    if(t->members) {
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    fprintf (get_code_file(), "\tflags.%s = (n >> %d) & 1;\n",
		     m->gen_name, (int)m->val);
	}
    }
    fprintf (get_code_file(), "\treturn flags;\n"
	     "}\n\n");
}

/*
 * This depends on the bit string being declared in increasing order
 */

static void
generate_units (const Type *t, const char *gen_name)
{
    Member *m;

    fprintf (headerfile,
             "const struct units * asn1_%s_units(void);\n",
             gen_name);

    fprintf (get_code_file(),
	     "static struct units %s_units[] = {\n",
	     gen_name);

    if(t->members) {
	HEIM_TAILQ_FOREACH_REVERSE(m, t->members, memhead, members) {
	    fprintf (get_code_file(),
		     "\t{\"%s\",\t1ULL << %d},\n", m->name, (int)m->val);
	}
    }

    fprintf (get_code_file(),
	     "\t{NULL,\t0}\n"
	     "};\n\n");

    fprintf (get_code_file(),
             "const struct units * asn1_%s_units(void){\n"
             "return %s_units;\n"
             "}\n\n",
             gen_name, gen_name);


}

void
generate_glue (const Type *t, const char *gen_name)
{
    switch(t->type) {
    case TTag:
	generate_glue(t->subtype, gen_name);
	break;
    case TBitString : {
        Member *m;

        if (HEIM_TAILQ_EMPTY(t->members))
            break;
        HEIM_TAILQ_FOREACH(m, t->members, members) {
            if (m->val > 63) {
                warnx("Not generating 2int, int2, or units for %s due to "
                      "having a member valued more than 63", gen_name);
                return;
            }
        }
        generate_2int (t, gen_name);
        generate_int2 (t, gen_name);
        if (parse_units_flag)
            generate_units (t, gen_name);
	break;
    }
    default :
	break;
    }
}
