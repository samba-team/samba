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
#include "lex.h"
#include "lex.h"

static Hashtab *htab;

struct symhead symbols;

static int
cmp(void *a, void *b)
{
    Symbol *s1 = (Symbol *) a;
    Symbol *s2 = (Symbol *) b;

    return strcmp(s1->name, s2->name);
}

static unsigned
hash(void *a)
{
    Symbol *s = (Symbol *) a;

    return hashjpw(s->name);
}

void
initsym(void)
{
    htab = hashtabnew(101, cmp, hash);
}


void
output_name(char *s)
{
    char *p;

    for (p = s; *p; ++p)
	if (*p == '-' || *p == '.')
	    *p = '_';
}

Symbol *
addsym(char *name)
{
    Symbol key, *s;

    key.name = name;
    s = (Symbol *) hashtabsearch(htab, (void *) &key);
    if (s == NULL) {
	s = (Symbol *) ecalloc(1, sizeof(*s));
	s->name = name;
	s->gen_name = estrdup(name);
	output_name(s->gen_name);
	s->stype = SUndefined;
	hashtabadd(htab, s);
        //HEIM_TAILQ_INSERT_TAIL(&symbols, s, symlist);
        do {
            if (((s)->symlist.tqe_next = (&symbols)->tqh_first) != NULL)
                (&symbols)->tqh_first->symlist.tqe_prev = &(s)->symlist.tqe_next;
            else
                (&symbols)->tqh_last = &(s)->symlist.tqe_next;
            (&symbols)->tqh_first = (s);
            (s)->symlist.tqe_prev = &(&symbols)->tqh_first;
        } while (0);
    }
    return s;
}

Symbol *
getsym(char *name)
{
    Symbol key;

    key.name = name;
    return (Symbol *) hashtabsearch(htab, (void *) &key);
}

static int
checkfunc(void *ptr, void *arg)
{
    Symbol *s = ptr;
    if (s->stype == SUndefined) {
	lex_error_message("%s is still undefined\n", s->name);
	*(int *) arg = 1;
    }
    return 0;
}

int
checkundefined(void)
{
    int f = 0;
    hashtabforeach(htab, checkfunc, &f);
    return f;
}

#if 0
static int
generate_1type(void *ptr, void *arg)
{
    Symbol *s = ptr;

    if (s->stype == Stype && s->type)
        generate_type(s);
    return 0;
}
#endif

void
generate_types(void)
{
    Symbol *s;

    if (checkundefined())
        errx(1, "Some types are undefined");
    HEIM_TAILQ_FOREACH_REVERSE(s, &symbols, symhead, symlist) {
        if (s->stype == Stype && s->type)
            generate_type(s);
    }
    //hashtabforeach(htab, generate_1type, NULL);
}

void
emitted_declaration(const Symbol *s)
{
    ((Symbol *)(uintptr_t)s)->emitted_declaration = 1;
}

void
emitted_definition(const Symbol *s)
{
    ((Symbol *)(uintptr_t)s)->emitted_definition = 1;
}

void
emitted_tag_enums(const Symbol *s)
{
    ((Symbol *)(uintptr_t)s)->emitted_tag_enums = 1;
}
