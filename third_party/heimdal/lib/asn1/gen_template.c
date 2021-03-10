/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2010 Apple Inc. All rights reserved.
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

/*
 * Currently we generate C source code defining constant arrays of structures
 * containing a sort of a "byte-coded" template of an ASN.1 compiler to be
 * interpreted at run-time.
 */

#include "gen_locl.h"
#include <vis.h>
#include <vis-extras.h>

static const char *symbol_name(const char *, const Type *);
static void generate_template_type(const char *, const char **, const char *, const char *, const char *,
				   Type *, int, int, int);

static const char *
ttype_symbol(const char *basename, const Type *t)
{
    return t->symbol->gen_name;
}

static const char *
integer_symbol(const char *basename, const Type *t)
{
    if (t->members)
        /*
         * XXX enum foo -- compute the size either from inspecting the members
         * and applying the ABI's rules for enum size, OR infer the field
         * size from a template by using the offsetof field.  The latter is
         * hard to do though.
         */
	return "int";
    else if (t->range == NULL)
	return "heim_integer";
    else if (t->range->min < 0 &&
             (t->range->min < INT_MIN || t->range->max > INT_MAX))
	return "int64_t";
    else if (t->range->min < 0)
	return "int";
    else if (t->range->max > UINT_MAX)
	return "uint64_t";
    else
	return "unsigned";
}

static const char *
boolean_symbol(const char *basename, const Type *t)
{
    return "int";
}


static const char *
octetstring_symbol(const char *basename, const Type *t)
{
    return "heim_octet_string";
}

static const char *
sequence_symbol(const char *basename, const Type *t)
{
    return basename;
}

static const char *
time_symbol(const char *basename, const Type *t)
{
    return "time_t";
}

static const char *
tag_symbol(const char *basename, const Type *t)
{
    return symbol_name(basename, t->subtype);
}

static const char *
generalstring_symbol(const char *basename, const Type *t)
{
    return "heim_general_string";
}

static const char *
printablestring_symbol(const char *basename, const Type *t)
{
    return "heim_printable_string";
}

static const char *
ia5string_symbol(const char *basename, const Type *t)
{
    return "heim_ia5_string";
}

static const char *
teletexstring_symbol(const char *basename, const Type *t)
{
    return "heim_general_string";
}

static const char *
visiblestring_symbol(const char *basename, const Type *t)
{
    return "heim_visible_string";
}

static const char *
utf8string_symbol(const char *basename, const Type *t)
{
    return "heim_utf8_string";
}

static const char *
bmpstring_symbol(const char *basename, const Type *t)
{
    return "heim_bmp_string";
}

static const char *
universalstring_symbol(const char *basename, const Type *t)
{
    return "heim_universal_string";
}

static const char *
oid_symbol(const char *basename, const Type *t)
{
    return "heim_oid";
}

static const char *
bitstring_symbol(const char *basename, const Type *t)
{
    if (t->members)
	return basename;
    return "heim_bit_string";
}



/* Keep this sorted by `type' so we can just index this by type */
const struct {
    enum typetype type;
    const char *(*symbol_name)(const char *, const Type *);
    int is_struct;
} types[] =  {
    { TBitString, bitstring_symbol, 0 },
    { TBoolean, boolean_symbol, 0 },
    { TChoice, sequence_symbol, 1 },
    { TEnumerated, integer_symbol, 0 },
    { TGeneralString, generalstring_symbol, 0 },
    { TTeletexString, teletexstring_symbol, 0 },
    { TGeneralizedTime, time_symbol, 0 },
    { TIA5String, ia5string_symbol, 0 },
    { TInteger, integer_symbol, 0 },
    { TNull, integer_symbol, 1 },
    { TOID, oid_symbol, 0 },
    { TOctetString, octetstring_symbol, 0 },
    { TPrintableString, printablestring_symbol, 0 },
    { TSequence, sequence_symbol, 1 },
    { TSequenceOf, tag_symbol, 1 },
    { TSet, sequence_symbol, 1 },
    { TSetOf, tag_symbol, 1 },
    { TTag, tag_symbol, 1 },
    { TType, ttype_symbol, 1 },
    { TUTCTime, time_symbol, 0 },
    { TUTF8String, utf8string_symbol, 0 },
    { TBMPString, bmpstring_symbol, 0 },
    { TUniversalString, universalstring_symbol, 0 },
    { TVisibleString, visiblestring_symbol, 0 },
};

static FILE *
get_code_file(void)
{
    if (!one_code_file)
	return templatefile;
    return codefile;
}


static int
is_supported_type_p(const Type *t)
{
    return t->type >= 0 && t->type <= TVisibleString &&
        types[t->type].type == t->type;
}

int
is_template_compat (const Symbol *s)
{
    return is_supported_type_p(s->type);
}

static const char *
symbol_name(const char *basename, const Type *t)
{
    if (t->type >= 0 && t->type <= TVisibleString &&
        types[t->type].type == t->type)
        return (types[t->type].symbol_name)(basename, t);
    if (t->type >= 0 && t->type <= TVisibleString)
        errx(1, "types[] is not sorted");
    errx(1, "unknown der type: %d\n", t->type);
    return NULL;
}


static char *
partial_offset(const char *basetype, const char *name, int need_offset, int isstruct)
{
    char *str;
    if (name == NULL || need_offset == 0)
	return strdup("0");
    if (asprintf(&str, "offsetof(%s%s, %s)", isstruct ? "struct " : "", basetype, name) < 0 || str == NULL)
	errx(1, "malloc");
    return str;
}

struct template {
    char *line;
    char *tt;
    char *offset;
    char *ptr;
    HEIM_TAILQ_ENTRY(template) members;
};

HEIM_TAILQ_HEAD(templatehead, template);

struct tlist {
    char *name;
    char *header;
    struct templatehead template;
    HEIM_TAILQ_ENTRY(tlist) tmembers;
};

HEIM_TAILQ_HEAD(tlisthead, tlist);

static void tlist_header(struct tlist *, const char *, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
static struct template *
    add_line(struct templatehead *, const char *, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
static int tlist_cmp(const struct tlist *, const struct tlist *);

static void add_line_pointer(struct templatehead *, const char *, const char *, const char *, ...)
    __attribute__ ((__format__ (__printf__, 4, 5)));
static void add_line_string(struct templatehead *, const char *, const char *, const char *, ...)
    __attribute__ ((__format__ (__printf__, 4, 5)));
static void add_line_pointer_reference(struct templatehead *, const char *, const char *, const char *, ...)
    __attribute__ ((__format__ (__printf__, 4, 5)));


static struct tlisthead tlistmaster = HEIM_TAILQ_HEAD_INITIALIZER(tlistmaster);
static unsigned long numdups = 0;

static struct tlist *
tlist_new(const char *name)
{
    struct tlist *tl = calloc(1, sizeof(*tl));
    tl->name = strdup(name);
    HEIM_TAILQ_INIT(&tl->template);
    return tl;
}

static void
tlist_header(struct tlist *t, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&t->header, fmt, ap) < 0 || t->header == NULL)
	errx(1, "malloc");
    va_end(ap);
}

static unsigned long
tlist_count(struct tlist *tl)
{
    unsigned int count = 0;
    struct template *q;

    HEIM_TAILQ_FOREACH(q, &tl->template, members) {
	count++;
    }
    return count;
}

static void
tlist_add(struct tlist *tl)
{
    HEIM_TAILQ_INSERT_TAIL(&tlistmaster, tl, tmembers);
}

static void
tlist_print(struct tlist *tl)
{
    struct template *q;
    unsigned int i = 1;
    FILE *f = get_code_file();

    fprintf(f, "const struct asn1_template asn1_%s[] = {\n", tl->name);
    fprintf(f, "/* 0 */ %s,\n", tl->header);
    HEIM_TAILQ_FOREACH(q, &tl->template, members) {
	int last = (HEIM_TAILQ_LAST(&tl->template, templatehead) == q);
	fprintf(f, "/* %lu */ %s%s\n", (unsigned long)i++, q->line, last ? "" : ",");
    }
    fprintf(f, "};\n");
}

static struct tlist *
tlist_find_by_name(const char *name)
{
    struct tlist *ql;
    HEIM_TAILQ_FOREACH(ql, &tlistmaster, tmembers) {
	if (strcmp(ql->name, name) == 0)
	    return ql;
    }
    return NULL;
}

static int
tlist_cmp_name(const char *tname, const char *qname)
{
    struct tlist *tl = tlist_find_by_name(tname);
    struct tlist *ql = tlist_find_by_name(qname);
    if (tl == NULL)
	return 1;
    if (ql == NULL)
	return -1;
    return tlist_cmp(tl, ql);
}

static int
tlist_cmp(const struct tlist *tl, const struct tlist *ql)
{
    int ret;
    struct template *t, *q;

    if (tl == ql)
        return 0;
    ret = strcmp(tl->header, ql->header);
    if (ret != 0) return ret;

    q = HEIM_TAILQ_FIRST(&ql->template);
    HEIM_TAILQ_FOREACH(t, &tl->template, members) {
	if (q == NULL) return 1;

	if (t->ptr == NULL || q->ptr == NULL) {
	    ret = strcmp(t->line, q->line);
	    if (ret != 0) return ret;
	} else {
	    ret = strcmp(t->tt, q->tt);
	    if (ret != 0) return ret;

	    ret = strcmp(t->offset, q->offset);
	    if (ret != 0) return ret;

	    if ((ret = strcmp(t->ptr, q->ptr)) != 0 ||
		(ret = tlist_cmp_name(t->ptr, q->ptr)) != 0)
		return ret;
	}
	q = HEIM_TAILQ_NEXT(q, members);
    }
    if (q != NULL) return -1;
    return 0;
}


static const char *
tlist_find_dup(const struct tlist *tl)
{
    struct tlist *ql;

    HEIM_TAILQ_FOREACH(ql, &tlistmaster, tmembers) {
	if (tlist_cmp(ql, tl) == 0) {
	    numdups++;
	    return ql->name;
	}
    }
    return NULL;
}


/*
 * Add an entry to a template.
 */

static struct template *
add_line(struct templatehead *t, const char *fmt, ...)
{
    struct template *q = calloc(1, sizeof(*q));
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&q->line, fmt, ap) < 0 || q->line == NULL)
	errx(1, "malloc");
    va_end(ap);
    HEIM_TAILQ_INSERT_TAIL(t, q, members);
    return q;
}

/*
 * Add an entry to a template, with the pointer field being a symbol name of a
 * template (i.e., an array, which decays to a pointer as usual in C).
 */
static void
add_line_pointer(struct templatehead *t,
		 const char *ptr,
		 const char *offset,
		 const char *ttfmt,
		 ...)
{
    struct template *q;
    va_list ap;
    char *tt = NULL;

    va_start(ap, ttfmt);
    if (vasprintf(&tt, ttfmt, ap) < 0 || tt == NULL)
	errx(1, "malloc");
    va_end(ap);

    if (ptr[0] == '&')
        q = add_line(t, "{ %s, %s, %s }", tt, offset, ptr);
    else
        q = add_line(t, "{ %s, %s, asn1_%s }", tt, offset, ptr);
    q->tt = tt;
    q->offset = strdup(offset);
    q->ptr = strdup(ptr);
}

/*
 * Add an entry to a template where the pointer field is a string literal.
 */
static void
add_line_string(struct templatehead *t,
		const char *str,
		const char *offset,
		const char *ttfmt,
		...)
{
    struct template *q;
    va_list ap;
    char *tt = NULL;

    va_start(ap, ttfmt);
    if (vasprintf(&tt, ttfmt, ap) < 0 || tt == NULL)
	errx(1, "malloc");
    va_end(ap);

    q = add_line(t, "{ %s, %s, \"%s\" }", tt, offset, str);
    q->tt = tt;
    q->offset = strdup(offset);
    q->ptr = strdup(str);
}

/*
 * Add an entry to a template, with the pointer field being a reference to
 * named object of a type other than a template or other array type.
 */
static void
add_line_pointer_reference(struct templatehead *t,
                           const char *ptr,
                           const char *offset,
                           const char *ttfmt,
                           ...)
{
    struct template *q;
    va_list ap;
    char *tt = NULL;

    va_start(ap, ttfmt);
    if (vasprintf(&tt, ttfmt, ap) < 0 || tt == NULL)
	errx(1, "malloc");
    va_end(ap);

    q = add_line(t, "{ %s, %s, (const void *)&asn1_%s }", tt, offset, ptr);
    q->tt = tt;
    q->offset = strdup(offset);
    q->ptr = strdup(ptr);
}

static int
use_extern(const Symbol *s)
{
    if (s->type == NULL)
	return 1;
    return 0;
}

static int
is_struct(const Type *t, int isstruct)
{
    if (t->type == TType)
	return 0;
    if (t->type == TSequence || t->type == TSet || t->type == TChoice)
	return 1;
    if (t->type == TTag)
	return is_struct(t->subtype, isstruct);

    if (t->type >= 0 && t->type <= TVisibleString &&
        types[t->type].type == t->type) {
        if (types[t->type].is_struct == 0)
            return 0;
        return isstruct;
    }
    if (t->type >= 0 && t->type <= TVisibleString)
        errx(1, "types[] is not sorted");
    errx(1, "unknown der type: %d\n", t->type);
    return isstruct;
}

static const Type *
compact_tag(const Type *t)
{
    while (t->type == TTag)
	t = t->subtype;
    return t;
}

static void
defval(struct templatehead *temp, Member *m)
{
    switch (m->defval->type) {
    case booleanvalue:
	add_line(temp, "{ A1_OP_DEFVAL|A1_DV_BOOLEAN, ~0, (void *)(uintptr_t)%u }",
                 m->defval->u.booleanvalue);
        break;
    case nullvalue:
	add_line(temp, "{ A1_OP_DEFVAL|A1_DV_NULL, ~0, (void *)(uintptr_t)0 }");
        break;
    case integervalue: {
        const char *dv = "A1_DV_INTEGER";
        Type *t = m->type;

        for (;;) {
            if (t->range)
                break;
            if (t->type == TInteger && t->members)
                break;
            if (t->type == TEnumerated)
                break;
            if (t->subtype)
                t = t->subtype;
            else if (t->symbol && t->symbol->type)
                t = t->symbol->type;
            else
                errx(1, "DEFAULT values for unconstrained INTEGER members not supported");
        }

        if (t->members)
            dv = "A1_DV_INTEGER32"; /* XXX Enum size assumptions!  No good! */
        else if (t->range && t->range->min < 0 &&
                 (t->range->min < INT_MIN || t->range->max > INT_MAX))
            dv = "A1_DV_INTEGER64";
        else if (t->range && t->range->min < 0)
            dv = "A1_DV_INTEGER32";
        else if (t->range && t->range->max > UINT_MAX)
            dv = "A1_DV_INTEGER64";
        else
            dv = "A1_DV_INTEGER32";
	add_line(temp, "{ A1_OP_DEFVAL|%s, ~0, (void *)(uintptr_t)%llu }",
                 dv, (long long)m->defval->u.integervalue);
        break;
    }
    case stringvalue: {
        char *quoted;

        if (rk_strasvis(&quoted, m->defval->u.stringvalue,
                        VIS_CSTYLE | VIS_NL, "\"") < 0)
            err(1, "Could not quote a string");
	add_line(temp, "{ A1_OP_DEFVAL|A1_DV_UTF8STRING, ~0, (void *)(uintptr_t)\"%s\" }",
                 quoted);
        free(quoted);
        break;
    }
    case objectidentifiervalue: {
        struct objid *o;
        size_t sz = sizeof("{ }");
        char *s, *p;
        int len;

        for (o = m->defval->u.objectidentifiervalue; o != NULL; o = o->next) {
            if ((len = snprintf(0, 0, " %d", o->value)) < 0)
                err(1, "Could not format integer");
            sz += len;
        }

        if ((p = s = malloc(sz)) == NULL)
                err(1, "Could not allocate string");

        len = snprintf(p, sz, "{");
        sz -= len;
        p += len;
        for (o = m->defval->u.objectidentifiervalue; o != NULL; o = o->next) {
            if ((len = snprintf(p, sz, " %d", o->value)) < 0 || len > sz - 1)
                err(1, "Could not format integer");
            sz -= len;
            p += len;
        }
        if ((len = snprintf(p, sz, " }")) >= sz)
            abort();
        sz -= len;
        if (sz != 0)
            abort();

	add_line(temp, "{ A1_OP_DEFVAL|A1_DV_INTEGER, ~0, (void *)(uintptr_t)\"%s\" }", s);
        free(s);
        break;
    }
    default: abort();
    }
}

int
objid_cmp(struct objid *oida, struct objid *oidb)
{
    struct objid *p;
    size_t ai, bi, alen, blen;
    int avals[20];
    int bvals[20];
    int c;

    /*
     * Our OID values are backwards here.  Comparing them is hard.
     */

    for (p = oida, alen = 0;
         p && alen < sizeof(avals)/sizeof(avals[0]);
         p = p->next)
        avals[alen++] = p->value;
    for (p = oidb, blen = 0;
         p && blen < sizeof(bvals)/sizeof(bvals[0]);
         p = p->next)
        bvals[blen++] = p->value;
    if (alen >= sizeof(avals)/sizeof(avals[0]) ||
        blen >= sizeof(bvals)/sizeof(bvals[0]))
        err(1, "OIDs with more components than %llu not supported",
            (unsigned long long)sizeof(avals)/sizeof(avals[0]));

    for (ai = 0, bi = 0; ai < alen && bi < blen;)
        if ((c = avals[(alen-1)-(ai++)] - bvals[(blen-1)-(bi++)]))
            return c;

    if (ai == alen && bi == blen)
        return 0;
    if (ai == alen)
        return 1;
    return -1;
}

int
object_cmp(const void *va, const void *vb)
{
    const IOSObject *oa = *(const IOSObject * const *)va;
    const IOSObject *ob = *(const IOSObject * const *)vb;

    switch (oa->typeidf->value->type) {
    case booleanvalue:
        return oa->typeidf->value->u.booleanvalue -
            ob->typeidf->value->u.booleanvalue;
    case nullvalue:
        return 0;
    case integervalue:
        return oa->typeidf->value->u.integervalue -
            ob->typeidf->value->u.integervalue;
    case stringvalue:
        return strcmp(oa->typeidf->value->u.stringvalue,
            ob->typeidf->value->u.stringvalue);
    case objectidentifiervalue: {
        return objid_cmp(oa->typeidf->value->u.objectidentifiervalue,
            ob->typeidf->value->u.objectidentifiervalue);
    }
    default:
            abort();
            return -1;
    }
}

void
sort_object_set(IOSObjectSet *os,       /* Object set to sort fields of */
                Field *typeidfield,     /* Field to sort by */
                IOSObject ***objectsp,  /* Output: array of objects */
                size_t *nobjsp)         /* Output: count of objects */
{
    IOSObject **objects;
    IOSObject *o;
    size_t i, nobjs = 0;

    *objectsp = NULL;

    HEIM_TAILQ_FOREACH(o, os->objects, objects) {
        ObjectField *typeidobjf = NULL;
        ObjectField *of;

        HEIM_TAILQ_FOREACH(of, o->objfields, objfields) {
            if (strcmp(of->name, typeidfield->name) == 0)
                typeidobjf = of;
        }
        if (!typeidobjf) {
            warnx("Ignoring incomplete object specification of %s "
                  "(missing type ID field)",
                  o->symbol ? o->symbol->name : "<unknown>");
            continue;
        }
        o->typeidf = typeidobjf;
        nobjs++;
    }
    *nobjsp = nobjs;

    if (nobjs == 0)
        return;

    if ((objects = calloc(nobjs, sizeof(*objects))) == NULL)
        err(1, "Out of memory");
    *objectsp = objects;

    i = 0;
    HEIM_TAILQ_FOREACH(o, os->objects, objects) {
        ObjectField *typeidobjf = NULL;
        ObjectField *of;

        HEIM_TAILQ_FOREACH(of, o->objfields, objfields) {
            if (strcmp(of->name, typeidfield->name) == 0)
                typeidobjf = of;
        }
        if (typeidobjf)
            objects[i++] = o;
    }
    qsort(objects, nobjs, sizeof(*objects), object_cmp);
}

static void
template_object_set(IOSObjectSet *os, Field *typeidfield, Field *opentypefield)
{
    IOSObject **objects = NULL;
    IOSObject *o;
    struct tlist *tl;
    size_t nobjs, i;

    if (os->symbol->emitted_template)
        return;

    sort_object_set(os, typeidfield, &objects, &nobjs);

    tl = tlist_new(os->symbol->name);
    add_line(&tl->template, "{ A1_OP_NAME, 0, \"%s\" }", os->symbol->name);
    for (i = 0; i < nobjs; i++) {
        ObjectField *typeidobjf = NULL, *opentypeobjf = NULL;
        ObjectField *of;
        char *s = NULL;

        o = objects[i];

        HEIM_TAILQ_FOREACH(of, o->objfields, objfields) {
            if (strcmp(of->name, typeidfield->name) == 0)
                typeidobjf = of;
            else if (strcmp(of->name, opentypefield->name) == 0)
                opentypeobjf = of;
        }
        if (!typeidobjf)
            continue; /* We've warned about this one already when sorting */
        if (!opentypeobjf) {
            warnx("Ignoring incomplete object specification of %s "
                  "(missing open type field)",
                  o->symbol ? o->symbol->name : "<unknown>");
            continue;
        }

        add_line(&tl->template, "{ A1_OP_NAME, 0, \"%s\" }", o->symbol->name);
        /*
         * Some of this logic could stand to move into sanity checks of object
         * definitions in asn1parse.y.
         */
        switch (typeidobjf->value->type) {
        case integervalue:
            add_line(&tl->template,
		     "{ A1_OP_OPENTYPE_ID | A1_OTI_IS_INTEGER, 0, (void *)(uintptr_t)%lld }",
                     (long long)typeidobjf->value->u.integervalue);
            break;
        case objectidentifiervalue:
            if (asprintf(&s, "oid_%s",
                         typeidobjf->value->s->gen_name) == -1 || !s)
                err(1, "Out of memory");
            add_line_pointer_reference(&tl->template, s, "0", "A1_OP_OPENTYPE_ID");
            free(s);
            s = NULL;
            break;
        default:
            errx(1, "Only integer and OID types supported "
                 "for open type type-ID fields");
        }

        if (asprintf(&s, "sizeof(%s)",
                     opentypeobjf->type->symbol->gen_name) == -1 || !s)
            err(1, "Out of memory");
        add_line_pointer_reference(&tl->template,
                                   opentypeobjf->type->symbol->gen_name, s,
                                   "A1_OP_OPENTYPE");
        free(s);
    }
    free(objects);

    tlist_header(tl, "{ 0, 0, ((void *)(uintptr_t)%zu) }", nobjs);
    tlist_print(tl);
    tlist_add(tl);
    os->symbol->emitted_template = 1;
}

static void
template_open_type(struct templatehead *temp,
                   const char *basetype,
                   const Type *t,
                   size_t typeididx,
                   size_t opentypeidx,
                   Field *typeidfield,
                   Field *opentypefield,
                   Member *m,
                   int is_array_of_open_type)
{
    char *s = NULL;

    if (typeididx >= 1<<10 || opentypeidx >= 1<<10)
        errx(1, "SET/SEQUENCE with too many members (%s)", basetype);

    if (asprintf(&s, "offsetof(%s, _ioschoice_%s)",
                 basetype, m->gen_name) == -1 || !s)
        err(1, "Out of memory");

    template_object_set(t->actual_parameter, typeidfield, opentypefield);
    add_line_pointer(temp, t->actual_parameter->symbol->gen_name, s,
                     /*
                      * We always sort object sets for now as we can't import
                      * values yet, so they must all be known.
                      */
                     "A1_OP_OPENTYPE_OBJSET | A1_OS_IS_SORTED |%s | (%llu << 10) | %llu",
                     is_array_of_open_type ? "A1_OS_OT_IS_ARRAY" : "0",
                     (unsigned long long)opentypeidx,
                     (unsigned long long)typeididx);
    free(s);
}

static void
template_names(struct templatehead *temp, const char *basetype, const Type *t)
{
    Member *m;

    add_line_string(temp, basetype, "0", "A1_OP_NAME");
    HEIM_TAILQ_FOREACH(m, t->members, members) {
        add_line_string(temp, m->name, "0", "A1_OP_NAME");
    }
}

static void
template_members(struct templatehead *temp,
                 const char *basetype,
                 const char *name,
                 const Type *t,
                 int optional,
                 int defaulted,
                 int implicit,
                 int isstruct,
                 int need_offset)
{
    char *poffset = NULL;

    if (optional && t->type != TTag && t->type != TType)
	errx(1, "%s...%s is optional and not a (TTag or TType)", basetype, name);

    poffset = partial_offset(basetype, name, need_offset, isstruct);

    switch (t->type) {
    case TType:
	if (use_extern(t->symbol)) {
	    add_line(temp, "{ A1_OP_TYPE_EXTERN %s%s%s, %s, &asn1_extern_%s}",
		     optional  ? "|A1_FLAG_OPTIONAL" : "",
		     defaulted ? "|A1_FLAG_DEFAULT" : "",
		     implicit  ? "|A1_FLAG_IMPLICIT" : "",
		     poffset, t->symbol->gen_name);
	} else {
	    add_line_pointer(temp, t->symbol->gen_name, poffset,
			     "A1_OP_TYPE %s%s%s",
			     optional  ? "|A1_FLAG_OPTIONAL" : "",
			     defaulted ? "|A1_FLAG_DEFAULT" : "",
			     implicit  ? "|A1_FLAG_IMPLICIT" : "");

	}
	break;
    case TEnumerated:
    case TInteger: {
        char *varname = NULL;
	char *itype = NULL;

	if (t->members)
	    itype = "IMEMBER";
	else if (t->range == NULL)
	    itype = "HEIM_INTEGER";
	else if (t->range->min < 0 &&
                 (t->range->min < INT_MIN || t->range->max > INT_MAX))
	    itype = "INTEGER64";
	else if (t->range->min < 0)
	    itype = "INTEGER";
	else if (t->range->max > UINT_MAX)
	    itype = "UNSIGNED64";
	else
	    itype = "UNSIGNED";

        /*
         * If `t->members' then we should generate a template for those
         * members.
         *
         * We don't know the name of this field, and the type may not have a
         * name.  If it has no name, we should generate a name for it, and if
         * it does have a name, use it, to name a template for its members.
         *
         * Then we could use that in _asn1_print() to pretty-print values of
         * enumerations.
         */
        if (t->members && t->symbol) {
            struct tlist *tl;
            Member *m;
            size_t nmemb = 0;

            if (asprintf(&varname, "%s_enum_names", t->symbol->gen_name) == -1 ||
                varname == NULL)
                err(1, "Out of memory");

            tl = tlist_new(varname);
            /*
             * XXX We're going to assume that t->members is sorted in
             * numerically ascending order in the module source.  We should
             * really sort it here.
             */
            HEIM_TAILQ_FOREACH(m, t->members, members) {
                if (m->val > UINT32_MAX)
                    errx(1, "Cannot handle %s type %s with named bit %s "
                         "larger than 63",
                         t->type == TEnumerated ? "ENUMERATED" : "INTEGER",
                         name, m->gen_name);
                add_line(&tl->template,
                         "{ A1_OP_NAME, %d, \"%s\" }", (int)m->val, m->name);
                nmemb++;
            }
	    tlist_header(tl, "{ 0, 0, ((void *)(uintptr_t)%zu) }", nmemb);
            /* XXX Accidentally O(N^2)? */
            if (!tlist_find_dup(tl)) {
                tlist_print(tl);
                tlist_add(tl);
            }
            add_line(temp, "{ A1_PARSE_T(A1T_%s), %s, asn1_%s }", itype, poffset, varname);
        } else {
            add_line(temp, "{ A1_PARSE_T(A1T_%s), %s, NULL }", itype, poffset);
        }
	break;
    }
    case TGeneralString:
	add_line(temp, "{ A1_PARSE_T(A1T_GENERAL_STRING), %s, NULL }", poffset);
	break;
    case TTeletexString:
	add_line(temp, "{ A1_PARSE_T(A1T_TELETEX_STRING), %s, NULL }", poffset);
	break;
    case TPrintableString:
	add_line(temp, "{ A1_PARSE_T(A1T_PRINTABLE_STRING), %s, NULL }", poffset);
	break;
    case TOctetString:
	add_line(temp, "{ A1_PARSE_T(A1T_OCTET_STRING), %s, NULL }", poffset);
	break;
    case TIA5String:
	add_line(temp, "{ A1_PARSE_T(A1T_IA5_STRING), %s, NULL }", poffset);
	break;
    case TBMPString:
	add_line(temp, "{ A1_PARSE_T(A1T_BMP_STRING), %s, NULL }", poffset);
	break;
    case TUniversalString:
	add_line(temp, "{ A1_PARSE_T(A1T_UNIVERSAL_STRING), %s, NULL }", poffset);
	break;
    case TVisibleString:
	add_line(temp, "{ A1_PARSE_T(A1T_VISIBLE_STRING), %s, NULL }", poffset);
	break;
    case TUTF8String:
	add_line(temp, "{ A1_PARSE_T(A1T_UTF8_STRING), %s, NULL }", poffset);
	break;
    case TGeneralizedTime:
	add_line(temp, "{ A1_PARSE_T(A1T_GENERALIZED_TIME), %s, NULL }", poffset);
	break;
    case TUTCTime:
	add_line(temp, "{ A1_PARSE_T(A1T_UTC_TIME), %s, NULL }", poffset);
	break;
    case TBoolean:
	add_line(temp, "{ A1_PARSE_T(A1T_BOOLEAN), %s, NULL }", poffset);
	break;
    case TOID:
	add_line(temp, "{ A1_PARSE_T(A1T_OID), %s, NULL }", poffset);
	break;
    case TNull:
	break;
    case TBitString: {
	struct templatehead template;
	struct template *q;
	Member *m;
	size_t count = 0, i;
	char *bname = NULL;
	FILE *f = get_code_file();
	static unsigned long bmember_counter = 0;

	HEIM_TAILQ_INIT(&template);

	if (HEIM_TAILQ_EMPTY(t->members)) {
	    add_line(temp, "{ A1_PARSE_T(A1T_HEIM_BIT_STRING), %s, NULL }", poffset);
	    break;
	}

	if (asprintf(&bname, "bmember_%s_%lu", name ? name : "", bmember_counter++) < 0 || bname == NULL)
	    errx(1, "malloc");
	output_name(bname);

	HEIM_TAILQ_FOREACH(m, t->members, members) {
            if (m->val > UINT32_MAX)
                errx(1, "Cannot handle BIT STRING type %s with named bit %s "
                     "larger than 63", name, m->gen_name);
	    add_line(&template, "{ 0, %d, \"%s\" }", (int)m->val, m->gen_name);
	}

	HEIM_TAILQ_FOREACH(q, &template, members) {
	    count++;
	}

	fprintf(f, "static const struct asn1_template asn1_%s_%s[] = {\n", basetype, bname);
	fprintf(f, "/* 0 */ { 0%s, sizeof(%s), ((void *)(uintptr_t)%lu) },\n",
		rfc1510_bitstring ? "|A1_HBF_RFC1510" : "",
		basetype, (unsigned long)count);
	i = 1;
	HEIM_TAILQ_FOREACH(q, &template, members) {
	    int last = (HEIM_TAILQ_LAST(&template, templatehead) == q);
	    fprintf(f, "/* %lu */ %s%s\n", (unsigned long)i++, q->line, last ? "" : ",");
	}
	fprintf(f, "};\n");

	add_line(temp, "{ A1_OP_BMEMBER, %s, asn1_%s_%s }", poffset, basetype, bname);

	free(bname);

	break;
    }
    case TSet: {
        Member *opentypemember = NULL;
	Member *typeidmember = NULL;
        Field *opentypefield = NULL;
        Field *typeidfield = NULL;
	Member *m;
        struct decoration deco;
        ssize_t more_deco = -1;
        size_t i = 0, typeididx = 0, opentypeidx = 0;
        int is_array_of_open_type = 0;

        if (isstruct && t->actual_parameter)
            get_open_type_defn_fields(t, &typeidmember, &opentypemember,
                                      &typeidfield, &opentypefield,
                                      &is_array_of_open_type);

	fprintf(get_code_file(), "/* tset: members isstruct: %d */\n", isstruct);

	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    char *newbasename = NULL;

	    if (m->ellipsis)
		continue;

            if (typeidmember == m) typeididx = i;
            if (opentypemember == m) opentypeidx = i;

	    if (name) {
		if (asprintf(&newbasename, "%s_%s", basetype, name) < 0)
		    errx(1, "malloc");
	    } else
		newbasename = strdup(basetype);
	    if (newbasename == NULL)
		errx(1, "malloc");

            if (m->defval)
                defval(temp, m);

	    template_members(temp, newbasename, m->gen_name, m->type, m->optional, m->defval ? 1 : 0, 0, isstruct, 1);

	    free(newbasename);
            i++;
	}

        if (isstruct && t->actual_parameter)
            template_open_type(temp, basetype, t, typeididx, opentypeidx,
                               typeidfield, opentypefield, opentypemember,
                               is_array_of_open_type);

        while (decorate_type(basetype, &deco, &more_deco)) {
            char *poffset2;

            poffset2 = partial_offset(basetype, deco.field_name, 1, isstruct);

            if (deco.ext) {
                char *ptr = NULL;

                /* Decorated with external C type */
                if (asprintf(&ptr, "&asn1_extern_%s_%s",
                             basetype, deco.field_name) == -1 || ptr == NULL)
                    err(1, "out of memory");
                add_line_pointer(temp, ptr, poffset2,
                                 "A1_OP_TYPE_DECORATE_EXTERN %s",
                                 deco.opt ? "|A1_FLAG_OPTIONAL" : "");
                free(ptr);
            } else
                /* Decorated with a templated ASN.1 type */
                add_line_pointer(temp, deco.field_type, poffset2,
                                 "A1_OP_TYPE_DECORATE %s",
                                 deco.opt ? "|A1_FLAG_OPTIONAL" : "");
            free(poffset2);
            free(deco.field_type);
        }

        if (isstruct)
            template_names(temp, basetype, t);
	break;
    }
    case TSequence: {
        Member *opentypemember = NULL;
	Member *typeidmember = NULL;
        Field *opentypefield = NULL;
        Field *typeidfield = NULL;
	Member *m;
        struct decoration deco;
        ssize_t more_deco = -1;
        size_t i = 0, typeididx = 0, opentypeidx = 0;
        int is_array_of_open_type = 0;

        if (isstruct && t->actual_parameter)
            get_open_type_defn_fields(t, &typeidmember, &opentypemember,
                                      &typeidfield, &opentypefield,
                                      &is_array_of_open_type);

	fprintf(get_code_file(), "/* tsequence: members isstruct: %d */\n", isstruct);

	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    char *newbasename = NULL;

	    if (m->ellipsis)
		continue;

            if (typeidmember == m) typeididx = i;
            if (opentypemember == m) opentypeidx = i;

	    if (name) {
		if (asprintf(&newbasename, "%s_%s", basetype, name) < 0)
		    errx(1, "malloc");
	    } else
		newbasename = strdup(basetype);
	    if (newbasename == NULL)
		errx(1, "malloc");

            if (m->defval)
                defval(temp, m);
            
	    template_members(temp, newbasename, m->gen_name, m->type, m->optional, m->defval ? 1 : 0, 0, isstruct, 1);

	    free(newbasename);
            i++;
	}

        if (isstruct && t->actual_parameter)
            template_open_type(temp, basetype, t, typeididx, opentypeidx,
                               typeidfield, opentypefield, opentypemember,
                               is_array_of_open_type);

        while (decorate_type(basetype, &deco, &more_deco)) {
            char *poffset2;

            poffset2 = partial_offset(basetype, deco.field_name, 1, isstruct);

            if (deco.ext) {
                char *ptr = NULL;

                /* Decorated with external C type */
                if (asprintf(&ptr, "&asn1_extern_%s_%s",
                             basetype, deco.field_name) == -1 || ptr == NULL)
                    err(1, "out of memory");
                add_line_pointer(temp, ptr, poffset2,
                                 "A1_OP_TYPE_DECORATE_EXTERN %s",
                                 deco.opt ? "|A1_FLAG_OPTIONAL" : "");
                free(ptr);
            } else
                /* Decorated with a templated ASN.1 type */
                add_line_pointer(temp, deco.field_type, poffset2,
                                 "A1_OP_TYPE_DECORATE %s",
                                 deco.opt ? "|A1_FLAG_OPTIONAL" : "");
            free(poffset2);
            free(deco.field_type);
        }

        if (isstruct)
            template_names(temp, basetype, t);
	break;
    }
    case TTag: {
	char *tname = NULL, *elname = NULL;
	const char *sename, *dupname;
	int subtype_is_struct = is_struct(t->subtype, isstruct);
	static unsigned long tag_counter = 0;
	int tagimplicit = 0;
        int prim = !(t->tag.tagclass != ASN1_C_UNIV &&
                     t->tag.tagenv == TE_EXPLICIT) &&
            is_primitive_type(t->subtype);

        if (t->tag.tagenv == TE_IMPLICIT) {
            Type *t2 = t->subtype ? t->subtype : t->symbol->type;

            while (t2->type == TType && (t2->subtype || t2->symbol->type))
                t2 = t2->subtype ? t2->subtype : t2->symbol->type;
            if (t2->type != TChoice)
                tagimplicit = 1;
        }

	fprintf(get_code_file(), "/* template_members: %s %s %s */\n", basetype, implicit ? "imp" : "exp", tagimplicit ? "imp" : "exp");

	if (subtype_is_struct)
	    sename = basetype;
	else
	    sename = symbol_name(basetype, t->subtype);

	if (asprintf(&tname, "tag_%s_%lu", name ? name : "", tag_counter++) < 0 || tname == NULL)
	    errx(1, "malloc");
	output_name(tname);

	if (asprintf(&elname, "%s_%s", basetype, tname) < 0 || elname == NULL)
	    errx(1, "malloc");

	generate_template_type(elname, &dupname, NULL, sename, name,
			       t->subtype, 0, subtype_is_struct, 0);

	add_line_pointer(temp, dupname, poffset,
			 "A1_TAG_T(%s,%s,%s)%s%s%s",
			 classname(t->tag.tagclass),
			 prim  ? "PRIM" : "CONS",
			 valuename(t->tag.tagclass, t->tag.tagvalue),
			 optional    ? "|A1_FLAG_OPTIONAL" : "",
			 defaulted   ? "|A1_FLAG_DEFAULT" : "",
			 tagimplicit ? "|A1_FLAG_IMPLICIT" : "");

	free(tname);
	free(elname);

	break;
    }
    case TSetOf:
    case TSequenceOf: {
	const char *type = NULL, *tname, *dupname;
	char *sename = NULL, *elname = NULL;
	int subtype_is_struct = is_struct(t->subtype, 0);
	static unsigned long seof_counter = 0;

	if (name && subtype_is_struct) {
	    tname = "seofTstruct";
	    if (asprintf(&sename, "%s_%s_val", basetype, name) < 0)
		errx(1, "malloc");
	} else if (subtype_is_struct) {
	    tname = "seofTstruct";
	    if (asprintf(&sename, "%s_val", symbol_name(basetype, t->subtype)) < 0)
		errx(1, "malloc");
	} else {
	    if (name)
		tname = name;
	    else
		tname = "seofTstruct";
	    sename = strdup(symbol_name(basetype, t->subtype));
	}
	if (sename == NULL)
	    errx(1, "malloc");

	if (t->type == TSetOf) type = "A1_OP_SETOF";
	else if (t->type == TSequenceOf) type = "A1_OP_SEQOF";
	else abort();

	if (asprintf(&elname, "%s_%s_%lu", basetype, tname, seof_counter++) < 0 || elname == NULL)
	    errx(1, "malloc");

	generate_template_type(elname, &dupname, NULL, sename, NULL, t->subtype,
			       0, subtype_is_struct, need_offset);

	add_line(temp, "{ %s, %s, asn1_%s }", type, poffset, dupname);
	free(sename);
	break;
    }
    case TChoice: {
        struct decoration deco;
        ssize_t more_deco = -1;
	struct templatehead template;
	struct template *q;
	size_t count = 0, i;
	char *tname = NULL;
	FILE *f = get_code_file();
	Member *m;
	int ellipsis = 0;
	char *e;
	static unsigned long choice_counter = 0;

	HEIM_TAILQ_INIT(&template);

	if (asprintf(&tname, "asn1_choice_%s_%s%lu",
		     basetype, name ? name : "", choice_counter++) < 0 || tname == NULL)
	    errx(1, "malloc");

	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    const char *dupname;
	    char *elname = NULL;
	    char *newbasename = NULL;
	    int subtype_is_struct;

	    if (m->ellipsis) {
		ellipsis = 1;
		continue;
	    }

	    subtype_is_struct = is_struct(m->type, 0);

	    if (asprintf(&elname, "%s_choice_%s", basetype, m->gen_name) < 0 || elname == NULL)
		errx(1, "malloc");

	    if (subtype_is_struct) {
		if (asprintf(&newbasename, "%s_%s", basetype, m->gen_name) < 0)
		    errx(1, "malloc");
	    } else
		newbasename = strdup(basetype);

	    if (newbasename == NULL)
		errx(1, "malloc");


	    generate_template_type(elname, &dupname, NULL,
				   symbol_name(newbasename, m->type),
				   NULL, m->type, 0, subtype_is_struct, 1);

	    add_line(&template, "{ %s, offsetof(%s%s, u.%s), asn1_%s }",
		     m->label, isstruct ? "struct " : "",
		     basetype, m->gen_name,
		     dupname);

	    free(elname);
	    free(newbasename);
	}

	HEIM_TAILQ_FOREACH(m, t->members, members) {
            add_line(&template, "{ 0, 0, \"%s\" }", m->name);
        }

	e = NULL;
	if (ellipsis) {
	    if (asprintf(&e, "offsetof(%s%s, u.asn1_ellipsis)", isstruct ? "struct " : "", basetype) < 0 || e == NULL)
		errx(1, "malloc");
	}

	HEIM_TAILQ_FOREACH(q, &template, members) {
	    count++;
	}

	fprintf(f, "static const struct asn1_template %s[] = {\n", tname);
	fprintf(f, "/* 0 */ { %s, offsetof(%s%s, element), ((void *)(uintptr_t)%lu) },\n",
		e ? e : "0", isstruct ? "struct " : "", basetype, (unsigned long)count);
	i = 1;
	HEIM_TAILQ_FOREACH(q, &template, members) {
	    int last = (HEIM_TAILQ_LAST(&template, templatehead) == q);
	    fprintf(f, "/* %lu */ %s%s\n", (unsigned long)i++, q->line, last ? "" : ",");
	}
	fprintf(f, "};\n");

	add_line(temp, "{ A1_OP_CHOICE, %s, %s }", poffset, tname);

        while (decorate_type(basetype, &deco, &more_deco)) {
            char *poffset2;

            poffset2 = partial_offset(basetype, deco.field_name, 1, isstruct);

            if (deco.ext) {
                char *ptr = NULL;

                /* Decorated with external C type */
                if (asprintf(&ptr, "&asn1_extern_%s_%s",
                             basetype, deco.field_name) == -1 || ptr == NULL)
                    err(1, "out of memory");
                add_line_pointer(temp, ptr, poffset2,
                                 "A1_OP_TYPE_DECORATE_EXTERN %s",
                                 deco.opt ? "|A1_FLAG_OPTIONAL" : "");
                free(ptr);
            } else
                /* Decorated with a templated ASN.1 type */
                add_line_pointer(temp, deco.field_type, poffset2,
                                 "A1_OP_TYPE_DECORATE %s",
                                 deco.opt ? "|A1_FLAG_OPTIONAL" : "");
            free(poffset2);
            free(deco.field_type);
        }

	free(e);
	free(tname);
	break;
    }
    default:
	abort ();
    }
    if (poffset)
	free(poffset);
}

static void
gen_extern_stubs(FILE *f, const char *name)
{
    fprintf(f,
	    "static const struct asn1_type_func asn1_extern_%s = {\n"
	    "\t(asn1_type_encode)encode_%s,\n"
	    "\t(asn1_type_decode)decode_%s,\n"
	    "\t(asn1_type_length)length_%s,\n"
	    "\t(asn1_type_copy)copy_%s,\n"
	    "\t(asn1_type_release)free_%s,\n"
	    "\t(asn1_type_print)print_%s,\n"
	    "\tsizeof(%s)\n"
	    "};\n",
	    name, name, name, name,
	    name, name, name, name);
}

void
gen_template_import(const Symbol *s)
{
    FILE *f = get_code_file();

    if (template_flag == 0)
	return;

    gen_extern_stubs(f, s->gen_name);
}

void
generate_template_type_forward(const char *name)
{
    fprintf(get_code_file(), "extern const struct asn1_template asn1_%s[];\n", name);
}

void
generate_template_objectset_forwards(const Symbol *s)
{
    if (!template_flag)
        return;
    fprintf(get_code_file(), "extern const struct asn1_template asn1_%s[];\n",
            s->gen_name);
}

static void
generate_template_type(const char *varname,
		       const char **dupname,
		       const char *symname,
		       const char *basetype,
		       const char *name,
		       Type *type,
		       int optional,
                       int isstruct,
                       int need_offset)
{
    struct tlist *tl;
    const char *d;
    char *szt = NULL;
    int have_ellipsis = 0;
    int implicit = 0;
    int n;

    tl = tlist_new(varname);

    if (type->type == TTag && type->tag.tagenv == TE_IMPLICIT) {
        Type *t = type->subtype ? type->subtype : type->symbol->type;

        while (t->type == TType && (t->subtype || t->symbol->type))
            t = t->subtype ? t->subtype : t->symbol->type;
        if (t->type != TChoice)
            implicit = (type->tag.tagenv == TE_IMPLICIT);
    }

    template_members(&tl->template, basetype, name, type, optional, 0,
                     implicit, isstruct, need_offset);

    /* if its a sequence or set type, check if there is a ellipsis */
    if (type->type == TSequence || type->type == TSet) {
	Member *m;
	HEIM_TAILQ_FOREACH(m, type->members, members) {
	    if (m->ellipsis)
		have_ellipsis = 1;
	}
    }

    if (isstruct)
	if (name)
	    n = asprintf(&szt, "struct %s_%s", basetype, name);
	else
	    n = asprintf(&szt, "struct %s", basetype);
    else
	n = asprintf(&szt, "%s", basetype);
    if (n < 0 || szt == NULL)
	errx(1, "malloc");

    if (HEIM_TAILQ_EMPTY(&tl->template) && compact_tag(type)->type != TNull)
	errx(1, "Tag %s...%s with no content ?", basetype, name ? name : "");

    fprintf(get_code_file(), "/* generate_template_type: %s */\n", tl->name);

    tlist_header(tl, "{ 0%s%s, sizeof(%s), ((void *)(uintptr_t)%lu) }",
		 (symname && preserve_type(symname)) ? "|A1_HF_PRESERVE" : "",
		 have_ellipsis ? "|A1_HF_ELLIPSIS" : "", szt, tlist_count(tl));

    free(szt);

    /* XXX Accidentally O(N^2)? */
    d = tlist_find_dup(tl);
    if (d) {
#if 0
	if (strcmp(d, tl->name) == 0)
	    errx(1, "found dup of ourself: %s", d);
#endif
	*dupname = d;
    } else {
	*dupname = tl->name;
	tlist_print(tl);
	tlist_add(tl);
    }
}


void
generate_template(const Symbol *s)
{
    FILE *f = get_code_file();
    const char *dupname;
    struct decoration deco;
    ssize_t more_deco = -1;

    if (use_extern(s)) {
	gen_extern_stubs(f, s->gen_name);
	return;
    }

    while (decorate_type(s->gen_name, &deco, &more_deco)) {
        if (!deco.ext)
            continue;
        if (deco.void_star && deco.header_name)
	    fprintf(f, "#include %s\n", deco.header_name);
        fprintf(f,
                "static const struct asn1_type_func asn1_extern_%s_%s = {\n"
                "\t(asn1_type_encode)0,\n"
                "\t(asn1_type_decode)0,\n"
                "\t(asn1_type_length)0,\n"
                "\t(asn1_type_copy)%s,\n"
                "\t(asn1_type_release)%s,\n"
                "\t(asn1_type_print)0,\n"
                "\tsizeof(%s)\n"
                "};\n", s->gen_name, deco.field_name,
                deco.copy_function_name && deco.copy_function_name[0] ?
                deco.copy_function_name : "0",
                deco.free_function_name && deco.free_function_name[0] ?
                deco.free_function_name : "0",
                deco.void_star ? "void *" : deco.field_type);
        free(deco.field_type);
    }

    generate_template_type(s->gen_name, &dupname, s->name, s->gen_name, NULL, s->type, 0, 0, 1);

    fprintf(f,
	    "\n"
	    "int ASN1CALL\n"
	    "decode_%s(const unsigned char *p, size_t len, %s *data, size_t *size)\n"
	    "{\n"
            "    memset(data, 0, sizeof(*data));\n"
	    "    return _asn1_decode_top(asn1_%s, 0|%s, p, len, data, size);\n"
	    "}\n"
	    "\n",
	    s->gen_name,
	    s->gen_name,
	    dupname,
	    support_ber ? "A1_PF_ALLOW_BER" : "0");

    fprintf(f,
	    "\n"
	    "int ASN1CALL\n"
	    "encode_%s(unsigned char *p, size_t len, const %s *data, size_t *size)\n"
	    "{\n"
	    "    return _asn1_encode%s(asn1_%s, p, len, data, size);\n"
	    "}\n"
	    "\n",
	    s->gen_name,
	    s->gen_name,
	    fuzzer_string,
	    dupname);

    fprintf(f,
	    "\n"
	    "size_t ASN1CALL\n"
	    "length_%s(const %s *data)\n"
	    "{\n"
	    "    return _asn1_length%s(asn1_%s, data);\n"
	    "}\n"
	    "\n",
	    s->gen_name,
	    s->gen_name,
	    fuzzer_string,
	    dupname);


    fprintf(f,
	    "\n"
	    "void ASN1CALL\n"
	    "free_%s(%s *data)\n"
	    "{\n"
	    "    _asn1_free_top(asn1_%s, data);\n"
	    "}\n"
	    "\n",
	    s->gen_name,
	    s->gen_name,
	    dupname);

    fprintf(f,
	    "\n"
	    "int ASN1CALL\n"
	    "copy_%s(const %s *from, %s *to)\n"
	    "{\n"
	    "    return _asn1_copy_top(asn1_%s, from, to);\n"
	    "}\n"
	    "\n",
	    s->gen_name,
	    s->gen_name,
	    s->gen_name,
	    dupname);

    fprintf(f,
	    "\n"
	    "char * ASN1CALL\n"
	    "print_%s(const %s *data, int flags)\n"
	    "{\n"
	    "    return _asn1_print_top(asn1_%s, flags, data);\n"
	    "}\n"
	    "\n",
	    s->gen_name,
	    s->gen_name,
	    dupname);
}
