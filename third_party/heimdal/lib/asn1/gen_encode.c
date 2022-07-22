/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

/* XXX same as der_length_tag */
static size_t
length_tag(unsigned int tag)
{
    size_t len = 0;

    if(tag <= 30)
        return 1;
    while(tag) {
        tag /= 128;
        len++;
    }
    return len + 1;
}

static void
encode_primitive (const char *typename, const char *name)
{
    fprintf (codefile,
	     "e = der_put_%s(p, len, %s, &l);\n"
	     "if (e) return e;\np -= l; len -= l; ret += l;\n\n",
	     typename,
	     name);
}

const char *
classname(Der_class class)
{
    const char *cn[] = { "ASN1_C_UNIV", "ASN1_C_APPL",
			 "ASN1_C_CONTEXT", "ASN1_C_PRIV" };
    if ((int)class >= sizeof(cn) / sizeof(cn[0]))
	return "???";
    return cn[class];
}


const char *
valuename(Der_class class, int value)
{
    static char s[32];
    struct {
	int value;
	const char *s;
    } *p, values[] = {
#define X(Y) { Y, #Y }
	X(UT_BMPString),
	X(UT_BitString),
	X(UT_Boolean),
	X(UT_EmbeddedPDV),
	X(UT_Enumerated),
	X(UT_External),
	X(UT_GeneralString),
	X(UT_GeneralizedTime),
	X(UT_GraphicString),
	X(UT_IA5String),
	X(UT_Integer),
	X(UT_Null),
	X(UT_NumericString),
	X(UT_OID),
	X(UT_ObjectDescriptor),
	X(UT_OctetString),
	X(UT_PrintableString),
	X(UT_Real),
	X(UT_RelativeOID),
	X(UT_Sequence),
	X(UT_Set),
	X(UT_TeletexString),
	X(UT_UTCTime),
	X(UT_UTF8String),
	X(UT_UniversalString),
	X(UT_VideotexString),
	X(UT_VisibleString),
#undef X
	{ -1, NULL }
    };
    if(class == ASN1_C_UNIV) {
	for(p = values; p->value != -1; p++)
	    if(p->value == value)
		return p->s;
    }
    snprintf(s, sizeof(s), "%d", value);
    return s;
}

static int
encode_type (const char *name, const Type *t, const char *tmpstr)
{
    int constructed = 1;

    switch (t->type) {
    case TType:
#if 0
	encode_type (name, t->symbol->type);
#endif
	fprintf (codefile,
		 "e = encode_%s(p, len, %s, &l);\n"
		 "if (e) return e;\np -= l; len -= l; ret += l;\n\n",
		 t->symbol->gen_name, name);
        constructed = !is_primitive_type(t);
	break;
    case TInteger:
	if(t->members) {
	    fprintf(codefile,
		    "{\n"
		    "int enumint = (int)*%s;\n",
		    name);
	    encode_primitive("integer", "&enumint");
	    fprintf(codefile, "}\n;");
	} else if (t->range == NULL) {
	    encode_primitive("heim_integer", name);
	} else if (t->range->min < 0 &&
                   (t->range->min < INT_MIN || t->range->max > INT_MAX)) {
            encode_primitive("integer64", name);
	} else if (t->range->min < 0) {
            encode_primitive("integer", name);
	} else if (t->range->max > UINT_MAX) {
	    encode_primitive("unsigned64", name);
	} else {
	    encode_primitive("unsigned", name);
	}

	constructed = 0;
	break;
    case TBoolean:
	encode_primitive ("boolean", name);
	constructed = 0;
	break;
    case TOctetString:
	encode_primitive ("octet_string", name);
	constructed = 0;
	break;
    case TBitString: {
	Member *m;
	int pos;

	if (HEIM_TAILQ_EMPTY(t->members)) {
	    encode_primitive("bit_string", name);
	    constructed = 0;
	    break;
	}

	fprintf (codefile, "{\n"
		 "unsigned char c = 0;\n");
	if (!rfc1510_bitstring)
	    fprintf (codefile,
		     "int rest = 0;\n"
		     "int bit_set = 0;\n");
#if 0
	pos = t->members->prev->val;
	/* fix for buggy MIT (and OSF?) code */
	if (pos > 31)
	    abort ();
#endif
	/*
	 * It seems that if we do not always set pos to 31 here, the MIT
	 * code will do the wrong thing.
	 *
	 * I hate ASN.1 (and DER), but I hate it even more when everybody
	 * has to screw it up differently.
	 */
	pos = HEIM_TAILQ_LAST(t->members, memhead)->val;
	if (rfc1510_bitstring) {
	    if (pos < 31)
		pos = 31;
	}

	HEIM_TAILQ_FOREACH_REVERSE(m, t->members, memhead, members) {
	    while (m->val / 8 < pos / 8) {
		if (!rfc1510_bitstring)
		    fprintf (codefile,
			     "if (c != 0 || bit_set) {\n");
		fprintf (codefile,
			 "if (len < 1) return ASN1_OVERFLOW;\n"
			 "*p-- = c; len--; ret++;\n");
		if (!rfc1510_bitstring)
		    fprintf (codefile,
			     "if (!bit_set) {\n"
			     "rest = 0;\n"
			     "while(c) { \n"
			     "if (c & 1) break;\n"
			     "c = c >> 1;\n"
			     "rest++;\n"
			     "}\n"
			     "bit_set = 1;\n"
			     "}\n"
			     "}\n");
		fprintf (codefile,
			 "c = 0;\n");
		pos -= 8;
	    }
	    fprintf (codefile,
		     "if((%s)->%s) {\n"
		     "c |= 1<<%d;\n",
		     name, m->gen_name, (int)(7 - m->val % 8));
	    fprintf (codefile,
		     "}\n");
	}

	if (!rfc1510_bitstring)
	    fprintf (codefile,
		     "if (c != 0 || bit_set) {\n");
	fprintf (codefile,
		 "if (len < 1) return ASN1_OVERFLOW;\n"
		 "*p-- = c; len--; ret++;\n");
	if (!rfc1510_bitstring)
	    fprintf (codefile,
		     "if (!bit_set) {\n"
		     "rest = 0;\n"
		     "if(c) { \n"
		     "while(c) { \n"
		     "if (c & 1) break;\n"
		     "c = c >> 1;\n"
		     "rest++;\n"
		     "}\n"
		     "}\n"
		     "}\n"
		     "}\n");

	fprintf (codefile,
		 "if (len < 1) return ASN1_OVERFLOW;\n"
		 "*p-- = %s;\n"
		 "len -= 1;\n"
		 "ret += 1;\n"
		 "}\n\n",
		 rfc1510_bitstring ? "0" : "rest");
	constructed = 0;
	break;
    }
    case TEnumerated : {
	encode_primitive ("enumerated", name);
	constructed = 0;
	break;
    }

    case TSet:
    case TSequence: {
	Member *m;

	if (t->members == NULL)
	    break;

	HEIM_TAILQ_FOREACH_REVERSE(m, t->members, memhead, members) {
	    char *s = NULL;

	    if (m->ellipsis)
		continue;

	    if (asprintf (&s, "%s(%s)->%s", m->optional ? "" : "&", name, m->gen_name) < 0 || s == NULL)
		errx(1, "malloc");
	    fprintf(codefile, "/* %s */\n", m->name);
	    if (m->optional)
		fprintf (codefile,
			 "if(%s) ",
			 s);
	    else if(m->defval)
		gen_compare_defval(s + 1, m->defval);
	    fprintf (codefile, "{\n");
	    fprintf (codefile, "size_t %s_oldret HEIMDAL_UNUSED_ATTRIBUTE = ret;\n", tmpstr);
	    fprintf (codefile, "ret = 0;\n");
	    encode_type (s, m->type, m->gen_name);
	    fprintf (codefile, "ret += %s_oldret;\n", tmpstr);
	    fprintf (codefile, "}\n");
	    free (s);
	}
	break;
    }
    case TSetOf: {

	fprintf(codefile,
		"{\n"
		"heim_octet_string *val;\n"
		"size_t elen = 0, totallen = 0;\n"
		"int eret = 0;\n");

	fprintf(codefile,
		"if ((%s)->len > UINT_MAX/sizeof(val[0]))\n"
		"return ERANGE;\n",
		name);

	fprintf(codefile,
		"val = calloc(1, sizeof(val[0]) * (%s)->len);\n"
		"if (val == NULL && (%s)->len != 0) return ENOMEM;\n",
		name, name);

	fprintf(codefile,
		"for(i = 0; i < (int)(%s)->len; i++) {\n",
		name);

	fprintf(codefile,
		"ASN1_MALLOC_ENCODE(%s, val[i].data, "
		"val[i].length, &(%s)->val[i], &elen, eret);\n",
		t->subtype->symbol->gen_name,
		name);

	fprintf(codefile,
		"if(eret) {\n"
		"i--;\n"
		"while (i >= 0) {\n"
		"free(val[i].data);\n"
		"i--;\n"
		"}\n"
		"free(val);\n"
		"return eret;\n"
		"}\n"
		"totallen += elen;\n"
		"}\n");

	fprintf(codefile,
		"if (totallen > len) {\n"
		"for (i = 0; i < (int)(%s)->len; i++) {\n"
		"free(val[i].data);\n"
		"}\n"
		"free(val);\n"
		"return ASN1_OVERFLOW;\n"
		"}\n",
		name);

	fprintf(codefile,
		"qsort(val, (%s)->len, sizeof(val[0]), _heim_der_set_sort);\n",
		name);

	fprintf (codefile,
		 "for(i = (int)(%s)->len - 1; i >= 0; --i) {\n"
		 "p -= val[i].length;\n"
		 "ret += val[i].length;\n"
		 "memcpy(p + 1, val[i].data, val[i].length);\n"
		 "free(val[i].data);\n"
		 "}\n"
		 "free(val);\n"
		 "}\n",
		 name);
	break;
    }
    case TSequenceOf: {
	char *sname = NULL;
	char *n = NULL;

	fprintf (codefile,
		 "for(i = (int)(%s)->len - 1; i >= 0; --i) {\n"
		 "size_t %s_for_oldret = ret;\n"
		 "ret = 0;\n",
		 name, tmpstr);
	if (asprintf (&n, "&(%s)->val[i]", name) < 0 || n == NULL)
	    errx(1, "malloc");
	if (asprintf (&sname, "%s_S_Of", tmpstr) < 0 || sname == NULL)
	    errx(1, "malloc");
	encode_type (n, t->subtype, sname);
	fprintf (codefile,
		 "ret += %s_for_oldret;\n"
		 "}\n",
		 tmpstr);
	free (n);
	free (sname);
	break;
    }
    case TGeneralizedTime:
	encode_primitive ("generalized_time", name);
	constructed = 0;
	break;
    case TGeneralString:
	encode_primitive ("general_string", name);
	constructed = 0;
	break;
    case TTeletexString:
	encode_primitive ("general_string", name);
	constructed = 0;
	break;
    case TTag: {
    	char *tname = NULL;
        int replace_tag = 0;
        int prim = !(t->tag.tagclass != ASN1_C_UNIV &&
                     t->tag.tagenv == TE_EXPLICIT) &&
            is_primitive_type(t->subtype);
	int c;
	if (asprintf (&tname, "%s_tag", tmpstr) < 0 || tname == NULL)
	    errx(1, "malloc");
        /*
         * HACK HACK HACK
         *
         * This is part of the fix to the bug where we treated IMPLICIT tags of
         * named types as EXPLICIT.  I.e.
         *
         *  Foo ::= SEQUENCE { ... }
         *  Bar ::= SEQUENCE { foo [0] IMPLICIT Foo }
         *
         * would get a context [0] constructed tag *and* a universal sequence
         * constructed tag when it should get only the first tag.
         *
         * Properly fixing this would require changing the signatures of the
         * encode, length, and decode functions we generate to take an optional
         * tag to replace the one the encoder would generate / decoder would
         * expect.  That would change the ABI, which... isn't stable, but it's
         * a bit soon to make that change.
         *
         * So, we're looking for IMPLICIT, and if we see any, we generate code
         * to replace the tag.
         *
         * On the decode side we need to know what tag to restore.  For this we
         * generate enums in the generated header.
         *
         * NOTE: We *do* "replace" the tags of IMPLICIT-tagged primitive types,
         *       but our primitive codec functions leave those tags out, which
         *       is why we don't have to der_replace_tag() them here.
         */
        /*
         * If the tag is IMPLICIT and it's not primitive and the subtype is not
         * any kind of structure...
         */
        if (t->tag.tagenv == TE_IMPLICIT && !prim &&
            t->subtype->type != TSequenceOf && t->subtype->type != TSetOf &&
            t->subtype->type != TChoice) {
            /* If it is a named type for a structured thing */
            if (t->subtype->symbol &&
                (t->subtype->type == TSequence ||
                 t->subtype->type == TSet))
                replace_tag = 1;
            else if (t->subtype->symbol && strcmp(t->subtype->symbol->name, "heim_any"))
                replace_tag = 1;
        } else if (t->tag.tagenv == TE_IMPLICIT && prim && t->subtype->symbol)
            /*
             * Because the subtype is named we are generating its codec
             * functions, and those will be adding their UNIVERSAL or whatever
             * tags unlike our raw primtive codec library.
             */
            replace_tag = is_tagged_type(t->subtype->symbol->type);

        if (replace_tag)
            fprintf(codefile,
                    "{ unsigned char *psave_%s = p, *pfree_%s = NULL;\n"
                    "size_t l2_%s, lensave_%s = len;\n"
                    "len = length_%s(%s);\n"
                    /* Allocate a temp buffer for the encoder */
                    "if ((p = pfree_%s = calloc(1, len)) == NULL) return ENOMEM;\n"
                    /* Make p point to the last byte of the allocated buf */
                    "p += len - 1;\n",
                    tmpstr, tmpstr, tmpstr, tmpstr,
                    t->subtype->symbol->gen_name, name, tmpstr);

        /* XXX Currently we generate code that leaks `pfree_%s` here.  */
	c = encode_type (name, t->subtype, tname);
        /* Explicit non-UNIVERSAL tags are always constructed */
        if (!c && t->tag.tagclass != ASN1_C_UNIV && t->tag.tagenv == TE_EXPLICIT)
            c = 1;
        if (replace_tag)
            fprintf(codefile,
                    "if (len) { free(pfree_%s); return EINVAL; }\n"
                    /*
                     * Here we have `p' pointing to one byte before the buffer
                     * we allocated above.
                     *
                     *     [ T_wrong | LL | VVVV ] // temp buffer
                     *   ^   ^
                     *   |   |
                     *   |   \
                     *   \    +-- p + 1
                     *    +-- p
                     *
                     * psave_<fieldName> still points to the last byte in the
                     * original buffer passed in where we should write the
                     * encoding of <fieldName>.
                     *
                     * We adjust psave_<fieldName> to point to before the TLV
                     * encoding of <fieldName> (with wrong tag) in the original
                     * buffer (this may NOT be a valid pointer, but we won't
                     * dereference it):
                     *
                     * [ ... | T_wrong | LL | VVVVV | ... ] // original buffer
                     *      ^
                     *      |
                     *      \
                     *       +-- psave_<fieldName>
                     */
                    "psave_%s -= l;\n"
                    /*
                     * We further adjust psave_<fieldName> to point to the last
                     * byte of what should be the T(ag) of the TLV encoding of
                     * <fieldName> (this is now a valid pointer), then...
                     *
                     *         |<--->| (not written yet)
                     *         |     | |<-------->| (not written yet)
                     * [ ... | T_right | LL | VVVVV | ... ] // original buffer
                     *                ^
                     *                |
                     *                \
                     *                 +-- psave_<fieldName>
                     */
                    "psave_%s += asn1_tag_length_%s;\n"
                    /*
                     * ...copy the L(ength)V(alue) of the TLV encoding of
                     * <fieldName>.
                     *
                     * [ ... | T_right | LL | VVVVV | ... ] // original buffer
                     *                   ^
                     *                   |
                     *                   \
                     *                    +-- psave_<fieldName> + 1
                     *
                     *             |<----->| length is
                     *             |       | `l' - asn1_tag_length_<fieldName>
                     * [ T_wrong | LL | VVVV ] // temp buffer
                     *   ^         ^
                     *   |         |
                     *   |         \
                     *   \          +-- p + 1 + asn1_tag_length_%s
                     *    +-- p + 1
                     */
                    "memcpy(psave_%s + 1, p + 1 + asn1_tag_length_%s, l - asn1_tag_length_%s);\n"
                    /*
                     * Encode the IMPLICIT tag.  Recall that encoders like
                     * der_put_tag() take a pointer to the last byte they
                     * should write to, and a length of bytes to the left of
                     * that that they are allowed to write into.
                     *
                     * [ ... | T_right | LL | VVVVV | ... ] // original buffer
                     *                ^
                     *                |
                     *                \
                     *                 +-- psave_<fieldName>
                     */
                    "e = der_put_tag(psave_%s, %zu, %s, %s, %d, &l2_%s);\n"
                    "if (e) { free(pfree_%s); return e; }\n"
                    /* Restore `len' and adjust it (see `p' below) */
                    "len = lensave_%s - (l + %zu - asn1_tag_length_%s);\n"
                    /*
                     * Adjust `ret' to account for the difference in size
                     * between the length of the right and wrong tags.
                     */
                    "ret += %zu - asn1_tag_length_%s;\n"
                    /* Free the buffer and restore `p' */
                    "free(pfree_%s);\n"
                    /*
                     * Make `p' point into the original buffer again, to one
                     * byte before the bytes we wrote:
                     *
                     * [ ... | T_right | LL | VVVVV | ... ] // original buffer
                     *      ^
                     *      |
                     *      \
                     *       +-- p
                     */
                    "p = psave_%s - (1 + %zu - asn1_tag_length_%s); }\n",
                    tmpstr, tmpstr, tmpstr, t->subtype->symbol->name,
                    tmpstr, t->subtype->symbol->name, t->subtype->symbol->name,
                    tmpstr, length_tag(t->tag.tagvalue),
                    classname(t->tag.tagclass),
                    c ? "CONS" : "PRIM",
                    t->tag.tagvalue,
                    tmpstr,

                    tmpstr, tmpstr, length_tag(t->tag.tagvalue), t->subtype->symbol->name,
                    length_tag(t->tag.tagvalue), t->subtype->symbol->name,
                    tmpstr, tmpstr, length_tag(t->tag.tagvalue), t->subtype->symbol->name);
        else
            fprintf(codefile,
                    "e = der_put_length_and_tag (p, len, ret, %s, %s, %s, &l);\n"
                    "if (e) return e;\np -= l; len -= l; ret += l;\n\n",
                    classname(t->tag.tagclass),
                    c ? "CONS" : "PRIM",
                    valuename(t->tag.tagclass, t->tag.tagvalue));
	free(tname);
        constructed = c;
	break;
    }
    case TChoice:{
	Member *m, *have_ellipsis = NULL;
	char *s = NULL;

	if (t->members == NULL)
	    break;

	fprintf(codefile, "\n");

	if (asprintf (&s, "(%s)", name) < 0 || s == NULL)
	    errx(1, "malloc");
	fprintf(codefile, "switch(%s->element) {\n", s);

	HEIM_TAILQ_FOREACH_REVERSE(m, t->members, memhead, members) {
	    char *s2 = NULL;

	    if (m->ellipsis) {
		have_ellipsis = m;
		continue;
	    }

	    fprintf (codefile, "case %s: {", m->label);
	    if (asprintf(&s2, "%s(%s)->u.%s", m->optional ? "" : "&",
			 s, m->gen_name) < 0 || s2 == NULL)
		errx(1, "malloc");
	    if (m->optional)
		fprintf (codefile, "if(%s) {\n", s2);
	    fprintf (codefile, "size_t %s_oldret = ret;\n", tmpstr);
	    fprintf (codefile, "ret = 0;\n");
	    constructed = encode_type (s2, m->type, m->gen_name);
	    fprintf (codefile, "ret += %s_oldret;\n", tmpstr);
	    if(m->optional)
		fprintf (codefile, "}\n");
	    fprintf(codefile, "break;\n");
	    fprintf(codefile, "}\n");
	    free (s2);
	}
	free (s);
	if (have_ellipsis) {
	    fprintf(codefile,
		    "case %s: {\n"
		    "if (len < (%s)->u.%s.length)\n"
		    "return ASN1_OVERFLOW;\n"
		    "p -= (%s)->u.%s.length;\n"
		    "ret += (%s)->u.%s.length;\n"
		    "memcpy(p + 1, (%s)->u.%s.data, (%s)->u.%s.length);\n"
		    "break;\n"
		    "}\n",
		    have_ellipsis->label,
		    name, have_ellipsis->gen_name,
		    name, have_ellipsis->gen_name,
		    name, have_ellipsis->gen_name,
		    name, have_ellipsis->gen_name,
		    name, have_ellipsis->gen_name);
	}
	fprintf(codefile, "};\n");
	break;
    }
    case TOID:
	encode_primitive ("oid", name);
	constructed = 0;
	break;
    case TUTCTime:
	encode_primitive ("utctime", name);
	constructed = 0;
	break;
    case TUTF8String:
	encode_primitive ("utf8string", name);
	constructed = 0;
	break;
    case TPrintableString:
	encode_primitive ("printable_string", name);
	constructed = 0;
	break;
    case TIA5String:
	encode_primitive ("ia5_string", name);
	constructed = 0;
	break;
    case TBMPString:
	encode_primitive ("bmp_string", name);
	constructed = 0;
	break;
    case TUniversalString:
	encode_primitive ("universal_string", name);
	constructed = 0;
	break;
    case TVisibleString:
	encode_primitive ("visible_string", name);
	constructed = 0;
	break;
    case TNull:
	fprintf (codefile, "/* NULL */\n");
	constructed = 0;
	break;
    default:
	abort ();
    }
    return constructed;
}

void
generate_type_encode (const Symbol *s)
{
    fprintf (codefile, "int ASN1CALL\n"
	     "encode_%s(unsigned char *p HEIMDAL_UNUSED_ATTRIBUTE, size_t len HEIMDAL_UNUSED_ATTRIBUTE,"
	     " const %s *data, size_t *size)\n"
	     "{\n",
	     s->gen_name, s->gen_name);

    switch (s->type->type) {
    case TInteger:
    case TBoolean:
    case TOctetString:
    case TGeneralizedTime:
    case TGeneralString:
    case TTeletexString:
    case TUTCTime:
    case TUTF8String:
    case TPrintableString:
    case TIA5String:
    case TBMPString:
    case TUniversalString:
    case TVisibleString:
    case TNull:
    case TBitString:
    case TEnumerated:
    case TOID:
    case TSequence:
    case TSequenceOf:
    case TSet:
    case TSetOf:
    case TTag:
    case TType:
    case TChoice:
	fprintf (codefile,
		 "size_t ret HEIMDAL_UNUSED_ATTRIBUTE = 0;\n"
		 "size_t l HEIMDAL_UNUSED_ATTRIBUTE;\n"
		 "int i HEIMDAL_UNUSED_ATTRIBUTE, e HEIMDAL_UNUSED_ATTRIBUTE;\n\n");

	encode_type("data", s->type, "Top");

	fprintf (codefile, "*size = ret;\n"
		 "return 0;\n");
	break;
    default:
	abort ();
    }
    fprintf (codefile, "}\n\n");
}
