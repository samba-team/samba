/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include "baselocl.h"
#include <ctype.h>
#include <base64.h>

#ifndef WIN32
#include <langinfo.h>
#endif

static heim_base_once_t heim_json_once = HEIM_BASE_ONCE_INIT;
static heim_string_t heim_tid_data_uuid_key = NULL;

static void
json_init_once(void *arg)
{
    heim_tid_data_uuid_key = __heim_string_constant("heimdal-type-data-76d7fca2-d0da-4b20-a126-1a10f8a0eae6");
}

struct twojson {
    void *ctx;
    void (*out)(void *, const char *);
    size_t indent;
    heim_json_flags_t flags;
    int ret;
    int first;
};

struct heim_strbuf {
    char *str;
    size_t len;
    size_t alloced;
    int	enomem;
    heim_json_flags_t flags;
};

static int
base2json(heim_object_t, struct twojson *, int);

static void
indent(struct twojson *j)
{
    size_t i = j->indent;
    if (j->flags & HEIM_JSON_F_ONE_LINE)
	return;
    if (j->flags & HEIM_JSON_F_INDENT2)
        while (i--)
            j->out(j->ctx, "  ");
    else if (j->flags & HEIM_JSON_F_INDENT4)
        while (i--)
            j->out(j->ctx, "    ");
    else if (j->flags & HEIM_JSON_F_INDENT8)
        while (i--)
            j->out(j->ctx, "        ");
    else
        while (i--)
            j->out(j->ctx, "\t");
}

static void
array2json(heim_object_t value, void *ctx, int *stop)
{
    struct twojson *j = ctx;
    if (j->ret)
	return;
    if (j->first) {
	j->first = 0;
    } else {
	j->out(j->ctx, NULL); /* eat previous '\n' if possible */
	j->out(j->ctx, ",\n");
    }
    j->ret = base2json(value, j, 0);
}

static void
dict2json(heim_object_t key, heim_object_t value, void *ctx)
{
    struct twojson *j = ctx;
    if (j->ret)
	return;
    if (j->first) {
	j->first = 0;
    } else {
	j->out(j->ctx, NULL); /* eat previous '\n' if possible */
	j->out(j->ctx, ",\n");
    }
    j->ret = base2json(key, j, 0);
    if (j->ret)
	return;
    switch (heim_get_tid(value)) {
    case HEIM_TID_ARRAY:
    case HEIM_TID_DICT:
    case HEIM_TID_DATA:
        j->out(j->ctx, ":\n");
        j->indent++;
        j->ret = base2json(value, j, 0);
        if (j->ret)
            return;
        j->indent--;
        break;
    default:
        j->out(j->ctx, ": ");
        j->ret = base2json(value, j, 1);
        break;
    }
}

#ifndef WIN32
static void
init_is_utf8(void *ptr)
{
    *(int *)ptr = strcasecmp("utf-8", nl_langinfo(CODESET)) == 0;
}
#endif

int
heim_locale_is_utf8(void)
{
#ifdef WIN32
    return 0; /* XXX Implement */
#else
    static int locale_is_utf8 = -1;
    static heim_base_once_t once = HEIM_BASE_ONCE_INIT;

    heim_base_once_f(&once, &locale_is_utf8, init_is_utf8);
    return locale_is_utf8;
#endif
}

static void
out_escaped_bmp(struct twojson *j, const unsigned char *p, int nbytes)
{
    unsigned char e[sizeof("\\u0000")];
    unsigned codepoint;

    if (nbytes == 2)
        codepoint = ((p[0] & 0x1f) << 6) | (p[1] & 0x3f);
    else if (nbytes == 3)
        codepoint = ((p[0] & 0x0f) << 12) | ((p[1] & 0x3f) << 6) | (p[2] & 0x3f);
    else
        abort();
    e[0]  = '\\';
    e[1]  = 'u';
    e[2]  = codepoint >> 12;
    e[2] += (e[2] < 10) ? '0' : ('A' - 10);
    e[3]  = (codepoint >> 8) & 0x0f;
    e[3] += (e[3] < 10) ? '0' : ('A' - 10);
    e[4]  = (codepoint >> 4) & 0x0f;
    e[4] += (e[4] < 10) ? '0' : ('A' - 10);
    e[5]  =  codepoint       & 0x0f;
    e[5] += (e[5] < 10) ? '0' : ('A' - 10);
    e[6]  = '\0';
    j->out(j->ctx, (char *)e);
}

static int
base2json(heim_object_t obj, struct twojson *j, int skip_indent)
{
    heim_tid_t type;
    int first = 0;

    if (obj == NULL) {
	if (j->flags & HEIM_JSON_F_CNULL2JSNULL) {
	    obj = heim_null_create();
	} else if (j->flags & HEIM_JSON_F_NO_C_NULL) {
	    return EINVAL;
	} else {
	    indent(j);
	    j->out(j->ctx, "<NULL>\n"); /* This is NOT valid JSON! */
	    return 0;
	}
    }

    type = heim_get_tid(obj);
    switch (type) {
    case HEIM_TID_ARRAY:
	indent(j);
	j->out(j->ctx, "[\n");
	j->indent++;
	first = j->first;
	j->first = 1;
	heim_array_iterate_f(obj, j, array2json);
	j->indent--;
	if (!j->first)
	    j->out(j->ctx, "\n");
	indent(j);
	j->out(j->ctx, "]\n");
	j->first = first;
	break;

    case HEIM_TID_DICT:
	indent(j);
	j->out(j->ctx, "{\n");
	j->indent++;
	first = j->first;
	j->first = 1;
	heim_dict_iterate_f(obj, j, dict2json);
	j->indent--;
	if (!j->first)
	    j->out(j->ctx, "\n");
	indent(j);
	j->out(j->ctx, "}\n");
	j->first = first;
	break;

    case HEIM_TID_STRING: {
	const unsigned char *s = (const unsigned char *)heim_string_get_utf8(obj);
	const unsigned char *p;
        unsigned int c, cp, ctop, cbot;
        char e[sizeof("\\u0123\\u3210")];
        int good;
        size_t i;

        if (!skip_indent)
            indent(j);
	j->out(j->ctx, "\"");
        for (p = s; (c = *p); p++) {
            switch (c) {
            /* ASCII control characters w/ C-like escapes */
            case '\b': j->out(j->ctx, "\\b");  continue;
            case '\f': j->out(j->ctx, "\\f");  continue;
            case '\n': j->out(j->ctx, "\\n");  continue;
            case '\r': j->out(j->ctx, "\\r");  continue;
            case '\t': j->out(j->ctx, "\\t");  continue;
            /* Other must-escape non-control ASCII characters */
            case '"':  j->out(j->ctx, "\\\""); continue;
            case '\\': j->out(j->ctx, "\\\\"); continue;
            default: break;
            }

            /*
             * JSON string encoding is... complex.
             *
             * Invalid UTF-8 w/  HEIM_JSON_F_STRICT_STRINGS set -> return 1
             *
             * Invalid UTF-8 w/o HEIM_JSON_F_STRICT_STRINGS set -> pass
             * through, a sort of Heimdal WTF-8, but not _the_ WTF-8.
             */
            if (c < 0x20) {
                /* ASCII control character w/o C-like escape */
                e[0] = '\\';
                e[1] = 'u';
                e[2] = '0';
                e[3] = '0';
                e[4] = "0123456789ABCDEF"[c>>4];
                e[5] = "0123456789ABCDEF"[c & 0x0f];
                e[6] = '\0';
                j->out(j->ctx, e);
                continue;
            }
            if (c < 0x80) {
                /* ASCII */
                e[0] = c;
                e[1] = '\0';
                j->out(j->ctx, e);
                continue;
            }
            if ((c & 0xc0) == 0x80) {
                /* UTF-8 bare non-leading byte */
                if (!(j->flags & HEIM_JSON_F_STRICT_STRINGS)) {
                    e[0] = c;
                    e[1] = '\0';
                    j->out(j->ctx, e);
                    continue;
                }
                return 1;
            }
            if ((c & 0xe0) == 0xc0) {
                /* UTF-8 leading byte of two-byte sequence */
                good = 1;
                for (i = 1; i < 2 && good && p[i]; i++) {
                    if ((p[i] & 0xc0) != 0x80)
                        good = 0;
                }
                if (i != 2)
                    good = 0;
                if (!good && !(j->flags & HEIM_JSON_F_STRICT_STRINGS)) {
                    e[0] = c;
                    e[1] = '\0';
                    j->out(j->ctx, e);
                    continue;
                } else if (!good) {
                    return 1;
                }
                if (j->flags & HEIM_JSON_F_ESCAPE_NON_ASCII) {
                    out_escaped_bmp(j, p, 2);
                    p += 1;
                    continue;
                }
                e[0] = c;
                e[1] = p[1];
                e[2] = '\0';
                j->out(j->ctx, e);
                p += 1;
                continue;
            }
            if ((c & 0xf0) == 0xe0) {
                /* UTF-8 leading byte of three-byte sequence */
                good = 1;
                for (i = 1; i < 3 && good && p[i]; i++) {
                    if ((p[i] & 0xc0) != 0x80)
                        good = 0;
                }
                if (i != 3)
                    good = 0;
                if (!good && !(j->flags & HEIM_JSON_F_STRICT_STRINGS)) {
                    e[0] = c;
                    e[1] = '\0';
                    j->out(j->ctx, e);
                    continue;
                } else if (!good) {
                    return 1;
                }
                if (j->flags & HEIM_JSON_F_ESCAPE_NON_ASCII) {
                    out_escaped_bmp(j, p, 3);
                    p += 2;
                    continue;
                }
                e[0] = c;
                e[1] = p[1];
                e[2] = p[2];
                e[3] = '\0';
                j->out(j->ctx, e);
                p += 2;
                continue;
            }

            if (c > 0xf7) {
                /* Invalid UTF-8 leading byte */
                if (!(j->flags & HEIM_JSON_F_STRICT_STRINGS)) {
                    e[0] = c;
                    e[1] = '\0';
                    j->out(j->ctx, e);
                    continue;
                }
                return 1;
            }

            /*
             * A codepoint > U+FFFF, needs encoding a la UTF-16 surrogate
             * pair because JSON takes after JS which uses UTF-16.  Ugly.
             */
            cp = c & 0x7;
            good = 1;
            for (i = 1; i < 4 && good && p[i]; i++) {
                if ((p[i] & 0xc0) == 0x80)
                    cp = (cp << 6) | (p[i] & 0x3f);
                else
                    good = 0;
            }
            if (i != 4)
                good = 0;
            if (!good && !(j->flags & HEIM_JSON_F_STRICT_STRINGS)) {
                e[0] = c;
                e[1] = '\0';
                j->out(j->ctx, e);
                continue;
            } else if (!good) {
                return 1;
            }
            p += 3;

            cp -= 0x10000;
            ctop = 0xD800 + (cp >>   10);
            cbot = 0xDC00 + (cp & 0x3ff);

            e[0 ] = '\\';
            e[1 ] = 'u';
            e[2 ] = "0123456789ABCDEF"[(ctop         ) >> 12];
            e[3 ] = "0123456789ABCDEF"[(ctop & 0x0f00) >>  8];
            e[4 ] = "0123456789ABCDEF"[(ctop & 0x00f0) >>  4];
            e[5 ] = "0123456789ABCDEF"[(ctop & 0x000f)      ];
            e[6 ] = '\\';
            e[7 ] = 'u';
            e[8 ] = "0123456789ABCDEF"[(cbot         ) >> 12];
            e[9 ] = "0123456789ABCDEF"[(cbot & 0x0f00) >>  8];
            e[10] = "0123456789ABCDEF"[(cbot & 0x00f0) >>  4];
            e[11] = "0123456789ABCDEF"[(cbot & 0x000f)      ];
            e[12] = '\0';
            j->out(j->ctx, e);
            continue;
        }
	j->out(j->ctx, "\"");
	break;
    }

    case HEIM_TID_DATA: {
	heim_dict_t d;
	heim_string_t v;
	const heim_octet_string *data;
	char *b64 = NULL;
	int ret;

	if (j->flags & HEIM_JSON_F_NO_DATA)
	    return EINVAL; /* JSON doesn't do binary */

	data = heim_data_get_data(obj);
	ret = rk_base64_encode(data->data, data->length, &b64);
	if (ret < 0 || b64 == NULL)
	    return ENOMEM;

	if (j->flags & HEIM_JSON_F_NO_DATA_DICT) {
	    indent(j);
	    j->out(j->ctx, "\"");
	    j->out(j->ctx, b64); /* base64-encode; hope there's no aliasing */
	    j->out(j->ctx, "\"");
	    free(b64);
	} else {
	    /*
	     * JSON has no way to represent binary data, therefore the
	     * following is a Heimdal-specific convention.
	     *
	     * We encode binary data as a dict with a single very magic
	     * key with a base64-encoded value.  The magic key includes
	     * a uuid, so we're not likely to alias accidentally.
	     */
	    d = heim_dict_create(2);
	    if (d == NULL) {
		free(b64);
		return ENOMEM;
	    }
	    v = heim_string_ref_create(b64, free);
	    if (v == NULL) {
		free(b64);
		heim_release(d);
		return ENOMEM;
	    }
	    ret = heim_dict_set_value(d, heim_tid_data_uuid_key, v);
	    heim_release(v);
	    if (ret) {
		heim_release(d);
		return ENOMEM;
	    }
	    ret = base2json(d, j, 0);
	    heim_release(d);
	    if (ret)
		return ret;
	}
	break;
    }

    case HEIM_TID_NUMBER: {
	char num[32];
        if (!skip_indent)
            indent(j);
	snprintf(num, sizeof (num), "%d", heim_number_get_int(obj));
	j->out(j->ctx, num);
	break;
    }
    case HEIM_TID_NULL:
        if (!skip_indent)
            indent(j);
	j->out(j->ctx, "null");
	break;
    case HEIM_TID_BOOL:
        if (!skip_indent)
            indent(j);
	j->out(j->ctx, heim_bool_val(obj) ? "true" : "false");
	break;
    default:
	return 1;
    }
    return 0;
}

static int
heim_base2json(heim_object_t obj, void *ctx, heim_json_flags_t flags,
	       void (*out)(void *, const char *))
{
    struct twojson j;

    heim_base_once_f(&heim_json_once, NULL, json_init_once);

    j.indent = 0;
    j.ctx = ctx;
    j.out = out;
    j.flags = flags;
    j.ret = 0;
    j.first = 1;

    if (!(flags & HEIM_JSON_F_NO_ESCAPE_NON_ASCII) &&
        !heim_locale_is_utf8())
        j.flags |= HEIM_JSON_F_ESCAPE_NON_ASCII;

    return base2json(obj, &j, 0);
}


/*
 *
 */

struct parse_ctx {
    unsigned long lineno;
    const uint8_t *p;
    const uint8_t *pstart;
    const uint8_t *pend;
    heim_error_t error;
    size_t depth;
    heim_json_flags_t flags;
};


static heim_object_t
parse_value(struct parse_ctx *ctx);

/*
 * This function eats whitespace, but, critically, it also succeeds
 * only if there's anything left to parse.
 */
static int
white_spaces(struct parse_ctx *ctx)
{
    while (ctx->p < ctx->pend) {
	uint8_t c = *ctx->p;
	if (c == ' ' || c == '\t' || c == '\r') {

	} else if (c == '\n') {
	    ctx->lineno++;
	} else
	    return 0;
	(ctx->p)++;
    }
    return -1;
}

static int
is_number(uint8_t n)
{
    return ('0' <= n && n <= '9');
}

static heim_number_t
parse_number(struct parse_ctx *ctx)
{
    int number = 0, neg = 1;

    if (ctx->p >= ctx->pend)
	return NULL;

    if (*ctx->p == '-') {
	if (ctx->p + 1 >= ctx->pend)
	    return NULL;
	neg = -1;
	ctx->p += 1;
    }

    while (ctx->p < ctx->pend) {
	if (is_number(*ctx->p)) {
	    number = (number * 10) + (*ctx->p - '0');
	} else {
	    break;
	}
	ctx->p += 1;
    }

    return heim_number_create(number * neg);
}

/*
 * Read 4 hex digits from ctx->p.
 *
 * If we don't have enough, rewind ctx->p and return -1 .
 */
static int
unescape_unicode(struct parse_ctx *ctx)
{
    int c = 0;
    int i;

    for (i = 0; i < 4 && ctx->p < ctx->pend; i++, ctx->p++) {
        if (*ctx->p >= '0' && *ctx->p <= '9') {
            c = (c << 4) + (*ctx->p - '0');
        } else if (*ctx->p >= 'A' && *ctx->p <= 'F') {
            c = (c << 4) + (10 + *ctx->p - 'A');
        } else if (*ctx->p >= 'a' && *ctx->p <= 'f') {
            c = (c << 4) + (10 + *ctx->p - 'a');
        } else {
            ctx->p -= i;
            return -1;
        }
    }
    return c;
}

static int
encode_utf8(struct parse_ctx *ctx, char **pp, char *pend, int c)
{
    char *p = *pp;

    if (c < 0x80) {
        /* ASCII */
        if (p >= pend) return 0;
        *(p++) = c;
        *pp = p;
        return 1;
    }
    if (c < 0x800) {
        /* 2 code unit UTF-8 sequence */
        if (p >= pend) return 0;
        *(p++) = 0xc0 | ((c >>  6)       );
        if (p == pend) return 0;
        *(p++) = 0x80 | ((c      ) & 0x3f);
        *pp = p;
        return 1;
    }
    if (c < 0x10000) {
        /* 3 code unit UTF-8 sequence */
        if (p >= pend) return 0;
        *(p++) = 0xe0 | ((c >> 12)       );
        if (p == pend) return 0;
        *(p++) = 0x80 | ((c >>  6) & 0x3f);
        if (p == pend) return 0;
        *(p++) = 0x80 | ((c)       & 0x3f);
        *pp = p;
        return 1;
    }
    if (c < 0x110000) {
        /* 4 code unit UTF-8 sequence */
        if (p >= pend) return 0;
        *(p++) = 0xf0 | ((c >> 18)       );
        if (p == pend) return 0;
        *(p++) = 0x80 | ((c >> 12) & 0x3f);
        if (p == pend) return 0;
        *(p++) = 0x80 | ((c >>  6) & 0x3f);
        if (p == pend) return 0;
        *(p++) = 0x80 | ((c)       & 0x3f);
        *pp = p;
        return 1;
    }
    return 0;
}

static heim_string_t
parse_string_error(struct parse_ctx *ctx,
                   char *freeme,
                   const char *msg)
{
    free(freeme);
    ctx->error = heim_error_create(EINVAL, "%s at %lu", msg, ctx->lineno);
    return NULL;
}

static heim_string_t
parse_string(struct parse_ctx *ctx)
{
    const uint8_t *start;
    heim_object_t o;
    size_t alloc_len = 0;
    size_t need = 0;
    char *p0, *p, *pend;
    int strict = ctx->flags & HEIM_JSON_F_STRICT_STRINGS;
    int binary = 0;

    if (*ctx->p != '"')
        return parse_string_error(ctx, NULL,
                                  "Expected a JSON string but found "
                                  "something else");
    start = ++(ctx->p);

    /* Estimate how many bytes we need to allocate */
    p0 = p = pend = NULL;
    for (need = 1; ctx->p < ctx->pend; ctx->p++) {
        need++;
        if (*ctx->p == '\\')
            ctx->p++;
        else if (*ctx->p == '"')
            break;
    }
    if (ctx->p == ctx->pend)
        return parse_string_error(ctx, NULL, "Unterminated JSON string");

    ctx->p = start;
    while (ctx->p < ctx->pend) {
        const unsigned char *p_save;
        int32_t ctop, cbot;

        if (*ctx->p == '"') {
            ctx->p++;
            break;
        }

        /* Allocate or resize our output buffer if need be */
        if (need || p == pend) {
            char *tmp;

            /*
             * Work out how far p is into p0 to re-esablish p after
             * the realloc()
             */
            size_t p0_to_p_len = (p - p0);

            tmp = realloc(p0, alloc_len + need + 5 /* slop? */);

            if (tmp == NULL) {
                ctx->error = heim_error_create_enomem();
                free(p0);
                return NULL;
            }
            alloc_len += need + 5;

            /*
             * We have two pointers, p and p0, we want to keep them
             * pointing into the same memory after the realloc()
             */
            p = tmp + p0_to_p_len;
            p0 = tmp;
            pend = p0 + alloc_len;

            need = 0;
        }

        if (*ctx->p != '\\') {
            unsigned char c = *ctx->p;

            /*
             * Not backslashed -> consume now.
             *
             * NOTE: All cases in this block must continue or return w/ error.
             */

            /* Check for unescaped ASCII control characters */
            if (c == '\n') {
                if (strict)
                    return parse_string_error(ctx, p0,
                                              "Unescaped newline in JSON string");
                /* Count the newline but don't add it to the decoding */
                ctx->lineno++;
            } else if (strict && *ctx->p <= 0x1f) {
                return parse_string_error(ctx, p0, "Unescaped ASCII control character");
            } else if (c == 0) {
                binary = 1;
            }
            if (!strict || c < 0x80) {
                /* ASCII, or not strict -> no need to validate */
                *(p++) = c;
                ctx->p++;
                continue;
            }

            /*
             * Being strict for parsing means we want to detect malformed UTF-8
             * sequences.
             *
             * If not strict then we just go on below and add to `p' whatever
             * bytes we find in `ctx->p' as we find them.
             *
             * For each two-byte sequence we need one more byte in `p[]'.  For
             * each three-byte sequence we need two more bytes in `p[]'.
             *
             * Setting `need' and looping will cause `p0' to be grown.
             *
             * NOTE: All cases in this block must continue or return w/ error.
             */
            if ((c & 0xe0) == 0xc0) {
                /* Two-byte UTF-8 encoding */
                if (pend - p < 2) {
                    need = 2;
                    continue; /* realloc p0 */
                }

                *(p++) = c;
                ctx->p++;
                if (ctx->p == ctx->pend)
                    return parse_string_error(ctx, p0, "Truncated UTF-8");
                c = *(ctx->p++);
                if ((c & 0xc0) != 0x80)
                    return parse_string_error(ctx, p0, "Truncated UTF-8");
                *(p++) = c;
                continue;
            }
            if ((c & 0xf0) == 0xe0) {
                /* Three-byte UTF-8 encoding */
                if (pend - p < 3) {
                    need = 3;
                    continue; /* realloc p0 */
                }

                *(p++) = c;
                ctx->p++;
                if (ctx->p == ctx->pend)
                    return parse_string_error(ctx, p0, "Truncated UTF-8");
                c = *(ctx->p++);
                if ((c & 0xc0) != 0x80)
                    return parse_string_error(ctx, p0, "Truncated UTF-8");
                *(p++) = c;
                c = *(ctx->p++);
                if ((c & 0xc0) != 0x80)
                    return parse_string_error(ctx, p0, "Truncated UTF-8");
                *(p++) = c;
                continue;
            }
            if ((c & 0xf8) == 0xf0)
                return parse_string_error(ctx, p0, "UTF-8 sequence not "
                                          "encoded as escaped UTF-16");
            if ((c & 0xc0) == 0x80)
                return parse_string_error(ctx, p0,
                                          "Invalid UTF-8 "
                                          "(bare continuation code unit)");

            return parse_string_error(ctx, p0, "Not UTF-8");
        }

        /* Backslash-quoted character */
        ctx->p++;
        if (ctx->p == ctx->pend) {
            ctx->error =
                heim_error_create(EINVAL,
                                  "Unterminated JSON string at line %lu",
                                  ctx->lineno);
            free(p0);
            return NULL;
        }
        switch (*ctx->p) {
        /* Simple escapes */
        case  'b': *(p++) = '\b'; ctx->p++; continue;
        case  'f': *(p++) = '\f'; ctx->p++; continue;
        case  'n': *(p++) = '\n'; ctx->p++; continue;
        case  'r': *(p++) = '\r'; ctx->p++; continue;
        case  't': *(p++) = '\t'; ctx->p++; continue;
        case  '"': *(p++) = '"';  ctx->p++; continue;
        case '\\': *(p++) = '\\'; ctx->p++; continue;
        /* Escaped Unicode handled below */
        case  'u':
            /*
             * Worst case for !strict we need 11 bytes for a truncated non-BMP
             * codepoint escape.  Call it 12.
             */
            if (strict)
                need = 4;
            else
                need = 12;
            if (pend - p < need) {
                /* Go back to the backslash, realloc, try again */
                ctx->p--;
                continue;
            }

            need = 0;
            ctx->p++;
            break;
        default:
            if (!strict) {
                *(p++) = *ctx->p;
                ctx->p++;
                continue;
            }
            ctx->error =
                heim_error_create(EINVAL,
                                  "Invalid backslash escape at line %lu",
                                  ctx->lineno);
            free(p0);
            return NULL;
        }

        /* Unicode code point */
        if (pend - p < 12) {
            need = 12;
            ctx->p -= 2; /* for "\\u" */
            continue; /* This will cause p0 to be realloc'ed */
        }
        p_save = ctx->p;
        ctop = cbot = -3;
        ctop = unescape_unicode(ctx);
        if (ctop == -1 && strict)
            return parse_string_error(ctx, p0, "Invalid escaped Unicode");
        if (ctop == -1) {
            /*
             * Not strict; tolerate bad input.
             *
             * Output "\\u" and then loop to treat what we expected to be four
             * digits as if they were not part of an escaped Unicode codepoint.
             */
            ctx->p = p_save;
            if (p < pend)
                *(p++) = '\\';
            if (p < pend)
                *(p++) = 'u';
            continue;
        }
        if (ctop == 0) {
            *(p++) = '\0';
            binary = 1;
            continue;
        }
        if (ctop < 0xd800) {
            if (!encode_utf8(ctx, &p, pend, ctop))
                return parse_string_error(ctx, p0,
                                          "Internal JSON string parse error");
            continue;
        }

        /*
         * We parsed the top escaped codepoint of a surrogate pair encoding
         * of a non-BMP Unicode codepoint.  What follows must be another
         * escaped codepoint.
         */
        if (ctx->p < ctx->pend && ctx->p[0] == '\\')
            ctx->p++;
        else
            ctop = -1;
        if (ctop > -1 && ctx->p < ctx->pend && ctx->p[0] == 'u')
            ctx->p++;
        else
            ctop = -1;
        if (ctop > -1) {
            /* Parse the hex digits of the bottom half of the surrogate pair */
            cbot = unescape_unicode(ctx);
            if (cbot == -1 || cbot < 0xdc00)
                ctop = -1;
        }
        if (ctop == -1) {
            if (strict)
                return parse_string_error(ctx, p0,
                                          "Invalid surrogate pair");

            /*
             * Output "\\u", rewind, output the digits of `ctop'.
             *
             * When we get to what should have been the bottom half of the
             * pair we'll necessarily fail to parse it as a normal escaped
             * Unicode codepoint, and once again, rewind and output its digits.
             */
            if (p < pend)
                *(p++) = '\\';
            if (p < pend)
                *(p++) = 'u';
            ctx->p = p_save;
            continue;
        }

        /* Finally decode the surrogate pair then encode as UTF-8 */
        ctop -= 0xd800;
        cbot -= 0xdc00;
        if (!encode_utf8(ctx, &p, pend, 0x10000 + ((ctop << 10) | (cbot & 0x3ff))))
            return parse_string_error(ctx, p0,
                                      "Internal JSON string parse error");
    }

    if (p0 == NULL)
        return heim_string_create("");

    /* NUL-terminate for rk_base64_decode() and plain paranoia */
    if (p0 != NULL && p == pend) {
        /*
	 * Work out how far p is into p0 to re-esablish p after
	 * the realloc()
	 */
        size_t p0_to_pend_len = (pend - p0);
        char *tmp = realloc(p0, 1 + p0_to_pend_len);

        if (tmp == NULL) {
            ctx->error = heim_error_create_enomem();
            free(p0);
            return NULL;
        }
        /*
         * We have three pointers, p, pend (which are the same)
         * and p0, we want to keep them pointing into the same
         * memory after the realloc()
         */
        p = tmp + p0_to_pend_len;

        pend = p + 1;
        p0 = tmp;
    }
    *(p++) = '\0';

    /* If there's embedded NULs, it's not a C string */
    if (binary) {
        o = heim_data_ref_create(p0, (p - 1) - p0, free);
        return o;
    }

    /* Sadly this will copy `p0' */
    o = heim_string_create_with_bytes(p0, p - p0);
    free(p0);
    return o;
}

static int
parse_pair(heim_dict_t dict, struct parse_ctx *ctx)
{
    heim_string_t key;
    heim_object_t value;

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == '}') {
	ctx->p++;
	return 0;
    }

    if (ctx->flags & HEIM_JSON_F_STRICT_DICT)
	/* JSON allows only string keys */
	key = parse_string(ctx);
    else
	/* heim_dict_t allows any heim_object_t as key */
	key = parse_value(ctx);
    if (key == NULL)
	/* Even heim_dict_t does not allow C NULLs as keys though! */
	return -1;

    if (white_spaces(ctx)) {
	heim_release(key);
	return -1;
    }

    if (*ctx->p != ':') {
	heim_release(key);
	return -1;
    }

    ctx->p += 1; /* safe because we call white_spaces() next */

    if (white_spaces(ctx)) {
	heim_release(key);
	return -1;
    }

    value = parse_value(ctx);
    if (value == NULL &&
	(ctx->error != NULL || (ctx->flags & HEIM_JSON_F_NO_C_NULL))) {
	if (ctx->error == NULL)
	    ctx->error = heim_error_create(EINVAL, "Invalid JSON encoding");
	heim_release(key);
	return -1;
    }
    heim_dict_set_value(dict, key, value);
    heim_release(key);
    heim_release(value);

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == '}') {
	/*
	 * Return 1 but don't consume the '}' so we can count the one
	 * pair in a one-pair dict
	 */
	return 1;
    } else if (*ctx->p == ',') {
	ctx->p++;
	return 1;
    }
    return -1;
}

static heim_dict_t
parse_dict(struct parse_ctx *ctx)
{
    heim_dict_t dict;
    size_t count = 0;
    int ret;

    heim_assert(*ctx->p == '{', "string doesn't start with {");

    dict = heim_dict_create(11);
    if (dict == NULL) {
	ctx->error = heim_error_create_enomem();
	return NULL;
    }

    ctx->p += 1; /* safe because parse_pair() calls white_spaces() first */

    while ((ret = parse_pair(dict, ctx)) > 0)
	count++;
    if (ret < 0) {
	heim_release(dict);
	return NULL;
    }
    if (count == 1 && !(ctx->flags & HEIM_JSON_F_NO_DATA_DICT)) {
	heim_object_t v = heim_dict_copy_value(dict, heim_tid_data_uuid_key);

	/*
	 * Binary data encoded as a dict with a single magic key with
	 * base64-encoded value?  Decode as heim_data_t.
	 */
	if (v != NULL && heim_get_tid(v) == HEIM_TID_STRING) {
	    void *buf;
	    size_t len;

	    buf = malloc(strlen(heim_string_get_utf8(v)));
	    if (buf == NULL) {
		heim_release(dict);
		heim_release(v);
		ctx->error = heim_error_create_enomem();
		return NULL;
	    }
	    len = rk_base64_decode(heim_string_get_utf8(v), buf);
	    heim_release(v);
	    if (len == -1) {
		free(buf);
		return dict; /* assume aliasing accident */
	    }
	    heim_release(dict);
	    return (heim_dict_t)heim_data_ref_create(buf, len, free);
	}
    }
    return dict;
}

static int
parse_item(heim_array_t array, struct parse_ctx *ctx)
{
    heim_object_t value;

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == ']') {
	ctx->p++; /* safe because parse_value() calls white_spaces() first */
	return 0;
    }

    value = parse_value(ctx);
    if (value == NULL &&
	(ctx->error || (ctx->flags & HEIM_JSON_F_NO_C_NULL)))
	return -1;

    heim_array_append_value(array, value);
    heim_release(value);

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == ']') {
	ctx->p++;
	return 0;
    } else if (*ctx->p == ',') {
	ctx->p++;
	return 1;
    }
    return -1;
}

static heim_array_t
parse_array(struct parse_ctx *ctx)
{
    heim_array_t array = heim_array_create();
    int ret;

    heim_assert(*ctx->p == '[', "array doesn't start with [");
    ctx->p += 1;

    while ((ret = parse_item(array, ctx)) > 0)
	;
    if (ret < 0) {
	heim_release(array);
	return NULL;
    }
    return array;
}

static heim_object_t
parse_value(struct parse_ctx *ctx)
{
    size_t len;
    heim_object_t o;

    if (white_spaces(ctx))
	return NULL;

    if (*ctx->p == '"') {
	return parse_string(ctx);
    } else if (*ctx->p == '{') {
	if (ctx->depth-- == 1) {
	    ctx->error = heim_error_create(EINVAL, "JSON object too deep");
	    return NULL;
	}
	o = parse_dict(ctx);
	ctx->depth++;
	return o;
    } else if (*ctx->p == '[') {
	if (ctx->depth-- == 1) {
	    ctx->error = heim_error_create(EINVAL, "JSON object too deep");
	    return NULL;
	}
	o = parse_array(ctx);
	ctx->depth++;
	return o;
    } else if (is_number(*ctx->p) || *ctx->p == '-') {
	return parse_number(ctx);
    }

    len = ctx->pend - ctx->p;

    if ((ctx->flags & HEIM_JSON_F_NO_C_NULL) == 0 &&
	len >= 6 && memcmp(ctx->p, "<NULL>", 6) == 0) {
	ctx->p += 6;
	return heim_null_create();
    } else if (len >= 4 && memcmp(ctx->p, "null", 4) == 0) {
	ctx->p += 4;
	return heim_null_create();
    } else if (len >= 4 && strncasecmp((char *)ctx->p, "true", 4) == 0) {
	ctx->p += 4;
	return heim_bool_create(1);
    } else if (len >= 5 && strncasecmp((char *)ctx->p, "false", 5) == 0) {
	ctx->p += 5;
	return heim_bool_create(0);
    }

    ctx->error = heim_error_create(EINVAL, "unknown char %c at %lu line %lu",
				   (char)*ctx->p, 
				   (unsigned long)(ctx->p - ctx->pstart),
				   ctx->lineno);
    return NULL;
}


heim_object_t
heim_json_create(const char *string, size_t max_depth, heim_json_flags_t flags,
		 heim_error_t *error)
{
    return heim_json_create_with_bytes(string, strlen(string), max_depth, flags,
				       error);
}

heim_object_t
heim_json_create_with_bytes(const void *data, size_t length, size_t max_depth,
			    heim_json_flags_t flags, heim_error_t *error)
{
    struct parse_ctx ctx;
    heim_object_t o;

    heim_base_once_f(&heim_json_once, NULL, json_init_once);

    ctx.lineno = 1;
    ctx.p = data;
    ctx.pstart = data;
    ctx.pend = ((uint8_t *)data) + length;
    ctx.error = NULL;
    ctx.flags = flags;
    ctx.depth = max_depth;

    o = parse_value(&ctx);

    if (o == NULL && error) {
	*error = ctx.error;
    } else if (ctx.error) {
	heim_release(ctx.error);
    }

    return o;
}


static void
show_printf(void *ctx, const char *str)
{
    if (str == NULL)
	return;
    fprintf(ctx, "%s", str);
}

/**
 * Dump a heimbase object to stderr (useful from the debugger!)
 *
 * @param obj object to dump using JSON or JSON-like format
 *
 * @addtogroup heimbase
 */
void
heim_show(heim_object_t obj)
{
    heim_base2json(obj, stderr, HEIM_JSON_F_NO_DATA_DICT, show_printf);
}

static void
strbuf_add(void *ctx, const char *str)
{
    struct heim_strbuf *strbuf = ctx;
    size_t len;

    if (strbuf->enomem)
	return;

    if (str == NULL) {
	/*
	 * Eat the last '\n'; this is used when formatting dict pairs
	 * and array items so that the ',' separating them is never
	 * preceded by a '\n'.
	 */
	if (strbuf->len > 0 && strbuf->str[strbuf->len - 1] == '\n')
	    strbuf->len--;
	return;
    }

    len = strlen(str);
    if ((len + 1) > (strbuf->alloced - strbuf->len)) {
	size_t new_len = strbuf->alloced + (strbuf->alloced >> 2) + len + 1;
	char *s;

	s = realloc(strbuf->str, new_len);
	if (s == NULL) {
	    strbuf->enomem = 1;
	    return;
	}
	strbuf->str = s;
	strbuf->alloced = new_len;
    }
    /* +1 so we copy the NUL */
    (void) memcpy(strbuf->str + strbuf->len, str, len + 1);
    strbuf->len += len;
    if (strbuf->str[strbuf->len - 1] == '\n' && 
	strbuf->flags & HEIM_JSON_F_ONE_LINE)
	strbuf->len--;
}

#define STRBUF_INIT_SZ 64

heim_string_t
heim_json_copy_serialize(heim_object_t obj, heim_json_flags_t flags, heim_error_t *error)
{
    heim_string_t str;
    struct heim_strbuf strbuf;
    int ret;

    if (error)
	*error = NULL;

    memset(&strbuf, 0, sizeof (strbuf));
    strbuf.str = malloc(STRBUF_INIT_SZ);
    if (strbuf.str == NULL) {
	if (error)
	    *error = heim_error_create_enomem();
	return NULL;
    }
    strbuf.len = 0;
    strbuf.alloced = STRBUF_INIT_SZ;
    strbuf.str[0] = '\0';
    strbuf.flags = flags;

    ret = heim_base2json(obj, &strbuf, flags, strbuf_add);
    if (ret || strbuf.enomem) {
	if (error) {
	    if (strbuf.enomem || ret == ENOMEM)
		*error = heim_error_create_enomem();
	    else
		*error = heim_error_create(1, "Impossible to JSON-encode "
					   "object");
	}
	free(strbuf.str);
	return NULL;
    }
    if (flags & HEIM_JSON_F_ONE_LINE) {
	strbuf.flags &= ~HEIM_JSON_F_ONE_LINE;
	strbuf_add(&strbuf, "\n");
    }
    str = heim_string_ref_create(strbuf.str, free);
    if (str == NULL) {
	if (error)
	    *error = heim_error_create_enomem();
	free(strbuf.str);
    }
    return str;
}

struct heim_eq_f_ctx {
    heim_dict_t other;
    int ret;
};

static void
heim_eq_dict_iter_f(heim_object_t key, heim_object_t val, void *d)
{
    struct heim_eq_f_ctx *ctx = d;
    heim_object_t other_val;

    if (!ctx->ret)
        return;

    /*
     * This doesn't work if the key is an array or a dict, which, anyways,
     * isn't allowed in JSON, though we allow it.
     */
    other_val = heim_dict_get_value(ctx->other, key);
    ctx->ret = heim_json_eq(val, other_val);
}

int
heim_json_eq(heim_object_t a, heim_object_t b)
{
    heim_tid_t atid, btid;

    if (a == b)
        return 1;
    if (a == NULL || b == NULL)
        return 0;
    atid = heim_get_tid(a);
    btid = heim_get_tid(b);
    if (atid != btid)
        return 0;
    switch (atid) {
    case HEIM_TID_ARRAY: {
        size_t len = heim_array_get_length(b);
        size_t i;

        if (heim_array_get_length(a) != len)
            return 0;
        for (i = 0; i < len; i++) {
            if (!heim_json_eq(heim_array_get_value(a, i),
                              heim_array_get_value(b, i)))
                return 0;
        }
        return 1;
    }
    case HEIM_TID_DICT: {
        struct heim_eq_f_ctx ctx;

        ctx.other = b;
        ctx.ret = 1;
        heim_dict_iterate_f(a, &ctx, heim_eq_dict_iter_f);

        if (ctx.ret) {
            ctx.other = a;
            heim_dict_iterate_f(b, &ctx, heim_eq_dict_iter_f);
        }
        return ctx.ret;
    }
    case HEIM_TID_STRING:
        return strcmp(heim_string_get_utf8(a), heim_string_get_utf8(b)) == 0;
    case HEIM_TID_DATA: {
        return heim_data_get_length(a) == heim_data_get_length(b) &&
               memcmp(heim_data_get_ptr(a), heim_data_get_ptr(b),
                      heim_data_get_length(a)) == 0;
    }
    case HEIM_TID_NUMBER:
        return heim_number_get_long(a) == heim_number_get_long(b);
    case HEIM_TID_NULL:
    case HEIM_TID_BOOL:
        return heim_bool_val(a) == heim_bool_val(b);
    default:
        break;
    }
    return 0;
}
