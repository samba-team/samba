/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
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

#include "der_locl.h"
#include <com_err.h>
#include <vis.h>
#include <vis-extras.h>
#include <heimbase.h>

#ifndef ENOTSUP
/* Very old MSVC CRTs don't have ENOTSUP */
#define ENOTSUP EINVAL
#endif

struct asn1_type_func asn1_template_prim[A1T_NUM_ENTRY] = {
#define el(name, type) {				\
	(asn1_type_encode)der_put_##name,		\
	(asn1_type_decode)der_get_##name,		\
	(asn1_type_length)der_length_##name,		\
	(asn1_type_copy)der_copy_##name,		\
	(asn1_type_release)der_free_##name,		\
	(asn1_type_print)der_print_##name,		\
	sizeof(type)					\
    }
#define elber(name, type) {				\
	(asn1_type_encode)der_put_##name,		\
	(asn1_type_decode)der_get_##name##_ber,		\
	(asn1_type_length)der_length_##name,		\
	(asn1_type_copy)der_copy_##name,		\
	(asn1_type_release)der_free_##name,		\
	(asn1_type_print)der_print_##name,		\
	sizeof(type)					\
    }
    el(integer, int),
    el(heim_integer, heim_integer),
    el(integer, int),
    el(integer64, int64_t),
    el(unsigned, unsigned),
    el(unsigned64, uint64_t),
    el(general_string, heim_general_string),
    el(octet_string, heim_octet_string),
    elber(octet_string, heim_octet_string),
    el(ia5_string, heim_ia5_string),
    el(bmp_string, heim_bmp_string),
    el(universal_string, heim_universal_string),
    el(printable_string, heim_printable_string),
    el(visible_string, heim_visible_string),
    el(utf8string, heim_utf8_string),
    el(generalized_time, time_t),
    el(utctime, time_t),
    el(bit_string, heim_bit_string),
    { (asn1_type_encode)der_put_boolean, (asn1_type_decode)der_get_boolean,
      (asn1_type_length)der_length_boolean, (asn1_type_copy)der_copy_integer,
      (asn1_type_release)der_free_integer, (asn1_type_print)der_print_boolean,
      sizeof(int)
    },
    el(oid, heim_oid),
    el(general_string, heim_general_string),
#undef el
#undef elber
};

size_t
_asn1_sizeofType(const struct asn1_template *t)
{
    return t->offset;
}

/*
 * Here is abstraction to not so well evil fact of bit fields in C,
 * they are endian dependent, so when getting and setting bits in the
 * host local structure we need to know the endianness of the host.
 *
 * Its not the first time in Heimdal this have bitten us, and some day
 * we'll grow up and use #defined constant, but bit fields are still
 * so pretty and shiny.
 */

static void
_asn1_bmember_get_bit(const unsigned char *p, void *data,
		      unsigned int bit, size_t size)
{
    unsigned int localbit = bit % 8;
    if ((*p >> (7 - localbit)) & 1) {
#ifdef WORDS_BIGENDIAN
	*(unsigned int *)data |= (1u << ((size * 8) - bit - 1));
#else
	*(unsigned int *)data |= (1u << bit);
#endif
    }
}

int
_asn1_bmember_isset_bit(const void *data, unsigned int bit, size_t size)
{
#ifdef WORDS_BIGENDIAN
    if ((*(unsigned int *)data) & (1u << ((size * 8) - bit - 1)))
	return 1;
    return 0;
#else
    if ((*(unsigned int *)data) & (1u << bit))
	return 1;
    return 0;
#endif
}

void
_asn1_bmember_put_bit(unsigned char *p, const void *data, unsigned int bit,
		      size_t size, unsigned int *bitset)
{
    unsigned int localbit = bit % 8;

    if (_asn1_bmember_isset_bit(data, bit, size)) {
	*p |= (1u << (7 - localbit));
	if (*bitset == 0)
	    *bitset = (7 - localbit) + 1;
    }
}

/*
 * Utility function to tell us if the encoding of some type per its template
 * will have an outer tag.  This is needed when the caller wants to slap on an
 * IMPLICIT tag: if the inner type has a tag then we need to replace it.
 */
static int
is_tagged(const struct asn1_template *t)
{
    size_t elements = A1_HEADER_LEN(t);

    t += A1_HEADER_LEN(t);
    if (elements != 1)
        return 0;
    switch (t->tt & A1_OP_MASK) {
    case A1_OP_SEQOF:       return 0;
    case A1_OP_SETOF:       return 0;
    case A1_OP_BMEMBER:     return 0;
    case A1_OP_PARSE:       return 0;
    case A1_OP_TAG:         return 1;
    case A1_OP_CHOICE:      return 1;
    case A1_OP_TYPE:        return 1;
    case A1_OP_TYPE_EXTERN: {
        const struct asn1_type_func *f = t->ptr;

        /*
         * XXX Add a boolean to struct asn1_type_func to tell us if the type is
         * tagged or not.  Basically, it's not tagged if it's primitive.
         */
        if (f->encode == (asn1_type_encode)encode_heim_any ||
            f->encode == (asn1_type_encode)encode_HEIM_ANY)
            return 0;
        abort(); /* XXX */
    }
    default: abort();
    }
}

static size_t
inner_type_taglen(const struct asn1_template *t)
{
    size_t elements = A1_HEADER_LEN(t);

    t += A1_HEADER_LEN(t);
    if (elements != 1)
        return 0;
    switch (t->tt & A1_OP_MASK) {
    case A1_OP_SEQOF:       return 0;
    case A1_OP_SETOF:       return 0;
    case A1_OP_BMEMBER:     return 0;
    case A1_OP_PARSE:       return 0;
    case A1_OP_CHOICE:      return 1;
    case A1_OP_TYPE:        return inner_type_taglen(t->ptr);
    case A1_OP_TAG:         return der_length_tag(A1_TAG_TAG(t->tt));
    case A1_OP_TYPE_EXTERN: {
        const struct asn1_type_func *f = t->ptr;

        /*
         * XXX Add a boolean to struct asn1_type_func to tell us if the type is
         * tagged or not.  Basically, it's not tagged if it's primitive.
         */
        if (f->encode == (asn1_type_encode)encode_heim_any ||
            f->encode == (asn1_type_encode)encode_HEIM_ANY)
            return 0;
        abort(); /* XXX */
    }
    default: abort();
#ifdef WIN32
             _exit(0); /* Quiet VC */
#endif
    }
}

/*
 * Compare some int of unknown size in a type ID field to the int value in
 * some IOS object's type ID template entry.
 *
 * This should be called with a `A1_TAG_T(ASN1_C_UNIV, PRIM, UT_Integer)'
 * template as the `ttypeid'.
 */
static int
typeid_int_cmp(const void *intp,
               int64_t i,
               const struct asn1_template *ttypeid)
{
    const struct asn1_template *tint = ttypeid->ptr;

    if ((tint[1].tt & A1_OP_MASK) != A1_OP_PARSE)
        return -1;
    if (A1_PARSE_TYPE(tint[1].tt) != A1T_INTEGER &&
        A1_PARSE_TYPE(tint[1].tt) != A1T_UNSIGNED &&
        A1_PARSE_TYPE(tint[1].tt) != A1T_INTEGER64 &&
        A1_PARSE_TYPE(tint[1].tt) != A1T_UNSIGNED64 &&
        A1_PARSE_TYPE(tint[1].tt) != A1T_IMEMBER)
        return -1;
    switch (tint[0].offset) {
    case 8:     return i - *(const int64_t *)intp;
    case 4:     return i - *(const int32_t *)intp;
    default:    return -1;
    }
}

/*
 * Map a logical SET/SEQUENCE member to a template entry.
 *
 * This should really have been done by the compiler, but clearly it wasn't.
 *
 * The point is that a struct type's template may be littered with entries that
 * don't directly correspond to a struct field (SET/SEQUENCE member), so we
 * have to count just the ones that do to get to the one we want.
 */
static const struct asn1_template *
template4member(const struct asn1_template *t, size_t f)
{
    size_t n = (uintptr_t)t->ptr;
    size_t i;

    for (i = 0, t++; i < n; t++, i++) {
        switch (t->tt & A1_OP_MASK) {
        case A1_OP_TAG:
        case A1_OP_TYPE:
        case A1_OP_TYPE_EXTERN:
            if (f-- == 0)
                return t;
            continue;
        case A1_OP_OPENTYPE_OBJSET:
        case A1_OP_NAME:
            return NULL;
        default:
            continue;
        }
    }
    return NULL;
}

/*
 * Attempt to decode known open type alternatives into a CHOICE-like
 * discriminated union.
 *
 * Arguments:
 *
 *  - object set template
 *  - decoder flags
 *  - pointer to memory object (C struct) to decode into
 *  - template for type ID field of `data'
 *  - template for open type field of `data' (an octet string or HEIM_ANY)
 *
 * Returns:
 *
 *  - 0
 *  - ENOMEM
 *
 * Other errors in decoding open type values are ignored, but applications can
 * note that an error must have occurred.  (Perhaps we should generate a `ret'
 * field for the discriminated union we decode into that we could use to
 * indicate what went wrong with decoding an open type value?  The application
 * can always try to decode itself to find out what the error was, but the
 * whole point is to save the developer the bother of writing code to decode
 * open type values.  Then again, the specific cause of any one decode failure
 * is not usually very important to users, so it's not very important to
 * applications either.)
 *
 * Here `data' is something like this:
 *
 *      typedef struct SingleAttribute {
 *          heim_oid type;              // <--- decoded already
 *          HEIM_ANY value;             // <--- decoded already
 *       // We must set this:
 *       // vvvvvvvv
 *          struct {
 *              enum {
 *                  choice_SingleAttribute_iosnumunknown = 0,
 *                  choice_SingleAttribute_iosnum_id_at_name,
 *                  ..
 *                  choice_SingleAttribute_iosnum_id_at_emailAddress,
 *              } element;     // <--- map type ID to enum
 *              union {
 *                  X520name* at_name;
 *                  X520name* at_surname;
 *                  ..
 *                  AliasIA5String* at_emailAddress;
 *              } u;           // <--- alloc and decode val above into this
 *          } _ioschoice_value;
 *      } SingleAttribute;
 *
 * or
 *
 *      typedef struct AttributeSet {
 *          heim_oid type;              // <--- decoded already
 *          struct AttributeSet_values {
 *              unsigned int len;       // <--- decoded already
 *              HEIM_ANY *val;          // <--- decoded already
 *          } values;
 *       // We must set this:
 *       // vvvvvvvv
 *          struct {
 *              enum { choice_AttributeSet_iosnumunknown = 0,
 *                  choice_AttributeSet_iosnum_id_at_name,
 *                  choice_AttributeSet_iosnum_id_at_surname,
 *                  ..
 *                  choice_AttributeSet_iosnum_id_at_emailAddress,
 *              } element;         // <--- map type ID to enum
 *              unsigned int len;   // <--- set len to len as above
 *              union {
 *                  X520name *at_name;
 *                  X520name *at_surname;
 *                  ..
 *                  AliasIA5String *at_emailAddress;
 *              } *val;         // <--- alloc and decode vals above into this
 *          } _ioschoice_values;
 *      } AttributeSet;
 */
static int
_asn1_decode_open_type(const struct asn1_template *t,
                       unsigned flags,
                       void *data,
                       const struct asn1_template *ttypeid,
                       const struct asn1_template *topentype)
{
    const struct asn1_template *ttypeid_univ = ttypeid;
    const struct asn1_template *tactual_type;
    const struct asn1_template *tos = t->ptr;
    size_t sz, n;
    size_t i = 0;
    unsigned int *lenp = NULL;  /* Pointer to array length field */
    unsigned int len = 1;       /* Array length */
    void **dp = NULL;           /* Decoded open type struct pointer */
    int *elementp;              /* Choice enum pointer */
    int typeid_is_oid = 0;
    int typeid_is_int = 0;
    int ret = 0;

    /*
     * NOTE: Here expressions like `DPO(data, t->offset + ...)' refer to parts
     *       of a _ioschoice_<fieldName> struct field of `data'.
     *
     *       Expressions like `DPO(data, topentype->offset + ...)' refer to
     *       the open type field in `data', which is either a `heim_any', a
     *       `heim_octet_string', or an array of one of those.
     *
     *       Expressions like `DPO(data, ttypeid->offset)' refer to the open
     *       type's type ID field in `data'.
     */

    /*
     * Minimal setup:
     *
     *  - set type choice to choice_<type>_iosnumunknown (zero).
     *  - set union value to zero
     *
     * We need a pointer to the choice ID:
     *
     *      typedef struct AttributeSet {
     *          heim_oid type;              // <--- decoded already
     *          struct AttributeSet_values {
     *              unsigned int len;       // <--- decoded already
     *              HEIM_ANY *val;          // <--- decoded already
     *          } values;
     *          struct {
     *              enum { choice_AttributeSet_iosnumunknown = 0,
     * ----------->     ...
     *              } element; // HERE
     *              ...
     *          } ...
     *      }
     *
     * XXX NOTE: We're assuming that sizeof(enum) == sizeof(int)!
     */
    elementp = DPO(data, t->offset);
    *elementp = 0; /* Set the choice to choice_<type>_iosnumunknown */
    if (t->tt & A1_OS_OT_IS_ARRAY) {
        /*
         * The open type is a SET OF / SEQUENCE OF -- an array.
         *
         * Get the number of elements to decode from:
         *
         *      typedef struct AttributeSet {
         *          heim_oid type;
         *          struct AttributeSet_values {
         * ------------>unsigned int len;       // HERE
         *              HEIM_ANY *val;
         *          } values;
         *          ...
         *      }
         */
        len = *((unsigned int *)DPO(data, topentype->offset));

        /*
         * Set the number of decoded elements to zero for now:
         *
         *      typedef struct AttributeSet {
         *          heim_oid type;
         *          struct AttributeSet_values {
         *              unsigned int len;
         *              HEIM_ANY *val;
         *          } values;
         *          struct {
         *              enum { ... } element;
         * ------------>unsigned int len;       // HERE
         *              ...
         *          } _ioschoice_values;
         *      }
         */
        lenp = DPO(data, t->offset + sizeof(*elementp));
        *lenp = 0;
        /*
         * Get a pointer to the place where we must put the decoded value:
         *
         *      typedef struct AttributeSet {
         *          heim_oid type;
         *          struct AttributeSet_values {
         *              unsigned int len;
         *              HEIM_ANY *val;
         *          } values;
         *          struct {
         *              enum { ... } element;
         *              unsigned int len;
         *              struct {
         *                  union { SomeType *some_choice; ... } u;
         * ------------>} *val;         // HERE
         *          } _ioschoice_values;
         *      } AttributeSet;
         */
        dp = DPO(data, t->offset + sizeof(*elementp) + sizeof(*lenp));
    } else {
        /*
         * Get a pointer to the place where we must put the decoded value:
         *
         *      typedef struct SingleAttribute {
         *          heim_oid type;
         *          HEIM_ANY value;
         *          struct {
         *              enum { ... } element;
         * ------------>union { SomeType *some_choice; ... } u; // HERE
         *          } _ioschoice_value;
         *      } SingleAttribute;
         */
        dp = DPO(data, t->offset + sizeof(*elementp));
    }

    /* Align `dp' */
    while (sizeof(void *) != sizeof(*elementp) &&
        ((uintptr_t)dp) % sizeof(void *) != 0)
        dp = (void *)(((char *)dp) + sizeof(*elementp));
    *dp = NULL;

    /*
     * Find out the type of the type ID member.  We currently support only
     * integers and OIDs.
     *
     * Chase through any tags to get to the type.
     */
    while (((ttypeid_univ->tt & A1_OP_MASK) == A1_OP_TAG &&
            A1_TAG_CLASS(ttypeid_univ->tt) == ASN1_C_CONTEXT) ||
           ((ttypeid_univ->tt & A1_OP_MASK) == A1_OP_TYPE)) {
        ttypeid_univ = ttypeid_univ->ptr;
        ttypeid_univ++;
    }
    switch (ttypeid_univ->tt & A1_OP_MASK) {
    case A1_OP_TAG:
        if (A1_TAG_CLASS(ttypeid_univ->tt) != ASN1_C_UNIV)
            return 0;       /* Do nothing, silently */
        switch (A1_TAG_TAG(ttypeid_univ->tt)) {
        case UT_OID:
            typeid_is_oid = 1;
            break;
        case UT_Integer: {
            const struct asn1_template *tint = ttypeid_univ->ptr;

            tint++;
            
            if ((tint->tt & A1_OP_MASK) != A1_OP_PARSE)
                return 0;   /* Do nothing, silently */
            if (A1_PARSE_TYPE(tint->tt) != A1T_INTEGER &&
                A1_PARSE_TYPE(tint->tt) != A1T_UNSIGNED &&
                A1_PARSE_TYPE(tint->tt) != A1T_INTEGER64 &&
                A1_PARSE_TYPE(tint->tt) != A1T_UNSIGNED64 &&
                A1_PARSE_TYPE(tint->tt) != A1T_IMEMBER)
                return 0;   /* Do nothing, silently (maybe a large int) */
            typeid_is_int = 1;
            break;
        }
        /* It might be cool to support string types as type ID types */
        default: return 0;  /* Do nothing, silently */
        }
        break;
    default: return 0;      /* Do nothing, silently */
    }

    /*
     * Find the type of the open type.
     *
     * An object set template looks like:
     *
     * const struct asn1_template asn1_ObjectSetName[] = {
     *     // Header entry (in this case it says there's 17 objects):
     *     { 0, 0, ((void*)17) },
     *
     *     // here's the name of the object set:
     *     { A1_OP_NAME, 0, "ObjectSetName" },
     *
     *     // then three entries per object: object name, object type ID,
     *     // object type:
     *     { A1_OP_NAME, 0, "ext-AuthorityInfoAccess" },
     *     { A1_OP_OPENTYPE_ID, 0, (const void*)&asn1_oid_oidName },
     *     { A1_OP_OPENTYPE, sizeof(SomeType), (const void*)&asn1_SomeType },
     *     ...
     * };
     *
     * `i' being a logical object offset, i*3+3 would be the index of the
     * A1_OP_OPENTYPE_ID entry for the current object, and i*3+4 the index of
     * the A1_OP_OPENTYPE entry for the current object.
     */
    if (t->tt & A1_OS_IS_SORTED) {
        size_t left = 0;
        size_t right = A1_HEADER_LEN(tos);
        const void *vp = DPO(data, ttypeid->offset);
        int c = -1;

        while (left < right) {
            size_t mid = (left + right) >> 1;

            if ((tos[3 + mid * 3].tt & A1_OP_MASK) != A1_OP_OPENTYPE_ID)
                return 0;
            if (typeid_is_int)
                c = typeid_int_cmp(vp, (intptr_t)tos[3 + mid * 3].ptr,
                                   ttypeid_univ);
            else if (typeid_is_oid)
                c = der_heim_oid_cmp(vp, tos[3 + mid * 3].ptr);
            if (c < 0) {
                right = mid;
            } else if (c > 0) {
                left = mid + 1;
            } else {
                i = mid;
                break;
            }
        }
        if (c)
            return 0; /* No match */
    } else {
        for (i = 0, n = A1_HEADER_LEN(tos); i < n; i++) {
            /* We add 1 to `i' because we're skipping the header */
            if ((tos[3 + i*3].tt & A1_OP_MASK) != A1_OP_OPENTYPE_ID)
                return 0;
            if (typeid_is_int &&
                typeid_int_cmp(DPO(data, ttypeid->offset),
                               (intptr_t)tos[3 + i*3].ptr,
                               ttypeid_univ))
                continue;
            if (typeid_is_oid &&
                der_heim_oid_cmp(DPO(data, ttypeid->offset), tos[3 + i*3].ptr))
                continue;
            break;
        }
        if (i == n)
            return 0; /* No match */
    }

    /* Match! */
    *elementp = i+1; /* Zero is the "unknown" choice, so add 1 */

    /*
     * We want the A1_OP_OPENTYPE template entry.  Its `offset' is the sizeof
     * the object we'll be decoding into, and its `ptr' is the pointer to the
     * template for decoding that type.
     */
    tactual_type = &tos[i*3 + 4];

    /* Decode the encoded open type value(s) */
    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        /*
         * Not a SET OF/SEQUENCE OF open type, just singular.
         *
         * We need the address of the octet string / ANY field containing the
         * encoded open type value:
         *
         *      typedef struct SingleAttribute {
         *          heim_oid type;
         * -------->HEIM_ANY value; // HERE
         *          struct {
         *              ...
         *          } ...
         *      }
         */
        const struct heim_base_data *d = DPOC(data, topentype->offset);
        void *o;

        if (d->data && d->length) {
            if ((o = calloc(1, tactual_type->offset)) == NULL)
                return ENOMEM;

            /* Re-enter to decode the encoded open type value */
            ret = _asn1_decode(tactual_type->ptr, flags, d->data, d->length, o, &sz);
            /*
             * Store the decoded object in the union:
             *
             *      typedef struct SingleAttribute {
             *          heim_oid type;
             *          HEIM_ANY value;
             *          struct {
             *              enum { ... } element;
             * ------------>union { SomeType *some_choice; ... } u; // HERE
             *          } _ioschoice_value;
             *      } SingleAttribute;
             *
             * All the union arms are pointers.
             */
            if (ret) {
                _asn1_free(tactual_type->ptr, o);
                free(o);
                /*
                 * So we failed to decode the open type -- that should not be fatal
                 * to decoding the rest of the input.  Only ENOMEM should be fatal.
                 */
                ret = 0;
            } else {
                *dp = o;
            }
        }
        return ret;
    } else {
        const struct heim_base_data * const *d;
        void **val; /* Array of pointers */

        /*
         * A SET OF/SEQUENCE OF open type, plural.
         *
         * We need the address of the octet string / ANY array pointer field
         * containing the encoded open type values:
         *
         *      typedef struct AttributeSet {
         *          heim_oid type;
         *          struct AttributeSet_values {
         *              unsigned int len;
         * ------------>HEIM_ANY *val;      // HERE
         *          } values;
         *      ...
         *      }
         *
         * We already know the value of the `len' field.
         */
        d = DPOC(data, topentype->offset + sizeof(unsigned int));
        while (sizeof(void *) != sizeof(len) &&
               ((uintptr_t)d) % sizeof(void *) != 0)
            d = (const void *)(((const char *)d) + sizeof(len));

        if ((val = calloc(len, sizeof(*val))) == NULL)
            ret = ENOMEM;

        /* Increment the count of decoded values as we decode */
        *lenp = len;
        for (i = 0; ret != ENOMEM && i < len; i++) {
            if ((val[i] = calloc(1, tactual_type->offset)) == NULL)
                ret = ENOMEM;
            if (ret == 0)
                /* Re-enter to decode the encoded open type value */
                ret = _asn1_decode(tactual_type->ptr, flags, d[0][i].data,
                                   d[0][i].length, val[i], &sz);
            if (ret) {
                _asn1_free(tactual_type->ptr, val[i]);
                free(val[i]);
                val[i] = NULL;
            }
        }
        if (ret != ENOMEM)
            ret = 0; /* See above */
        *dp = val;
        return ret;
    }
}

int
_asn1_decode(const struct asn1_template *t, unsigned flags,
	     const unsigned char *p, size_t len, void *data, size_t *size)
{
    const struct asn1_template *tbase = t;
    const struct asn1_template *tdefval = NULL;
    size_t elements = A1_HEADER_LEN(t);
    size_t oldlen = len;
    int ret = 0;
    const unsigned char *startp = NULL;
    unsigned int template_flags = t->tt;

    /*
     * Important notes:
     *
     *  - by and large we don't call _asn1_free() on error, except when we're
     *    decoding optional things or choices, then we do call _asn1_free()
     *    here
     *
     *    instead we leave it to _asn1_decode_top() to call _asn1_free() on
     *    error
     *
     *  - on error all fields of whatever we didn't _asn1_free() must have been
     *    initialized to sane values because _asn1_decode_top() will call
     *    _asn1_free() on error, so we must have left everything initialized
     *    that _asn1_free() could possibly look at
     *
     *  - so we must initialize everything
     *
     *    FIXME? but we mostly rely on calloc() to do this...
     *
     *  - we don't use malloc() unless we're going to write over the whole
     *    thing with memcpy() or whatever
     */

    /* skip over header */
    t++;

    if (template_flags & A1_HF_PRESERVE)
	startp = p;

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_OPENTYPE_OBJSET: {
            size_t opentypeid = t->tt & ((1<<10)-1);
            size_t opentype = (t->tt >> 10) & ((1<<10)-1);

            /* Note that the only error returned here would be ENOMEM */
            ret = _asn1_decode_open_type(t, flags, data,
                                         template4member(tbase, opentypeid),
                                         template4member(tbase, opentype));
            if (ret)
                return ret;
            break;
        }
	case A1_OP_TYPE_DECORATE_EXTERN: break;
	case A1_OP_TYPE_DECORATE: break;
        case A1_OP_NAME: break;
	case A1_OP_DEFVAL:
            tdefval = t;
            break;
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    size_t newsize, elsize;
	    void *el = DPO(data, t->offset);
	    void **pel = (void **)el;

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		elsize = _asn1_sizeofType(t->ptr);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		elsize = f->size;
	    }

	    if (t->tt & A1_FLAG_OPTIONAL) {
		*pel = calloc(1, elsize);
		if (*pel == NULL)
		    return ENOMEM;
		el = *pel;
                if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
                    ret = _asn1_decode(t->ptr, flags, p, len, el, &newsize);
                } else {
                    const struct asn1_type_func *f = t->ptr;
                    ret = (f->decode)(p, len, el, &newsize);
                }
                if (ret) {
                    /*
                     * Optional field not present in encoding, presumably,
                     * though we should really look more carefully at `ret'.
                     */
                    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
                        _asn1_free(t->ptr, el);
                    } else {
                        const struct asn1_type_func *f = t->ptr;
                        f->release(el);
                    }
		    free(*pel);
		    *pel = NULL;
		    break;
                }
	    } else {
                if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
                    ret = _asn1_decode(t->ptr, flags, p, len, el, &newsize);
                } else {
                    const struct asn1_type_func *f = t->ptr;
                    ret = (f->decode)(p, len, el, &newsize);
                }
            }
	    if (ret) {
		if (t->tt & A1_FLAG_OPTIONAL) {
		} else if (t->tt & A1_FLAG_DEFAULT) {
                    if (!tdefval)
                        return ASN1_PARSE_ERROR; /* Can't happen */
                    /*
                     * Defaulted field not present in encoding, presumably,
                     * though we should really look more carefully at `ret'.
                     */
                    if (tdefval->tt & A1_DV_BOOLEAN) {
                        int *i = (void *)(char *)el;

                        *i = tdefval->ptr ? 1 : 0;
                    } else if (tdefval->tt & A1_DV_INTEGER64) {
                        int64_t *i = (void *)(char *)el;

                        *i = (int64_t)(intptr_t)tdefval->ptr;
                    } else if (tdefval->tt & A1_DV_INTEGER32) {
                        int32_t *i = (void *)(char *)el;

                        *i = (int32_t)(intptr_t)tdefval->ptr;
                    } else if (tdefval->tt & A1_DV_INTEGER) {
                        struct heim_integer *i = (void *)(char *)el;

                        if ((ret = der_copy_heim_integer(tdefval->ptr, i)))
                            return ret;
                    } else if (tdefval->tt & A1_DV_UTF8STRING) {
                        char **s = el;

                        if ((*s = strdup(tdefval->ptr)) == NULL)
                            return ENOMEM;
                    } else {
                        abort();
                    }
                    break;
                }
		return ret; /* Error decoding required field */
	    }
	    p += newsize; len -= newsize;

	    break;
	}
	case A1_OP_TAG: {
	    Der_type dertype;
	    size_t newsize = 0;
	    size_t datalen, l = 0;
	    void *olddata = data;
	    int is_indefinite = 0;
	    int subflags = flags;
            int replace_tag = (t->tt & A1_FLAG_IMPLICIT) && is_tagged(t->ptr);
	    void *el = data = DPO(data, t->offset);
	    void **pel = (void **)el;

            /*
             * XXX If this type (chasing t->ptr through IMPLICIT tags, if this
             * one is too, till we find a non-TTag) is a [UNIVERSAL SET] type,
             * then we have to accept fields out of order.  For each field tag
             * we see we'd have to do a linear search of the SET's template
             * because it won't be sorted (or we could sort a copy and do a
             * binary search on that, but these SETs will always be small so it
             * won't be worthwhile).  We'll need a utility function to do all
             * of this.
             */
	    ret = der_match_tag_and_length(p, len, A1_TAG_CLASS(t->tt),
					   &dertype, A1_TAG_TAG(t->tt),
					   &datalen, &l);
	    if (ret) {
		if (t->tt & A1_FLAG_OPTIONAL) {
                    data = olddata;
		    break;
                } else if (t->tt & A1_FLAG_DEFAULT) {
                    if (!tdefval)
                        return ASN1_PARSE_ERROR; /* Can't happen */
                    /*
                     * Defaulted field not present in encoding, presumably,
                     * though we should really look more carefully at `ret'.
                     */
                    if (tdefval->tt & A1_DV_BOOLEAN) {
                        int *i = (void *)(char *)data;

                        *i = tdefval->ptr ? 1 : 0;
                    } else if (tdefval->tt & A1_DV_INTEGER64) {
                        int64_t *i = (void *)(char *)data;

                        *i = (int64_t)(intptr_t)tdefval->ptr;
                    } else if (tdefval->tt & A1_DV_INTEGER32) {
                        int32_t *i = (void *)(char *)data;

                        *i = (int32_t)(intptr_t)tdefval->ptr;
                    } else if (tdefval->tt & A1_DV_INTEGER) {
                        struct heim_integer *i = (void *)(char *)data;

                        if ((ret = der_copy_heim_integer(tdefval->ptr, i)))
                            return ret;
                    } else if (tdefval->tt & A1_DV_UTF8STRING) {
                        char **s = data;

                        if ((*s = strdup(tdefval->ptr)) == NULL)
                            return ENOMEM;
                    } else {
                        abort();
                    }
                    data = olddata;
                    break;
                }
		return ret; /* Error decoding required field */
	    }

	    p += l; len -= l;

	    /*
	     * Only allow indefinite encoding for OCTET STRING and BER
	     * for now. Should handle BIT STRING too.
	     */

	    if (dertype != A1_TAG_TYPE(t->tt) && (flags & A1_PF_ALLOW_BER)) {
		const struct asn1_template *subtype = t->ptr;
		subtype++; /* skip header */

		if (((subtype->tt & A1_OP_MASK) == A1_OP_PARSE) &&
		    A1_PARSE_TYPE(subtype->tt) == A1T_OCTET_STRING)
		    subflags |= A1_PF_INDEFINTE;
	    }

	    if (datalen == ASN1_INDEFINITE) {
		if ((flags & A1_PF_ALLOW_BER) == 0)
		    return ASN1_GOT_BER;
		is_indefinite = 1;
		datalen = len;
		if (datalen < 2)
		    return ASN1_OVERRUN;
		/* hide EndOfContent for sub-decoder, catching it below */
		datalen -= 2;
	    } else if (datalen > len)
		return ASN1_OVERRUN;

	    if (t->tt & A1_FLAG_OPTIONAL) {
		size_t ellen = _asn1_sizeofType(t->ptr);

		*pel = calloc(1, ellen);
		if (*pel == NULL)
		    return ENOMEM;
		data = *pel;
	    }

            if (replace_tag) {
                const struct asn1_template *subtype = t->ptr;
                int have_tag = 0;

                /*
                 * So, we have an IMPLICIT tag.  What we want to do is find the
                 * template for the body of the type so-tagged.  That's going
                 * to be a template that has a tag that isn't itself IMPLICIT.
                 *
                 * So we chase the pointer in the template until we find such a
                 * thing, then decode using that template.
                 */
                while (!have_tag) {
                    subtype++;
                    if ((subtype->tt & A1_OP_MASK) == A1_OP_TAG)
                        replace_tag = (subtype->tt & A1_FLAG_IMPLICIT) && is_tagged(t->ptr);
                    if (replace_tag) {
                        subtype = subtype->ptr;
                        continue;
                    }
                    if ((subtype->tt & A1_OP_MASK) == A1_OP_TAG) {
                        ret = _asn1_decode(subtype->ptr, subflags, p, datalen, data, &newsize);
                        have_tag = 1;
                    } else {
                        subtype = subtype->ptr;
                    }
                }
            } else {
                ret = _asn1_decode(t->ptr, subflags, p, datalen, data, &newsize);
            }
            if (ret == 0 && !is_indefinite && newsize != datalen)
		/* Hidden data */
                ret = ASN1_EXTRA_DATA;

            if (ret == 0) {
                if (is_indefinite) {
                    /* If we use indefinite encoding, the newsize is the datasize. */
                    datalen = newsize;
                }

                len -= datalen;
                p += datalen;

                /*
                 * Indefinite encoding needs a trailing EndOfContent,
                 * check for that.
                 */
                if (is_indefinite) {
                    ret = der_match_tag_and_length(p, len, ASN1_C_UNIV,
                                                   &dertype, UT_EndOfContent,
                                                   &datalen, &l);
                    if (ret == 0 && dertype != PRIM)
                        ret = ASN1_BAD_ID;
                    else if (ret == 0 && datalen != 0)
                        ret = ASN1_INDEF_EXTRA_DATA;
                    if (ret == 0) {
                        p += l; len -= l;
                    }
                }
            }
            if (ret) {
                if (!(t->tt & A1_FLAG_OPTIONAL))
                    return ret;

                _asn1_free(t->ptr, data);
                free(data);
                *pel = NULL;
                return ret;
            }
	    data = olddata;

	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    size_t newsize;
	    void *el = DPO(data, t->offset);

	    /*
	     * INDEFINITE primitive types are one element after the
	     * same type but non-INDEFINITE version.
	    */
	    if (flags & A1_PF_INDEFINTE)
		type++;

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR();
		return ASN1_PARSE_ERROR;
	    }

	    ret = (asn1_template_prim[type].decode)(p, len, el, &newsize);
	    if (ret)
		return ret;
	    p += newsize; len -= newsize;

	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    struct template_of *el = DPO(data, t->offset);
	    size_t newsize;
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    size_t vallength = 0;

	    while (len > 0) {
		void *tmp;
		size_t newlen = vallength + ellen;
		if (vallength > newlen)
		    return ASN1_OVERFLOW;

                /* XXX Slow */
		tmp = realloc(el->val, newlen);
		if (tmp == NULL)
		    return ENOMEM;

		memset(DPO(tmp, vallength), 0, ellen);
		el->val = tmp;

		el->len++;
		ret = _asn1_decode(t->ptr, flags & (~A1_PF_INDEFINTE), p, len,
				   DPO(el->val, vallength), &newsize);
		if (ret)
		    return ret;
		vallength = newlen;
		p += newsize; len -= newsize;
	    }

	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t bsize = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
	    size_t pos = 0;

	    bmember++;

	    memset(data, 0, bsize);

	    if (len < 1)
		return ASN1_OVERRUN;
	    p++; len--;

	    while (belements && len) {
		while (bmember->offset / 8 > pos / 8) {
		    if (len < 1)
			break;
		    p++; len--;
		    pos += 8;
		}
		if (len) {
		    _asn1_bmember_get_bit(p, data, bmember->offset, bsize);
		    belements--; bmember++;
		}
	    }
	    len = 0;
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    unsigned int *element = DPO(data, choice->offset);
	    size_t datalen;
	    unsigned int i;

	    /*
             * CHOICE element IDs are assigned in monotonically increasing
             * fashion.  Therefore any unrealistic value is a suitable invalid
             * CHOICE value.  The largest binary value (or -1 if treating the
             * enum as signed on a twos-complement system, or...) will do.
             */
	    *element = ~0;

	    for (i = 1; i < A1_HEADER_LEN(choice) + 1 && choice[i].tt; i++) {
		/*
                 * This is more permissive than is required.  CHOICE
                 * alternatives must have different outer tags, so in principle
                 * we should just match the tag at `p' and `len' in sequence to
                 * the choice alternatives.
                 *
                 * Trying every alternative instead happens to do this anyways
                 * because each one will first match the tag at `p' and `len',
                 * but if there are CHOICE altnernatives with the same outer
                 * tag, then we'll allow it, and they had better be unambiguous
                 * in their internal details, otherwise there would be some
                 * aliasing.
                 *
                 * Arguably the *compiler* should detect ambiguous CHOICE types
                 * and raise an error, then we don't have to be concerned here
                 * at all.
                 */
		ret = _asn1_decode(choice[i].ptr, 0, p, len,
				   DPO(data, choice[i].offset), &datalen);
		if (ret == 0) {
		    *element = i;
		    p += datalen; len -= datalen;
		    break;
		}
                _asn1_free(choice[i].ptr, DPO(data, choice[i].offset));
                if (ret != ASN1_BAD_ID && ret != ASN1_MISPLACED_FIELD &&
                    ret != ASN1_MISSING_FIELD)
		    return ret;
	    }
	    if (i >= A1_HEADER_LEN(choice) + 1 || !choice[i].tt) {
                /*
                 * If this is an extensible CHOICE, then choice->tt will be the
                 * offset to u.ellipsis.  If it's not, then this "extension" is
                 * an error and must stop parsing it.  (We could be permissive
                 * and throw away the extension, though one might as well just
                 * mark such a CHOICE as extensible.)
                 */
		if (choice->tt == 0)
		    return ASN1_BAD_ID;

                /* This is the ellipsis case */
		*element = 0;
		ret = der_get_octet_string(p, len,
					   DPO(data, choice->tt), &datalen);
		if (ret)
		    return ret;
		p += datalen; len -= datalen;
	    }

	    break;
	}
	default:
	    ABORT_ON_ERROR();
	    return ASN1_PARSE_ERROR;
	}
	t++;
	elements--;
    }
    /* if we are using padding, eat up read of context */
    if (template_flags & A1_HF_ELLIPSIS)
	len = 0;

    oldlen -= len;

    if (size)
	*size = oldlen;

    /*
     * saved the raw bits if asked for it, useful for signature
     * verification.
     */
    if (startp) {
	heim_octet_string *save = data;

	save->data = malloc(oldlen);
	if (save->data == NULL)
	    return ENOMEM;
	else {
	    save->length = oldlen;
	    memcpy(save->data, startp, oldlen);
	}
    }
    return 0;
}

/*
 * This should be called with a `A1_TAG_T(ASN1_C_UNIV, PRIM, UT_Integer)'
 * template as the `ttypeid'.
 */
static int
typeid_int_copy(void *intp,
                int64_t i,
                const struct asn1_template *ttypeid)
{
    const struct asn1_template *tint = ttypeid->ptr;

    if ((tint[1].tt & A1_OP_MASK) != A1_OP_PARSE)
        return -1;
    if (A1_PARSE_TYPE(tint[1].tt) != A1T_INTEGER)
        return -1;
    switch (tint[0].offset) {
    case 8:     *((int64_t *)intp) = i; return 0;
    case 4:     *((int32_t *)intp) = i; return 0;
    default:    memset(intp, 0, tint[0].offset); return 0;
    }
}

/* See commentary in _asn1_decode_open_type() */
static int
_asn1_encode_open_type(const struct asn1_template *t,
                       const void *data,    /* NOTE: Not really const */
                       const struct asn1_template *ttypeid,
                       const struct asn1_template *topentype)
{
    const struct asn1_template *ttypeid_univ = ttypeid;
    const struct asn1_template *tactual_type;
    const struct asn1_template *tos = t->ptr;
    size_t sz, i;
    unsigned int *lenp = NULL;
    unsigned int len = 1;
    int element = *(const int *)DPOC(data, t->offset);
    int typeid_is_oid = 0;
    int typeid_is_int = 0;
    int enotsup = 0;
    int ret = 0;

    if (element == 0 || element >= A1_HEADER_LEN(tos) + 1)
        return 0;

    if (t->tt & A1_OS_OT_IS_ARRAY) {
        /* The actual `len' is from the decoded open type field */
        len = *(const unsigned int *)DPOC(data, t->offset + sizeof(element));

        if (!len)
            return 0; /* The app may be encoding the open type by itself */
    }

    /* Work out the type ID field's type */
    while (((ttypeid_univ->tt & A1_OP_MASK) == A1_OP_TAG &&
            A1_TAG_CLASS(ttypeid_univ->tt) == ASN1_C_CONTEXT) ||
           ((ttypeid_univ->tt & A1_OP_MASK) == A1_OP_TYPE)) {
        ttypeid_univ = ttypeid_univ->ptr;
        ttypeid_univ++;
    }
    switch (ttypeid_univ->tt & A1_OP_MASK) {
    case A1_OP_TAG:
        if (A1_TAG_CLASS(ttypeid_univ->tt) != ASN1_C_UNIV) {
            enotsup = 1;
            break;
        }
        switch (A1_TAG_TAG(ttypeid_univ->tt)) {
        case UT_OID:
            typeid_is_oid = 1;
            break;
        case UT_Integer: {
            const struct asn1_template *tint = ttypeid_univ->ptr;

            tint++;
            if ((tint->tt & A1_OP_MASK) != A1_OP_PARSE ||
                A1_PARSE_TYPE(tint->tt) != A1T_INTEGER) {
                enotsup = 1;
                break;
            }
            typeid_is_int = 1;
            break;
        }
        default: enotsup = 1; break;
        }
        break;
    default: enotsup = 1; break;
    }

    /*
     * The app may not be aware of our automatic open type handling, so if the
     * open type already appears to have been encoded, then ignore the decoded
     * values.
     */
    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        struct heim_base_data *os = DPO(data, topentype->offset);

        if (os->length && os->data)
            return 0;
    } else {
        struct heim_base_data **os = DPO(data, topentype->offset + sizeof(len));

        while (sizeof(void *) != sizeof(unsigned int) &&
               ((uintptr_t)os) % sizeof(void *) != 0)
            os = (void *)(((char *)os) + sizeof(unsigned int));

        lenp = DPO(data, topentype->offset);
        if (*lenp == len && os[0]->length && os[0]->data)
            return 0;
    }

    if (typeid_is_int) {
        /*
         * Copy the int from the type ID object field to the type ID struct
         * field.
         */
        ret = typeid_int_copy(DPO(data, ttypeid->offset),
                              (intptr_t)tos[3 + (element-1)*3].ptr, ttypeid_univ);
    } else if (typeid_is_oid) {
        /*
         * Copy the OID from the type ID object field to the type ID struct
         * field.
         */
        ret = der_copy_oid(tos[3 + (element-1)*3].ptr, DPO(data, ttypeid->offset));
    } else
        enotsup = 1;

    /*
     * If the app did not already encode the open type, we can't help it if we
     * don't know what it is.
     */
    if (enotsup)
        return ENOTSUP;

    tactual_type = &tos[(element-1)*3 + 4];

    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        struct heim_base_data *os = DPO(data, topentype->offset);
        const void * const *d = DPOC(data, t->offset + sizeof(element));

        while (sizeof(void *) != sizeof(element) &&
               ((uintptr_t)d) % sizeof(void *) != 0) {
            d = (void *)(((char *)d) + sizeof(element));
        }

        os->length = _asn1_length(tactual_type->ptr, *d);
        if ((os->data = malloc(os->length)) == NULL)
            return ENOMEM;
        ret = _asn1_encode(tactual_type->ptr, (os->length - 1) + (unsigned char *)os->data, os->length, *d, &sz);
    } else {
        struct heim_base_data *os;
        const void * const *val =
            DPOC(data, t->offset + sizeof(element) + sizeof(*lenp));

        if ((os = calloc(len, sizeof(*os))) == NULL)
            return ENOMEM;

        *lenp = len;
        for (i = 0; ret == 0 && i < len; i++) {
            os[i].length = _asn1_length(tactual_type->ptr, val[i]);
            if ((os[i].data = malloc(os[i].length)) == NULL)
                ret = ENOMEM;
            if (ret == 0)
                ret = _asn1_encode(tactual_type->ptr, (os[i].length - 1) + (unsigned char *)os[i].data, os[i].length,
                                   val[i], &sz);
        }
        if (ret) {
            for (i = 0; i < (*lenp); i++)
                free(os[i].data);
            free(os);
            *lenp = 0;
            return ret;
        }
        *(struct heim_base_data **)DPO(data, topentype->offset + sizeof(len)) = os;
    }
    return ret;
}

int
_asn1_encode(const struct asn1_template *t, unsigned char *p, size_t len, const void *data, size_t *size)
{
    const struct asn1_template *tbase = t;
    size_t elements = A1_HEADER_LEN(t);
    int ret = 0;
    size_t oldlen = len;

    t += A1_HEADER_LEN(t);

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_OPENTYPE_OBJSET: {
            size_t opentypeid = t->tt & ((1<<10)-1);
            size_t opentype = (t->tt >> 10) & ((1<<10)-1);
            ret = _asn1_encode_open_type(t, data,
                                         template4member(tbase, opentypeid),
                                         template4member(tbase, opentype));
            if (ret)
                return ret;
            break;
        }
        case A1_OP_NAME: break;
	case A1_OP_DEFVAL: break;
	case A1_OP_TYPE_DECORATE_EXTERN: break;
	case A1_OP_TYPE_DECORATE: break;
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    size_t newsize;
	    const void *el = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **pel = (void **)el;
		if (*pel == NULL)
		    break;
		el = *pel;
            } else if ((t->tt & A1_FLAG_DEFAULT) && elements > 1) {
                const struct asn1_template *tdefval = t - 1;
                /* Compare tdefval to whatever's at `el' */
                if (tdefval->tt & A1_DV_BOOLEAN) {
                    const int *i = (void *)(char *)el;

                    if ((*i && tdefval->ptr) || (!*i && !tdefval->ptr))
                        break;
                } else if (tdefval->tt & A1_DV_INTEGER64) {
                    const int64_t *i = (void *)(char *)el;

                    if (*i == (int64_t)(intptr_t)tdefval->ptr)
                        break;
                } else if (tdefval->tt & A1_DV_INTEGER32) {
                    const int32_t *i = (void *)(char *)el;

                    if ((int64_t)(intptr_t)tdefval->ptr <= INT_MAX &&
                        (int64_t)(intptr_t)tdefval->ptr >= INT_MIN &&
                        *i == (int32_t)(intptr_t)tdefval->ptr)
                        break;
                } else if (tdefval->tt & A1_DV_INTEGER) {
                    const struct heim_integer *i = (void *)(char *)el;

                    if (der_heim_integer_cmp(i, tdefval->ptr) == 0)
                        break;
                } else if (tdefval->tt & A1_DV_UTF8STRING) {
                    const char * const *s = el;

                    if (*s && strcmp(*s, tdefval->ptr) == 0)
                        break;
                } else {
                    abort();
                }
            }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		ret = _asn1_encode(t->ptr, p, len, el, &newsize);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		ret = (f->encode)(p, len, el, &newsize);
	    }

	    if (ret)
		return ret;
	    p -= newsize; len -= newsize;

	    break;
	}
	case A1_OP_TAG: {
	    const void *olddata = data;
	    size_t l, datalen = 0;
            int replace_tag = 0;

            /*
             * XXX If this type (chasing t->ptr through IMPLICIT tags, if this
             * one is too) till we find a non-TTag) is a [UNIVERSAL SET] type,
             * then we have to sort [a copy of] its template by tag, then
             * encode the SET using that sorted template.  These SETs will
             * generally be small, so when they are we might want to allocate
             * the copy on the stack and insertion sort it.  We'll need a
             * utility function to do all of this.
             */

	    data = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **el = (void **)data;
		if (*el == NULL) {
		    data = olddata;
		    break;
		}
		data = *el;
            } else if ((t->tt & A1_FLAG_DEFAULT) && elements > 1) {
                const struct asn1_template *tdefval = t - 1;
                int exclude = 0;

                /* Compare tdefval to whatever's at `data' */
                if (tdefval->tt & A1_DV_BOOLEAN) {
                    const int *i = (void *)(char *)data;

                    if ((*i && tdefval->ptr) || (!*i && !tdefval->ptr))
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_INTEGER64) {
                    const int64_t *i = (void *)(char *)data;

                    if (*i == (int64_t)(intptr_t)tdefval->ptr)
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_INTEGER32) {
                    const int32_t *i = (void *)(char *)data;

                    if ((int64_t)(intptr_t)tdefval->ptr <= INT_MAX &&
                        (int64_t)(intptr_t)tdefval->ptr >= INT_MIN &&
                        *i == (int32_t)(intptr_t)tdefval->ptr)
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_INTEGER) {
                    const struct heim_integer *i = (void *)(char *)data;

                    if (der_heim_integer_cmp(i, tdefval->ptr) == 0)
                        break;
                } else if (tdefval->tt & A1_DV_UTF8STRING) {
                    const char * const *s = data;

                    if (*s && strcmp(*s, tdefval->ptr) == 0)
                        exclude = 1;
                } else {
                    abort();
                }
                if (exclude) {
                    data = olddata;
                    break;
                }
            }

            replace_tag = (t->tt & A1_FLAG_IMPLICIT) && is_tagged(t->ptr);

            /* IMPLICIT tags need special handling (see gen_encode.c) */
            if (replace_tag) {
                unsigned char *pfree, *psave = p;
                Der_class found_class;
                Der_type found_type = 0;
                unsigned int found_tag;
                size_t lensave = len;
                size_t oldtaglen = 0;
                size_t taglen = der_length_tag(A1_TAG_TAG(t->tt));;

                /* Allocate a buffer at least as big as we need */
                len = _asn1_length(t->ptr, data) + taglen;
                if ((p = pfree = malloc(len)) == NULL) {
                    ret = ENOMEM;
                } else {
                    /*
                     * Encode into it (with the wrong tag, which we'll replace
                     * below).
                     */
                    p += len - 1;
                    ret = _asn1_encode(t->ptr, p, len, data, &datalen);
                }
                if (ret == 0) {
                    /* Get the old tag and, critically, its length */
                    len -= datalen; p -= datalen;
                    ret = der_get_tag(p + 1, datalen, &found_class, &found_type,
                                      &found_tag, &oldtaglen);
                }
                if (ret == 0) {
                    /* Drop the old tag */
                    len += oldtaglen; p += oldtaglen;
                    /* Put the new tag */
                    ret = der_put_tag(p, len,
                                      A1_TAG_CLASS(t->tt),
                                      found_type,
                                      A1_TAG_TAG(t->tt), &l);
                }
                if (ret == 0) {
                    /* Copy the encoding where it belongs */
                    psave -= (datalen + l - oldtaglen);
                    lensave -= (datalen + l - oldtaglen);
                    memcpy(psave + 1, p + 1 - l, datalen + l - oldtaglen);
                    p = psave;
                    len = lensave;
                }
                free(pfree);
            } else {
                /* Easy case */
                ret = _asn1_encode(t->ptr, p, len, data, &datalen);
                if (ret)
                    return ret;

                len -= datalen; p -= datalen;

                ret = der_put_length_and_tag(p, len, datalen,
                                             A1_TAG_CLASS(t->tt),
                                             A1_TAG_TYPE(t->tt),
                                             A1_TAG_TAG(t->tt), &l);
                if (ret == 0) {
                    p -= l; len -= l;
                }
            }
	    if (ret)
		return ret;

	    data = olddata;

	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    size_t newsize;
	    const void *el = DPOC(data, t->offset);

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR();
		return ASN1_PARSE_ERROR;
	    }

	    ret = (asn1_template_prim[type].encode)(p, len, el, &newsize);
	    if (ret)
		return ret;
	    p -= newsize; len -= newsize;

	    break;
	}
	case A1_OP_SETOF: {
	    const struct template_of *el = DPOC(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    heim_octet_string *val;
	    unsigned char *elptr = el->val;
	    size_t i, totallen;

	    if (el->len == 0)
		break;

	    if (el->len > UINT_MAX/sizeof(val[0]))
		return ERANGE;

	    val = calloc(el->len, sizeof(val[0]));
	    if (val == NULL)
		return ENOMEM;

	    for(totallen = 0, i = 0; i < el->len; i++) {
		unsigned char *next;
		size_t l;

		val[i].length = _asn1_length(t->ptr, elptr);
		if (val[i].length) {
		    val[i].data = malloc(val[i].length);
		    if (val[i].data == NULL) {
			ret = ENOMEM;
			break;
		    }
		}

		ret = _asn1_encode(t->ptr, DPO(val[i].data, val[i].length - 1),
				   val[i].length, elptr, &l);
		if (ret)
		    break;

		next = elptr + ellen;
		if (next < elptr) {
		    ret = ASN1_OVERFLOW;
		    break;
		}
		elptr = next;
		totallen += val[i].length;
	    }
	    if (ret == 0 && totallen > len)
		ret = ASN1_OVERFLOW;
	    if (ret) {
		for (i = 0; i < el->len; i++)
		    free(val[i].data);
		free(val);
		return ret;
	    }

	    len -= totallen;

	    qsort(val, el->len, sizeof(val[0]), _heim_der_set_sort);

	    i = el->len - 1;
	    do {
		p -= val[i].length;
		memcpy(p + 1, val[i].data, val[i].length);
		free(val[i].data);
	    } while(i-- > 0);
	    free(val);

	    break;

	}
	case A1_OP_SEQOF: {
	    struct template_of *el = DPO(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    size_t newsize;
	    unsigned int i;
	    unsigned char *elptr = el->val;

	    if (el->len == 0)
		break;

	    elptr += ellen * (el->len - 1);

	    for (i = 0; i < el->len; i++) {
		ret = _asn1_encode(t->ptr, p, len,
				   elptr,
				   &newsize);
		if (ret)
		    return ret;
		p -= newsize; len -= newsize;
		elptr -= ellen;
	    }

	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t bsize = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
	    size_t pos;
	    unsigned char c = 0;
	    unsigned int bitset = 0;
	    int rfc1510 = (bmember->tt & A1_HBF_RFC1510);

	    bmember += belements;

	    if (rfc1510)
		pos = 31;
	    else
		pos = bmember->offset;

	    while (belements && len) {
		while (bmember->offset / 8 < pos / 8) {
		    if (rfc1510 || bitset || c) {
			if (len < 1)
			    return ASN1_OVERFLOW;
			*p-- = c; len--;
		    }
		    c = 0;
		    pos -= 8;
		}
		_asn1_bmember_put_bit(&c, data, bmember->offset, bsize, &bitset);
		belements--; bmember--;
	    }
	    if (rfc1510 || bitset) {
		if (len < 1)
		    return ASN1_OVERFLOW;
		*p-- = c; len--;
	    }

	    if (len < 1)
		return ASN1_OVERFLOW;
	    if (rfc1510 || bitset == 0)
		*p-- = 0;
	    else
		*p-- = bitset - 1;

	    len--;

	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const unsigned int *element = DPOC(data, choice->offset);
	    size_t datalen;
	    const void *el;

	    if (*element > A1_HEADER_LEN(choice)) {
		printf("element: %d\n", *element);
		return ASN1_PARSE_ERROR;
	    }

	    if (*element == 0) {
                if (choice->tt) {
                    /* This is an extensible CHOICE */
                    ret += der_put_octet_string(p, len,
                                                DPOC(data, choice->tt), &datalen);
                    len -= datalen; p -= datalen;
                } /* else this is really an error -- XXX what to do? */
	    } else {
		choice += *element;
		el = DPOC(data, choice->offset);
		ret = _asn1_encode(choice->ptr, p, len, el, &datalen);
		if (ret)
		    return ret;
                len -= datalen; p -= datalen;
	    }

	    break;
	}
	default:
	    ABORT_ON_ERROR();
	}
	t--;
	elements--;
    }
    if (size)
	*size = oldlen - len;

    return 0;
}

static size_t
_asn1_length_open_type_helper(const struct asn1_template *t,
                              size_t sz)
{
    const struct asn1_template *tinner = t->ptr;

    switch (t->tt & A1_OP_MASK) {
    case A1_OP_TAG:
        /* XXX Not tail-recursive :( */
        sz = _asn1_length_open_type_helper(tinner, sz);
        sz += der_length_len(sz);
        sz += der_length_tag(A1_TAG_TAG(t->tt));
        return sz;
    default:
        return sz;
    }
}

static size_t
_asn1_length_open_type_id(const struct asn1_template *t,
                          const void *data)
{
    struct asn1_template pretend[2] = {
	{ 0, 0, ((void*)(uintptr_t)1) },
    };
    pretend[1] = *t;
    while ((t->tt & A1_OP_MASK) == A1_OP_TAG)
        t = t->ptr;
    pretend[0].offset = t->offset;
    return _asn1_length(pretend, data);
}

/* See commentary in _asn1_encode_open_type() */
static size_t
_asn1_length_open_type(const struct asn1_template *tbase,
                       const struct asn1_template *t,
                       const void *data,
                       const struct asn1_template *ttypeid,
                       const struct asn1_template *topentype)
{
    const struct asn1_template *ttypeid_univ = ttypeid;
    const struct asn1_template *tactual_type;
    const struct asn1_template *tos = t->ptr;
    const unsigned int *lenp = NULL;
    unsigned int len = 1;
    size_t sz = 0;
    size_t i;
    int element = *(const int *)DPOC(data, t->offset);
    int typeid_is_oid = 0;
    int typeid_is_int = 0;

    /* If nothing to encode, we add nothing to the length */
    if (element == 0 || element >= A1_HEADER_LEN(tos) + 1)
        return 0;
    if (t->tt & A1_OS_OT_IS_ARRAY) {
        len = *(const unsigned int *)DPOC(data, t->offset + sizeof(element));
        if (!len)
            return 0;
    }

    /* Work out the type ID field's type */
    while (((ttypeid_univ->tt & A1_OP_MASK) == A1_OP_TAG &&
            A1_TAG_CLASS(ttypeid_univ->tt) == ASN1_C_CONTEXT) ||
           ((ttypeid_univ->tt & A1_OP_MASK) == A1_OP_TYPE)) {
        ttypeid_univ = ttypeid_univ->ptr;
        ttypeid_univ++;
    }
    switch (ttypeid_univ->tt & A1_OP_MASK) {
    case A1_OP_TAG:
        if (A1_TAG_CLASS(ttypeid_univ->tt) != ASN1_C_UNIV)
            return 0;
        switch (A1_TAG_TAG(ttypeid_univ->tt)) {
        case UT_OID:
            typeid_is_oid = 1;
            break;
        case UT_Integer: {
            const struct asn1_template *tint = ttypeid_univ->ptr;

            tint++;
            if ((tint->tt & A1_OP_MASK) != A1_OP_PARSE ||
                A1_PARSE_TYPE(tint->tt) != A1T_INTEGER)
                return 0;
            typeid_is_int = 1;
            break;
        }
        default: return 0;
        }
        break;
    default: return 0;
    }
    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        struct heim_base_data *os = DPO(data, topentype->offset);

        if (os->length && os->data)
            return 0;
    } else {
        struct heim_base_data **os = DPO(data, topentype->offset + sizeof(len));

        while (sizeof(void *) != sizeof(unsigned int) &&
               ((uintptr_t)os) % sizeof(void *) != 0)
            os = (void *)(((char *)os) + sizeof(unsigned int));

        lenp = DPOC(data, topentype->offset);
        if (*lenp == len && os[0]->length && os[0]->data)
            return 0;
    }

    /* Compute the size of the type ID field */
    if (typeid_is_int) {
        int64_t i8;
        int32_t i4;

        switch (ttypeid_univ->offset) {
        case 8:
            i8 = (intptr_t)t->ptr;
            sz = _asn1_length_open_type_id(ttypeid, &i8);
            i8 = 0;
            sz -= _asn1_length_open_type_id(ttypeid, &i8);
            break;
        case 4:
            i4 = (intptr_t)t->ptr;
            sz = _asn1_length_open_type_id(ttypeid, &i4);
            i4 = 0;
            sz -= _asn1_length_open_type_id(ttypeid, &i8);
            break;
        default:
            return 0;
        }
    } else if (typeid_is_oid) {
        heim_oid no_oid = { 0, 0 };

        sz = _asn1_length_open_type_id(ttypeid, tos[3 + (element - 1)*3].ptr);
        sz -= _asn1_length_open_type_id(ttypeid, &no_oid);
    }

    tactual_type = &tos[(element-1)*3 + 4];

    /* Compute the size of the encoded value(s) */
    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        const void * const *d = DPOC(data, t->offset + sizeof(element));

        while (sizeof(void *) != sizeof(element) &&
               ((uintptr_t)d) % sizeof(void *) != 0)
            d = (void *)(((char *)d) + sizeof(element));
        if (*d)
            sz += _asn1_length(tactual_type->ptr, *d);
    } else {
        size_t bodysz;
        const void * const * val =
            DPOC(data, t->offset + sizeof(element) + sizeof(*lenp));

        /* Compute the size of the encoded SET OF / SEQUENCE OF body */
        for (i = 0, bodysz = 0; i < len; i++) {
            if (val[i])
                bodysz += _asn1_length(tactual_type->ptr, val[i]);
        }

        /*
         * We now know the size of the body of the SET OF or SEQUENCE OF.  Now
         * we just need to count the length of all the TLs on the outside.
         */
        sz += _asn1_length_open_type_helper(topentype, bodysz);
    }
    return sz;
}

size_t
_asn1_length(const struct asn1_template *t, const void *data)
{
    const struct asn1_template *tbase = t;
    size_t elements = A1_HEADER_LEN(t);
    size_t ret = 0;

    t += A1_HEADER_LEN(t);

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_OPENTYPE_OBJSET: {
            size_t opentypeid = t->tt & ((1<<10)-1);
            size_t opentype = (t->tt >> 10) & ((1<<10)-1);
            ret += _asn1_length_open_type(tbase, t, data,
                                          template4member(tbase, opentypeid),
                                          template4member(tbase, opentype));
            break;
        }
        case A1_OP_NAME: break;
	case A1_OP_DEFVAL: break;
	case A1_OP_TYPE_DECORATE_EXTERN: break;
	case A1_OP_TYPE_DECORATE: break;
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    const void *el = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **pel = (void **)el;
		if (*pel == NULL)
		    break;
		el = *pel;
            } else if ((t->tt & A1_FLAG_DEFAULT) && elements > 1) {
                const struct asn1_template *tdefval = t - 1;

                /* Compare tdefval to whatever's at `el' */
                if (tdefval->tt & A1_DV_BOOLEAN) {
                    const int *i = (void *)(char *)el;

                    if ((*i && tdefval->ptr) || (!*i && !tdefval->ptr))
                        break;
                } else if (tdefval->tt & A1_DV_INTEGER64) {
                    const int64_t *i = (void *)(char *)el;

                    if (*i == (int64_t)(intptr_t)tdefval->ptr)
                        break;
                } else if (tdefval->tt & A1_DV_INTEGER32) {
                    const int32_t *i = (void *)(char *)el;

                    if ((int64_t)(intptr_t)tdefval->ptr <= INT_MAX &&
                        (int64_t)(intptr_t)tdefval->ptr >= INT_MIN &&
                        *i == (int32_t)(intptr_t)tdefval->ptr)
                        break;
                } else if (tdefval->tt & A1_DV_INTEGER) {
                    const struct heim_integer *i = (void *)(char *)el;

                    if (der_heim_integer_cmp(i, tdefval->ptr) == 0)
                        break;
                } else if (tdefval->tt & A1_DV_UTF8STRING) {
                    const char * const *s = el;

                    if (*s && strcmp(*s, tdefval->ptr) == 0)
                        break;
                } else {
                    abort();
                }
            }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		ret += _asn1_length(t->ptr, el);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		ret += (f->length)(el);
	    }
	    break;
	}
	case A1_OP_TAG: {
	    size_t datalen;
	    const void *olddata = data;
            size_t oldtaglen = 0;

	    data = DPO(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **el = (void **)data;
		if (*el == NULL) {
		    data = olddata;
		    break;
		}
		data = *el;
	    } else if ((t->tt & A1_FLAG_DEFAULT) && elements > 1) {
                const struct asn1_template *tdefval = t - 1;
                int exclude = 0;

                /* Compare tdefval to whatever's at `data' */
                if (tdefval->tt & A1_DV_BOOLEAN) {
                    const int *i = (void *)(char *)data;

                    if ((*i && tdefval->ptr) || (!*i && !tdefval->ptr))
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_INTEGER64) {
                    const int64_t *i = (void *)(char *)data;

                    if (*i == (int64_t)(intptr_t)tdefval->ptr)
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_INTEGER32) {
                    const int32_t *i = (void *)(char *)data;

                    if ((int64_t)(intptr_t)tdefval->ptr <= INT_MAX &&
                        (int64_t)(intptr_t)tdefval->ptr >= INT_MIN &&
                        *i == (int32_t)(intptr_t)tdefval->ptr)
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_INTEGER) {
                    const struct heim_integer *i = (void *)(char *)data;

                    if (der_heim_integer_cmp(i, tdefval->ptr) == 0)
                        exclude = 1;
                } else if (tdefval->tt & A1_DV_UTF8STRING) {
                    const char * const *s = data;

                    if (*s && strcmp(*s, tdefval->ptr) == 0)
                        exclude = 1;
                } else {
                    abort();
                }
                if (exclude) {
                    data = olddata;
                    break;
                }
            }

            if (t->tt & A1_FLAG_IMPLICIT)
                oldtaglen = inner_type_taglen(t->ptr);

	    datalen = _asn1_length(t->ptr, data);
	    ret += datalen;
	    ret += der_length_tag(A1_TAG_TAG(t->tt));
            ret += oldtaglen ? -oldtaglen : der_length_len(datalen);
	    data = olddata;
	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    const void *el = DPOC(data, t->offset);

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR();
		break;
	    }
	    ret += (asn1_template_prim[type].length)(el);
	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    const struct template_of *el = DPOC(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    const unsigned char *element = el->val;
	    unsigned int i;

	    for (i = 0; i < el->len; i++) {
		ret += _asn1_length(t->ptr, element);
		element += ellen;
	    }

	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t size = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
	    int rfc1510 = (bmember->tt & A1_HBF_RFC1510);

	    if (rfc1510) {
		ret += 5;
	    } else {

		ret += 1;

		bmember += belements;

		while (belements) {
		    if (_asn1_bmember_isset_bit(data, bmember->offset, size)) {
			ret += (bmember->offset / 8) + 1;
			break;
		    }
		    belements--; bmember--;
		}
	    }
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const unsigned int *element = DPOC(data, choice->offset);

	    if (*element > A1_HEADER_LEN(choice))
		break;

	    if (*element == 0) {
                if (choice->tt)
                    ret += der_length_octet_string(DPOC(data, choice->tt));
	    } else {
		choice += *element;
		ret += _asn1_length(choice->ptr, DPOC(data, choice->offset));
	    }
	    break;
	}
	default:
	    ABORT_ON_ERROR();
	    break;
	}
	elements--;
	t--;
    }
    return ret;
}

/* See commentary in _asn1_decode_open_type() */
static void
_asn1_free_open_type(const struct asn1_template *t, /* object set template */
                     void *data)
{
    const struct asn1_template *tactual_type;
    const struct asn1_template *tos = t->ptr;
    unsigned int *lenp = NULL;  /* Pointer to array length field */
    unsigned int len = 1;       /* Array length */
    size_t i;
    void **dp;
    void **val;
    int *elementp = DPO(data, t->offset);   /* Choice enum pointer */

    /* XXX We assume sizeof(enum) == sizeof(int) */
    if (!*elementp || *elementp >= A1_HEADER_LEN(tos) + 1)
        return; /* Unknown choice -> it's not decoded, nothing to free here */
    tactual_type = tos[3*(*elementp - 1) + 4].ptr;

    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        dp = DPO(data, t->offset + sizeof(*elementp));
        while (sizeof(void *) != sizeof(*elementp) &&
               ((uintptr_t)dp) % sizeof(void *) != 0)
            dp = (void *)(((char *)dp) + sizeof(*elementp));
        if (*dp) {
            _asn1_free(tactual_type, *dp);
            free(*dp);
            *dp = NULL;
        }
        return;
    }

    lenp = DPO(data, t->offset + sizeof(*elementp));
    len = *lenp;
    dp = DPO(data, t->offset + sizeof(*elementp) + sizeof(*lenp));
    while (sizeof(void *) != sizeof(*elementp) &&
           ((uintptr_t)dp) % sizeof(void *) != 0)
        dp = (void *)(((char *)dp) + sizeof(*elementp));
    val = *dp;

    for (i = 0; i < len; i++) {
        if (val[i]) {
            _asn1_free(tactual_type, val[i]);
            free(val[i]);
        }
    }
    free(val);
    *lenp = 0;
    *dp = NULL;
}

void
_asn1_free(const struct asn1_template *t, void *data)
{
    size_t elements = A1_HEADER_LEN(t);

    if (t->tt & A1_HF_PRESERVE)
	der_free_octet_string(data);

    t++;

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_OPENTYPE_OBJSET: {
            _asn1_free_open_type(t, data);
            break;
        }
        case A1_OP_NAME: break;
	case A1_OP_DEFVAL: break;
	case A1_OP_TYPE_DECORATE_EXTERN:
	case A1_OP_TYPE_DECORATE:
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    void *el = DPO(data, t->offset);
            void **pel = (void **)el;

	    if (t->tt & A1_FLAG_OPTIONAL) {
		if (*pel == NULL)
		    break;
		el = *pel;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE || (t->tt & A1_OP_MASK) == A1_OP_TYPE_DECORATE) {
		_asn1_free(t->ptr, el);
	    } else if ((t->tt & A1_OP_MASK) == A1_OP_TYPE_EXTERN) {
		const struct asn1_type_func *f = t->ptr;
		(f->release)(el);
	    } else {
                /* A1_OP_TYPE_DECORATE_EXTERN */
		const struct asn1_type_func *f = t->ptr;

                if (f && f->release)
                    (f->release)(el);
                else if (f)
                    memset(el, 0, f->size);
	    }
	    if (t->tt & A1_FLAG_OPTIONAL) {
		free(el);
                *pel = NULL;
            }

	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    void *el = DPO(data, t->offset);

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR();
		break;
	    }
	    (asn1_template_prim[type].release)(el);
	    break;
	}
	case A1_OP_TAG: {
	    void *el = DPO(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
                void **pel = (void **)el;

		if (*pel == NULL)
		    break;
                _asn1_free(t->ptr, *pel);
		free(*pel);
                *pel = NULL;
            } else {
                _asn1_free(t->ptr, el);
            }

	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    struct template_of *el = DPO(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    unsigned char *element = el->val;
	    unsigned int i;

	    for (i = 0; i < el->len; i++) {
		_asn1_free(t->ptr, element);
		element += ellen;
	    }
	    free(el->val);
	    el->val = NULL;
	    el->len = 0;

	    break;
	}
	case A1_OP_BMEMBER:
	    break;
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const unsigned int *element = DPOC(data, choice->offset);

	    if (*element > A1_HEADER_LEN(choice))
		break;

	    if (*element == 0) {
                /*
                 * If choice->tt != 0 then this is an extensible choice, and
                 * the offset choice->tt is the offset to u.ellipsis.
                 */
                if (choice->tt != 0)
                    der_free_octet_string(DPO(data, choice->tt));
                /*
                 * Else this was a not-fully initialized CHOICE.  We could
                 * stand to memset clear the rest of it though...
                 */
	    } else {
		choice += *element;
		_asn1_free(choice->ptr, DPO(data, choice->offset));
	    }
	    break;
	}
	default:
	    ABORT_ON_ERROR();
	    break;
	}
	t++;
	elements--;
    }
}

static char *
getindent(int flags, unsigned int i)
{
    char *s;

    if (!(flags & ASN1_PRINT_INDENT) ||  i == 0)
        return NULL;
    if (i > 128)
        i = 128;
    if ((s = malloc(i * 2 + 2)) == NULL)
        return NULL;
    s[0] = '\n';
    s[i * 2 + 1] = '\0';
    memset(s + 1, ' ', i * 2);
    return s;
}

static struct rk_strpool *_asn1_print(const struct asn1_template *,
                                      struct rk_strpool *,
                                      int,
                                      unsigned int,
                                      const void *,
                                      const heim_octet_string *);

/* See commentary in _asn1_decode_open_type() */
static struct rk_strpool *
_asn1_print_open_type(const struct asn1_template *t, /* object set template */
                      struct rk_strpool *r,
                      int flags,
                      unsigned int indent,
                      const void *data,
                      const char *opentype_name)
{
    const struct asn1_template *tactual_type;
    const struct asn1_template *tos = t->ptr;
    const unsigned int *lenp = NULL;  /* Pointer to array length field */
    unsigned int len = 1;       /* Array length */
    size_t i;
    const void * const *dp;
    const void * const *val;
    const int *elementp = DPOC(data, t->offset);   /* Choice enum pointer */
    char *indents = getindent(flags, indent);

    /* XXX We assume sizeof(enum) == sizeof(int) */
    if (!*elementp || *elementp >= A1_HEADER_LEN(tos) + 1) {
        r = rk_strpoolprintf(r, ",%s\"_%s_choice\":\"_ERROR_DECODING_\"",
                             indents ? indents : "", opentype_name);
        free(indents);
        return r;
    }
    tactual_type = tos[3*(*elementp - 1) + 4].ptr;

    r = rk_strpoolprintf(r, ",%s\"_%s_choice\":\"%s\"",
                         indents ? indents : "", opentype_name,
                         (const char *)tos[3*(*elementp - 1) + 2].ptr);
    if (!r) {
        free(indents);
        return r;
    }

    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        dp = DPOC(data, t->offset + sizeof(*elementp));
        while (sizeof(void *) != sizeof(*elementp) &&
               ((uintptr_t)dp) % sizeof(void *) != 0)
            dp = (void *)(((char *)dp) + sizeof(*elementp));
        if (*dp) {
            struct rk_strpool *r2 = NULL;
            char *s = NULL;

            r2 = _asn1_print(tactual_type, r2, flags, indent + 1, *dp, NULL);
            if (r2 == NULL) {
                r = rk_strpoolprintf(r, ",%s\"_%s\":\"_ERROR_FORMATTING_\"",
                                     indents ? indents : "", opentype_name);
                free(indents);
                return r;
            }
            s = rk_strpoolcollect(r2);
            if (s)
                r = rk_strpoolprintf(r, ",%s\"_%s\":%s",
                                     indents ? indents : "", opentype_name, s);
            free(s);
        }
	free(indents);
        return r;
    }

    lenp = DPOC(data, t->offset + sizeof(*elementp));
    len = *lenp;
    dp = DPOC(data, t->offset + sizeof(*elementp) + sizeof(*lenp));
    while (sizeof(void *) != sizeof(*elementp) &&
           ((uintptr_t)dp) % sizeof(void *) != 0)
        dp = (void *)(((char *)dp) + sizeof(*elementp));
    val = *dp;

    r = rk_strpoolprintf(r, ",%s\"_%s\":[", indents ? indents : "",
                         opentype_name);
    free(indents);
    indents = getindent(flags, indent + 1);
    r = rk_strpoolprintf(r, "%s", indents ? indents : "");
    for (i = 0; r && i < len; i++) {
        struct rk_strpool *r2 = NULL;
        char *s = NULL;;

        if (val[i]) {
            r2 = _asn1_print(tactual_type, r2, flags, indent + 2, val[i], NULL);
            if (r2 == NULL) {
                rk_strpoolfree(r);
                free(indents);
                return NULL;
            }
        }
        if (i)
            r = rk_strpoolprintf(r, ",%s", indents ? indents : "");
        if (r)
            r = rk_strpoolprintf(r, "%s", (s = rk_strpoolcollect(r2)));
        free(s);
    }
    free(indents);
    return rk_strpoolprintf(r, "]");
}

static struct rk_strpool *
_asn1_print(const struct asn1_template *t,
            struct rk_strpool *r,
            int flags,
            unsigned int indent,
            const void *data,
            const heim_octet_string *saved)
{
    const struct asn1_template *tbase = t;
    const struct asn1_template *tnames;
    size_t nelements = A1_HEADER_LEN(t);
    size_t elements = nelements;
    size_t nnames = 0;
    char *indents = getindent(flags, indent);

    for (t += nelements; t > tbase && (t->tt & A1_OP_MASK) == A1_OP_NAME; t--)
        nnames++;

    tnames = tbase + nelements - nnames + 1;

    if (!r)
        r = rk_strpoolprintf(r, "%s", "");

    if (nnames)
        r = rk_strpoolprintf(r, "%s{\"_type\":\"%s\"",
                             indents ? indents : "",
                             (const char *)(tnames++)->ptr);
    if (saved && r) {
        char *s = der_print_octet_string(data, 0);

        if (!s) {
            rk_strpoolfree(r);
            free(indents);
            return NULL;
        }
        r = rk_strpoolprintf(r, ",%s\"_save\":\"%s\"",
                             indents ? indents : "", s);
        free(s);
    }
    saved = NULL;
    if (tbase->tt & A1_HF_PRESERVE)
        saved = data;

    t = tbase + 1;
    while (r && elements && (t->tt & A1_OP_MASK) != A1_OP_NAME) {
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_NAME:
            continue;
	case A1_OP_DEFVAL:
            t++;
            elements--;
            continue;
        case A1_OP_OPENTYPE_OBJSET: {
            size_t opentype = (t->tt >> 10) & ((1<<10)-1);
            r = _asn1_print_open_type(t, r, flags, indent + 1, data,
                                      tbase[(nelements - nnames) + 2 + opentype].ptr);
            t++;
            elements--;
            continue;
        }
        default: break;
        }
        if (nnames &&
            (t->tt & A1_OP_MASK) != A1_OP_TYPE_DECORATE_EXTERN &&
            (t->tt & A1_OP_MASK) != A1_OP_TYPE_DECORATE)
            r = rk_strpoolprintf(r, ",%s\"%s\":",
                                 indents ? indents : "",
                                 (const char *)(tnames++)->ptr);
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_OPENTYPE_OBJSET:
            break;
        case A1_OP_NAME: break;
	case A1_OP_DEFVAL: break;
	case A1_OP_TYPE_DECORATE_EXTERN: break;
	case A1_OP_TYPE_DECORATE: break; /* We could probably print this though */
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    const void *el = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		const void * const *pel = (const void *const *)el;
		if (*pel == NULL) {
                    r = rk_strpoolprintf(r, "null");
		    break;
                }
		el = *pel;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		r = _asn1_print(t->ptr, r, flags, indent + 1, el, saved);
	    } else {
		const struct asn1_type_func *f = t->ptr;
                char *s = NULL;

                s = (f->print)(el, 0);
                if (s == NULL) {
                    rk_strpoolfree(r);
                    free(indents);
                    return NULL;
                }
		r = rk_strpoolprintf(r, "%s", s);
                free(s);
	    }
	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    const void *el = DPOC(data, t->offset);
            char *s = NULL;

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR();
		break;
	    }

            if (type == A1T_IMEMBER && t->ptr) {
                /* Enumeration.  Use the symbolic name of this value */
                const struct asn1_template *tenum = t->ptr;
                size_t left = 0;
                size_t right = A1_HEADER_LEN(tenum);
                size_t mid;
                uint32_t v = *(unsigned int *)el;
                int c = -1;

                while (left <= right) {
                    mid = (left + right) >> 1;

                    if ((tenum[mid].tt & A1_OP_MASK) != A1_OP_NAME)
                        break;
                    c = v - tenum[mid].offset;
                    if (c < 0) {
                        if (mid)
                            right = mid - 1;
                        else
                            break;
                    } else if (c > 0) {
                        left = mid + 1;
                    } else {
                        break;
                    }
                }
                if (c == 0) {
                    r = rk_strpoolprintf(r, "\"%s\"", (const char *)tenum[mid].ptr);
                    break;
                }
            }
	    s = (asn1_template_prim[type].print)(el, flags);
            switch (type) {
            case A1T_OID:
            case A1T_IMEMBER:
            case A1T_BOOLEAN:
            case A1T_INTEGER:
            case A1T_INTEGER64:
            case A1T_UNSIGNED:
            case A1T_UNSIGNED64:
                if (s)
                    r = rk_strpoolprintf(r, "%s", s);
                break;
            default: {
                char *s2 = NULL;

                if (s)
                    (void) rk_strasvis(&s2, s, VIS_CSTYLE|VIS_TAB|VIS_NL, "\"");
                free(s);
                s = s2;
                if (s)
                    r = rk_strpoolprintf(r, "\"%s\"", s);
            }
            }
            if (!s) {
                rk_strpoolfree(r);
                free(indents);
                return NULL;
            }
            free(s);
	    break;
	}
	case A1_OP_TAG: {
	    const void *el = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		const void * const *pel = (const void * const *)el;
		if (*pel == NULL) {
                    r = rk_strpoolprintf(r, "null");
		    break;
                }
		el = *pel;
	    }

	    r = _asn1_print(t->ptr, r, flags, indent + 1, el, saved);
	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    const struct template_of *el = DPOC(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    const unsigned char *element = el->val;
	    unsigned int i;

            r = rk_strpoolprintf(r, "%s[", indents ? indents : "");
	    for (i = 0; r && i < el->len; i++) {
                if (i)
                    r = rk_strpoolprintf(r, ",%s", indents ? indents : "");
		r = _asn1_print(t->ptr, r, flags, indent + 1, element, saved);
		element += ellen;
	    }
            if (r)
                r = rk_strpoolprintf(r, "]");
	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t size = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
            int first = 1;

            bmember += belements;
            r = rk_strpoolprintf(r, "%s[", indents ? indents : "");
            while (r && belements) {
                if (r && _asn1_bmember_isset_bit(data, bmember->offset, size)) {
                    if (!first)
                        r = rk_strpoolprintf(r, ",");
                    first = 0;
                    r = rk_strpoolprintf(r, "%s\"%s\"", indents ? indents : "",
                                         (const char *)bmember->ptr);
                }
                belements--; bmember--;
	    }
            if (r)
                r = rk_strpoolprintf(r, "]");
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const unsigned int *element = DPOC(data, choice->offset);
            unsigned int nchoices = ((uintptr_t)choice->ptr) >> 1;

	    if (*element > A1_HEADER_LEN(choice)) {
                r = rk_strpoolprintf(r, "null");
            } else if (*element == 0) {
                /* XXX If choice->tt then we should print the u.ellipsis */
                r = rk_strpoolprintf(r, "null");
	    } else {
		choice += *element;
                r = rk_strpoolprintf(r, "%s{\"_choice\":\"%s\",%s\"value\":",
                                     indents ? indents : "",
                                     (const char *)choice[nchoices].ptr,
                                     indents ? indents : "");
                if (r)
                    r = _asn1_print(choice->ptr, r, flags, indent + 1,
                                    DPOC(data, choice->offset), NULL);
                if (r)
                    r = rk_strpoolprintf(r, "}");
	    }
	    break;
	}
	default:
	    ABORT_ON_ERROR();
	    break;
	}
	t++;
	elements--;
    }
    free(indents);
    if (nnames && r)
        return rk_strpoolprintf(r, "}");
    return r;
}

char *
_asn1_print_top(const struct asn1_template *t,
                int flags,
                const void *data)
{
    struct rk_strpool *r = _asn1_print(t, NULL, flags, 0, data, NULL);

    if (r == NULL)
        return NULL;
    return rk_strpoolcollect(r);
}

/* See commentary in _asn1_decode_open_type() */
static int
_asn1_copy_open_type(const struct asn1_template *t, /* object set template */
                     const void *from,
                     void *to)
{
    const struct asn1_template *tactual_type;
    const struct asn1_template *tos = t->ptr;
    size_t i;
    const void * const *dfromp;
    const void * const *valfrom;
    const unsigned int *lenfromp;
    void **dtop;
    void **valto;
    unsigned int *lentop;
    unsigned int len;
    const int *efromp = DPO(from, t->offset);
    int *etop = DPO(to, t->offset);
    int ret = 0;

    /* XXX We assume sizeof(enum) == sizeof(int) */
    if (!*efromp || *efromp >= A1_HEADER_LEN(tos) + 1) {
        if ((t->tt & A1_OS_OT_IS_ARRAY))
            memset(etop, 0, sizeof(int) + sizeof(unsigned int) + sizeof(void *));
        else
            memset(etop, 0, sizeof(int) + sizeof(void *));
        return 0; /* Unknown choice -> not copied */
    }
    tactual_type = &tos[3*(*efromp - 1) + 4];

    if (!(t->tt & A1_OS_OT_IS_ARRAY)) {
        dfromp = DPO(from, t->offset + sizeof(*efromp));
        while (sizeof(void *) != sizeof(*efromp) &&
               ((uintptr_t)dfromp) % sizeof(void *) != 0)
            dfromp = (void *)(((char *)dfromp) + sizeof(*efromp));
        if (!*dfromp)
            return 0;

        dtop = DPO(to, t->offset + sizeof(*etop));
        while (sizeof(void *) != sizeof(*etop) &&
               ((uintptr_t)dtop) % sizeof(void *) != 0)
            dtop = (void *)(((char *)dtop) + sizeof(*etop));

        if ((*dtop = calloc(1, tactual_type->offset)) == NULL)
            ret = ENOMEM;
        if (ret == 0)
            ret = _asn1_copy(tactual_type->ptr, *dfromp, *dtop);
        if (ret == 0)
            *etop = *efromp;
        return ret;
    }

    lenfromp = DPO(from, t->offset + sizeof(*efromp));
    dfromp   = DPO(from, t->offset + sizeof(*efromp) + sizeof(*lenfromp));
    valfrom  = *dfromp;
    lentop   = DPO(to,   t->offset + sizeof(*etop));
    dtop     = DPO(to,   t->offset + sizeof(*etop)   + sizeof(*lentop));

    *etop = *efromp;

    len = *lenfromp;
    *lentop = 0;
    *dtop = NULL;
    if ((valto = calloc(len, sizeof(valto[0]))) == NULL)
        ret = ENOMEM;
    for (i = 0, len = *lenfromp; ret == 0 && i < len; i++) {
        if (valfrom[i] == NULL) {
            valto[i] = NULL;
            continue;
        }
        if ((valto[i] = calloc(1, tactual_type->offset)) == NULL)
            ret = ENOMEM;
        else
            ret = _asn1_copy(tactual_type->ptr, valfrom[i], valto[i]);
        (*lentop)++;
    }

    for (i = 0; ret && i < (*lentop); i++) {
        if (valto[i]) {
            _asn1_free(tactual_type->ptr, valto[i]);
            free(valto[i]);
        }
    }
    if (ret) {
        free(valto);
        *lentop = 0;
    } else
        *dtop = valto;
    return ret;
}

int
_asn1_copy(const struct asn1_template *t, const void *from, void *to)
{
    size_t elements = A1_HEADER_LEN(t);
    int ret = 0;
    int preserve = (t->tt & A1_HF_PRESERVE);

    t++;

    if (preserve) {
	ret = der_copy_octet_string(from, to);
	if (ret)
	    return ret;
    }

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
        case A1_OP_OPENTYPE_OBJSET: {
            _asn1_copy_open_type(t, from, to);
            break;
        }
        case A1_OP_NAME: break;
	case A1_OP_DEFVAL: break;
	case A1_OP_TYPE_DECORATE_EXTERN:
	case A1_OP_TYPE_DECORATE:
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    const void *fel = DPOC(from, t->offset);
	    void *tel = DPO(to, t->offset);
	    void **ptel = (void **)tel;
	    size_t size;

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE ||
                (t->tt & A1_OP_MASK) == A1_OP_TYPE_DECORATE) {
		size = _asn1_sizeofType(t->ptr);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		size = f->size;
	    }

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **pfel = (void **)fel;
		if (*pfel == NULL)
		    break;
		fel = *pfel;

		tel = *ptel = calloc(1, size);
		if (tel == NULL)
		    return ENOMEM;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE ||
                (t->tt & A1_OP_MASK) == A1_OP_TYPE_DECORATE) {
		ret = _asn1_copy(t->ptr, fel, tel);
	    } else if ((t->tt & A1_OP_MASK) == A1_OP_TYPE_EXTERN) {
		const struct asn1_type_func *f = t->ptr;
                ret = (f->copy)(fel, tel);
	    } else {
		const struct asn1_type_func *f = t->ptr;

                /* A1_OP_TYPE_DECORATE_EXTERN */
                if (f && f->copy)
                    ret = (f->copy)(fel, tel);
                else if (f)
                    memset(tel, 0, f->size);
	    }

	    if (ret) {
		if (t->tt & A1_FLAG_OPTIONAL) {
		    free(*ptel);
		    *ptel = NULL;
		}
		return ret;
	    }
	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    const void *fel = DPOC(from, t->offset);
	    void *tel = DPO(to, t->offset);

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR();
		return ASN1_PARSE_ERROR;
	    }
	    ret = (asn1_template_prim[type].copy)(fel, tel);
	    if (ret)
		return ret;
	    break;
	}
	case A1_OP_TAG: {
	    const void *oldfrom = from;
	    void *oldto = to;
	    void **tel = NULL;

	    from = DPOC(from, t->offset);
	    to = DPO(to, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **fel = (void **)from;
		tel = (void **)to;
		if (*fel == NULL) {
		    from = oldfrom;
		    to = oldto;
		    break;
		}
		from = *fel;

		to = *tel = calloc(1, _asn1_sizeofType(t->ptr));
		if (to == NULL)
		    return ENOMEM;
	    }

	    ret = _asn1_copy(t->ptr, from, to);
	    if (ret) {
		if (tel) {
		    free(*tel);
		    *tel = NULL;
		}
		return ret;
	    }

	    from = oldfrom;
	    to = oldto;

	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    const struct template_of *fel = DPOC(from, t->offset);
	    struct template_of *tel = DPO(to, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    unsigned int i;

	    tel->val = calloc(fel->len, ellen);
	    if (tel->val == NULL && fel->len > 0)
		return ENOMEM;

	    tel->len = fel->len;

	    for (i = 0; i < fel->len; i++) {
		ret = _asn1_copy(t->ptr,
				 DPOC(fel->val, (i * ellen)),
				 DPO(tel->val, (i *ellen)));
		if (ret)
		    return ret;
	    }
	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t size = bmember->offset;
	    memcpy(to, from, size);
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const unsigned int *felement = DPOC(from, choice->offset);
	    unsigned int *telement = DPO(to, choice->offset);

	    if (*felement > A1_HEADER_LEN(choice))
		return ASN1_PARSE_ERROR;

	    *telement = *felement;

	    if (*felement == 0) {
                if (choice->tt)
                    ret = der_copy_octet_string(DPOC(from, choice->tt), DPO(to, choice->tt));
                /*
                 * Else we should really memset clear the rest of this choice,
                 * but we don't really know its size.
                 */
	    } else {
		choice += *felement;
		ret = _asn1_copy(choice->ptr,
				 DPOC(from, choice->offset),
				 DPO(to, choice->offset));
	    }
	    if (ret)
		return ret;
	    break;
	}
	default:
	    ABORT_ON_ERROR();
	    break;
	}
	t++;
	elements--;
    }
    return 0;
}

int
_asn1_decode_top(const struct asn1_template *t, unsigned flags, const unsigned char *p, size_t len, void *data, size_t *size)
{
    int ret;
    memset(data, 0, t->offset);
    ret = _asn1_decode(t, flags, p, len, data, size);
    if (ret)
	_asn1_free_top(t, data);

    return ret;
}

int
_asn1_copy_top(const struct asn1_template *t, const void *from, void *to)
{
    int ret;
    memset(to, 0, t->offset);
    ret = _asn1_copy(t, from, to);
    if (ret)
	_asn1_free_top(t, to);

    return ret;
}

void
_asn1_free_top(const struct asn1_template *t, void *data)
{
    _asn1_free(t, data);
    memset(data, 0, t->offset);
}
