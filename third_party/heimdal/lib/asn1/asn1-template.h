/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

/* asn1 templates */

#ifndef __TEMPLATE_H__
#define __TEMPLATE_H__

/*
 * TBD:
 * 
 *  - For OER also encode number of optional/default/extension elements into
 *    header entry's ptr field, not just the number of entries that follow it.
 *
 *  - For JER we'll need to encode encoding options (encode as array, encode as
 *    object, etc.)
 *
 *  - For open types we'll need to be able to indicate what encoding rules the
 *    type uses.
 *
 *  - We have too many bits for tags (20) and probably not enough for ops (4
 *    bits, and we've used all but one).
 */

/* header:
 *   HF  flags if not a BIT STRING type
 *   HBF flags if     a BIT STRING type
 *
 * ptr is count of elements
 * offset is size of struct
 */

/* tag:
 *  0..20 tag
 * 21     type
 * 22..23 class
 * 24..27 flags
 * 28..31 op
 *
 * ptr points to template for tagged type
 * offset is offset of struct field
 */

/* parse:
 *  0..11 type
 * 12..23 unused
 * 24..27 flags
 * 28..31 op
 *
 * ptr is NULL
 * offset is ...
 */

/* defval: (next template entry is defaulted)
 *
 *  DV    flags (ptr is or points to defval)
 *
 * ptr is default value or pointer to default value
 * offset is all ones
 */

/* name: first one is the name of the SET/SEQUENCE/CHOICE type
 *       subsequent ones are the name of the nth field
 *
 *  0..23 unused
 * 24..27 flags A1_NM_*
 * 28..31 op
 *
 * ptr is const char * pointer to the name as C string
 * offset is all zeros
 */

/* objset:
 *  0..9  open type ID entry index
 * 10..19 open type entry index
 * 20..23 unused
 * 24..27 flags A1_OS_*
 * 28..31 op
 *
 * ptr points to object set template
 * offset is the offset of the choice struct
 */

/* opentypeid: offset is zero
 *             ptr points to value if it is not an integer
 *             ptr   is the  value if it is     an integer
 *  0..23 unused
 * 24..27 flags A1_OTI_*
 * 28..31 op
 */

/* opentype: offset is sizeof C type for this open type choice
 *           ptr points to template for type choice
 *  0..23 unused
 * 24..27 flags
 * 28..31 op
 */

#define A1_OP_MASK			(0xf0000000)
#define A1_OP_TYPE			(0x10000000) /* templated type */
#define A1_OP_TYPE_EXTERN		(0x20000000) /* templated type (imported) */
#define A1_OP_TAG			(0x30000000) /* a tag */
#define A1_OP_PARSE			(0x40000000) /* primitive type */
#define A1_OP_SEQOF			(0x50000000) /* sequence of */
#define A1_OP_SETOF			(0x60000000) /* set      of */
#define A1_OP_BMEMBER			(0x70000000) /* BIT STRING member */
#define A1_OP_CHOICE			(0x80000000) /* CHOICE */
#define A1_OP_DEFVAL			(0x90000000) /* def. value */
#define A1_OP_OPENTYPE_OBJSET		(0xa0000000) /* object set for open type */
#define A1_OP_OPENTYPE_ID		(0xb0000000) /* open type id field */
#define A1_OP_OPENTYPE			(0xc0000000) /* open type    field */
#define A1_OP_NAME			(0xd0000000) /* symbol */
#define A1_OP_TYPE_DECORATE		(0xe0000000) /* decoration w/ templated type */
#define A1_OP_TYPE_DECORATE_EXTERN	(0xf0000000) /* decoration w/ some C type */
						     /* 0x00.. is still free */

#define A1_FLAG_MASK		(0x0f000000)
#define A1_FLAG_OPTIONAL	(0x01000000)
#define A1_FLAG_IMPLICIT	(0x02000000)
#define A1_FLAG_DEFAULT		(0x04000000)

#define A1_TAG_T(CLASS,TYPE,TAG)	((A1_OP_TAG) | (((CLASS) << 22) | ((TYPE) << 21) | (TAG)))
#define A1_TAG_CLASS(x)		(((x) >> 22) & 0x3)
#define A1_TAG_TYPE(x)		(((x) >> 21) & 0x1)
#define A1_TAG_TAG(x)		((x) & 0x1fffff)

#define A1_TAG_LEN(t)		((uintptr_t)(t)->ptr)
#define A1_HEADER_LEN(t)	((uintptr_t)(t)->ptr)

#define A1_PARSE_T(type)	((A1_OP_PARSE) | (type))
#define A1_PARSE_TYPE_MASK	0xfff
#define A1_PARSE_TYPE(x)	(A1_PARSE_TYPE_MASK & (x))

#define A1_PF_INDEFINTE		0x1
#define A1_PF_ALLOW_BER		0x2

#define A1_HF_PRESERVE		0x1
#define A1_HF_ELLIPSIS		0x2

#define A1_HBF_RFC1510		0x1

#define A1_DV_BOOLEAN		0x01
#define A1_DV_INTEGER		0x02
#define A1_DV_INTEGER32		0x04
#define A1_DV_INTEGER64		0x08
#define A1_DV_UTF8STRING	0x10

#define A1_OS_IS_SORTED		(0x01000000)
#define A1_OS_OT_IS_ARRAY	(0x02000000)
#define A1_OTI_IS_INTEGER	(0x04000000)


struct asn1_template {
    uint32_t tt;
    uint32_t offset;
    const void *ptr;
};

typedef int (ASN1CALL *asn1_type_decode)(const unsigned char *, size_t, void *, size_t *);
typedef int (ASN1CALL *asn1_type_encode)(unsigned char *, size_t, const void *, size_t *);
typedef size_t (ASN1CALL *asn1_type_length)(const void *);
typedef void (ASN1CALL *asn1_type_release)(void *);
typedef int (ASN1CALL *asn1_type_copy)(const void *, void *);
typedef char * (ASN1CALL *asn1_type_print)(const void *, int);

struct asn1_type_func {
    asn1_type_encode encode;
    asn1_type_decode decode;
    asn1_type_length length;
    asn1_type_copy copy;
    asn1_type_release release;
    asn1_type_print print;
    size_t size;
};

struct template_of {
    unsigned int len;
    void *val;
};

enum template_types {
    A1T_IMEMBER = 0,
    A1T_HEIM_INTEGER,
    A1T_INTEGER,
    A1T_INTEGER64,
    A1T_UNSIGNED,
    A1T_UNSIGNED64,
    A1T_GENERAL_STRING,
    A1T_OCTET_STRING,
    A1T_OCTET_STRING_BER,
    A1T_IA5_STRING,
    A1T_BMP_STRING,
    A1T_UNIVERSAL_STRING,
    A1T_PRINTABLE_STRING,
    A1T_VISIBLE_STRING,
    A1T_UTF8_STRING,
    A1T_GENERALIZED_TIME,
    A1T_UTC_TIME,
    A1T_HEIM_BIT_STRING,
    A1T_BOOLEAN,
    A1T_OID,
    A1T_TELETEX_STRING,
    A1T_NUM_ENTRY
};

extern struct asn1_type_func asn1_template_prim[A1T_NUM_ENTRY];

#define ABORT_ON_ERROR() abort()

#define DPOC(data,offset) ((const void *)(((const unsigned char *)data)  + offset))
#define DPO(data,offset) ((void *)(((unsigned char *)data)  + offset))

/*
 * These functions are needed by the generated template stubs and are
 * really internal functions. Since they are part of der-private.h
 * that contains extra prototypes that really a private we included a
 * copy here.
 */

int
_asn1_copy_top (
	const struct asn1_template * /*t*/,
	const void * /*from*/,
	void * /*to*/);

void
_asn1_free_top(const struct asn1_template *, void *);

char *
_asn1_print_top(const struct asn1_template *, int, const void *);

int
_asn1_decode_top (
	const struct asn1_template * /*t*/,
	unsigned /*flags*/,
	const unsigned char * /*p*/,
	size_t /*len*/,
	void * /*data*/,
	size_t * /*size*/);

int
_asn1_encode (
	const struct asn1_template * /*t*/,
	unsigned char * /*p*/,
	size_t /*len*/,
	const void * /*data*/,
	size_t * /*size*/);

int
_asn1_encode_fuzzer (
	const struct asn1_template * /*t*/,
	unsigned char * /*p*/,
	size_t /*len*/,
	const void * /*data*/,
	size_t * /*size*/);

void
_asn1_free (
	const struct asn1_template * /*t*/,
	void * /*data*/);

size_t
_asn1_length (
	const struct asn1_template * /*t*/,
	const void * /*data*/);

size_t
_asn1_length_fuzzer (
	const struct asn1_template * /*t*/,
	const void * /*data*/);


#endif
