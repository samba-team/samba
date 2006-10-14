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

/* $Id$ */

#ifndef __DER_H__
#define __DER_H__

typedef enum {
    ASN1_C_UNIV = 0,
    ASN1_C_APPL = 1,
    ASN1_C_CONTEXT = 2,
    ASN1_C_PRIVATE = 3
} Der_class;

typedef enum {PRIM = 0, CONS = 1} Der_type;

#define MAKE_TAG(CLASS, TYPE, TAG)  (((CLASS) << 6) | ((TYPE) << 5) | (TAG))

/* Universal tags */

enum {
    UT_EndOfContent	= 0,
    UT_Boolean		= 1,
    UT_Integer		= 2,	
    UT_BitString	= 3,
    UT_OctetString	= 4,
    UT_Null		= 5,
    UT_OID		= 6,
    UT_Enumerated	= 10,
    UT_UTF8String	= 12,
    UT_Sequence		= 16,
    UT_Set		= 17,
    UT_PrintableString	= 19,
    UT_IA5String	= 22,
    UT_UTCTime		= 23,
    UT_GeneralizedTime	= 24,
    UT_UniversalString	= 25,
    UT_VisibleString	= 26,
    UT_GeneralString	= 27,
    UT_BMPString	= 30,
    /* unsupported types */
    UT_ObjectDescriptor = 7,
    UT_External		= 8,
    UT_Real		= 9,
    UT_EmbeddedPDV	= 11,
    UT_RelativeOID	= 13,
    UT_NumericString	= 18,
    UT_TeletexString	= 20,
    UT_VideotexString	= 21,
    UT_GraphicString	= 25
};

#define ASN1_INDEFINITE 0xdce0deed

typedef struct asn1_der_time_t {
    time_t dt_sec;
    unsigned long dt_nsec;
} asn1_der_time_t;

typedef struct asn1_ber_time_t {
    time_t bt_sec;
    unsigned bt_nsec;
    int bt_zone;
} asn1_ber_time_t;

int der_get_unsigned (const unsigned char *p, size_t len,
		      unsigned *ret, size_t *size);
int der_get_integer (const unsigned char *p, size_t len,
		     int *ret, size_t *size);
int der_get_heim_integer (const unsigned char *p, size_t len,
			  heim_integer *ret, size_t *size);
int der_get_boolean(const unsigned char *p, size_t len,
		    int *data, size_t *size);
int der_get_length (const unsigned char *p, size_t len,
		    size_t *val, size_t *size);
int der_get_general_string (const unsigned char *p, size_t len, 
			    heim_general_string *str, size_t *size);
int der_get_utf8string (const unsigned char *p, size_t len, 
			    heim_utf8_string *str, size_t *size);
int der_get_universal_string (const unsigned char *p, size_t len, 
			     heim_universal_string *str, size_t *size);
int der_get_bmp_string (const unsigned char *p, size_t len, 
			heim_bmp_string *str, size_t *size);
int der_get_printable_string (const unsigned char *p, size_t len, 
			    heim_printable_string *str, size_t *size);
int der_get_ia5_string (const unsigned char *p, size_t len,
			heim_ia5_string *str, size_t *size);
int der_get_octet_string (const unsigned char *p, size_t len, 
			  heim_octet_string *data, size_t *size);
int der_get_generalized_time (const unsigned char *p, size_t len, 
			      time_t *data, size_t *size);
int der_get_generalized_time_der (const unsigned char *p, size_t len, 
				  asn1_der_time_t *data, size_t *size);
int der_get_generalized_time_ber (const unsigned char *p, size_t len, 
				  asn1_ber_time_t *data, size_t *size);
int der_get_utctime (const unsigned char *p, size_t len, 
		     time_t *data, size_t *size);
int der_get_oid (const unsigned char *p, size_t len,
		 heim_oid *data, size_t *size);
int der_get_bit_string (const unsigned char *p, size_t len,
			heim_bit_string *data, size_t *size);
int der_get_tag (const unsigned char *p, size_t len, 
		 Der_class *class, Der_type *type,
		 unsigned int *tag, size_t *size);

int der_match_tag (const unsigned char *p, size_t len, 
		   Der_class class, Der_type type,
		   unsigned int tag, size_t *size);
int der_match_tag_and_length (const unsigned char *p, size_t len,
			      Der_class class, Der_type type, unsigned int tag,
			      size_t *length_ret, size_t *size);

int der_put_unsigned (unsigned char *p, size_t len, const unsigned *val, size_t*);
int der_put_integer (unsigned char *p, size_t len, const int *val, size_t*);
int der_put_heim_integer (unsigned char *p, size_t len, 
			  const heim_integer *val, size_t*);
int der_put_boolean (unsigned char *p, size_t len, const int *val, size_t*);

int der_put_length (unsigned char *p, size_t len, size_t val, size_t*);
int der_put_general_string (unsigned char *p, size_t len,
			    const heim_general_string *str, size_t*);
int der_put_utf8string (unsigned char *p, size_t len,
			const heim_utf8_string *str, size_t*);
int der_put_universal_string (unsigned char *p, size_t len,
			      const heim_universal_string *str, size_t*);
int der_put_bmp_string (unsigned char *p, size_t len,
			    const heim_bmp_string *str, size_t*);
int der_put_printable_string (unsigned char *p, size_t len,
			    const heim_printable_string *str, size_t*);
int der_put_ia5_string (unsigned char *p, size_t len,
			const heim_ia5_string *str, size_t*);
int der_put_octet_string (unsigned char *p, size_t len,
			  const heim_octet_string *data, size_t*);
int der_put_generalized_time (unsigned char *p, size_t len, 
			      const time_t *data, size_t *size);
int der_put_utctime (unsigned char *p, size_t len, 
		     const time_t *data, size_t *size);
int der_put_oid (unsigned char *p, size_t len,
		 const heim_oid *data, size_t *size);
int der_put_bit_string (unsigned char *p, size_t len,
			const heim_bit_string *data, size_t *size);
int der_put_tag (unsigned char *p, size_t len, Der_class class, Der_type type,
		 unsigned int tag, size_t*);
int der_put_length_and_tag (unsigned char*, size_t, size_t, 
			    Der_class, Der_type, unsigned int, size_t*);

void free_integer (int *num);
void free_heim_integer (heim_integer *num);
void free_octet_string (heim_octet_string *k);
void free_general_string (heim_general_string *str);
void free_octet_string (heim_octet_string *k);
void free_oid (heim_oid *k);
void free_bit_string (heim_bit_string *k);
void free_generalized_time (time_t *t);
void free_utctime (time_t *t);
void free_utf8string (heim_utf8_string*);
void free_printable_string (heim_printable_string*);
void free_ia5_string (heim_ia5_string*);
void free_universal_string (heim_universal_string*);
void free_bmp_string (heim_bmp_string*);

size_t length_len (size_t len);
size_t length_integer (const int *data);
size_t length_heim_integer (const heim_integer *data);
size_t length_unsigned (const unsigned *data);
size_t length_enumerated (const unsigned *data);
size_t length_general_string (const heim_general_string *data);
size_t length_octet_string (const heim_octet_string *k);
size_t length_oid (const heim_oid *k);
size_t length_bit_string (const heim_bit_string *k);
size_t length_generalized_time (const time_t *t);
size_t length_utctime (const time_t *t);
size_t length_utf8string (const heim_utf8_string*);
size_t length_printable_string (const heim_printable_string*);
size_t length_ia5_string (const heim_ia5_string*);
size_t length_bmp_string (const heim_bmp_string*);
size_t length_universal_string (const heim_universal_string*);
size_t length_boolean (const int*);

int copy_heim_integer (const heim_integer *, heim_integer *);
int copy_general_string (const heim_general_string *, heim_general_string *);
int copy_octet_string (const heim_octet_string *, heim_octet_string *);
int copy_oid (const heim_oid *from, heim_oid *to);
int copy_bit_string (const heim_bit_string *from, heim_bit_string *to);
int copy_utf8string (const heim_utf8_string*, heim_utf8_string*);
int copy_printable_string (const heim_printable_string*,heim_printable_string*);
int copy_ia5_string (const heim_ia5_string*,heim_ia5_string*);
int copy_universal_string(const heim_universal_string*,heim_universal_string*);
int copy_bmp_string (const heim_bmp_string*,heim_bmp_string*);

int heim_oid_cmp(const heim_oid *, const heim_oid *);
int heim_octet_string_cmp(const heim_octet_string *,const heim_octet_string *);
int heim_bit_string_cmp(const heim_bit_string *, const heim_bit_string *);
int heim_integer_cmp(const heim_integer *, const heim_integer *);
int heim_bmp_string_cmp(const heim_bmp_string *, const heim_bmp_string *);
int heim_universal_string_cmp(const heim_universal_string *, 
			      const heim_universal_string *);

int der_parse_oid(const char *, heim_oid *);

int _heim_fix_dce(size_t reallen, size_t *len);
int _heim_der_set_sort(const void *, const void *);
int _heim_time2generalizedtime (time_t, heim_octet_string *, int);

const char *	der_get_class_name(unsigned);
int		der_get_class_num(const char *);
const char *	der_get_type_name(unsigned);
int		der_get_type_num(const char *);
const char *	der_get_tag_name(unsigned);
int		der_get_tag_num(const char *);

int		der_parse_hex_heim_integer(const char *, heim_integer *);
int		der_print_hex_heim_integer(const heim_integer *, char **);

int		der_print_heim_oid (const heim_oid *, char, char **);
int		der_parse_heim_oid (const char *, const char *, heim_oid *);


#endif /* __DER_H__ */
