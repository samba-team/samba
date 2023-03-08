/*
 * Copyright (c) 2003-2005 Kungliga Tekniska Högskolan
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

#include "der_locl.h"

int ASN1CALL
der_heim_oid_cmp(const heim_oid *p, const heim_oid *q)
{
    int c;

    if (p->length == q->length) {
        if (p->length == 0)
            return 0;
        return memcmp(p->components,
                      q->components,
                      p->length * sizeof(*p->components));
    }
    if (p->length < q->length) {
        if (p->length == 0 ||
            (c = memcmp(p->components,
                        q->components,
                        p->length * sizeof(*p->components))) == 0)
            return -1;
        return c;
    }
    if (q->length == 0 ||
        (c = memcmp(p->components,
                    q->components,
                    q->length * sizeof(*p->components))) == 0)
        return 1;
    return c;
}

int ASN1CALL
der_heim_octet_string_cmp(const heim_octet_string *p,
			  const heim_octet_string *q)
{
    int c;

    if (p->length == q->length) {
        if (p->length == 0)
            return 0;
        return memcmp(p->data, q->data, p->length);
    }
    if (p->length < q->length) {
        if (p->length == 0 ||
            (c = memcmp(p->data, q->data, p->length)) == 0)
            return -1;
        return c;
    }
    if (q->length == 0 ||
        (c = memcmp(p->data, q->data, q->length)) == 0)
        return 1;
    return c;
}

int ASN1CALL
der_printable_string_cmp(const heim_printable_string *p,
			 const heim_printable_string *q)
{
    return der_heim_octet_string_cmp(p, q);
}

int ASN1CALL
der_ia5_string_cmp(const heim_ia5_string *p,
		   const heim_ia5_string *q)
{
    return der_heim_octet_string_cmp(p, q);
}

int ASN1CALL
der_heim_bit_string_cmp(const heim_bit_string *p,
			const heim_bit_string *q)
{
    unsigned char pc, qc;
    size_t bits;
    int c = 0;

    /* Compare prefix */
    if (p->length == 0 && q->length == 0)
        return 0;
    if (p->length > 7 && q->length > 7) {
        if (p->length < q->length)
            c = memcmp(p->data, q->data, p->length / 8);
        else
            c = memcmp(p->data, q->data, q->length / 8);
    }
    if (c)
        return c;

    /* Prefixes are equal, c == 0 */

    if (p->length == q->length && p->length % 8 == 0)
        return 0;
    if (p->length == 0 && q->length)
        return -1; /* No trailing bits of p to compare to corresponding bits of q */
    if (q->length == 0 && p->length)
        return  1; /* No trailing bits of q to compare to corresponding bits of p */

    /* c == 0, lengths are not equal, both are at least 1 bit */
    pc = ((unsigned char *)p->data)[p->length / 8];
    qc = ((unsigned char *)q->data)[q->length / 8];
    if (p->length < q->length)
        bits = p->length % 8;
    else
        bits = q->length % 8;

    if (bits > 0) {
        if ((pc & 0x80) == 0 && (qc & 0x80) != 0)
            return -1;
        if ((pc & 0x80) != 0 && (qc & 0x80) == 0)
            return 1;
    }
    if (bits > 1) {
        if ((pc & 0x40) == 0 && (qc & 0x40) != 0)
            return -1;
        if ((pc & 0x40) != 0 && (qc & 0x40) == 0)
            return 1;
    }
    if (bits > 2) {
        if ((pc & 0x20) == 0 && (qc & 0x20) != 0)
            return -1;
        if ((pc & 0x20) != 0 && (qc & 0x20) == 0)
            return 1;
    }
    if (bits > 3) {
        if ((pc & 0x10) == 0 && (qc & 0x10) != 0)
            return -1;
        if ((pc & 0x10) != 0 && (qc & 0x10) == 0)
            return 1;
    }
    if (bits > 4) {
        if ((pc & 0x08) == 0 && (qc & 0x08) != 0)
            return -1;
        if ((pc & 0x08) != 0 && (qc & 0x08) == 0)
            return 1;
    }
    if (bits > 5) {
        if ((pc & 0x04) == 0 && (qc & 0x04) != 0)
            return -1;
        if ((pc & 0x04) != 0 && (qc & 0x04) == 0)
            return 1;
    }
    if (bits > 6) {
        if ((pc & 0x02) == 0 && (qc & 0x02) != 0)
            return -1;
        if ((pc & 0x02) != 0 && (qc & 0x02) == 0)
            return 1;
    }
    /*
     * `bits' can't be 8.
     *
     * All leading `bits' bits of the tail of the shorter of `p' or `q' are
     * equal.
     */
    if (p->length < q->length)
        return -1;
    if (q->length < p->length)
        return  1;
    return 0;
}

int ASN1CALL
der_heim_integer_cmp(const heim_integer *p,
		     const heim_integer *q)
{
    if (p->negative != q->negative)
	return q->negative - p->negative;
    if (p->length != q->length)
	return (int)(p->length - q->length);
    return memcmp(p->data, q->data, p->length);
}

int ASN1CALL
der_heim_bmp_string_cmp(const heim_bmp_string *p, const heim_bmp_string *q)
{
    int c;

    if (p->length == q->length) {
        if (p->length == 0)
            return 0;
        return memcmp(p->data, q->data, p->length * sizeof(q->data[0]));
    }
    if (p->length < q->length) {
        if (p->length == 0 ||
            (c = memcmp(p->data, q->data, p->length * sizeof(q->data[0]))) == 0)
            return -1;
        return c;
    }
    if (q->length == 0 ||
        (c = memcmp(p->data, q->data, q->length * sizeof(q->data[0]))) == 0)
        return 1;
    return c;
}

int ASN1CALL
der_heim_universal_string_cmp(const heim_universal_string *p,
			      const heim_universal_string *q)
{
    int c;

    if (p->length == q->length) {
        if (p->length == 0)
            return 0;
        return memcmp(p->data, q->data, p->length * sizeof(q->data[0]));
    }
    if (p->length < q->length) {
        if (p->length == 0 ||
            (c = memcmp(p->data, q->data, p->length * sizeof(q->data[0]))) == 0)
            return -1;
        return c;
    }
    if (q->length == 0 ||
        (c = memcmp(p->data, q->data, q->length * sizeof(q->data[0]))) == 0)
        return 1;
    return c;
}
