/* 
   Unix SMB/CIFS implementation.
   simple SPNEGO routines
   Copyright (C) Andrew Tridgell 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/util/asn_1.h"

/* free an asn1 structure */
void asn1_free(struct asn1_data *data)
{
	talloc_free(data->data);
}

/* write to the ASN1 buffer, advancing the buffer pointer */
BOOL asn1_write(struct asn1_data *data, const void *p, int len)
{
	if (data->has_error) return False;
	if (data->length < data->ofs+len) {
		uint8_t *newp;
		newp = talloc_realloc(NULL, data->data, uint8_t, data->ofs+len);
		if (!newp) {
			asn1_free(data);
			data->has_error = True;
			return False;
		}
		data->data = newp;
		data->length = data->ofs+len;
	}
	memcpy(data->data + data->ofs, p, len);
	data->ofs += len;
	return True;
}

/* useful fn for writing a uint8_t */
BOOL asn1_write_uint8(struct asn1_data *data, uint8_t v)
{
	return asn1_write(data, &v, 1);
}

/* push a tag onto the asn1 data buffer. Used for nested structures */
BOOL asn1_push_tag(struct asn1_data *data, uint8_t tag)
{
	struct nesting *nesting;

	asn1_write_uint8(data, tag);
	nesting = talloc(NULL, struct nesting);
	if (!nesting) {
		data->has_error = True;
		return False;
	}

	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	return asn1_write_uint8(data, 0xff);
}

/* pop a tag */
BOOL asn1_pop_tag(struct asn1_data *data)
{
	struct nesting *nesting;
	size_t len;

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = True;
		return False;
	}
	len = data->ofs - (nesting->start+1);
	/* yes, this is ugly. We don't know in advance how many bytes the length
	   of a tag will take, so we assumed 1 byte. If we were wrong then we 
	   need to correct our mistake */
	if (len > 0xFFFF) {
		data->data[nesting->start] = 0x83;
		if (!asn1_write_uint8(data, 0)) return False;
		if (!asn1_write_uint8(data, 0)) return False;
		if (!asn1_write_uint8(data, 0)) return False;
		memmove(data->data+nesting->start+4, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = (len>>16) & 0xFF;
		data->data[nesting->start+2] = (len>>8) & 0xFF;
		data->data[nesting->start+3] = len&0xff;
	} else if (len > 255) {
		data->data[nesting->start] = 0x82;
		if (!asn1_write_uint8(data, 0)) return False;
		if (!asn1_write_uint8(data, 0)) return False;
		memmove(data->data+nesting->start+3, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len>>8;
		data->data[nesting->start+2] = len&0xff;
	} else if (len > 127) {
		data->data[nesting->start] = 0x81;
		if (!asn1_write_uint8(data, 0)) return False;
		memmove(data->data+nesting->start+2, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len;
	} else {
		data->data[nesting->start] = len;
	}

	data->nesting = nesting->next;
	talloc_free(nesting);
	return True;
}

/* "i" is the one's complement representation, as is the normal result of an
 * implicit signed->unsigned conversion */

static BOOL push_int_bigendian(struct asn1_data *data, unsigned int i, BOOL negative)
{
	uint8_t lowest = i & 0xFF;

	i = i >> 8;
	if (i != 0)
		if (!push_int_bigendian(data, i, negative))
			return False;

	if (data->nesting->start+1 == data->ofs) {

		/* We did not write anything yet, looking at the highest
		 * valued byte */

		if (negative) {
			/* Don't write leading 0xff's */
			if (lowest == 0xFF)
				return True;

			if ((lowest & 0x80) == 0) {
				/* The only exception for a leading 0xff is if
				 * the highest bit is 0, which would indicate
				 * a positive value */
				if (!asn1_write_uint8(data, 0xff))
					return False;
			}
		} else {
			if (lowest & 0x80) {
				/* The highest bit of a positive integer is 1,
				 * this would indicate a negative number. Push
				 * a 0 to indicate a positive one */
				if (!asn1_write_uint8(data, 0))
					return False;
			}
		}
	}

	return asn1_write_uint8(data, lowest);
}

/* write an Integer without the tag framing. Needed for example for the LDAP
 * Abandon Operation */

BOOL asn1_write_implicit_Integer(struct asn1_data *data, int i)
{
	if (i == -1) {
		/* -1 is special as it consists of all-0xff bytes. In
                    push_int_bigendian this is the only case that is not
                    properly handled, as all 0xff bytes would be handled as
                    leading ones to be ignored. */
		return asn1_write_uint8(data, 0xff);
	} else {
		return push_int_bigendian(data, i, i<0);
	}
}


/* write an integer */
BOOL asn1_write_Integer(struct asn1_data *data, int i)
{
	if (!asn1_push_tag(data, ASN1_INTEGER)) return False;
	if (!asn1_write_implicit_Integer(data, i)) return False;
	return asn1_pop_tag(data);
}

/* write an object ID to a ASN1 buffer */
BOOL asn1_write_OID(struct asn1_data *data, const char *OID)
{
	uint_t v, v2;
	const char *p = (const char *)OID;
	char *newp;

	if (!asn1_push_tag(data, ASN1_OID))
		return False;
	v = strtol(p, &newp, 10);
	p = newp;
	v2 = strtol(p, &newp, 10);
	p = newp;
	if (!asn1_write_uint8(data, 40*v + v2))
		return False;

	while (*p) {
		v = strtol(p, &newp, 10);
		p = newp;
		if (v >= (1<<28)) asn1_write_uint8(data, 0x80 | ((v>>28)&0xff));
		if (v >= (1<<21)) asn1_write_uint8(data, 0x80 | ((v>>21)&0xff));
		if (v >= (1<<14)) asn1_write_uint8(data, 0x80 | ((v>>14)&0xff));
		if (v >= (1<<7)) asn1_write_uint8(data, 0x80 | ((v>>7)&0xff));
		if (!asn1_write_uint8(data, v&0x7f))
			return False;
	}
	return asn1_pop_tag(data);
}

/* write an octet string */
BOOL asn1_write_OctetString(struct asn1_data *data, const void *p, size_t length)
{
	asn1_push_tag(data, ASN1_OCTET_STRING);
	asn1_write(data, p, length);
	asn1_pop_tag(data);
	return !data->has_error;
}

/* write a LDAP string */
BOOL asn1_write_LDAPString(struct asn1_data *data, const char *s)
{
	asn1_write(data, s, strlen(s));
	return !data->has_error;
}

/* write a general string */
BOOL asn1_write_GeneralString(struct asn1_data *data, const char *s)
{
	asn1_push_tag(data, ASN1_GENERAL_STRING);
	asn1_write_LDAPString(data, s);
	asn1_pop_tag(data);
	return !data->has_error;
}

BOOL asn1_write_ContextSimple(struct asn1_data *data, uint8_t num, DATA_BLOB *blob)
{
	asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(num));
	asn1_write(data, blob->data, blob->length);
	asn1_pop_tag(data);
	return !data->has_error;
}

/* write a BOOLEAN */
BOOL asn1_write_BOOLEAN(struct asn1_data *data, BOOL v)
{
	asn1_push_tag(data, ASN1_BOOLEAN);
	asn1_write_uint8(data, v ? 0xFF : 0);
	asn1_pop_tag(data);
	return !data->has_error;
}

BOOL asn1_read_BOOLEAN(struct asn1_data *data, BOOL *v)
{
	uint8_t tmp = 0;
	asn1_start_tag(data, ASN1_BOOLEAN);
	asn1_read_uint8(data, &tmp);
	if (tmp == 0xFF) {
		*v = True;
	} else {
		*v = False;
	}
	asn1_end_tag(data);
	return !data->has_error;
}

/* check a BOOLEAN */
BOOL asn1_check_BOOLEAN(struct asn1_data *data, BOOL v)
{
	uint8_t b = 0;

	asn1_read_uint8(data, &b);
	if (b != ASN1_BOOLEAN) {
		data->has_error = True;
		return False;
	}
	asn1_read_uint8(data, &b);
	if (b != v) {
		data->has_error = True;
		return False;
	}
	return !data->has_error;
}


/* load a struct asn1_data structure with a lump of data, ready to be parsed */
BOOL asn1_load(struct asn1_data *data, DATA_BLOB blob)
{
	ZERO_STRUCTP(data);
	data->data = talloc_memdup(NULL, blob.data, blob.length);
	if (!data->data) {
		data->has_error = True;
		return False;
	}
	data->length = blob.length;
	return True;
}

/* Peek into an ASN1 buffer, not advancing the pointer */
BOOL asn1_peek(struct asn1_data *data, void *p, int len)
{
	if (len < 0 || data->ofs + len < data->ofs || data->ofs + len < len)
		return False;

	if (data->ofs + len > data->length) {
		/* we need to mark the buffer as consumed, so the caller knows
		   this was an out of data error, and not a decode error */
		data->ofs = data->length;
		return False;
	}

	memcpy(p, data->data + data->ofs, len);
	return True;
}

/* read from a ASN1 buffer, advancing the buffer pointer */
BOOL asn1_read(struct asn1_data *data, void *p, int len)
{
	if (!asn1_peek(data, p, len)) {
		data->has_error = True;
		return False;
	}

	data->ofs += len;
	return True;
}

/* read a uint8_t from a ASN1 buffer */
BOOL asn1_read_uint8(struct asn1_data *data, uint8_t *v)
{
	return asn1_read(data, v, 1);
}

BOOL asn1_peek_uint8(struct asn1_data *data, uint8_t *v)
{
	return asn1_peek(data, v, 1);
}

BOOL asn1_peek_tag(struct asn1_data *data, uint8_t tag)
{
	uint8_t b;

	if (asn1_tag_remaining(data) <= 0) {
		return False;
	}

	if (!asn1_peek(data, &b, sizeof(b)))
		return False;

	return (b == tag);
}

/* start reading a nested asn1 structure */
BOOL asn1_start_tag(struct asn1_data *data, uint8_t tag)
{
	uint8_t b;
	struct nesting *nesting;
	
	if (!asn1_read_uint8(data, &b))
		return False;

	if (b != tag) {
		data->has_error = True;
		return False;
	}
	nesting = talloc(NULL, struct nesting);
	if (!nesting) {
		data->has_error = True;
		return False;
	}

	if (!asn1_read_uint8(data, &b)) {
		return False;
	}

	if (b & 0x80) {
		int n = b & 0x7f;
		if (!asn1_read_uint8(data, &b))
			return False;
		nesting->taglen = b;
		while (n > 1) {
			if (!asn1_read_uint8(data, &b)) 
				return False;
			nesting->taglen = (nesting->taglen << 8) | b;
			n--;
		}
	} else {
		nesting->taglen = b;
	}
	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	if (asn1_tag_remaining(data) == -1) {
		return False;
	}
	return !data->has_error;
}


/* stop reading a tag */
BOOL asn1_end_tag(struct asn1_data *data)
{
	struct nesting *nesting;

	/* make sure we read it all */
	if (asn1_tag_remaining(data) != 0) {
		data->has_error = True;
		return False;
	}

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = True;
		return False;
	}

	data->nesting = nesting->next;
	talloc_free(nesting);
	return True;
}

/* work out how many bytes are left in this nested tag */
int asn1_tag_remaining(struct asn1_data *data)
{
	int remaining;
	if (data->has_error) {
		return -1;
	}

	if (!data->nesting) {
		data->has_error = True;
		return -1;
	}
	remaining = data->nesting->taglen - (data->ofs - data->nesting->start);
	if (remaining > (data->length - data->ofs)) {
		data->has_error = True;
		return -1;
	}
	return remaining;
}

/* read an object ID from a ASN1 buffer */
BOOL asn1_read_OID(struct asn1_data *data, const char **OID)
{
	uint8_t b;
	char *tmp_oid = NULL;

	if (!asn1_start_tag(data, ASN1_OID)) return False;
	asn1_read_uint8(data, &b);

	tmp_oid = talloc_asprintf(NULL, "%u",  b/40);
	tmp_oid = talloc_asprintf_append(tmp_oid, " %u",  b%40);

	while (!data->has_error && asn1_tag_remaining(data) > 0) {
		uint_t v = 0;
		do {
			asn1_read_uint8(data, &b);
			v = (v<<7) | (b&0x7f);
		} while (!data->has_error && (b & 0x80));
		tmp_oid = talloc_asprintf_append(tmp_oid, " %u",  v);
	}

	asn1_end_tag(data);

	*OID = talloc_strdup(NULL, tmp_oid);
	talloc_free(tmp_oid);

	return (*OID && !data->has_error);
}

/* check that the next object ID is correct */
BOOL asn1_check_OID(struct asn1_data *data, const char *OID)
{
	const char *id;

	if (!asn1_read_OID(data, &id)) return False;

	if (strcmp(id, OID) != 0) {
		data->has_error = True;
		return False;
	}
	talloc_free(discard_const(id));
	return True;
}

/* read a LDAPString from a ASN1 buffer */
BOOL asn1_read_LDAPString(struct asn1_data *data, char **s)
{
	int len;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = True;
		return False;
	}
	*s = talloc_size(NULL, len+1);
	if (! *s) {
		data->has_error = True;
		return False;
	}
	asn1_read(data, *s, len);
	(*s)[len] = 0;
	return !data->has_error;
}


/* read a GeneralString from a ASN1 buffer */
BOOL asn1_read_GeneralString(struct asn1_data *data, char **s)
{
	if (!asn1_start_tag(data, ASN1_GENERAL_STRING)) return False;
	if (!asn1_read_LDAPString(data, s)) return False;
	return asn1_end_tag(data);
}


/* read a octet string blob */
BOOL asn1_read_OctetString(struct asn1_data *data, DATA_BLOB *blob)
{
	int len;
	ZERO_STRUCTP(blob);
	if (!asn1_start_tag(data, ASN1_OCTET_STRING)) return False;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = True;
		return False;
	}
	*blob = data_blob(NULL, len+1);
	if (!blob->data) {
		data->has_error = True;
		return False;
	}
	asn1_read(data, blob->data, len);
	asn1_end_tag(data);
	blob->length--;
	blob->data[len] = 0;
	
	if (data->has_error) {
		data_blob_free(blob);
		*blob = data_blob(NULL, 0);
		return False;
	}
	return True;
}

BOOL asn1_read_ContextSimple(struct asn1_data *data, uint8_t num, DATA_BLOB *blob)
{
	int len;
	ZERO_STRUCTP(blob);
	if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(num))) return False;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = True;
		return False;
	}
	*blob = data_blob(NULL, len);
	if (!blob->data) {
		data->has_error = True;
		return False;
	}
	asn1_read(data, blob->data, len);
	asn1_end_tag(data);
	return !data->has_error;
}

/* read an interger without tag*/
BOOL asn1_read_implicit_Integer(struct asn1_data *data, int *i)
{
	uint8_t b;
	*i = 0;

	while (!data->has_error && asn1_tag_remaining(data)>0) {
		if (!asn1_read_uint8(data, &b)) return False;
		*i = (*i << 8) + b;
	}
	return !data->has_error;	
	
}

/* read an interger */
BOOL asn1_read_Integer(struct asn1_data *data, int *i)
{
	*i = 0;

	if (!asn1_start_tag(data, ASN1_INTEGER)) return False;
	if (!asn1_read_implicit_Integer(data, i)) return False;
	return asn1_end_tag(data);	
}

/* read an interger */
BOOL asn1_read_enumerated(struct asn1_data *data, int *v)
{
	*v = 0;
	
	if (!asn1_start_tag(data, ASN1_ENUMERATED)) return False;
	while (!data->has_error && asn1_tag_remaining(data)>0) {
		uint8_t b;
		asn1_read_uint8(data, &b);
		*v = (*v << 8) + b;
	}
	return asn1_end_tag(data);	
}

/* check a enumarted value is correct */
BOOL asn1_check_enumerated(struct asn1_data *data, int v)
{
	uint8_t b;
	if (!asn1_start_tag(data, ASN1_ENUMERATED)) return False;
	asn1_read_uint8(data, &b);
	asn1_end_tag(data);

	if (v != b)
		data->has_error = False;

	return !data->has_error;
}

/* write an enumarted value to the stream */
BOOL asn1_write_enumerated(struct asn1_data *data, uint8_t v)
{
	if (!asn1_push_tag(data, ASN1_ENUMERATED)) return False;
	asn1_write_uint8(data, v);
	asn1_pop_tag(data);
	return !data->has_error;
}

/*
  check if a ASN.1 blob is a full tag
*/
NTSTATUS asn1_full_tag(DATA_BLOB blob, uint8_t tag, size_t *packet_size)
{
	struct asn1_data asn1;
	int size;

	ZERO_STRUCT(asn1);
	asn1.data = blob.data;
	asn1.length = blob.length;
	asn1_start_tag(&asn1, tag);
	if (asn1.has_error) {
		talloc_free(asn1.nesting);
		return STATUS_MORE_ENTRIES;
	}
	size = asn1_tag_remaining(&asn1) + asn1.ofs;
	talloc_free(asn1.nesting);

	if (size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}		

	*packet_size = size;
	return NT_STATUS_OK;
}
