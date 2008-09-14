/* 
   Unix SMB/CIFS implementation.
   simple SPNEGO routines
   Copyright (C) Andrew Tridgell 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

/* free an asn1 structure */
void asn1_free(ASN1_DATA *data)
{
	struct nesting *nesting = data->nesting;

	while (nesting) {
		struct nesting *nnext = nesting->next;
		free(nesting);
		nesting = nnext;
	};
	data->nesting = NULL;
	SAFE_FREE(data->data);
}

/* write to the ASN1 buffer, advancing the buffer pointer */
bool asn1_write(ASN1_DATA *data, const void *p, int len)
{
	if (data->has_error) return false;
	if (data->length < data->ofs+len) {
		data->data = SMB_REALLOC_ARRAY(data->data, unsigned char,
					       data->ofs+len);
		if (!data->data) {
			data->has_error = true;
			return false;
		}
		data->length = data->ofs+len;
	}
	memcpy(data->data + data->ofs, p, len);
	data->ofs += len;
	return true;
}

/* useful fn for writing a uint8 */
bool asn1_write_uint8(ASN1_DATA *data, uint8 v)
{
	return asn1_write(data, &v, 1);
}

/* push a tag onto the asn1 data buffer. Used for nested structures */
bool asn1_push_tag(ASN1_DATA *data, uint8 tag)
{
	struct nesting *nesting;

	asn1_write_uint8(data, tag);
	nesting = SMB_MALLOC_P(struct nesting);
	if (!nesting) {
		data->has_error = true;
		return false;
	}

	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	return asn1_write_uint8(data, 0xff);
}

/* pop a tag */
bool asn1_pop_tag(ASN1_DATA *data)
{
	struct nesting *nesting;
	size_t len;

	if (data->has_error) {
		return false;
	}

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = true;
		return false;
	}
	len = data->ofs - (nesting->start+1);
	/* yes, this is ugly. We don't know in advance how many bytes the length
	   of a tag will take, so we assumed 1 byte. If we were wrong then we 
	   need to correct our mistake */
	if (len > 0xFFFF) {
		data->data[nesting->start] = 0x83;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+4, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = (len>>16) & 0xFF;
		data->data[nesting->start+2] = (len>>8) & 0xFF;
		data->data[nesting->start+3] = len&0xff;
	} else if (len > 255) {
		data->data[nesting->start] = 0x82;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+3, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len>>8;
		data->data[nesting->start+2] = len&0xff;
	} else if (len > 127) {
		data->data[nesting->start] = 0x81;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+2, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len;
	} else {
		data->data[nesting->start] = len;
	}

	data->nesting = nesting->next;
	free(nesting);
	return true;
}


/* write an integer */
bool asn1_write_Integer(ASN1_DATA *data, int i)
{
	if (!asn1_push_tag(data, ASN1_INTEGER)) return false;
	do {
		asn1_write_uint8(data, i);
		i = i >> 8;
	} while (i);
	return asn1_pop_tag(data);
}

/* write an object ID to a ASN1 buffer */
bool asn1_write_OID(ASN1_DATA *data, const char *OID)
{
	unsigned v, v2;
	const char *p = (const char *)OID;
	char *newp;

	if (!asn1_push_tag(data, ASN1_OID))
		return false;
	v = strtol(p, &newp, 10);
	p = newp;
	v2 = strtol(p, &newp, 10);
	p = newp;
	if (!asn1_write_uint8(data, 40*v + v2))
		return false;

	while (*p) {
		v = strtol(p, &newp, 10);
		p = newp;
		if (v >= (1<<28)) asn1_write_uint8(data, 0x80 | ((v>>28)&0xff));
		if (v >= (1<<21)) asn1_write_uint8(data, 0x80 | ((v>>21)&0xff));
		if (v >= (1<<14)) asn1_write_uint8(data, 0x80 | ((v>>14)&0xff));
		if (v >= (1<<7)) asn1_write_uint8(data, 0x80 | ((v>>7)&0xff));
		if (!asn1_write_uint8(data, v&0x7f))
			return false;
	}
	return asn1_pop_tag(data);
}

/* write an octet string */
bool asn1_write_OctetString(ASN1_DATA *data, const void *p, size_t length)
{
	asn1_push_tag(data, ASN1_OCTET_STRING);
	asn1_write(data, p, length);
	asn1_pop_tag(data);
	return !data->has_error;
}

/* write a general string */
bool asn1_write_GeneralString(ASN1_DATA *data, const char *s)
{
	asn1_push_tag(data, ASN1_GENERAL_STRING);
	asn1_write(data, s, strlen(s));
	asn1_pop_tag(data);
	return !data->has_error;
}

/* write a BOOLEAN */
bool asn1_write_BOOLEAN(ASN1_DATA *data, bool v)
{
	asn1_write_uint8(data, ASN1_BOOLEAN);
	asn1_write_uint8(data, v);
	return !data->has_error;
}

/* write a BOOLEAN - hmm, I suspect this one is the correct one, and the 
   above boolean is bogus. Need to check */
bool asn1_write_BOOLEAN2(ASN1_DATA *data, bool v)
{
	asn1_push_tag(data, ASN1_BOOLEAN);
	asn1_write_uint8(data, v);
	asn1_pop_tag(data);
	return !data->has_error;
}

/* check a BOOLEAN */
bool asn1_check_BOOLEAN(ASN1_DATA *data, bool v)
{
	uint8 b = 0;

	asn1_read_uint8(data, &b);
	if (b != ASN1_BOOLEAN) {
		data->has_error = true;
		return false;
	}
	asn1_read_uint8(data, &b);
	if (b != v) {
		data->has_error = true;
		return false;
	}
	return !data->has_error;
}


/* load a ASN1_DATA structure with a lump of data, ready to be parsed */
bool asn1_load(ASN1_DATA *data, DATA_BLOB blob)
{
	ZERO_STRUCTP(data);
	data->data = (unsigned char *)memdup(blob.data, blob.length);
	if (!data->data) {
		data->has_error = true;
		return false;
	}
	data->length = blob.length;
	return true;
}

/* read from a ASN1 buffer, advancing the buffer pointer */
bool asn1_read(ASN1_DATA *data, void *p, int len)
{
	if (data->has_error)
		return false;

	if (len < 0 || data->ofs + len < data->ofs || data->ofs + len < len) {
		data->has_error = true;
		return false;
	}

	if (data->ofs + len > data->length) {
		data->has_error = true;
		return false;
	}
	memcpy(p, data->data + data->ofs, len);
	data->ofs += len;
	return true;
}

/* read a uint8 from a ASN1 buffer */
bool asn1_read_uint8(ASN1_DATA *data, uint8 *v)
{
	return asn1_read(data, v, 1);
}

/*
 * Check thta the value of the ASN1 buffer at the current offset equals tag.
 */
bool asn1_check_tag(ASN1_DATA *data, uint8 tag)
{
	if (data->has_error || data->ofs >= data->length || data->ofs < 0) {
		data->has_error = true;
		return false;
	}

	return (tag == data->data[data->ofs]);
}

/* start reading a nested asn1 structure */
bool asn1_start_tag(ASN1_DATA *data, uint8 tag)
{
	uint8 b;
	struct nesting *nesting;
	
	if (!asn1_read_uint8(data, &b))
		return false;

	if (b != tag) {
		data->has_error = true;
		return false;
	}
	nesting = SMB_MALLOC_P(struct nesting);
	if (!nesting) {
		data->has_error = true;
		return false;
	}

	if (!asn1_read_uint8(data, &b)) {
		SAFE_FREE(nesting);
		return false;
	}

	if (b & 0x80) {
		int n = b & 0x7f;
		if (!asn1_read_uint8(data, &b)) {
			SAFE_FREE(nesting);
			return false;
		}
		nesting->taglen = b;
		while (n > 1) {
			if (!asn1_read_uint8(data, &b)) {
				SAFE_FREE(nesting);
				return false;
			}
			nesting->taglen = (nesting->taglen << 8) | b;
			n--;
		}
	} else {
		nesting->taglen = b;
	}
	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	return !data->has_error;
}


/* stop reading a tag */
bool asn1_end_tag(ASN1_DATA *data)
{
	struct nesting *nesting;

	/* make sure we read it all */
	if (asn1_tag_remaining(data) != 0) {
		data->has_error = true;
		return false;
	}

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = true;
		return false;
	}

	data->nesting = nesting->next;
	free(nesting);
	return true;
}

/* work out how many bytes are left in this nested tag */
int asn1_tag_remaining(ASN1_DATA *data)
{
	if (data->has_error)
		return 0;

	if (!data->nesting) {
		data->has_error = true;
		return -1;
	}
	return data->nesting->taglen - (data->ofs - data->nesting->start);
}

/* read an object ID from a ASN1 buffer */
bool asn1_read_OID(ASN1_DATA *data, char **OID)
{
	uint8 b = 0;
	char *oid_str = NULL;

	*OID = NULL;

	if (!asn1_start_tag(data, ASN1_OID)) {
		return false;
	}
	asn1_read_uint8(data, &b);

	oid_str = talloc_asprintf(NULL,
			"%u",
			b/40);
	if (!oid_str) {
		data->has_error = true;
		goto out;
	}
	oid_str = talloc_asprintf_append(oid_str,
			" %u",
			b%40);
	if (!oid_str) {
		data->has_error = true;
		goto out;
	}

	while (asn1_tag_remaining(data) > 0) {
		unsigned v = 0;
		do {
			asn1_read_uint8(data, &b);
			v = (v<<7) | (b&0x7f);
		} while (!data->has_error && b & 0x80);
		oid_str = talloc_asprintf_append(oid_str,
					" %u",
					v);
		if (!oid_str) {
			data->has_error = true;
			goto out;
		}
	}

  out:

	asn1_end_tag(data);

	if (!data->has_error) {
	  	*OID = SMB_STRDUP(oid_str);
	}

	TALLOC_FREE(oid_str);

	return !data->has_error;
}

/* check that the next object ID is correct */
bool asn1_check_OID(ASN1_DATA *data, const char *OID)
{
	char *id;

	if (!asn1_read_OID(data, &id)) {
		return false;
	}

	if (strcmp(id, OID) != 0) {
		data->has_error = true;
		free(id);
		return false;
	}
	free(id);
	return true;
}

/* read a GeneralString from a ASN1 buffer */
bool asn1_read_GeneralString(ASN1_DATA *data, char **s)
{
	int len;
	char *str;

	*s = NULL;

	if (!asn1_start_tag(data, ASN1_GENERAL_STRING)) {
		return false;
	}
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}
	str = SMB_MALLOC_ARRAY(char, len+1);
	if (!str) {
		data->has_error = true;
		return false;
	}
	asn1_read(data, str, len);
	str[len] = 0;
	asn1_end_tag(data);

	if (!data->has_error) {
		*s = str;
	}
	return !data->has_error;
}

/* read a octet string blob */
bool asn1_read_OctetString(ASN1_DATA *data, DATA_BLOB *blob)
{
	int len;
	ZERO_STRUCTP(blob);
	if (!asn1_start_tag(data, ASN1_OCTET_STRING)) return false;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}
	*blob = data_blob(NULL, len);
	asn1_read(data, blob->data, len);
	asn1_end_tag(data);
	return !data->has_error;
}

/* read an interger */
bool asn1_read_Integer(ASN1_DATA *data, int *i)
{
	uint8 b;
	*i = 0;
	
	if (!asn1_start_tag(data, ASN1_INTEGER)) return false;
	while (asn1_tag_remaining(data)>0) {
		asn1_read_uint8(data, &b);
		*i = (*i << 8) + b;
	}
	return asn1_end_tag(data);	
	
}

/* check a enumarted value is correct */
bool asn1_check_enumerated(ASN1_DATA *data, int v)
{
	uint8 b;
	if (!asn1_start_tag(data, ASN1_ENUMERATED)) return false;
	asn1_read_uint8(data, &b);
	asn1_end_tag(data);

	if (v != b)
		data->has_error = false;

	return !data->has_error;
}

/* write an enumarted value to the stream */
bool asn1_write_enumerated(ASN1_DATA *data, uint8 v)
{
	if (!asn1_push_tag(data, ASN1_ENUMERATED)) return false;
	asn1_write_uint8(data, v);
	asn1_pop_tag(data);
	return !data->has_error;
}

bool ber_write_OID_String(DATA_BLOB *blob, const char *OID)
{
	uint_t v, v2;
	const char *p = (const char *)OID;
	char *newp;
	int i;

	v = strtoul(p, &newp, 10);
	if (newp[0] != '.') return false;
	p = newp + 1;

	v2 = strtoul(p, &newp, 10);
	if (newp[0] != '.') return false;
	p = newp + 1;

	/*the ber representation can't use more space then the string one */
	*blob = data_blob(NULL, strlen(OID));
	if (!blob->data) return false;

	blob->data[0] = 40*v + v2;

	i = 1;
	while (*p) {
		v = strtoul(p, &newp, 10);
		if (newp[0] == '.') {
			p = newp + 1;
		} else if (newp[0] == '\0') {
			p = newp;
		} else {
			data_blob_free(blob);
			return false;
		}
		if (v >= (1<<28)) blob->data[i++] = (0x80 | ((v>>28)&0x7f));
		if (v >= (1<<21)) blob->data[i++] = (0x80 | ((v>>21)&0x7f));
		if (v >= (1<<14)) blob->data[i++] = (0x80 | ((v>>14)&0x7f));
		if (v >= (1<<7)) blob->data[i++] = (0x80 | ((v>>7)&0x7f));
		blob->data[i++] = (v&0x7f);
	}

	blob->length = i;

	return true;
}

/* read an object ID from a data blob */
bool ber_read_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB blob, const char **OID)
{
	int i;
	uint8_t *b;
	uint_t v;
	char *tmp_oid = NULL;

	if (blob.length < 2) return false;

	b = blob.data;

	tmp_oid = talloc_asprintf(mem_ctx, "%u",  b[0]/40);
	if (!tmp_oid) goto nomem;
	tmp_oid = talloc_asprintf_append_buffer(tmp_oid, ".%u",  b[0]%40);
	if (!tmp_oid) goto nomem;

	for(i = 1, v = 0; i < blob.length; i++) {
		v = (v<<7) | (b[i]&0x7f);
		if ( ! (b[i] & 0x80)) {
			tmp_oid = talloc_asprintf_append_buffer(tmp_oid, ".%u",  v);
			v = 0;
		}
		if (!tmp_oid) goto nomem;
	}

	if (v != 0) {
		talloc_free(tmp_oid);
		return false;
	}

	*OID = tmp_oid;
	return true;

nomem:
	return false;
}


