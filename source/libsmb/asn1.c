/* 
   Unix SMB/Netbios implementation.
   Version 3.0
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

void asn1_free(ASN1_DATA *data)
{
	free(data->data);
}

BOOL asn1_check_empty(ASN1_DATA *data)
{
	if (data->nesting) return False;
	return True;
}

BOOL asn1_write(ASN1_DATA *data, const void *p, int len)
{
	if (data->length < data->ofs+len) {
		data->data = Realloc(data->data, data->ofs+len);
		if (!data->data) return False;
		data->length = data->ofs+len;
	}
	memcpy(data->data + data->ofs, p, len);
	data->ofs += len;
	return True;
}

BOOL asn1_write_uint8(ASN1_DATA *data, uint8 v)
{
	return asn1_write(data, &v, 1);
}

BOOL asn1_push_tag(ASN1_DATA *data, uint8 tag)
{
	struct nesting *nesting;

	asn1_write_uint8(data, tag);
	nesting = (struct nesting *)malloc(sizeof(struct nesting));
	if (!nesting) return False;

	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	asn1_write_uint8(data, 0xff);
	return True;
}

BOOL asn1_pop_tag(ASN1_DATA *data)
{
	struct nesting *nesting;
	size_t len;

	nesting = data->nesting;

	if (!nesting) {
		return False;
	}
	len = data->ofs - (nesting->start+1);
	if (len > 127) {
		data->data[nesting->start] = 0x82;
		asn1_write_uint8(data, 0);
		asn1_write_uint8(data, 0);
		memmove(data->data+nesting->start+3, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len>>8;
		data->data[nesting->start+2] = len&0xff;
	} else {
		data->data[nesting->start] = len;
	}

	data->nesting = nesting->next;
	free(nesting);
	return True;
}


BOOL asn1_write_OID(ASN1_DATA *data, const char *OID)
{
	unsigned v, v2;
	char *p = (char *)OID;

	asn1_push_tag(data, ASN1_OID);
	v = strtol(p, &p, 10);
	v2 = strtol(p, &p, 10);
	asn1_write_uint8(data, 40*v + v2);

	while (*p) {
		v = strtol(p, &p, 10);
		if (v >= (1<<28)) asn1_write_uint8(data, 0x80 | ((v>>28)&0xff));
		if (v >= (1<<21)) asn1_write_uint8(data, 0x80 | ((v>>21)&0xff));
		if (v >= (1<<14)) asn1_write_uint8(data, 0x80 | ((v>>14)&0xff));
		if (v >= (1<<7)) asn1_write_uint8(data, 0x80 | ((v>>7)&0xff));
		asn1_write_uint8(data, v&0x7f);
	}
	asn1_pop_tag(data);
	return True;
}

BOOL asn1_write_OctetString(ASN1_DATA *data, const void *p, size_t length)
{
	asn1_push_tag(data, ASN1_OCTET_STRING);
	asn1_write(data, p, length);
	asn1_pop_tag(data);
	return True;
}

BOOL asn1_write_GeneralString(ASN1_DATA *data, const char *s)
{
	asn1_push_tag(data, ASN1_GENERAL_STRING);
	asn1_write(data, s, strlen(s));
	asn1_pop_tag(data);
	return True;
}

BOOL asn1_write_BOOLEAN(ASN1_DATA *data, BOOL v)
{
	asn1_write_uint8(data, ASN1_BOOLEAN);
	asn1_write_uint8(data, v);
	return True;
}

