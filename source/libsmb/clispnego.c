/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   simple kerberos5/SPNEGO routines
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

/*
  generate a negTokenInit packet given a GUID, a list of supported
  OIDs (the mechanisms) and a principal name string 
*/
DATA_BLOB spnego_gen_negTokenInit(uint8 guid[16], 
				  const char *OIDs[], 
				  const char *principal)
{
	int i;
	ASN1_DATA data;
	DATA_BLOB ret;

	memset(&data, 0, sizeof(data));

	asn1_write(&data, guid, 16);
	asn1_push_tag(&data,ASN1_APPLICATION(0));
	asn1_write_OID(&data,OID_SPNEGO);
	asn1_push_tag(&data,ASN1_CONTEXT(0));
	asn1_push_tag(&data,ASN1_SEQUENCE(0));

	asn1_push_tag(&data,ASN1_CONTEXT(0));
	asn1_push_tag(&data,ASN1_SEQUENCE(0));
	for (i=0; OIDs[i]; i++) {
		asn1_write_OID(&data,OIDs[i]);
	}
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	asn1_push_tag(&data, ASN1_CONTEXT(0));
	asn1_write_GeneralString(&data,principal);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);

	if (data.has_error) {
		DEBUG(1,("Failed to build negTokenInit at offset %d\n", (int)data.ofs));
		asn1_free(&data);
	}

	ret = data_blob(data.data, data.length);
	asn1_free(&data);

	return ret;
}


/*
  parse a negTokenInit packet giving a GUID, a list of supported
  OIDs (the mechanisms) and a principal name string 
*/
BOOL spnego_parse_negTokenInit(DATA_BLOB blob,
			       uint8 guid[16], 
			       char *OIDs[ASN1_MAX_OIDS], 
			       char **principal)
{
	int i;
	BOOL ret;
	ASN1_DATA data;

	asn1_load(&data, blob);

	asn1_read(&data, guid, 16);
	asn1_start_tag(&data,ASN1_APPLICATION(0));
	asn1_check_OID(&data,OID_SPNEGO);
	asn1_start_tag(&data,ASN1_CONTEXT(0));
	asn1_start_tag(&data,ASN1_SEQUENCE(0));

	asn1_start_tag(&data,ASN1_CONTEXT(0));
	asn1_start_tag(&data,ASN1_SEQUENCE(0));
	for (i=0; asn1_tag_remaining(&data) > 0 && i < ASN1_MAX_OIDS; i++) {
		char *oid = NULL;
		asn1_read_OID(&data,&oid);
		OIDs[i] = oid;
	}
	OIDs[i] = NULL;
	asn1_end_tag(&data);
	asn1_end_tag(&data);

	asn1_start_tag(&data, ASN1_CONTEXT(3));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_CONTEXT(0));
	asn1_read_GeneralString(&data,principal);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);

	asn1_end_tag(&data);
	asn1_end_tag(&data);

	asn1_end_tag(&data);

	ret = !data.has_error;
	asn1_free(&data);
	return ret;
}


/*
  generate a negTokenTarg packet given a list of OIDs and a security blob
*/
DATA_BLOB gen_negTokenTarg(const char *OIDs[], DATA_BLOB blob)
{
	int i;
	ASN1_DATA data;
	DATA_BLOB ret;

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data, ASN1_APPLICATION(0));
	asn1_write_OID(&data,OID_SPNEGO);
	asn1_push_tag(&data, ASN1_CONTEXT(0));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));

	asn1_push_tag(&data, ASN1_CONTEXT(0));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	for (i=0; OIDs[i]; i++) {
		asn1_write_OID(&data,OIDs[i]);
	}
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(2));
	asn1_write_OctetString(&data,blob.data,blob.length);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);

	if (data.has_error) {
		DEBUG(1,("Failed to build negTokenTarg at offset %d\n", (int)data.ofs));
		asn1_free(&data);
	}

	ret = data_blob(data.data, data.length);
	asn1_free(&data);

	return ret;
}


/*
  parse a negTokenTarg packet giving a list of OIDs and a security blob
*/
BOOL parse_negTokenTarg(DATA_BLOB blob, char *OIDs[ASN1_MAX_OIDS], DATA_BLOB *secblob)
{
	int i;
	ASN1_DATA data;

	asn1_load(&data, blob);
	asn1_start_tag(&data, ASN1_APPLICATION(0));
	asn1_check_OID(&data,OID_SPNEGO);
	asn1_start_tag(&data, ASN1_CONTEXT(0));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));

	asn1_start_tag(&data, ASN1_CONTEXT(0));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	for (i=0; asn1_tag_remaining(&data) > 0 && i < ASN1_MAX_OIDS; i++) {
		char *oid = NULL;
		asn1_read_OID(&data,&oid);
		OIDs[i] = oid;
	}
	OIDs[i] = NULL;
	asn1_end_tag(&data);
	asn1_end_tag(&data);

	asn1_start_tag(&data, ASN1_CONTEXT(2));
	asn1_read_OctetString(&data,secblob);
	asn1_end_tag(&data);

	asn1_end_tag(&data);
	asn1_end_tag(&data);

	asn1_end_tag(&data);

	if (data.has_error) {
		DEBUG(1,("Failed to parse negTokenTarg at offset %d\n", (int)data.ofs));
		asn1_free(&data);
		return False;
	}

	asn1_free(&data);
	return True;
}

/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
static DATA_BLOB spnego_gen_krb5_wrap(DATA_BLOB ticket)
{
	ASN1_DATA data;
	DATA_BLOB ret;

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data, ASN1_APPLICATION(0));
	asn1_write_OID(&data, OID_KERBEROS5);
	asn1_write_BOOLEAN(&data, 0);
	asn1_write(&data, ticket.data, ticket.length);
	asn1_pop_tag(&data);

	if (data.has_error) {
		DEBUG(1,("Failed to build krb5 wrapper at offset %d\n", (int)data.ofs));
		asn1_free(&data);
	}

	ret = data_blob(data.data, data.length);
	asn1_free(&data);

	return ret;
}

/*
  parse a krb5 GSS-API wrapper packet giving a ticket
*/
BOOL spnego_parse_krb5_wrap(DATA_BLOB blob, DATA_BLOB *ticket)
{
	BOOL ret;
	ASN1_DATA data;
	int ata_remaining;

	asn1_load(&data, blob);
	asn1_start_tag(&data, ASN1_APPLICATION(0));
	asn1_check_OID(&data, OID_KERBEROS5);
	asn1_check_BOOLEAN(&data, 0);

	data_remaining = asn1_tag_remaining(&data);

	if (data_remaining < 1) {
		data.has_error = True;
	} else {
		*ticket = data_blob(data.data, data_remaining);
		asn1_read(&data, ticket->data, ticket->length);
	}

	asn1_end_tag(&data);

	ret = !data.has_error;

	asn1_free(&data);

	return ret;
}


/* 
   generate a SPNEGO negTokenTarg packet, ready for a EXTENDED_SECURITY
   kerberos session setup 
*/
DATA_BLOB spnego_gen_negTokenTarg(struct cli_state *cli, char *principal)
{
	DATA_BLOB tkt, tkt_wrapped, targ;
	const char *krb_mechs[] = {OID_KERBEROS5_OLD, OID_NTLMSSP, NULL};

	/* get a kerberos ticket for the service */
	tkt = krb5_get_ticket(principal);

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tkt);

	/* and wrap that in a shiny SPNEGO wrapper */
	targ = gen_negTokenTarg(krb_mechs, tkt_wrapped);

	data_blob_free(&tkt_wrapped);
	data_blob_free(&tkt);

	return targ;
}


/*
  parse a spnego NTLMSSP challenge packet giving two security blobs
*/
BOOL spnego_parse_challenge(DATA_BLOB blob,
			    DATA_BLOB *chal1, DATA_BLOB *chal2)
{
	BOOL ret;
	ASN1_DATA data;

	ZERO_STRUCTP(chal1);
	ZERO_STRUCTP(chal2);

	asn1_load(&data, blob);
	asn1_start_tag(&data,ASN1_CONTEXT(1));
	asn1_start_tag(&data,ASN1_SEQUENCE(0));

	asn1_start_tag(&data,ASN1_CONTEXT(0));
	asn1_check_enumerated(&data,1);
	asn1_end_tag(&data);

	asn1_start_tag(&data,ASN1_CONTEXT(1));
	asn1_check_OID(&data, OID_NTLMSSP);
	asn1_end_tag(&data);

	asn1_start_tag(&data,ASN1_CONTEXT(2));
	asn1_read_OctetString(&data, chal1);
	asn1_end_tag(&data);

	/* the second challenge is optional (XP doesn't send it) */
	if (asn1_tag_remaining(&data)) {
		asn1_start_tag(&data,ASN1_CONTEXT(3));
		asn1_read_OctetString(&data, chal2);
		asn1_end_tag(&data);
	}

	asn1_end_tag(&data);
	asn1_end_tag(&data);

	ret = !data.has_error;
	asn1_free(&data);
	return ret;
}


/*
  generate a spnego NTLMSSP challenge packet given two security blobs
  The second challenge is optional
*/
BOOL spnego_gen_challenge(DATA_BLOB *blob,
			  DATA_BLOB *chal1, DATA_BLOB *chal2)
{
	ASN1_DATA data;

	ZERO_STRUCT(data);

	asn1_push_tag(&data,ASN1_CONTEXT(1));
	asn1_push_tag(&data,ASN1_SEQUENCE(0));

	asn1_push_tag(&data,ASN1_CONTEXT(0));
	asn1_write_enumerated(&data,1);
	asn1_pop_tag(&data);

	asn1_push_tag(&data,ASN1_CONTEXT(1));
	asn1_write_OID(&data, OID_NTLMSSP);
	asn1_pop_tag(&data);

	asn1_push_tag(&data,ASN1_CONTEXT(2));
	asn1_write_OctetString(&data, chal1->data, chal1->length);
	asn1_pop_tag(&data);

	/* the second challenge is optional (XP doesn't send it) */
	if (chal2) {
		asn1_push_tag(&data,ASN1_CONTEXT(3));
		asn1_write_OctetString(&data, chal2->data, chal2->length);
		asn1_pop_tag(&data);
	}

	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	if (data.has_error) {
		return False;
	}

	*blob = data_blob(data.data, data.length);
	asn1_free(&data);
	return True;
}

/*
 generate a SPNEGO NTLMSSP auth packet. This will contain the encrypted passwords
*/
DATA_BLOB spnego_gen_auth(DATA_BLOB blob)
{
	ASN1_DATA data;
	DATA_BLOB ret;

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data, ASN1_CONTEXT(1));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	asn1_push_tag(&data, ASN1_CONTEXT(2));
	asn1_write_OctetString(&data,blob.data,blob.length);	
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	ret = data_blob(data.data, data.length);

	asn1_free(&data);

	return ret;
}

/*
 parse a SPNEGO NTLMSSP auth packet. This contains the encrypted passwords
*/
BOOL spnego_parse_auth(DATA_BLOB blob, DATA_BLOB *auth)
{
	ASN1_DATA data;

	asn1_load(&data, blob);
	asn1_start_tag(&data, ASN1_CONTEXT(1));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_CONTEXT(2));
	asn1_read_OctetString(&data,auth);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);

	if (data.has_error) {
		DEBUG(3,("spnego_parse_auth failed at %d\n", (int)data.ofs));
		asn1_free(&data);
		return False;
	}

	asn1_free(&data);
	return True;
}


/*
  this is a tiny msrpc packet generator. I am only using this to
  avoid tying this code to a particular varient of our rpc code. This
  generator is not general enough for all our rpc needs, its just
  enough for the spnego/ntlmssp code

  format specifiers are:

  U = unicode string (input is unix string)
  B = data blob (pointer + length)
  b = data blob in header (pointer + length)
  d = word (4 bytes)
  C = constant ascii string
 */
BOOL msrpc_gen(DATA_BLOB *blob,
	       const char *format, ...)
{
	int i, n;
	va_list ap;
	char *s;
	uint8 *b;
	int head_size=0, data_size=0;
	int head_ofs, data_ofs;

	/* first scan the format to work out the header and body size */
	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			s = va_arg(ap, char *);
			head_size += 8;
			data_size += str_charnum(s) * 2;
			break;
		case 'B':
			b = va_arg(ap, uint8 *);
			head_size += 8;
			data_size += va_arg(ap, int);
			break;
		case 'b':
			b = va_arg(ap, uint8 *);
			head_size += va_arg(ap, int);
			break;
		case 'd':
			n = va_arg(ap, int);
			head_size += 4;
			break;
		case 'C':
			s = va_arg(ap, char *);
			head_size += str_charnum(s) + 1;
			break;
		}
	}
	va_end(ap);

	/* allocate the space, then scan the format again to fill in the values */
	blob->data = malloc(head_size + data_size);
	blob->length = head_size + data_size;
	if (!blob->data) return False;

	head_ofs = 0;
	data_ofs = head_size;

	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			s = va_arg(ap, char *);
			n = str_charnum(s);
			SSVAL(blob->data, head_ofs, n*2); head_ofs += 2;
			SSVAL(blob->data, head_ofs, n*2); head_ofs += 2;
			SIVAL(blob->data, head_ofs, data_ofs); head_ofs += 4;
			push_string(NULL, blob->data+data_ofs, s, n*2, STR_UNICODE|STR_NOALIGN);
			data_ofs += n*2;
			break;
		case 'B':
			b = va_arg(ap, uint8 *);
			n = va_arg(ap, int);
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SIVAL(blob->data, head_ofs, data_ofs); head_ofs += 4;
			memcpy(blob->data+data_ofs, b, n);
			data_ofs += n;
			break;
		case 'd':
			n = va_arg(ap, int);
			SIVAL(blob->data, head_ofs, n); head_ofs += 4;
			break;
		case 'b':
			b = va_arg(ap, uint8 *);
			n = va_arg(ap, int);
			memcpy(blob->data + head_ofs, b, n);
			head_ofs += n;
			break;
		case 'C':
			s = va_arg(ap, char *);
			head_ofs += push_string(NULL, blob->data+head_ofs, s, -1, 
						STR_ASCII|STR_TERMINATE);
			break;
		}
	}
	va_end(ap);

	return True;
}


/*
  this is a tiny msrpc packet parser. This the the partner of msrpc_gen

  format specifiers are:

  U = unicode string (input is unix string)
  B = data blob
  b = data blob in header
  d = word (4 bytes)
  C = constant ascii string
 */
BOOL msrpc_parse(DATA_BLOB *blob,
		 const char *format, ...)
{
	int i;
	va_list ap;
	char **ps, *s;
	DATA_BLOB *b;
	int head_ofs = 0;
	uint16 len1, len2;
	uint32 ptr;
	uint32 *v;
	pstring p;

	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;
			/* make sure its in the right format - be strict */
			if (len1 != len2 || (len1&1) || ptr + len1 > blob->length) {
				return False;
			}
			ps = va_arg(ap, char **);
			pull_string(NULL, p, blob->data + ptr, -1, len1, 
				    STR_UNICODE|STR_NOALIGN);
			(*ps) = strdup(p);
			break;
		case 'B':
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;
			/* make sure its in the right format - be strict */
			if (len1 != len2 || ptr + len1 > blob->length) {
				return False;
			}
			b = (DATA_BLOB *)va_arg(ap, void *);
			*b = data_blob(blob->data + ptr, len1);
			break;
		case 'b':
			b = (DATA_BLOB *)va_arg(ap, void *);
			len1 = va_arg(ap, unsigned);
			*b = data_blob(blob->data + head_ofs, len1);
			head_ofs += len1;
			break;
		case 'd':
			v = va_arg(ap, uint32 *);
			*v = IVAL(blob->data, head_ofs); head_ofs += 4;
			break;
		case 'C':
			s = va_arg(ap, char *);
			head_ofs += pull_string(NULL, p, blob->data+head_ofs, -1, 
						blob->length - head_ofs, 
						STR_ASCII|STR_TERMINATE);
			if (strcmp(s, p) != 0) {
				return False;
			}
			break;
		}
	}
	va_end(ap);

	return True;
}
