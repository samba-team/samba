/* 
   Unix SMB/CIFS implementation.   
   simple ASN1 code
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

#ifndef _ASN_1_H
#define _ASN_1_H

struct nesting {
	off_t start;
	size_t taglen; /* for parsing */
	struct nesting *next;
};

typedef struct {
	uint8 *data;
	size_t length;
	off_t ofs;
	struct nesting *nesting;
	BOOL has_error;
} ASN1_DATA;


#define ASN1_APPLICATION(x) ((x)+0x60)
#define ASN1_SEQUENCE(x) ((x)+0x30)
#define ASN1_CONTEXT(x) ((x)+0xa0)
#define ASN1_GENERAL_STRING 0x1b
#define ASN1_OCTET_STRING 0x4
#define ASN1_OID 0x6
#define ASN1_BOOLEAN 0x1
#define ASN1_INTEGER 0x2
#define ASN1_ENUMERATED 0xa

#define ASN1_MAX_OIDS 20

/* some well known object IDs */
#define OID_SPNEGO "1 3 6 1 5 5 2"
#define OID_NTLMSSP "1 3 6 1 4 1 311 2 2 10"
#define OID_KERBEROS5_OLD "1 2 840 48018 1 2 2"
#define OID_KERBEROS5 "1 2 840 113554 1 2 2"

#endif /* _ASN_1_H */
