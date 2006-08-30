/* 
   Unix SMB/CIFS implementation.
   simple kerberos5/SPNEGO routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Andrew Bartlett 2002-2003
   
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
#include "pstring.h"

/*
  this is a tiny msrpc packet generator. I am only using this to
  avoid tying this code to a particular varient of our rpc code. This
  generator is not general enough for all our rpc needs, its just
  enough for the spnego/ntlmssp code

  format specifiers are:

  U = unicode string (input is unix string)
  a = address (input is char *unix_string)
      (1 byte type, 1 byte length, unicode/ASCII string, all inline)
  A = ASCII string (input is unix string)
  B = data blob (pointer + length)
  b = data blob in header (pointer + length)
  D
  d = word (4 bytes)
  C = constant ascii string
 */
BOOL msrpc_gen(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
	       const char *format, ...)
{
	int i;
	ssize_t n;
	va_list ap;
	char *s;
	uint8_t *b;
	int head_size=0, data_size=0;
	int head_ofs, data_ofs;
	int *intargs;

	DATA_BLOB *pointers;

	pointers = talloc_array(mem_ctx, DATA_BLOB, strlen(format));
	intargs = talloc_array(pointers, int, strlen(format));

	/* first scan the format to work out the header and body size */
	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			s = va_arg(ap, char *);
			head_size += 8;
			n = push_ucs2_talloc(pointers, (void **)&pointers[i].data, s);
			if (n == -1) {
				return False;
			}
			pointers[i].length = n;
			pointers[i].length -= 2;
			data_size += pointers[i].length;
			break;
		case 'A':
			s = va_arg(ap, char *);
			head_size += 8;
			n = push_ascii_talloc(pointers, (char **)&pointers[i].data, s);
			if (n == -1) {
				return False;
			}
			pointers[i].length = n;
			pointers[i].length -= 1;
			data_size += pointers[i].length;
			break;
		case 'a':
			n = va_arg(ap, int);
			intargs[i] = n;
			s = va_arg(ap, char *);
			n = push_ucs2_talloc(pointers, (void **)&pointers[i].data, s);
			if (n == -1) {
				return False;
			}
			pointers[i].length = n;
			pointers[i].length -= 2;
			data_size += pointers[i].length + 4;
			break;
		case 'B':
			b = va_arg(ap, uint8_t *);
			head_size += 8;
			pointers[i].data = b;
			pointers[i].length = va_arg(ap, int);
			data_size += pointers[i].length;
			break;
		case 'b':
			b = va_arg(ap, uint8_t *);
			pointers[i].data = b;
			pointers[i].length = va_arg(ap, int);
			head_size += pointers[i].length;
			break;
		case 'd':
			n = va_arg(ap, int);
			intargs[i] = n;
			head_size += 4;
			break;
		case 'C':
			s = va_arg(ap, char *);
			pointers[i].data = (uint8_t *)s;
			pointers[i].length = strlen(s)+1;
			head_size += pointers[i].length;
			break;
		}
	}
	va_end(ap);

	/* allocate the space, then scan the format again to fill in the values */
	*blob = data_blob_talloc(mem_ctx, NULL, head_size + data_size);

	head_ofs = 0;
	data_ofs = head_size;

	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
		case 'A':
		case 'B':
			n = pointers[i].length;
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SIVAL(blob->data, head_ofs, data_ofs); head_ofs += 4;
			if (pointers[i].data && n) /* don't follow null pointers... */
				memcpy(blob->data+data_ofs, pointers[i].data, n);
			data_ofs += n;
			break;
		case 'a':
			n = intargs[i];
			SSVAL(blob->data, data_ofs, n); data_ofs += 2;

			n = pointers[i].length;
			SSVAL(blob->data, data_ofs, n); data_ofs += 2;
			if (n >= 0) {
				memcpy(blob->data+data_ofs, pointers[i].data, n);
			}
			data_ofs += n;
			break;
		case 'd':
			n = intargs[i];
			SIVAL(blob->data, head_ofs, n); 
			head_ofs += 4;
			break;
		case 'b':
			n = pointers[i].length;
			memcpy(blob->data + head_ofs, pointers[i].data, n);
			head_ofs += n;
			break;
		case 'C':
			n = pointers[i].length;
			memcpy(blob->data + head_ofs, pointers[i].data, n);
			head_ofs += n;
			break;
		}
	}
	va_end(ap);
	
	talloc_free(pointers);

	return True;
}


/* a helpful macro to avoid running over the end of our blob */
#define NEED_DATA(amount) \
if ((head_ofs + amount) > blob->length) { \
        return False; \
}

/*
  this is a tiny msrpc packet parser. This the the partner of msrpc_gen

  format specifiers are:

  U = unicode string (output is unix string)
  A = ascii string
  B = data blob
  b = data blob in header
  d = word (4 bytes)
  C = constant ascii string
 */

BOOL msrpc_parse(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob,
		 const char *format, ...)
{
	int i;
	va_list ap;
	const char **ps, *s;
	DATA_BLOB *b;
	size_t head_ofs = 0;
	uint16_t len1, len2;
	uint32_t ptr;
	uint32_t *v;
	pstring p;

	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			NEED_DATA(8);
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;

			ps = (const char **)va_arg(ap, char **);
			if (len1 == 0 && len2 == 0) {
				*ps = "";
			} else {
				/* make sure its in the right format - be strict */
				if ((len1 != len2) || (ptr + len1 < ptr) || (ptr + len1 < len1) || (ptr + len1 > blob->length)) {
					return False;
				}
				if (len1 & 1) {
					/* if odd length and unicode */
					return False;
				}
				if (blob->data + ptr < (uint8_t *)ptr || blob->data + ptr < blob->data)
					return False;

				if (0 < len1) {
					pull_string(p, blob->data + ptr, sizeof(p), 
						    len1, STR_UNICODE|STR_NOALIGN);
					(*ps) = talloc_strdup(mem_ctx, p);
					if (!(*ps)) {
						return False;
					}
				} else {
					(*ps) = "";
				}
			}
			break;
		case 'A':
			NEED_DATA(8);
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;

			ps = (const char **)va_arg(ap, char **);
			/* make sure its in the right format - be strict */
			if (len1 == 0 && len2 == 0) {
				*ps = "";
			} else {
				if ((len1 != len2) || (ptr + len1 < ptr) || (ptr + len1 < len1) || (ptr + len1 > blob->length)) {
					return False;
				}

				if (blob->data + ptr < (uint8_t *)ptr || blob->data + ptr < blob->data)
					return False;	

				if (0 < len1) {
					pull_string(p, blob->data + ptr, sizeof(p), 
						    len1, STR_ASCII|STR_NOALIGN);
					(*ps) = talloc_strdup(mem_ctx, p);
					if (!(*ps)) {
						return False;
					}
				} else {
					(*ps) = "";
				}
			}
			break;
		case 'B':
			NEED_DATA(8);
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;

			b = (DATA_BLOB *)va_arg(ap, void *);
			if (len1 == 0 && len2 == 0) {
				*b = data_blob_talloc(mem_ctx, NULL, 0);
			} else {
				/* make sure its in the right format - be strict */
				if ((len1 != len2) || (ptr + len1 < ptr) || (ptr + len1 < len1) || (ptr + len1 > blob->length)) {
					return False;
				}

				if (blob->data + ptr < (uint8_t *)ptr || blob->data + ptr < blob->data)
					return False;	
			
				*b = data_blob_talloc(mem_ctx, blob->data + ptr, len1);
			}
			break;
		case 'b':
			b = (DATA_BLOB *)va_arg(ap, void *);
			len1 = va_arg(ap, uint_t);
			/* make sure its in the right format - be strict */
			NEED_DATA(len1);
			if (blob->data + head_ofs < (uint8_t *)head_ofs || blob->data + head_ofs < blob->data)
				return False;	
			
			*b = data_blob_talloc(mem_ctx, blob->data + head_ofs, len1);
			head_ofs += len1;
			break;
		case 'd':
			v = va_arg(ap, uint32_t *);
			NEED_DATA(4);
			*v = IVAL(blob->data, head_ofs); head_ofs += 4;
			break;
		case 'C':
			s = va_arg(ap, char *);

			if (blob->data + head_ofs < (uint8_t *)head_ofs || blob->data + head_ofs < blob->data)
				return False;	
	
			head_ofs += pull_string(p, blob->data+head_ofs, sizeof(p), 
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
