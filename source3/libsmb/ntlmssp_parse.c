/*
   Unix SMB/CIFS implementation.
   simple kerberos5/SPNEGO routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Andrew Bartlett 2002-2003

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
bool msrpc_gen(DATA_BLOB *blob,
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
		case 'A':
			s = va_arg(ap, char *);
			head_size += 8;
			data_size += str_ascii_charnum(s);
			break;
		case 'a':
			n = va_arg(ap, int);
			s = va_arg(ap, char *);
			data_size += (str_charnum(s) * 2) + 4;
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

	/* allocate the space, then scan the format
	 * again to fill in the values */

	*blob = data_blob(NULL, head_size + data_size);

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
			push_string(NULL, blob->data+data_ofs,
					s, n*2, STR_UNICODE|STR_NOALIGN);
			data_ofs += n*2;
			break;
		case 'A':
			s = va_arg(ap, char *);
			n = str_ascii_charnum(s);
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SIVAL(blob->data, head_ofs, data_ofs); head_ofs += 4;
			push_string(NULL, blob->data+data_ofs,
					s, n, STR_ASCII|STR_NOALIGN);
			data_ofs += n;
			break;
		case 'a':
			n = va_arg(ap, int);
			SSVAL(blob->data, data_ofs, n); data_ofs += 2;
			s = va_arg(ap, char *);
			n = str_charnum(s);
			SSVAL(blob->data, data_ofs, n*2); data_ofs += 2;
			if (0 < n) {
				push_string(NULL, blob->data+data_ofs, s, n*2,
					    STR_UNICODE|STR_NOALIGN);
			}
			data_ofs += n*2;
			break;

		case 'B':
			b = va_arg(ap, uint8 *);
			n = va_arg(ap, int);
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SSVAL(blob->data, head_ofs, n); head_ofs += 2;
			SIVAL(blob->data, head_ofs, data_ofs); head_ofs += 4;
			if (n && b) /* don't follow null pointers... */
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
			n = str_charnum(s) + 1;
			head_ofs += push_string(NULL, blob->data+head_ofs, s, n,
						STR_ASCII|STR_TERMINATE);
			break;
		}
	}
	va_end(ap);

	return true;
}


/* a helpful macro to avoid running over the end of our blob */
#define NEED_DATA(amount) \
if ((head_ofs + amount) > blob->length) { \
        va_end(ap); \
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

bool msrpc_parse(const DATA_BLOB *blob,
		 const char *format, ...)
{
	int i;
	va_list ap;
	char **ps, *s;
	DATA_BLOB *b;
	size_t head_ofs = 0;
	uint16 len1, len2;
	uint32 ptr;
	uint32 *v;

	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			NEED_DATA(8);
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;

			ps = va_arg(ap, char **);
			if (len1 == 0 && len2 == 0) {
				*ps = smb_xstrdup("");
			} else {
				/* make sure its in the right format
				 * be strict */
				if ((len1 != len2) || (ptr + len1 < ptr) ||
						(ptr + len1 < len1) ||
						(ptr + len1 > blob->length)) {
					va_end(ap);
					return false;
				}
				if (len1 & 1) {
					/* if odd length and unicode */
					va_end(ap);
					return false;
				}
				if (blob->data + ptr <
						(uint8 *)(unsigned long)ptr ||
				    blob->data + ptr < blob->data) {
					va_end(ap);
					return false;
				}

				if (0 < len1) {
					char *p = NULL;
					pull_string_talloc(talloc_tos(),
						NULL,
						0,
						&p,
						blob->data + ptr,
						len1,
						STR_UNICODE|STR_NOALIGN);
					if (p) {
						(*ps) = smb_xstrdup(p);
						TALLOC_FREE(p);
					} else {
						(*ps) = smb_xstrdup("");
					}
				} else {
					(*ps) = smb_xstrdup("");
				}
			}
			break;
		case 'A':
			NEED_DATA(8);
			len1 = SVAL(blob->data, head_ofs); head_ofs += 2;
			len2 = SVAL(blob->data, head_ofs); head_ofs += 2;
			ptr =  IVAL(blob->data, head_ofs); head_ofs += 4;

			ps = va_arg(ap, char **);
			/* make sure its in the right format - be strict */
			if (len1 == 0 && len2 == 0) {
				*ps = smb_xstrdup("");
			} else {
				if ((len1 != len2) || (ptr + len1 < ptr) ||
						(ptr + len1 < len1) ||
						(ptr + len1 > blob->length)) {
					va_end(ap);
					return false;
				}

				if (blob->data + ptr <
						(uint8 *)(unsigned long)ptr ||
				    blob->data + ptr < blob->data) {
					va_end(ap);
					return false;
				}

				if (0 < len1) {
					char *p = NULL;
					pull_string_talloc(talloc_tos(),
						NULL,
						0,
						&p,
						blob->data + ptr,
						len1,
						STR_ASCII|STR_NOALIGN);
					if (p) {
						(*ps) = smb_xstrdup(p);
						TALLOC_FREE(p);
					} else {
						(*ps) = smb_xstrdup("");
					}
				} else {
					(*ps) = smb_xstrdup("");
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
				*b = data_blob_null;
			} else {
				/* make sure its in the right format
				 * be strict */
				if ((len1 != len2) || (ptr + len1 < ptr) ||
						(ptr + len1 < len1) ||
						(ptr + len1 > blob->length)) {
					va_end(ap);
					return false;
				}

				if (blob->data + ptr <
						(uint8 *)(unsigned long)ptr ||
				    blob->data + ptr < blob->data) {
					va_end(ap);
					return false;
				}

				*b = data_blob(blob->data + ptr, len1);
			}
			break;
		case 'b':
			b = (DATA_BLOB *)va_arg(ap, void *);
			len1 = va_arg(ap, unsigned);
			/* make sure its in the right format - be strict */
			NEED_DATA(len1);
			if (blob->data + head_ofs < (uint8 *)head_ofs ||
					blob->data + head_ofs < blob->data) {
				va_end(ap);
				return false;
			}

			*b = data_blob(blob->data + head_ofs, len1);
			head_ofs += len1;
			break;
		case 'd':
			v = va_arg(ap, uint32 *);
			NEED_DATA(4);
			*v = IVAL(blob->data, head_ofs); head_ofs += 4;
			break;
		case 'C':
			s = va_arg(ap, char *);

			if (blob->data + head_ofs < (uint8 *)head_ofs ||
			    blob->data + head_ofs < blob->data) {
				va_end(ap);
				return false;
			}

			{
				char *p = NULL;
				size_t ret = pull_string_talloc(talloc_tos(),
						NULL,
						0,
						&p,
						blob->data+head_ofs,
						blob->length - head_ofs,
						STR_ASCII|STR_TERMINATE);
				if (ret == (size_t)-1 || p == NULL) {
					va_end(ap);
					return false;
				}
				head_ofs += ret;
				if (strcmp(s, p) != 0) {
					TALLOC_FREE(p);
					va_end(ap);
					return false;
				}
				TALLOC_FREE(p);
			}
			break;
		}
	}
	va_end(ap);

	return True;
}
