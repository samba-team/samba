 /* 
   Unix SMB/CIFS implementation.

   ldif utilities for ldb

   Copyright (C) Andrew Tridgell 2004
   
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
  this base64 decoder was taken from jitterbug (written by tridge).
  we might need to replace it with a new version
*/
static int base64_decode(char *s)
{
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int bit_offset, byte_offset, idx, i, n;
	unsigned char *d = (unsigned char *)s;
	char *p;

	n=i=0;

	while (*s && (p=strchr(b64,*s))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		d[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			d[byte_offset] |= (idx << (2-bit_offset));
			n = byte_offset+1;
		} else {
			d[byte_offset] |= (idx >> (bit_offset-2));
			d[byte_offset+1] = 0;
			d[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			n = byte_offset+2;
		}
		s++; i++;
	}

	if (*s && !p) {
		/* the only termination allowed */
		if (*s != '=') {
			return -1;
		}
	}

	/* null terminate */
	d[n] = 0;
	return n;
}


/*
  encode as base64
  caller frees
*/
char *ldb_base64_encode(const char *buf, int len)
{
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int bit_offset, byte_offset, idx, i;
	unsigned char *d = (unsigned char *)buf;
	int bytes = (len*8 + 5)/6;
	char *out;

	out = malloc(bytes+2);
	if (!out) return NULL;

	for (i=0;i<bytes;i++) {
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		if (bit_offset < 3) {
			idx = (d[byte_offset] >> (2-bit_offset)) & 0x3F;
		} else {
			idx = (d[byte_offset] << (bit_offset-2)) & 0x3F;
			if (byte_offset+1 < len) {
				idx |= (d[byte_offset+1] >> (8-(bit_offset-2)));
			}
		}
		out[i] = b64[idx];
	}

	out[i++] = '=';
	out[i] = 0;

	return out;
}

/*
  see if a buffer should be base64 encoded
*/
int ldb_should_b64_encode(const struct ldb_val *val)
{
	int i;
	unsigned char *p = val->data;

	if (val->length == 0 || p[0] == ' ' || p[0] == ':') {
		return 1;
	}

	for (i=0; i<val->length; i++) {
		if (!isprint(p[i]) || p[i] == '\n') {
			return 1;
		}
	}
	return 0;
}


/*
  encode as base64 to a file
*/
static int base64_encode_f(FILE *f, const char *buf, int len, int start_pos)
{
	int i;
	char *b = ldb_base64_encode(buf, len);

	if (!b) {
		return -1;
	}

	for (i=0;b[i];i++) {
		fputc(b[i], f);
		if (b[i+1] && (i + start_pos) % 77 == 0) {
			fputc('\n', f);
			fputc(' ', f);
		}
	}
	free(b);
	return 0;
}

/*
  write a line folded string onto a file
*/
static void fold_string(FILE *f, const char *buf, size_t length, int start_pos)
{
	int i;

	for (i=0;i<length;i++) {
		fputc(buf[i], f);
		if (i != (length-1) && (i + start_pos) % 77 == 0) {
			fputc('\n', f);
			fputc(' ', f);
		}
	}
}


/*
  pull a ldif chunk, which is defined as a piece of data ending in \n\n or EOF
  this routine removes any RFC2849 continuations and comments

  caller frees
*/
static char *next_chunk(FILE *f)
{
	size_t alloc_size=0, chunk_size = 0;
	char *chunk = NULL;
	int c;
	int in_comment = 0;

	while ((c = fgetc(f)) != EOF) {
		if (chunk_size == alloc_size) {
			char *c2;
			alloc_size += 1024;
			c2 = realloc_p(chunk, char, alloc_size);
			if (!c2) {
				free(chunk);
				errno = ENOMEM;
				return NULL;
			}
			chunk = c2;
		}

		if (in_comment) {
			if (c == '\n') {
				in_comment = 0;
			}
			continue;			
		}
		
		/* handle continuation lines - see RFC2849 */
		if (c == ' ' && chunk_size > 1 && chunk[chunk_size-1] == '\n') {
			chunk_size--;
			continue;
		}
		
		/* chunks are terminated by a double line-feed */
		if (c == '\n' && chunk_size > 0 && chunk[chunk_size-1] == '\n') {
			chunk[chunk_size-1] = 0;
			return chunk;
		}

		if (c == '#' && (chunk_size == 0 || chunk[chunk_size-1] == '\n')) {
			in_comment = 1;
			continue;
		}

		chunk[chunk_size++] = c;
	}

	return chunk;
}


/* simple ldif attribute parser */
static int next_attr(char **s, char **attr, struct ldb_val *value)
{
	char *p;
	int base64_encoded = 0;

	p = strchr(*s, ':');
	if (!p) {
		return -1;
	}

	*p++ = 0;

	if (*p == ':') {
		base64_encoded = 1;
		p++;
	}

	*attr = *s;

	while (isspace(*p)) {
		p++;
	}

	value->data = p;

	p = strchr(p, '\n');

	if (!p) {
		value->length = strlen((char *)value->data);
		*s = ((char *)value->data) + value->length;
	} else {
		value->length = p - (char *)value->data;
		*s = p+1;
		*p = 0;
	}

	if (base64_encoded) {
		int len = base64_decode(value->data);
		if (len == -1) {
			/* it wasn't valid base64 data */
			return -1;
		}
		value->length = len;
	}

	return 0;
}


/*
  free a message from a ldif_read
*/
void ldif_read_free(struct ldb_message *msg)
{
	if (msg->elements) free(msg->elements);
	if (msg->private) free(msg->private);
	free(msg);
}

/*
 read from a LDIF file, creating a ldb_message
*/
struct ldb_message *ldif_read(FILE *f)
{
	struct ldb_message *msg;
	char *attr=NULL, *chunk=NULL, *s;
	struct ldb_val value;

	value.data = NULL;

	msg = malloc_p(struct ldb_message);
	if (!msg) return NULL;

	msg->dn = NULL;
	msg->elements = NULL;
	msg->num_elements = 0;
	msg->private = NULL;

	chunk = next_chunk(f);
	if (!chunk) {
		goto failed;
	}

	msg->private = chunk;
	s = chunk;

	if (next_attr(&s, &attr, &value) != 0) {
		goto failed;
	}
	
	/* first line must be a dn */
	if (strcmp(attr, "dn") != 0) {
		fprintf(stderr, "First line must be a dn not '%s'\n", attr);
		goto failed;
	}

	msg->dn = value.data;

	while (next_attr(&s, &attr, &value) == 0) {
		msg->elements = realloc_p(msg->elements, 
					  struct ldb_message_element, 
					  msg->num_elements+1);
		if (!msg->elements) {
			goto failed;
		}
		msg->elements[msg->num_elements].flags = 0;
		msg->elements[msg->num_elements].name = attr;
		msg->elements[msg->num_elements].value = value;
		msg->num_elements++;
	}

	return msg;

failed:
	if (msg) ldif_read_free(msg);
	return NULL;
}


/*
  write to a ldif file 
*/
void ldif_write(FILE *f, const struct ldb_message *msg)
{
	int i;
	fprintf(f, "dn: %s\n", msg->dn);
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_should_b64_encode(&msg->elements[i].value)) {
			fprintf(f, "%s:: ", msg->elements[i].name);
			base64_encode_f(f, 
					msg->elements[i].value.data, 
					msg->elements[i].value.length,
					strlen(msg->elements[i].name)+3);
			fprintf(f, "\n");
		} else {
			fprintf(f, "%s: ", msg->elements[i].name);
			fold_string(f, msg->elements[i].value.data,				    
				    msg->elements[i].value.length,
				    strlen(msg->elements[i].name)+2);
			fprintf(f, "\n");
		}
	}
	fprintf(f,"\n");
}
