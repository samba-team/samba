/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldif routines
 *
 *  Description: ldif pack/unpack routines
 *
 *  Author: Andrew Tridgell
 */

/*
  see RFC2849 for the LDIF format definition
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

/* this macro is used to handle the return checking on fprintf_fn() */
#define CHECK_RET do { if (ret < 0) return ret; total += ret; } while (0)

/*
  write a line folded string onto a file
*/
static int fold_string(int (*fprintf_fn)(void *, const char *, ...), void *private,
			const char *buf, size_t length, int start_pos)
{
	int i;
	int total=0, ret;

	for (i=0;i<length;i++) {
		ret = fprintf_fn(private, "%c", buf[i]);
		CHECK_RET;
		if (i != (length-1) && (i + start_pos) % 77 == 0) {
			ret = fprintf_fn(private, "\n ");
			CHECK_RET;
		}
	}

	return total;
}

/*
  encode as base64 to a file
*/
static int base64_encode_f(int (*fprintf_fn)(void *, const char *, ...), void *private,
			   const char *buf, int len, int start_pos)
{
	char *b = ldb_base64_encode(buf, len);
	int ret;

	if (!b) {
		return -1;
	}

	ret = fold_string(fprintf_fn, private, b, strlen(b), start_pos);

	free(b);
	return ret;
}


static const struct {
	const char *name;
	enum ldb_changetype changetype;
} ldb_changetypes[] = {
	{"add",    LDB_CHANGETYPE_ADD},
	{"delete", LDB_CHANGETYPE_DELETE},
	{"modify", LDB_CHANGETYPE_MODIFY},
	{NULL, 0}
};

/*
  write to ldif, using a caller supplied write method
*/
int ldif_write(int (*fprintf_fn)(void *, const char *, ...), 
	       void *private,
	       const struct ldb_ldif *ldif)
{
	int i, j;
	int total=0, ret;
	const struct ldb_message *msg;

	msg = &ldif->msg;

	ret = fprintf_fn(private, "dn: %s\n", msg->dn);
	CHECK_RET;

	if (ldif->changetype != LDB_CHANGETYPE_NONE) {
		for (i=0;ldb_changetypes[i].name;i++) {
			if (ldb_changetypes[i].changetype == ldif->changetype) {
				break;
			}
		}
		if (!ldb_changetypes[i].name) {
			fprintf(stderr,"Invalid changetype\n");
			return -1;
		}
		ret = fprintf_fn(private, "changetype: %s\n", ldb_changetypes[i].name);
		CHECK_RET;
	}

	for (i=0;i<msg->num_elements;i++) {
		for (j=0;j<msg->elements[i].num_values;j++) {
			if (ldb_should_b64_encode(&msg->elements[i].values[j])) {
				ret = fprintf_fn(private, "%s:: ", 
						 msg->elements[i].name);
				CHECK_RET;
				ret = base64_encode_f(fprintf_fn, private, 
						      msg->elements[i].values[j].data, 
						      msg->elements[i].values[j].length,
						      strlen(msg->elements[i].name)+3);
				CHECK_RET;
				ret = fprintf_fn(private, "\n");
				CHECK_RET;
			} else {
				ret = fprintf_fn(private, "%s: ", msg->elements[i].name);
				CHECK_RET;
				ret = fold_string(fprintf_fn, private,
						  msg->elements[i].values[j].data,
						  msg->elements[i].values[j].length,
						  strlen(msg->elements[i].name)+2);
				CHECK_RET;
				ret = fprintf_fn(private, "\n");
				CHECK_RET;
			}
		}
	}
	ret = fprintf_fn(private,"\n");
	CHECK_RET;

	return total;
}

#undef CHECK_RET


/*
  pull a ldif chunk, which is defined as a piece of data ending in \n\n or EOF
  this routine removes any RFC2849 continuations and comments

  caller frees
*/
static char *next_chunk(int (*fgetc_fn)(void *), void *private)
{
	size_t alloc_size=0, chunk_size = 0;
	char *chunk = NULL;
	int c;
	int in_comment = 0;

	while ((c = fgetc_fn(private)) != EOF) {
		if (chunk_size+1 >= alloc_size) {
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

		/* ignore leading blank lines */
		if (chunk_size == 0 && c == '\n') {
			continue;
		}

		chunk[chunk_size++] = c;
	}

	if (chunk) {
		chunk[chunk_size] = 0;
	}

	return chunk;
}


/* simple ldif attribute parser */
static int next_attr(char **s, char **attr, struct ldb_val *value)
{
	char *p;
	int base64_encoded = 0;

	if (strncmp(*s, "-\n", 2) == 0) {
		value->length = 0;
		*attr = "-";
		*s += 2;
		return 0;
	}

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
void ldif_read_free(struct ldb_ldif *ldif)
{
	struct ldb_message *msg = &ldif->msg;
	int i;
	for (i=0;i<msg->num_elements;i++) {
		if (msg->elements[i].values) free(msg->elements[i].values);
	}
	if (msg->elements) free(msg->elements);
	if (msg->private) free(msg->private);
	free(ldif);
}

/*
  add an empty element
*/
static int msg_add_empty(struct ldb_message *msg, const char *name, unsigned flags)
{
	struct ldb_message_element *el2, *el;

	el2 = realloc_p(msg->elements, struct ldb_message_element, msg->num_elements+1);
	if (!el2) {
		errno = ENOMEM;
		return -1;
	}
	
	msg->elements = el2;

	el = &msg->elements[msg->num_elements];
	
	el->name = name;
	el->num_values = 0;
	el->values = NULL;
	el->flags = flags;

	msg->num_elements++;

	return 0;
}

/*
 read from a LDIF source, creating a ldb_message
*/
struct ldb_ldif *ldif_read(int (*fgetc_fn)(void *), void *private)
{
	struct ldb_ldif *ldif;
	struct ldb_message *msg;
	char *attr=NULL, *chunk=NULL, *s;
	struct ldb_val value;
	unsigned flags = 0;

	value.data = NULL;

	ldif = malloc_p(struct ldb_ldif);
	if (!ldif) return NULL;

	ldif->changetype = LDB_CHANGETYPE_NONE;
	msg = &ldif->msg;

	msg->dn = NULL;
	msg->elements = NULL;
	msg->num_elements = 0;
	msg->private = NULL;

	chunk = next_chunk(fgetc_fn, private);
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
		struct ldb_message_element *el;
		int empty = 0;

		if (strcmp(attr, "changetype") == 0) {
			int i;
			for (i=0;ldb_changetypes[i].name;i++) {
				if (strcmp((char *)value.data, ldb_changetypes[i].name) == 0) {
					ldif->changetype = ldb_changetypes[i].changetype;
					break;
				}
			}
			if (!ldb_changetypes[i].name) {
				fprintf(stderr,"Bad changetype '%s'\n",
					(char *)value.data);
			}
			flags = 0;
			continue;
		}

		if (strcmp(attr, "add") == 0) {
			flags = LDB_FLAG_MOD_ADD;
			empty = 1;
		}
		if (strcmp(attr, "delete") == 0) {
			flags = LDB_FLAG_MOD_DELETE;
			empty = 1;
		}
		if (strcmp(attr, "replace") == 0) {
			flags = LDB_FLAG_MOD_REPLACE;
			empty = 1;
		}
		if (strcmp(attr, "-") == 0) {
			flags = 0;
			continue;
		}

		if (empty) {
			if (msg_add_empty(msg, (char *)value.data, flags) != 0) {
				goto failed;
			}
			continue;
		}
		
		el = &msg->elements[msg->num_elements-1];

		if (msg->num_elements > 0 && strcmp(attr, el->name) == 0 &&
		    flags == el->flags) {
			/* its a continuation */
			el->values = 
				realloc_p(el->values, struct ldb_val, el->num_values+1);
			if (!el->values) {
				goto failed;
			}
			el->values[el->num_values] = value;
			el->num_values++;
		} else {
			/* its a new attribute */
			msg->elements = realloc_p(msg->elements, 
						  struct ldb_message_element, 
						  msg->num_elements+1);
			if (!msg->elements) {
				goto failed;
			}
			msg->elements[msg->num_elements].flags = flags;
			msg->elements[msg->num_elements].name = attr;
			el = &msg->elements[msg->num_elements];
			el->values = malloc_p(struct ldb_val);
			if (!el->values) {
				goto failed;
			}
			el->num_values = 1;
			el->values[0] = value;
			msg->num_elements++;
		}
	}

	return ldif;

failed:
	if (ldif) ldif_read_free(ldif);
	return NULL;
}



/*
  a wrapper around ldif_read() for reading from FILE*
*/
struct ldif_read_file_state {
	FILE *f;
};

static int fgetc_file(void *private)
{
	struct ldif_read_file_state *state = private;
	return fgetc(state->f);
}

struct ldb_ldif *ldif_read_file(FILE *f)
{
	struct ldif_read_file_state state;
	state.f = f;
	return ldif_read(fgetc_file, &state);
}


/*
  a wrapper around ldif_read() for reading from const char*
*/
struct ldif_read_string_state {
	const char *s;
};

static int fgetc_string(void *private)
{
	struct ldif_read_string_state *state = private;
	if (state->s[0] != 0) {
		return *state->s++;
	}
	return EOF;
}

struct ldb_ldif *ldif_read_string(const char *s)
{
	struct ldif_read_string_state state;
	state.s = s;
	return ldif_read(fgetc_string, &state);
}


/*
  wrapper around ldif_write() for a file
*/
struct ldif_write_file_state {
	FILE *f;
};

static int fprintf_file(void *private, const char *fmt, ...)
{
	struct ldif_write_file_state *state = private;
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vfprintf(state->f, fmt, ap);
	va_end(ap);
	return ret;
}

int ldif_write_file(FILE *f, const struct ldb_ldif *ldif)
{
	struct ldif_write_file_state state;
	state.f = f;
	return ldif_write(fprintf_file, &state, ldif);
}
