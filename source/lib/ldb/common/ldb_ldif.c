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
	uint8_t *d = (uint8_t *)s;
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
char *ldb_base64_encode(struct ldb_context *ldb, const char *buf, int len)
{
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int bit_offset, byte_offset, idx, i;
	const uint8_t *d = (const uint8_t *)buf;
	int bytes = (len*8 + 5)/6;
	char *out;

	out = ldb_malloc(ldb, bytes+2);
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
	uint8_t *p = val->data;

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
static int fold_string(int (*fprintf_fn)(void *, const char *, ...), void *private_data,
			const char *buf, size_t length, int start_pos)
{
	int i;
	int total=0, ret;

	for (i=0;i<length;i++) {
		ret = fprintf_fn(private_data, "%c", buf[i]);
		CHECK_RET;
		if (i != (length-1) && (i + start_pos) % 77 == 0) {
			ret = fprintf_fn(private_data, "\n ");
			CHECK_RET;
		}
	}

	return total;
}

/*
  encode as base64 to a file
*/
static int base64_encode_f(struct ldb_context *ldb,
			   int (*fprintf_fn)(void *, const char *, ...), 
			   void *private_data,
			   const char *buf, int len, int start_pos)
{
	char *b = ldb_base64_encode(ldb, buf, len);
	int ret;

	if (!b) {
		return -1;
	}

	ret = fold_string(fprintf_fn, private_data, b, strlen(b), start_pos);

	ldb_free(ldb, b);
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
int ldb_ldif_write(struct ldb_context *ldb,
		   int (*fprintf_fn)(void *, const char *, ...), 
		   void *private_data,
		   const struct ldb_ldif *ldif)
{
	int i, j;
	int total=0, ret;
	const struct ldb_message *msg;

	msg = &ldif->msg;

	ret = fprintf_fn(private_data, "dn: %s\n", msg->dn);
	CHECK_RET;

	if (ldif->changetype != LDB_CHANGETYPE_NONE) {
		for (i=0;ldb_changetypes[i].name;i++) {
			if (ldb_changetypes[i].changetype == ldif->changetype) {
				break;
			}
		}
		if (!ldb_changetypes[i].name) {
			ldb_debug(ldb, LDB_DEBUG_ERROR, "Error: Invalid ldif changetype %d\n",
				  ldif->changetype);
			return -1;
		}
		ret = fprintf_fn(private_data, "changetype: %s\n", ldb_changetypes[i].name);
		CHECK_RET;
	}

	for (i=0;i<msg->num_elements;i++) {
		if (ldif->changetype == LDB_CHANGETYPE_MODIFY) {
			switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {
			case LDB_FLAG_MOD_ADD:
				fprintf_fn(private_data, "add: %s\n", 
					   msg->elements[i].name);
				break;
			case LDB_FLAG_MOD_DELETE:
				fprintf_fn(private_data, "delete: %s\n", 
					   msg->elements[i].name);
				break;
			case LDB_FLAG_MOD_REPLACE:
				fprintf_fn(private_data, "replace: %s\n", 
					   msg->elements[i].name);
				break;
			}
		}

		for (j=0;j<msg->elements[i].num_values;j++) {
			if (ldb_should_b64_encode(&msg->elements[i].values[j])) {
				ret = fprintf_fn(private_data, "%s:: ", 
						 msg->elements[i].name);
				CHECK_RET;
				ret = base64_encode_f(ldb, fprintf_fn, private_data, 
						      msg->elements[i].values[j].data, 
						      msg->elements[i].values[j].length,
						      strlen(msg->elements[i].name)+3);
				CHECK_RET;
				ret = fprintf_fn(private_data, "\n");
				CHECK_RET;
			} else {
				ret = fprintf_fn(private_data, "%s: ", msg->elements[i].name);
				CHECK_RET;
				ret = fold_string(fprintf_fn, private_data,
						  msg->elements[i].values[j].data,
						  msg->elements[i].values[j].length,
						  strlen(msg->elements[i].name)+2);
				CHECK_RET;
				ret = fprintf_fn(private_data, "\n");
				CHECK_RET;
			}
		}
		if (ldif->changetype == LDB_CHANGETYPE_MODIFY) {
			fprintf_fn(private_data, "-\n");
		}
	}
	ret = fprintf_fn(private_data,"\n");
	CHECK_RET;

	return total;
}

#undef CHECK_RET


/*
  pull a ldif chunk, which is defined as a piece of data ending in \n\n or EOF
  this routine removes any RFC2849 continuations and comments

  caller frees
*/
static char *next_chunk(struct ldb_context *ldb, 
			int (*fgetc_fn)(void *), void *private_data)
{
	size_t alloc_size=0, chunk_size = 0;
	char *chunk = NULL;
	int c;
	int in_comment = 0;

	while ((c = fgetc_fn(private_data)) != EOF) {
		if (chunk_size+1 >= alloc_size) {
			char *c2;
			alloc_size += 1024;
			c2 = ldb_realloc_p(ldb, chunk, char, alloc_size);
			if (!c2) {
				ldb_free(ldb, chunk);
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
static int next_attr(char **s, const char **attr, struct ldb_val *value)
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
void ldb_ldif_read_free(struct ldb_context *ldb, struct ldb_ldif *ldif)
{
	struct ldb_message *msg = &ldif->msg;
	int i;
	for (i=0;i<msg->num_elements;i++) {
		if (msg->elements[i].name) ldb_free(ldb, msg->elements[i].name);
		if (msg->elements[i].values) ldb_free(ldb, msg->elements[i].values);
	}
	if (msg->elements) ldb_free(ldb, msg->elements);
	if (msg->private_data) ldb_free(ldb, msg->private_data);
	ldb_free(ldb, ldif);
}

/*
  add an empty element
*/
static int msg_add_empty(struct ldb_context *ldb,
			 struct ldb_message *msg, const char *name, unsigned flags)
{
	struct ldb_message_element *el2, *el;

	el2 = ldb_realloc_p(ldb, msg->elements, 
			    struct ldb_message_element, msg->num_elements+1);
	if (!el2) {
		errno = ENOMEM;
		return -1;
	}
	
	msg->elements = el2;

	el = &msg->elements[msg->num_elements];
	
	el->name = ldb_strdup(ldb, name);
	el->num_values = 0;
	el->values = NULL;
	el->flags = flags;

	if (!el->name) {
		errno = ENOMEM;
		return -1;
	}

	msg->num_elements++;

	return 0;
}

/*
 read from a LDIF source, creating a ldb_message
*/
struct ldb_ldif *ldb_ldif_read(struct ldb_context *ldb,
			       int (*fgetc_fn)(void *), void *private_data)
{
	struct ldb_ldif *ldif;
	struct ldb_message *msg;
	const char *attr=NULL;
	char *chunk=NULL, *s;
	struct ldb_val value;
	unsigned flags = 0;

	value.data = NULL;

	ldif = ldb_malloc_p(ldb, struct ldb_ldif);
	if (!ldif) return NULL;

	ldif->changetype = LDB_CHANGETYPE_NONE;
	msg = &ldif->msg;

	msg->dn = NULL;
	msg->elements = NULL;
	msg->num_elements = 0;
	msg->private_data = NULL;

	chunk = next_chunk(ldb, fgetc_fn, private_data);
	if (!chunk) {
		goto failed;
	}

	msg->private_data = chunk;
	s = chunk;

	if (next_attr(&s, &attr, &value) != 0) {
		goto failed;
	}
	
	/* first line must be a dn */
	if (ldb_attr_cmp(attr, "dn") != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Error: First line of ldif must be a dn not '%s'\n", 
			  attr);
		goto failed;
	}

	msg->dn = value.data;

	while (next_attr(&s, &attr, &value) == 0) {
		struct ldb_message_element *el;
		int empty = 0;

		if (ldb_attr_cmp(attr, "changetype") == 0) {
			int i;
			for (i=0;ldb_changetypes[i].name;i++) {
				if (ldb_attr_cmp((char *)value.data, ldb_changetypes[i].name) == 0) {
					ldif->changetype = ldb_changetypes[i].changetype;
					break;
				}
			}
			if (!ldb_changetypes[i].name) {
				ldb_debug(ldb, LDB_DEBUG_ERROR, 
					  "Error: Bad ldif changetype '%s'\n",(char *)value.data);
			}
			flags = 0;
			continue;
		}

		if (ldb_attr_cmp(attr, "add") == 0) {
			flags = LDB_FLAG_MOD_ADD;
			empty = 1;
		}
		if (ldb_attr_cmp(attr, "delete") == 0) {
			flags = LDB_FLAG_MOD_DELETE;
			empty = 1;
		}
		if (ldb_attr_cmp(attr, "replace") == 0) {
			flags = LDB_FLAG_MOD_REPLACE;
			empty = 1;
		}
		if (ldb_attr_cmp(attr, "-") == 0) {
			flags = 0;
			continue;
		}

		if (empty) {
			if (msg_add_empty(ldb, msg, (char *)value.data, flags) != 0) {
				goto failed;
			}
			continue;
		}
		
		el = &msg->elements[msg->num_elements-1];

		if (msg->num_elements > 0 && ldb_attr_cmp(attr, el->name) == 0 &&
		    flags == el->flags) {
			/* its a continuation */
			el->values = 
				ldb_realloc_p(ldb, el->values, 
					      struct ldb_val, el->num_values+1);
			if (!el->values) {
				goto failed;
			}
			el->values[el->num_values] = value;
			el->num_values++;
		} else {
			/* its a new attribute */
			msg->elements = ldb_realloc_p(ldb, msg->elements, 
						      struct ldb_message_element, 
						      msg->num_elements+1);
			if (!msg->elements) {
				goto failed;
			}
			el = &msg->elements[msg->num_elements];
			el->flags = flags;
			el->name = ldb_strdup(ldb, attr);
			el->values = ldb_malloc_p(ldb, struct ldb_val);
			if (!el->values || !el->name) {
				goto failed;
			}
			el->num_values = 1;
			el->values[0] = value;
			msg->num_elements++;
		}
	}

	return ldif;

failed:
	if (ldif) ldb_ldif_read_free(ldb, ldif);
	return NULL;
}



/*
  a wrapper around ldif_read() for reading from FILE*
*/
struct ldif_read_file_state {
	FILE *f;
};

static int fgetc_file(void *private_data)
{
	struct ldif_read_file_state *state = private_data;
	return fgetc(state->f);
}

struct ldb_ldif *ldb_ldif_read_file(struct ldb_context *ldb, FILE *f)
{
	struct ldif_read_file_state state;
	state.f = f;
	return ldb_ldif_read(ldb, fgetc_file, &state);
}


/*
  a wrapper around ldif_read() for reading from const char*
*/
struct ldif_read_string_state {
	const char *s;
};

static int fgetc_string(void *private_data)
{
	struct ldif_read_string_state *state = private_data;
	if (state->s[0] != 0) {
		return *state->s++;
	}
	return EOF;
}

struct ldb_ldif *ldb_ldif_read_string(struct ldb_context *ldb, const char *s)
{
	struct ldif_read_string_state state;
	state.s = s;
	return ldb_ldif_read(ldb, fgetc_string, &state);
}


/*
  wrapper around ldif_write() for a file
*/
struct ldif_write_file_state {
	FILE *f;
};

static int fprintf_file(void *private_data, const char *fmt, ...)
{
	struct ldif_write_file_state *state = private_data;
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vfprintf(state->f, fmt, ap);
	va_end(ap);
	return ret;
}

int ldb_ldif_write_file(struct ldb_context *ldb, FILE *f, const struct ldb_ldif *ldif)
{
	struct ldif_write_file_state state;
	state.f = f;
	return ldb_ldif_write(ldb, fprintf_file, &state, ldif);
}
