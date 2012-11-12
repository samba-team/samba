/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
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

#include "ldb_private.h"
#include "system/locale.h"

/*
  
*/
static int ldb_read_data_file(TALLOC_CTX *mem_ctx, struct ldb_val *value)
{
	struct stat statbuf;
	char *buf;
	int count, size, bytes;
	int ret;
	int f;
	const char *fname = (const char *)value->data;

	if (strncmp(fname, "file://", 7) != 0) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	fname += 7;

	f = open(fname, O_RDONLY);
	if (f == -1) {
		return -1;
	}

	if (fstat(f, &statbuf) != 0) {
		ret = -1;
		goto done;
	}

	if (statbuf.st_size == 0) {
		ret = -1;
		goto done;
	}

	value->data = (uint8_t *)talloc_size(mem_ctx, statbuf.st_size + 1);
	if (value->data == NULL) {
		ret = -1;
		goto done;
	}
	value->data[statbuf.st_size] = 0;

	count = 0;
	size = statbuf.st_size;
	buf = (char *)value->data;
	while (count < statbuf.st_size) {
		bytes = read(f, buf, size);
		if (bytes == -1) {
			talloc_free(value->data);
			ret = -1;
			goto done;
		}
		count += bytes;
		buf += bytes;
		size -= bytes;
	}

	value->length = statbuf.st_size;
	ret = statbuf.st_size;

done:
	close(f);
	return ret;
}

/*
  this base64 decoder was taken from jitterbug (written by tridge).
  we might need to replace it with a new version
*/
int ldb_base64_decode(char *s)
{
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int bit_offset=0, byte_offset, idx, i, n;
	uint8_t *d = (uint8_t *)s;
	char *p=NULL;

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
	if (bit_offset >= 3) {
		n--;
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
char *ldb_base64_encode(TALLOC_CTX *mem_ctx, const char *buf, int len)
{
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int bit_offset, byte_offset, idx, i;
	const uint8_t *d = (const uint8_t *)buf;
	int bytes = (len*8 + 5)/6, pad_bytes = (bytes % 4) ? 4 - (bytes % 4) : 0;
	char *out;

	out = talloc_array(mem_ctx, char, bytes+pad_bytes+1);
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

	for (;i<bytes+pad_bytes;i++)
		out[i] = '=';
	out[i] = 0;

	return out;
}

/*
  see if a buffer should be base64 encoded
*/
int ldb_should_b64_encode(struct ldb_context *ldb, const struct ldb_val *val)
{
	unsigned int i;
	uint8_t *p = val->data;

	if (val->length == 0) {
		return 0;
	}

	if (p[0] == ' ' || p[0] == ':') {
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
	size_t i;
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

#undef CHECK_RET

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

	talloc_free(b);
	return ret;
}


static const struct {
	const char *name;
	enum ldb_changetype changetype;
} ldb_changetypes[] = {
	{"add",    LDB_CHANGETYPE_ADD},
	{"delete", LDB_CHANGETYPE_DELETE},
	{"modify", LDB_CHANGETYPE_MODIFY},
	{"modrdn", LDB_CHANGETYPE_MODRDN},
	{"moddn",  LDB_CHANGETYPE_MODRDN},
	{NULL, 0}
};

/* this macro is used to handle the return checking on fprintf_fn() */
#define CHECK_RET do { if (ret < 0) { talloc_free(mem_ctx); return ret; } total += ret; } while (0)

/*
  write to ldif, using a caller supplied write method, and only printing secrets if we are not in a trace
*/
static int ldb_ldif_write_trace(struct ldb_context *ldb,
				int (*fprintf_fn)(void *, const char *, ...), 
				void *private_data,
				const struct ldb_ldif *ldif, 
				bool in_trace)
{
	TALLOC_CTX *mem_ctx;
	unsigned int i, j;
	int total=0, ret;
	char *p;
	const struct ldb_message *msg;
	const char * const * secret_attributes = ldb_get_opaque(ldb, LDB_SECRET_ATTRIBUTE_LIST_OPAQUE);

	mem_ctx = talloc_named_const(NULL, 0, "ldb_ldif_write");

	msg = ldif->msg;
	p = ldb_dn_get_extended_linearized(mem_ctx, msg->dn, 1);
	ret = fprintf_fn(private_data, "dn: %s\n", p);
	talloc_free(p);
	CHECK_RET;

	if (ldif->changetype != LDB_CHANGETYPE_NONE) {
		for (i=0;ldb_changetypes[i].name;i++) {
			if (ldb_changetypes[i].changetype == ldif->changetype) {
				break;
			}
		}
		if (!ldb_changetypes[i].name) {
			ldb_debug(ldb, LDB_DEBUG_ERROR, "Error: Invalid ldif changetype %d",
				  ldif->changetype);
			talloc_free(mem_ctx);
			return -1;
		}
		ret = fprintf_fn(private_data, "changetype: %s\n", ldb_changetypes[i].name);
		CHECK_RET;
	}

	for (i=0;i<msg->num_elements;i++) {
		const struct ldb_schema_attribute *a;

		a = ldb_schema_attribute_by_name(ldb, msg->elements[i].name);

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
		
		if (in_trace && secret_attributes && ldb_attr_in_list(secret_attributes, msg->elements[i].name)) {
			/* Deliberatly skip printing this password */
			ret = fprintf_fn(private_data, "# %s::: REDACTED SECRET ATTRIBUTE\n",
					 msg->elements[i].name);
			CHECK_RET;
			continue;
		}

		for (j=0;j<msg->elements[i].num_values;j++) {
			struct ldb_val v;
			bool use_b64_encode;
			ret = a->syntax->ldif_write_fn(ldb, mem_ctx, &msg->elements[i].values[j], &v);
			if (ret != LDB_SUCCESS) {
				v = msg->elements[i].values[j];
			}
			use_b64_encode = !(ldb->flags & LDB_FLG_SHOW_BINARY)
					&& ldb_should_b64_encode(ldb, &v);
			if (ret != LDB_SUCCESS || use_b64_encode) {
				ret = fprintf_fn(private_data, "%s:: ", 
						 msg->elements[i].name);
				CHECK_RET;
				ret = base64_encode_f(ldb, fprintf_fn, private_data, 
						      (char *)v.data, v.length,
						      strlen(msg->elements[i].name)+3);
				CHECK_RET;
				ret = fprintf_fn(private_data, "\n");
				CHECK_RET;
			} else {
				ret = fprintf_fn(private_data, "%s: ", msg->elements[i].name);
				CHECK_RET;
				if (ldb->flags & LDB_FLG_SHOW_BINARY) {
					ret = fprintf_fn(private_data, "%*.*s", 
							 v.length, v.length, (char *)v.data);
				} else {
					ret = fold_string(fprintf_fn, private_data,
							  (char *)v.data, v.length,
							  strlen(msg->elements[i].name)+2);
				}
				CHECK_RET;
				ret = fprintf_fn(private_data, "\n");
				CHECK_RET;
			}
			if (v.data != msg->elements[i].values[j].data) {
				talloc_free(v.data);
			}
		}
		if (ldif->changetype == LDB_CHANGETYPE_MODIFY) {
			fprintf_fn(private_data, "-\n");
		}
	}
	ret = fprintf_fn(private_data,"\n");
	CHECK_RET;

	talloc_free(mem_ctx);

	return total;
}

#undef CHECK_RET


/*
  write to ldif, using a caller supplied write method
*/
int ldb_ldif_write(struct ldb_context *ldb,
		   int (*fprintf_fn)(void *, const char *, ...), 
		   void *private_data,
		   const struct ldb_ldif *ldif)
{
	return ldb_ldif_write_trace(ldb, fprintf_fn, private_data, ldif, false);
}


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
			c2 = talloc_realloc(ldb, chunk, char, alloc_size);
			if (!c2) {
				talloc_free(chunk);
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
static int next_attr(TALLOC_CTX *mem_ctx, char **s, const char **attr, struct ldb_val *value)
{
	char *p;
	int base64_encoded = 0;
	int binary_file = 0;

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

	if (*p == '<') {
		binary_file = 1;
		p++;
	}

	*attr = *s;

	while (*p == ' ' || *p == '\t') {
		p++;
	}

	value->data = (uint8_t *)p;

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
		int len = ldb_base64_decode((char *)value->data);
		if (len == -1) {
			/* it wasn't valid base64 data */
			return -1;
		}
		value->length = len;
	}

	if (binary_file) {
		int len = ldb_read_data_file(mem_ctx, value);
		if (len == -1) {
			/* an error occurred while trying to retrieve the file */
			return -1;
		}
	}

	return 0;
}


/*
  free a message from a ldif_read
*/
void ldb_ldif_read_free(struct ldb_context *ldb, struct ldb_ldif *ldif)
{
	talloc_free(ldif);
}

int ldb_ldif_parse_modrdn(struct ldb_context *ldb,
			  const struct ldb_ldif *ldif,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn **_olddn,
			  struct ldb_dn **_newrdn,
			  bool *_deleteoldrdn,
			  struct ldb_dn **_newsuperior,
			  struct ldb_dn **_newdn)
{
	struct ldb_message *msg = ldif->msg;
	struct ldb_val *newrdn_val = NULL;
	struct ldb_val *deleteoldrdn_val = NULL;
	struct ldb_val *newsuperior_val = NULL;
	struct ldb_dn *olddn = NULL;
	struct ldb_dn *newrdn = NULL;
	bool deleteoldrdn = true;
	struct ldb_dn *newsuperior = NULL;
	struct ldb_dn *newdn = NULL;
	struct ldb_val tmp_false;
	struct ldb_val tmp_true;
	bool ok;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (tmp_ctx == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "Error: talloc_new() failed");
		goto err_op;
	}

	if (ldif->changetype != LDB_CHANGETYPE_MODRDN) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: invalid changetype '%d'",
			  ldif->changetype);
		goto err_other;
	}

	if (msg->num_elements < 2) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: num_elements[%u] < 2",
			  msg->num_elements);
		goto err_other;
	}

	if (msg->num_elements > 3) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: num_elements[%u] > 3",
			  msg->num_elements);
		goto err_other;
	}

#define CHECK_ELEMENT(i, _name, v, needed) do { \
	v = NULL; \
	if (msg->num_elements < (i + 1)) { \
		if (needed) { \
			ldb_debug(ldb, LDB_DEBUG_ERROR, \
				  "Error: num_elements[%u] < (%u + 1)", \
				  msg->num_elements, i); \
			goto err_other; \
		} \
	} else if (ldb_attr_cmp(msg->elements[i].name, _name) != 0) { \
		ldb_debug(ldb, LDB_DEBUG_ERROR, \
			  "Error: elements[%u].name[%s] != [%s]", \
			  i, msg->elements[i].name, _name); \
		goto err_other; \
	} else if (msg->elements[i].flags != 0) { \
		ldb_debug(ldb, LDB_DEBUG_ERROR, \
			  "Error: elements[%u].flags[0x%X} != [0x0]", \
			  i, msg->elements[i].flags); \
		goto err_other; \
	} else if (msg->elements[i].num_values != 1) { \
		ldb_debug(ldb, LDB_DEBUG_ERROR, \
			  "Error: elements[%u].num_values[%u] != 1", \
			  i, msg->elements[i].num_values); \
		goto err_other; \
	} else { \
		v = &msg->elements[i].values[0]; \
	} \
} while (0)

	CHECK_ELEMENT(0, "newrdn", newrdn_val, true);
	CHECK_ELEMENT(1, "deleteoldrdn", deleteoldrdn_val, true);
	CHECK_ELEMENT(2, "newsuperior", newsuperior_val, false);

#undef CHECK_ELEMENT

	olddn = ldb_dn_copy(tmp_ctx, msg->dn);
	if (olddn == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: failed to copy olddn '%s'",
			  ldb_dn_get_linearized(msg->dn));
		goto err_op;
	}

	newrdn = ldb_dn_from_ldb_val(tmp_ctx, ldb, newrdn_val);
	if (!ldb_dn_validate(newrdn)) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: Unable to parse dn '%s'",
			  (char *)newrdn_val->data);
		goto err_dn;
	}

	tmp_false.length = 1;
	tmp_false.data = discard_const_p(uint8_t, "0");
	tmp_true.length = 1;
	tmp_true.data = discard_const_p(uint8_t, "1");
	if (ldb_val_equal_exact(deleteoldrdn_val, &tmp_false) == 1) {
		deleteoldrdn = false;
	} else if (ldb_val_equal_exact(deleteoldrdn_val, &tmp_true) == 1) {
		deleteoldrdn = true;
	} else {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: deleteoldrdn value invalid '%s' not '0'/'1'",
			  (char *)deleteoldrdn_val->data);
		goto err_attr;
	}

	if (newsuperior_val) {
		newsuperior = ldb_dn_from_ldb_val(tmp_ctx, ldb, newsuperior_val);
		if (!ldb_dn_validate(newsuperior)) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Error: Unable to parse dn '%s'",
				  (char *)newsuperior_val->data);
			goto err_dn;
		}
	} else {
		newsuperior = ldb_dn_get_parent(tmp_ctx, msg->dn);
		if (newsuperior == NULL) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Error: Unable to get parent dn '%s'",
				  ldb_dn_get_linearized(msg->dn));
			goto err_dn;
		}
	}

	newdn = ldb_dn_copy(tmp_ctx, newrdn);
	if (newdn == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: failed to copy newrdn '%s'",
			  ldb_dn_get_linearized(newrdn));
		goto err_op;
	}

	ok = ldb_dn_add_base(newdn, newsuperior);
	if (!ok) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: failed to base '%s' to newdn '%s'",
			  ldb_dn_get_linearized(newsuperior),
			  ldb_dn_get_linearized(newdn));
		goto err_op;
	}

	if (_olddn) {
		*_olddn = talloc_move(mem_ctx, &olddn);
	}
	if (_newrdn) {
		*_newrdn = talloc_move(mem_ctx, &newrdn);
	}
	if (_deleteoldrdn) {
		*_deleteoldrdn = deleteoldrdn;
	}
	if (_newsuperior) {
		if (newsuperior_val) {
			*_newrdn = talloc_move(mem_ctx, &newrdn);
		} else {
			*_newrdn = NULL;
		}
	}
	if (_newdn) {
		*_newdn = talloc_move(mem_ctx, &newdn);
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
err_other:
	talloc_free(tmp_ctx);
	return LDB_ERR_OTHER;
err_op:
	talloc_free(tmp_ctx);
	return LDB_ERR_OPERATIONS_ERROR;
err_attr:
	talloc_free(tmp_ctx);
	return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
err_dn:
	talloc_free(tmp_ctx);
	return LDB_ERR_INVALID_DN_SYNTAX;
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

	ldif = talloc(ldb, struct ldb_ldif);
	if (!ldif) return NULL;

	ldif->msg = talloc(ldif, struct ldb_message);
	if (ldif->msg == NULL) {
		talloc_free(ldif);
		return NULL;
	}

	ldif->changetype = LDB_CHANGETYPE_NONE;
	msg = ldif->msg;

	msg->dn = NULL;
	msg->elements = NULL;
	msg->num_elements = 0;

	chunk = next_chunk(ldb, fgetc_fn, private_data);
	if (!chunk) {
		goto failed;
	}
	talloc_steal(ldif, chunk);

	s = chunk;

	if (next_attr(ldif, &s, &attr, &value) != 0) {
		goto failed;
	}
	
	/* first line must be a dn */
	if (ldb_attr_cmp(attr, "dn") != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Error: First line of ldif must be a dn not '%s'",
			  attr);
		goto failed;
	}

	msg->dn = ldb_dn_from_ldb_val(msg, ldb, &value);

	if ( ! ldb_dn_validate(msg->dn)) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Error: Unable to parse dn '%s'",
			  (char *)value.data);
		goto failed;
	}

	while (next_attr(ldif, &s, &attr, &value) == 0) {
		const struct ldb_schema_attribute *a;
		struct ldb_message_element *el;
		int ret, empty = 0;

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
					  "Error: Bad ldif changetype '%s'",(char *)value.data);
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
			if (ldb_msg_add_empty(msg, (char *)value.data, flags, NULL) != 0) {
				goto failed;
			}
			continue;
		}
		
		el = &msg->elements[msg->num_elements-1];

		a = ldb_schema_attribute_by_name(ldb, attr);

		if (msg->num_elements > 0 && ldb_attr_cmp(attr, el->name) == 0 &&
		    flags == el->flags) {
			/* its a continuation */
			el->values = 
				talloc_realloc(msg->elements, el->values, 
						 struct ldb_val, el->num_values+1);
			if (!el->values) {
				goto failed;
			}
			ret = a->syntax->ldif_read_fn(ldb, el->values, &value, &el->values[el->num_values]);
			if (ret != 0) {
				goto failed;
			}
			if (value.length == 0) {
				ldb_debug(ldb, LDB_DEBUG_ERROR,
					  "Error: Attribute value cannot be empty for attribute '%s'", el->name);
				goto failed;
			}
			if (value.data != el->values[el->num_values].data) {
				talloc_steal(el->values, el->values[el->num_values].data);
			}
			el->num_values++;
		} else {
			/* its a new attribute */
			msg->elements = talloc_realloc(msg, msg->elements, 
							 struct ldb_message_element, 
							 msg->num_elements+1);
			if (!msg->elements) {
				goto failed;
			}
			el = &msg->elements[msg->num_elements];
			el->flags = flags;
			el->name = talloc_strdup(msg->elements, attr);
			el->values = talloc(msg->elements, struct ldb_val);
			if (!el->values || !el->name) {
				goto failed;
			}
			el->num_values = 1;
			ret = a->syntax->ldif_read_fn(ldb, el->values, &value, &el->values[0]);
			if (ret != 0) {
				goto failed;
			}
			if (value.data != el->values[0].data) {
				talloc_steal(el->values, el->values[0].data);
			}
			msg->num_elements++;
		}
	}

	if (ldif->changetype == LDB_CHANGETYPE_MODRDN) {
		int ret;

		ret = ldb_ldif_parse_modrdn(ldb, ldif, ldif,
					    NULL, NULL, NULL, NULL, NULL);
		if (ret != LDB_SUCCESS) {
			goto failed;
		}
	}

	return ldif;

failed:
	talloc_free(ldif);
	return NULL;
}



/*
  a wrapper around ldif_read() for reading from FILE*
*/

static int fgetc_file(void *private_data)
{
	int c;
	struct ldif_read_file_state *state =
		(struct ldif_read_file_state *)private_data;
	c = fgetc(state->f);
	if (c == '\n') {
		state->line_no++;
	}
	return c;
}

struct ldb_ldif *ldb_ldif_read_file_state(struct ldb_context *ldb, 
					  struct ldif_read_file_state *state)
{
	return ldb_ldif_read(ldb, fgetc_file, state);
}

struct ldb_ldif *ldb_ldif_read_file(struct ldb_context *ldb, FILE *f)
{
	struct ldif_read_file_state state;
	state.f = f;
	return ldb_ldif_read_file_state(ldb, &state);
}

/*
  a wrapper around ldif_read() for reading from const char*
*/
struct ldif_read_string_state {
	const char *s;
};

static int fgetc_string(void *private_data)
{
	struct ldif_read_string_state *state =
		(struct ldif_read_string_state *)private_data;
	if (state->s[0] != 0) {
		return *state->s++;
	}
	return EOF;
}

struct ldb_ldif *ldb_ldif_read_string(struct ldb_context *ldb, const char **s)
{
	struct ldif_read_string_state state;
	struct ldb_ldif *ldif;
	state.s = *s;
	ldif = ldb_ldif_read(ldb, fgetc_string, &state);
	*s = state.s;
	return ldif;
}


/*
  wrapper around ldif_write() for a file
*/
struct ldif_write_file_state {
	FILE *f;
};

static int fprintf_file(void *private_data, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);

static int fprintf_file(void *private_data, const char *fmt, ...)
{
	struct ldif_write_file_state *state =
		(struct ldif_write_file_state *)private_data;
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

/*
  wrapper around ldif_write() for a string
*/
struct ldif_write_string_state {
	char *string;
};

static int ldif_printf_string(void *private_data, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);

static int ldif_printf_string(void *private_data, const char *fmt, ...)
{
	struct ldif_write_string_state *state =
		(struct ldif_write_string_state *)private_data;
	va_list ap;
	size_t oldlen = talloc_get_size(state->string);
	va_start(ap, fmt);
	
	state->string = talloc_vasprintf_append(state->string, fmt, ap);
	va_end(ap);
	if (!state->string) {
		return -1;
	}

	return talloc_get_size(state->string) - oldlen;
}

char *ldb_ldif_write_redacted_trace_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, 
					   const struct ldb_ldif *ldif)
{
	struct ldif_write_string_state state;
	state.string = talloc_strdup(mem_ctx, "");
	if (!state.string) {
		return NULL;
	}
	if (ldb_ldif_write_trace(ldb, ldif_printf_string, &state, ldif, true) == -1) {
		return NULL;
	}
	return state.string;
}

char *ldb_ldif_write_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, 
			    const struct ldb_ldif *ldif)
{
	struct ldif_write_string_state state;
	state.string = talloc_strdup(mem_ctx, "");
	if (!state.string) {
		return NULL;
	}
	if (ldb_ldif_write(ldb, ldif_printf_string, &state, ldif) == -1) {
		return NULL;
	}
	return state.string;
}

/*
  convenient function to turn a ldb_message into a string. Useful for
  debugging
 */
char *ldb_ldif_message_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, 
			      enum ldb_changetype changetype,
			      const struct ldb_message *msg)
{
	struct ldb_ldif ldif;

	ldif.changetype = changetype;
	ldif.msg = discard_const_p(struct ldb_message, msg);

	return ldb_ldif_write_string(ldb, mem_ctx, &ldif);
}
