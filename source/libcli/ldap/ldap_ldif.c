/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
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

/****************************************************************************
 *
 * LDIF parser
 *
 * Shamelessly stolen and adapted from ldb.
 *
 ***************************************************************************/

/*
  pull a ldif chunk, which is defined as a piece of data ending in \n\n or EOF
  this routine removes any RFC2849 continuations and comments

  caller frees
*/
static char *next_chunk(TALLOC_CTX *mem_ctx,
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
			c2 = talloc_realloc(mem_ctx, chunk, alloc_size);
			if (!c2) {
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
		if (c == ' ' && chunk_size > 1 &&
		    chunk[chunk_size-1] == '\n') {
			chunk_size--;
			continue;
		}
		
		/* chunks are terminated by a double line-feed */
		if (c == '\n' && chunk_size > 0 &&
		    chunk[chunk_size-1] == '\n') {
			chunk[chunk_size-1] = 0;
			return chunk;
		}

		if (c == '#' &&
		    (chunk_size == 0 || chunk[chunk_size-1] == '\n')) {
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
static int next_attr(char **s, const char **attr, struct ldap_val *value)
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
		DATA_BLOB blob = base64_decode_data_blob(value->data);
		memcpy(value->data, blob.data, blob.length);
		value->length = blob.length;
		((char *)value->data)[value->length] = '\0';
	}

	return 0;
}

BOOL add_value_to_attrib(TALLOC_CTX *mem_ctx, struct ldap_val *value,
			 struct ldap_attribute *attrib)
{
	attrib->values = talloc_realloc_p(mem_ctx, 
					  attrib->values,
					  DATA_BLOB,
					  attrib->num_values+1);
	if (attrib->values == NULL)
		return False;

	attrib->values[attrib->num_values] =
		data_blob_talloc(mem_ctx, value->data, value->length);
	attrib->num_values += 1;
	return True;
}

BOOL add_attrib_to_array_talloc(TALLOC_CTX *mem_ctx,
				       const struct ldap_attribute *attrib,
				       struct ldap_attribute **attribs,
				       int *num_attribs)
{
	*attribs = talloc_realloc_p(mem_ctx,
				    *attribs,
				    struct ldap_attribute,
				    *num_attribs+1);

	if (*attribs == NULL)
		return False;

	(*attribs)[*num_attribs] = *attrib;
	*num_attribs += 1;
	return True;
}

static BOOL fill_add_attributes(struct ldap_message *msg, char **chunk)
{
	struct ldap_AddRequest *r = &msg->r.AddRequest;
	const char *attr_name;
	struct ldap_val value;

	r->num_attributes = 0;
	r->attributes = NULL;

	while (next_attr(chunk, &attr_name, &value) == 0) {
		int i;
		struct ldap_attribute *attrib = NULL;
		
		for (i=0; i<r->num_attributes; i++) {
			if (strequal(r->attributes[i].name, attr_name)) {
				attrib = &r->attributes[i];
				break;
			}
		}

		if (attrib == NULL) {
			r->attributes = talloc_realloc_p(msg->mem_ctx,
							 r->attributes,
							 struct ldap_attribute,
							 r->num_attributes+1);
			if (r->attributes == NULL)
				return False;

			attrib = &(r->attributes[r->num_attributes]);
			r->num_attributes += 1;
			ZERO_STRUCTP(attrib);
			attrib->name = talloc_strdup(msg->mem_ctx,
						     attr_name);
		}

		if (!add_value_to_attrib(msg->mem_ctx, &value, attrib))
			return False;
	}
	return True;
}

BOOL add_mod_to_array_talloc(TALLOC_CTX *mem_ctx,
				    struct ldap_mod *mod,
				    struct ldap_mod **mods,
				    int *num_mods)
{
	*mods = talloc_realloc_p(mem_ctx, *mods, struct ldap_mod, (*num_mods)+1);

	if (*mods == NULL)
		return False;

	(*mods)[*num_mods] = *mod;
	*num_mods += 1;
	return True;
}

static BOOL fill_mods(struct ldap_message *msg, char **chunk)
{
	struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
	const char *attr_name;
	struct ldap_val value;

	r->num_mods = 0;
	r->mods = NULL;

	while (next_attr(chunk, &attr_name, &value) == 0) {

		struct ldap_mod mod;
		mod.type = LDAP_MODIFY_NONE;

		mod.attrib.name = talloc_strdup(msg->mem_ctx, value.data);

		if (strequal(attr_name, "add"))
			mod.type = LDAP_MODIFY_ADD;

		if (strequal(attr_name, "delete"))
			mod.type = LDAP_MODIFY_DELETE;

		if (strequal(attr_name, "replace"))
			mod.type = LDAP_MODIFY_REPLACE;

		if (mod.type == LDAP_MODIFY_NONE) {
			DEBUG(2, ("ldif modification type %s unsupported\n",
				  attr_name));
			return False;
		}

		mod.attrib.num_values = 0;
		mod.attrib.values = NULL;

		while (next_attr(chunk, &attr_name, &value) == 0) {
			if (strequal(attr_name, "-"))
				break;
			if (!strequal(attr_name, mod.attrib.name)) {
				DEBUG(3, ("attrib name %s does not "
					  "match %s\n", attr_name,
					  mod.attrib.name));
				return False;
			}
			if (!add_value_to_attrib(msg->mem_ctx, &value,
						 &mod.attrib)) {
				DEBUG(3, ("Could not add value\n"));
				return False;
			}
		}

		if (!add_mod_to_array_talloc(msg->mem_ctx, &mod, &r->mods,
					     &r->num_mods))
			return False;
	}

	return True;
}

/*
 read from a LDIF source, creating a ldap_message
*/
static struct ldap_message *ldif_read(int (*fgetc_fn)(void *),
				      void *private_data)
{
	struct ldap_message *msg;
	const char *attr=NULL;
	const char *dn;
	char *chunk=NULL, *s;
	struct ldap_val value;

	value.data = NULL;

	msg = new_ldap_message();
	if (msg == NULL)
		return NULL;

	chunk = next_chunk(msg->mem_ctx, fgetc_fn, private_data);
	if (!chunk) {
		goto failed;
	}

	s = chunk;

	if (next_attr(&s, &attr, &value) != 0) {
		goto failed;
	}
	
	/* first line must be a dn */
	if (!strequal(attr, "dn")) {
		DEBUG(5, ("Error: First line of ldif must be a dn not '%s'\n",
			  attr));
		goto failed;
	}

	dn = talloc_strdup(msg->mem_ctx, value.data);

	if (next_attr(&s, &attr, &value) != 0) {
		goto failed;
	}

	if (!strequal(attr, "changetype")) {
		DEBUG(5, ("Error: Second line of ldif must be a changetype "
			  "not '%s'\n",  attr));
		goto failed;
	}

	if (strequal(value.data, "delete")) {
		msg->type = LDAP_TAG_DelRequest;
		msg->r.DelRequest.dn = dn;
		return msg;
	}

	if (strequal(value.data, "add")) {
		msg->type = LDAP_TAG_AddRequest;

		msg->r.AddRequest.dn = dn;

		if (!fill_add_attributes(msg, &s))
			goto failed;

		return msg;
	}

	if (strequal(value.data, "modify")) {
		msg->type = LDAP_TAG_ModifyRequest;

		msg->r.ModifyRequest.dn = dn;

		if (!fill_mods(msg, &s))
			goto failed;

		return msg;
	}

	DEBUG(3, ("changetype %s not supported\n", (char *)value.data));

failed:
	destroy_ldap_message(msg);
	return NULL;
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

struct ldap_message *ldap_ldif2msg(const char *s)
{
	struct ldif_read_string_state state;
	state.s = s;
	return ldif_read(fgetc_string, &state);
}

