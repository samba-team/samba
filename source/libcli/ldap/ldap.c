/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Volker Lendecke 2004
    
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
 * LDAP filter parser -- main routine is ldap_parse_filter
 *
 * Shamelessly stolen and adapted from ldb.
 *
 ***************************************************************************/

/* Hmm. A blob might be more appropriate here :-) */

struct ldap_val {
	unsigned int length;
	void *data;
};

enum ldap_parse_op {LDAP_OP_SIMPLE, LDAP_OP_AND, LDAP_OP_OR, LDAP_OP_NOT};

struct ldap_parse_tree {
	enum ldap_parse_op operation;
	union {
		struct {
			char *attr;
			struct ldap_val value;
		} simple;
		struct {
			unsigned int num_elements;
			struct ldap_parse_tree **elements;
		} list;
		struct {
			struct ldap_parse_tree *child;
		} not;
	} u;
};

#define LDAP_ALL_SEP "()&|=!"

/*
  return next token element. Caller frees
*/
static char *ldap_parse_lex(TALLOC_CTX *mem_ctx, const char **s,
			   const char *sep)
{
	const char *p = *s;
	char *ret;

	while (isspace(*p)) {
		p++;
	}
	*s = p;

	if (*p == 0) {
		return NULL;
	}

	if (strchr(sep, *p)) {
		(*s) = p+1;
		ret = talloc_strndup(mem_ctx, p, 1);
		if (!ret) {
			errno = ENOMEM;
		}
		return ret;
	}

	while (*p && (isalnum(*p) || !strchr(sep, *p))) {
		p++;
	}

	if (p == *s) {
		return NULL;
	}

	ret = talloc_strndup(mem_ctx, *s, p - *s);
	if (!ret) {
		errno = ENOMEM;
	}

	*s = p;

	return ret;
}


/*
  find a matching close brace in a string
*/
static const char *match_brace(const char *s)
{
	unsigned int count = 0;
	while (*s && (count != 0 || *s != ')')) {
		if (*s == '(') {
			count++;
		}
		if (*s == ')') {
			count--;
		}
		s++;
	}
	if (! *s) {
		return NULL;
	}
	return s;
}

static struct ldap_parse_tree *ldap_parse_filter(TALLOC_CTX *mem_ctx,
					       const char **s);

/*
  <simple> ::= <attributetype> <filtertype> <attributevalue>
*/
static struct ldap_parse_tree *ldap_parse_simple(TALLOC_CTX *mem_ctx,
					       const char *s)
{
	char *eq, *val, *l;
	struct ldap_parse_tree *ret;

	l = ldap_parse_lex(mem_ctx, &s, LDAP_ALL_SEP);
	if (!l) {
		return NULL;
	}

	if (strchr("()&|=", *l))
		return NULL;

	eq = ldap_parse_lex(mem_ctx, &s, LDAP_ALL_SEP);
	if (!eq || strcmp(eq, "=") != 0)
		return NULL;

	val = ldap_parse_lex(mem_ctx, &s, ")");
	if (val && strchr("()&|", *val))
		return NULL;
	
	ret = talloc(mem_ctx, sizeof(*ret));
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDAP_OP_SIMPLE;
	ret->u.simple.attr = l;
	ret->u.simple.value.data = val;
	ret->u.simple.value.length = val?strlen(val):0;

	return ret;
}


/*
  parse a filterlist
  <and> ::= '&' <filterlist>
  <or> ::= '|' <filterlist>
  <filterlist> ::= <filter> | <filter> <filterlist>
*/
static struct ldap_parse_tree *ldap_parse_filterlist(TALLOC_CTX *mem_ctx,
						   enum ldap_parse_op op,
						   const char *s)
{
	struct ldap_parse_tree *ret, *next;

	ret = talloc(mem_ctx, sizeof(*ret));

	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = op;
	ret->u.list.num_elements = 1;
	ret->u.list.elements = talloc(mem_ctx, sizeof(*ret->u.list.elements));
	if (!ret->u.list.elements) {
		errno = ENOMEM;
		return NULL;
	}

	ret->u.list.elements[0] = ldap_parse_filter(mem_ctx, &s);
	if (!ret->u.list.elements[0]) {
		return NULL;
	}

	while (isspace(*s)) s++;

	while (*s && (next = ldap_parse_filter(mem_ctx, &s))) {
		struct ldap_parse_tree **e;
		e = talloc_realloc(mem_ctx, ret->u.list.elements,
				   sizeof(struct ldap_parse_tree) *
				   (ret->u.list.num_elements+1));
		if (!e) {
			errno = ENOMEM;
			return NULL;
		}
		ret->u.list.elements = e;
		ret->u.list.elements[ret->u.list.num_elements] = next;
		ret->u.list.num_elements++;
		while (isspace(*s)) s++;
	}

	return ret;
}


/*
  <not> ::= '!' <filter>
*/
static struct ldap_parse_tree *ldap_parse_not(TALLOC_CTX *mem_ctx, const char *s)
{
	struct ldap_parse_tree *ret;

	ret = talloc(mem_ctx, sizeof(*ret));
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDAP_OP_NOT;
	ret->u.not.child = ldap_parse_filter(mem_ctx, &s);
	if (!ret->u.not.child)
		return NULL;

	return ret;
}

/*
  parse a filtercomp
  <filtercomp> ::= <and> | <or> | <not> | <simple>
*/
static struct ldap_parse_tree *ldap_parse_filtercomp(TALLOC_CTX *mem_ctx,
						   const char *s)
{
	while (isspace(*s)) s++;

	switch (*s) {
	case '&':
		return ldap_parse_filterlist(mem_ctx, LDAP_OP_AND, s+1);

	case '|':
		return ldap_parse_filterlist(mem_ctx, LDAP_OP_OR, s+1);

	case '!':
		return ldap_parse_not(mem_ctx, s+1);

	case '(':
	case ')':
		return NULL;
	}

	return ldap_parse_simple(mem_ctx, s);
}


/*
  <filter> ::= '(' <filtercomp> ')'
*/
static struct ldap_parse_tree *ldap_parse_filter(TALLOC_CTX *mem_ctx,
					       const char **s)
{
	char *l, *s2;
	const char *p, *p2;
	struct ldap_parse_tree *ret;

	l = ldap_parse_lex(mem_ctx, s, LDAP_ALL_SEP);
	if (!l) {
		return NULL;
	}

	if (strcmp(l, "(") != 0) {
		return NULL;
	}

	p = match_brace(*s);
	if (!p) {
		return NULL;
	}
	p2 = p + 1;

	s2 = talloc_strndup(mem_ctx, *s, p - *s);
	if (!s2) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ldap_parse_filtercomp(mem_ctx, s2);

	*s = p2;

	return ret;
}

/*
  main parser entry point. Takes a search string and returns a parse tree

  expression ::= <simple> | <filter>
*/
static struct ldap_parse_tree *ldap_parse_tree(TALLOC_CTX *mem_ctx, const char *s)
{
	while (isspace(*s)) s++;

	if (*s == '(') {
		return ldap_parse_filter(mem_ctx, &s);
	}

	return ldap_parse_simple(mem_ctx, s);
}

static BOOL ldap_push_filter(ASN1_DATA *data, struct ldap_parse_tree *tree)
{
	switch (tree->operation) {
	case LDAP_OP_SIMPLE: {
		if ((tree->u.simple.value.length == 1) &&
		    (((char *)(tree->u.simple.value.data))[0] == '*')) {
			/* Just a presence test */
			asn1_push_tag(data, 0x87);
			asn1_write(data, tree->u.simple.attr,
				   strlen(tree->u.simple.attr));
			asn1_pop_tag(data);
			return !data->has_error;
		}

		/* Equality is all we currently do... */
		asn1_push_tag(data, 0xa3);
		asn1_write_OctetString(data, tree->u.simple.attr,
				      strlen(tree->u.simple.attr));
		asn1_write_OctetString(data, tree->u.simple.value.data,
				      tree->u.simple.value.length);
		asn1_pop_tag(data);
		break;
	}

	case LDAP_OP_AND: {
		int i;

		asn1_push_tag(data, 0xa0);
		for (i=0; i<tree->u.list.num_elements; i++) {
			ldap_push_filter(data, tree->u.list.elements[i]);
		}
		asn1_pop_tag(data);
		break;
	}

	case LDAP_OP_OR: {
		int i;

		asn1_push_tag(data, 0xa1);
		for (i=0; i<tree->u.list.num_elements; i++) {
			ldap_push_filter(data, tree->u.list.elements[i]);
		}
		asn1_pop_tag(data);
		break;
	}
	default:
		return False;
	}
	return !data->has_error;
}

/****************************************************************************
 *
 * LDIF parser
 *
 * Shamelessly stolen and adapted from Samba 4.
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

static BOOL add_value_to_attrib(TALLOC_CTX *mem_ctx, struct ldap_val *value,
				struct ldap_attribute *attrib)
{
	attrib->values = talloc_realloc(mem_ctx, attrib->values,
					sizeof(*attrib->values) *
					(attrib->num_values+1));
	if (attrib->values == NULL)
		return False;

	attrib->values[attrib->num_values] =
		data_blob_talloc(mem_ctx, value->data, value->length);
	attrib->num_values += 1;
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
			r->attributes = talloc_realloc(msg->mem_ctx,
						       r->attributes,
						       sizeof(*r->attributes) *
						       (r->num_attributes+1));
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

static BOOL add_mod_to_array_talloc(TALLOC_CTX *mem_ctx,
				    struct ldap_mod *mod,
				    struct ldap_mod **mods,
				    int *num_mods)
{
	*mods = talloc_realloc(mem_ctx, *mods,
			       sizeof(**mods) * ((*num_mods)+1));

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
			mod.type = LDAP_MOD_ADD;

		if (strequal(attr_name, "delete"))
			mod.type = LDAP_MOD_DELETE;

		if (strequal(attr_name, "replace"))
			mod.type = LDAP_MOD_REPLACE;

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

static void ldap_encode_response(enum ldap_request_tag tag,
				 struct ldap_Result *result,
				 ASN1_DATA *data)
{
	asn1_push_tag(data, ASN1_APPLICATION(tag));
	asn1_write_enumerated(data, result->resultcode);
	asn1_write_OctetString(data, result->dn,
			       (result->dn) ? strlen(result->dn) : 0);
	asn1_write_OctetString(data, result->errormessage,
			       (result->errormessage) ?
			       strlen(result->errormessage) : 0);
	if (result->referral != NULL)
		asn1_write_OctetString(data, result->referral,
				       strlen(result->referral));
	asn1_pop_tag(data);
}

BOOL ldap_encode(struct ldap_message *msg, DATA_BLOB *result)
{
	ASN1_DATA data;
	int i, j;

	ZERO_STRUCT(data);
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	asn1_write_Integer(&data, msg->messageid);

	switch (msg->type) {
	case LDAP_TAG_BindRequest: {
		struct ldap_BindRequest *r = &msg->r.BindRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_BindRequest));
		asn1_write_Integer(&data, r->version);
		asn1_write_OctetString(&data, r->dn,
				       (r->dn != NULL) ? strlen(r->dn) : 0);

		switch (r->mechanism) {
		case LDAP_AUTH_MECH_SIMPLE:
			/* context, primitive */
			asn1_push_tag(&data, r->mechanism | 0x80);
			asn1_write(&data, r->creds.password,
				   strlen(r->creds.password));
			asn1_pop_tag(&data);
			break;
		case LDAP_AUTH_MECH_SASL:
			/* context, constructed */
			asn1_push_tag(&data, r->mechanism | 0xa0);
			asn1_write_OctetString(&data, r->creds.SASL.mechanism,
					       strlen(r->creds.SASL.mechanism));
			asn1_write_OctetString(&data, r->creds.SASL.creds.data,
					       r->creds.SASL.creds.length);
			asn1_pop_tag(&data);
			break;
		default:
			return False;
		}

		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_BindResponse: {
		struct ldap_BindResponse *r = &msg->r.BindResponse;
		ldap_encode_response(msg->type, &r->response, &data);
		break;
	}
	case LDAP_TAG_UnbindRequest: {
/*		struct ldap_UnbindRequest *r = &msg->r.UnbindRequest; */
		break;
	}
	case LDAP_TAG_SearchRequest: {
		struct ldap_SearchRequest *r = &msg->r.SearchRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_SearchRequest));
		asn1_write_OctetString(&data, r->basedn, strlen(r->basedn));
		asn1_write_enumerated(&data, r->scope);
		asn1_write_enumerated(&data, r->deref);
		asn1_write_Integer(&data, r->sizelimit);
		asn1_write_Integer(&data, r->timelimit);
		asn1_write_BOOLEAN2(&data, r->attributesonly);

		{
			TALLOC_CTX *mem_ctx = talloc_init("ldap_parse_tree");
			struct ldap_parse_tree *tree;

			if (mem_ctx == NULL)
				return False;

			tree = ldap_parse_tree(mem_ctx, r->filter);

			if (tree == NULL)
				return False;

			ldap_push_filter(&data, tree);

			talloc_destroy(mem_ctx);
		}

		asn1_push_tag(&data, ASN1_SEQUENCE(0));
		for (i=0; i<r->num_attributes; i++) {
			asn1_write_OctetString(&data, r->attributes[i],
					       strlen(r->attributes[i]));
		}
		asn1_pop_tag(&data);

		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_SearchResultEntry: {
		struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_SearchResultEntry));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));
		for (i=0; i<r->num_attributes; i++) {
			struct ldap_attribute *attr = &r->attributes[i];
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_OctetString(&data, attr->name,
					       strlen(attr->name));
			asn1_push_tag(&data, ASN1_SEQUENCE(1));
			for (j=0; j<attr->num_values; j++) {
				asn1_write_OctetString(&data,
						       attr->values[j].data,
						       attr->values[j].length);
			}
			asn1_pop_tag(&data);
			asn1_pop_tag(&data);
		}
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_SearchResultDone: {
		struct ldap_Result *r = &msg->r.SearchResultDone;
		ldap_encode_response(msg->type, r, &data);
		break;
	}
	case LDAP_TAG_ModifyRequest: {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_ModifyRequest));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));

		for (i=0; i<r->num_mods; i++) {
			struct ldap_attribute *attrib = &r->mods[i].attrib;
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_enumerated(&data, r->mods[i].type);
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_OctetString(&data, attrib->name,
					       strlen(attrib->name));
			asn1_push_tag(&data, ASN1_SET);
			for (j=0; j<attrib->num_values; j++) {
				asn1_write_OctetString(&data,
						       attrib->values[j].data,
						       attrib->values[j].length);
	
			}
			asn1_pop_tag(&data);
			asn1_pop_tag(&data);
			asn1_pop_tag(&data);
		}
		
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_ModifyResponse: {
		struct ldap_Result *r = &msg->r.ModifyResponse;
		ldap_encode_response(msg->type, r, &data);
		break;
	}
	case LDAP_TAG_AddRequest: {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_AddRequest));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));

		for (i=0; i<r->num_attributes; i++) {
			struct ldap_attribute *attrib = &r->attributes[i];
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_OctetString(&data, attrib->name,
					       strlen(attrib->name));
			asn1_push_tag(&data, ASN1_SET);
			for (j=0; j<r->attributes[i].num_values; j++) {
				asn1_write_OctetString(&data,
						       attrib->values[j].data,
						       attrib->values[j].length);
			}
			asn1_pop_tag(&data);
			asn1_pop_tag(&data);
		}
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_AddResponse: {
		struct ldap_Result *r = &msg->r.AddResponse;
		ldap_encode_response(msg->type, r, &data);
		break;
	}
	case LDAP_TAG_DelRequest: {
		struct ldap_DelRequest *r = &msg->r.DelRequest;
		asn1_push_tag(&data,
			      ASN1_APPLICATION_SIMPLE(LDAP_TAG_DelRequest));
		asn1_write(&data, r->dn, strlen(r->dn));
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_DelResponse: {
		struct ldap_Result *r = &msg->r.DelResponse;
		ldap_encode_response(msg->type, r, &data);
		break;
	}
	case LDAP_TAG_ModifyDNRequest: {
		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest;
		asn1_push_tag(&data,
			      ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_write_OctetString(&data, r->newrdn, strlen(r->newrdn));
		asn1_write_BOOLEAN2(&data, r->deleteolddn);
		if (r->newsuperior != NULL) {
			asn1_push_tag(&data, ASN1_CONTEXT_SIMPLE(0));
			asn1_write(&data, r->newsuperior,
				   strlen(r->newsuperior));
			asn1_pop_tag(&data);
		}
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_ModifyDNResponse: {
/*		struct ldap_Result *r = &msg->r.ModifyDNResponse; */
		break;
	}
	case LDAP_TAG_CompareRequest: {
		struct ldap_CompareRequest *r = &msg->r.CompareRequest;
		asn1_push_tag(&data,
			      ASN1_APPLICATION(LDAP_TAG_CompareRequest));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));
		asn1_write_OctetString(&data, r->attribute,
				       strlen(r->attribute));
		asn1_write_OctetString(&data, r->value,
				       strlen(r->value));
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_CompareResponse: {
/*		struct ldap_Result *r = &msg->r.CompareResponse; */
		break;
	}
	case LDAP_TAG_AbandonRequest: {
		struct ldap_AbandonRequest *r = &msg->r.AbandonRequest;
		asn1_push_tag(&data,
			      ASN1_APPLICATION_SIMPLE(LDAP_TAG_AbandonRequest));
		asn1_write_Integer(&data, r->messageid);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_SearchResultReference: {
/*		struct ldap_SearchResRef *r = &msg->r.SearchResultReference; */
		break;
	}
	case LDAP_TAG_ExtendedRequest: {
		struct ldap_ExtendedRequest *r = &msg->r.ExtendedRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_ExtendedRequest));
		asn1_push_tag(&data, ASN1_CONTEXT_SIMPLE(0));
		asn1_write(&data, r->oid, strlen(r->oid));
		asn1_pop_tag(&data);
		asn1_push_tag(&data, ASN1_CONTEXT_SIMPLE(1));
		asn1_write(&data, r->value.data, r->value.length);
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_ExtendedResponse: {
		struct ldap_ExtendedResponse *r = &msg->r.ExtendedResponse;
		ldap_encode_response(msg->type, &r->response, &data);
		break;
	}
	default:
		return False;
	}

	asn1_pop_tag(&data);
	*result = data_blob(data.data, data.length);
	asn1_free(&data);
	return True;
}

static const char *blob2string_talloc(TALLOC_CTX *mem_ctx,
				      DATA_BLOB blob)
{
	char *result = talloc(mem_ctx, blob.length+1);
	memcpy(result, blob.data, blob.length);
	result[blob.length] = '\0';
	return result;
}

static BOOL asn1_read_OctetString_talloc(TALLOC_CTX *mem_ctx,
					 ASN1_DATA *data,
					 const char **result)
{
	DATA_BLOB string;
	if (!asn1_read_OctetString(data, &string))
		return False;
	*result = blob2string_talloc(mem_ctx, string);
	data_blob_free(&string);
	return True;
}

static void ldap_decode_response(TALLOC_CTX *mem_ctx,
				 ASN1_DATA *data,
				 enum ldap_request_tag tag,
				 struct ldap_Result *result)
{
	asn1_start_tag(data, ASN1_APPLICATION(tag));
	asn1_read_enumerated(data, &result->resultcode);
	asn1_read_OctetString_talloc(mem_ctx, data, &result->dn);
	asn1_read_OctetString_talloc(mem_ctx, data, &result->errormessage);
	if (asn1_peek_tag(data, ASN1_OCTET_STRING))
		asn1_read_OctetString_talloc(mem_ctx, data, &result->referral);
	else
		result->referral = NULL;
	asn1_end_tag(data);
}

static BOOL add_attrib_to_array_talloc(TALLOC_CTX *mem_ctx,
				       const struct ldap_attribute *attrib,
				       struct ldap_attribute **attribs,
				       int *num_attribs)
{
	*attribs = talloc_realloc(mem_ctx, *attribs,
				  sizeof(**attribs) * (*num_attribs+1));

	if (*attribs == NULL)
		return False;

	(*attribs)[*num_attribs] = *attrib;
	*num_attribs += 1;
	return True;
}
				       
static BOOL ldap_decode_filter(TALLOC_CTX *mem_ctx, ASN1_DATA *data,
			       char **filter)
{
	uint8 filter_tag, tag_desc;

	if (!asn1_peek_uint8(data, &filter_tag))
		return False;

	tag_desc = filter_tag;
	filter_tag &= 0x1f;	/* strip off the asn1 stuff */
	tag_desc &= 0xe0;

	switch(filter_tag) {
	case 0: {
		/* AND of one or more filters */
		if (tag_desc != 0xa0) /* context compount */
			return False;

		asn1_start_tag(data, ASN1_CONTEXT(0));

		*filter = talloc_strdup(mem_ctx, "(&");
		if (*filter == NULL)
			return False;

		while (asn1_tag_remaining(data) > 0) {
			char *subfilter;
			if (!ldap_decode_filter(mem_ctx, data, &subfilter))
				return False;
			*filter = talloc_asprintf(mem_ctx, "%s%s", *filter,
						  subfilter);
			if (*filter == NULL)
				return False;
		}
		asn1_end_tag(data);

		*filter = talloc_asprintf(mem_ctx, "%s)", *filter);
		break;
	}
	case 1: {
		/* OR of one or more filters */
		if (tag_desc != 0xa0) /* context compount */
			return False;

		asn1_start_tag(data, ASN1_CONTEXT(1));

		*filter = talloc_strdup(mem_ctx, "(|");
		if (*filter == NULL)
			return False;

		while (asn1_tag_remaining(data) > 0) {
			char *subfilter;
			if (!ldap_decode_filter(mem_ctx, data, &subfilter))
				return False;
			*filter = talloc_asprintf(mem_ctx, "%s%s", *filter,
						  subfilter);
			if (*filter == NULL)
				return False;
		}

		asn1_end_tag(data);

		*filter = talloc_asprintf(mem_ctx, "%s)", *filter);
		break;
	}
	case 3: {
		/* equalityMatch */
		const char *attrib, *value;
		if (tag_desc != 0xa0) /* context compound */
			return False;
		asn1_start_tag(data, ASN1_CONTEXT(3));
		asn1_read_OctetString_talloc(mem_ctx, data, &attrib);
		asn1_read_OctetString_talloc(mem_ctx, data, &value);
		asn1_end_tag(data);
		if ((data->has_error) || (attrib == NULL) || (value == NULL))
			return False;
		*filter = talloc_asprintf(mem_ctx, "(%s=%s)", attrib, value);
		break;
	}
	case 7: {
		/* Normal presence, "attribute=*" */
		int attr_len;
		char *attr_name;
		if (tag_desc != 0x80) /* context simple */
			return False;
		if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(7)))
			return False;
		attr_len = asn1_tag_remaining(data);
		attr_name = malloc(attr_len+1);
		if (attr_name == NULL)
			return False;
		asn1_read(data, attr_name, attr_len);
		attr_name[attr_len] = '\0';
		*filter = talloc_asprintf(mem_ctx, "(%s=*)", attr_name);
		SAFE_FREE(attr_name);
		asn1_end_tag(data);
		break;
	}
	default:
		return False;
	}
	if (*filter == NULL)
		return False;
	return True;
}

static void ldap_decode_attrib(TALLOC_CTX *mem_ctx, ASN1_DATA *data,
			       struct ldap_attribute *attrib)
{
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_OctetString_talloc(mem_ctx, data, &attrib->name);
	asn1_start_tag(data, ASN1_SET);
	while (asn1_peek_tag(data, ASN1_OCTET_STRING)) {
		DATA_BLOB blob;
		struct ldap_val value;
		asn1_read_OctetString(data, &blob);
		value.data = blob.data;
		value.length = blob.length;
		add_value_to_attrib(mem_ctx, &value, attrib);
		data_blob_free(&blob);
	}
	asn1_end_tag(data);
	asn1_end_tag(data);
	
}

static void ldap_decode_attribs(TALLOC_CTX *mem_ctx, ASN1_DATA *data,
				struct ldap_attribute **attributes,
				int *num_attributes)
{
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	while (asn1_peek_tag(data, ASN1_SEQUENCE(0))) {
		struct ldap_attribute attrib;
		ZERO_STRUCT(attrib);
		ldap_decode_attrib(mem_ctx, data, &attrib);
		add_attrib_to_array_talloc(mem_ctx, &attrib,
					   attributes, num_attributes);
	}
	asn1_end_tag(data);
}

BOOL ldap_decode(ASN1_DATA *data, struct ldap_message *msg)
{
	uint8 tag;

	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_Integer(data, &msg->messageid);

	if (!asn1_peek_uint8(data, &tag))
		return False;

	switch(tag) {

	case ASN1_APPLICATION(LDAP_TAG_BindRequest): {
		struct ldap_BindRequest *r = &msg->r.BindRequest;
		msg->type = LDAP_TAG_BindRequest;
		asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_BindRequest));
		asn1_read_Integer(data, &r->version);
		asn1_read_OctetString_talloc(msg->mem_ctx, data, &r->dn);
		if (asn1_peek_tag(data, 0x80)) {
			int pwlen;
			r->creds.password = "";
			/* Mechanism 0 (SIMPLE) */
			asn1_start_tag(data, 0x80);
			pwlen = asn1_tag_remaining(data);
			if (pwlen != 0) {
				char *pw = talloc(msg->mem_ctx, pwlen+1);
				asn1_read(data, pw, pwlen);
				pw[pwlen] = '\0';
				r->creds.password = pw;
			}
			asn1_end_tag(data);
		}
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_BindResponse): {
		struct ldap_BindResponse *r = &msg->r.BindResponse;
		msg->type = LDAP_TAG_BindResponse;
		ldap_decode_response(msg->mem_ctx,
				     data, LDAP_TAG_BindResponse,
				     &r->response);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_UnbindRequest): {
		msg->type = LDAP_TAG_UnbindRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchRequest): {
		struct ldap_SearchRequest *r = &msg->r.SearchRequest;
		msg->type = LDAP_TAG_SearchRequest;
		asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_SearchRequest));
		asn1_read_OctetString_talloc(msg->mem_ctx, data, &r->basedn);
		asn1_read_enumerated(data, (int *)&(r->scope));
		asn1_read_enumerated(data, (int *)&(r->deref));
		asn1_read_Integer(data, &r->sizelimit);
		asn1_read_Integer(data, &r->timelimit);
		asn1_read_BOOLEAN2(data, &r->attributesonly);

		/* Maybe create a TALLOC_CTX for the filter? This can waste
		 * quite a bit of memory recursing down. */
		ldap_decode_filter(msg->mem_ctx, data, &r->filter);

		asn1_start_tag(data, ASN1_SEQUENCE(0));

		r->num_attributes = 0;
		r->attributes = NULL;

		while (asn1_tag_remaining(data) > 0) {
			const char *attr;
			if (!asn1_read_OctetString_talloc(msg->mem_ctx, data,
							  &attr))
				return False;
			if (!add_string_to_array(msg->mem_ctx, attr,
						 &r->attributes,
						 &r->num_attributes))
				return False;
		}

		asn1_end_tag(data);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultEntry): {
		struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;
		msg->type = LDAP_TAG_SearchResultEntry;
		r->attributes = NULL;
		r->num_attributes = 0;
		asn1_start_tag(data,
			       ASN1_APPLICATION(LDAP_TAG_SearchResultEntry));
		asn1_read_OctetString_talloc(msg->mem_ctx, data, &r->dn);
		ldap_decode_attribs(msg->mem_ctx, data, &r->attributes,
				    &r->num_attributes);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultDone): {
		struct ldap_Result *r = &msg->r.SearchResultDone;
		msg->type = LDAP_TAG_SearchResultDone;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_SearchResultDone, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultReference): {
/*		struct ldap_SearchResRef *r = &msg->r.SearchResultReference; */
		msg->type = LDAP_TAG_SearchResultReference;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyRequest): {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		msg->type = LDAP_TAG_ModifyRequest;
		asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_ModifyRequest));
		asn1_read_OctetString_talloc(msg->mem_ctx, data, &r->dn);
		asn1_start_tag(data, ASN1_SEQUENCE(0));

		r->num_mods = 0;
		r->mods = NULL;

		while (asn1_tag_remaining(data) > 0) {
			struct ldap_mod mod;
			ZERO_STRUCT(mod);
			asn1_start_tag(data, ASN1_SEQUENCE(0));
			asn1_read_enumerated(data, &mod.type);
			ldap_decode_attrib(msg->mem_ctx, data, &mod.attrib);
			asn1_end_tag(data);
			if (!add_mod_to_array_talloc(msg->mem_ctx, &mod,
						     &r->mods, &r->num_mods))
				break;
		}

		asn1_end_tag(data);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyResponse): {
		struct ldap_Result *r = &msg->r.ModifyResponse;
		msg->type = LDAP_TAG_ModifyResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_ModifyResponse, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddRequest): {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		msg->type = LDAP_TAG_AddRequest;
		asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_AddRequest));
		asn1_read_OctetString_talloc(msg->mem_ctx, data, &r->dn);

		r->attributes = NULL;
		r->num_attributes = 0;
		ldap_decode_attribs(msg->mem_ctx, data, &r->attributes,
				    &r->num_attributes);

		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddResponse): {
		struct ldap_Result *r = &msg->r.AddResponse;
		msg->type = LDAP_TAG_AddResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_AddResponse, r);
		break;
	}

	case ASN1_APPLICATION_SIMPLE(LDAP_TAG_DelRequest): {
		struct ldap_DelRequest *r = &msg->r.DelRequest;
		int len;
		char *dn;
		msg->type = LDAP_TAG_DelRequest;
		asn1_start_tag(data,
			       ASN1_APPLICATION_SIMPLE(LDAP_TAG_DelRequest));
		len = asn1_tag_remaining(data);
		dn = talloc(msg->mem_ctx, len+1);
		if (dn == NULL)
			break;
		asn1_read(data, dn, len);
		dn[len] = '\0';
		r->dn = dn;
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_DelResponse): {
		struct ldap_Result *r = &msg->r.DelResponse;
		msg->type = LDAP_TAG_DelResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_DelResponse, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest): {
/*		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest; */
		msg->type = LDAP_TAG_ModifyDNRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyDNResponse): {
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		msg->type = LDAP_TAG_ModifyDNResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_ModifyDNResponse, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_CompareRequest): {
/*		struct ldap_CompareRequest *r = &msg->r.CompareRequest; */
		msg->type = LDAP_TAG_CompareRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_CompareResponse): {
		struct ldap_Result *r = &msg->r.CompareResponse;
		msg->type = LDAP_TAG_CompareResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_CompareResponse, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AbandonRequest): {
/*		struct ldap_AbandonRequest *r = &msg->r.AbandonRequest; */
		msg->type = LDAP_TAG_AbandonRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ExtendedRequest): {
/*		struct ldap_ExtendedRequest *r = &msg->r.ExtendedRequest; */
		msg->type = LDAP_TAG_ExtendedRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ExtendedResponse): {
		struct ldap_ExtendedResponse *r = &msg->r.ExtendedResponse;
		msg->type = LDAP_TAG_ExtendedResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_ExtendedResponse, &r->response);
		/* I have to come across an operation that actually sends
		 * something back to really see what's going on. The currently
		 * needed pwdchange does not send anything back. */
		r->name = NULL;
		r->value.data = NULL;
		r->value.length = 0;
		break;
	}

	}

	asn1_end_tag(data);
	return ((!data->has_error) && (data->nesting == NULL));
}

BOOL ldap_parse_basic_url(TALLOC_CTX *mem_ctx, const char *url,
			  char **host, uint16 *port, BOOL *ldaps)
{
	int tmp_port = 0;
	fstring protocol;
	fstring tmp_host;
	const char *p = url;

	/* skip leading "URL:" (if any) */
	if ( strnequal( p, "URL:", 4 ) ) {
		p += 4;
	}

	/* Paranoia check */
	SMB_ASSERT(sizeof(protocol)>10 && sizeof(tmp_host)>254);
		
	sscanf(p, "%10[^:]://%254[^:/]:%d", protocol, tmp_host, &tmp_port);

	if (strequal(protocol, "ldap")) {
		*port = 389;
		*ldaps = False;
	} else if (strequal(protocol, "ldaps")) {
		*port = 636;
		*ldaps = True;
	} else {
		DEBUG(0, ("unrecognised protocol (%s)!\n", protocol));
		return False;
	}

	if (tmp_port != 0)
		*port = tmp_port;
	
	*host = talloc_strdup(mem_ctx, tmp_host);

	return (*host != NULL);
}

struct ldap_connection *new_ldap_connection(void)
{
	TALLOC_CTX *mem_ctx = talloc_init("ldap_connection");
	struct ldap_connection *result;

	if (mem_ctx == NULL)
		return NULL;

	result = talloc(mem_ctx, sizeof(*result));

	if (result == NULL)
		return NULL;

	result->mem_ctx = mem_ctx;
	result->next_msgid = 1;
	result->outstanding = NULL;
	result->searchid = 0;
	result->search_entries = NULL;
	return result;
}

BOOL ldap_connect(struct ldap_connection *conn, const char *url)
{
	struct hostent *hp;
	struct in_addr ip;

	if (!ldap_parse_basic_url(conn->mem_ctx, url, &conn->host,
				  &conn->port, &conn->ldaps))
		return False;

	hp = sys_gethostbyname(conn->host);

	if ((hp == NULL) || (hp->h_addr == NULL))
		return False;

	putip((char *)&ip, (char *)hp->h_addr);

	conn->sock = open_socket_out(SOCK_STREAM, &ip, conn->port, 10000);

	return (conn->sock >= 0);
}

BOOL ldap_set_simple_creds(struct ldap_connection *conn,
			   const char *dn, const char *password)
{
	conn->auth_dn = talloc_strdup(conn->mem_ctx, dn);
	conn->simple_pw = talloc_strdup(conn->mem_ctx, password);

	return ((conn->auth_dn != NULL) && (conn->simple_pw != NULL));
}

struct ldap_message *new_ldap_message(void)
{
	TALLOC_CTX *mem_ctx = talloc_init("ldap_message");
	struct ldap_message *result;

	if (mem_ctx == NULL)
		return NULL;

	result = talloc(mem_ctx, sizeof(*result));

	if (result == NULL)
		return NULL;

	result->mem_ctx = mem_ctx;
	return result;
}

void destroy_ldap_message(struct ldap_message *msg)
{
	if (msg != NULL)
		talloc_destroy(msg->mem_ctx);
}

BOOL ldap_send_msg(struct ldap_connection *conn, struct ldap_message *msg,
		   const struct timeval *endtime)
{
	DATA_BLOB request;
	BOOL result;
	struct ldap_queue_entry *entry;

	msg->messageid = conn->next_msgid++;

	if (!ldap_encode(msg, &request))
		return False;

	result = (write_data_until(conn->sock, request.data, request.length,
				   endtime) == request.length);

	data_blob_free(&request);

	if (!result)
		return result;

	/* abandon and unbind don't expect results */

	if ((msg->type == LDAP_TAG_AbandonRequest) ||
	    (msg->type == LDAP_TAG_UnbindRequest))
		return True;

	entry = malloc(sizeof(*entry));	

	if (entry == NULL)
		return False;

	entry->msgid = msg->messageid;
	entry->msg = NULL;
	DLIST_ADD(conn->outstanding, entry);

	return True;
}

BOOL ldap_receive_msg(struct ldap_connection *conn, struct ldap_message *msg,
		      const struct timeval *endtime)
{
        struct asn1_data data;
        BOOL result;

        if (!asn1_read_sequence_until(conn->sock, &data, endtime))
                return False;

        result = ldap_decode(&data, msg);

        asn1_free(&data);
        return result;
}

static struct ldap_message *recv_from_queue(struct ldap_connection *conn,
					    int msgid)
{
	struct ldap_queue_entry *e;

	for (e = conn->outstanding; e != NULL; e = e->next) {

		if (e->msgid == msgid) {
			struct ldap_message *result = e->msg;
			DLIST_REMOVE(conn->outstanding, e);
			SAFE_FREE(e);
			return result;
		}
	}

	return NULL;
}

static void add_search_entry(struct ldap_connection *conn,
			     struct ldap_message *msg)
{
	struct ldap_queue_entry *e = malloc(sizeof *e);

	if (e == NULL)
		return;

	e->msg = msg;
	DLIST_ADD_END(conn->search_entries, e, struct ldap_queue_entry *);
	return;
}

static void fill_outstanding_request(struct ldap_connection *conn,
				     struct ldap_message *msg)
{
	struct ldap_queue_entry *e;

	for (e = conn->outstanding; e != NULL; e = e->next) {
		if (e->msgid == msg->messageid) {
			e->msg = msg;
			return;
		}
	}

	/* This reply has not been expected, destroy the incoming msg */
	destroy_ldap_message(msg);
	return;
}

struct ldap_message *ldap_receive(struct ldap_connection *conn, int msgid,
				  const struct timeval *endtime)
{
	struct ldap_message *result = recv_from_queue(conn, msgid);

	if (result != NULL)
		return result;

	while (True) {
		struct asn1_data data;
		result = new_ldap_message();
		BOOL res;

		if (!asn1_read_sequence_until(conn->sock, &data, endtime))
			return NULL;

		res = ldap_decode(&data, result);
		asn1_free(&data);

		if (!res)
			return NULL;

		if (result->messageid == msgid)
			return result;

		if (result->type == LDAP_TAG_SearchResultEntry) {
			add_search_entry(conn, result);
		} else {
			fill_outstanding_request(conn, result);
		}
	}

	return NULL;
}

struct ldap_message *ldap_transaction(struct ldap_connection *conn,
				      struct ldap_message *request)
{
	if (!ldap_send_msg(conn, request, NULL))
		return False;

	return ldap_receive(conn, request->messageid, NULL);
}

BOOL ldap_setup_connection(struct ldap_connection *conn,
			   const char *url)
{
	struct ldap_message *msg = new_ldap_message();
	struct ldap_message *response;
	BOOL result;

	if (msg == NULL)
		return False;

	if (!ldap_connect(conn, url)) {
		destroy_ldap_message(msg);
		return False;
	}

	msg->messageid = conn->next_msgid++;
	msg->type = LDAP_TAG_BindRequest;
	msg->r.BindRequest.version = 3;
	msg->r.BindRequest.dn = conn->auth_dn;
	msg->r.BindRequest.mechanism = LDAP_AUTH_MECH_SIMPLE;
	msg->r.BindRequest.creds.password = conn->simple_pw;

	if ((response = ldap_transaction(conn, msg)) == NULL)
		return False;

	result = (response->r.BindResponse.response.resultcode == 0);

	destroy_ldap_message(msg);
	destroy_ldap_message(response);
	return result;
}

static BOOL ldap_abandon_message(struct ldap_connection *conn, int msgid,
				 const struct timeval *endtime)
{
	struct ldap_message *msg = new_ldap_message();
	BOOL result;

	if (msg == NULL)
		return False;

	msg->type = LDAP_TAG_AbandonRequest;
	msg->r.AbandonRequest.messageid = msgid;

	result = ldap_send_msg(conn, msg, endtime);
	destroy_ldap_message(msg);
	return result;
}

struct ldap_message *new_ldap_search_message(const char *base,
					     enum ldap_scope scope,
					     char *filter,
					     int num_attributes,
					     const char **attributes)
{
	struct ldap_message *res = new_ldap_message();

	if (res == NULL)
		return NULL;

	res->type = LDAP_TAG_SearchRequest;
	res->r.SearchRequest.basedn = base;
	res->r.SearchRequest.scope = scope;
	res->r.SearchRequest.deref = LDAP_DEREFERENCE_NEVER;
	res->r.SearchRequest.timelimit = 0;
	res->r.SearchRequest.sizelimit = 0;
	res->r.SearchRequest.attributesonly = False;
	res->r.SearchRequest.filter = filter;
	res->r.SearchRequest.num_attributes = num_attributes;
	res->r.SearchRequest.attributes = attributes;
	return res;
}

struct ldap_message *new_ldap_simple_bind_msg(const char *dn, const char *pw)
{
	struct ldap_message *res = new_ldap_message();

	if (res == NULL)
		return NULL;

	res->type = LDAP_TAG_BindRequest;
	res->r.BindRequest.version = 3;
	res->r.BindRequest.dn = talloc_strdup(res->mem_ctx, dn);
	res->r.BindRequest.mechanism = LDAP_AUTH_MECH_SIMPLE;
	res->r.BindRequest.creds.password = talloc_strdup(res->mem_ctx, pw);
	return res;
}

BOOL ldap_setsearchent(struct ldap_connection *conn, struct ldap_message *msg,
		       const struct timeval *endtime)
{
	if ((conn->searchid != 0) &&
	    (!ldap_abandon_message(conn, conn->searchid, endtime)))
		return False;

	conn->searchid = conn->next_msgid;
	return ldap_send_msg(conn, msg, endtime);
}

struct ldap_message *ldap_getsearchent(struct ldap_connection *conn,
				       const struct timeval *endtime)
{
	struct ldap_message *result;

	if (conn->search_entries != NULL) {
		struct ldap_queue_entry *e = conn->search_entries;

		result = e->msg;
		DLIST_REMOVE(conn->search_entries, e);
		SAFE_FREE(e);
		return result;
	}

	result = ldap_receive(conn, conn->searchid, endtime);

	if (result->type == LDAP_TAG_SearchResultEntry)
		return result;

	if (result->type == LDAP_TAG_SearchResultDone) {
		/* TODO: Handle Paged Results */
		destroy_ldap_message(result);
		return NULL;
	}

	/* TODO: Handle Search References here */
	return NULL;
}

void ldap_endsearchent(struct ldap_connection *conn,
		       const struct timeval *endtime)
{
	struct ldap_queue_entry *e;

	e = conn->search_entries;

	while (e != NULL) {
		struct ldap_queue_entry *next = e->next;
		DLIST_REMOVE(conn->search_entries, e);
		SAFE_FREE(e);
		e = next;
	}
}

struct ldap_message *ldap_searchone(struct ldap_connection *conn,
				    struct ldap_message *msg,
				    const struct timeval *endtime)
{
	struct ldap_message *res1, *res2 = NULL;
	if (!ldap_setsearchent(conn, msg, endtime))
		return NULL;

	res1 = ldap_getsearchent(conn, endtime);

	if (res1 != NULL)
		res2 = ldap_getsearchent(conn, endtime);

	ldap_endsearchent(conn, endtime);

	if (res1 == NULL)
		return NULL;

	if (res2 != NULL) {
		/* More than one entry */
		destroy_ldap_message(res1);
		destroy_ldap_message(res2);
		return NULL;
	}

	return res1;
}

BOOL ldap_find_single_value(struct ldap_message *msg, const char *attr,
			    DATA_BLOB *value)
{
	int i;
	struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;

	if (msg->type != LDAP_TAG_SearchResultEntry)
		return False;

	for (i=0; i<r->num_attributes; i++) {
		if (strequal(attr, r->attributes[i].name)) {
			if (r->attributes[i].num_values != 1)
				return False;

			*value = r->attributes[i].values[0];
			return True;
		}
	}
	return False;
}

BOOL ldap_find_single_string(struct ldap_message *msg, const char *attr,
			     TALLOC_CTX *mem_ctx, char **value)
{
	DATA_BLOB blob;

	if (!ldap_find_single_value(msg, attr, &blob))
		return False;

	*value = talloc(mem_ctx, blob.length+1);

	if (*value == NULL)
		return False;

	memcpy(*value, blob.data, blob.length);
	(*value)[blob.length] = '\0';
	return True;
}

BOOL ldap_find_single_int(struct ldap_message *msg, const char *attr,
			  int *value)
{
	DATA_BLOB blob;
	char *val;
	int errno_save;
	BOOL res;

	if (!ldap_find_single_value(msg, attr, &blob))
		return False;

	val = malloc(blob.length+1);
	if (val == NULL)
		return False;

	memcpy(val, blob.data, blob.length);
	val[blob.length] = '\0';

	errno_save = errno;
	errno = 0;

	*value = strtol(val, NULL, 10);

	res = (errno == 0);

	free(val);
	errno = errno_save;

	return res;
}

int ldap_error(struct ldap_connection *conn)
{
	return 0;
}

NTSTATUS ldap2nterror(int ldaperror)
{
	return NT_STATUS_OK;
}
