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
#include "smb_ldap.h"

/* Filter stuff shamelessly stolen and adapted from Samba 4. */

struct ldb_val {
	unsigned int length;
	void *data;
};

enum ldb_parse_op {LDB_OP_SIMPLE, LDB_OP_AND, LDB_OP_OR, LDB_OP_NOT};

struct ldb_parse_tree {
	enum ldb_parse_op operation;
	union {
		struct {
			char *attr;
			struct ldb_val value;
		} simple;
		struct {
			unsigned int num_elements;
			struct ldb_parse_tree **elements;
		} list;
		struct {
			struct ldb_parse_tree *child;
		} not;
	} u;
};

#define LDB_ALL_SEP "()&|=!"

/*
  return next token element. Caller frees
*/
static char *ldb_parse_lex(TALLOC_CTX *mem_ctx, const char **s,
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

static struct ldb_parse_tree *ldb_parse_filter(TALLOC_CTX *mem_ctx,
					       const char **s);

/*
  <simple> ::= <attributetype> <filtertype> <attributevalue>
*/
static struct ldb_parse_tree *ldb_parse_simple(TALLOC_CTX *mem_ctx,
					       const char *s)
{
	char *eq, *val, *l;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(mem_ctx, &s, LDB_ALL_SEP);
	if (!l) {
		return NULL;
	}

	if (strchr("()&|=", *l))
		return NULL;

	eq = ldb_parse_lex(mem_ctx, &s, LDB_ALL_SEP);
	if (!eq || strcmp(eq, "=") != 0)
		return NULL;

	val = ldb_parse_lex(mem_ctx, &s, ")");
	if (val && strchr("()&|", *val))
		return NULL;
	
	ret = talloc(mem_ctx, sizeof(*ret));
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDB_OP_SIMPLE;
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
static struct ldb_parse_tree *ldb_parse_filterlist(TALLOC_CTX *mem_ctx,
						   enum ldb_parse_op op,
						   const char *s)
{
	struct ldb_parse_tree *ret, *next;

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

	ret->u.list.elements[0] = ldb_parse_filter(mem_ctx, &s);
	if (!ret->u.list.elements[0]) {
		return NULL;
	}

	while (isspace(*s)) s++;

	while (*s && (next = ldb_parse_filter(mem_ctx, &s))) {
		struct ldb_parse_tree **e;
		e = talloc_realloc(mem_ctx, ret->u.list.elements,
				   sizeof(struct ldb_parse_tree) *
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
static struct ldb_parse_tree *ldb_parse_not(TALLOC_CTX *mem_ctx, const char *s)
{
	struct ldb_parse_tree *ret;

	ret = talloc(mem_ctx, sizeof(*ret));
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDB_OP_NOT;
	ret->u.not.child = ldb_parse_filter(mem_ctx, &s);
	if (!ret->u.not.child)
		return NULL;

	return ret;
}

/*
  parse a filtercomp
  <filtercomp> ::= <and> | <or> | <not> | <simple>
*/
static struct ldb_parse_tree *ldb_parse_filtercomp(TALLOC_CTX *mem_ctx,
						   const char *s)
{
	while (isspace(*s)) s++;

	switch (*s) {
	case '&':
		return ldb_parse_filterlist(mem_ctx, LDB_OP_AND, s+1);

	case '|':
		return ldb_parse_filterlist(mem_ctx, LDB_OP_OR, s+1);

	case '!':
		return ldb_parse_not(mem_ctx, s+1);

	case '(':
	case ')':
		return NULL;
	}

	return ldb_parse_simple(mem_ctx, s);
}


/*
  <filter> ::= '(' <filtercomp> ')'
*/
static struct ldb_parse_tree *ldb_parse_filter(TALLOC_CTX *mem_ctx,
					       const char **s)
{
	char *l, *s2;
	const char *p, *p2;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(mem_ctx, s, LDB_ALL_SEP);
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

	ret = ldb_parse_filtercomp(mem_ctx, s2);

	*s = p2;

	return ret;
}

/*
  main parser entry point. Takes a search string and returns a parse tree

  expression ::= <simple> | <filter>
*/
static struct ldb_parse_tree *ldb_parse_tree(TALLOC_CTX *mem_ctx, const char *s)
{
	while (isspace(*s)) s++;

	if (*s == '(') {
		return ldb_parse_filter(mem_ctx, &s);
	}

	return ldb_parse_simple(mem_ctx, s);
}

static BOOL ldap_push_filter(ASN1_DATA *data, struct ldb_parse_tree *tree)
{
	switch (tree->operation) {
	case LDB_OP_SIMPLE: {
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

	case LDB_OP_AND: {
		int i;

		asn1_push_tag(data, 0xa0);
		for (i=0; i<tree->u.list.num_elements; i++) {
			ldap_push_filter(data, tree->u.list.elements[i]);
		}
		asn1_pop_tag(data);
		break;
	}

	case LDB_OP_OR: {
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
		asn1_write_OctetString(&data, r->dn, (r->dn != NULL) ? strlen(r->dn) : 0);

		switch (r->mechanism) {
		case LDAP_AUTH_MECH_SIMPLE:
			asn1_push_tag(&data, r->mechanism | 0x80); /* context, primitive */
			asn1_write(&data, r->creds.password,
				   strlen(r->creds.password));
			asn1_pop_tag(&data);
			break;
		case LDAP_AUTH_MECH_SASL:
			asn1_push_tag(&data, r->mechanism | 0xa0); /* context, constructed */
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
/*		struct ldap_BindResponse *r = &msg->r.BindResponse; */
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
			TALLOC_CTX *mem_ctx = talloc_init("ldb_parse_tree");
			struct ldb_parse_tree *tree;

			if (mem_ctx == NULL)
				return False;

			tree = ldb_parse_tree(mem_ctx, r->filter);

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
/*		struct ldap_SearchResultEntry *r = &msg->r.SearchResultEntry; */
		break;
	}
	case LDAP_TAG_SearchResultDone: {
/*		struct ldap_SearchResultDone *r = &msg->r.SearchResultDone; */
		break;
	}
	case LDAP_TAG_ModifyRequest: {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_ModifyRequest));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));

		for (i=0; i<r->num_mods; i++) {
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_enumerated(&data, r->mods[i].type);
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_OctetString(&data, r->mods[i].attribute,
					       strlen(r->mods[i].attribute));
			asn1_push_tag(&data, ASN1_SET);
			for (j=0; j<r->mods[i].num_values; j++) {
				asn1_write_OctetString(&data, r->mods[i].values[j],
						       strlen(r->mods[i].values[j]));
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
/*		struct ldap_Result *r = &msg->r.ModifyResponse; */
		break;
	}
	case LDAP_TAG_AddRequest: {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_AddRequest));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));

		for (i=0; i<r->num_attributes; i++) {
			asn1_push_tag(&data, ASN1_SEQUENCE(0));
			asn1_write_OctetString(&data, r->attributes[i].name,
					       strlen(r->attributes[i].name));
			asn1_push_tag(&data, ASN1_SET);
			for (j=0; j<r->attributes[i].num_values; j++) {
				asn1_write_OctetString(&data, r->attributes[i].values[j],
						       strlen(r->attributes[i].values[j]));
			}
			asn1_pop_tag(&data);
			asn1_pop_tag(&data);
		}
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_AddResponse: {
/*		struct ldap_Result *r = &msg->r.AddResponse; */
		break;
	}
	case LDAP_TAG_DelRequest: {
		struct ldap_DelRequest *r = &msg->r.DelRequest;
		asn1_push_tag(&data, ASN1_APPLICATION_SIMPLE(LDAP_TAG_DelRequest));
		asn1_write(&data, r->dn, strlen(r->dn));
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_DelResponse: {
/*		struct ldap_Result *r = &msg->r.DelResponse; */
		break;
	}
	case LDAP_TAG_ModifyDNRequest: {
		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest));
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
		asn1_push_tag(&data, ASN1_APPLICATION(LDAP_TAG_CompareRequest));
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
		asn1_push_tag(&data, ASN1_APPLICATION_SIMPLE(LDAP_TAG_AbandonRequest));
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
/*		struct ldap_ExtendedResponse *r = &msg->r.ExtendedResponse; */
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

static BOOL add_string_to_array_talloc(TALLOC_CTX *mem_ctx,
				       const char *string,
				       const char ***strings,
				       int *num_strings)
{
	*strings = talloc_realloc(mem_ctx, *strings,
				  sizeof(**strings) * (*num_strings+1));

	if (*strings == NULL)
		return False;

	(*strings)[*num_strings] = string;
	*num_strings += 1;
	return True;
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
				       

BOOL ldap_decode(ASN1_DATA *data, struct ldap_message *msg)
{
	uint8 tag;

	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_Integer(data, &msg->messageid);

	if (!asn1_peek_uint8(data, &tag))
		return False;

	switch(tag) {

	case ASN1_APPLICATION(LDAP_TAG_BindRequest): {
/*		struct ldap_BindRequest *r = &msg->r.BindRequest; */
		msg->type = LDAP_TAG_BindRequest;
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
/*		struct ldap_UnbindRequest *r = &msg->r.UnbindRequest; */
		msg->type = LDAP_TAG_UnbindRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchRequest): {
/*		struct ldap_SearchRequest *r = &msg->r.SearchRequest; */
		msg->type = LDAP_TAG_SearchRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultEntry): {
		struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;
		msg->type = LDAP_TAG_SearchResultEntry;
		r->attributes = NULL;
		r->num_attributes = 0;
		asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_SearchResultEntry));
		asn1_read_OctetString_talloc(msg->mem_ctx, data, &r->dn);
		asn1_start_tag(data, ASN1_SEQUENCE(0));
		while (asn1_peek_tag(data, ASN1_SEQUENCE(0))) {
			struct ldap_attribute attrib;
			ZERO_STRUCT(attrib);
			asn1_start_tag(data, ASN1_SEQUENCE(0));
			asn1_read_OctetString_talloc(msg->mem_ctx, data,
						     &attrib.name);
			asn1_start_tag(data, ASN1_SEQUENCE(1));
			while (asn1_peek_tag(data, ASN1_OCTET_STRING)) {
				const char *value;
				asn1_read_OctetString_talloc(msg->mem_ctx, data,
							     &value);
				add_string_to_array_talloc(msg->mem_ctx,
							   value,
							   &attrib.values,
							   &attrib.num_values);
			}
			asn1_end_tag(data);
			asn1_end_tag(data);
			add_attrib_to_array_talloc(msg->mem_ctx,
						   &attrib,
						   &r->attributes,
						   &r->num_attributes);
		}
		asn1_end_tag(data);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultDone): {
		struct ldap_SearchResultDone *r = &msg->r.SearchResultDone;
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
/*		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest; */
		msg->type = LDAP_TAG_ModifyRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyResponse): {
		struct ldap_ModifyResponse *r = &msg->r.ModifyResponse;
		msg->type = LDAP_TAG_ModifyResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_ModifyResponse, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddRequest): {
/*		struct ldap_AddRequest *r = &msg->r.AddRequest; */
		msg->type = LDAP_TAG_AddRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddResponse): {
		struct ldap_AddResponse *r = &msg->r.AddResponse;
		msg->type = LDAP_TAG_AddResponse;
		ldap_decode_response(msg->mem_ctx, data,
				     LDAP_TAG_AddResponse, r);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_DelRequest): {
/*		struct ldap_DelRequest *r = &msg->r.DelRequest; */
		msg->type = LDAP_TAG_DelRequest;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_DelResponse): {
		struct ldap_DelResponse *r = &msg->r.DelResponse;
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
		struct ldap_ModifyDNResponse *r = &msg->r.ModifyDNResponse;
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
		struct ldap_CompareResponse *r = &msg->r.CompareResponse;
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
	return !data->has_error;
}

struct ldap_connection {
	TALLOC_CTX *mem_ctx;
	int sock;
	int next_msgid;
	char *host;
	uint16 port;
	BOOL ldaps;

	const char *auth_dn;
	const char *simple_pw;
};

static BOOL ldap_parse_basic_url(TALLOC_CTX *mem_ctx, const char *url,
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
	talloc_destroy(msg->mem_ctx);
}

BOOL ldap_send_msg(struct ldap_connection *conn, struct ldap_message *msg)
{
	DATA_BLOB request;
	BOOL result;

	msg->messageid = conn->next_msgid++;

	if (!ldap_encode(msg, &request))
		return False;

	result = (write_data(conn->sock, request.data,
			     request.length) == request.length);

	data_blob_free(&request);
	return result;
}

BOOL ldap_receive_msg(struct ldap_connection *conn, struct ldap_message *msg)
{
	struct asn1_data data;
	BOOL result;

	if (!asn1_read_sequence(conn->sock, &data))
		return False;

	result = ldap_decode(&data, msg);

	asn1_free(&data);
	return result;
}

BOOL ldap_transaction(struct ldap_connection *conn,
		      struct ldap_message *request,
		      struct ldap_message *response)
{
	if (!ldap_send_msg(conn, request))
		return False;
	return ldap_receive_msg(conn, response);
}

BOOL ldap_setup_connection(struct ldap_connection *conn,
			   const char *url)
{
	struct ldap_message *msg = new_ldap_message();
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

	if (!ldap_transaction(conn, msg, msg))
		return False;

	result = (msg->r.BindResponse.response.resultcode == 0);

	destroy_ldap_message(msg);
	return result;
}

