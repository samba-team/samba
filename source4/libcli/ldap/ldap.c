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
#include "system/iconv.h"
#include "asn_1.h"
#include "libcli/ldap/ldap.h"


static BOOL ldap_push_filter(struct asn1_data *data, struct ldb_parse_tree *tree)
{
	int i;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		if ((tree->u.simple.value.length == 1) &&
		    (((char *)(tree->u.simple.value.data))[0] == '*')) {
			/* Just a presence test */
			asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(7));
			asn1_write(data, tree->u.simple.attr,
				   strlen(tree->u.simple.attr));
			asn1_pop_tag(data);
			return !data->has_error;
		}

		/* equality test */
		asn1_push_tag(data, ASN1_CONTEXT(3));
		asn1_write_OctetString(data, tree->u.simple.attr,
				      strlen(tree->u.simple.attr));
		asn1_write_OctetString(data, tree->u.simple.value.data,
				      tree->u.simple.value.length);
		asn1_pop_tag(data);
		break;

	case LDB_OP_EXTENDED:
		/*
		  MatchingRuleAssertion ::= SEQUENCE {
		  matchingRule    [1] MatchingRuleID OPTIONAL,
		  type            [2] AttributeDescription OPTIONAL,
		  matchValue      [3] AssertionValue,
		  dnAttributes    [4] BOOLEAN DEFAULT FALSE
		  }
		*/
		asn1_push_tag(data, ASN1_CONTEXT(9));
		if (tree->u.extended.rule_id) {
			asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(1));
			asn1_write_LDAPString(data, tree->u.extended.rule_id);
			asn1_pop_tag(data);
		}
		if (tree->u.extended.attr) {
			asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(2));
			asn1_write_LDAPString(data, tree->u.extended.attr);
			asn1_pop_tag(data);
		}
		asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(3));
		asn1_write_LDAPString(data, tree->u.extended.value.data);
		asn1_pop_tag(data);
		asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(4));
		asn1_write_uint8(data, tree->u.extended.dnAttributes);
		asn1_pop_tag(data);
		asn1_pop_tag(data);
		break;
		

	case LDB_OP_AND:
	case LDB_OP_OR:
		asn1_push_tag(data, ASN1_CONTEXT(tree->operation==LDB_OP_AND?0:1));
		for (i=0; i<tree->u.list.num_elements; i++) {
			if (!ldap_push_filter(data, tree->u.list.elements[i])) {
				return False;
			}
		}
		asn1_pop_tag(data);
		break;

	case LDB_OP_NOT:
		asn1_push_tag(data, ASN1_CONTEXT(2));
		if (!ldap_push_filter(data, tree->u.isnot.child)) {
			return False;
		}
		asn1_pop_tag(data);
		break;

	default:
		return False;
	}
	return !data->has_error;
}

static void ldap_encode_response(struct asn1_data *data, struct ldap_Result *result)
{
	asn1_write_enumerated(data, result->resultcode);
	asn1_write_OctetString(data, result->dn,
			       (result->dn) ? strlen(result->dn) : 0);
	asn1_write_OctetString(data, result->errormessage,
			       (result->errormessage) ?
			       strlen(result->errormessage) : 0);
	if (result->referral) {
		asn1_push_tag(data, ASN1_CONTEXT(3));
		asn1_write_OctetString(data, result->referral,
				       strlen(result->referral));
		asn1_pop_tag(data);
	}
}

BOOL ldap_encode(struct ldap_message *msg, DATA_BLOB *result)
{
	struct asn1_data data;
	int i, j;

	ZERO_STRUCT(data);
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	asn1_write_Integer(&data, msg->messageid);

	switch (msg->type) {
	case LDAP_TAG_BindRequest: {
		struct ldap_BindRequest *r = &msg->r.BindRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_Integer(&data, r->version);
		asn1_write_OctetString(&data, r->dn,
				       (r->dn != NULL) ? strlen(r->dn) : 0);

		switch (r->mechanism) {
		case LDAP_AUTH_MECH_SIMPLE:
			/* context, primitive */
			asn1_push_tag(&data, ASN1_CONTEXT_SIMPLE(0));
			asn1_write(&data, r->creds.password,
				   strlen(r->creds.password));
			asn1_pop_tag(&data);
			break;
		case LDAP_AUTH_MECH_SASL:
			/* context, constructed */
			asn1_push_tag(&data, ASN1_CONTEXT(3));
			asn1_write_OctetString(&data, r->creds.SASL.mechanism,
					       strlen(r->creds.SASL.mechanism));
			asn1_write_OctetString(&data, r->creds.SASL.secblob.data,
					       r->creds.SASL.secblob.length);
			asn1_pop_tag(&data);
			break;
		default:
			return False;
		}

		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_BindResponse: {
		struct ldap_BindResponse *r = &msg->r.BindResponse;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, &r->response);
		asn1_write_ContextSimple(&data, 7, &r->SASL.secblob);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_UnbindRequest: {
/*		struct ldap_UnbindRequest *r = &msg->r.UnbindRequest; */
		break;
	}
	case LDAP_TAG_SearchRequest: {
		struct ldap_SearchRequest *r = &msg->r.SearchRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->basedn, strlen(r->basedn));
		asn1_write_enumerated(&data, r->scope);
		asn1_write_enumerated(&data, r->deref);
		asn1_write_Integer(&data, r->sizelimit);
		asn1_write_Integer(&data, r->timelimit);
		asn1_write_BOOLEAN(&data, r->attributesonly);

		if (!ldap_push_filter(&data, r->tree)) {
			return False;
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
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));
		for (i=0; i<r->num_attributes; i++) {
			struct ldb_message_element *attr = &r->attributes[i];
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
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, r);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_ModifyRequest: {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));

		for (i=0; i<r->num_mods; i++) {
			struct ldb_message_element *attrib = &r->mods[i].attrib;
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
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, r);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_AddRequest: {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));

		for (i=0; i<r->num_attributes; i++) {
			struct ldb_message_element *attrib = &r->attributes[i];
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
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, r);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_DelRequest: {
		struct ldap_DelRequest *r = &msg->r.DelRequest;
		asn1_push_tag(&data, ASN1_APPLICATION_SIMPLE(msg->type));
		asn1_write(&data, r->dn, strlen(r->dn));
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_DelResponse: {
		struct ldap_Result *r = &msg->r.DelResponse;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, r);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_ModifyDNRequest: {
		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_write_OctetString(&data, r->newrdn, strlen(r->newrdn));
		asn1_write_BOOLEAN(&data, r->deleteolddn);
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
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, r);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_CompareRequest: {
		struct ldap_CompareRequest *r = &msg->r.CompareRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->dn, strlen(r->dn));
		asn1_push_tag(&data, ASN1_SEQUENCE(0));
		asn1_write_OctetString(&data, r->attribute,
				       strlen(r->attribute));
		asn1_write_OctetString(&data, r->value.data,
				       r->value.length);
		asn1_pop_tag(&data);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_CompareResponse: {
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, r);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_AbandonRequest: {
		struct ldap_AbandonRequest *r = &msg->r.AbandonRequest;
		asn1_push_tag(&data, ASN1_APPLICATION_SIMPLE(msg->type));
		asn1_write_implicit_Integer(&data, r->messageid);
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_SearchResultReference: {
		struct ldap_SearchResRef *r = &msg->r.SearchResultReference;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		asn1_write_OctetString(&data, r->referral, strlen(r->referral));
		asn1_pop_tag(&data);
		break;
	}
	case LDAP_TAG_ExtendedRequest: {
		struct ldap_ExtendedRequest *r = &msg->r.ExtendedRequest;
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
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
		asn1_push_tag(&data, ASN1_APPLICATION(msg->type));
		ldap_encode_response(&data, &r->response);
		asn1_pop_tag(&data);
		break;
	}
	default:
		return False;
	}

	asn1_pop_tag(&data);

	if (data.has_error) {
		asn1_free(&data);
		return False;
	}

	*result = data_blob(data.data, data.length);
	asn1_free(&data);
	return True;
}

static const char *blob2string_talloc(TALLOC_CTX *mem_ctx,
				      DATA_BLOB blob)
{
	char *result = talloc_size(mem_ctx, blob.length+1);
	memcpy(result, blob.data, blob.length);
	result[blob.length] = '\0';
	return result;
}

static BOOL asn1_read_OctetString_talloc(TALLOC_CTX *mem_ctx,
					 struct asn1_data *data,
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
				 struct asn1_data *data,
				 struct ldap_Result *result)
{
	asn1_read_enumerated(data, &result->resultcode);
	asn1_read_OctetString_talloc(mem_ctx, data, &result->dn);
	asn1_read_OctetString_talloc(mem_ctx, data, &result->errormessage);
	if (asn1_peek_tag(data, ASN1_CONTEXT(3))) {
		asn1_start_tag(data, ASN1_CONTEXT(3));
		asn1_read_OctetString_talloc(mem_ctx, data, &result->referral);
		asn1_end_tag(data);
	} else {
		result->referral = NULL;
	}
}


/*
  parse the ASN.1 formatted search string into a ldb_parse_tree
*/
static struct ldb_parse_tree *ldap_decode_filter_tree(TALLOC_CTX *mem_ctx, 
						      struct asn1_data *data)
{
	uint8_t filter_tag;
	struct ldb_parse_tree *ret;

	if (!asn1_peek_uint8(data, &filter_tag)) {
		return NULL;
	}

	filter_tag &= 0x1f;	/* strip off the asn1 stuff */

	ret = talloc(mem_ctx, struct ldb_parse_tree);
	if (ret == NULL) return NULL;

	switch(filter_tag) {
	case 0:
	case 1:
		/* AND or OR of one or more filters */
		ret->operation = (filter_tag == 0)?LDB_OP_AND:LDB_OP_OR;
		ret->u.list.num_elements = 0;
		ret->u.list.elements = NULL;

		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) {
			goto failed;
		}

		while (asn1_tag_remaining(data) > 0) {
			struct ldb_parse_tree *subtree;
			subtree = ldap_decode_filter_tree(ret, data);
			if (subtree == NULL) {
				goto failed;
			}
			ret->u.list.elements = 
				talloc_realloc(ret, ret->u.list.elements, 
					       struct ldb_parse_tree *, 
					       ret->u.list.num_elements+1);
			if (ret->u.list.elements == NULL) {
				goto failed;
			}
			talloc_steal(ret->u.list.elements, subtree);
			ret->u.list.elements[ret->u.list.num_elements] = subtree;
			ret->u.list.num_elements++;
		}
		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;

	case 2:
		/* 'not' operation */
		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) {
			goto failed;
		}

		ret->operation = LDB_OP_NOT;
		ret->u.isnot.child = ldap_decode_filter_tree(ret, data);
		if (ret->u.isnot.child == NULL) {
			goto failed;
		}
		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;

	case 3: {
		/* equalityMatch */
		const char *attrib;
		DATA_BLOB value;

		asn1_start_tag(data, ASN1_CONTEXT(filter_tag));
		asn1_read_OctetString_talloc(mem_ctx, data, &attrib);
		asn1_read_OctetString(data, &value);
		asn1_end_tag(data);
		if ((data->has_error) || (attrib == NULL) || (value.data == NULL)) {
			goto failed;
		}

		ret->operation = LDB_OP_SIMPLE;
		ret->u.simple.attr = talloc_steal(ret, attrib);
		ret->u.simple.value.data = talloc_steal(ret, value.data);
		ret->u.simple.value.length = value.length;
		break;
	}
	case 7: {
		/* Normal presence, "attribute=*" */
		char *attr;

		if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(filter_tag))) {
			goto failed;
		}
		if (!asn1_read_LDAPString(data, &attr)) {
			goto failed;
		}

		ret->operation = LDB_OP_SIMPLE;
		ret->u.simple.attr = talloc_steal(ret, attr);
		ret->u.simple.value.data = talloc_strdup(ret, "*");
		if (ret->u.simple.value.data == NULL) {
			goto failed;
		}
		ret->u.simple.value.length = 1;
		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;
	}
	case 9: {
		char *oid, *attr, *value;
		uint8_t dnAttributes;
		/* an extended search */
		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) {
			goto failed;
		}

		asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(1));
		asn1_read_LDAPString(data, &oid);
		asn1_end_tag(data);
		asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(2));
		asn1_read_LDAPString(data, &attr);
		asn1_end_tag(data);
		asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(3));
		asn1_read_LDAPString(data, &value);
		asn1_end_tag(data);
		asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(4));
		asn1_read_uint8(data, &dnAttributes);
		asn1_end_tag(data);
		if ((data->has_error) || (oid == NULL) || (value == NULL)) {
			goto failed;
		}

		ret->operation               = LDB_OP_EXTENDED;
		ret->u.extended.attr         = talloc_steal(ret, attr);
		ret->u.extended.rule_id      = talloc_steal(ret, oid);
		ret->u.extended.value.data   = talloc_steal(ret, value);
		ret->u.extended.value.length = strlen(value);
		ret->u.extended.dnAttributes = dnAttributes;

		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;
	}

	default:
		DEBUG(0,("Unsupported LDAP filter operation 0x%x\n", filter_tag));
		goto failed;
	}
	
	return ret;

failed:
	talloc_free(ret);
	return NULL;	
}


static void ldap_decode_attrib(TALLOC_CTX *mem_ctx, struct asn1_data *data,
			       struct ldb_message_element *attrib)
{
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_OctetString_talloc(mem_ctx, data, &attrib->name);
	asn1_start_tag(data, ASN1_SET);
	while (asn1_peek_tag(data, ASN1_OCTET_STRING)) {
		DATA_BLOB blob;
		asn1_read_OctetString(data, &blob);
		add_value_to_attrib(mem_ctx, &blob, attrib);
	}
	asn1_end_tag(data);
	asn1_end_tag(data);
	
}

static void ldap_decode_attribs(TALLOC_CTX *mem_ctx, struct asn1_data *data,
				struct ldb_message_element **attributes,
				int *num_attributes)
{
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	while (asn1_peek_tag(data, ASN1_SEQUENCE(0))) {
		struct ldb_message_element attrib;
		ZERO_STRUCT(attrib);
		ldap_decode_attrib(mem_ctx, data, &attrib);
		add_attrib_to_array_talloc(mem_ctx, &attrib,
					   attributes, num_attributes);
	}
	asn1_end_tag(data);
}

BOOL ldap_decode(struct asn1_data *data, struct ldap_message *msg)
{
	uint8_t tag;

	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_Integer(data, &msg->messageid);

	if (!asn1_peek_uint8(data, &tag))
		return False;

	switch(tag) {

	case ASN1_APPLICATION(LDAP_TAG_BindRequest): {
		struct ldap_BindRequest *r = &msg->r.BindRequest;
		msg->type = LDAP_TAG_BindRequest;
		asn1_start_tag(data, tag);
		asn1_read_Integer(data, &r->version);
		asn1_read_OctetString_talloc(msg, data, &r->dn);
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(0))) {
			int pwlen;
			r->creds.password = "";
			r->mechanism = LDAP_AUTH_MECH_SIMPLE;
			asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(0));
			pwlen = asn1_tag_remaining(data);
			if (pwlen != 0) {
				char *pw = talloc_size(msg, pwlen+1);
				asn1_read(data, pw, pwlen);
				pw[pwlen] = '\0';
				r->creds.password = pw;
			}
			asn1_end_tag(data);
		} else if (asn1_peek_tag(data, ASN1_CONTEXT(3))){
			asn1_start_tag(data, ASN1_CONTEXT(3));
			r->mechanism = LDAP_AUTH_MECH_SASL;
			asn1_read_OctetString_talloc(msg, data, &r->creds.SASL.mechanism);
			asn1_read_OctetString(data, &r->creds.SASL.secblob);
			if (r->creds.SASL.secblob.data) {
				talloc_steal(msg, r->creds.SASL.secblob.data);
			}
			asn1_end_tag(data);
		}
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_BindResponse): {
		struct ldap_BindResponse *r = &msg->r.BindResponse;
		msg->type = LDAP_TAG_BindResponse;
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, &r->response);
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(7))) {
			DATA_BLOB tmp_blob = data_blob(NULL, 0);
			asn1_read_ContextSimple(data, 7, &tmp_blob);
			r->SASL.secblob = data_blob_talloc(msg, tmp_blob.data, tmp_blob.length);
			data_blob_free(&tmp_blob);
		} else {
			r->SASL.secblob = data_blob(NULL, 0);
		}
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION_SIMPLE(LDAP_TAG_UnbindRequest): {
		msg->type = LDAP_TAG_UnbindRequest;
		asn1_start_tag(data, tag);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchRequest): {
		struct ldap_SearchRequest *r = &msg->r.SearchRequest;
		msg->type = LDAP_TAG_SearchRequest;
		asn1_start_tag(data, tag);
		asn1_read_OctetString_talloc(msg, data, &r->basedn);
		asn1_read_enumerated(data, (int *)&(r->scope));
		asn1_read_enumerated(data, (int *)&(r->deref));
		asn1_read_Integer(data, &r->sizelimit);
		asn1_read_Integer(data, &r->timelimit);
		asn1_read_BOOLEAN(data, &r->attributesonly);

		r->tree = ldap_decode_filter_tree(msg, data);
		if (r->tree == NULL) {
			return False;
		}

		asn1_start_tag(data, ASN1_SEQUENCE(0));

		r->num_attributes = 0;
		r->attributes = NULL;

		while (asn1_tag_remaining(data) > 0) {
			const char *attr;
			if (!asn1_read_OctetString_talloc(msg, data,
							  &attr))
				return False;
			if (!add_string_to_array(msg, attr,
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
		asn1_start_tag(data, tag);
		asn1_read_OctetString_talloc(msg, data, &r->dn);
		ldap_decode_attribs(msg, data, &r->attributes,
				    &r->num_attributes);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultDone): {
		struct ldap_Result *r = &msg->r.SearchResultDone;
		msg->type = LDAP_TAG_SearchResultDone;
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, r);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultReference): {
		struct ldap_SearchResRef *r = &msg->r.SearchResultReference;
		msg->type = LDAP_TAG_SearchResultReference;
		asn1_start_tag(data, tag);
		asn1_read_OctetString_talloc(msg, data, &r->referral);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyRequest): {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		msg->type = LDAP_TAG_ModifyRequest;
		asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_ModifyRequest));
		asn1_read_OctetString_talloc(msg, data, &r->dn);
		asn1_start_tag(data, ASN1_SEQUENCE(0));

		r->num_mods = 0;
		r->mods = NULL;

		while (asn1_tag_remaining(data) > 0) {
			struct ldap_mod mod;
			int v;
			ZERO_STRUCT(mod);
			asn1_start_tag(data, ASN1_SEQUENCE(0));
			asn1_read_enumerated(data, &v);
			mod.type = v;
			ldap_decode_attrib(msg, data, &mod.attrib);
			asn1_end_tag(data);
			if (!add_mod_to_array_talloc(msg, &mod,
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
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, r);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddRequest): {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		msg->type = LDAP_TAG_AddRequest;
		asn1_start_tag(data, tag);
		asn1_read_OctetString_talloc(msg, data, &r->dn);

		r->attributes = NULL;
		r->num_attributes = 0;
		ldap_decode_attribs(msg, data, &r->attributes,
				    &r->num_attributes);

		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddResponse): {
		struct ldap_Result *r = &msg->r.AddResponse;
		msg->type = LDAP_TAG_AddResponse;
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, r);
		asn1_end_tag(data);
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
		dn = talloc_size(msg, len+1);
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
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, r);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest): {
		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest;
		msg->type = LDAP_TAG_ModifyDNRequest;
		asn1_start_tag(data,
			       ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest));
		asn1_read_OctetString_talloc(msg, data, &r->dn);
		asn1_read_OctetString_talloc(msg, data, &r->newrdn);
		asn1_read_BOOLEAN(data, &r->deleteolddn);
		r->newsuperior = NULL;
		if (asn1_tag_remaining(data) > 0) {
			int len;
			char *newsup;
			asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(0));
			len = asn1_tag_remaining(data);
			newsup = talloc_size(msg, len+1);
			if (newsup == NULL)
				break;
			asn1_read(data, newsup, len);
			newsup[len] = '\0';
			r->newsuperior = newsup;
			asn1_end_tag(data);
		}
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyDNResponse): {
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		msg->type = LDAP_TAG_ModifyDNResponse;
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, r);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_CompareRequest): {
		struct ldap_CompareRequest *r = &msg->r.CompareRequest;
		msg->type = LDAP_TAG_CompareRequest;
		asn1_start_tag(data,
			       ASN1_APPLICATION(LDAP_TAG_CompareRequest));
		asn1_read_OctetString_talloc(msg, data, &r->dn);
		asn1_start_tag(data, ASN1_SEQUENCE(0));
		asn1_read_OctetString_talloc(msg, data, &r->attribute);
		asn1_read_OctetString(data, &r->value);
		if (r->value.data) {
			talloc_steal(msg, r->value.data);
		}
		asn1_end_tag(data);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_CompareResponse): {
		struct ldap_Result *r = &msg->r.CompareResponse;
		msg->type = LDAP_TAG_CompareResponse;
		asn1_start_tag(data, tag);
		ldap_decode_response(msg, data, r);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION_SIMPLE(LDAP_TAG_AbandonRequest): {
		struct ldap_AbandonRequest *r = &msg->r.AbandonRequest;
		msg->type = LDAP_TAG_AbandonRequest;
		asn1_start_tag(data, tag);
		asn1_read_implicit_Integer(data, &r->messageid);
		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ExtendedRequest): {
		struct ldap_ExtendedRequest *r = &msg->r.ExtendedRequest;
		DATA_BLOB tmp_blob = data_blob(NULL, 0);

		msg->type = LDAP_TAG_ExtendedRequest;
		asn1_start_tag(data,tag);
		if (!asn1_read_ContextSimple(data, 0, &tmp_blob)) {
			return False;
		}
		r->oid = blob2string_talloc(msg, tmp_blob);
		data_blob_free(&tmp_blob);
		if (!r->oid) {
			return False;
		}

		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(1))) {
			asn1_read_ContextSimple(data, 1, &tmp_blob);
			r->value = data_blob_talloc(msg, tmp_blob.data, tmp_blob.length);
			data_blob_free(&tmp_blob);
		} else {
			r->value = data_blob(NULL, 0);
		}

		asn1_end_tag(data);
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ExtendedResponse): {
		struct ldap_ExtendedResponse *r = &msg->r.ExtendedResponse;
		msg->type = LDAP_TAG_ExtendedResponse;
		asn1_start_tag(data, tag);		
		ldap_decode_response(msg, data, &r->response);
		/* I have to come across an operation that actually sends
		 * something back to really see what's going on. The currently
		 * needed pwdchange does not send anything back. */
		r->name = NULL;
		r->value.data = NULL;
		r->value.length = 0;
		asn1_end_tag(data);
		break;
	}
	default: 
		return False;
	}

	msg->num_controls = 0;
	msg->controls = NULL;

	if (asn1_peek_tag(data, ASN1_CONTEXT(0))) {
		int i;
		struct ldap_Control *ctrl = NULL;

		asn1_start_tag(data, ASN1_CONTEXT(0));

		for (i=0; asn1_peek_tag(data, ASN1_SEQUENCE(0)); i++) {
			asn1_start_tag(data, ASN1_SEQUENCE(0));

			ctrl = talloc_realloc(msg, ctrl, struct ldap_Control, i+1);
			if (!ctrl) {
				return False;
			}
			ctrl[i].oid = NULL;
			ctrl[i].critical = False;
			ctrl[i].value = data_blob(NULL, 0);

			asn1_read_OctetString_talloc(ctrl, data, &ctrl[i].oid);

			if (asn1_peek_tag(data, ASN1_BOOLEAN)) {
				asn1_read_BOOLEAN(data, &ctrl[i].critical);
			}

			if (asn1_peek_tag(data, ASN1_OCTET_STRING)) {
				asn1_read_OctetString(data, &ctrl[i].value);
				if (ctrl[i].value.data) {
					talloc_steal(msg, ctrl[i].value.data);
				}
			}

			asn1_end_tag(data);
		}
		msg->num_controls = i;
		msg->controls = ctrl;

		asn1_end_tag(data);
	}

	asn1_end_tag(data);
	return ((!data->has_error) && (data->nesting == NULL));
}


