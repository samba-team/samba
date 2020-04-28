/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
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
#include "../lib/util/asn1.h"
#include "../libcli/ldap/ldap_message.h"

_PUBLIC_ struct ldap_message *new_ldap_message(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct ldap_message);
}


static bool add_value_to_attrib(TALLOC_CTX *mem_ctx, struct ldb_val *value,
				struct ldb_message_element *attrib)
{
	attrib->values = talloc_realloc(mem_ctx,
					attrib->values,
					DATA_BLOB,
					attrib->num_values+1);
	if (attrib->values == NULL)
		return false;

	attrib->values[attrib->num_values].data = talloc_steal(attrib->values,
							       value->data);
	attrib->values[attrib->num_values].length = value->length;
	attrib->num_values += 1;
	return true;
}

static bool add_attrib_to_array_talloc(TALLOC_CTX *mem_ctx,
				       const struct ldb_message_element *attrib,
				       struct ldb_message_element **attribs,
				       int *num_attribs)
{
	*attribs = talloc_realloc(mem_ctx,
				  *attribs,
				  struct ldb_message_element,
				  *num_attribs+1);

	if (*attribs == NULL)
		return false;

	(*attribs)[*num_attribs] = *attrib;
	talloc_steal(*attribs, attrib->values);
	talloc_steal(*attribs, attrib->name);
	*num_attribs += 1;
	return true;
}

static bool add_mod_to_array_talloc(TALLOC_CTX *mem_ctx,
				    struct ldap_mod *mod,
				    struct ldap_mod **mods,
				    int *num_mods)
{
	*mods = talloc_realloc(mem_ctx, *mods, struct ldap_mod, (*num_mods)+1);

	if (*mods == NULL)
		return false;

	(*mods)[*num_mods] = *mod;
	*num_mods += 1;
	return true;
}

static bool ldap_decode_control_value(void *mem_ctx, DATA_BLOB value,
				      const struct ldap_control_handler *handlers,
				      struct ldb_control *ctrl)
{
	int i;

	if (!handlers) {
		return true;
	}

	for (i = 0; handlers[i].oid != NULL; i++) {
		if (strcmp(handlers[i].oid, ctrl->oid) == 0) {
			if (!handlers[i].decode || !handlers[i].decode(mem_ctx, value, &ctrl->data)) {
				return false;
			}
			break;
		}
	}
	if (handlers[i].oid == NULL) {
		return false;
	}

	return true;
}

static bool ldap_decode_control_wrapper(void *mem_ctx, struct asn1_data *data,
					struct ldb_control *ctrl, DATA_BLOB *value)
{
	DATA_BLOB oid;

	if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) {
		return false;
	}

	if (!asn1_read_OctetString(data, mem_ctx, &oid)) {
		return false;
	}
	ctrl->oid = talloc_strndup(mem_ctx, (char *)oid.data, oid.length);
	if (!ctrl->oid) {
		return false;
	}

	if (asn1_peek_tag(data, ASN1_BOOLEAN)) {
		bool critical;
		if (!asn1_read_BOOLEAN(data, &critical)) {
			return false;
		}
		ctrl->critical = critical;
	} else {
		ctrl->critical = false;
	}

	ctrl->data = NULL;

	if (!asn1_peek_tag(data, ASN1_OCTET_STRING)) {
		*value = data_blob(NULL, 0);
		goto end_tag;
	}

	if (!asn1_read_OctetString(data, mem_ctx, value)) {
		return false;
	}

end_tag:
	if (!asn1_end_tag(data)) {
		return false;
	}

	return true;
}

static bool ldap_encode_control(void *mem_ctx, struct asn1_data *data,
				const struct ldap_control_handler *handlers,
				struct ldb_control *ctrl)
{
	DATA_BLOB value;
	int i;

	if (!handlers) {
		return false;
	}

	for (i = 0; handlers[i].oid != NULL; i++) {
		if (!ctrl->oid) {
			/* not encoding this control, the OID has been
			 * set to NULL indicating it isn't really
			 * here */
			return true;
		}
		if (strcmp(handlers[i].oid, ctrl->oid) == 0) {
			if (!handlers[i].encode) {
				if (ctrl->critical) {
					return false;
				} else {
					/* not encoding this control */
					return true;
				}
			}
			if (!handlers[i].encode(mem_ctx, ctrl->data, &value)) {
				return false;
			}
			break;
		}
	}
	if (handlers[i].oid == NULL) {
		return false;
	}

	if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) {
		return false;
	}

	if (!asn1_write_OctetString(data, ctrl->oid, strlen(ctrl->oid))) {
		return false;
	}

	if (ctrl->critical) {
		if (!asn1_write_BOOLEAN(data, ctrl->critical)) {
			return false;
		}
	}

	if (!ctrl->data) {
		goto pop_tag;
	}

	if (!asn1_write_OctetString(data, value.data, value.length)) {
		return false;
	}

pop_tag:
	if (!asn1_pop_tag(data)) {
		return false;
	}

	return true;
}

static bool ldap_push_filter(struct asn1_data *data, struct ldb_parse_tree *tree)
{
	int i;

	switch (tree->operation) {
	case LDB_OP_AND:
	case LDB_OP_OR:
		if (!asn1_push_tag(data, ASN1_CONTEXT(tree->operation==LDB_OP_AND?0:1))) return false;
		for (i=0; i<tree->u.list.num_elements; i++) {
			if (!ldap_push_filter(data, tree->u.list.elements[i])) {
				return false;
			}
		}
		if (!asn1_pop_tag(data)) return false;
		break;

	case LDB_OP_NOT:
		if (!asn1_push_tag(data, ASN1_CONTEXT(2))) return false;
		if (!ldap_push_filter(data, tree->u.isnot.child)) {
			return false;
		}
		if (!asn1_pop_tag(data)) return false;
		break;

	case LDB_OP_EQUALITY:
		/* equality test */
		if (!asn1_push_tag(data, ASN1_CONTEXT(3))) return false;
		if (!asn1_write_OctetString(data, tree->u.equality.attr,
				      strlen(tree->u.equality.attr))) return false;
		if (!asn1_write_OctetString(data, tree->u.equality.value.data,
				      tree->u.equality.value.length)) return false;
		if (!asn1_pop_tag(data)) return false;
		break;

	case LDB_OP_SUBSTRING:
		/*
		  SubstringFilter ::= SEQUENCE {
			  type            AttributeDescription,
			  -- at least one must be present
			  substrings      SEQUENCE OF CHOICE {
				  initial [0] LDAPString,
				  any     [1] LDAPString,
				  final   [2] LDAPString } }
		*/
		if (!asn1_push_tag(data, ASN1_CONTEXT(4))) return false;
		if (!asn1_write_OctetString(data, tree->u.substring.attr, strlen(tree->u.substring.attr))) return false;
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) return false;

		if (tree->u.substring.chunks && tree->u.substring.chunks[0]) {
			i = 0;
			if (!tree->u.substring.start_with_wildcard) {
				if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(0))) return false;
				if (!asn1_write_DATA_BLOB_LDAPString(data, tree->u.substring.chunks[i])) return false;
				if (!asn1_pop_tag(data)) return false;
				i++;
			}
			while (tree->u.substring.chunks[i]) {
				int ctx;

				if (( ! tree->u.substring.chunks[i + 1]) &&
				    (tree->u.substring.end_with_wildcard == 0)) {
					ctx = 2;
				} else {
					ctx = 1;
				}
				if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(ctx))) return false;
				if (!asn1_write_DATA_BLOB_LDAPString(data, tree->u.substring.chunks[i])) return false;
				if (!asn1_pop_tag(data)) return false;
				i++;
			}
		}
		if (!asn1_pop_tag(data)) return false;
		if (!asn1_pop_tag(data)) return false;
		break;

	case LDB_OP_GREATER:
		/* greaterOrEqual test */
		if (!asn1_push_tag(data, ASN1_CONTEXT(5))) return false;
		if (!asn1_write_OctetString(data, tree->u.comparison.attr,
				      strlen(tree->u.comparison.attr))) return false;
		if (!asn1_write_OctetString(data, tree->u.comparison.value.data,
				      tree->u.comparison.value.length)) return false;
		if (!asn1_pop_tag(data)) return false;
		break;

	case LDB_OP_LESS:
		/* lessOrEqual test */
		if (!asn1_push_tag(data, ASN1_CONTEXT(6))) return false;
		if (!asn1_write_OctetString(data, tree->u.comparison.attr,
				      strlen(tree->u.comparison.attr))) return false;
		if (!asn1_write_OctetString(data, tree->u.comparison.value.data,
				      tree->u.comparison.value.length)) return false;
		if (!asn1_pop_tag(data)) return false;
		break;

	case LDB_OP_PRESENT:
		/* present test */
		if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(7))) return false;
		if (!asn1_write_LDAPString(data, tree->u.present.attr)) return false;
		if (!asn1_pop_tag(data)) return false;
		return !asn1_has_error(data);

	case LDB_OP_APPROX:
		/* approx test */
		if (!asn1_push_tag(data, ASN1_CONTEXT(8))) return false;
		if (!asn1_write_OctetString(data, tree->u.comparison.attr,
				      strlen(tree->u.comparison.attr))) return false;
		if (!asn1_write_OctetString(data, tree->u.comparison.value.data,
				      tree->u.comparison.value.length)) return false;
		if (!asn1_pop_tag(data)) return false;
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
		if (!asn1_push_tag(data, ASN1_CONTEXT(9))) return false;
		if (tree->u.extended.rule_id) {
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(1))) return false;
			if (!asn1_write_LDAPString(data, tree->u.extended.rule_id)) return false;
			if (!asn1_pop_tag(data)) return false;
		}
		if (tree->u.extended.attr) {
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(2))) return false;
			if (!asn1_write_LDAPString(data, tree->u.extended.attr)) return false;
			if (!asn1_pop_tag(data)) return false;
		}
		if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(3))) return false;
		if (!asn1_write_DATA_BLOB_LDAPString(data, &tree->u.extended.value)) return false;
		if (!asn1_pop_tag(data)) return false;
		if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(4))) return false;
		if (!asn1_write_uint8(data, tree->u.extended.dnAttributes)) return false;
		if (!asn1_pop_tag(data)) return false;
		if (!asn1_pop_tag(data)) return false;
		break;

	default:
		return false;
	}
	return !asn1_has_error(data);
}

static bool ldap_encode_response(struct asn1_data *data, struct ldap_Result *result)
{
	if (!asn1_write_enumerated(data, result->resultcode)) return false;
	if (!asn1_write_OctetString(data, result->dn,
			       (result->dn) ? strlen(result->dn) : 0)) return false;
	if (!asn1_write_OctetString(data, result->errormessage,
			       (result->errormessage) ?
			       strlen(result->errormessage) : 0)) return false;
	if (result->referral) {
		if (!asn1_push_tag(data, ASN1_CONTEXT(3))) return false;
		if (!asn1_write_OctetString(data, result->referral,
				       strlen(result->referral))) return false;
		if (!asn1_pop_tag(data)) return false;
	}
	return true;
}

_PUBLIC_ bool ldap_encode(struct ldap_message *msg,
			  const struct ldap_control_handler *control_handlers,
			  DATA_BLOB *result, TALLOC_CTX *mem_ctx)
{
	struct asn1_data *data = asn1_init(mem_ctx, ASN1_MAX_TREE_DEPTH);
	int i, j;

	if (!data) return false;

	if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
	if (!asn1_write_Integer(data, msg->messageid)) goto err;

	switch (msg->type) {
	case LDAP_TAG_BindRequest: {
		struct ldap_BindRequest *r = &msg->r.BindRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_Integer(data, r->version)) goto err;
		if (!asn1_write_OctetString(data, r->dn,
				       (r->dn != NULL) ? strlen(r->dn) : 0)) goto err;

		switch (r->mechanism) {
		case LDAP_AUTH_MECH_SIMPLE:
			/* context, primitive */
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(0))) goto err;
			if (!asn1_write(data, r->creds.password,
				   strlen(r->creds.password))) goto err;
			if (!asn1_pop_tag(data)) goto err;
			break;
		case LDAP_AUTH_MECH_SASL:
			/* context, constructed */
			if (!asn1_push_tag(data, ASN1_CONTEXT(3))) goto err;
			if (!asn1_write_OctetString(data, r->creds.SASL.mechanism,
					       strlen(r->creds.SASL.mechanism))) goto err;
			if (r->creds.SASL.secblob) {
				if (!asn1_write_OctetString(data, r->creds.SASL.secblob->data,
						       r->creds.SASL.secblob->length)) goto err;
			}
			if (!asn1_pop_tag(data)) goto err;
			break;
		default:
			goto err;
		}

		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_BindResponse: {
		struct ldap_BindResponse *r = &msg->r.BindResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, &r->response)) goto err;
		if (r->SASL.secblob) {
			if (!asn1_write_ContextSimple(data, 7, r->SASL.secblob)) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_UnbindRequest: {
/*		struct ldap_UnbindRequest *r = &msg->r.UnbindRequest; */
		if (!asn1_push_tag(data, ASN1_APPLICATION_SIMPLE(msg->type))) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_SearchRequest: {
		struct ldap_SearchRequest *r = &msg->r.SearchRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->basedn, strlen(r->basedn))) goto err;
		if (!asn1_write_enumerated(data, r->scope)) goto err;
		if (!asn1_write_enumerated(data, r->deref)) goto err;
		if (!asn1_write_Integer(data, r->sizelimit)) goto err;
		if (!asn1_write_Integer(data, r->timelimit)) goto err;
		if (!asn1_write_BOOLEAN(data, r->attributesonly)) goto err;

		if (!ldap_push_filter(data, r->tree)) {
			goto err;
		}

		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
		for (i=0; i<r->num_attributes; i++) {
			if (!asn1_write_OctetString(data, r->attributes[i],
					       strlen(r->attributes[i]))) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_SearchResultEntry: {
		struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->dn, strlen(r->dn))) goto err;
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
		for (i=0; i<r->num_attributes; i++) {
			struct ldb_message_element *attr = &r->attributes[i];
			if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
			if (!asn1_write_OctetString(data, attr->name,
					       strlen(attr->name))) goto err;
			if (!asn1_push_tag(data, ASN1_SEQUENCE(1))) goto err;
			for (j=0; j<attr->num_values; j++) {
				if (!asn1_write_OctetString(data,
						       attr->values[j].data,
						       attr->values[j].length)) goto err;
			}
			if (!asn1_pop_tag(data)) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_SearchResultDone: {
		struct ldap_Result *r = &msg->r.SearchResultDone;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, r)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_ModifyRequest: {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->dn, strlen(r->dn))) goto err;
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;

		for (i=0; i<r->num_mods; i++) {
			struct ldb_message_element *attrib = &r->mods[i].attrib;
			if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
			if (!asn1_write_enumerated(data, r->mods[i].type)) goto err;
			if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
			if (!asn1_write_OctetString(data, attrib->name,
					       strlen(attrib->name))) goto err;
			if (!asn1_push_tag(data, ASN1_SET)) goto err;
			for (j=0; j<attrib->num_values; j++) {
				if (!asn1_write_OctetString(data,
						       attrib->values[j].data,
						       attrib->values[j].length)) goto err;
	
			}
			if (!asn1_pop_tag(data)) goto err;
			if (!asn1_pop_tag(data)) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_ModifyResponse: {
		struct ldap_Result *r = &msg->r.ModifyResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, r)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_AddRequest: {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->dn, strlen(r->dn))) goto err;
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;

		for (i=0; i<r->num_attributes; i++) {
			struct ldb_message_element *attrib = &r->attributes[i];
			if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
			if (!asn1_write_OctetString(data, attrib->name,
					       strlen(attrib->name))) goto err;
			if (!asn1_push_tag(data, ASN1_SET)) goto err;
			for (j=0; j<r->attributes[i].num_values; j++) {
				if (!asn1_write_OctetString(data,
						       attrib->values[j].data,
						       attrib->values[j].length)) goto err;
			}
			if (!asn1_pop_tag(data)) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_AddResponse: {
		struct ldap_Result *r = &msg->r.AddResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, r)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_DelRequest: {
		struct ldap_DelRequest *r = &msg->r.DelRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION_SIMPLE(msg->type))) goto err;
		if (!asn1_write(data, r->dn, strlen(r->dn))) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_DelResponse: {
		struct ldap_Result *r = &msg->r.DelResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, r)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_ModifyDNRequest: {
		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->dn, strlen(r->dn))) goto err;
		if (!asn1_write_OctetString(data, r->newrdn, strlen(r->newrdn))) goto err;
		if (!asn1_write_BOOLEAN(data, r->deleteolddn)) goto err;
		if (r->newsuperior) {
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(0))) goto err;
			if (!asn1_write(data, r->newsuperior,
				   strlen(r->newsuperior))) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_ModifyDNResponse: {
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, r)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_CompareRequest: {
		struct ldap_CompareRequest *r = &msg->r.CompareRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->dn, strlen(r->dn))) goto err;
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
		if (!asn1_write_OctetString(data, r->attribute,
				       strlen(r->attribute))) goto err;
		if (!asn1_write_OctetString(data, r->value.data,
				       r->value.length)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_CompareResponse: {
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, r)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_AbandonRequest: {
		struct ldap_AbandonRequest *r = &msg->r.AbandonRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION_SIMPLE(msg->type))) goto err;
		if (!asn1_write_implicit_Integer(data, r->messageid)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_SearchResultReference: {
		struct ldap_SearchResRef *r = &msg->r.SearchResultReference;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_write_OctetString(data, r->referral, strlen(r->referral))) goto err;
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_ExtendedRequest: {
		struct ldap_ExtendedRequest *r = &msg->r.ExtendedRequest;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(0))) goto err;
		if (!asn1_write(data, r->oid, strlen(r->oid))) goto err;
		if (!asn1_pop_tag(data)) goto err;
		if (r->value) {
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(1))) goto err;
			if (!asn1_write(data, r->value->data, r->value->length)) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	case LDAP_TAG_ExtendedResponse: {
		struct ldap_ExtendedResponse *r = &msg->r.ExtendedResponse;
		if (!asn1_push_tag(data, ASN1_APPLICATION(msg->type))) goto err;
		if (!ldap_encode_response(data, &r->response)) goto err;
		if (r->oid) {
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(10))) goto err;
			if (!asn1_write(data, r->oid, strlen(r->oid))) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		if (r->value) {
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(11))) goto err;
			if (!asn1_write(data, r->value->data, r->value->length)) goto err;
			if (!asn1_pop_tag(data)) goto err;
		}
		if (!asn1_pop_tag(data)) goto err;
		break;
	}
	default:
		goto err;
	}

	if (msg->controls != NULL) {
		if (!asn1_push_tag(data, ASN1_CONTEXT(0))) goto err;
		
		for (i = 0; msg->controls[i] != NULL; i++) {
			if (!ldap_encode_control(mem_ctx, data,
						 control_handlers,
						 msg->controls[i])) {
				DEBUG(0,("Unable to encode control %s\n",
					 msg->controls[i]->oid));
				goto err;
			}
		}

		if (!asn1_pop_tag(data)) goto err;
	}

	if (!asn1_pop_tag(data)) goto err;

	if (!asn1_extract_blob(data, mem_ctx, result)) {
		goto err;
	}

	asn1_free(data);

	return true;

  err:

	asn1_free(data);
	return false;
}

static const char *blob2string_talloc(TALLOC_CTX *mem_ctx,
				      DATA_BLOB blob)
{
	char *result = talloc_array(mem_ctx, char, blob.length+1);
	if (result == NULL) {
		return NULL;
	}
	memcpy(result, blob.data, blob.length);
	result[blob.length] = '\0';
	return result;
}

bool asn1_read_OctetString_talloc(TALLOC_CTX *mem_ctx,
				  struct asn1_data *data,
				  const char **result)
{
	DATA_BLOB string;
	if (!asn1_read_OctetString(data, mem_ctx, &string))
		return false;
	*result = blob2string_talloc(mem_ctx, string);
	data_blob_free(&string);
	return *result ? true : false;
}

static bool ldap_decode_response(TALLOC_CTX *mem_ctx,
				 struct asn1_data *data,
				 struct ldap_Result *result)
{
	if (!asn1_read_enumerated(data, &result->resultcode)) return false;
	if (!asn1_read_OctetString_talloc(mem_ctx, data, &result->dn)) return false;
	if (!asn1_read_OctetString_talloc(mem_ctx, data, &result->errormessage)) return false;
	if (asn1_peek_tag(data, ASN1_CONTEXT(3))) {
		if (!asn1_start_tag(data, ASN1_CONTEXT(3))) return false;
		if (!asn1_read_OctetString_talloc(mem_ctx, data, &result->referral)) return false;
		if (!asn1_end_tag(data)) return false;
	} else {
		result->referral = NULL;
	}
	return true;
}

static struct ldb_val **ldap_decode_substring(TALLOC_CTX *mem_ctx, struct ldb_val **chunks, int chunk_num, char *value)
{

	chunks = talloc_realloc(mem_ctx, chunks, struct ldb_val *, chunk_num + 2);
	if (chunks == NULL) {
		return NULL;
	}

	chunks[chunk_num] = talloc(mem_ctx, struct ldb_val);
	if (chunks[chunk_num] == NULL) {
		return NULL;
	}

	chunks[chunk_num]->data = (uint8_t *)talloc_strdup(mem_ctx, value);
	if (chunks[chunk_num]->data == NULL) {
		return NULL;
	}
	chunks[chunk_num]->length = strlen(value);

	chunks[chunk_num + 1] = NULL;

	return chunks;
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

		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) goto failed;
		if (!asn1_read_OctetString_talloc(mem_ctx, data, &attrib)) goto failed;
		if (!asn1_read_OctetString(data, mem_ctx, &value)) goto failed;
		if (!asn1_end_tag(data)) goto failed;
		if (asn1_has_error(data) || (attrib == NULL) ||
		    (value.data == NULL)) {
			goto failed;
		}

		ret->operation = LDB_OP_EQUALITY;
		ret->u.equality.attr = talloc_steal(ret, attrib);
		ret->u.equality.value.data = talloc_steal(ret, value.data);
		ret->u.equality.value.length = value.length;
		break;
	}
	case 4: {
		/* substrings */
		DATA_BLOB attr;
		uint8_t subs_tag;
		char *value;
		int chunk_num = 0;

		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) {
			goto failed;
		}
		if (!asn1_read_OctetString(data, mem_ctx, &attr)) {
			goto failed;
		}

		ret->operation = LDB_OP_SUBSTRING;
		ret->u.substring.attr = talloc_strndup(ret, (char *)attr.data, attr.length);
		if (ret->u.substring.attr == NULL) {
			goto failed;
		}
		ret->u.substring.chunks = NULL;
		ret->u.substring.start_with_wildcard = 1;
		ret->u.substring.end_with_wildcard = 1;

		if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) {
			goto failed;
		}

		while (asn1_tag_remaining(data) > 0) {
			if (!asn1_peek_uint8(data, &subs_tag)) goto failed;
			subs_tag &= 0x1f;	/* strip off the asn1 stuff */
			if (subs_tag > 2) goto failed;

			if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(subs_tag))) goto failed;
			if (!asn1_read_LDAPString(data, mem_ctx, &value)) goto failed;
			if (!asn1_end_tag(data)) goto failed;

			switch (subs_tag) {
			case 0:
				if (ret->u.substring.chunks != NULL) {
					/* initial value found in the middle */
					goto failed;
				}

				ret->u.substring.chunks = ldap_decode_substring(ret, NULL, 0, value);
				if (ret->u.substring.chunks == NULL) {
					goto failed;
				}

				ret->u.substring.start_with_wildcard = 0;
				chunk_num = 1;
				break;

			case 1:
				if (ret->u.substring.end_with_wildcard == 0) {
					/* "any" value found after a "final" value */
					goto failed;
				}

				ret->u.substring.chunks = ldap_decode_substring(ret,
										ret->u.substring.chunks,
										chunk_num,
										value);
				if (ret->u.substring.chunks == NULL) {
					goto failed;
				}

				chunk_num++;
				break;

			case 2:
				ret->u.substring.chunks = ldap_decode_substring(ret,
										ret->u.substring.chunks,
										chunk_num,
										value);
				if (ret->u.substring.chunks == NULL) {
					goto failed;
				}

				ret->u.substring.end_with_wildcard = 0;
				break;

			default:
				goto failed;
			}

		}

		if (!asn1_end_tag(data)) { /* SEQUENCE */
			goto failed;
		}

		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;
	}
	case 5: {
		/* greaterOrEqual */
		const char *attrib;
		DATA_BLOB value;

		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) goto failed;
		if (!asn1_read_OctetString_talloc(mem_ctx, data, &attrib)) goto failed;
		if (!asn1_read_OctetString(data, mem_ctx, &value)) goto failed;
		if (!asn1_end_tag(data)) goto failed;
		if (asn1_has_error(data) || (attrib == NULL) ||
		    (value.data == NULL)) {
			goto failed;
		}

		ret->operation = LDB_OP_GREATER;
		ret->u.comparison.attr = talloc_steal(ret, attrib);
		ret->u.comparison.value.data = talloc_steal(ret, value.data);
		ret->u.comparison.value.length = value.length;
		break;
	}
	case 6: {
		/* lessOrEqual */
		const char *attrib;
		DATA_BLOB value;

		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) goto failed;
		if (!asn1_read_OctetString_talloc(mem_ctx, data, &attrib)) goto failed;
		if (!asn1_read_OctetString(data, mem_ctx, &value)) goto failed;
		if (!asn1_end_tag(data)) goto failed;
		if (asn1_has_error(data) || (attrib == NULL) ||
		    (value.data == NULL)) {
			goto failed;
		}

		ret->operation = LDB_OP_LESS;
		ret->u.comparison.attr = talloc_steal(ret, attrib);
		ret->u.comparison.value.data = talloc_steal(ret, value.data);
		ret->u.comparison.value.length = value.length;
		break;
	}
	case 7: {
		/* Normal presence, "attribute=*" */
		char *attr;

		if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(filter_tag))) {
			goto failed;
		}
		if (!asn1_read_LDAPString(data, ret, &attr)) {
			goto failed;
		}

		ret->operation = LDB_OP_PRESENT;
		ret->u.present.attr = talloc_steal(ret, attr);

		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;
	}
	case 8: {
		/* approx */
		const char *attrib;
		DATA_BLOB value;

		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) goto failed;
		if (!asn1_read_OctetString_talloc(mem_ctx, data, &attrib)) goto failed;
		if (!asn1_read_OctetString(data, mem_ctx, &value)) goto failed;
		if (!asn1_end_tag(data)) goto failed;
		if (asn1_has_error(data) || (attrib == NULL) ||
		    (value.data == NULL)) {
			goto failed;
		}

		ret->operation = LDB_OP_APPROX;
		ret->u.comparison.attr = talloc_steal(ret, attrib);
		ret->u.comparison.value.data = talloc_steal(ret, value.data);
		ret->u.comparison.value.length = value.length;
		break;
	}
	case 9: {
		char *oid = NULL, *attr = NULL, *value;
		uint8_t dnAttributes;
		/* an extended search */
		if (!asn1_start_tag(data, ASN1_CONTEXT(filter_tag))) {
			goto failed;
		}

		/* FIXME: read carefully rfc2251.txt there are a number of 'MUST's
		   we need to check we properly implement --SSS */ 
		/* either oid or type must be defined */
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(1))) { /* optional */
			if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(1))) goto failed;
			if (!asn1_read_LDAPString(data, ret, &oid)) goto failed;
			if (!asn1_end_tag(data)) goto failed;
		}
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(2))) {	/* optional  */
			if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(2))) goto failed;
			if (!asn1_read_LDAPString(data, ret, &attr)) goto failed;
			if (!asn1_end_tag(data)) goto failed;
		}
		if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(3))) goto failed;
		if (!asn1_read_LDAPString(data, ret, &value)) goto failed;
		if (!asn1_end_tag(data)) goto failed;
		/* dnAttributes is marked as BOOLEAN DEFAULT FALSE
		   it is not marked as OPTIONAL but openldap tools
		   do not set this unless it is to be set as TRUE
		   NOTE: openldap tools do not work with AD as it
		   seems that AD always requires the dnAttributes
		   boolean value to be set */
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(4))) {
			if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(4))) goto failed;
			if (!asn1_read_uint8(data, &dnAttributes)) goto failed;
			if (!asn1_end_tag(data)) goto failed;
		} else {
			dnAttributes = 0;
		}
		if ((oid == NULL && attr == NULL) || (value == NULL)) {
			goto failed;
		}

		if (oid) {
			ret->operation               = LDB_OP_EXTENDED;

			/* From the RFC2251: If the type field is
			   absent and matchingRule is present, the matchValue is compared
			   against all attributes in an entry which support that matchingRule
			*/
			if (attr) {
				ret->u.extended.attr = talloc_steal(ret, attr);
			} else {
				ret->u.extended.attr = talloc_strdup(ret, "*");
				if (ret->u.extended.attr == NULL) {
					goto failed;
				}
			}
			ret->u.extended.rule_id      = talloc_steal(ret, oid);
			ret->u.extended.value.data   = (uint8_t *)talloc_steal(ret, value);
			ret->u.extended.value.length = strlen(value);
			ret->u.extended.dnAttributes = dnAttributes;
		} else {
			ret->operation               = LDB_OP_EQUALITY;
			ret->u.equality.attr         = talloc_steal(ret, attr);
			ret->u.equality.value.data   = (uint8_t *)talloc_steal(ret, value);
			ret->u.equality.value.length = strlen(value);
		}
		if (!asn1_end_tag(data)) {
			goto failed;
		}
		break;
	}

	default:
		goto failed;
	}
	
	return ret;

failed:
	talloc_free(ret);
	return NULL;	
}

/* Decode a single LDAP attribute, possibly containing multiple values */
static bool ldap_decode_attrib(TALLOC_CTX *mem_ctx, struct asn1_data *data,
			       struct ldb_message_element *attrib)
{
	if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) return false;
	if (!asn1_read_OctetString_talloc(mem_ctx, data, &attrib->name)) return false;
	if (!asn1_start_tag(data, ASN1_SET)) return false;
	while (asn1_peek_tag(data, ASN1_OCTET_STRING)) {
		DATA_BLOB blob;
		if (!asn1_read_OctetString(data, mem_ctx, &blob)) return false;
		add_value_to_attrib(mem_ctx, &blob, attrib);
	}
	if (!asn1_end_tag(data)) return false;
	return asn1_end_tag(data);
}

/* Decode a set of LDAP attributes, as found in the dereference control */
bool ldap_decode_attribs_bare(TALLOC_CTX *mem_ctx, struct asn1_data *data,
			      struct ldb_message_element **attributes,
			      int *num_attributes)
{
	while (asn1_peek_tag(data, ASN1_SEQUENCE(0))) {
		struct ldb_message_element attrib;
		ZERO_STRUCT(attrib);
		if (!ldap_decode_attrib(mem_ctx, data, &attrib)) return false;
		add_attrib_to_array_talloc(mem_ctx, &attrib,
					   attributes, num_attributes);
	}
	return true;
}

/* Decode a set of LDAP attributes, as found in a search entry */
static bool ldap_decode_attribs(TALLOC_CTX *mem_ctx, struct asn1_data *data,
				struct ldb_message_element **attributes,
				int *num_attributes)
{
	if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) return false;
	if (!ldap_decode_attribs_bare(mem_ctx, data,
				 attributes, num_attributes)) return false;
	return asn1_end_tag(data);
}

/* This routine returns LDAP status codes */

_PUBLIC_ NTSTATUS ldap_decode(struct asn1_data *data,
			      const struct ldap_request_limits *limits,
			      const struct ldap_control_handler *control_handlers,
			      struct ldap_message *msg)
{
	uint8_t tag;

	if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto prot_err;
	if (!asn1_read_Integer(data, &msg->messageid)) goto prot_err;

	if (!asn1_peek_uint8(data, &tag)) goto prot_err;

	switch(tag) {

	case ASN1_APPLICATION(LDAP_TAG_BindRequest): {
		struct ldap_BindRequest *r = &msg->r.BindRequest;
		msg->type = LDAP_TAG_BindRequest;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_read_Integer(data, &r->version)) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->dn)) goto prot_err;
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(0))) {
			int pwlen;
			r->creds.password = "";
			r->mechanism = LDAP_AUTH_MECH_SIMPLE;
			if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(0))) goto prot_err;
			pwlen = asn1_tag_remaining(data);
			if (pwlen == -1) {
				goto prot_err;
			}
			if (pwlen != 0) {
				char *pw = talloc_array(msg, char, pwlen+1);
				if (!pw) {
					return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
				}
				if (!asn1_read(data, pw, pwlen)) goto prot_err;
				pw[pwlen] = '\0';
				r->creds.password = pw;
			}
			if (!asn1_end_tag(data)) goto prot_err;
		} else if (asn1_peek_tag(data, ASN1_CONTEXT(3))){
			if (!asn1_start_tag(data, ASN1_CONTEXT(3))) goto prot_err;
			r->mechanism = LDAP_AUTH_MECH_SASL;
			if (!asn1_read_OctetString_talloc(msg, data, &r->creds.SASL.mechanism)) goto prot_err;
			if (asn1_peek_tag(data, ASN1_OCTET_STRING)) { /* optional */
				DATA_BLOB tmp_blob = data_blob(NULL, 0);
				if (!asn1_read_OctetString(data, msg, &tmp_blob)) goto prot_err;
				r->creds.SASL.secblob = talloc(msg, DATA_BLOB);
				if (!r->creds.SASL.secblob) {
					return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
				}
				*r->creds.SASL.secblob = data_blob_talloc(r->creds.SASL.secblob,
									  tmp_blob.data, tmp_blob.length);
				data_blob_free(&tmp_blob);
			} else {
				r->creds.SASL.secblob = NULL;
			}
			if (!asn1_end_tag(data)) goto prot_err;
		} else {
			/* Neither Simple nor SASL bind */
			goto prot_err;
		}
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_BindResponse): {
		struct ldap_BindResponse *r = &msg->r.BindResponse;
		msg->type = LDAP_TAG_BindResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, &r->response)) goto prot_err;
		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(7))) {
			DATA_BLOB tmp_blob = data_blob(NULL, 0);
			if (!asn1_read_ContextSimple(data, msg, 7, &tmp_blob)) goto prot_err;
			r->SASL.secblob = talloc(msg, DATA_BLOB);
			if (!r->SASL.secblob) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}
			*r->SASL.secblob = data_blob_talloc(r->SASL.secblob,
							    tmp_blob.data, tmp_blob.length);
			data_blob_free(&tmp_blob);
		} else {
			r->SASL.secblob = NULL;
		}
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION_SIMPLE(LDAP_TAG_UnbindRequest): {
		msg->type = LDAP_TAG_UnbindRequest;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchRequest): {
		struct ldap_SearchRequest *r = &msg->r.SearchRequest;
		int sizelimit, timelimit;
		const char **attrs = NULL;
		size_t request_size = asn1_get_length(data);
		msg->type = LDAP_TAG_SearchRequest;
		if (request_size > limits->max_search_size) {
			goto prot_err;
		}
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->basedn)) goto prot_err;
		if (!asn1_read_enumerated(data, (int *)(void *)&(r->scope))) goto prot_err;
		if (!asn1_read_enumerated(data, (int *)(void *)&(r->deref))) goto prot_err;
		if (!asn1_read_Integer(data, &sizelimit)) goto prot_err;
		r->sizelimit = sizelimit;
		if (!asn1_read_Integer(data, &timelimit)) goto prot_err;
		r->timelimit = timelimit;
		if (!asn1_read_BOOLEAN(data, &r->attributesonly)) goto prot_err;

		r->tree = ldap_decode_filter_tree(msg, data);
		if (r->tree == NULL) {
			goto prot_err;
		}

		if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto prot_err;

		r->num_attributes = 0;
		r->attributes = NULL;

		while (asn1_tag_remaining(data) > 0) {

			const char *attr;
			if (!asn1_read_OctetString_talloc(msg, data,
							  &attr))
				goto prot_err;
			if (!add_string_to_array(msg, attr,
						 &attrs,
						 &r->num_attributes))
				goto prot_err;
		}
		r->attributes = attrs;

		if (!asn1_end_tag(data)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultEntry): {
		struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;
		msg->type = LDAP_TAG_SearchResultEntry;
		r->attributes = NULL;
		r->num_attributes = 0;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->dn)) goto prot_err;
		if (!ldap_decode_attribs(msg, data, &r->attributes,
				    &r->num_attributes)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultDone): {
		struct ldap_Result *r = &msg->r.SearchResultDone;
		msg->type = LDAP_TAG_SearchResultDone;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, r)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_SearchResultReference): {
		struct ldap_SearchResRef *r = &msg->r.SearchResultReference;
		msg->type = LDAP_TAG_SearchResultReference;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->referral)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyRequest): {
		struct ldap_ModifyRequest *r = &msg->r.ModifyRequest;
		msg->type = LDAP_TAG_ModifyRequest;
		if (!asn1_start_tag(data, ASN1_APPLICATION(LDAP_TAG_ModifyRequest))) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->dn)) goto prot_err;
		if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto prot_err;

		r->num_mods = 0;
		r->mods = NULL;

		while (asn1_tag_remaining(data) > 0) {
			struct ldap_mod mod;
			int v;
			ZERO_STRUCT(mod);
			if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto prot_err;
			if (!asn1_read_enumerated(data, &v)) goto prot_err;
			mod.type = v;
			if (!ldap_decode_attrib(msg, data, &mod.attrib)) goto prot_err;
			if (!asn1_end_tag(data)) goto prot_err;
			if (!add_mod_to_array_talloc(msg, &mod,
						     &r->mods, &r->num_mods)) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}
		}

		if (!asn1_end_tag(data)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyResponse): {
		struct ldap_Result *r = &msg->r.ModifyResponse;
		msg->type = LDAP_TAG_ModifyResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, r)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddRequest): {
		struct ldap_AddRequest *r = &msg->r.AddRequest;
		msg->type = LDAP_TAG_AddRequest;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->dn)) goto prot_err;

		r->attributes = NULL;
		r->num_attributes = 0;
		if (!ldap_decode_attribs(msg, data, &r->attributes,
				    &r->num_attributes)) goto prot_err;

		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_AddResponse): {
		struct ldap_Result *r = &msg->r.AddResponse;
		msg->type = LDAP_TAG_AddResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, r)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION_SIMPLE(LDAP_TAG_DelRequest): {
		struct ldap_DelRequest *r = &msg->r.DelRequest;
		int len;
		char *dn;
		msg->type = LDAP_TAG_DelRequest;
		if (!asn1_start_tag(data,
			       ASN1_APPLICATION_SIMPLE(LDAP_TAG_DelRequest))) goto prot_err;
		len = asn1_tag_remaining(data);
		if (len == -1) {
			goto prot_err;
		}
		dn = talloc_array(msg, char, len+1);
		if (dn == NULL)
			break;
		if (!asn1_read(data, dn, len)) goto prot_err;
		dn[len] = '\0';
		r->dn = dn;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_DelResponse): {
		struct ldap_Result *r = &msg->r.DelResponse;
		msg->type = LDAP_TAG_DelResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, r)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest): {
		struct ldap_ModifyDNRequest *r = &msg->r.ModifyDNRequest;
		msg->type = LDAP_TAG_ModifyDNRequest;
		if (!asn1_start_tag(data,
			       ASN1_APPLICATION(LDAP_TAG_ModifyDNRequest))) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->dn)) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->newrdn)) goto prot_err;
		if (!asn1_read_BOOLEAN(data, &r->deleteolddn)) goto prot_err;
		r->newsuperior = NULL;
		if (asn1_tag_remaining(data) > 0) {
			int len;
			char *newsup;
			if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(0))) goto prot_err;
			len = asn1_tag_remaining(data);
			if (len == -1) {
				goto prot_err;
			}
			newsup = talloc_array(msg, char, len+1);
			if (newsup == NULL) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}
			if (!asn1_read(data, newsup, len)) goto prot_err;
			newsup[len] = '\0';
			r->newsuperior = newsup;
			if (!asn1_end_tag(data)) goto prot_err;
		}
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ModifyDNResponse): {
		struct ldap_Result *r = &msg->r.ModifyDNResponse;
		msg->type = LDAP_TAG_ModifyDNResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, r)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_CompareRequest): {
		struct ldap_CompareRequest *r = &msg->r.CompareRequest;
		msg->type = LDAP_TAG_CompareRequest;
		if (!asn1_start_tag(data,
			       ASN1_APPLICATION(LDAP_TAG_CompareRequest))) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->dn)) goto prot_err;
		if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto prot_err;
		if (!asn1_read_OctetString_talloc(msg, data, &r->attribute)) goto prot_err;
		if (!asn1_read_OctetString(data, msg, &r->value)) goto prot_err;
		if (r->value.data) {
			talloc_steal(msg, r->value.data);
		}
		if (!asn1_end_tag(data)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_CompareResponse): {
		struct ldap_Result *r = &msg->r.CompareResponse;
		msg->type = LDAP_TAG_CompareResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, r)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION_SIMPLE(LDAP_TAG_AbandonRequest): {
		struct ldap_AbandonRequest *r = &msg->r.AbandonRequest;
		msg->type = LDAP_TAG_AbandonRequest;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!asn1_read_implicit_Integer(data, &r->messageid)) goto prot_err;
		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ExtendedRequest): {
		struct ldap_ExtendedRequest *r = &msg->r.ExtendedRequest;
		DATA_BLOB tmp_blob = data_blob(NULL, 0);

		msg->type = LDAP_TAG_ExtendedRequest;
		if (!asn1_start_tag(data,tag)) goto prot_err;
		if (!asn1_read_ContextSimple(data, msg, 0, &tmp_blob)) {
			goto prot_err;
		}
		r->oid = blob2string_talloc(msg, tmp_blob);
		data_blob_free(&tmp_blob);
		if (!r->oid) {
			return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
		}

		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(1))) {
			if (!asn1_read_ContextSimple(data, msg, 1, &tmp_blob)) goto prot_err;
			r->value = talloc(msg, DATA_BLOB);
			if (!r->value) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}
			*r->value = data_blob_talloc(r->value, tmp_blob.data, tmp_blob.length);
			data_blob_free(&tmp_blob);
		} else {
			r->value = NULL;
		}

		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}

	case ASN1_APPLICATION(LDAP_TAG_ExtendedResponse): {
		struct ldap_ExtendedResponse *r = &msg->r.ExtendedResponse;
		DATA_BLOB tmp_blob = data_blob(NULL, 0);

		msg->type = LDAP_TAG_ExtendedResponse;
		if (!asn1_start_tag(data, tag)) goto prot_err;
		if (!ldap_decode_response(msg, data, &r->response)) goto prot_err;

		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(10))) {
			if (!asn1_read_ContextSimple(data, msg, 1, &tmp_blob)) goto prot_err;
			r->oid = blob2string_talloc(msg, tmp_blob);
			data_blob_free(&tmp_blob);
			if (!r->oid) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}
		} else {
			r->oid = NULL;
		}

		if (asn1_peek_tag(data, ASN1_CONTEXT_SIMPLE(11))) {
			if (!asn1_read_ContextSimple(data, msg, 1, &tmp_blob)) goto prot_err;
			r->value = talloc(msg, DATA_BLOB);
			if (!r->value) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}
			*r->value = data_blob_talloc(r->value, tmp_blob.data, tmp_blob.length);
			data_blob_free(&tmp_blob);
		} else {
			r->value = NULL;
		}

		if (!asn1_end_tag(data)) goto prot_err;
		break;
	}
	default:
		goto prot_err;
	}

	msg->controls = NULL;
	msg->controls_decoded = NULL;

	if (asn1_peek_tag(data, ASN1_CONTEXT(0))) {
		int i = 0;
		struct ldb_control **ctrl = NULL;
		bool *decoded = NULL;

		if (!asn1_start_tag(data, ASN1_CONTEXT(0))) goto prot_err;

		while (asn1_peek_tag(data, ASN1_SEQUENCE(0))) {
			DATA_BLOB value;
			/* asn1_start_tag(data, ASN1_SEQUENCE(0)); */

			ctrl = talloc_realloc(msg, ctrl, struct ldb_control *, i+2);
			if (!ctrl) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}

			decoded = talloc_realloc(msg, decoded, bool, i+1);
			if (!decoded) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}

			ctrl[i] = talloc(ctrl, struct ldb_control);
			if (!ctrl[i]) {
				return NT_STATUS_LDAP(LDAP_OPERATIONS_ERROR);
			}

			if (!ldap_decode_control_wrapper(ctrl[i], data, ctrl[i], &value)) {
				goto prot_err;
			}

			if (!ldap_decode_control_value(ctrl[i], value,
						       control_handlers,
						       ctrl[i])) {
				if (ctrl[i]->critical) {
					ctrl[i]->data = NULL;
					decoded[i] = false;
					i++;
				} else {
					talloc_free(ctrl[i]);
					ctrl[i] = NULL;
				}
			} else {
				decoded[i] = true;
				i++;
			}
		}

		if (ctrl != NULL) {
			ctrl[i] = NULL;
		}

		msg->controls = ctrl;
		msg->controls_decoded = decoded;

		if (!asn1_end_tag(data)) goto prot_err;
	}

	if (!asn1_end_tag(data)) goto prot_err;
	if (asn1_has_error(data) || asn1_has_nesting(data)) {
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}
	return NT_STATUS_OK;

  prot_err:

	return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
}


/*
  return NT_STATUS_OK if a blob has enough bytes in it to be a full
  ldap packet. Set packet_size if true.
*/
NTSTATUS ldap_full_packet(void *private_data, DATA_BLOB blob, size_t *packet_size)
{
	int ret;

	if (blob.length < 6) {
		/*
		 * We need at least 6 bytes to workout the length
		 * of the pdu.
		 */
		return STATUS_MORE_ENTRIES;
	}

	ret = asn1_peek_full_tag(blob, ASN1_SEQUENCE(0), packet_size);
	if (ret != 0) {
		return map_nt_error_from_unix_common(ret);
	}
	return NT_STATUS_OK;
}
