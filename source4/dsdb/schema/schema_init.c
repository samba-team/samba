/* 
   Unix SMB/CIFS mplementation.
   DSDB schema header
   
   Copyright (C) Stefan Metzmacher 2006
    
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
#include "dsdb/samdb/samdb.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"

WERROR dsdb_load_oid_mappings(struct dsdb_schema *schema, const struct drsuapi_DsReplicaOIDMapping_Ctr *ctr)
{
	uint32_t i,j;

	schema->prefixes = talloc_array(schema, struct dsdb_schema_oid_prefix, ctr->num_mappings);
	W_ERROR_HAVE_NO_MEMORY(schema->prefixes);

	for (i=0, j=0; i < ctr->num_mappings; i++) {
		if (ctr->mappings[i].oid.oid == NULL) {
			return WERR_INVALID_PARAM;
		}

		if (strncasecmp(ctr->mappings[i].oid.oid, "ff", 2) == 0) {
			if (ctr->mappings[i].id_prefix != 0) {
				return WERR_INVALID_PARAM;
			}

			/* the magic value should be in the last array member */
			if (i != (ctr->num_mappings - 1)) {
				return WERR_INVALID_PARAM;
			}

			if (ctr->mappings[i].oid.__ndr_size != 21) {
				return WERR_INVALID_PARAM;
			}

			schema->schema_info = talloc_strdup(schema, ctr->mappings[i].oid.oid);
			W_ERROR_HAVE_NO_MEMORY(schema->schema_info);
		} else {
			/* the last array member should contain the magic value not a oid */
			if (i == (ctr->num_mappings - 1)) {
				return WERR_INVALID_PARAM;
			}

			schema->prefixes[j].id	= ctr->mappings[i].id_prefix<<16;
			schema->prefixes[j].oid	= talloc_asprintf(schema->prefixes, "%s.",
								  ctr->mappings[i].oid.oid);
			W_ERROR_HAVE_NO_MEMORY(schema->prefixes[j].oid);
			schema->prefixes[j].oid_len = strlen(schema->prefixes[j].oid);
			j++;
		}
	}

	schema->num_prefixes = j;
	return WERR_OK;
}

WERROR dsdb_verify_oid_mappings(const struct dsdb_schema *schema, const struct drsuapi_DsReplicaOIDMapping_Ctr *ctr)
{
	uint32_t i,j;

	for (i=0; i < ctr->num_mappings; i++) {
		if (ctr->mappings[i].oid.oid == NULL) {
			return WERR_INVALID_PARAM;
		}

		if (strncasecmp(ctr->mappings[i].oid.oid, "ff", 2) == 0) {
			if (ctr->mappings[i].id_prefix != 0) {
				return WERR_INVALID_PARAM;
			}

			/* the magic value should be in the last array member */
			if (i != (ctr->num_mappings - 1)) {
				return WERR_INVALID_PARAM;
			}

			if (ctr->mappings[i].oid.__ndr_size != 21) {
				return WERR_INVALID_PARAM;
			}

			if (strcasecmp(schema->schema_info, ctr->mappings[i].oid.oid) != 0) {
				return WERR_DS_DRA_SCHEMA_MISMATCH;
			}
		} else {
			/* the last array member should contain the magic value not a oid */
			if (i == (ctr->num_mappings - 1)) {
				return WERR_INVALID_PARAM;
			}

			for (j=0; j < schema->num_prefixes; j++) {
				size_t oid_len;
				if (schema->prefixes[j].id != (ctr->mappings[i].id_prefix<<16)) {
					continue;
				}

				oid_len = strlen(ctr->mappings[i].oid.oid);

				if (oid_len != (schema->prefixes[j].oid_len - 1)) {
					return WERR_DS_DRA_SCHEMA_MISMATCH;
				}

				if (strncmp(ctr->mappings[i].oid.oid, schema->prefixes[j].oid, oid_len) != 0) {
					return WERR_DS_DRA_SCHEMA_MISMATCH;				
				}

				break;
			}

			if (j == schema->num_prefixes) {
				return WERR_DS_DRA_SCHEMA_MISMATCH;				
			}
		}
	}

	return WERR_OK;
}

WERROR dsdb_map_oid2int(const struct dsdb_schema *schema, const char *in, uint32_t *out)
{
	uint32_t i;

	for (i=0; i < schema->num_prefixes; i++) {
		const char *val_str;
		char *end_str;
		unsigned val;

		if (strncmp(schema->prefixes[i].oid, in, schema->prefixes[i].oid_len) != 0) {
			continue;
		}

		val_str = in + schema->prefixes[i].oid_len;
		end_str = NULL;
		errno = 0;

		if (val_str[0] == '\0') {
			return WERR_INVALID_PARAM;
		}

		/* two '.' chars are invalid */
		if (val_str[0] == '.') {
			return WERR_INVALID_PARAM;
		}

		val = strtoul(val_str, &end_str, 10);
		if (end_str[0] == '.' && end_str[1] != '\0') {
			/*
			 * if it's a '.' and not the last char
			 * then maybe an other mapping apply
			 */
			continue;
		} else if (end_str[0] != '\0') {
			return WERR_INVALID_PARAM;
		} else if (val > 0xFFFF) {
			return WERR_INVALID_PARAM;
		}

		*out = schema->prefixes[i].id | val;
		return WERR_OK;
	}

	return WERR_DS_NO_MSDS_INTID;
}

WERROR dsdb_map_int2oid(const struct dsdb_schema *schema, uint32_t in, TALLOC_CTX *mem_ctx, const char **out)
{
	uint32_t i;

	for (i=0; i < schema->num_prefixes; i++) {
		const char *val;
		if (schema->prefixes[i].id != (in & 0xFFFF0000)) {
			continue;
		}

		val = talloc_asprintf(mem_ctx, "%s%u",
				      schema->prefixes[i].oid,
				      in & 0xFFFF);
		W_ERROR_HAVE_NO_MEMORY(val);

		*out = val;
		return WERR_OK;
	}

	return WERR_DS_NO_MSDS_INTID;
}

#define GET_STRING_LDB(msg, attr, mem_ctx, p, elem, strict) do { \
	(p)->elem = samdb_result_string(msg, attr, NULL);\
	if (strict && (p)->elem == NULL) { \
		d_printf("%s: %s == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	talloc_steal(mem_ctx, (p)->elem); \
} while (0)

#define GET_BOOL_LDB(msg, attr, p, elem, strict) do { \
	const char *str; \
	str = samdb_result_string(msg, attr, NULL);\
	if (str == NULL) { \
		if (strict) { \
			d_printf("%s: %s == NULL\n", __location__, attr); \
			return WERR_INVALID_PARAM; \
		} else { \
			(p)->elem = False; \
		} \
	} else if (strcasecmp("TRUE", str) == 0) { \
		(p)->elem = True; \
	} else if (strcasecmp("FALSE", str) == 0) { \
		(p)->elem = False; \
	} else { \
		d_printf("%s: %s == %s\n", __location__, attr, str); \
		return WERR_INVALID_PARAM; \
	} \
} while (0)

#define GET_UINT32_LDB(msg, attr, p, elem) do { \
	(p)->elem = samdb_result_uint(msg, attr, 0);\
} while (0)

#define GET_GUID_LDB(msg, attr, p, elem) do { \
	(p)->elem = samdb_result_guid(msg, attr);\
} while (0)

#define GET_BLOB_LDB(msg, attr, mem_ctx, p, elem) do { \
	const struct ldb_val *_val;\
	_val = ldb_msg_find_ldb_val(msg, attr);\
	if (_val) {\
		(p)->elem = *_val;\
		talloc_steal(mem_ctx, (p)->elem.data);\
	} else {\
		ZERO_STRUCT((p)->elem);\
	}\
} while (0)

WERROR dsdb_attribute_from_ldb(struct ldb_message *msg, TALLOC_CTX *mem_ctx, struct dsdb_attribute *attr)
{
	GET_STRING_LDB(msg, "cn", mem_ctx, attr, cn, True);
	GET_STRING_LDB(msg, "lDAPDisplayName", mem_ctx, attr, lDAPDisplayName, True);
	GET_STRING_LDB(msg, "attributeID", mem_ctx, attr, attributeID_oid, True);
	/* set an invalid value */
	attr->attributeID_id = 0xFFFFFFFF;
	GET_GUID_LDB(msg, "schemaIDGUID", attr, schemaIDGUID);
	GET_UINT32_LDB(msg, "mAPIID", attr, mAPIID);

	GET_GUID_LDB(msg, "attributeSecurityGUID", attr, attributeSecurityGUID);

	GET_UINT32_LDB(msg, "searchFlags", attr, searchFlags);
	GET_UINT32_LDB(msg, "systemFlags", attr, systemFlags);
	GET_BOOL_LDB(msg, "isMemberOfPartialAttributeSet", attr, isMemberOfPartialAttributeSet, False);
	GET_UINT32_LDB(msg, "linkID", attr, linkID);

	GET_STRING_LDB(msg, "attributeSyntax", mem_ctx, attr, attributeSyntax_oid, True);
	/* set an invalid value */
	attr->attributeSyntax_id = 0xFFFFFFFF;
	GET_UINT32_LDB(msg, "oMSyntax", attr, oMSyntax);
	GET_BLOB_LDB(msg, "oMObjectClass", mem_ctx, attr, oMObjectClass);

	GET_BOOL_LDB(msg, "isSingleValued", attr, isSingleValued, True);
	GET_UINT32_LDB(msg, "rangeLower", attr, rangeLower);
	GET_UINT32_LDB(msg, "rangeUpper", attr, rangeUpper);
	GET_BOOL_LDB(msg, "extendedCharsAllowed", attr, extendedCharsAllowed, False);

	GET_UINT32_LDB(msg, "schemaFlagsEx", attr, schemaFlagsEx);
	GET_BLOB_LDB(msg, "msDs-Schema-Extensions", mem_ctx, attr, msDs_Schema_Extensions);

	GET_BOOL_LDB(msg, "showInAdvancedViewOnly", attr, showInAdvancedViewOnly, False);
	GET_STRING_LDB(msg, "adminDisplayName", mem_ctx, attr, adminDisplayName, False);
	GET_STRING_LDB(msg, "adminDescription", mem_ctx, attr, adminDescription, False);
	GET_STRING_LDB(msg, "classDisplayName", mem_ctx, attr, classDisplayName, False);
	GET_BOOL_LDB(msg, "isEphemeral", attr, isEphemeral, False);
	GET_BOOL_LDB(msg, "isDefunct", attr, isDefunct, False);
	GET_BOOL_LDB(msg, "systemOnly", attr, systemOnly, False);

	attr->syntax = dsdb_syntax_for_attribute(attr);
	if (!attr->syntax) {
		return WERR_DS_ATT_SCHEMA_REQ_SYNTAX;
	}

	return WERR_OK;
}

WERROR dsdb_class_from_ldb(struct ldb_message *msg, TALLOC_CTX *mem_ctx, struct dsdb_class *obj)
{
	GET_STRING_LDB(msg, "cn", mem_ctx, obj, cn, True);
	GET_STRING_LDB(msg, "lDAPDisplayName", mem_ctx, obj, lDAPDisplayName, True);
	GET_STRING_LDB(msg, "governsID", mem_ctx, obj, governsID_oid, True);
	/* set an invalid value */
	obj->governsID_id = 0xFFFFFFFF;
	GET_GUID_LDB(msg, "schemaIDGUID", obj, schemaIDGUID);

	GET_UINT32_LDB(msg, "objectClassCategory", obj, objectClassCategory);
	GET_STRING_LDB(msg, "rDNAttID", mem_ctx, obj, rDNAttID, False);
	GET_STRING_LDB(msg, "defaultObjectCategory", mem_ctx, obj, defaultObjectCategory, True);
 
	GET_STRING_LDB(msg, "subClassOf", mem_ctx, obj, subClassOf, True);

	obj->systemAuxiliaryClass	= NULL;
	obj->systemPossSuperiors	= NULL;
	obj->systemMustContain		= NULL;
	obj->systemMayContain		= NULL;

	obj->auxiliaryClass		= NULL;
	obj->possSuperiors		= NULL;
	obj->mustContain		= NULL;
	obj->mayContain			= NULL;

	GET_STRING_LDB(msg, "defaultSecurityDescriptor", mem_ctx, obj, defaultSecurityDescriptor, False);

	GET_UINT32_LDB(msg, "schemaFlagsEx", obj, schemaFlagsEx);
	GET_BLOB_LDB(msg, "msDs-Schema-Extensions", mem_ctx, obj, msDs_Schema_Extensions);

	GET_BOOL_LDB(msg, "showInAdvancedViewOnly", obj, showInAdvancedViewOnly, False);
	GET_STRING_LDB(msg, "adminDisplayName", mem_ctx, obj, adminDisplayName, False);
	GET_STRING_LDB(msg, "adminDescription", mem_ctx, obj, adminDescription, False);
	GET_STRING_LDB(msg, "classDisplayName", mem_ctx, obj, classDisplayName, False);
	GET_BOOL_LDB(msg, "defaultHidingValue", obj, defaultHidingValue, False);
	GET_BOOL_LDB(msg, "isDefunct", obj, isDefunct, False);
	GET_BOOL_LDB(msg, "systemOnly", obj, systemOnly, False);

	return WERR_OK;
}

static const struct {
	const char *name;
	const char *oid;
} name_mappings[] = {
	{ "cn",					"2.5.4.3" },
	{ "name",				"1.2.840.113556.1.4.1" },
	{ "lDAPDisplayName",			"1.2.840.113556.1.2.460" },
	{ "attributeID", 			"1.2.840.113556.1.2.30" },
	{ "schemaIDGUID", 			"1.2.840.113556.1.4.148" },
	{ "mAPIID", 				"1.2.840.113556.1.2.49" },
	{ "attributeSecurityGUID", 		"1.2.840.113556.1.4.149" },
	{ "searchFlags", 			"1.2.840.113556.1.2.334" },
	{ "systemFlags", 			"1.2.840.113556.1.4.375" },
	{ "isMemberOfPartialAttributeSet", 	"1.2.840.113556.1.4.639" },
	{ "linkID", 				"1.2.840.113556.1.2.50" },
	{ "attributeSyntax", 			"1.2.840.113556.1.2.32" },
	{ "oMSyntax", 				"1.2.840.113556.1.2.231" },
	{ "oMObjectClass", 			"1.2.840.113556.1.2.218" },
	{ "isSingleValued",			"1.2.840.113556.1.2.33" },
	{ "rangeLower", 			"1.2.840.113556.1.2.34" },
	{ "rangeUpper", 			"1.2.840.113556.1.2.35" },
	{ "extendedCharsAllowed", 		"1.2.840.113556.1.2.380" },
	{ "schemaFlagsEx", 			"1.2.840.113556.1.4.120" },
	{ "msDs-Schema-Extensions", 		"1.2.840.113556.1.4.1440" },
	{ "showInAdvancedViewOnly", 		"1.2.840.113556.1.2.169" },
	{ "adminDisplayName", 			"1.2.840.113556.1.2.194" },
	{ "adminDescription", 			"1.2.840.113556.1.2.226" },
	{ "classDisplayName", 			"1.2.840.113556.1.4.610" },
	{ "isEphemeral", 			"1.2.840.113556.1.4.1212" },
	{ "isDefunct", 				"1.2.840.113556.1.4.661" },
	{ "systemOnly", 			"1.2.840.113556.1.4.170" },
	{ "governsID",				"1.2.840.113556.1.2.22" },
	{ "objectClassCategory",		"1.2.840.113556.1.2.370" },
	{ "rDNAttID",				"1.2.840.113556.1.2.26" },
	{ "defaultObjectCategory",		"1.2.840.113556.1.4.783" },
	{ "subClassOf",				"1.2.840.113556.1.2.21" },
	{ "systemAuxiliaryClass",		"1.2.840.113556.1.4.198" },
	{ "systemPossSuperiors",		"1.2.840.113556.1.4.195" },
	{ "systemMustContain",			"1.2.840.113556.1.4.197" },
	{ "systemMayContain",			"1.2.840.113556.1.4.196" },
	{ "auxiliaryClass",			"1.2.840.113556.1.2.351" },
	{ "possSuperiors",			"1.2.840.113556.1.2.8" },
	{ "mustContain",			"1.2.840.113556.1.2.24" },
	{ "mayContain",				"1.2.840.113556.1.2.25" },
	{ "defaultSecurityDescriptor",		"1.2.840.113556.1.4.224" },
	{ "defaultHidingValue",			"1.2.840.113556.1.4.518" },
};

static struct drsuapi_DsReplicaAttribute *dsdb_find_object_attr_name(struct dsdb_schema *schema,
								     struct drsuapi_DsReplicaObject *obj,
								     const char *name,
								     uint32_t *idx)
{
	WERROR status;
	uint32_t i, id;
	const char *oid = NULL;

	for(i=0; i < ARRAY_SIZE(name_mappings); i++) {
		if (strcmp(name_mappings[i].name, name) != 0) continue;

		oid = name_mappings[i].oid;
		break;
	}

	if (!oid) {
		return NULL;
	}

	status = dsdb_map_oid2int(schema, oid, &id);
	if (!W_ERROR_IS_OK(status)) {
		return NULL;
	}

	for (i=0; i < obj->attribute_ctr.num_attributes; i++) {
		if (obj->attribute_ctr.attributes[i].attid != id) continue;

		if (idx) *idx = i;
		return &obj->attribute_ctr.attributes[i];
	}

	return NULL;
}

#define GET_STRING_DS(s, r, attr, mem_ctx, p, elem, strict) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(s, r, attr, NULL); \
	if (strict && !_a) { \
		d_printf("%s: %s == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && _a->value_ctr.data_blob.num_values != 1) { \
		d_printf("%s: %s num_values == %u\n", __location__, attr, \
			_a->value_ctr.data_blob.num_values); \
		return WERR_INVALID_PARAM; \
	} \
	if (_a && _a->value_ctr.data_blob.num_values >= 1) { \
		ssize_t _ret; \
		_ret = convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX, \
					     _a->value_ctr.data_blob.values[0].data->data, \
					     _a->value_ctr.data_blob.values[0].data->length, \
					     (void **)discard_const(&(p)->elem)); \
		if (_ret == -1) { \
			DEBUG(0,("%s: invalid data!\n", attr)); \
			dump_data(0, \
				     _a->value_ctr.data_blob.values[0].data->data, \
				     _a->value_ctr.data_blob.values[0].data->length); \
			return WERR_FOOBAR; \
		} \
	} else { \
		(p)->elem = NULL; \
	} \
} while (0)

#define GET_DN_DS(s, r, attr, mem_ctx, p, elem, strict) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(s, r, attr, NULL); \
	if (strict && !_a) { \
		d_printf("%s: %s == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && _a->value_ctr.data_blob.num_values != 1) { \
		d_printf("%s: %s num_values == %u\n", __location__, attr, \
			_a->value_ctr.data_blob.num_values); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && !_a->value_ctr.data_blob.values[0].data) { \
		d_printf("%s: %s data == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (_a && _a->value_ctr.data_blob.num_values >= 1 \
	    && _a->value_ctr.data_blob.values[0].data) { \
		struct drsuapi_DsReplicaObjectIdentifier3 _id3; \
		NTSTATUS _nt_status; \
		_nt_status = ndr_pull_struct_blob_all(_a->value_ctr.data_blob.values[0].data, \
						      mem_ctx, &_id3,\
						      (ndr_pull_flags_fn_t)ndr_pull_drsuapi_DsReplicaObjectIdentifier3);\
		if (!NT_STATUS_IS_OK(_nt_status)) { \
			return ntstatus_to_werror(_nt_status); \
		} \
		(p)->elem = _id3.dn; \
	} else { \
		(p)->elem = NULL; \
	} \
} while (0)

#define GET_BOOL_DS(s, r, attr, p, elem, strict) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(s, r, attr, NULL); \
	if (strict && !_a) { \
		d_printf("%s: %s == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && _a->value_ctr.data_blob.num_values != 1) { \
		d_printf("%s: %s num_values == %u\n", __location__, attr, \
			_a->value_ctr.data_blob.num_values); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && !_a->value_ctr.data_blob.values[0].data) { \
		d_printf("%s: %s data == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && _a->value_ctr.data_blob.values[0].data->length != 4) { \
		d_printf("%s: %s length == %u\n", __location__, attr, \
			_a->value_ctr.data_blob.values[0].data->length); \
		return WERR_INVALID_PARAM; \
	} \
	if (_a && _a->value_ctr.data_blob.num_values >= 1 \
	    && _a->value_ctr.data_blob.values[0].data \
	    && _a->value_ctr.data_blob.values[0].data->length == 4) { \
		(p)->elem = (IVAL(_a->value_ctr.data_blob.values[0].data->data,0)?True:False);\
	} else { \
		(p)->elem = False; \
	} \
} while (0)

#define GET_UINT32_DS(s, r, attr, p, elem) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(s, r, attr, NULL); \
	if (_a && _a->value_ctr.data_blob.num_values >= 1 \
	    && _a->value_ctr.data_blob.values[0].data \
	    && _a->value_ctr.data_blob.values[0].data->length == 4) { \
		(p)->elem = IVAL(_a->value_ctr.data_blob.values[0].data->data,0);\
	} else { \
		(p)->elem = 0; \
	} \
} while (0)

#define GET_GUID_DS(s, r, attr, mem_ctx, p, elem) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(s, r, attr, NULL); \
	if (_a && _a->value_ctr.data_blob.num_values >= 1 \
	    && _a->value_ctr.data_blob.values[0].data \
	    && _a->value_ctr.data_blob.values[0].data->length == 16) { \
	    	NTSTATUS _nt_status; \
		_nt_status = ndr_pull_struct_blob_all(_a->value_ctr.data_blob.values[0].data, \
						      mem_ctx, &(p)->elem, \
						      (ndr_pull_flags_fn_t)ndr_pull_GUID); \
		if (!NT_STATUS_IS_OK(_nt_status)) { \
			return ntstatus_to_werror(_nt_status); \
		} \
	} else { \
		ZERO_STRUCT((p)->elem);\
	} \
} while (0)

#define GET_BLOB_DS(s, r, attr, mem_ctx, p, elem) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(s, r, attr, NULL); \
	if (_a && _a->value_ctr.data_blob.num_values >= 1 \
	    && _a->value_ctr.data_blob.values[0].data) { \
		(p)->elem = *_a->value_ctr.data_blob.values[0].data;\
		talloc_steal(mem_ctx, (p)->elem.data); \
	} else { \
		ZERO_STRUCT((p)->elem);\
	}\
} while (0)

WERROR dsdb_attribute_from_drsuapi(struct dsdb_schema *schema,
				   struct drsuapi_DsReplicaObject *r,
				   TALLOC_CTX *mem_ctx,
				   struct dsdb_attribute *attr)
{
	WERROR status;

	GET_STRING_DS(schema, r, "name", mem_ctx, attr, cn, True);
	GET_STRING_DS(schema, r, "lDAPDisplayName", mem_ctx, attr, lDAPDisplayName, True);
	GET_UINT32_DS(schema, r, "attributeID", attr, attributeID_id);
	status = dsdb_map_int2oid(schema, attr->attributeID_id, mem_ctx, &attr->attributeID_oid);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map attributeID 0x%08X: %s\n",
			__location__, attr->lDAPDisplayName, attr->attributeID_id,
			win_errstr(status)));
		return status;
	}
	GET_GUID_DS(schema, r, "schemaIDGUID", mem_ctx, attr, schemaIDGUID);
	GET_UINT32_DS(schema, r, "mAPIID", attr, mAPIID);

	GET_GUID_DS(schema, r, "attributeSecurityGUID", mem_ctx, attr, attributeSecurityGUID);

	GET_UINT32_DS(schema, r, "searchFlags", attr, searchFlags);
	GET_UINT32_DS(schema, r, "systemFlags", attr, systemFlags);
	GET_BOOL_DS(schema, r, "isMemberOfPartialAttributeSet", attr, isMemberOfPartialAttributeSet, False);
	GET_UINT32_DS(schema, r, "linkID", attr, linkID);

	GET_UINT32_DS(schema, r, "attributeSyntax", attr, attributeSyntax_id);
	status = dsdb_map_int2oid(schema, attr->attributeSyntax_id, mem_ctx, &attr->attributeSyntax_oid);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map attributeSyntax 0x%08X: %s\n",
			__location__, attr->lDAPDisplayName, attr->attributeSyntax_id,
			win_errstr(status)));
		return status;
	}
	GET_UINT32_DS(schema, r, "oMSyntax", attr, oMSyntax);
	GET_BLOB_DS(schema, r, "oMObjectClass", mem_ctx, attr, oMObjectClass);

	GET_BOOL_DS(schema, r, "isSingleValued", attr, isSingleValued, True);
	GET_UINT32_DS(schema, r, "rangeLower", attr, rangeLower);
	GET_UINT32_DS(schema, r, "rangeUpper", attr, rangeUpper);
	GET_BOOL_DS(schema, r, "extendedCharsAllowed", attr, extendedCharsAllowed, False);

	GET_UINT32_DS(schema, r, "schemaFlagsEx", attr, schemaFlagsEx);
	GET_BLOB_DS(schema, r, "msDs-Schema-Extensions", mem_ctx, attr, msDs_Schema_Extensions);

	GET_BOOL_DS(schema, r, "showInAdvancedViewOnly", attr, showInAdvancedViewOnly, False);
	GET_STRING_DS(schema, r, "adminDisplayName", mem_ctx, attr, adminDisplayName, False);
	GET_STRING_DS(schema, r, "adminDescription", mem_ctx, attr, adminDescription, False);
	GET_STRING_DS(schema, r, "classDisplayName", mem_ctx, attr, classDisplayName, False);
	GET_BOOL_DS(schema, r, "isEphemeral", attr, isEphemeral, False);
	GET_BOOL_DS(schema, r, "isDefunct", attr, isDefunct, False);
	GET_BOOL_DS(schema, r, "systemOnly", attr, systemOnly, False);

	attr->syntax = dsdb_syntax_for_attribute(attr);
	if (!attr->syntax) {
		return WERR_DS_ATT_SCHEMA_REQ_SYNTAX;
	}

	return WERR_OK;
}

WERROR dsdb_class_from_drsuapi(struct dsdb_schema *schema,
			       struct drsuapi_DsReplicaObject *r,
			       TALLOC_CTX *mem_ctx,
			       struct dsdb_class *obj)
{
	WERROR status;

	GET_STRING_DS(schema, r, "name", mem_ctx, obj, cn, True);
	GET_STRING_DS(schema, r, "lDAPDisplayName", mem_ctx, obj, lDAPDisplayName, True);
	GET_UINT32_DS(schema, r, "governsID", obj, governsID_id);
	status = dsdb_map_int2oid(schema, obj->governsID_id, mem_ctx, &obj->governsID_oid);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map governsID 0x%08X: %s\n",
			__location__, obj->lDAPDisplayName, obj->governsID_id,
			win_errstr(status)));
		return status;
	}
	GET_GUID_DS(schema, r, "schemaIDGUID", mem_ctx, obj, schemaIDGUID);

	GET_UINT32_DS(schema, r, "objectClassCategory", obj, objectClassCategory);
	GET_STRING_DS(schema, r, "rDNAttID", mem_ctx, obj, rDNAttID, False);
	GET_DN_DS(schema, r, "defaultObjectCategory", mem_ctx, obj, defaultObjectCategory, True);

	GET_STRING_DS(schema, r, "subClassOf", mem_ctx, obj, subClassOf, True);

	obj->systemAuxiliaryClass	= NULL;
	obj->systemPossSuperiors	= NULL;
	obj->systemMustContain		= NULL;
	obj->systemMayContain		= NULL;

	obj->auxiliaryClass		= NULL;
	obj->possSuperiors		= NULL;
	obj->mustContain		= NULL;
	obj->mayContain			= NULL;

	GET_STRING_DS(schema, r, "defaultSecurityDescriptor", mem_ctx, obj, defaultSecurityDescriptor, False);

	GET_UINT32_DS(schema, r, "schemaFlagsEx", obj, schemaFlagsEx);
	GET_BLOB_DS(schema, r, "msDs-Schema-Extensions", mem_ctx, obj, msDs_Schema_Extensions);

	GET_BOOL_DS(schema, r, "showInAdvancedViewOnly", obj, showInAdvancedViewOnly, False);
	GET_STRING_DS(schema, r, "adminDisplayName", mem_ctx, obj, adminDisplayName, False);
	GET_STRING_DS(schema, r, "adminDescription", mem_ctx, obj, adminDescription, False);
	GET_STRING_DS(schema, r, "classDisplayName", mem_ctx, obj, classDisplayName, False);
	GET_BOOL_DS(schema, r, "defaultHidingValue", obj, defaultHidingValue, False);
	GET_BOOL_DS(schema, r, "isDefunct", obj, isDefunct, False);
	GET_BOOL_DS(schema, r, "systemOnly", obj, systemOnly, False);

	return WERR_OK;
}

const struct dsdb_attribute *dsdb_attribute_by_attributeID_id(const struct dsdb_schema *schema,
							      uint32_t id)
{
	struct dsdb_attribute *cur;

	/*
	 * 0xFFFFFFFF is used as value when no mapping table is available,
	 * so don't try to match with it
	 */
	if (id == 0xFFFFFFFF) return NULL;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (cur->attributeID_id != id) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_attribute *dsdb_attribute_by_attributeID_oid(const struct dsdb_schema *schema,
							       const char *oid)
{
	struct dsdb_attribute *cur;

	if (!oid) return NULL;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (strcmp(cur->attributeID_oid, oid) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_attribute *dsdb_attribute_by_lDAPDisplayName(const struct dsdb_schema *schema,
							       const char *name)
{
	struct dsdb_attribute *cur;

	if (!name) return NULL;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (strcmp(cur->lDAPDisplayName, name) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_governsID_id(const struct dsdb_schema *schema,
						    uint32_t id)
{
	struct dsdb_class *cur;

	/*
	 * 0xFFFFFFFF is used as value when no mapping table is available,
	 * so don't try to match with it
	 */
	if (id == 0xFFFFFFFF) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (cur->governsID_id != id) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_governsID_oid(const struct dsdb_schema *schema,
						     const char *oid)
{
	struct dsdb_class *cur;

	if (!oid) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (strcmp(cur->governsID_oid, oid) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_lDAPDisplayName(const struct dsdb_schema *schema,
						       const char *name)
{
	struct dsdb_class *cur;

	if (!name) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (strcmp(cur->lDAPDisplayName, name) != 0) continue;

		return cur;
	}

	return NULL;
}

const char *dsdb_lDAPDisplayName_by_id(const struct dsdb_schema *schema,
				       uint32_t id)
{
	const struct dsdb_attribute *a;
	const struct dsdb_class *c;

	/* TODO: add binary search */
	a = dsdb_attribute_by_attributeID_id(schema, id);
	if (a) {
		return a->lDAPDisplayName;
	}

	c = dsdb_class_by_governsID_id(schema, id);
	if (c) {
		return c->lDAPDisplayName;
	}

	return NULL;
}
