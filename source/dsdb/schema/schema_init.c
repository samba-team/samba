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
#include "librpc/gen_ndr/drsuapi.h"

#define _PREFIX(uint32, oid) {uint32,oid,sizeof(oid)}
static const struct {
	uint32_t uint32;
	const char *oid;
	size_t oid_len;
} prefix_mappings[] = {
	_PREFIX(0x00000000, "2.5.4."),
	_PREFIX(0x00010000, "2.5.6."),
	_PREFIX(0x00020000, "1.2.840.113556.1.2."),
	_PREFIX(0x00030000, "1.2.840.113556.1.3."),
	_PREFIX(0x00080000, "2.5.5."),
	_PREFIX(0x00090000, "1.2.840.113556.1.4."),
	_PREFIX(0x000A0000, "1.2.840.113556.1.5."),
	_PREFIX(0x00140000, "2.16.840.1.113730.3."),
	_PREFIX(0x00150000, "0.9.2342.19200300.100.1."),
	_PREFIX(0x00160000, "2.16.840.1.113730.3.1."),
	_PREFIX(0x00170000, "1.2.840.113556.1.5.7000."),
	_PREFIX(0x00180000, "2.5.21."),
	_PREFIX(0x00190000, "2.5.18."),
	_PREFIX(0x001A0000, "2.5.20."),
	_PREFIX(0x001B0000, "1.3.6.1.4.1.1466.101.119."),
	_PREFIX(0x001C0000, "2.16.840.1.113730.3.2."),
	_PREFIX(0x001D0000, "1.3.6.1.4.1.250.1."),
	_PREFIX(0x001E0000, "1.2.840.113549.1.9."),
	_PREFIX(0x001F0000, "0.9.2342.19200300.100.4."),
};

WERROR dsdb_map_oid2int(const char *in, uint32_t *out)
{
	uint32_t i;

	for (i=0; i < ARRAY_SIZE(prefix_mappings); i++) {
		const char *val_str;
		char *end_str;
		unsigned val;

		if (strncmp(prefix_mappings[i].oid, in, prefix_mappings[i].oid_len - 1) != 0) {
			continue;
		}

		val_str = in + prefix_mappings[i].oid_len - 1;
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

		*out = prefix_mappings[i].uint32 | val;
		return WERR_OK;
	}

	return WERR_DS_NO_MSDS_INTID;
}

WERROR dsdb_map_int2oid(uint32_t in, TALLOC_CTX *mem_ctx, const char **out)
{
	uint32_t i;

	for (i=0; i < ARRAY_SIZE(prefix_mappings); i++) {
		const char *val;
		if (prefix_mappings[i].uint32 != (in & 0xFFFF0000)) {
			continue;
		}

		val = talloc_asprintf(mem_ctx, "%s%u",
				      prefix_mappings[i].oid,
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
	WERROR status;

	GET_STRING_LDB(msg, "cn", mem_ctx, attr, cn, True);
	GET_STRING_LDB(msg, "lDAPDisplayName", mem_ctx, attr, lDAPDisplayName, True);
	GET_STRING_LDB(msg, "attributeID", mem_ctx, attr, attributeID_oid, True);
	status = dsdb_map_oid2int(attr->attributeID_oid, &attr->attributeID_id);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map attributeID '%s': %s\n",
			__location__, attr->lDAPDisplayName, attr->attributeID_oid,
			win_errstr(status)));
		return status;
	}
	GET_GUID_LDB(msg, "schemaIDGUID", attr, schemaIDGUID);
	GET_UINT32_LDB(msg, "mAPIID", attr, mAPIID);

	GET_GUID_LDB(msg, "attributeSecurityGUID", attr, attributeSecurityGUID);

	GET_UINT32_LDB(msg, "searchFlags", attr, searchFlags);
	GET_UINT32_LDB(msg, "systemFlags", attr, systemFlags);
	GET_BOOL_LDB(msg, "isMemberOfPartialAttributeSet", attr, isMemberOfPartialAttributeSet, False);
	GET_UINT32_LDB(msg, "linkID", attr, linkID);

	GET_STRING_LDB(msg, "attributeSyntax", mem_ctx, attr, attributeSyntax_oid, True);
	status = dsdb_map_oid2int(attr->attributeSyntax_oid, &attr->attributeSyntax_id);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map attributeSyntax '%s': %s\n",
			__location__, attr->lDAPDisplayName, attr->attributeSyntax_oid,
			win_errstr(status)));
		return status;
	}
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

	return WERR_OK;
}

WERROR dsdb_class_from_ldb(struct ldb_message *msg, TALLOC_CTX *mem_ctx, struct dsdb_class *obj)
{
	WERROR status;

	GET_STRING_LDB(msg, "cn", mem_ctx, obj, cn, True);
	GET_STRING_LDB(msg, "lDAPDisplayName", mem_ctx, obj, lDAPDisplayName, True);
	GET_STRING_LDB(msg, "governsID", mem_ctx, obj, governsID_oid, True);
	status = dsdb_map_oid2int(obj->governsID_oid, &obj->governsID_id);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map governsID '%s': %s\n",
			__location__, obj->lDAPDisplayName, obj->governsID_oid,
			win_errstr(status)));
		return status;
	}
	GET_GUID_LDB(msg, "schemaIDGUID", obj, schemaIDGUID);

	GET_UINT32_LDB(msg, "objectClassCategory", obj, objectClassCategory);
	GET_STRING_LDB(msg, "rDNAttID", mem_ctx, obj, rDNAttID, False);
	GET_STRING_LDB(msg, "defaultObjectCategory", mem_ctx, obj, defaultObjectCategory, True);
 
	GET_STRING_LDB(msg, "subClassOf", mem_ctx, obj, subClassOf, True);

	GET_STRING_LDB(msg, "systemAuxiliaryClass", mem_ctx, obj, systemAuxiliaryClass, False);
	obj->systemPossSuperiors= NULL;
	obj->systemMustContain	= NULL;
	obj->systemMayContain	= NULL;

	GET_STRING_LDB(msg, "auxiliaryClass", mem_ctx, obj, auxiliaryClass, False);
	obj->possSuperiors	= NULL;
	obj->mustContain	= NULL;
	obj->mayContain		= NULL;

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
	{ "attributeSyntax", 			"1.2.840.113556.1.2.30" },
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

static struct drsuapi_DsReplicaAttribute *dsdb_find_object_attr_name(struct drsuapi_DsReplicaObject *obj,
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

	status = dsdb_map_oid2int(oid, &id);
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

#define GET_STRING_DS(r, attr, mem_ctx, p, elem, strict) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(r, attr, NULL); \
	if (strict && !_a) { \
		d_printf("%s: %s == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && _a->value_ctr.unicode_string.num_values != 1) { \
		d_printf("%s: %s num_values == %u\n", __location__, attr, \
			_a->value_ctr.unicode_string.num_values); \
		return WERR_INVALID_PARAM; \
	} \
	if (_a && _a->value_ctr.unicode_string.num_values >= 1) { \
		(p)->elem = talloc_steal(mem_ctx, _a->value_ctr.unicode_string.values[0].string);\
	} else { \
		(p)->elem = NULL; \
	} \
} while (0)

#define GET_BOOL_DS(r, attr, p, elem, strict) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(r, attr, NULL); \
	if (strict && !_a) { \
		d_printf("%s: %s == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && _a->value_ctr.uint32.num_values != 1) { \
		d_printf("%s: %s num_values == %u\n", __location__, attr, \
			_a->value_ctr.uint32.num_values); \
		return WERR_INVALID_PARAM; \
	} \
	if (strict && !_a->value_ctr.uint32.values[0].value) { \
		d_printf("%s: %s value == NULL\n", __location__, attr); \
		return WERR_INVALID_PARAM; \
	} \
	if (_a && _a->value_ctr.uint32.num_values >= 1 \
	    && _a->value_ctr.uint32.values[0].value) { \
		(p)->elem = (*_a->value_ctr.uint32.values[0].value?True:False);\
	} else { \
		(p)->elem = False; \
	} \
} while (0)

#define GET_UINT32_DS(r, attr, p, elem) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(r, attr, NULL); \
	if (_a && _a->value_ctr.uint32.num_values >= 1 \
	    && _a->value_ctr.uint32.values[0].value) { \
		(p)->elem = *_a->value_ctr.uint32.values[0].value;\
	} else { \
		(p)->elem = 0; \
	} \
} while (0)

#define GET_GUID_DS(r, attr, p, elem) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(r, attr, NULL); \
	if (_a && _a->value_ctr.guid.num_values >= 1 \
	    && _a->value_ctr.guid.values[0].guid) { \
		(p)->elem = *_a->value_ctr.guid.values[0].guid;\
	} else { \
		ZERO_STRUCT((p)->elem);\
	} \
} while (0)

#define GET_BLOB_DS(r, attr, mem_ctx, p, elem) do { \
	struct drsuapi_DsReplicaAttribute *_a; \
	_a = dsdb_find_object_attr_name(r, attr, NULL); \
	if (_a && _a->value_ctr.data_blob.num_values >= 1 \
	    && _a->value_ctr.data_blob.values[0].data) { \
		(p)->elem = *_a->value_ctr.data_blob.values[0].data;\
		talloc_steal(mem_ctx, (p)->elem.data); \
	} else { \
		ZERO_STRUCT((p)->elem);\
	}\
} while (0)

WERROR dsdb_attribute_from_drsuapi(struct drsuapi_DsReplicaObject *r, TALLOC_CTX *mem_ctx, struct dsdb_attribute *attr)
{
	WERROR status;

	GET_STRING_DS(r, "name", mem_ctx, attr, cn, True);
	GET_STRING_DS(r, "lDAPDisplayName", mem_ctx, attr, lDAPDisplayName, True);
	GET_UINT32_DS(r, "attributeID", attr, attributeID_id);
	status = dsdb_map_int2oid(attr->attributeID_id, mem_ctx, &attr->attributeID_oid);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map attributeID 0x%08X: %s\n",
			__location__, attr->lDAPDisplayName, attr->attributeID_id,
			win_errstr(status)));
		return status;
	}
	GET_GUID_DS(r, "schemaIDGUID", attr, schemaIDGUID);
	GET_UINT32_DS(r, "mAPIID", attr, mAPIID);

	GET_GUID_DS(r, "attributeSecurityGUID", attr, attributeSecurityGUID);

	GET_UINT32_DS(r, "searchFlags", attr, searchFlags);
	GET_UINT32_DS(r, "systemFlags", attr, systemFlags);
	GET_BOOL_DS(r, "isMemberOfPartialAttributeSet", attr, isMemberOfPartialAttributeSet, False);
	GET_UINT32_DS(r, "linkID", attr, linkID);

	GET_UINT32_DS(r, "attributeSyntax", attr, attributeSyntax_id);
	status = dsdb_map_int2oid(attr->attributeSyntax_id, mem_ctx, &attr->attributeSyntax_oid);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map attributeSyntax 0x%08X: %s\n",
			__location__, attr->lDAPDisplayName, attr->attributeSyntax_id,
			win_errstr(status)));
		return status;
	}
	GET_UINT32_DS(r, "oMSyntax", attr, oMSyntax);
	GET_BLOB_DS(r, "oMObjectClass", mem_ctx, attr, oMObjectClass);

	GET_BOOL_DS(r, "isSingleValued", attr, isSingleValued, True);
	GET_UINT32_DS(r, "rangeLower", attr, rangeLower);
	GET_UINT32_DS(r, "rangeUpper", attr, rangeUpper);
	GET_BOOL_DS(r, "extendedCharsAllowed", attr, extendedCharsAllowed, False);

	GET_UINT32_DS(r, "schemaFlagsEx", attr, schemaFlagsEx);
	GET_BLOB_DS(r, "msDs-Schema-Extensions", mem_ctx, attr, msDs_Schema_Extensions);

	GET_BOOL_DS(r, "showInAdvancedViewOnly", attr, showInAdvancedViewOnly, False);
	GET_STRING_DS(r, "adminDisplayName", mem_ctx, attr, adminDisplayName, False);
	GET_STRING_DS(r, "adminDescription", mem_ctx, attr, adminDescription, False);
	GET_STRING_DS(r, "classDisplayName", mem_ctx, attr, classDisplayName, False);
	GET_BOOL_DS(r, "isEphemeral", attr, isEphemeral, False);
	GET_BOOL_DS(r, "isDefunct", attr, isDefunct, False);
	GET_BOOL_DS(r, "systemOnly", attr, systemOnly, False);

	return WERR_OK;
}

WERROR dsdb_class_from_drsuapi(struct drsuapi_DsReplicaObject *r, TALLOC_CTX *mem_ctx, struct dsdb_class *obj)
{
	WERROR status;

	GET_STRING_DS(r, "name", mem_ctx, obj, cn, True);
	GET_STRING_DS(r, "lDAPDisplayName", mem_ctx, obj, lDAPDisplayName, True);
	GET_UINT32_DS(r, "governsID", obj, governsID_id);
	status = dsdb_map_int2oid(obj->governsID_id, mem_ctx, &obj->governsID_oid);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("%s: '%s': unable to map governsID 0x%08X: %s\n",
			__location__, obj->lDAPDisplayName, obj->governsID_id,
			win_errstr(status)));
		return status;
	}
	GET_GUID_DS(r, "schemaIDGUID", obj, schemaIDGUID);

	GET_UINT32_DS(r, "objectClassCategory", obj, objectClassCategory);
	GET_STRING_DS(r, "rDNAttID", mem_ctx, obj, rDNAttID, False);
	GET_STRING_DS(r, "defaultObjectCategory", mem_ctx, obj, defaultObjectCategory, True);
 
	GET_STRING_DS(r, "subClassOf", mem_ctx, obj, subClassOf, True);

	GET_STRING_DS(r, "systemAuxiliaryClass", mem_ctx, obj, systemAuxiliaryClass, False);
	obj->systemPossSuperiors= NULL;
	obj->systemMustContain	= NULL;
	obj->systemMayContain	= NULL;

	GET_STRING_DS(r, "auxiliaryClass", mem_ctx, obj, auxiliaryClass, False);
	obj->possSuperiors	= NULL;
	obj->mustContain	= NULL;
	obj->mayContain		= NULL;

	GET_STRING_DS(r, "defaultSecurityDescriptor", mem_ctx, obj, defaultSecurityDescriptor, False);

	GET_UINT32_DS(r, "schemaFlagsEx", obj, schemaFlagsEx);
	GET_BLOB_DS(r, "msDs-Schema-Extensions", mem_ctx, obj, msDs_Schema_Extensions);

	GET_BOOL_DS(r, "showInAdvancedViewOnly", obj, showInAdvancedViewOnly, False);
	GET_STRING_DS(r, "adminDisplayName", mem_ctx, obj, adminDisplayName, False);
	GET_STRING_DS(r, "adminDescription", mem_ctx, obj, adminDescription, False);
	GET_STRING_DS(r, "classDisplayName", mem_ctx, obj, classDisplayName, False);
	GET_BOOL_DS(r, "defaultHidingValue", obj, defaultHidingValue, False);
	GET_BOOL_DS(r, "isDefunct", obj, isDefunct, False);
	GET_BOOL_DS(r, "systemOnly", obj, systemOnly, False);

	return WERR_OK;
}
