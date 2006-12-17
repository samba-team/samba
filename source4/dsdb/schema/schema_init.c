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
	_PREFIX(0x001A0000, "2.5.20."),
	_PREFIX(0x001C0000, "2.16.840.1.113730.3.2."),
	_PREFIX(0x001D0000, "1.3.6.1.4.1.250.1."),
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

		val = strtoul(val_str, &end_str, 10);
		if (end_str[0] != '\0') {
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

#define GET_STRING(p, elem, strict) do { \
	(p)->elem = samdb_result_string(msg, #elem, NULL);\
	if (strict && (p)->elem == NULL) { \
		d_printf("%s: %s == NULL\n", __location__, #elem); \
		return WERR_INVALID_PARAM; \
	} \
	(void)talloc_steal(p, (p)->elem); \
} while (0)

#define GET_BOOL(p, elem, strict) do { \
	const char *str; \
	str = samdb_result_string(msg, #elem, NULL);\
	if (str == NULL) { \
		if (strict) { \
			d_printf("%s: %s == NULL\n", __location__, #elem); \
			return WERR_INVALID_PARAM; \
		} else { \
			(p)->elem = False; \
		} \
	} else if (strcasecmp("TRUE", str) == 0) { \
		(p)->elem = True; \
	} else if (strcasecmp("FALSE", str) == 0) { \
		(p)->elem = False; \
	} else { \
		d_printf("%s: %s == %s\n", __location__, #elem, str); \
		return WERR_INVALID_PARAM; \
	} \
} while (0)

#define GET_UINT32(p, elem) do { \
	(p)->elem = samdb_result_uint(msg, #elem, 0);\
} while (0)

#define GET_GUID(p, elem) do { \
	(p)->elem = samdb_result_guid(msg, #elem);\
} while (0)

#define GET_BLOB(p, elem) do { \
	const struct ldb_val *_val;\
	_val = ldb_msg_find_ldb_val(msg, #elem);\
	if (_val) {\
		(p)->elem = *_val;\
		(void)talloc_steal(p, (p)->elem.data);\
	} else {\
		ZERO_STRUCT((p)->elem);\
	}\
} while (0)

WERROR dsdb_attribute_from_ldb(struct ldb_message *msg, TALLOC_CTX *mem_ctx, struct dsdb_attribute *attr)
{
	WERROR status;

	GET_STRING(attr, cn, True);
	GET_STRING(attr, lDAPDisplayName, True);
	GET_STRING(attr, attributeID_oid, True);
	status = dsdb_map_oid2int(attr->attributeID_oid, &attr->attributeID_id);
	W_ERROR_NOT_OK_RETURN(status);
	GET_GUID(attr, schemaIDGUID);
	GET_UINT32(attr, mAPIID);

	GET_GUID(attr, attributeSecurityGUID);

	GET_UINT32(attr, searchFlags);
	GET_UINT32(attr, systemFlags);
	GET_BOOL(attr, isMemberOfPartialAttributeSet, False);
	GET_UINT32(attr, linkID);

	GET_STRING(attr, attributeSyntax_oid, True);
	status = dsdb_map_oid2int(attr->attributeSyntax_oid, &attr->attributeSyntax_id);
	W_ERROR_NOT_OK_RETURN(status);
	GET_UINT32(attr, oMSyntax);
	GET_BLOB(attr, oMObjectClass);

	GET_BOOL(attr, isSingleValued, True);
	GET_UINT32(attr, rangeLower);
	GET_UINT32(attr, rangeUpper);
	GET_BOOL(attr, extendedCharsAllowed, False);

	GET_UINT32(attr, schemaFlagsEx);
	GET_BLOB(attr, msDs_Schema_Extensions);

	GET_BOOL(attr, showInAdvancedViewOnly, False);
	GET_STRING(attr, adminDisplayName, True);
	GET_STRING(attr, adminDescription, True);
	GET_STRING(attr, classDisplayName, True);
	GET_BOOL(attr, isEphemeral, False);
	GET_BOOL(attr, isDefunct, False);
	GET_BOOL(attr, systemOnly, False);

	return WERR_OK;
}

WERROR dsdb_class_from_ldb(struct ldb_message *msg, TALLOC_CTX *mem_ctx, struct dsdb_class *obj)
{
	WERROR status;

	GET_STRING(obj, cn, True);
	GET_STRING(obj, lDAPDisplayName, True);
	GET_STRING(obj, governsID_oid, True);
	status = dsdb_map_oid2int(obj->governsID_oid, &obj->governsID_id);
	W_ERROR_NOT_OK_RETURN(status);
	GET_GUID(obj, schemaIDGUID);

	GET_UINT32(obj, objectClassCategory);
	GET_STRING(obj, rDNAttID, True);
	GET_STRING(obj, defaultObjectCategory, True);

	GET_STRING(obj, subClassOf, True);

	GET_STRING(obj, systemAuxiliaryClass, False);
	obj->systemPossSuperiors= NULL;
	obj->systemMustContain	= NULL;
	obj->systemMayContain	= NULL;

	GET_STRING(obj, auxiliaryClass, False);
	obj->possSuperiors	= NULL;
	obj->mustContain	= NULL;
	obj->mayContain		= NULL;

	GET_STRING(obj, defaultSecurityDescriptor, False);

	GET_UINT32(obj, schemaFlagsEx);
	GET_BLOB(obj, msDs_Schema_Extensions);

	GET_BOOL(obj, showInAdvancedViewOnly, False);
	GET_STRING(obj, adminDisplayName, True);
	GET_STRING(obj, adminDescription, True);
	GET_STRING(obj, classDisplayName, True);
	GET_BOOL(obj, defaultHidingValue, True);
	GET_BOOL(obj, isDefunct, False);
	GET_BOOL(obj, systemOnly, False);

	return WERR_OK;
}
