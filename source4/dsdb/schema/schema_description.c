/* 
   Unix SMB/CIFS Implementation.
   Print schema info into string format
   
   Copyright (C) Andrew Bartlett 2006-2008
    
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
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"

#undef strcasecmp

char *schema_attribute_description(TALLOC_CTX *mem_ctx, 
					  enum dsdb_schema_convert_target target,
					  const char *separator,
					  const char *oid, 
					  const char *name,
					  const char *equality, 
					  const char *substring, 
					  const char *syntax,
					  bool single_value, bool operational,
					  uint32_t *range_lower,
					  uint32_t *range_upper,
					  const char *property_guid,
					  const char *property_set_guid,
					  bool indexed, bool system_only)
{
	char *schema_entry = talloc_asprintf(mem_ctx, 
					     "(%s%s%s", separator, oid, separator);

	talloc_asprintf_addbuf(
		&schema_entry, "NAME '%s'%s", name, separator);

	if (equality) {
		talloc_asprintf_addbuf(
			&schema_entry, "EQUALITY %s%s", equality, separator);
	}
	if (substring) {
		talloc_asprintf_addbuf(
			&schema_entry, "SUBSTR %s%s", substring, separator);
	}

	if (syntax) {
		talloc_asprintf_addbuf(
			&schema_entry, "SYNTAX %s%s", syntax, separator);
	}

	if (single_value) {
		talloc_asprintf_addbuf(
			&schema_entry, "SINGLE-VALUE%s", separator);
	}

	if (operational) {
		talloc_asprintf_addbuf(
			&schema_entry, "NO-USER-MODIFICATION%s", separator);
	}

	if (range_lower) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"RANGE-LOWER '%u'%s",
			*range_lower,
			separator);
	}

	if (range_upper) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"RANGE-UPPER '%u'%s",
			*range_upper,
			separator);
	}

	if (property_guid) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"PROPERTY-GUID '%s'%s",
			property_guid,
			separator);
	}

	if (property_set_guid) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"PROPERTY-SET-GUID '%s'%s",
			property_set_guid,
			separator);
	}

	if (indexed) {
		talloc_asprintf_addbuf(
			&schema_entry, "INDEXED%s", separator);
	}

	if (system_only) {
		talloc_asprintf_addbuf(
			&schema_entry, "SYSTEM-ONLY%s", separator);
	}

	talloc_asprintf_addbuf(&schema_entry, ")");

	return schema_entry;
}

char *schema_attribute_to_description(TALLOC_CTX *mem_ctx, const struct dsdb_attribute *attribute) 
{
	char *schema_description;
	const char *syntax = attribute->syntax->ldap_oid;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NULL;
	}

	schema_description 
		= schema_attribute_description(mem_ctx, 
					       TARGET_AD_SCHEMA_SUBENTRY,
					       " ",
					       attribute->attributeID_oid,
					       attribute->lDAPDisplayName,
					       NULL, NULL, talloc_asprintf(tmp_ctx, "'%s'", syntax),
					       attribute->isSingleValued,
					       attribute->systemOnly,/* TODO: is this correct? */
					       NULL, NULL, NULL, NULL,
					       false, false);
	talloc_free(tmp_ctx);
	return schema_description;
}

char *schema_attribute_to_extendedInfo(TALLOC_CTX *mem_ctx, const struct dsdb_attribute *attribute)
{
	char *schema_description;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NULL;
	}

	schema_description
		= schema_attribute_description(mem_ctx,
					       TARGET_AD_SCHEMA_SUBENTRY,
					       " ",
					       attribute->attributeID_oid,
					       attribute->lDAPDisplayName,
					       NULL, NULL, NULL,
					       false, false,
					       attribute->rangeLower,
					       attribute->rangeUpper,
					       GUID_hexstring(tmp_ctx, &attribute->schemaIDGUID),
					       GUID_hexstring(tmp_ctx, &attribute->attributeSecurityGUID),
					       /*
						* We actually ignore the indexed
						* flag for confidential
						* attributes, but we'll include
						* it for the purposes of
						* description.
						*/
					       (attribute->searchFlags & SEARCH_FLAG_ATTINDEX),
					       attribute->systemOnly);
	talloc_free(tmp_ctx);
	return schema_description;
}

#define APPEND_ATTRS(attributes)				\
	do {								\
		unsigned int k;						\
		for (k=0; attributes && attributes[k]; k++) {		\
			const char *attr_name = attributes[k];		\
									\
			talloc_asprintf_addbuf(&schema_entry,           \
							      "%s ",	\
							      attr_name); \
			if (attributes[k+1]) {				\
				if (target == TARGET_OPENLDAP && ((k+1)%5 == 0)) { \
					talloc_asprintf_addbuf(&schema_entry, \
									      "$%s ", separator); \
				} else {				\
					talloc_asprintf_addbuf(&schema_entry, \
									      "$ "); \
				}					\
			}						\
		}							\
	} while (0)
	

/* Print a schema class or dITContentRule as a string.  
 *
 * To print a scheam class, specify objectClassCategory but not auxillary_classes
 * To print a dITContentRule, specify auxillary_classes but set objectClassCategory == -1
 *
 */

char *schema_class_description(TALLOC_CTX *mem_ctx, 
			       enum dsdb_schema_convert_target target,
			       const char *separator,
			       const char *oid, 
			       const char *name,
			       const char **auxillary_classes,
			       const char *subClassOf,
			       int objectClassCategory,
			       const char **must,
			       const char **may,
			       const char *schemaHexGUID)
{
	char *schema_entry = talloc_asprintf(mem_ctx, 
					     "(%s%s%s", separator, oid, separator);

	talloc_asprintf_addbuf(&schema_entry, "NAME '%s'%s", name, separator);

	if (auxillary_classes) {
		talloc_asprintf_addbuf(&schema_entry, "AUX ( ");

		APPEND_ATTRS(auxillary_classes);

		talloc_asprintf_addbuf(&schema_entry, ")%s", separator);
	}

	if (subClassOf && strcasecmp(subClassOf, name) != 0) {
		talloc_asprintf_addbuf(
			&schema_entry, "SUP %s%s", subClassOf, separator);
	}

	switch (objectClassCategory) {
	case -1:
		break;
		/* Dummy case for when used for printing ditContentRules */
	case 0:
		/*
		 * NOTE: this is an type 88 class
		 *       e.g. 2.5.6.6 NAME 'person'
		 *	 but w2k3 gives STRUCTURAL here!
		 */
		talloc_asprintf_addbuf(
			&schema_entry, "STRUCTURAL%s", separator);
		break;
	case 1:
		talloc_asprintf_addbuf(
			&schema_entry, "STRUCTURAL%s", separator);
		break;
	case 2:
		talloc_asprintf_addbuf(
			&schema_entry, "ABSTRACT%s", separator);
		break;
	case 3:
		talloc_asprintf_addbuf(
			&schema_entry, "AUXILIARY%s", separator);
		break;
	}

	if (must) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"MUST (%s",
			target == TARGET_AD_SCHEMA_SUBENTRY ? "" : " ");

		APPEND_ATTRS(must);

		talloc_asprintf_addbuf(
			&schema_entry, ")%s", separator);
	}

	if (may) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"MAY (%s",
			target == TARGET_AD_SCHEMA_SUBENTRY ? "" : " ");

		APPEND_ATTRS(may);

		talloc_asprintf_addbuf(
			&schema_entry, ")%s", separator);
	}

	if (schemaHexGUID) {
		talloc_asprintf_addbuf(
			&schema_entry,
			"CLASS-GUID '%s'%s",
			schemaHexGUID,
			separator);
	}

	talloc_asprintf_addbuf(&schema_entry, ")");

	return schema_entry;
}

char *schema_class_to_description(TALLOC_CTX *mem_ctx, const struct dsdb_class *sclass)
{
	char *schema_description;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NULL;
	}
	
	schema_description
		= schema_class_description(mem_ctx, 
					   TARGET_AD_SCHEMA_SUBENTRY,
					   " ",
					   sclass->governsID_oid,
					   sclass->lDAPDisplayName,
					   NULL, 
					   sclass->subClassOf,
					   sclass->objectClassCategory,
					   dsdb_attribute_list(tmp_ctx, 
							       sclass, DSDB_SCHEMA_ALL_MUST),
					   dsdb_attribute_list(tmp_ctx, 
							       sclass, DSDB_SCHEMA_ALL_MAY),
					   NULL);
	talloc_free(tmp_ctx);
	return schema_description;
}

char *schema_class_to_dITContentRule(TALLOC_CTX *mem_ctx, const struct dsdb_class *sclass,
				     const struct dsdb_schema *schema)
{
	unsigned int i;
	char *schema_description;
	const char **aux_class_list = NULL;
	const char **attrs;
	const char **must_attr_list = NULL;
	const char **may_attr_list = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	const struct dsdb_class *aux_class;
	if (!tmp_ctx) {
		return NULL;
	}

	aux_class_list = merge_attr_list(tmp_ctx, aux_class_list, sclass->systemAuxiliaryClass);
	aux_class_list = merge_attr_list(tmp_ctx, aux_class_list, sclass->auxiliaryClass);

	for (i=0; aux_class_list && aux_class_list[i]; i++) {
		aux_class = dsdb_class_by_lDAPDisplayName(schema, aux_class_list[i]);
		
		attrs = dsdb_attribute_list(mem_ctx, aux_class, DSDB_SCHEMA_ALL_MUST);
		must_attr_list = merge_attr_list(mem_ctx, must_attr_list, attrs);

		attrs = dsdb_attribute_list(mem_ctx, aux_class, DSDB_SCHEMA_ALL_MAY);
		may_attr_list = merge_attr_list(mem_ctx, may_attr_list, attrs);
	}

	schema_description
		= schema_class_description(mem_ctx, 
					   TARGET_AD_SCHEMA_SUBENTRY,
					   " ",
					   sclass->governsID_oid,
					   sclass->lDAPDisplayName,
					   (const char **)aux_class_list,
					   NULL, /* Must not specify a
						  * SUP (subclass) in
						  * ditContentRules
						  * per MS-ADTS
						  * 3.1.1.3.1.1.1 */
					   -1, must_attr_list, may_attr_list,
					   NULL);
	talloc_free(tmp_ctx);
	return schema_description;
}

char *schema_class_to_extendedInfo(TALLOC_CTX *mem_ctx, const struct dsdb_class *sclass)
{
	char *schema_description = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NULL;
	}

	schema_description
		= schema_class_description(mem_ctx,
					   TARGET_AD_SCHEMA_SUBENTRY,
					   " ",
					   sclass->governsID_oid,
					   sclass->lDAPDisplayName,
					   NULL,
					   NULL, /* Must not specify a
						  * SUP (subclass) in
						  * ditContentRules
						  * per MS-ADTS
						  * 3.1.1.3.1.1.1 */
					   -1, NULL, NULL,
					   GUID_hexstring(tmp_ctx, &sclass->schemaIDGUID));
	talloc_free(tmp_ctx);
	return schema_description;
}


