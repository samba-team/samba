/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2006

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

/*
 *  Name: ldb
 *
 *  Component: ldb schema module
 *
 *  Description: add schema syntax functionality
 *
 *  Author: Simo Sorce
 *
 *  License: GNU GPL v2 or Later
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "schema_syntax.h"

int map_schema_syntax(uint32_t om_syntax, const char *attr_syntax, const struct ldb_val *om_class, enum schema_internal_syntax *syntax)
{
	int ret;

	ret = LDB_SUCCESS;

	switch(om_syntax) {
	case 1:
		*syntax = SCHEMA_AS_BOOLEAN;
		break;
	case 2:
		*syntax = SCHEMA_AS_INTEGER;
		break;
	case 4:
		if (strcmp(attr_syntax, "2.5.5.10") == 0) {
			*syntax = SCHEMA_AS_OCTET_STRING;
			break;
		}
		if (strcmp(attr_syntax, "2.5.5.17") == 0) {
			*syntax = SCHEMA_AS_SID;
			break;
		}
		ret = LDB_ERR_OPERATIONS_ERROR;
		break;
	case 6:
		*syntax = SCHEMA_AS_OID;
		break;
	case 10:
		*syntax = SCHEMA_AS_ENUMERATION;
		break;
	case 18:
		*syntax = SCHEMA_AS_NUMERIC_STRING;
		break;
	case 19:
		*syntax = SCHEMA_AS_PRINTABLE_STRING;
		break;
	case 20:
		*syntax = SCHEMA_AS_CASE_IGNORE_STRING;
		break;
	case 22:
		*syntax = SCHEMA_AS_IA5_STRING;
		break;
	case 23:
		*syntax = SCHEMA_AS_UTC_TIME;
		break;
	case 24:
		*syntax = SCHEMA_AS_GENERALIZED_TIME;
		break;
	case 27:
		*syntax = SCHEMA_AS_CASE_SENSITIVE_STRING;
		break;
	case 64:
		*syntax = SCHEMA_AS_DIRECTORY_STRING;
		break;
	case 65:
		*syntax = SCHEMA_AS_LARGE_INTEGER;
		break;
	case 66:
		*syntax = SCHEMA_AS_OBJECT_SECURITY_DESCRIPTOR;
		break;
	case 127:
		if (!om_class) {
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}
		
		if (memcmp(om_class->data, "\x2b\x0c\x02\x87\x73\x1c\x00\x85\x4a\x00", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_DN;
			break;
		}
		if (memcmp(om_class->data, "\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x0b", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_DN_BINARY;
			break;
		}
		if (memcmp(om_class->data, "\x56\x06\x01\x02\x05\x0b\x1d\x00\x00\x00", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_OR_NAME;
			break;
		}
		if (memcmp(om_class->data, "\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x06", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_REPLICA_LINK;
			break;
		}
		if (memcmp(om_class->data, "\x2b\x0c\x02\x87\x73\x1c\x00\x85\x5c\x00", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_PRESENTATION_ADDRESS;
			break;
		}
		if (memcmp(om_class->data, "\x2b\x0c\x02\x87\x73\x1c\x00\x85\x3e\x00", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_ACCESS_POINT;
			break;
		}
		if (memcmp(om_class->data, "\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x0c", MIN(om_class->length, 10)) == 0) {
			*syntax = SCHEMA_AS_DN_STRING;
			break;
		}
		/* not found will error in default: */
	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
	}

	return ret;
}

static int schema_validate_boolean(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{

	if ((strncmp("TRUE", (const char *)val->data, val->length) != 0) &&
	    (strncmp("FALSE", (const char *)val->data, val->length) != 0)) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	return LDB_SUCCESS;
}

static int schema_validate_integer(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	int value;
	char *endptr;

	errno = 0;
	value = strtol((const char *)val->data, &endptr, 0);
	if (errno) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if (endptr[0] != '\0') return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if ((min > INT_MIN) && (value < min)) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if ((max < INT_MAX) && (value > max)) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;

	return LDB_SUCCESS;
}

static int schema_validate_binary_blob(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* is there anythign we should check in a binary blob ? */
	return LDB_SUCCESS;
}

static int schema_validate_sid(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: validate binary form of objectSid */
	return LDB_SUCCESS;	
}

static int schema_validate_oid(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	if (strspn((const char *)val->data, "0123456789.") != val->length)
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;

	return LDB_SUCCESS;
}

static int schema_validate_numeric_string(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	if (strspn((const char *)val->data, "0123456789") != val->length)
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;

	return LDB_SUCCESS;
}

static int schema_validate_printable_string(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what constitutes the printable character set */
	return LDB_SUCCESS;
}

static int schema_validate_teletext_string(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what constitutes the teletext character set */
	return LDB_SUCCESS;
}

static int schema_validate_ia5_string(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what constitutes the IA5 character set */
	return LDB_SUCCESS;
}

static int schema_validate_utc_time(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: validate syntax of UTC Time string */
	return LDB_SUCCESS;
}

static int schema_validate_generalized_time(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: validate syntax of Generalized Time string */
	return LDB_SUCCESS;
}

/* NOTE: not a single attribute has this syntax in the basic w2k3 schema */
static int schema_validate_sensitive_string(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what constitutes a "case sensitive string" */
	return LDB_SUCCESS;
}

static int schema_validate_unicode_string(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: validate utf8 string */
	return LDB_SUCCESS;
}

static int schema_validate_large_integer(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: validate large integer/interval */
	return LDB_SUCCESS;
}

static int schema_validate_object_sd(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: validate object Security Descriptor */
	return LDB_SUCCESS;
}

static int schema_validate_dn(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	struct ldb_dn *dn;
	int ret = LDB_SUCCESS;

	dn = ldb_dn_new(ldb, ldb, (const char *)val->data);
	if ( ! ldb_dn_validate(dn)) {
		ret = LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	talloc_free(dn);
	return ret;
}

static int schema_validate_binary_plus_dn(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	int ret = LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	TALLOC_CTX *memctx;
	struct ldb_dn *dn;
	char *str, *p;
	char *endptr;
	int num;
       
	memctx = talloc_new(NULL);
	if (!memctx) return LDB_ERR_OPERATIONS_ERROR;

	str = talloc_strdup(memctx, (const char *)val->data);
	if (!str) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (strncasecmp(str, "B:", 2) != 0) {
		goto done;
	}

	/* point at the number of chars in the string */
	str = strchr(&str[2], ':');
	if (!str) {
		goto done;
	}
	str++;

	errno = 0;
	num = strtol(str, &endptr, 0);
	if (errno) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if (endptr[0] != ':') return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if ((min > INT_MIN) && (num < min)) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if ((max < INT_MAX) && (num > max)) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;

	/* point at the string */
	str = strchr(str, ':');
	if (!str) {
		goto done;
	}
	str++;

	/* terminate the string */
	p = strchr(str, ':');
	if (!p) {
		goto done;
	}
	*p = '\0';

	if (strlen(str) != 2*num) {
		goto done;
	}

	str = p + 1;

	dn = ldb_dn_new(memctx, ldb, str);
	if (ldb_dn_validate(dn)) {
		ret = LDB_SUCCESS;
	}

done:
	talloc_free(memctx);
	return ret;
}

static int schema_validate_x400_or_name(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what is the syntax of an X400 OR NAME */
	return LDB_SUCCESS;
}

static int schema_validate_presentation_address(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what is the syntax of a presentation address */
	return LDB_SUCCESS;
}

static int schema_validate_x400_access_point(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	/* TODO: find out what is the syntax of an X400 Access Point */
	return LDB_SUCCESS;
}

/* NOTE: seem there isn't a single attribute defined like this in the base w2k3 schema */
static int schema_validate_string_plus_dn(struct ldb_context *ldb, struct ldb_val *val, int min, int max)
{
	int ret = LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	TALLOC_CTX *memctx;
	struct ldb_dn *dn;
	char *str, *p;
	char *endptr;
	int num;
       
	memctx = talloc_new(NULL);
	if (!memctx) return LDB_ERR_OPERATIONS_ERROR;

	str = talloc_strdup(memctx, (const char *)val->data);
	if (!str) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (strncasecmp(str, "S:", 2) != 0) {
		goto done;
	}

	/* point at the number of chars in the string */
	str = strchr(&str[2], ':');
	if (!str) {
		goto done;
	}
	str++;

	errno = 0;
	num = strtol(str, &endptr, 0);
	if (errno) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if (endptr[0] != ':') return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if ((min > INT_MIN) && (num < min)) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	if ((max < INT_MAX) && (num > max)) return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;

	/* point at the string */
	str = strchr(str, ':');
	if (!str) {
		goto done;
	}
	str++;

	/* terminate the string */
	p = strchr(str, ':');
	if (!p) {
		goto done;
	}
	*p = '\0';

	if (strlen(str) != num) {
		goto done;
	}

	str = p + 1;

	dn = ldb_dn_new(memctx, ldb, str);
	if (ldb_dn_validate(dn)) {
		ret = LDB_SUCCESS;
	}

done:
	talloc_free(memctx);
	return ret;
}

struct schema_syntax_validator {
	enum schema_internal_syntax type;
	int (*validate)(struct ldb_context *ldb, struct ldb_val *, int, int);
};

struct schema_syntax_validator schema_syntax_validators[] = {
	{ SCHEMA_AS_BOOLEAN, schema_validate_boolean },
	{ SCHEMA_AS_INTEGER, schema_validate_integer },
	{ SCHEMA_AS_OCTET_STRING, schema_validate_binary_blob },
	{ SCHEMA_AS_SID, schema_validate_sid },
	{ SCHEMA_AS_OID, schema_validate_oid },
	{ SCHEMA_AS_ENUMERATION, schema_validate_integer },
	{ SCHEMA_AS_NUMERIC_STRING, schema_validate_numeric_string },
	{ SCHEMA_AS_PRINTABLE_STRING, schema_validate_printable_string },
	{ SCHEMA_AS_CASE_IGNORE_STRING, schema_validate_teletext_string },
	{ SCHEMA_AS_IA5_STRING, schema_validate_ia5_string },
	{ SCHEMA_AS_UTC_TIME, schema_validate_utc_time },
	{ SCHEMA_AS_GENERALIZED_TIME, schema_validate_generalized_time },
	{ SCHEMA_AS_CASE_SENSITIVE_STRING, schema_validate_sensitive_string },
	{ SCHEMA_AS_DIRECTORY_STRING, schema_validate_unicode_string },
	{ SCHEMA_AS_LARGE_INTEGER, schema_validate_large_integer },
	{ SCHEMA_AS_OBJECT_SECURITY_DESCRIPTOR, schema_validate_object_sd },
	{ SCHEMA_AS_DN, schema_validate_dn },
	{ SCHEMA_AS_DN_BINARY, schema_validate_binary_plus_dn },
	{ SCHEMA_AS_OR_NAME, schema_validate_x400_or_name },
	{ SCHEMA_AS_REPLICA_LINK, schema_validate_binary_blob },
	{ SCHEMA_AS_PRESENTATION_ADDRESS, schema_validate_presentation_address }, /* see rfc1278 ? */
	{ SCHEMA_AS_ACCESS_POINT, schema_validate_x400_access_point },
	{ SCHEMA_AS_DN_STRING, schema_validate_string_plus_dn },
	{ -1, NULL }
};

int schema_validate(struct ldb_context *ldb,
		    struct ldb_message_element *el,
		    enum schema_internal_syntax type,
		    bool single, int min, int max)
{
	struct schema_syntax_validator *v;
	int i, ret;

	if (single && (el->num_values > 1)) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	for (i = 0; schema_syntax_validators[i].type != 0; i++) {
		if (schema_syntax_validators[i].type == type)
			break;
	}
	if (schema_syntax_validators[i].type == 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	v = &schema_syntax_validators[i];
	
	for (i = 0; i < el->num_values; i++) {
		ret = v->validate(ldb, &el->values[i], min, max);
	}

	return LDB_SUCCESS;
}


