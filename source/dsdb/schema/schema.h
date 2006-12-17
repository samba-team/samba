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

#ifndef _DSDB_SCHEMA_H
#define _DSDB_SCHEMA_H

struct dsdb_attribute {
	struct dsdb_attribute *prev, *next;

	const char *cn;
	const char *lDAPDisplayName;
	const char *attributeID_oid;
	uint32_t attributeID_id;
	struct GUID schemaIDGUID;
	uint32_t mAPIID;

	struct GUID attributeSecurityGUID;

	uint32_t searchFlags;
	uint32_t systemFlags;
	BOOL isMemberOfPartialAttributeSet;
	uint32_t linkID;

	const char *attributeSyntax_oid;
	uint32_t attributeSyntax_id;
	uint32_t oMSyntax;
	struct ldb_val oMObjectClass;

	BOOL isSingleValued;
	uint32_t rangeLower;
	uint32_t rangeUpper;
	BOOL extendedCharsAllowed;

	uint32_t schemaFlagsEx;
	struct ldb_val msDs_Schema_Extensions;

	BOOL showInAdvancedViewOnly;
	const char *adminDisplayName;
	const char *adminDescription;
	const char *classDisplayName;
	BOOL isEphemeral;
	BOOL isDefunct;
	BOOL systemOnly;
};

struct dsdb_class {
	struct dsdb_class *prev, *next;

	const char *cn;
	const char *lDAPDisplayName;
	const char *governsID_oid;
	uint32_t governsID_id;
	struct GUID schemaIDGUID;

	uint32_t objectClassCategory;
	const char *rDNAttID;
	const char *defaultObjectCategory;

	const char *subClassOf;

	const char *systemAuxiliaryClass;
	const char **systemPossSuperiors;
	const char **systemMustContain;
	const char **systemMayContain;

	const char *auxiliaryClass;
	const char **possSuperiors;
	const char **mustContain;
	const char **mayContain;

	const char *defaultSecurityDescriptor;

	uint32_t schemaFlagsEx;
	struct ldb_val msDs_Schema_Extensions;

	BOOL showInAdvancedViewOnly;
	const char *adminDisplayName;
	const char *adminDescription;
	const char *classDisplayName;
	BOOL defaultHidingValue;
	BOOL isDefunct;
	BOOL systemOnly;
};

struct dsdb_schema {
	struct dsdb_attribute *attributes;
	struct dsdb_class *classes;
};

#endif /* _DSDB_SCHEMA_H */
