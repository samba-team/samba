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


/* Syntax-Table

   see ldap_server/devdocs/AD-syntaxes.txt
*/

enum schema_internal_syntax {
	SCHEMA_AS_BOOLEAN = 1,
	SCHEMA_AS_INTEGER = 2,
	SCHEMA_AS_OCTET_STRING = 3,
	SCHEMA_AS_SID = 4,
	SCHEMA_AS_OID = 5,
	SCHEMA_AS_ENUMERATION = 6,
	SCHEMA_AS_NUMERIC_STRING = 7,
	SCHEMA_AS_PRINTABLE_STRING = 8,
	SCHEMA_AS_CASE_IGNORE_STRING = 9,
	SCHEMA_AS_IA5_STRING = 10,
	SCHEMA_AS_UTC_TIME = 11,
	SCHEMA_AS_GENERALIZED_TIME = 12,
	SCHEMA_AS_CASE_SENSITIVE_STRING = 13,
	SCHEMA_AS_DIRECTORY_STRING = 14,
	SCHEMA_AS_LARGE_INTEGER = 15,
	SCHEMA_AS_OBJECT_SECURITY_DESCRIPTOR = 16,
	SCHEMA_AS_DN = 17,
	SCHEMA_AS_DN_BINARY = 18,
	SCHEMA_AS_OR_NAME = 19,
	SCHEMA_AS_REPLICA_LINK = 20,
	SCHEMA_AS_PRESENTATION_ADDRESS = 21,
	SCHEMA_AS_ACCESS_POINT = 22,
	SCHEMA_AS_DN_STRING = 23
};

int map_schema_syntax(uint32_t om_syntax,
		      const char *attr_syntax,
		      const struct ldb_val *om_class,
		      enum schema_internal_syntax *syntax);

int schema_validate(struct ldb_context *ldb,
		    struct ldb_message_element *el,
		    enum schema_internal_syntax type,
		    bool single, int min, int max);

