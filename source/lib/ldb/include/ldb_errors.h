/* 
   ldb database library

   Copyright (C) Simo Sorce  2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb header
 *
 *  Description: defines error codes following RFC 2251 ldap error codes
 *
 *  Author: Simo Sorce
 */

#ifndef _LDB_ERRORS_H_
#define _LDB_ERRORS_H_ 1

/* 
 * Not all error codes make sense for ldb,
 * but they are keept here for reference anyway
 */

#define LDB_SUCCESS				0
#define LDB_ERR_OPERATIONS_ERROR		1
#define LDB_ERR_PROTOCOL_ERROR			2
#define LDB_ERR_TIME_LIMIT_EXCEEDED		3
#define LDB_ERR_SIZE_LIMIT_EXCEEDED		4
#define LDB_ERR_COMPARE_FALSE			5
#define LDB_ERR_COMPARE_TRUE			6
#define LDB_ERR_AUTH_METHOD_NOT_SUPPORTED	7
#define LDB_ERR_STRONG_AUTH_REQUIRED		8
/* 9 RESERVED */
#define LDB_ERR_REFERRAL			10
#define LDB_ERR_ADMIN_LIMIT_EXCEEDED		11
#define LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION	12
#define LDB_ERR_CONFIDENTIALITY_REQUIRED	13
#define LDB_ERR_SASL_BIND_IN_PROGRESS		14
#define LDB_ERR_NO_SUCH_ATTRIBUTE		16
#define LDB_ERR_UNDEFINED_ATTRIBUTE_TYPE	17
#define LDB_ERR_INAPPROPRIATE_MATCHING		18
#define LDB_ERR_CONSTRAINT_VIOLAION		19
#define LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS	20
#define LDB_ERR_INVALID_ATTRIBUTE_SYNTAX	21
/* 22-31 unused */
#define LDB_ERR_NO_SUCH_OBJECT			32
#define LDB_ERR_ALIAS_PROBLEM			33
#define LDB_ERR_INVALID_DN_SYNTAX		34
/* 53 RESERVED */
#define LDB_ERR_ALIAS_DEREFERENCING_PROBLEM	36
/* 37-47 unused */
#define LDB_ERR_INAPPROPRIATE_AUTHENTICATION	48
#define LDB_ERR_INVALID_CREDENTIALS		49
#define LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS	50
#define LDB_ERR_BUSY				51
#define LDB_ERR_UNAVAILABLE			52
#define LDB_ERR_UNWILLING_TO_PERFORM		53
#define LDB_ERR_LOOP_DETECT			54
/* 55-63 unused */
#define LDB_ERR_NAMING_VIOLATION		64
#define LDB_ERR_OBJECT_CLASS_VIOLATION		65
#define LDB_ERR_NOT_ALLOWED_ON_NON_LEAF		66
#define LDB_ERR_NOT_ALLOWED_ON_RDN		67
#define LDB_ERR_ENTRY_ALREADY_EXISTS		68
#define LDB_ERR_OBJECT_CLASS_MODS_PROHIBITED	69
/* 70 RESERVED FOR CLDAP */
#define LDB_ERR_AFFECTS_MULTIPLE_DSAS		71
/* 72-79 unused */
#define LDB_ERR_OTHER				80
/* 81-90 RESERVED for APIs */

#endif /* _LDB_ERRORS_H_ */
