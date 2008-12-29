/* 
   Unix SMB/CIFS Implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Volker Lendecke 2004
    
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

#ifndef _SMB_LDAP_H_
#define _SMB_LDAP_H_

#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/misc.h"

enum ldap_request_tag {
	LDAP_TAG_BindRequest = 0,
	LDAP_TAG_BindResponse = 1,
	LDAP_TAG_UnbindRequest = 2,
	LDAP_TAG_SearchRequest = 3,
	LDAP_TAG_SearchResultEntry = 4,
	LDAP_TAG_SearchResultDone = 5,
	LDAP_TAG_ModifyRequest = 6,
	LDAP_TAG_ModifyResponse = 7,
	LDAP_TAG_AddRequest = 8,
	LDAP_TAG_AddResponse = 9,
	LDAP_TAG_DelRequest = 10,
	LDAP_TAG_DelResponse = 11,
	LDAP_TAG_ModifyDNRequest = 12,
	LDAP_TAG_ModifyDNResponse = 13,
	LDAP_TAG_CompareRequest = 14,
	LDAP_TAG_CompareResponse = 15,
	LDAP_TAG_AbandonRequest = 16,
	LDAP_TAG_SearchResultReference = 19,
	LDAP_TAG_ExtendedRequest = 23,
	LDAP_TAG_ExtendedResponse = 24
};

enum ldap_auth_mechanism {
	LDAP_AUTH_MECH_SIMPLE = 0,
	LDAP_AUTH_MECH_SASL = 3
};

enum ldap_result_code {
	LDAP_SUCCESS				= 0,
	LDAP_OPERATIONS_ERROR			= 1,
	LDAP_PROTOCOL_ERROR			= 2,
	LDAP_TIME_LIMIT_EXCEEDED		= 3,
	LDAP_SIZE_LIMIT_EXCEEDED		= 4,
	LDAP_COMPARE_FALSE			= 5,
	LDAP_COMPARE_TRUE			= 6,
	LDAP_AUTH_METHOD_NOT_SUPPORTED		= 7,
	LDAP_STRONG_AUTH_REQUIRED		= 8,
	LDAP_REFERRAL				= 10,
	LDAP_ADMIN_LIMIT_EXCEEDED		= 11,
	LDAP_UNAVAILABLE_CRITICAL_EXTENSION	= 12,
	LDAP_CONFIDENTIALITY_REQUIRED		= 13,
	LDAP_SASL_BIND_IN_PROGRESS		= 14,
	LDAP_NO_SUCH_ATTRIBUTE			= 16,
	LDAP_UNDEFINED_ATTRIBUTE_TYPE		= 17,
	LDAP_INAPPROPRIATE_MATCHING		= 18,
	LDAP_CONSTRAINT_VIOLATION		= 19,
	LDAP_ATTRIBUTE_OR_VALUE_EXISTS		= 20,
	LDAP_INVALID_ATTRIBUTE_SYNTAX		= 21,
	LDAP_NO_SUCH_OBJECT			= 32,
	LDAP_ALIAS_PROBLEM			= 33,
	LDAP_INVALID_DN_SYNTAX			= 34,
	LDAP_ALIAS_DEREFERENCING_PROBLEM	= 36,
	LDAP_INAPPROPRIATE_AUTHENTICATION	= 48,
	LDAP_INVALID_CREDENTIALS		= 49,
	LDAP_INSUFFICIENT_ACCESS_RIGHTS		= 50,
	LDAP_BUSY				= 51,
	LDAP_UNAVAILABLE			= 52,
	LDAP_UNWILLING_TO_PERFORM		= 53,
	LDAP_LOOP_DETECT			= 54,
	LDAP_NAMING_VIOLATION			= 64,
	LDAP_OBJECT_CLASS_VIOLATION		= 65,
	LDAP_NOT_ALLOWED_ON_NON_LEAF		= 66,
	LDAP_NOT_ALLOWED_ON_RDN			= 67,
	LDAP_ENTRY_ALREADY_EXISTS		= 68,
	LDAP_OBJECT_CLASS_MODS_PROHIBITED	= 69,
	LDAP_AFFECTS_MULTIPLE_DSAS		= 71,
	LDAP_OTHER 				= 80
};

struct ldap_Result {
	int resultcode;
	const char *dn;
	const char *errormessage;
	const char *referral;
};

struct ldap_BindRequest {
	int version;
	const char *dn;
	enum ldap_auth_mechanism mechanism;
	union {
		const char *password;
		struct {
			const char *mechanism;
			DATA_BLOB *secblob;/* optional */
		} SASL;
	} creds;
};

struct ldap_BindResponse {
	struct ldap_Result response;
	union {
		DATA_BLOB *secblob;/* optional */
	} SASL;
};

struct ldap_UnbindRequest {
	uint8_t __dummy;
};

enum ldap_scope {
	LDAP_SEARCH_SCOPE_BASE = 0,
	LDAP_SEARCH_SCOPE_SINGLE = 1,
	LDAP_SEARCH_SCOPE_SUB = 2
};

enum ldap_deref {
	LDAP_DEREFERENCE_NEVER = 0,
	LDAP_DEREFERENCE_IN_SEARCHING = 1,
	LDAP_DEREFERENCE_FINDING_BASE = 2,
	LDAP_DEREFERENCE_ALWAYS
};

struct ldap_SearchRequest {
	const char *basedn;
	enum ldap_scope scope;
	enum ldap_deref deref;
	uint32_t timelimit;
	uint32_t sizelimit;
	bool attributesonly;
	struct ldb_parse_tree *tree;
	int num_attributes;
	const char **attributes;
};

struct ldap_SearchResEntry {
	const char *dn;
	int num_attributes;
	struct ldb_message_element *attributes;
};

struct ldap_SearchResRef {
	const char *referral;
};

enum ldap_modify_type {
	LDAP_MODIFY_NONE = -1,
	LDAP_MODIFY_ADD = 0,
	LDAP_MODIFY_DELETE = 1,
	LDAP_MODIFY_REPLACE = 2
};

struct ldap_mod {
	enum ldap_modify_type type;
	struct ldb_message_element attrib;
};

struct ldap_ModifyRequest {
	const char *dn;
	int num_mods;
	struct ldap_mod *mods;
};

struct ldap_AddRequest {
	const char *dn;
	int num_attributes;
	struct ldb_message_element *attributes;
};

struct ldap_DelRequest {
	const char *dn;
};

struct ldap_ModifyDNRequest {
	const char *dn;
	const char *newrdn;
	bool deleteolddn;
	const char *newsuperior;/* optional */
};

struct ldap_CompareRequest {
	const char *dn;
	const char *attribute;
	DATA_BLOB value;
};

struct ldap_AbandonRequest {
	uint32_t messageid;
};

struct ldap_ExtendedRequest {
	const char *oid;
	DATA_BLOB *value;/* optional */
};

struct ldap_ExtendedResponse {
	struct ldap_Result response;
	const char *oid;/* optional */
	DATA_BLOB *value;/* optional */
};

union ldap_Request {
	struct ldap_Result 		GeneralResult;
	struct ldap_BindRequest 	BindRequest;
	struct ldap_BindResponse 	BindResponse;
	struct ldap_UnbindRequest 	UnbindRequest;
	struct ldap_SearchRequest 	SearchRequest;
	struct ldap_SearchResEntry 	SearchResultEntry;
	struct ldap_Result 		SearchResultDone;
	struct ldap_SearchResRef 	SearchResultReference;
	struct ldap_ModifyRequest 	ModifyRequest;
	struct ldap_Result 		ModifyResponse;
	struct ldap_AddRequest 		AddRequest;
	struct ldap_Result 		AddResponse;
	struct ldap_DelRequest 		DelRequest;
	struct ldap_Result 		DelResponse;
	struct ldap_ModifyDNRequest 	ModifyDNRequest;
	struct ldap_Result 		ModifyDNResponse;
	struct ldap_CompareRequest 	CompareRequest;
	struct ldap_Result 		CompareResponse;
	struct ldap_AbandonRequest 	AbandonRequest;
	struct ldap_ExtendedRequest 	ExtendedRequest;
	struct ldap_ExtendedResponse 	ExtendedResponse;
};


struct ldap_message {
	int                     messageid;
	enum ldap_request_tag   type;
	union ldap_Request      r;
	struct ldb_control    **controls;
	bool                   *controls_decoded;
};

struct tevent_context;
struct cli_credentials;
struct dom_sid;
struct asn1_data;

struct ldap_message *new_ldap_message(TALLOC_CTX *mem_ctx);
NTSTATUS ldap_decode(struct asn1_data *data, struct ldap_message *msg);
bool ldap_encode(struct ldap_message *msg, DATA_BLOB *result, TALLOC_CTX *mem_ctx);

#endif 
