/*
   Unix SMB/CIFS implementation.
   Infrastructure for async ldap client requests
   Copyright (C) Volker Lendecke 2009

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

#ifndef __TLDAP_H__
#define __TLDAP_H__

#include "replace.h"
#include <talloc.h>
#include <tevent.h>
#include "lib/util/data_blob.h"

struct tldap_context;
struct tldap_message;

struct tldap_control {
	const char *oid;
	DATA_BLOB value;
	bool critical;
};

struct tldap_attribute {
	char *name;
	int num_values;
	DATA_BLOB *values;
};

struct tldap_mod {
	int mod_op;
	char *attribute;
	int num_values;
	DATA_BLOB *values;
};

#if defined(HAVE_IMMEDIATE_STRUCTURES)
typedef struct { uint8_t rc; } TLDAPRC;
#define TLDAP_RC(x) ((TLDAPRC){.rc = x})
#define TLDAP_RC_V(x) ((x).rc)
#else
typedef uint8_t TLDAPRC;
#define TLDAP_RC(x) (x)
#define TLDAP_RC_V(x) (x)
#endif

#define TLDAP_RC_EQUAL(x,y) (TLDAP_RC_V(x)==TLDAP_RC_V(y))
#define TLDAP_RC_IS_SUCCESS(x) TLDAP_RC_EQUAL(x,TLDAP_SUCCESS)

#define TLDAP_SUCCESS TLDAP_RC(0x00)
#define TLDAP_OPERATIONS_ERROR TLDAP_RC(0x01)
#define TLDAP_PROTOCOL_ERROR TLDAP_RC(0x02)
#define TLDAP_TIMELIMIT_EXCEEDED TLDAP_RC(0x03)
#define TLDAP_SIZELIMIT_EXCEEDED TLDAP_RC(0x04)
#define TLDAP_COMPARE_FALSE TLDAP_RC(0x05)
#define TLDAP_COMPARE_TRUE TLDAP_RC(0x06)
#define TLDAP_STRONG_AUTH_NOT_SUPPORTED TLDAP_RC(0x07)
#define TLDAP_STRONG_AUTH_REQUIRED TLDAP_RC(0x08)
#define TLDAP_REFERRAL TLDAP_RC(0x0a)
#define TLDAP_ADMINLIMIT_EXCEEDED TLDAP_RC(0x0b)
#define TLDAP_UNAVAILABLE_CRITICAL_EXTENSION TLDAP_RC(0x0c)
#define TLDAP_CONFIDENTIALITY_REQUIRED TLDAP_RC(0x0d)
#define TLDAP_SASL_BIND_IN_PROGRESS TLDAP_RC(0x0e)
#define TLDAP_NO_SUCH_ATTRIBUTE TLDAP_RC(0x10)
#define TLDAP_UNDEFINED_TYPE TLDAP_RC(0x11)
#define TLDAP_INAPPROPRIATE_MATCHING TLDAP_RC(0x12)
#define TLDAP_CONSTRAINT_VIOLATION TLDAP_RC(0x13)
#define TLDAP_TYPE_OR_VALUE_EXISTS TLDAP_RC(0x14)
#define TLDAP_INVALID_SYNTAX TLDAP_RC(0x15)
#define TLDAP_NO_SUCH_OBJECT TLDAP_RC(0x20)
#define TLDAP_ALIAS_PROBLEM TLDAP_RC(0x21)
#define TLDAP_INVALID_DN_SYNTAX TLDAP_RC(0x22)
#define TLDAP_IS_LEAF TLDAP_RC(0x23)
#define TLDAP_ALIAS_DEREF_PROBLEM TLDAP_RC(0x24)
#define TLDAP_INAPPROPRIATE_AUTH TLDAP_RC(0x30)
#define TLDAP_INVALID_CREDENTIALS TLDAP_RC(0x31)
#define TLDAP_INSUFFICIENT_ACCESS TLDAP_RC(0x32)
#define TLDAP_BUSY TLDAP_RC(0x33)
#define TLDAP_UNAVAILABLE TLDAP_RC(0x34)
#define TLDAP_UNWILLING_TO_PERFORM TLDAP_RC(0x35)
#define TLDAP_LOOP_DETECT TLDAP_RC(0x36)
#define TLDAP_NAMING_VIOLATION TLDAP_RC(0x40)
#define TLDAP_OBJECT_CLASS_VIOLATION TLDAP_RC(0x41)
#define TLDAP_NOT_ALLOWED_ON_NONLEAF TLDAP_RC(0x42)
#define TLDAP_NOT_ALLOWED_ON_RDN TLDAP_RC(0x43)
#define TLDAP_ALREADY_EXISTS TLDAP_RC(0x44)
#define TLDAP_NO_OBJECT_CLASS_MODS TLDAP_RC(0x45)
#define TLDAP_RESULTS_TOO_LARGE TLDAP_RC(0x46)
#define TLDAP_AFFECTS_MULTIPLE_DSAS TLDAP_RC(0x47)
#define TLDAP_OTHER TLDAP_RC(0x50)
#define TLDAP_SERVER_DOWN TLDAP_RC(0x51)
#define TLDAP_LOCAL_ERROR TLDAP_RC(0x52)
#define TLDAP_ENCODING_ERROR TLDAP_RC(0x53)
#define TLDAP_DECODING_ERROR TLDAP_RC(0x54)
#define TLDAP_TIMEOUT TLDAP_RC(0x55)
#define TLDAP_AUTH_UNKNOWN TLDAP_RC(0x56)
#define TLDAP_FILTER_ERROR TLDAP_RC(0x57)
#define TLDAP_USER_CANCELLED TLDAP_RC(0x58)
#define TLDAP_PARAM_ERROR TLDAP_RC(0x59)
#define TLDAP_NO_MEMORY TLDAP_RC(0x5a)
#define TLDAP_CONNECT_ERROR TLDAP_RC(0x5b)
#define TLDAP_NOT_SUPPORTED TLDAP_RC(0x5c)
#define TLDAP_CONTROL_NOT_FOUND TLDAP_RC(0x5d)
#define TLDAP_NO_RESULTS_RETURNED TLDAP_RC(0x5e)
#define TLDAP_MORE_RESULTS_TO_RETURN TLDAP_RC(0x5f)
#define TLDAP_CLIENT_LOOP TLDAP_RC(0x60)
#define TLDAP_REFERRAL_LIMIT_EXCEEDED TLDAP_RC(0x61)

bool tevent_req_ldap_error(struct tevent_req *req, TLDAPRC rc);
bool tevent_req_is_ldap_error(struct tevent_req *req, TLDAPRC *perr);

struct tldap_context *tldap_context_create(TALLOC_CTX *mem_ctx, int fd);
struct tstream_context *tldap_get_tstream(struct tldap_context *ld);
void tldap_set_tstream(struct tldap_context *ld,
		       struct tstream_context *stream);

bool tldap_connection_ok(struct tldap_context *ld);
bool tldap_context_setattr(struct tldap_context *ld,
			   const char *name, const void *pptr);
void *tldap_context_getattr(struct tldap_context *ld, const char *name);

struct tevent_req *tldap_sasl_bind_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tldap_context *ld,
					const char *dn,
					const char *mechanism,
					DATA_BLOB *creds,
					struct tldap_control *sctrls,
					int num_sctrls,
					struct tldap_control *cctrls,
					int num_cctrls);
TLDAPRC tldap_sasl_bind_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			     DATA_BLOB *serverSaslCreds);
TLDAPRC tldap_sasl_bind(struct tldap_context *ldap,
			const char *dn,
			const char *mechanism,
			DATA_BLOB *creds,
			struct tldap_control *sctrls,
			int num_sctrls,
			struct tldap_control *cctrls,
			int num_cctrls,
			TALLOC_CTX *mem_ctx,
			DATA_BLOB *serverSaslCreds);

struct tevent_req *tldap_simple_bind_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tldap_context *ldap,
					  const char *dn,
					  const char *passwd);
TLDAPRC tldap_simple_bind_recv(struct tevent_req *req);
TLDAPRC tldap_simple_bind(struct tldap_context *ldap, const char *dn,
			  const char *passwd);

struct tevent_req *tldap_search_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tldap_context *ld,
				     const char *base, int scope,
				     const char *filter,
				     const char **attrs,
				     int num_attrs,
				     int attrsonly,
				     struct tldap_control *sctrls,
				     int num_sctrls,
				     struct tldap_control *cctrls,
				     int num_cctrls,
				     int timelimit,
				     int sizelimit,
				     int deref);
TLDAPRC tldap_search_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct tldap_message **pmsg);

struct tevent_req *tldap_search_all_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct tldap_context *ld, const char *base, int scope,
	const char *filter, const char **attrs, int num_attrs, int attrsonly,
	struct tldap_control *sctrls, int num_sctrls,
	struct tldap_control *cctrls, int num_cctrls,
	int timelimit, int sizelimit, int deref);
TLDAPRC tldap_search_all_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			      struct tldap_message ***msgs,
			      struct tldap_message **result);

TLDAPRC tldap_search(struct tldap_context *ld,
		     const char *base, int scope, const char *filter,
		     const char **attrs, int num_attrs, int attrsonly,
		     struct tldap_control *sctrls, int num_sctrls,
		     struct tldap_control *cctrls, int num_cctrls,
		     int timelimit, int sizelimit, int deref,
		     TALLOC_CTX *mem_ctx, struct tldap_message ***pmsgs);

bool tldap_entry_dn(struct tldap_message *msg, char **dn);
bool tldap_entry_attributes(struct tldap_message *msg,
			    struct tldap_attribute **attributes,
			    int *num_attributes);

struct tevent_req *tldap_add_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct tldap_context *ld,
				  const char *dn,
				  struct tldap_mod *attributes,
				  int num_attributes,
				  struct tldap_control *sctrls,
				  int num_sctrls,
				  struct tldap_control *cctrls,
				  int num_cctrls);
TLDAPRC tldap_add_recv(struct tevent_req *req);
TLDAPRC tldap_add(struct tldap_context *ld, const char *dn,
		  struct tldap_mod *attributes, int num_attributes,
		  struct tldap_control *sctrls, int num_sctrls,
		  struct tldap_control *cctrls, int num_cctrls);

struct tevent_req *tldap_modify_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tldap_context *ld,
				     const char *dn,
				     struct tldap_mod *mods, int num_mods,
				     struct tldap_control *sctrls,
				     int num_sctrls,
				     struct tldap_control *cctrls,
				     int num_cctrls);
TLDAPRC tldap_modify_recv(struct tevent_req *req);
TLDAPRC tldap_modify(struct tldap_context *ld, const char *dn,
		     struct tldap_mod *mods, int num_mods,
		     struct tldap_control *sctrls, int num_sctrls,
		     struct tldap_control *cctrls, int num_cctrls);

struct tevent_req *tldap_delete_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tldap_context *ld,
				     const char *dn,
				     struct tldap_control *sctrls,
				     int num_sctrls,
				     struct tldap_control *cctrls,
				     int num_cctrls);
TLDAPRC tldap_delete_recv(struct tevent_req *req);
TLDAPRC tldap_delete(struct tldap_context *ld, const char *dn,
		     struct tldap_control *sctrls, int num_sctrls,
		     struct tldap_control *cctrls, int num_cctrls);

int tldap_msg_id(const struct tldap_message *msg);
int tldap_msg_type(const struct tldap_message *msg);
const char *tldap_msg_matcheddn(struct tldap_message *msg);
const char *tldap_msg_diagnosticmessage(struct tldap_message *msg);
const char *tldap_msg_referral(struct tldap_message *msg);
void tldap_msg_sctrls(struct tldap_message *msg, int *num_sctrls,
		      struct tldap_control **sctrls);
struct tldap_message *tldap_ctx_lastmsg(struct tldap_context *ld);
const char *tldap_rc2string(TLDAPRC rc);

/* DEBUG */
enum tldap_debug_level {
	TLDAP_DEBUG_FATAL,
	TLDAP_DEBUG_ERROR,
	TLDAP_DEBUG_WARNING,
	TLDAP_DEBUG_TRACE
};

void tldap_set_debug(struct tldap_context *ld,
		     void (*log_fn)(void *log_private,
				    enum tldap_debug_level level,
				    const char *fmt,
				    va_list ap) PRINTF_ATTRIBUTE(3,0),
		     void *log_private);

/*
 * "+ 0x60" is from ASN1_APPLICATION
 */
#define TLDAP_REQ_BIND (0 + 0x60)
#define TLDAP_RES_BIND (1 + 0x60)
#define TLDAP_REQ_UNBIND (2 + 0x60)
#define TLDAP_REQ_SEARCH (3 + 0x60)
#define TLDAP_RES_SEARCH_ENTRY (4 + 0x60)
#define TLDAP_RES_SEARCH_RESULT (5 + 0x60)
#define TLDAP_REQ_MODIFY (6 + 0x60)
#define TLDAP_RES_MODIFY (7 + 0x60)
#define TLDAP_REQ_ADD (8 + 0x60)
#define TLDAP_RES_ADD (9 + 0x60)
/* ASN1_APPLICATION_SIMPLE instead of ASN1_APPLICATION */
#define TLDAP_REQ_DELETE (10 + 0x40)
#define TLDAP_RES_DELETE (11 + 0x60)
#define TLDAP_REQ_MODDN (12 + 0x60)
#define TLDAP_RES_MODDN (13 + 0x60)
#define TLDAP_REQ_COMPARE (14 + 0x60)
#define TLDAP_RES_COMPARE (15 + 0x60)
/* ASN1_APPLICATION_SIMPLE instead of ASN1_APPLICATION */
#define TLDAP_REQ_ABANDON (16 + 0x40)
#define TLDAP_RES_SEARCH_REFERENCE (19 + 0x60)
#define TLDAP_REQ_EXTENDED (23 + 0x60)
#define TLDAP_RES_EXTENDED (24 + 0x60)
#define TLDAP_RES_INTERMEDIATE (25 + 0x60)

#define TLDAP_MOD_ADD (0)
#define TLDAP_MOD_DELETE (1)
#define TLDAP_MOD_REPLACE (2)

#define TLDAP_SCOPE_BASE (0)
#define TLDAP_SCOPE_ONE (1)
#define TLDAP_SCOPE_SUB (2)

#define TLDAP_CONTROL_PAGEDRESULTS "1.2.840.113556.1.4.319"

#endif
