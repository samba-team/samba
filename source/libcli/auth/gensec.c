/* 
   Unix SMB/CIFS implementation.
 
   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
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

/* the list of currently registered GENSEC backends */
const static struct gensec_security_ops **generic_security_ops;
static int gensec_num_backends;

static const struct gensec_security_ops *gensec_security_by_authtype(uint8_t auth_type)
{
	int i;
	for (i=0; i < gensec_num_backends; i++) {
		if (generic_security_ops[i]->auth_type == auth_type) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

static const struct gensec_security_ops *gensec_security_by_oid(const char *oid_string)
{
	int i;
	for (i=0; i < gensec_num_backends; i++) {
		if (generic_security_ops[i]->oid &&
		    (strcmp(generic_security_ops[i]->oid, oid_string) == 0)) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

static const struct gensec_security_ops *gensec_security_by_sasl_name(const char *sasl_name)
{
	int i;
	for (i=0; i < gensec_num_backends; i++) {
		if (generic_security_ops[i]->sasl_name 
		    && (strcmp(generic_security_ops[i]->sasl_name, sasl_name) == 0)) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

static const struct gensec_security_ops *gensec_security_by_name(const char *name)
{
	int i;
	for (i=0; i < gensec_num_backends; i++) {
		if (generic_security_ops[i]->name 
		    && (strcmp(generic_security_ops[i]->name, name) == 0)) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

const struct gensec_security_ops **gensec_security_all(int *num_backends_out)
{
	*num_backends_out = gensec_num_backends;
	return generic_security_ops;
}

const char **gensec_security_oids(TALLOC_CTX *mem_ctx, const char *skip) 
{
	int i, j = 0;
	const char **oid_list;
	int num_backends;
	const struct gensec_security_ops **ops = gensec_security_all(&num_backends);
	if (!ops) {
		return NULL;
	}
	oid_list = talloc_array_p(mem_ctx, const char *, num_backends + 1);
	if (!oid_list) {
		return NULL;
	}
	
	for (i=0; i<num_backends; i++) {
		if (!ops[i]->oid) {
			continue;
		}
		
		if (skip && strcmp(skip, ops[i]->oid)==0) {
			continue;
		}

		oid_list[j] = ops[i]->oid;
		j++;
	}
	oid_list[j] = NULL;
	return oid_list;
}

/*
  note that memory context is the parent context to hang this gensec context off. It may be NULL.
*/
static NTSTATUS gensec_start(TALLOC_CTX *mem_ctx, struct gensec_security **gensec_security) 
{
	/* awaiting a correct fix from metze */
	if (!gensec_init()) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	(*gensec_security) = talloc_p(mem_ctx, struct gensec_security);
	if (!(*gensec_security)) {
		return NT_STATUS_NO_MEMORY;
	}

	(*gensec_security)->ops = NULL;

	ZERO_STRUCT((*gensec_security)->user);
	ZERO_STRUCT((*gensec_security)->target);
	ZERO_STRUCT((*gensec_security)->default_user);

	(*gensec_security)->default_user.name = "";
	(*gensec_security)->default_user.domain = talloc_strdup(*gensec_security, lp_workgroup());
	(*gensec_security)->default_user.realm = talloc_strdup(*gensec_security, lp_realm());

	(*gensec_security)->subcontext = False;
	(*gensec_security)->want_features = 0;
	return NT_STATUS_OK;
}

/** 
 * Start a GENSEC subcontext, with a copy of the properties of the parent
 *
 * @note Used by SPENGO in particular, for the actual implementation mechanism
 */

NTSTATUS gensec_subcontext_start(struct gensec_security *parent, 
				 struct gensec_security **gensec_security)
{
	(*gensec_security) = talloc_p(parent, struct gensec_security);
	if (!(*gensec_security)) {
		return NT_STATUS_NO_MEMORY;
	}

	(**gensec_security) = *parent;
	(*gensec_security)->ops = NULL;
	(*gensec_security)->private_data = NULL;

	(*gensec_security)->subcontext = True;

	return NT_STATUS_OK;
}

NTSTATUS gensec_client_start(TALLOC_CTX *mem_ctx, struct gensec_security **gensec_security)
{
	NTSTATUS status;
	status = gensec_start(mem_ctx, gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	(*gensec_security)->gensec_role = GENSEC_CLIENT;
	(*gensec_security)->password_callback = NULL;

	ZERO_STRUCT((*gensec_security)->user);

	return status;
}

NTSTATUS gensec_server_start(TALLOC_CTX *mem_ctx, struct gensec_security **gensec_security)
{
	NTSTATUS status;
	status = gensec_start(mem_ctx, gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	(*gensec_security)->gensec_role = GENSEC_SERVER;

	return status;
}

static NTSTATUS gensec_start_mech(struct gensec_security *gensec_security) 
{
	NTSTATUS status;
	DEBUG(5, ("Starting GENSEC %smechanism %s\n", 
		  gensec_security->subcontext ? "sub" : "", 
		  gensec_security->ops->name));
	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		if (gensec_security->ops->client_start) {
			status = gensec_security->ops->client_start(gensec_security);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(1, ("Faild to start GENSEC client mech %s: %s\n",
					  gensec_security->ops->name, nt_errstr(status))); 
			}
			return status;
		}
	case GENSEC_SERVER:
		if (gensec_security->ops->server_start) {
			status = gensec_security->ops->server_start(gensec_security);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(1, ("Faild to start GENSEC server mech %s: %s\n",
					  gensec_security->ops->name, nt_errstr(status))); 
			}
			return status;
		}
	}
	return NT_STATUS_INVALID_PARAMETER;
}

/** 
 * Start a GENSEC sub-mechanism by DCERPC allocated 'auth type' number 
 */

NTSTATUS gensec_start_mech_by_authtype(struct gensec_security *gensec_security, 
				       uint8_t auth_type, uint8_t auth_level) 
{
	gensec_security->ops = gensec_security_by_authtype(auth_type);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for auth_type=%d\n", (int)auth_type));
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (auth_level == DCERPC_AUTH_LEVEL_INTEGRITY) {
		gensec_want_feature(gensec_security, GENSEC_WANT_SIGN);
	}
	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		gensec_want_feature(gensec_security, GENSEC_WANT_SIGN);
		gensec_want_feature(gensec_security, GENSEC_WANT_SEAL);
	}

	return gensec_start_mech(gensec_security);
}

const char *gensec_get_name_by_authtype(uint8_t authtype) 
{
	const struct gensec_security_ops *ops;
	ops = gensec_security_by_authtype(authtype);
	if (ops) {
		return ops->name;
	}
	return NULL;
}
	

const char *gensec_get_name_by_oid(const char *oid_string) 
{
	const struct gensec_security_ops *ops;
	ops = gensec_security_by_oid(oid_string);
	if (ops) {
		return ops->name;
	}
	return NULL;
}
	

/** 
 * Start a GENSEC sub-mechanism by OID, used in SPNEGO
 *
 * @note This should also be used when you wish to just start NLTMSSP (for example), as it uses a
 *       well-known #define to hook it in.
 */

NTSTATUS gensec_start_mech_by_oid(struct gensec_security *gensec_security, 
				  const char *mech_oid) 
{
	gensec_security->ops = gensec_security_by_oid(mech_oid);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for oid=%s\n", mech_oid));
		return NT_STATUS_INVALID_PARAMETER;
	}
	return gensec_start_mech(gensec_security);
}

/** 
 * Start a GENSEC sub-mechanism by a well know SASL name
 *
 */

NTSTATUS gensec_start_mech_by_sasl_name(struct gensec_security *gensec_security, 
					const char *sasl_name) 
{
	gensec_security->ops = gensec_security_by_sasl_name(sasl_name);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for sasl_name=%s\n", sasl_name));
		return NT_STATUS_INVALID_PARAMETER;
	}
	return gensec_start_mech(gensec_security);
}

/*
  wrappers for the gensec function pointers
*/
NTSTATUS gensec_unseal_packet(struct gensec_security *gensec_security, 
			      TALLOC_CTX *mem_ctx, 
			      uint8_t *data, size_t length, 
			      const uint8_t *whole_pdu, size_t pdu_length, 
			      DATA_BLOB *sig)
{
	if (!gensec_security->ops->unseal_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!(gensec_security->want_features & GENSEC_WANT_SEAL)) {
		if (gensec_security->want_features & GENSEC_WANT_SIGN) {
			return gensec_check_packet(gensec_security, mem_ctx, 
						   data, length, 
						   whole_pdu, pdu_length, 
						   sig);
		}
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_security->ops->unseal_packet(gensec_security, mem_ctx, 
						   data, length, 
						   whole_pdu, pdu_length, 
						   sig);
}

NTSTATUS gensec_check_packet(struct gensec_security *gensec_security, 
			     TALLOC_CTX *mem_ctx, 
			     const uint8_t *data, size_t length, 
			     const uint8_t *whole_pdu, size_t pdu_length, 
			     const DATA_BLOB *sig)
{
	if (!gensec_security->ops->check_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!(gensec_security->want_features & GENSEC_WANT_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_security->ops->check_packet(gensec_security, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

NTSTATUS gensec_seal_packet(struct gensec_security *gensec_security, 
			    TALLOC_CTX *mem_ctx, 
			    uint8_t *data, size_t length, 
			    const uint8_t *whole_pdu, size_t pdu_length, 
			    DATA_BLOB *sig)
{
	if (!gensec_security->ops->seal_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!(gensec_security->want_features & GENSEC_WANT_SEAL)) {
		if (gensec_security->want_features & GENSEC_WANT_SIGN) {
			return gensec_sign_packet(gensec_security, mem_ctx, 
						  data, length, 
						  whole_pdu, pdu_length, 
						  sig);
		}
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_security->ops->seal_packet(gensec_security, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

NTSTATUS gensec_sign_packet(struct gensec_security *gensec_security, 
			    TALLOC_CTX *mem_ctx, 
			    const uint8_t *data, size_t length, 
			    const uint8_t *whole_pdu, size_t pdu_length, 
			    DATA_BLOB *sig)
{
	if (!gensec_security->ops->sign_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!(gensec_security->want_features & GENSEC_WANT_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_security->ops->sign_packet(gensec_security, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

size_t gensec_sig_size(struct gensec_security *gensec_security) 
{
	if (!gensec_security->ops->sig_size) {
		return 0;
	}
	if (!(gensec_security->want_features & GENSEC_WANT_SIGN)) {
		return 0;
	}
	
	return gensec_security->ops->sig_size(gensec_security);
}

NTSTATUS gensec_session_key(struct gensec_security *gensec_security, 
			    DATA_BLOB *session_key)
{
	if (!gensec_security->ops->session_key) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!(gensec_security->want_features & GENSEC_WANT_SESSION_KEY)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_security->ops->session_key(gensec_security, session_key);
}

/** 
 * Return the credentials of a logged on user, including session keys
 * etc.
 *
 * Only valid after a successful authentication
 *
 * May only be called once per authentication.
 *
 */

NTSTATUS gensec_session_info(struct gensec_security *gensec_security, 
			     struct auth_session_info **session_info)
{
	if (!gensec_security->ops->session_info) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return gensec_security->ops->session_info(gensec_security, session_info);
}

/**
 * Next state function for the GENSEC state machine
 * 
 * @param gensec_security GENSEC State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent, 
 *                or NT_STATUS_OK if the user is authenticated. 
 */

NTSTATUS gensec_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
		       const DATA_BLOB in, DATA_BLOB *out) 
{
	return gensec_security->ops->update(gensec_security, out_mem_ctx, in, out);
}

void gensec_end(struct gensec_security **gensec_security)
{
	if ((*gensec_security)->ops) {
		(*gensec_security)->ops->end(*gensec_security);
	}
	(*gensec_security)->private_data = NULL;

	talloc_free(*gensec_security);
	*gensec_security = NULL;
}

/** 
 * Set the requirement for a certain feature on the connection
 *
 */

void gensec_want_feature(struct gensec_security *gensec_security,
			 uint32 feature) 
{
	gensec_security->want_features |= feature;
}

/** 
 * Check the requirement for a certain feature on the connection
 *
 */

BOOL gensec_have_feature(struct gensec_security *gensec_security,
			 uint32 feature) 
{
	if (gensec_security->want_features & feature) {
		return True;
	}

	return False;
}

/** 
 * Set a username on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_unparsed_username(struct gensec_security *gensec_security, const char *user) 
{
	char *p;
	char *u = talloc_strdup(gensec_security, user);
	if (!u) {
		return NT_STATUS_NO_MEMORY;
	}

	p = strchr_m(user, '@');
	
	if (p) {
		*p = '\0';
		gensec_security->user.name = talloc_strdup(gensec_security, u);
		if (!gensec_security->user.name) {
			return NT_STATUS_NO_MEMORY;
		}
		
		gensec_security->user.realm = talloc_strdup(gensec_security, p+1);
		if (!gensec_security->user.realm) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	} 

	p = strchr_m(user, '\\');
	if (!p) {
		p = strchr_m(user, '/');
	}
	
	if (p) {
		*p = '\0';
		gensec_security->user.domain = talloc_strdup(gensec_security, u);
		if (!gensec_security->user.domain) {
			return NT_STATUS_NO_MEMORY;
		}
		gensec_security->user.name = talloc_strdup(gensec_security, p+1);
		if (!gensec_security->user.name) {
			return NT_STATUS_NO_MEMORY;
		}
		
		return NT_STATUS_OK;
	} 
	
	gensec_security->user.name = u;
	if (!gensec_security->user.name) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set a username on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_username(struct gensec_security *gensec_security, const char *user) 
{
	gensec_security->user.name = talloc_strdup(gensec_security, user);
	if (!gensec_security->user.name) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set a username on a GENSEC context - ensures it is talloc()ed 
 *
 */

const char *gensec_get_username(struct gensec_security *gensec_security) 
{
	if (gensec_security->user.name) {
		return gensec_security->user.name;
	}
	return gensec_security->default_user.name;
}

/** 
 * Set a domain on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_domain(struct gensec_security *gensec_security, const char *domain) 
{
	gensec_security->user.domain = talloc_strdup(gensec_security, domain);
	if (!gensec_security->user.domain) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Return the NT domain for this GENSEC context
 *
 */

const char *gensec_get_domain(struct gensec_security *gensec_security) 
{
	if (gensec_security->user.domain) {
		return gensec_security->user.domain;
	} else if (gensec_security->user.realm) {
		return gensec_security->user.realm;
	}
	return gensec_security->default_user.domain;
}

/** 
 * Set a kerberos realm on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_realm(struct gensec_security *gensec_security, const char *realm) 
{
	gensec_security->user.realm = talloc_strdup(gensec_security, realm);
	if (!gensec_security->user.realm) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Return the Krb5 realm for this context
 *
 */

const char *gensec_get_realm(struct gensec_security *gensec_security) 
{
	if (gensec_security->user.realm) {
		return gensec_security->user.realm;
	} else if (gensec_security->user.domain) {
		return gensec_security->user.domain;
	}
	return gensec_security->default_user.realm;
}

/** 
 * Return a kerberos principal for this context, if one has been set 
 *
 */

char *gensec_get_client_principal(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx) 
{
	const char *realm = gensec_get_realm(gensec_security);
	if (realm) {
		return talloc_asprintf(mem_ctx, "%s@%s", 
				       gensec_get_username(gensec_security), 
				       gensec_get_realm(gensec_security));
	} else {
		return talloc_strdup(mem_ctx, gensec_get_username(gensec_security));
	}
}

/** 
 * Set the password outright on GENSEC context - ensures it is talloc()ed, and that we will
 * not do a callback
 *
 */

NTSTATUS gensec_set_password(struct gensec_security *gensec_security,
			     const char *password) 
{
	gensec_security->user.password = talloc_strdup(gensec_security, password);
	if (!gensec_security->user.password) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set the target principal name (if already known) on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_target_principal(struct gensec_security *gensec_security, const char *principal) 
{
	gensec_security->target.principal = talloc_strdup(gensec_security, principal);
	if (!gensec_security->target.principal) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set the target service (such as 'http' or 'host') on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_target_service(struct gensec_security *gensec_security, const char *service) 
{
	gensec_security->target.service = talloc_strdup(gensec_security, service);
	if (!gensec_security->target.service) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set the target hostname (suitable for kerberos resolutation) on a GENSEC context - ensures it is talloc()ed 
 *
 */

NTSTATUS gensec_set_target_hostname(struct gensec_security *gensec_security, const char *hostname) 
{
	gensec_security->target.hostname = talloc_strdup(gensec_security, hostname);
	if (!gensec_security->target.hostname) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

const char *gensec_get_target_hostname(struct gensec_security *gensec_security) 
{
	if (gensec_security->target.hostname) {
		return gensec_security->target.hostname;
	}

	/* TODO: Add a 'set sockaddr' call, and do a reverse lookup */
	return NULL;
}

const char *gensec_get_target_service(struct gensec_security *gensec_security) 
{
	if (gensec_security->target.service) {
		return gensec_security->target.service;
	}

	return "host";
}

/** 
 * Set a password callback, if the gensec module we use demands a password
 */

void gensec_set_password_callback(struct gensec_security *gensec_security, 
				  gensec_password_callback callback, void *callback_private_data) 
{
	gensec_security->password_callback = callback;
	gensec_security->password_callback_private = callback_private_data;
}

/**
 * Get (or call back for) a password.
 */

NTSTATUS gensec_get_password(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx, 
			     char **password) 
{
	if (gensec_security->user.password) {
		*password = talloc_strdup(mem_ctx, gensec_security->user.password);
		if (!*password) {
			return NT_STATUS_NO_MEMORY;
		} else {
			return NT_STATUS_OK;
		}
	}
	if (!gensec_security->password_callback) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return gensec_security->password_callback(gensec_security, mem_ctx, password);
}

/*
  register a GENSEC backend. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.
*/
static NTSTATUS gensec_register(const void *_ops)
{
	const struct gensec_security_ops *ops = _ops;
	
	if (!lp_parm_bool(-1, "gensec", ops->name, True)) {
		DEBUG(2,("gensec subsystem %s is disabled\n", ops->name));
		return NT_STATUS_OK;
	}

	if (gensec_security_by_name(ops->name) != NULL) {
		/* its already registered! */
		DEBUG(0,("GENSEC backend '%s' already registered\n", 
			 ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	generic_security_ops = Realloc(generic_security_ops, sizeof(generic_security_ops[0]) * (gensec_num_backends+1));
	if (!generic_security_ops) {
		smb_panic("out of memory in gensec_register");
	}

	generic_security_ops[gensec_num_backends] = ops;

	gensec_num_backends++;

	DEBUG(3,("GENSEC backend '%s' registered\n", 
		 ops->name));

	return NT_STATUS_OK;
}

/*
  return the GENSEC interface version, and the size of some critical types
  This can be used by backends to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/
const struct gensec_critical_sizes *gensec_interface_version(void)
{
	static const struct gensec_critical_sizes critical_sizes = {
		GENSEC_INTERFACE_VERSION,
		sizeof(struct gensec_security_ops),
		sizeof(struct gensec_security),
	};

	return &critical_sizes;
}

/*
  initialise the GENSEC subsystem
*/
BOOL gensec_init(void)
{
	static BOOL initialised;
	NTSTATUS status;

	/* this is *completely* the wrong way to do this */
	if (initialised) {
		return True;
	}

	status = register_subsystem("gensec", gensec_register); 
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	static_init_gensec;
	gensec_dcerpc_schannel_init();

	initialised = True;
	DEBUG(3,("GENSEC subsystem version %d initialised\n", GENSEC_INTERFACE_VERSION));
	return True;
}
