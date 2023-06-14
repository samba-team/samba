/*
   Unix SMB/CIFS implementation.
   Samba Active Directory authentication policy utility functions

   Copyright (C) Catalyst.Net Ltd 2023

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

#ifndef KDC_AUTHN_POLICY_UTIL_H
#define KDC_AUTHN_POLICY_UTIL_H

#include "lib/replace/replace.h"
#include "auth/authn_policy.h"
#include <talloc.h>

struct ldb_context;
struct loadparm_context;
struct ldb_message;

bool authn_policy_silos_and_policies_in_effect(struct ldb_context *samdb);

bool authn_policy_allowed_ntlm_network_auth_in_effect(struct ldb_context *samdb);

/*
 * Look up the silo assigned to an account. If one exists, returns its details
 * and whether it is enforced or not. ‘silo_attrs’ comprises the attributes to
 * include in the search result, the relevant set of which can differ depending
 * on the account’s objectClass.
 */
int authn_policy_get_assigned_silo(struct ldb_context *samdb,
				   TALLOC_CTX *mem_ctx,
				   const struct ldb_message *msg,
				   const char *const *silo_attrs,
				   const struct ldb_message **silo_msg_out,
				   bool *is_enforced);

struct auth_user_info_dc;

/* Authentication policies for Kerberos clients. */

/*
 * Get the applicable authentication policy for an account acting as a Kerberos
 * client.
 */
int authn_policy_kerberos_client(struct ldb_context *samdb,
				 TALLOC_CTX *mem_ctx,
				 const struct ldb_message *msg,
				 const struct authn_kerberos_client_policy **policy_out);

/*
 * Perform an access check for the device with which the client is
 * authenticating. ‘device_info’ must be talloc-allocated so that we can make a
 * reference to it.
 */
NTSTATUS authn_policy_authenticate_from_device(TALLOC_CTX *mem_ctx,
					       struct ldb_context *samdb,
					       struct loadparm_context* lp_ctx,
					       const struct auth_user_info_dc *device_info,
					       const struct authn_kerberos_client_policy *client_policy,
					       struct authn_audit_info **client_audit_info_out);

/* Return whether an authentication policy enforces device restrictions. */
bool authn_policy_device_restrictions_present(const struct authn_kerberos_client_policy *policy);

/* Authentication policies for NTLM clients. */

/*
 * Get the applicable authentication policy for an account acting as an NTLM
 * client.
 */
int authn_policy_ntlm_client(struct ldb_context *samdb,
			     TALLOC_CTX *mem_ctx,
			     const struct ldb_message *msg,
			     const struct authn_ntlm_client_policy **policy_out);

/* Authentication policies for servers. */

struct authn_server_policy;

/*
 * Get the applicable authentication policy for an account acting as a
 * server.
 */
int authn_policy_server(struct ldb_context *samdb,
			TALLOC_CTX *mem_ctx,
			const struct ldb_message *msg,
			const struct authn_server_policy **policy_out);

/* Return whether an authentication policy enforces restrictions. */
bool authn_policy_restrictions_present(const struct authn_server_policy *policy);

/* Create a structure containing auditing information. */
NTSTATUS _authn_kerberos_client_policy_audit_info(
	TALLOC_CTX *mem_ctx,
	const struct authn_kerberos_client_policy *client_policy,
	const struct auth_user_info_dc *client_info,
	enum authn_audit_event event,
	enum authn_audit_reason reason,
	NTSTATUS policy_status,
	const char *location,
	struct authn_audit_info **audit_info_out);

/* Create a structure containing auditing information. */
#define authn_kerberos_client_policy_audit_info( \
	mem_ctx, \
	policy, \
	client_info, \
	event, \
	reason, \
	policy_status, \
	audit_info_out) \
	_authn_kerberos_client_policy_audit_info( \
		mem_ctx, \
		policy, \
		client_info, \
		event, \
		reason, \
		policy_status, \
		__location__, \
		audit_info_out)

/* Create a structure containing auditing information. */
NTSTATUS _authn_ntlm_client_policy_audit_info(
	TALLOC_CTX *mem_ctx,
	const struct authn_ntlm_client_policy *policy,
	const struct auth_user_info_dc *client_info,
	enum authn_audit_event event,
	enum authn_audit_reason reason,
	NTSTATUS policy_status,
	const char *location,
	struct authn_audit_info **audit_info_out);

/* Create a structure containing auditing information. */
#define authn_ntlm_client_policy_audit_info( \
	mem_ctx, \
	policy, \
	client_info, \
	event, \
	reason, \
	policy_status, \
	audit_info_out) \
	_authn_ntlm_client_policy_audit_info( \
		mem_ctx, \
		policy, \
		client_info, \
		event, \
		reason, \
		policy_status, \
		__location__, \
		audit_info_out)

/* Create a structure containing auditing information. */
NTSTATUS _authn_server_policy_audit_info(
	TALLOC_CTX *mem_ctx,
	const struct authn_server_policy *policy,
	const struct auth_user_info_dc *client_info,
	enum authn_audit_event event,
	enum authn_audit_reason reason,
	NTSTATUS policy_status,
	const char *location,
	struct authn_audit_info **audit_info_out);

/* Create a structure containing auditing information. */
#define authn_server_policy_audit_info( \
	mem_ctx, \
	policy, \
	client_info, \
	event, \
	reason, \
	policy_status, \
	audit_info_out) \
	_authn_server_policy_audit_info( \
		mem_ctx, \
		policy, \
		client_info, \
		event, \
		reason, \
		policy_status, \
		__location__, \
		audit_info_out)

#endif
