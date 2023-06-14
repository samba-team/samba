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

#include "lib/replace/replace.h"
#include "source4/kdc/authn_policy_util.h"
#include "auth/authn_policy_impl.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "libcli/security/security.h"
#include "libcli/util/werror.h"
#include "auth/common_auth.h"
#include "source4/auth/session.h"
#include "source4/dsdb/samdb/samdb.h"
#include "source4/dsdb/samdb/ldb_modules/util.h"

bool authn_policy_silos_and_policies_in_effect(struct ldb_context *samdb)
{
	const int functional_level = dsdb_dc_functional_level(samdb);
	return functional_level >= DS_DOMAIN_FUNCTION_2012_R2;
}

bool authn_policy_allowed_ntlm_network_auth_in_effect(struct ldb_context *samdb)
{
	const int functional_level = dsdb_dc_functional_level(samdb);
	return functional_level >= DS_DOMAIN_FUNCTION_2016;
}

/*
 * Depending on the type of the account, we need to refer to different
 * attributes of authentication silo objects. This structure keeps track of the
 * attributes to use for a certain account type.
 */
struct authn_silo_attrs {
	const char *policy;
	const char *attrs[];
};

/*
 * Depending on the type of the account, we need to refer to different
 * attributes of authentication policy objects. This structure keeps track of
 * the attributes to use for a certain account type.
 */
struct authn_policy_attrs {
	/* This applies at FL2016 and up. */
	const char *allowed_ntlm_network_auth;
	/* The remainder apply at FL2012_R2 and up. */
	const char *allowed_to_authenticate_from;
	const char *allowed_to_authenticate_to;
	const char *tgt_lifetime;
	const char *attrs[];
};

struct authn_attrs {
	const struct authn_silo_attrs *silo;
	const struct authn_policy_attrs *policy;
};

/*
 * Get the authentication attributes that apply to an account of a certain
 * class.
 */
static const struct authn_attrs authn_policy_get_attrs(const struct ldb_message *msg)
{
	const struct authn_attrs null_authn_attrs = {
		.silo = NULL,
		.policy = NULL,
	};
	const struct ldb_message_element *objectclass_el = NULL;
	unsigned i;

	objectclass_el = ldb_msg_find_element(msg, "objectClass");
	if (objectclass_el == NULL || objectclass_el->num_values == 0) {
		return null_authn_attrs;
	}

	/*
	 * Iterate over the objectClasses, starting at the most-derived class.
	 */
	for (i = objectclass_el->num_values; i > 0; --i) {
		const struct ldb_val *objectclass_val = &objectclass_el->values[i - 1];
		const char *objectclass = NULL;

		objectclass = (const char *)objectclass_val->data;
		if (objectclass == NULL) {
			continue;
		}

#define COMMON_AUTHN_SILO_ATTRS \
	"msDS-AuthNPolicySiloEnforced", \
	"msDS-AuthNPolicySiloMembers", \
	"name"

#define COMMON_AUTHN_POLICY_ATTRS \
	"msDS-AuthNPolicyEnforced", \
	"msDS-StrongNTLMPolicy", \
	"name"

		/*
		 * See which of three classes this object is most closely
		 * derived from.
		 */
		if (strcasecmp(objectclass, "user") == 0) {
			static const struct authn_silo_attrs user_authn_silo_attrs = {
				.policy = "msDS-UserAuthNPolicy",
				.attrs = {
					COMMON_AUTHN_SILO_ATTRS,
					"msDS-UserAuthNPolicy",
					NULL,
				},
			};

			static const struct authn_policy_attrs user_authn_policy_attrs = {
				.allowed_ntlm_network_auth = "msDS-UserAllowedNTLMNetworkAuthentication",
				.allowed_to_authenticate_from = "msDS-UserAllowedToAuthenticateFrom",
				.allowed_to_authenticate_to = "msDS-UserAllowedToAuthenticateTo",
				.tgt_lifetime = "msDS-UserTGTLifetime",
				.attrs = {
					COMMON_AUTHN_POLICY_ATTRS,
					"msDS-UserAllowedNTLMNetworkAuthentication",
					"msDS-UserAllowedToAuthenticateFrom",
					"msDS-UserAllowedToAuthenticateTo",
					"msDS-UserTGTLifetime",
					NULL,
				},
			};

			return (struct authn_attrs) {
				.silo = &user_authn_silo_attrs,
				.policy = &user_authn_policy_attrs,
			};
		}

		if (strcasecmp(objectclass, "computer") == 0) {
			static const struct authn_silo_attrs computer_authn_silo_attrs = {
				.policy = "msDS-ComputerAuthNPolicy",
				.attrs = {
					COMMON_AUTHN_SILO_ATTRS,
					"msDS-ComputerAuthNPolicy",
					NULL,
				},
			};

			static const struct authn_policy_attrs computer_authn_policy_attrs = {
				.allowed_ntlm_network_auth = NULL,
				.allowed_to_authenticate_from = NULL,
				.allowed_to_authenticate_to = "msDS-ComputerAllowedToAuthenticateTo",
				.tgt_lifetime = "msDS-ComputerTGTLifetime",
				.attrs = {
					COMMON_AUTHN_POLICY_ATTRS,
					"msDS-ComputerAllowedToAuthenticateTo",
					"msDS-ComputerTGTLifetime",
					NULL,
				},
			};

			return (struct authn_attrs) {
				.silo = &computer_authn_silo_attrs,
				.policy = &computer_authn_policy_attrs,
			};
		}

		if (strcasecmp(objectclass, "msDS-ManagedServiceAccount") == 0) {
			static const struct authn_silo_attrs service_authn_silo_attrs = {
				.policy = "msDS-ServiceAuthNPolicy",
				.attrs = {
					COMMON_AUTHN_SILO_ATTRS,
					"msDS-ServiceAuthNPolicy",
					NULL,
				},
			};

			static const struct authn_policy_attrs service_authn_policy_attrs = {
				.allowed_ntlm_network_auth = "msDS-ServiceAllowedNTLMNetworkAuthentication",
				.allowed_to_authenticate_from = "msDS-ServiceAllowedToAuthenticateFrom",
				.allowed_to_authenticate_to = "msDS-ServiceAllowedToAuthenticateTo",
				.tgt_lifetime = "msDS-ServiceTGTLifetime",
				.attrs = {
					COMMON_AUTHN_POLICY_ATTRS,
					"msDS-ServiceAllowedNTLMNetworkAuthentication",
					"msDS-ServiceAllowedToAuthenticateFrom",
					"msDS-ServiceAllowedToAuthenticateTo",
					"msDS-ServiceTGTLifetime",
					NULL,
				},
			};

			return (struct authn_attrs) {
				.silo = &service_authn_silo_attrs,
				.policy = &service_authn_policy_attrs,
			};
		}
	}

#undef COMMON_AUTHN_SILO_ATTRS
#undef COMMON_AUTHN_POLICY_ATTRS

	/* No match — this object is not a user. */
	return null_authn_attrs;
}

/*
 * Look up the silo assigned to an account. If one exists, returns its details
 * and whether it is enforced or not. ‘silo_attrs’ comprises the attributes to
 * include in the search result, the relevant set of which can differ depending
 * on the account’s objectClass.
 */
int authn_policy_get_assigned_silo(struct ldb_context *samdb,
				   TALLOC_CTX *mem_ctx,
				   const struct ldb_message *msg,
				   const char * const *silo_attrs,
				   const struct ldb_message **silo_msg_out,
				   bool *is_enforced)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = 0;
	const struct ldb_message_element *authn_silo = NULL;
	struct ldb_dn *authn_silo_dn = NULL;
	struct ldb_message *authn_silo_msg = NULL;
	const struct ldb_message_element *members = NULL;
	const char *linearized_dn = NULL;
	struct ldb_val linearized_dn_val;

	*silo_msg_out = NULL;
	*is_enforced = true;

	if (!authn_policy_silos_and_policies_in_effect(samdb)) {
		return 0;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	authn_silo = ldb_msg_find_element(msg, "msDS-AssignedAuthNPolicySilo");
	/* Is the account assigned to a silo? */
	if (authn_silo == NULL || !authn_silo->num_values) {
		goto out;
	}

	authn_silo_dn = ldb_dn_from_ldb_val(tmp_ctx, samdb, &authn_silo->values[0]);
	if (authn_silo_dn == NULL) {
		ret = ENOMEM;
		goto out;
	}

	ret = dsdb_search_one(samdb,
			      tmp_ctx,
			      &authn_silo_msg,
			      authn_silo_dn,
			      LDB_SCOPE_BASE,
			      silo_attrs,
			      0, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* Not found. */
		ret = 0;
		goto out;
	}
	if (ret) {
		goto out;
	}

	members = ldb_msg_find_element(authn_silo_msg,
				       "msDS-AuthNPolicySiloMembers");
	if (members == NULL) {
		goto out;
	}

	linearized_dn = ldb_dn_get_linearized(msg->dn);
	if (linearized_dn == NULL) {
		ret = ENOMEM;
		goto out;
	}

	linearized_dn_val = data_blob_string_const(linearized_dn);
	/* Is the account a member of the silo? */
	if (!ldb_msg_find_val(members, &linearized_dn_val)) {
		goto out;
	}

	/* Is the silo actually enforced? */
	*is_enforced = ldb_msg_find_attr_as_bool(
		authn_silo_msg,
		"msDS-AuthNPolicySiloEnforced",
		false);

	*silo_msg_out = talloc_move(mem_ctx, &authn_silo_msg);

out:
	talloc_free(tmp_ctx);
	return ret;
}

/*
 * Look up the authentication policy assigned to an account, returning its
 * details if it exists. ‘authn_attrs’ specifies which attributes are relevant,
 * and should be chosen based on the account’s objectClass.
 */
static int samba_kdc_authn_policy_msg(struct ldb_context *samdb,
				      TALLOC_CTX *mem_ctx,
				      const struct ldb_message *msg,
				      const struct authn_attrs authn_attrs,
				      struct ldb_message **authn_policy_msg_out,
				      struct authn_policy *authn_policy_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = 0;
	const struct ldb_message *authn_silo_msg = NULL;
	const struct ldb_message_element *authn_policy = NULL;
	const char *silo_name = NULL;
	const char *policy_name = NULL;
	struct ldb_dn *authn_policy_dn = NULL;
	struct ldb_message *authn_policy_msg = NULL;
	bool belongs_to_silo = false;
	bool is_enforced = true;

	*authn_policy_msg_out = NULL;
	*authn_policy_out = (struct authn_policy) {};

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	/* See whether the account is assigned to a silo. */
	ret = authn_policy_get_assigned_silo(samdb,
					     tmp_ctx,
					     msg,
					     authn_attrs.silo->attrs,
					     &authn_silo_msg,
					     &is_enforced);
	if (ret) {
		goto out;
	}

	if (authn_silo_msg != NULL) {
		belongs_to_silo = true;

		silo_name = ldb_msg_find_attr_as_string(authn_silo_msg, "name", NULL);

		/* Get the applicable authentication policy. */
		authn_policy = ldb_msg_find_element(
			authn_silo_msg,
			authn_attrs.silo->policy);
	} else {
		/*
		 * If no silo is assigned, take the policy that is directly
		 * assigned to the account.
		 */
		authn_policy = ldb_msg_find_element(msg, "msDS-AssignedAuthNPolicy");
	}

	if (authn_policy == NULL || !authn_policy->num_values) {
		/* No policy applies; we’re done. */
		goto out;
	}

	authn_policy_dn = ldb_dn_from_ldb_val(tmp_ctx, samdb, &authn_policy->values[0]);
	if (authn_policy_dn == NULL) {
		ret = ENOMEM;
		goto out;
	}

	/* Look up the policy object. */
	ret = dsdb_search_one(samdb,
			      tmp_ctx,
			      &authn_policy_msg,
			      authn_policy_dn,
			      LDB_SCOPE_BASE,
			      authn_attrs.policy->attrs,
			      0, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* Not found. */
		ret = 0;
		goto out;
	}
	if (ret) {
		goto out;
	}

	policy_name = ldb_msg_find_attr_as_string(authn_policy_msg, "name", NULL);

	if (!belongs_to_silo) {
		is_enforced = ldb_msg_find_attr_as_bool(
			authn_policy_msg,
			"msDS-AuthNPolicyEnforced",
			false);
	}

	authn_policy_out->silo_name = talloc_move(mem_ctx, &silo_name);
	authn_policy_out->policy_name = talloc_move(mem_ctx, &policy_name);
	authn_policy_out->enforced = is_enforced;

	*authn_policy_msg_out = talloc_move(mem_ctx, &authn_policy_msg);

out:
	talloc_free(tmp_ctx);
	return ret;
}

/*
 * Reference an existing authentication policy onto a talloc context, returning
 * ‘true’ on success.
 */
static bool authn_policy_ref(TALLOC_CTX *mem_ctx,
			     struct authn_policy *policy_out,
			     const struct authn_policy *policy)
{
	const char *silo_name = NULL;
	const char *policy_name = NULL;

	if (policy->silo_name != NULL) {
		silo_name = talloc_strdup(mem_ctx, policy->silo_name);
		if (silo_name == NULL) {
			return false;
		}
	}

	if (policy->policy_name != NULL) {
		policy_name = talloc_strdup(mem_ctx, policy->policy_name);
		if (policy_name == NULL) {
			/*
			 * We can’t free ‘silo_name’ here, as it is declared
			 * const. It will be freed with the parent context.
			 */
			return false;
		}
	}

	*policy_out = (struct authn_policy) {
		.silo_name = silo_name,
		.policy_name = policy_name,
		.enforced = policy->enforced,
	};

	return true;
}

/* Create a structure containing auditing information. */
static NTSTATUS _authn_policy_audit_info(TALLOC_CTX *mem_ctx,
					 const struct authn_policy *policy,
					 const struct authn_int64_optional tgt_lifetime_raw,
					 const struct auth_user_info_dc *client_info,
					 const enum authn_audit_event event,
					 const enum authn_audit_reason reason,
					 const NTSTATUS policy_status,
					 const char *location,
					 struct authn_audit_info **audit_info_out)
{
	struct authn_audit_info *audit_info = NULL;
	bool ok;

	if (audit_info_out == NULL) {
		return NT_STATUS_OK;
	}

	audit_info = talloc_zero(mem_ctx, struct authn_audit_info);
	if (audit_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (client_info != NULL) {
		/*
		 * Keep a reference to the client’s user information so that it
		 * is available to be logged later.
		 */
		audit_info->client_info = talloc_reference(audit_info, client_info);
		if (audit_info->client_info == NULL) {
			talloc_free(audit_info);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (policy != NULL) {
		audit_info->policy = talloc_zero(audit_info, struct authn_policy);
		if (audit_info->policy == NULL) {
			talloc_free(audit_info);
			return NT_STATUS_NO_MEMORY;
		}

		ok = authn_policy_ref(audit_info, audit_info->policy, policy);
		if (!ok) {
			talloc_free(audit_info);
			return NT_STATUS_NO_MEMORY;
		}
	}

	audit_info->event = event;
	audit_info->reason = reason;
	audit_info->policy_status = policy_status;
	audit_info->location = location;
	audit_info->tgt_lifetime_raw = tgt_lifetime_raw;

	*audit_info_out = audit_info;
	return NT_STATUS_OK;
}

/* Create a structure containing auditing information. */
#define authn_policy_audit_info( \
	mem_ctx, \
	policy, \
	tgt_lifetime_raw, \
	client_info, \
	event, \
	reason, \
	policy_status, \
	audit_info_out) \
	_authn_policy_audit_info( \
		mem_ctx, \
		policy, \
		tgt_lifetime_raw, \
		client_info, \
		event, \
		reason, \
		policy_status, \
		__location__, \
		audit_info_out)

/*
 * Perform an access check against the security descriptor set in an
 * authentication policy. ‘client_info’ must be talloc-allocated so that we can
 * make a reference to it.
 */
static NTSTATUS _authn_policy_access_check(TALLOC_CTX *mem_ctx,
					   struct ldb_context *samdb,
					   struct loadparm_context* lp_ctx,
					   const struct auth_user_info_dc *client_info,
					   const struct authn_policy *policy,
					   const struct authn_int64_optional tgt_lifetime_raw,
					   const enum authn_audit_event restriction_event,
					   const DATA_BLOB *descriptor_blob,
					   const char *location,
					   struct authn_audit_info **audit_info_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	NTSTATUS status2;
	enum ndr_err_code ndr_err;
	struct security_descriptor *descriptor = NULL;
	struct security_token *security_token = NULL;
	uint32_t session_info_flags =
		AUTH_SESSION_INFO_DEFAULT_GROUPS |
		AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
	const uint32_t access_desired = SEC_ADS_CONTROL_ACCESS;
	uint32_t access_granted;
	enum authn_audit_event event = restriction_event;
	enum authn_audit_reason reason = AUTHN_AUDIT_REASON_NONE;

	if (audit_info_out != NULL) {
		*audit_info_out = NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (!(client_info->info->user_flags & NETLOGON_GUEST)) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	descriptor = talloc(tmp_ctx, struct security_descriptor);
	if (descriptor == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ndr_err = ndr_pull_struct_blob(descriptor_blob,
				       tmp_ctx,
				       descriptor,
				       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("Failed to unmarshall "
			"security descriptor for authentication policy: %s\n",
			nt_errstr(status));
		reason = AUTHN_AUDIT_REASON_DESCRIPTOR_INVALID;
		goto out;
	}

	/* Require that the security descriptor has an owner set. */
	if (descriptor->owner_sid == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		reason = AUTHN_AUDIT_REASON_DESCRIPTOR_NO_OWNER;
		goto out;
	}

	status = auth_generate_security_token(tmp_ctx,
					       lp_ctx,
					       samdb,
					       client_info,
					       session_info_flags,
					       &security_token);
	if (!NT_STATUS_IS_OK(status)) {
		reason = AUTHN_AUDIT_REASON_SECURITY_TOKEN_FAILURE;
		goto out;
	}

	status = sec_access_check_ds(descriptor, security_token,
					access_desired, &access_granted,
					NULL, NULL);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		status = NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
		reason = AUTHN_AUDIT_REASON_ACCESS_DENIED;
		goto out;
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	event = AUTHN_AUDIT_EVENT_OK;
out:
	/*
	 * Create the structure with auditing information here while we have all
	 * the relevant information to hand. It will contain references to
	 * information regarding the client and the policy, to be consulted
	 * after the referents have possibly been freed.
	 */
	status2 = _authn_policy_audit_info(mem_ctx,
					   policy,
					   tgt_lifetime_raw,
					   client_info,
					   event,
					   reason,
					   status,
					   location,
					   audit_info_out);
	if (!NT_STATUS_IS_OK(status2)) {
		status = status2;
	} else if (!authn_policy_is_enforced(policy)) {
		status = NT_STATUS_OK;
	}

	talloc_free(tmp_ctx);
	return status;
}

#define authn_policy_access_check(mem_ctx, \
	samdb, \
	lp_ctx, \
	client_info, \
	policy, \
	tgt_lifetime_raw, \
	restriction_event, \
	descriptor_blob, \
	audit_info_out) \
	_authn_policy_access_check(mem_ctx, \
		samdb, \
		lp_ctx, \
		client_info, \
		policy, \
		tgt_lifetime_raw, \
		restriction_event, \
		descriptor_blob, \
		__location__, \
		audit_info_out)

/* Return an authentication policy moved onto a talloc context. */
static struct authn_policy authn_policy_move(TALLOC_CTX *mem_ctx,
					     struct authn_policy *policy)
{
	return (struct authn_policy) {
		.silo_name = talloc_move(mem_ctx, &policy->silo_name),
		.policy_name = talloc_move(mem_ctx, &policy->policy_name),
		.enforced = policy->enforced,
	};
}

/* Authentication policies for Kerberos clients. */

/*
 * Get the applicable authentication policy for an account acting as a Kerberos
 * client.
 */
int authn_policy_kerberos_client(struct ldb_context *samdb,
				 TALLOC_CTX *mem_ctx,
				 const struct ldb_message *msg,
				 const struct authn_kerberos_client_policy **policy_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = 0;
	struct authn_attrs authn_attrs;
	struct ldb_message *authn_policy_msg = NULL;
	struct authn_kerberos_client_policy *client_policy = NULL;
	struct authn_policy policy;

	*policy_out = NULL;

	if (!authn_policy_silos_and_policies_in_effect(samdb)) {
		return 0;
	}

	/*
	 * Get the silo and policy attributes that apply to objects of this
	 * account’s objectclass.
	 */
	authn_attrs = authn_policy_get_attrs(msg);
	if (authn_attrs.silo == NULL || authn_attrs.policy == NULL) {
		/*
		 * No applicable silo or policy attributes (somehow). Either
		 * this account isn’t derived from ‘user’, or the message is
		 * missing an objectClass element.
		 */
		goto out;
	}

	if (authn_attrs.policy->allowed_to_authenticate_from == NULL &&
	    authn_attrs.policy->tgt_lifetime == NULL)
	{
		/* No relevant policy attributes apply. */
		goto out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	ret = samba_kdc_authn_policy_msg(samdb,
					 tmp_ctx,
					 msg,
					 authn_attrs,
					 &authn_policy_msg,
					 &policy);
	if (ret) {
		goto out;
	}

	if (authn_policy_msg == NULL) {
		/* No policy applies. */
		goto out;
	}

	client_policy = talloc_zero(tmp_ctx, struct authn_kerberos_client_policy);
	if (client_policy == NULL) {
		ret = ENOMEM;
		goto out;
	}

	client_policy->policy = authn_policy_move(client_policy, &policy);

	if (authn_attrs.policy->allowed_to_authenticate_from != NULL) {
		const struct ldb_val *allowed_from = ldb_msg_find_ldb_val(
			authn_policy_msg,
			authn_attrs.policy->allowed_to_authenticate_from);

		if (allowed_from != NULL && allowed_from->data != NULL) {
			client_policy->allowed_to_authenticate_from = data_blob_const(
				talloc_steal(client_policy, allowed_from->data),
				allowed_from->length);
		}
	}

	if (authn_attrs.policy->tgt_lifetime != NULL) {
		client_policy->tgt_lifetime_raw = ldb_msg_find_attr_as_int64(
			authn_policy_msg,
			authn_attrs.policy->tgt_lifetime,
			0);
	}

	*policy_out = talloc_move(mem_ctx, &client_policy);

out:
	talloc_free(tmp_ctx);
	return ret;
}

/* Get device restrictions enforced by an authentication policy. */
static const DATA_BLOB *authn_policy_kerberos_device_restrictions(const struct authn_kerberos_client_policy *policy)
{
	const DATA_BLOB *restrictions = NULL;

	if (policy == NULL) {
		return NULL;
	}

	restrictions = &policy->allowed_to_authenticate_from;
	if (restrictions->data == NULL) {
		return NULL;
	}

	return restrictions;
}

/* Return whether an authentication policy enforces device restrictions. */
bool authn_policy_device_restrictions_present(const struct authn_kerberos_client_policy *policy)
{
	return authn_policy_kerberos_device_restrictions(policy) != NULL;
}

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
					       struct authn_audit_info **client_audit_info_out)
{
	NTSTATUS status = NT_STATUS_OK;
	const DATA_BLOB *restrictions = NULL;

	restrictions = authn_policy_kerberos_device_restrictions(client_policy);
	if (restrictions == NULL) {
		goto out;
	}

	status = authn_policy_access_check(mem_ctx,
					   samdb,
					   lp_ctx,
					   device_info,
					   &client_policy->policy,
					   authn_int64_some(client_policy->tgt_lifetime_raw),
					   AUTHN_AUDIT_EVENT_KERBEROS_DEVICE_RESTRICTION,
					   restrictions,
					   client_audit_info_out);
out:
	return status;
}

/* Authentication policies for NTLM clients. */

/*
 * Get the applicable authentication policy for an account acting as an NTLM
 * client.
 */
int authn_policy_ntlm_client(struct ldb_context *samdb,
			     TALLOC_CTX *mem_ctx,
			     const struct ldb_message *msg,
			     const struct authn_ntlm_client_policy **policy_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = 0;
	struct authn_attrs authn_attrs;
	struct ldb_message *authn_policy_msg = NULL;
	struct authn_ntlm_client_policy *client_policy = NULL;
	struct authn_policy policy;

	*policy_out = NULL;

	if (!authn_policy_silos_and_policies_in_effect(samdb)) {
		return 0;
	}

	/*
	 * Get the silo and policy attributes that apply to objects of this
	 * account’s objectclass.
	 */
	authn_attrs = authn_policy_get_attrs(msg);
	if (authn_attrs.silo == NULL || authn_attrs.policy == NULL) {
		/*
		 * No applicable silo or policy attributes (somehow). Either
		 * this account isn’t derived from ‘user’, or the message is
		 * missing an objectClass element.
		 */
		goto out;
	}

	if (authn_attrs.policy->allowed_to_authenticate_from == NULL &&
	    authn_attrs.policy->allowed_ntlm_network_auth == NULL)
	{
		/* No relevant policy attributes apply. */
		goto out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	ret = samba_kdc_authn_policy_msg(samdb,
					 tmp_ctx,
					 msg,
					 authn_attrs,
					 &authn_policy_msg,
					 &policy);
	if (ret) {
		goto out;
	}

	if (authn_policy_msg == NULL) {
		/* No policy applies. */
		goto out;
	}

	client_policy = talloc_zero(tmp_ctx, struct authn_ntlm_client_policy);
	if (client_policy == NULL) {
		ret = ENOMEM;
		goto out;
	}

	client_policy->policy = authn_policy_move(client_policy, &policy);

	if (authn_attrs.policy->allowed_to_authenticate_from != NULL) {
		const struct ldb_val *allowed_from = ldb_msg_find_ldb_val(
			authn_policy_msg,
			authn_attrs.policy->allowed_to_authenticate_from);

		if (allowed_from != NULL && allowed_from->data != NULL) {
			client_policy->allowed_to_authenticate_from = data_blob_const(
				talloc_steal(client_policy, allowed_from->data),
				allowed_from->length);
		}
	}

	if (authn_attrs.policy->allowed_ntlm_network_auth != NULL &&
	    authn_policy_allowed_ntlm_network_auth_in_effect(samdb))
	{
		client_policy->allowed_ntlm_network_auth = ldb_msg_find_attr_as_bool(
			authn_policy_msg,
			authn_attrs.policy->allowed_ntlm_network_auth,
			false);
	}

	*policy_out = talloc_move(mem_ctx, &client_policy);

out:
	talloc_free(tmp_ctx);
	return ret;
}

/* Return whether an authentication policy enforces device restrictions. */
static bool authn_policy_ntlm_device_restrictions_present(const struct authn_ntlm_client_policy *policy)
{
	if (policy == NULL) {
		return false;
	}

	return policy->allowed_to_authenticate_from.data != NULL;
}

/* Check whether the client is allowed to authenticate using NTLM. */
NTSTATUS authn_policy_ntlm_apply_device_restriction(TALLOC_CTX *mem_ctx,
						    const struct authn_ntlm_client_policy *client_policy,
						    struct authn_audit_info **client_audit_info_out)
{
	NTSTATUS status;
	NTSTATUS status2;

	if (client_audit_info_out != NULL) {
		*client_audit_info_out = NULL;
	}

	if (client_policy == NULL) {
		return NT_STATUS_OK;
	}

	/*
	 * Access control restrictions cannot be applied to NTLM.
	 *
	 * If NTLM authentication is disallowed and the policy enforces a device
	 * restriction, deny the authentication.
	 */

	if (!authn_policy_ntlm_device_restrictions_present(client_policy)) {
		return authn_policy_audit_info(mem_ctx,
					       &client_policy->policy,
					       authn_int64_none() /* tgt_lifetime_raw */,
					       NULL /* client_info */,
					       AUTHN_AUDIT_EVENT_OK,
					       AUTHN_AUDIT_REASON_NONE,
					       NT_STATUS_OK,
					       client_audit_info_out);
	}

	/*
	 * (Although MS-APDS doesn’t state it, AllowedNTLMNetworkAuthentication
	 * applies to interactive logons too.)
	 */
	if (client_policy->allowed_ntlm_network_auth) {
		return authn_policy_audit_info(mem_ctx,
					       &client_policy->policy,
					       authn_int64_none() /* tgt_lifetime_raw */,
					       NULL /* client_info */,
					       AUTHN_AUDIT_EVENT_OK,
					       AUTHN_AUDIT_REASON_NONE,
					       NT_STATUS_OK,
					       client_audit_info_out);
	}

	status = NT_STATUS_ACCOUNT_RESTRICTION;
	status2 = authn_policy_audit_info(mem_ctx,
					  &client_policy->policy,
					  authn_int64_none() /* tgt_lifetime_raw */,
					  NULL /* client_info */,
					  AUTHN_AUDIT_EVENT_NTLM_DEVICE_RESTRICTION,
					  AUTHN_AUDIT_REASON_NONE,
					  status,
					  client_audit_info_out);
	if (!NT_STATUS_IS_OK(status2)) {
		status = status2;
	} else if (!authn_policy_is_enforced(&client_policy->policy)) {
		status = NT_STATUS_OK;
	}

	return status;
}

/* Authentication policies for servers. */

/*
 * Get the applicable authentication policy for an account acting as a
 * server.
 */
int authn_policy_server(struct ldb_context *samdb,
			TALLOC_CTX *mem_ctx,
			const struct ldb_message *msg,
			const struct authn_server_policy **policy_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = 0;
	struct authn_attrs authn_attrs;
	struct ldb_message *authn_policy_msg = NULL;
	struct authn_server_policy *server_policy = NULL;
	struct authn_policy policy;

	*policy_out = NULL;

	if (!authn_policy_silos_and_policies_in_effect(samdb)) {
		return 0;
	}

	/*
	 * Get the silo and policy attributes that apply to objects of this
	 * account’s objectclass.
	 */
	authn_attrs = authn_policy_get_attrs(msg);
	if (authn_attrs.silo == NULL || authn_attrs.policy == NULL) {
		/*
		 * No applicable silo or policy attributes (somehow). Either
		 * this account isn’t derived from ‘user’, or the message is
		 * missing an objectClass element.
		 */
		goto out;
	}

	if (authn_attrs.policy->allowed_to_authenticate_to == NULL) {
		/* The relevant policy attribute doesn’t apply. */
		goto out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	ret = samba_kdc_authn_policy_msg(samdb,
					 tmp_ctx,
					 msg,
					 authn_attrs,
					 &authn_policy_msg,
					 &policy);
	if (ret) {
		goto out;
	}

	if (authn_policy_msg == NULL) {
		/* No policy applies. */
		goto out;
	}

	server_policy = talloc_zero(tmp_ctx, struct authn_server_policy);
	if (server_policy == NULL) {
		ret = ENOMEM;
		goto out;
	}

	server_policy->policy = authn_policy_move(server_policy, &policy);

	if (authn_attrs.policy->allowed_to_authenticate_to != NULL) {
		const struct ldb_val *allowed_to = ldb_msg_find_ldb_val(
			authn_policy_msg,
			authn_attrs.policy->allowed_to_authenticate_to);

		if (allowed_to != NULL && allowed_to->data != NULL) {
			server_policy->allowed_to_authenticate_to = data_blob_const(
				talloc_steal(server_policy, allowed_to->data),
				allowed_to->length);
		}
	}

	*policy_out = talloc_move(mem_ctx, &server_policy);

out:
	talloc_free(tmp_ctx);
	return ret;
}

/* Get restrictions enforced by an authentication policy. */
static const DATA_BLOB *authn_policy_restrictions(const struct authn_server_policy *policy)
{
	const DATA_BLOB *restrictions = NULL;

	if (policy == NULL) {
		return NULL;
	}

	restrictions = &policy->allowed_to_authenticate_to;
	if (restrictions->data == NULL) {
		return NULL;
	}

	return restrictions;
}

/* Return whether an authentication policy enforces restrictions. */
bool authn_policy_restrictions_present(const struct authn_server_policy *policy)
{
	return authn_policy_restrictions(policy) != NULL;
}

/*
 * Perform an access check for the client attempting to authenticate to the
 * server. ‘user_info’ must be talloc-allocated so that we can make a reference
 * to it.
 */
NTSTATUS authn_policy_authenticate_to_service(TALLOC_CTX *mem_ctx,
					      struct ldb_context *samdb,
					      struct loadparm_context* lp_ctx,
					      const enum authn_policy_auth_type auth_type,
					      const struct auth_user_info_dc *user_info,
					      const struct authn_server_policy *server_policy,
					      struct authn_audit_info **server_audit_info_out)
{
	NTSTATUS status = NT_STATUS_OK;
	const DATA_BLOB *restrictions = NULL;
	enum authn_audit_event event;

	restrictions = authn_policy_restrictions(server_policy);
	if (restrictions == NULL) {
		return authn_server_policy_audit_info(mem_ctx,
						      server_policy,
						      user_info,
						      AUTHN_AUDIT_EVENT_OK,
						      AUTHN_AUDIT_REASON_NONE,
						      NT_STATUS_OK,
						      server_audit_info_out);
	}

	switch (auth_type) {
	case AUTHN_POLICY_AUTH_TYPE_KERBEROS:
		event = AUTHN_AUDIT_EVENT_KERBEROS_SERVER_RESTRICTION;
		break;
	case AUTHN_POLICY_AUTH_TYPE_NTLM:
		event = AUTHN_AUDIT_EVENT_NTLM_SERVER_RESTRICTION;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER_4;
	}

	status = authn_policy_access_check(mem_ctx,
					   samdb,
					   lp_ctx,
					   user_info,
					   &server_policy->policy,
					   authn_int64_none() /* tgt_lifetime_raw */,
					   event,
					   restrictions,
					   server_audit_info_out);
	return status;
}

/* Create a structure containing auditing information. */
NTSTATUS _authn_kerberos_client_policy_audit_info(
	TALLOC_CTX *mem_ctx,
	const struct authn_kerberos_client_policy *client_policy,
	const struct auth_user_info_dc *client_info,
	const enum authn_audit_event event,
	const enum authn_audit_reason reason,
	const NTSTATUS policy_status,
	const char *location,
	struct authn_audit_info **audit_info_out)
{
	const struct authn_policy *policy = NULL;
	struct authn_int64_optional tgt_lifetime_raw = authn_int64_none();

	if (client_policy != NULL) {
		policy = &client_policy->policy;
		tgt_lifetime_raw = authn_int64_some(client_policy->tgt_lifetime_raw);
	}

	return _authn_policy_audit_info(mem_ctx,
					policy,
					tgt_lifetime_raw,
					client_info,
					event,
					reason,
					policy_status,
					location,
					audit_info_out);
}

/* Create a structure containing auditing information. */
NTSTATUS _authn_ntlm_client_policy_audit_info(
	TALLOC_CTX *mem_ctx,
	const struct authn_ntlm_client_policy *client_policy,
	const struct auth_user_info_dc *client_info,
	const enum authn_audit_event event,
	const enum authn_audit_reason reason,
	const NTSTATUS policy_status,
	const char *location,
	struct authn_audit_info **audit_info_out)
{
	const struct authn_policy *policy = NULL;

	if (client_policy != NULL) {
		policy = &client_policy->policy;
	}

	return _authn_policy_audit_info(mem_ctx,
					policy,
					authn_int64_none() /* tgt_lifetime_raw */,
					client_info,
					event,
					reason,
					policy_status,
					location,
					audit_info_out);
}

/* Create a structure containing auditing information. */
NTSTATUS _authn_server_policy_audit_info(
	TALLOC_CTX *mem_ctx,
	const struct authn_server_policy *server_policy,
	const struct auth_user_info_dc *client_info,
	const enum authn_audit_event event,
	const enum authn_audit_reason reason,
	const NTSTATUS policy_status,
	const char *location,
	struct authn_audit_info **audit_info_out)
{
	const struct authn_policy *policy = NULL;

	if (server_policy != NULL) {
		policy = &server_policy->policy;
	}

	return _authn_policy_audit_info(mem_ctx,
					policy,
					authn_int64_none() /* tgt_lifetime_raw */,
					client_info,
					event,
					reason,
					policy_status,
					location,
					audit_info_out);
}
