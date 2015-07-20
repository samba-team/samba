/*
   Unix SMB/CIFS implementation.

   module to store/fetch session keys for the schannel client

   Copyright (C) Stefan Metzmacher 2013

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

#ifndef NETLOGON_CREDS_CLI_H
#define NETLOGON_CREDS_CLI_H

#include "librpc/gen_ndr/dcerpc.h"
#include "librpc/gen_ndr/schannel.h"

struct netlogon_creds_cli_context;
struct cli_credentials;
struct messaging_context;
struct dcerpc_binding_handle;
struct db_context;

NTSTATUS netlogon_creds_cli_set_global_db(struct db_context **db);
NTSTATUS netlogon_creds_cli_open_global_db(struct loadparm_context *lp_ctx);
void netlogon_creds_cli_close_global_db(void);

NTSTATUS netlogon_creds_cli_context_global(struct loadparm_context *lp_ctx,
				struct messaging_context *msg_ctx,
				const char *client_account,
				enum netr_SchannelType type,
				const char *server_computer,
				const char *server_netbios_domain,
				const char *server_dns_domain,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_cli_context **_context);
NTSTATUS netlogon_creds_bind_cli_credentials(
	struct netlogon_creds_cli_context *context, TALLOC_CTX *mem_ctx,
	struct cli_credentials **pcli_creds);

char *netlogon_creds_cli_debug_string(
		const struct netlogon_creds_cli_context *context,
		TALLOC_CTX *mem_ctx);

enum dcerpc_AuthLevel netlogon_creds_cli_auth_level(
		struct netlogon_creds_cli_context *context);

NTSTATUS netlogon_creds_cli_get(struct netlogon_creds_cli_context *context,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_CredentialState **_creds);
bool netlogon_creds_cli_validate(struct netlogon_creds_cli_context *context,
			const struct netlogon_creds_CredentialState *creds1);

NTSTATUS netlogon_creds_cli_store(struct netlogon_creds_cli_context *context,
				  struct netlogon_creds_CredentialState *creds);
NTSTATUS netlogon_creds_cli_delete(struct netlogon_creds_cli_context *context,
				   struct netlogon_creds_CredentialState *creds);
NTSTATUS netlogon_creds_cli_delete_lck(
	struct netlogon_creds_cli_context *context);

struct tevent_req *netlogon_creds_cli_lock_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context);
NTSTATUS netlogon_creds_cli_lock_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			struct netlogon_creds_CredentialState **creds);
NTSTATUS netlogon_creds_cli_lock(struct netlogon_creds_cli_context *context,
			TALLOC_CTX *mem_ctx,
			struct netlogon_creds_CredentialState **creds);

struct netlogon_creds_cli_lck;

enum netlogon_creds_cli_lck_type {
	NETLOGON_CREDS_CLI_LCK_NONE,
	NETLOGON_CREDS_CLI_LCK_SHARED,
	NETLOGON_CREDS_CLI_LCK_EXCLUSIVE,
};

struct tevent_req *netlogon_creds_cli_lck_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct netlogon_creds_cli_context *context,
	enum netlogon_creds_cli_lck_type type);
NTSTATUS netlogon_creds_cli_lck_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx,
	struct netlogon_creds_cli_lck **lck);
NTSTATUS netlogon_creds_cli_lck(
	struct netlogon_creds_cli_context *context,
	enum netlogon_creds_cli_lck_type type,
	TALLOC_CTX *mem_ctx, struct netlogon_creds_cli_lck **lck);

struct tevent_req *netlogon_creds_cli_auth_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				uint8_t num_nt_hashes,
				const struct samr_Password * const *nt_hashes);
NTSTATUS netlogon_creds_cli_auth_recv(struct tevent_req *req,
				      uint8_t *idx_nt_hashes);
NTSTATUS netlogon_creds_cli_auth(struct netlogon_creds_cli_context *context,
				 struct dcerpc_binding_handle *b,
				 uint8_t num_nt_hashes,
				 const struct samr_Password * const *nt_hashes,
				 uint8_t *idx_nt_hashes);

struct tevent_req *netlogon_creds_cli_check_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b);
NTSTATUS netlogon_creds_cli_check_recv(struct tevent_req *req,
				       union netr_Capabilities *capabilities);
NTSTATUS netlogon_creds_cli_check(struct netlogon_creds_cli_context *context,
				  struct dcerpc_binding_handle *b,
				  union netr_Capabilities *capabilities);

struct tevent_req *netlogon_creds_cli_ServerPasswordSet_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				const DATA_BLOB *new_password,
				const uint32_t *new_version);
NTSTATUS netlogon_creds_cli_ServerPasswordSet_recv(struct tevent_req *req);
NTSTATUS netlogon_creds_cli_ServerPasswordSet(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				const DATA_BLOB *new_password,
				const uint32_t *new_version);

struct tevent_req *netlogon_creds_cli_LogonSamLogon_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				enum netr_LogonInfoClass logon_level,
				const union netr_LogonLevel *logon,
				uint32_t flags);
NTSTATUS netlogon_creds_cli_LogonSamLogon_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint16_t *validation_level,
					union netr_Validation **validation,
					uint8_t *authoritative,
					uint32_t *flags);
NTSTATUS netlogon_creds_cli_LogonSamLogon(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				enum netr_LogonInfoClass logon_level,
				const union netr_LogonLevel *logon,
				TALLOC_CTX *mem_ctx,
				uint16_t *validation_level,
				union netr_Validation **validation,
				uint8_t *authoritative,
				uint32_t *flags);
struct tevent_req *netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_send(TALLOC_CTX *mem_ctx,
									     struct tevent_context *ev,
									     struct netlogon_creds_cli_context *context,
									     struct dcerpc_binding_handle *b,
									     const char *site_name,
									     uint32_t dns_ttl,
									     struct NL_DNS_NAME_INFO_ARRAY *dns_names);
NTSTATUS netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_recv(struct tevent_req *req);
NTSTATUS netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				const char *site_name,
				uint32_t dns_ttl,
				struct NL_DNS_NAME_INFO_ARRAY *dns_names);

struct tevent_req *netlogon_creds_cli_ServerGetTrustInfo_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct netlogon_creds_cli_context *context,
					struct dcerpc_binding_handle *b);
NTSTATUS netlogon_creds_cli_ServerGetTrustInfo_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					struct samr_Password *new_owf_password,
					struct samr_Password *old_owf_password,
					struct netr_TrustInfo **trust_info);
NTSTATUS netlogon_creds_cli_ServerGetTrustInfo(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				TALLOC_CTX *mem_ctx,
				struct samr_Password *new_owf_password,
				struct samr_Password *old_owf_password,
				struct netr_TrustInfo **trust_info);

struct tevent_req *netlogon_creds_cli_GetForestTrustInformation_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct netlogon_creds_cli_context *context,
					struct dcerpc_binding_handle *b);
NTSTATUS netlogon_creds_cli_GetForestTrustInformation_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			struct lsa_ForestTrustInformation **forest_trust_info);
NTSTATUS netlogon_creds_cli_GetForestTrustInformation(
			struct netlogon_creds_cli_context *context,
			struct dcerpc_binding_handle *b,
			TALLOC_CTX *mem_ctx,
			struct lsa_ForestTrustInformation **forest_trust_info);

struct tevent_req *netlogon_creds_cli_SendToSam_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     struct netlogon_creds_cli_context *context,
						     struct dcerpc_binding_handle *b,
						     struct netr_SendToSamBase *message);

NTSTATUS netlogon_creds_cli_SendToSam(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				struct netr_SendToSamBase *message);

struct tevent_req *netlogon_creds_cli_LogonGetDomainInfo_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct netlogon_creds_cli_context *context,
					struct dcerpc_binding_handle *b,
					uint32_t level,
					union netr_WorkstationInfo *query);
NTSTATUS netlogon_creds_cli_LogonGetDomainInfo_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			union netr_DomainInfo **info);
NTSTATUS netlogon_creds_cli_LogonGetDomainInfo(
			struct netlogon_creds_cli_context *context,
			struct dcerpc_binding_handle *b,
			TALLOC_CTX *mem_ctx,
			uint32_t level,
			union netr_WorkstationInfo *query,
			union netr_DomainInfo **info);

#endif /* NETLOGON_CREDS_CLI_H */
