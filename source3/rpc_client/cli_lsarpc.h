/* The following definitions come from rpc_client/cli_lsarpc.c  */

/**
 * @brief Open a LSA policy.
 *
 * @param[in]  h        The dcerpc binding hanlde to use.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  sec_qos  Enable security quality of services.
 *
 * @param[in]  des_access The disired access rights to be granted.
 *
 * @param[out]  pol     A pointer to a rpc policy handle.
 *
 * @param[out]  result  A pointer for the NDR NTSTATUS error code.
 *
 * @return              A corresponding NTSTATUS error code for the connection.
 */
NTSTATUS dcerpc_lsa_open_policy(struct dcerpc_binding_handle *h,
				TALLOC_CTX *mem_ctx,
				bool sec_qos,
				uint32_t des_access,
				struct policy_handle *pol,
				NTSTATUS *result);
NTSTATUS rpccli_lsa_open_policy(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				bool sec_qos, uint32 des_access,
				struct policy_handle *pol);

NTSTATUS rpccli_lsa_open_policy2(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx, bool sec_qos,
				 uint32 des_access, struct policy_handle *pol);
NTSTATUS rpccli_lsa_lookup_sids(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *pol,
				int num_sids,
				const struct dom_sid *sids,
				char ***pdomains,
				char ***pnames,
				enum lsa_SidType **ptypes);
NTSTATUS rpccli_lsa_lookup_sids3(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *pol,
				 int num_sids,
				 const struct dom_sid *sids,
				 char ***pdomains,
				 char ***pnames,
				 enum lsa_SidType **ptypes);
NTSTATUS rpccli_lsa_lookup_names(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *pol, int num_names,
				 const char **names,
				 const char ***dom_names,
				 int level,
				 struct dom_sid **sids,
				 enum lsa_SidType **types);
NTSTATUS rpccli_lsa_lookup_names4(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  struct policy_handle *pol, int num_names,
				  const char **names,
				  const char ***dom_names,
				  int level,
				  struct dom_sid **sids,
				  enum lsa_SidType **types);

bool fetch_domain_sid( char *domain, char *remote_machine, struct dom_sid *psid);

