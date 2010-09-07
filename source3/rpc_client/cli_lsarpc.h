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
NTSTATUS dcerpc_lsa_open_policy2(struct dcerpc_binding_handle *h,
				 TALLOC_CTX *mem_ctx,
				 const char *srv_name_slash,
				 bool sec_qos,
				 uint32_t des_access,
				 struct policy_handle *pol,
				 NTSTATUS *result);
NTSTATUS rpccli_lsa_open_policy2(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx, bool sec_qos,
				 uint32 des_access, struct policy_handle *pol);

/**
 * @brief Look up the names that correspond to an array of sids.
 *
 * @param[in]  h        The initialized binding handle for a dcerpc connection.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  pol      The opened domain policy handle.
 *
 * @param[in]  num_sids The number of sids in the sids array to look up.
 *
 * @param[in]  sids     The array of sids to look up.
 *
 * @param[out]  pdomains A pointer to store the refercenced domains.
 *
 * @param[out]  pnames  A pointer to an array for the translated names.
 *
 * @param[out]  ptypes  A pointer to an array for the types of the names.
 *
 * @param[out]  result  A pointer for the conversion result.
 *
 * @return              A corresponding NTSTATUS error code.
 */
NTSTATUS dcerpc_lsa_lookup_sids(struct dcerpc_binding_handle *h,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *pol,
				int num_sids,
				const struct dom_sid *sids,
				char ***pdomains,
				char ***pnames,
				enum lsa_SidType **ptypes,
				NTSTATUS *result);
NTSTATUS rpccli_lsa_lookup_sids(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *pol,
				int num_sids,
				const struct dom_sid *sids,
				char ***pdomains,
				char ***pnames,
				enum lsa_SidType **ptypes);

/**
 * @brief Look up the names that correspond to an array of sids.
 *
 * @param[in]  h        The initialized binding handle for a dcerpc connection.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  pol      The opened domain policy handle.
 *
 * @param[in]  num_sids The number of sids in the sids array to look up.
 *
 * @param[in]  sids     The array of sids to look up.
 *
 * @param[out]  pdomains A pointer to store the refercenced domains.
 *
 * @param[out]  pnames  A pointer to an array for the translated names.
 *
 * @param[out]  ptypes  A pointer to an array for the types of the names.
 *
 * @param[out]  result  A pointer for the conversion result.
 *
 * @return              A corresponding NTSTATUS error code.
 */
NTSTATUS dcerpc_lsa_lookup_sids3(struct dcerpc_binding_handle *h,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *pol,
				 int num_sids,
				 const struct dom_sid *sids,
				 char ***pdomains,
				 char ***pnames,
				 enum lsa_SidType **ptypes,
				 NTSTATUS *result);
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

