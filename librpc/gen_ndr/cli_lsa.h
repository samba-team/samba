#include "../librpc/gen_ndr/ndr_lsa.h"
#ifndef __CLI_LSARPC__
#define __CLI_LSARPC__
NTSTATUS rpccli_lsa_Close(struct rpc_pipe_client *cli,
			  TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle /* [in,out] [ref] */);
NTSTATUS rpccli_lsa_Delete(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   struct policy_handle *handle /* [in] [ref] */);
NTSTATUS rpccli_lsa_EnumPrivs(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      struct policy_handle *handle /* [in] [ref] */,
			      uint32_t *resume_handle /* [in,out] [ref] */,
			      struct lsa_PrivArray *privs /* [out] [ref] */,
			      uint32_t max_count /* [in]  */);
NTSTATUS rpccli_lsa_QuerySecurity(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  struct policy_handle *handle /* [in] [ref] */,
				  uint32_t sec_info /* [in]  */,
				  struct sec_desc_buf **sdbuf /* [out] [ref] */);
NTSTATUS rpccli_lsa_SetSecObj(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      struct policy_handle *handle /* [in] [ref] */,
			      uint32_t sec_info /* [in]  */,
			      struct sec_desc_buf *sdbuf /* [in] [ref] */);
NTSTATUS rpccli_lsa_ChangePassword(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_OpenPolicy(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       uint16_t *system_name /* [in] [unique] */,
			       struct lsa_ObjectAttribute *attr /* [in] [ref] */,
			       uint32_t access_mask /* [in]  */,
			       struct policy_handle *handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_QueryInfoPolicy(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    struct policy_handle *handle /* [in] [ref] */,
				    enum lsa_PolicyInfo level /* [in]  */,
				    union lsa_PolicyInformation **info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_SetInfoPolicy(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  struct policy_handle *handle /* [in] [ref] */,
				  enum lsa_PolicyInfo level /* [in]  */,
				  union lsa_PolicyInformation *info /* [in] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_ClearAuditLog(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CreateAccount(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  struct policy_handle *handle /* [in] [ref] */,
				  struct dom_sid2 *sid /* [in] [ref] */,
				  uint32_t access_mask /* [in]  */,
				  struct policy_handle *acct_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_EnumAccounts(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle /* [in] [ref] */,
				 uint32_t *resume_handle /* [in,out] [ref] */,
				 struct lsa_SidArray *sids /* [out] [ref] */,
				 uint32_t num_entries /* [in] [range(0,8192)] */);
NTSTATUS rpccli_lsa_CreateTrustedDomain(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					struct policy_handle *policy_handle /* [in] [ref] */,
					struct lsa_DomainInfo *info /* [in] [ref] */,
					uint32_t access_mask /* [in]  */,
					struct policy_handle *trustdom_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_EnumTrustDom(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle /* [in] [ref] */,
				 uint32_t *resume_handle /* [in,out] [ref] */,
				 struct lsa_DomainList *domains /* [out] [ref] */,
				 uint32_t max_size /* [in]  */);
NTSTATUS rpccli_lsa_LookupNames(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *handle /* [in] [ref] */,
				uint32_t num_names /* [in] [range(0,1000)] */,
				struct lsa_String *names /* [in] [size_is(num_names)] */,
				struct lsa_RefDomainList **domains /* [out] [ref] */,
				struct lsa_TransSidArray *sids /* [in,out] [ref] */,
				enum lsa_LookupNamesLevel level /* [in]  */,
				uint32_t *count /* [in,out] [ref] */);
NTSTATUS rpccli_lsa_LookupSids(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle /* [in] [ref] */,
			       struct lsa_SidArray *sids /* [in] [ref] */,
			       struct lsa_RefDomainList **domains /* [out] [ref] */,
			       struct lsa_TransNameArray *names /* [in,out] [ref] */,
			       uint16_t level /* [in]  */,
			       uint32_t *count /* [in,out] [ref] */);
NTSTATUS rpccli_lsa_CreateSecret(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle /* [in] [ref] */,
				 struct lsa_String name /* [in]  */,
				 uint32_t access_mask /* [in]  */,
				 struct policy_handle *sec_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_OpenAccount(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *handle /* [in] [ref] */,
				struct dom_sid2 *sid /* [in] [ref] */,
				uint32_t access_mask /* [in]  */,
				struct policy_handle *acct_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_EnumPrivsAccount(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct policy_handle *handle /* [in] [ref] */,
				     struct lsa_PrivilegeSet **privs /* [out] [ref] */);
NTSTATUS rpccli_lsa_AddPrivilegesToAccount(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   struct policy_handle *handle /* [in] [ref] */,
					   struct lsa_PrivilegeSet *privs /* [in] [ref] */);
NTSTATUS rpccli_lsa_RemovePrivilegesFromAccount(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx,
						struct policy_handle *handle /* [in] [ref] */,
						uint8_t remove_all /* [in]  */,
						struct lsa_PrivilegeSet *privs /* [in] [unique] */);
NTSTATUS rpccli_lsa_GetQuotasForAccount(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_SetQuotasForAccount(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_GetSystemAccessAccount(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   struct policy_handle *handle /* [in] [ref] */,
					   uint32_t *access_mask /* [out] [ref] */);
NTSTATUS rpccli_lsa_SetSystemAccessAccount(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   struct policy_handle *handle /* [in] [ref] */,
					   uint32_t access_mask /* [in]  */);
NTSTATUS rpccli_lsa_OpenTrustedDomain(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      struct policy_handle *handle /* [in] [ref] */,
				      struct dom_sid2 *sid /* [in] [ref] */,
				      uint32_t access_mask /* [in]  */,
				      struct policy_handle *trustdom_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_QueryTrustedDomainInfo(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   struct policy_handle *trustdom_handle /* [in] [ref] */,
					   enum lsa_TrustDomInfoEnum level /* [in]  */,
					   union lsa_TrustedDomainInfo **info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_SetInformationTrustedDomain(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx,
						struct policy_handle *trustdom_handle /* [in] [ref] */,
						enum lsa_TrustDomInfoEnum level /* [in]  */,
						union lsa_TrustedDomainInfo *info /* [in] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_OpenSecret(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle /* [in] [ref] */,
			       struct lsa_String name /* [in]  */,
			       uint32_t access_mask /* [in]  */,
			       struct policy_handle *sec_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_SetSecret(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      struct policy_handle *sec_handle /* [in] [ref] */,
			      struct lsa_DATA_BUF *new_val /* [in] [unique] */,
			      struct lsa_DATA_BUF *old_val /* [in] [unique] */);
NTSTATUS rpccli_lsa_QuerySecret(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *sec_handle /* [in] [ref] */,
				struct lsa_DATA_BUF_PTR *new_val /* [in,out] [unique] */,
				NTTIME *new_mtime /* [in,out] [unique] */,
				struct lsa_DATA_BUF_PTR *old_val /* [in,out] [unique] */,
				NTTIME *old_mtime /* [in,out] [unique] */);
NTSTATUS rpccli_lsa_LookupPrivValue(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    struct policy_handle *handle /* [in] [ref] */,
				    struct lsa_String *name /* [in] [ref] */,
				    struct lsa_LUID *luid /* [out] [ref] */);
NTSTATUS rpccli_lsa_LookupPrivName(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   struct policy_handle *handle /* [in] [ref] */,
				   struct lsa_LUID *luid /* [in] [ref] */,
				   struct lsa_StringLarge **name /* [out] [ref] */);
NTSTATUS rpccli_lsa_LookupPrivDisplayName(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  struct policy_handle *handle /* [in] [ref] */,
					  struct lsa_String *name /* [in] [ref] */,
					  uint16_t language_id /* [in]  */,
					  uint16_t language_id_sys /* [in]  */,
					  struct lsa_StringLarge **disp_name /* [out] [ref] */,
					  uint16_t *returned_language_id /* [out] [ref] */);
NTSTATUS rpccli_lsa_DeleteObject(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle /* [in,out] [ref] */);
NTSTATUS rpccli_lsa_EnumAccountsWithUserRight(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      struct policy_handle *handle /* [in] [ref] */,
					      struct lsa_String *name /* [in] [unique] */,
					      struct lsa_SidArray *sids /* [out] [ref] */);
NTSTATUS rpccli_lsa_EnumAccountRights(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      struct policy_handle *handle /* [in] [ref] */,
				      struct dom_sid2 *sid /* [in] [ref] */,
				      struct lsa_RightSet *rights /* [out] [ref] */);
NTSTATUS rpccli_lsa_AddAccountRights(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct policy_handle *handle /* [in] [ref] */,
				     struct dom_sid2 *sid /* [in] [ref] */,
				     struct lsa_RightSet *rights /* [in] [ref] */);
NTSTATUS rpccli_lsa_RemoveAccountRights(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					struct policy_handle *handle /* [in] [ref] */,
					struct dom_sid2 *sid /* [in] [ref] */,
					uint8_t remove_all /* [in]  */,
					struct lsa_RightSet *rights /* [in] [ref] */);
NTSTATUS rpccli_lsa_QueryTrustedDomainInfoBySid(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx,
						struct policy_handle *handle /* [in] [ref] */,
						struct dom_sid2 *dom_sid /* [in] [ref] */,
						enum lsa_TrustDomInfoEnum level /* [in]  */,
						union lsa_TrustedDomainInfo **info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_SetTrustedDomainInfo(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *handle /* [in] [ref] */,
					 struct dom_sid2 *dom_sid /* [in] [ref] */,
					 enum lsa_TrustDomInfoEnum level /* [in]  */,
					 union lsa_TrustedDomainInfo *info /* [in] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_DeleteTrustedDomain(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					struct policy_handle *handle /* [in] [ref] */,
					struct dom_sid2 *dom_sid /* [in] [ref] */);
NTSTATUS rpccli_lsa_StorePrivateData(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_RetrievePrivateData(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_OpenPolicy2(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				const char *system_name /* [in] [unique,charset(UTF16)] */,
				struct lsa_ObjectAttribute *attr /* [in] [ref] */,
				uint32_t access_mask /* [in]  */,
				struct policy_handle *handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_GetUserName(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				const char *system_name /* [in] [unique,charset(UTF16)] */,
				struct lsa_String **account_name /* [in,out] [ref] */,
				struct lsa_String **authority_name /* [in,out] [unique] */);
NTSTATUS rpccli_lsa_QueryInfoPolicy2(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct policy_handle *handle /* [in] [ref] */,
				     enum lsa_PolicyInfo level /* [in]  */,
				     union lsa_PolicyInformation **info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_SetInfoPolicy2(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   struct policy_handle *handle /* [in] [ref] */,
				   enum lsa_PolicyInfo level /* [in]  */,
				   union lsa_PolicyInformation *info /* [in] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_QueryTrustedDomainInfoByName(struct rpc_pipe_client *cli,
						 TALLOC_CTX *mem_ctx,
						 struct policy_handle *handle /* [in] [ref] */,
						 struct lsa_String *trusted_domain /* [in] [ref] */,
						 enum lsa_TrustDomInfoEnum level /* [in]  */,
						 union lsa_TrustedDomainInfo **info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_SetTrustedDomainInfoByName(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       struct policy_handle *handle /* [in] [ref] */,
					       struct lsa_String trusted_domain /* [in]  */,
					       enum lsa_TrustDomInfoEnum level /* [in]  */,
					       union lsa_TrustedDomainInfo *info /* [in] [unique,switch_is(level)] */);
NTSTATUS rpccli_lsa_EnumTrustedDomainsEx(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *handle /* [in] [ref] */,
					 uint32_t *resume_handle /* [in,out] [ref] */,
					 struct lsa_DomainListEx *domains /* [out] [ref] */,
					 uint32_t max_size /* [in]  */);
NTSTATUS rpccli_lsa_CreateTrustedDomainEx(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  struct policy_handle *policy_handle /* [in] [ref] */,
					  struct lsa_TrustDomainInfoInfoEx *info /* [in] [ref] */,
					  struct lsa_TrustDomainInfoAuthInfoInternal *auth_info /* [in] [ref] */,
					  uint32_t access_mask /* [in]  */,
					  struct policy_handle *trustdom_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_CloseTrustedDomainEx(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *handle /* [in,out] [ref] */);
NTSTATUS rpccli_lsa_QueryDomainInformationPolicy(struct rpc_pipe_client *cli,
						 TALLOC_CTX *mem_ctx,
						 struct policy_handle *handle /* [in] [ref] */,
						 uint16_t level /* [in]  */,
						 union lsa_DomainInformationPolicy **info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_lsa_SetDomainInformationPolicy(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       struct policy_handle *handle /* [in] [ref] */,
					       uint16_t level /* [in]  */,
					       union lsa_DomainInformationPolicy *info /* [in] [unique,switch_is(level)] */);
NTSTATUS rpccli_lsa_OpenTrustedDomainByName(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    struct policy_handle *handle /* [in] [ref] */,
					    struct lsa_String name /* [in]  */,
					    uint32_t access_mask /* [in]  */,
					    struct policy_handle *trustdom_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_TestCall(struct rpc_pipe_client *cli,
			     TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LookupSids2(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *handle /* [in] [ref] */,
				struct lsa_SidArray *sids /* [in] [ref] */,
				struct lsa_RefDomainList **domains /* [out] [ref] */,
				struct lsa_TransNameArray2 *names /* [in,out] [ref] */,
				uint16_t level /* [in]  */,
				uint32_t *count /* [in,out] [ref] */,
				uint32_t unknown1 /* [in]  */,
				uint32_t unknown2 /* [in]  */);
NTSTATUS rpccli_lsa_LookupNames2(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle /* [in] [ref] */,
				 uint32_t num_names /* [in] [range(0,1000)] */,
				 struct lsa_String *names /* [in] [size_is(num_names)] */,
				 struct lsa_RefDomainList **domains /* [out] [ref] */,
				 struct lsa_TransSidArray2 *sids /* [in,out] [ref] */,
				 enum lsa_LookupNamesLevel level /* [in]  */,
				 uint32_t *count /* [in,out] [ref] */,
				 uint32_t lookup_options /* [in]  */,
				 uint32_t client_revision /* [in]  */);
NTSTATUS rpccli_lsa_CreateTrustedDomainEx2(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   struct policy_handle *policy_handle /* [in] [ref] */,
					   struct lsa_TrustDomainInfoInfoEx *info /* [in] [ref] */,
					   struct lsa_TrustDomainInfoAuthInfoInternal *auth_info /* [in] [ref] */,
					   uint32_t access_mask /* [in]  */,
					   struct policy_handle *trustdom_handle /* [out] [ref] */);
NTSTATUS rpccli_lsa_CREDRWRITE(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRREAD(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRENUMERATE(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRWRITEDOMAINCREDENTIALS(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRREADDOMAINCREDENTIALS(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRDELETE(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRGETTARGETINFO(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRPROFILELOADED(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LookupNames3(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle /* [in] [ref] */,
				 uint32_t num_names /* [in] [range(0,1000)] */,
				 struct lsa_String *names /* [in] [size_is(num_names)] */,
				 struct lsa_RefDomainList **domains /* [out] [ref] */,
				 struct lsa_TransSidArray3 *sids /* [in,out] [ref] */,
				 enum lsa_LookupNamesLevel level /* [in]  */,
				 uint32_t *count /* [in,out] [ref] */,
				 uint32_t lookup_options /* [in]  */,
				 uint32_t client_revision /* [in]  */);
NTSTATUS rpccli_lsa_CREDRGETSESSIONTYPES(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LSARREGISTERAUDITEVENT(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LSARGENAUDITEVENT(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LSARUNREGISTERAUDITEVENT(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_lsaRQueryForestTrustInformation(struct rpc_pipe_client *cli,
						    TALLOC_CTX *mem_ctx,
						    struct policy_handle *handle /* [in] [ref] */,
						    struct lsa_String *trusted_domain_name /* [in] [ref] */,
						    uint16_t unknown /* [in]  */,
						    struct lsa_ForestTrustInformation **forest_trust_info /* [out] [ref] */);
NTSTATUS rpccli_lsa_LSARSETFORESTTRUSTINFORMATION(struct rpc_pipe_client *cli,
						  TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_CREDRRENAME(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LookupSids3(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct lsa_SidArray *sids /* [in] [ref] */,
				struct lsa_RefDomainList **domains /* [out] [ref] */,
				struct lsa_TransNameArray2 *names /* [in,out] [ref] */,
				uint16_t level /* [in]  */,
				uint32_t *count /* [in,out] [ref] */,
				uint32_t unknown1 /* [in]  */,
				uint32_t unknown2 /* [in]  */);
NTSTATUS rpccli_lsa_LookupNames4(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 uint32_t num_names /* [in] [range(0,1000)] */,
				 struct lsa_String *names /* [in] [size_is(num_names)] */,
				 struct lsa_RefDomainList **domains /* [out] [ref] */,
				 struct lsa_TransSidArray3 *sids /* [in,out] [ref] */,
				 enum lsa_LookupNamesLevel level /* [in]  */,
				 uint32_t *count /* [in,out] [ref] */,
				 uint32_t lookup_options /* [in]  */,
				 uint32_t client_revision /* [in]  */);
NTSTATUS rpccli_lsa_LSAROPENPOLICYSCE(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LSARADTREGISTERSECURITYEVENTSOURCE(struct rpc_pipe_client *cli,
						       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE(struct rpc_pipe_client *cli,
							 TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_lsa_LSARADTREPORTSECURITYEVENT(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx);
#endif /* __CLI_LSARPC__ */
