#include "librpc/gen_ndr/ndr_svcctl.h"
#ifndef __CLI_SVCCTL__
#define __CLI_SVCCTL__
NTSTATUS rpccli_svcctl_CloseServiceHandle(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle);
NTSTATUS rpccli_svcctl_ControlService(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t control, struct SERVICE_STATUS *status);
NTSTATUS rpccli_svcctl_DeleteService(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle);
NTSTATUS rpccli_svcctl_LockServiceDatabase(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct policy_handle *lock);
NTSTATUS rpccli_svcctl_QueryServiceObjectSecurity(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_svcctl_SetServiceObjectSecurity(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_svcctl_QueryServiceStatus(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct SERVICE_STATUS *status);
NTSTATUS rpccli_svcctl_SetServiceStatus(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_svcctl_UnlockServiceDatabase(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *lock);
NTSTATUS rpccli_svcctl_NotifyBootConfigStatus(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_svcctl_SCSetServiceBitsW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t bits, uint32_t bitson, uint32_t immediate);
NTSTATUS rpccli_svcctl_ChangeServiceConfigW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t type, uint32_t start, uint32_t error, const char *binary_path, const char *load_order_group, uint32_t *tag_id, const char *dependencies, const char *service_start_name, const char *password, const char *display_name);
NTSTATUS rpccli_svcctl_CreateServiceW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *scmanager_handle, const char *ServiceName, const char *DisplayName, uint32_t desired_access, uint32_t type, uint32_t start_type, uint32_t error_control, const char *binary_path, const char *LoadOrderGroupKey, uint32_t **TagId, uint8_t *dependencies, uint32_t dependencies_size, const char *service_start_name, uint8_t *password, uint32_t password_size, struct policy_handle *handle);
NTSTATUS rpccli_svcctl_EnumDependentServicesW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *service, uint32_t state, struct ENUM_SERVICE_STATUS **status, uint32_t buf_size, uint32_t *bytes_needed, uint32_t *services_returned);
NTSTATUS rpccli_svcctl_EnumServicesStatusW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t type, uint32_t state, uint32_t buf_size, uint8_t **service, uint32_t *bytes_needed, uint32_t *services_returned, uint32_t **resume_handle);
NTSTATUS rpccli_svcctl_OpenSCManagerW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *MachineName, const char *DatabaseName, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_svcctl_OpenServiceW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *scmanager_handle, const char *ServiceName, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_svcctl_QueryServiceConfigW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint8_t **query, uint32_t buf_size, uint32_t *bytes_needed);
NTSTATUS rpccli_svcctl_QueryServiceLockStatusW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t buf_size, struct SERVICE_LOCK_STATUS *status, uint32_t *required_buf_size);
NTSTATUS rpccli_svcctl_StartServiceW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t NumArgs, const char *Arguments);
NTSTATUS rpccli_svcctl_GetServiceDisplayNameW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *service_name, const char **display_name, uint32_t **display_name_length);
NTSTATUS rpccli_svcctl_GetServiceKeyNameW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *service_name, const char **key_name, uint32_t **display_name_length);
NTSTATUS rpccli_svcctl_SCSetServiceBitsA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t bits, uint32_t bitson, uint32_t immediate);
NTSTATUS rpccli_svcctl_ChangeServiceConfigA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t type, uint32_t start, uint32_t error, const char *binary_path, const char *load_order_group, uint32_t *tag_id, const char *dependencies, const char *service_start_name, const char *password, const char *display_name);
NTSTATUS rpccli_svcctl_CreateServiceA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *ServiceName, const char *DisplayName, uint32_t desired_access, uint32_t type, uint32_t start_type, uint32_t error_control, const char *binary_path, const char *LoadOrderGroupKey, uint32_t **TagId, const char *dependencies, const char *service_start_name, const char *password);
NTSTATUS rpccli_svcctl_EnumDependentServicesA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *service, uint32_t state, struct ENUM_SERVICE_STATUS **status, uint32_t buf_size, uint32_t *bytes_needed, uint32_t *services_returned);
NTSTATUS rpccli_svcctl_EnumServicesStatusA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t type, uint32_t state, uint32_t buf_size, uint8_t **service, uint32_t *bytes_needed, uint32_t *services_returned, uint32_t **resume_handle);
NTSTATUS rpccli_svcctl_OpenSCManagerA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *MachineName, const char *DatabaseName, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_svcctl_OpenServiceA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *scmanager_handle, const char *ServiceName, uint32_t access_mask);
NTSTATUS rpccli_svcctl_QueryServiceConfigA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint8_t **query, uint32_t buf_size, uint32_t *bytes_needed);
NTSTATUS rpccli_svcctl_QueryServiceLockStatusA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t buf_size, struct SERVICE_LOCK_STATUS *status, uint32_t *required_buf_size);
NTSTATUS rpccli_svcctl_StartServiceA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t NumArgs, const char *Arguments);
NTSTATUS rpccli_svcctl_GetServiceDisplayNameA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *service_name, const char **display_name, uint32_t **display_name_length);
NTSTATUS rpccli_svcctl_GetServiceKeyNameA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *service_name, const char **key_name, uint32_t **display_name_length);
NTSTATUS rpccli_svcctl_GetCurrentGroupeStateW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_svcctl_EnumServiceGroupW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_svcctl_ChangeServiceConfig2A(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t info_level, uint8_t *info);
NTSTATUS rpccli_svcctl_ChangeServiceConfig2W(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t info_level, uint8_t *info);
NTSTATUS rpccli_svcctl_QueryServiceConfig2A(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t info_level, uint8_t **buffer, uint32_t buf_size, uint32_t *bytes_needed);
NTSTATUS rpccli_svcctl_QueryServiceConfig2W(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t info_level, uint8_t **buffer, uint32_t buf_size, uint32_t *bytes_needed);
NTSTATUS rpccli_svcctl_QueryServiceStatusEx(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t info_level, uint8_t **buffer, uint32_t buf_size, uint32_t *bytes_needed);
NTSTATUS rpccli_EnumServicesStatusExA(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *scmanager, uint32_t info_level, uint32_t type, uint32_t state, uint8_t **services, uint32_t buf_size, uint32_t *bytes_needed, uint32_t *service_returned, uint32_t **resume_handle, const char **group_name);
NTSTATUS rpccli_EnumServicesStatusExW(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *scmanager, uint32_t info_level, uint32_t type, uint32_t state, uint8_t **services, uint32_t buf_size, uint32_t *bytes_needed, uint32_t *service_returned, uint32_t **resume_handle, const char **group_name);
NTSTATUS rpccli_svcctl_SCSendTSMessage(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
#endif /* __CLI_SVCCTL__ */
