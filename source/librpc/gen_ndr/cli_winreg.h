#include "librpc/gen_ndr/ndr_winreg.h"
#ifndef __CLI_WINREG__
#define __CLI_WINREG__
NTSTATUS rpccli_winreg_OpenHKCR(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_OpenHKCU(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_OpenHKLM(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_OpenHKPD(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_OpenHKU(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_CloseKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle);
NTSTATUS rpccli_winreg_CreateKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String name, struct winreg_String keyclass, uint32_t options, uint32_t access_mask, struct winreg_SecBuf *secdesc, struct policy_handle *new_handle, enum winreg_CreateAction **action_taken);
NTSTATUS rpccli_winreg_DeleteKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String key);
NTSTATUS rpccli_winreg_DeleteValue(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String value);
NTSTATUS rpccli_winreg_EnumKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t enum_index, struct winreg_StringBuf *name, struct winreg_StringBuf **keyclass, NTTIME **last_changed_time);
NTSTATUS rpccli_winreg_EnumValue(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t enum_index, struct winreg_ValNameBuf *name, enum winreg_Type **type, uint8_t **data, uint32_t **data_size, uint32_t **value_length);
NTSTATUS rpccli_winreg_FlushKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle);
NTSTATUS rpccli_winreg_GetKeySecurity(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t sec_info, struct KeySecurityData *sd);
NTSTATUS rpccli_winreg_LoadKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String *keyname, struct winreg_String *filename);
NTSTATUS rpccli_winreg_NotifyChangeKeyValue(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint8_t watch_subtree, uint32_t notify_filter, uint32_t unknown, struct winreg_String string1, struct winreg_String string2, uint32_t unknown2);
NTSTATUS rpccli_winreg_OpenKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *parent_handle, struct winreg_String keyname, uint32_t unknown, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_QueryInfoKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String *classname, uint32_t *num_subkeys, uint32_t *max_subkeylen, uint32_t *max_classlen, uint32_t *num_values, uint32_t *max_valnamelen, uint32_t *max_valbufsize, uint32_t *secdescsize, NTTIME *last_changed_time);
NTSTATUS rpccli_winreg_QueryValue(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String value_name, enum winreg_Type **type, uint8_t **data, uint32_t **data_size, uint32_t **value_length);
NTSTATUS rpccli_winreg_ReplaceKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_winreg_RestoreKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String *filename, uint32_t flags);
NTSTATUS rpccli_winreg_SaveKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String *filename, struct KeySecurityAttribute *sec_attrib);
NTSTATUS rpccli_winreg_SetKeySecurity(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t access_mask, struct KeySecurityData *sd);
NTSTATUS rpccli_winreg_SetValue(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, struct winreg_String name, enum winreg_Type type, uint8_t *data, uint32_t size);
NTSTATUS rpccli_winreg_UnLoadKey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_winreg_InitiateSystemShutdown(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot);
NTSTATUS rpccli_winreg_AbortSystemShutdown(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *server);
NTSTATUS rpccli_winreg_GetVersion(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *handle, uint32_t *version);
NTSTATUS rpccli_winreg_OpenHKCC(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_OpenHKDD(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_QueryMultipleValues(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct policy_handle *key_handle, struct QueryMultipleValue *values, uint32_t num_values, uint8_t **buffer, uint32_t *buffer_size);
NTSTATUS rpccli_winreg_InitiateSystemShutdownEx(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot, uint32_t reason);
NTSTATUS rpccli_winreg_SaveKeyEx(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_winreg_OpenHKPT(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_OpenHKPN(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
NTSTATUS rpccli_winreg_QueryMultipleValues2(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
#endif /* __CLI_WINREG__ */
