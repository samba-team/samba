#include "librpc/gen_ndr/ndr_winreg.h"
#ifndef __SRV_WINREG__
#define __SRV_WINREG__
WERROR _winreg_OpenHKCR(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_OpenHKCU(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_OpenHKLM(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_OpenHKPD(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_OpenHKU(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_CloseKey(pipes_struct *p, struct policy_handle *handle);
WERROR _winreg_CreateKey(pipes_struct *p, struct policy_handle *handle, struct winreg_String name, struct winreg_String keyclass, uint32_t options, uint32_t access_mask, struct winreg_SecBuf *secdesc, struct policy_handle *new_handle, enum winreg_CreateAction *action_taken);
WERROR _winreg_DeleteKey(pipes_struct *p, struct policy_handle *handle, struct winreg_String key);
WERROR _winreg_DeleteValue(pipes_struct *p, struct policy_handle *handle, struct winreg_String value);
WERROR _winreg_EnumKey(pipes_struct *p, struct policy_handle *handle, uint32_t enum_index, struct winreg_StringBuf *name, struct winreg_StringBuf *keyclass, NTTIME *last_changed_time);
WERROR _winreg_EnumValue(pipes_struct *p, struct policy_handle *handle, uint32_t enum_index, struct winreg_ValNameBuf *name, enum winreg_Type *type, uint8_t *data, uint32_t *data_size, uint32_t *value_length);
WERROR _winreg_FlushKey(pipes_struct *p, struct policy_handle *handle);
WERROR _winreg_GetKeySecurity(pipes_struct *p, struct policy_handle *handle, uint32_t sec_info, struct KeySecurityData *sd);
WERROR _winreg_LoadKey(pipes_struct *p, struct policy_handle *handle, struct winreg_String *keyname, struct winreg_String *filename);
WERROR _winreg_NotifyChangeKeyValue(pipes_struct *p, struct policy_handle *handle, uint8_t watch_subtree, uint32_t notify_filter, uint32_t unknown, struct winreg_String string1, struct winreg_String string2, uint32_t unknown2);
WERROR _winreg_OpenKey(pipes_struct *p, struct policy_handle *parent_handle, struct winreg_String keyname, uint32_t unknown, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_QueryInfoKey(pipes_struct *p, struct policy_handle *handle, struct winreg_String *classname, uint32_t *num_subkeys, uint32_t *max_subkeylen, uint32_t *max_classlen, uint32_t *num_values, uint32_t *max_valnamelen, uint32_t *max_valbufsize, uint32_t *secdescsize, NTTIME *last_changed_time);
WERROR _winreg_QueryValue(pipes_struct *p, struct policy_handle *handle, struct winreg_String value_name, enum winreg_Type *type, uint8_t *data, uint32_t *data_size, uint32_t *value_length);
WERROR _winreg_ReplaceKey(pipes_struct *p);
WERROR _winreg_RestoreKey(pipes_struct *p, struct policy_handle *handle, struct winreg_String *filename, uint32_t flags);
WERROR _winreg_SaveKey(pipes_struct *p, struct policy_handle *handle, struct winreg_String *filename, struct KeySecurityAttribute *sec_attrib);
WERROR _winreg_SetKeySecurity(pipes_struct *p, struct policy_handle *handle, uint32_t access_mask, struct KeySecurityData *sd);
WERROR _winreg_SetValue(pipes_struct *p, struct policy_handle *handle, struct winreg_String name, enum winreg_Type type, uint8_t *data, uint32_t size);
WERROR _winreg_UnLoadKey(pipes_struct *p);
WERROR _winreg_InitiateSystemShutdown(pipes_struct *p, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot);
WERROR _winreg_AbortSystemShutdown(pipes_struct *p, uint16_t *server);
WERROR _winreg_GetVersion(pipes_struct *p, struct policy_handle *handle, uint32_t *version);
WERROR _winreg_OpenHKCC(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_OpenHKDD(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_QueryMultipleValues(pipes_struct *p, struct policy_handle *key_handle, struct QueryMultipleValue *values, uint32_t num_values, uint8_t *buffer, uint32_t *buffer_size);
WERROR _winreg_InitiateSystemShutdownEx(pipes_struct *p, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot, uint32_t reason);
WERROR _winreg_SaveKeyEx(pipes_struct *p);
WERROR _winreg_OpenHKPT(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_OpenHKPN(pipes_struct *p, uint16_t *system_name, uint32_t access_mask, struct policy_handle *handle);
WERROR _winreg_QueryMultipleValues2(pipes_struct *p);
void winreg_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_winreg_init(void);
#endif /* __SRV_WINREG__ */
