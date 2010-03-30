/*
 *  Unix SMB/CIFS implementation.
 *
 *  SPOOLSS RPC Pipe server / winreg client routines
 *
 *  Copyright (c) 2010      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "srv_spoolss_util.h"
#include "../librpc/gen_ndr/srv_winreg.h"
#include "../librpc/gen_ndr/cli_winreg.h"

#define TOP_LEVEL_PRINT_KEY "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print"
#define TOP_LEVEL_PRINT_PRINTERS_KEY TOP_LEVEL_PRINT_KEY "\\Printers"
#define TOP_LEVEL_CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\Print"
#define TOP_LEVEL_CONTROL_FORMS_KEY TOP_LEVEL_CONTROL_KEY "\\Forms"

/********************************************************************
 static helper functions
********************************************************************/

/**
 * @internal
 *
 * @brief Connect to the interal winreg server and open the given printer key.
 *
 * The function will create the needed subkeys if they don't exist.
 *
 * @param[in]  mem_ctx       The memory context to use.
 *
 * @param[in]  server_info   The supplied server info.
 *
 * @param[out] winreg_pipe   A pointer for the winreg rpc client pipe.
 *
 * @param[in]  path          The path to the key to open.
 *
 * @param[in]  key           The key to open.
 *
 * @param[in]  create_key    Set to true if the key should be created if it
 *                           doesn't exist.
 *
 * @param[in]  access_mask   The access mask to open the key.
 *
 * @param[out] hive_handle   A policy handle for the opened hive.
 *
 * @param[out] key_handle    A policy handle for the opened key.
 *
 * @return                   WERR_OK on success, the corresponding DOS error
 *                           code if something gone wrong.
 */
static WERROR winreg_printer_openkey(TALLOC_CTX *mem_ctx,
			      struct auth_serversupplied_info *server_info,
			      struct rpc_pipe_client **winreg_pipe,
			      const char *path,
			      const char *key,
			      bool create_key,
			      uint32_t access_mask,
			      struct policy_handle *hive_handle,
			      struct policy_handle *key_handle)
{
	struct rpc_pipe_client *pipe_handle;
	struct winreg_String wkey, wkeyclass;
	char *keyname;
	NTSTATUS status;
	WERROR result = WERR_OK;

	/* create winreg connection */
	status = rpc_pipe_open_internal(mem_ctx,
					&ndr_table_winreg.syntax_id,
					rpc_winreg_dispatch,
					server_info,
					&pipe_handle);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_openkey: Could not connect to winreg_pipe: %s\n",
			  nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	status = rpccli_winreg_OpenHKLM(pipe_handle,
					mem_ctx,
					NULL,
					access_mask,
					hive_handle,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_openkey: Could not open HKLM hive: %s\n",
			  nt_errstr(status)));
		talloc_free(pipe_handle);
		if (!W_ERROR_IS_OK(result)) {
			return result;
		}
		return ntstatus_to_werror(status);
	}

	if (key && *key) {
		keyname = talloc_asprintf(mem_ctx, "%s\\%s", path, key);
	} else {
		keyname = talloc_strdup(mem_ctx, path);
	}
	if (keyname == NULL) {
		talloc_free(pipe_handle);
		return WERR_NOMEM;
	}

	ZERO_STRUCT(wkey);
	wkey.name = keyname;

	if (create_key) {
		enum winreg_CreateAction action = REG_ACTION_NONE;

		ZERO_STRUCT(wkeyclass);
		wkeyclass.name = "";

		status = rpccli_winreg_CreateKey(pipe_handle,
						 mem_ctx,
						 hive_handle,
						 wkey,
						 wkeyclass,
						 0,
						 access_mask,
						 NULL,
						 key_handle,
						 &action,
						 &result);
		switch (action) {
			case REG_ACTION_NONE:
				DEBUG(8, ("winreg_printer_openkey:createkey did nothing -- huh?\n"));
				break;
			case REG_CREATED_NEW_KEY:
				DEBUG(8, ("winreg_printer_openkey: createkey created %s\n", keyname));
				break;
			case REG_OPENED_EXISTING_KEY:
				DEBUG(8, ("winreg_printer_openkey: createkey opened existing %s\n", keyname));
				break;
		}
	} else {
		status = rpccli_winreg_OpenKey(pipe_handle,
					       mem_ctx,
					       hive_handle,
					       wkey,
					       0,
					       access_mask,
					       key_handle,
					       &result);
	}
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(pipe_handle);
		if (!W_ERROR_IS_OK(result)) {
			return result;
		}
		return ntstatus_to_werror(status);
	}

	*winreg_pipe = pipe_handle;

	return WERR_OK;
}

/**
 * @brief Create the registry keyname for the given printer.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  printer  The name of the printer to get the registry key.
 *
 * @return     The registry key or NULL on error.
 */
static char *winreg_printer_data_keyname(TALLOC_CTX *mem_ctx, const char *printer) {
	return talloc_asprintf(mem_ctx, "%s\\%s", TOP_LEVEL_PRINT_PRINTERS_KEY, printer);
}

/**
 * @internal
 *
 * @brief Enumerate values of an opened key handle and retrieve the data.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  pipe_handle The pipe handle for the rpc connection.
 *
 * @param[in]  key_hnd  The opened key handle.
 *
 * @param[out] pnum_values A pointer to store he number of values found.
 *
 * @param[out] pnum_values A pointer to store the number of values we found.
 *
 * @return                   WERR_OK on success, the corresponding DOS error
 *                           code if something gone wrong.
 */
static WERROR winreg_printer_enumvalues(TALLOC_CTX *mem_ctx,
					struct rpc_pipe_client *pipe_handle,
					struct policy_handle *key_hnd,
					uint32_t *pnum_values,
					struct spoolss_PrinterEnumValues **penum_values)
{
	TALLOC_CTX *tmp_ctx;
	uint32_t num_subkeys, max_subkeylen, max_classlen;
	uint32_t num_values, max_valnamelen, max_valbufsize;
	uint32_t secdescsize;
	uint32_t i;
	NTTIME last_changed_time;
	struct winreg_String classname;

	struct spoolss_PrinterEnumValues *enum_values;

	WERROR result = WERR_OK;
	NTSTATUS status;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	ZERO_STRUCT(classname);

	status = rpccli_winreg_QueryInfoKey(pipe_handle,
					    tmp_ctx,
					    key_hnd,
					    &classname,
					    &num_subkeys,
					    &max_subkeylen,
					    &max_classlen,
					    &num_values,
					    &max_valnamelen,
					    &max_valbufsize,
					    &secdescsize,
					    &last_changed_time,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_enumvalues: Could not query info: %s\n",
			  nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			goto error;
		}
		result = ntstatus_to_werror(status);
		goto error;
	}

	if (num_values == 0) {
		*pnum_values = 0;
		TALLOC_FREE(tmp_ctx);
		return WERR_OK;
	}

	enum_values = TALLOC_ARRAY(tmp_ctx, struct spoolss_PrinterEnumValues, num_values);
	if (enum_values == NULL) {
		result = WERR_NOMEM;
		goto error;
	}

	for (i = 0; i < num_values; i++) {
		struct spoolss_PrinterEnumValues val;
		struct winreg_ValNameBuf name_buf;
		enum winreg_Type type = REG_NONE;
		uint8_t *data = NULL;
		uint32_t data_size;
		uint32_t length;
		char n = '\0';;

		name_buf.name = &n;
		name_buf.size = max_valnamelen + 2;
		name_buf.length = 0;

		data_size = max_valbufsize;
		data = (uint8_t *) TALLOC(tmp_ctx, data_size);
		length = 0;

		status = rpccli_winreg_EnumValue(pipe_handle,
						 tmp_ctx,
						 key_hnd,
						 i,
						 &name_buf,
						 &type,
						 data,
						 &data_size,
						 &length,
						 &result);
		if (W_ERROR_EQUAL(result, WERR_NO_MORE_ITEMS) ) {
			result = WERR_OK;
			status = NT_STATUS_OK;
			break;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("winreg_printer_enumvalues: Could not enumerate values: %s\n",
				  nt_errstr(status)));
			if (!W_ERROR_IS_OK(result)) {
				goto error;
			}
			result = ntstatus_to_werror(status);
			goto error;
		}

		if (name_buf.name == NULL) {
			result = WERR_INVALID_PARAMETER;
			goto error;
		}

		val.value_name = talloc_strdup(enum_values, name_buf.name);
		if (val.value_name == NULL) {
			result = WERR_NOMEM;
			goto error;
		}
		val.value_name_len = strlen_m_term(val.value_name) * 2;

		val.type = type;
		val.data_length = data_size;
		if (val.data_length) {
			val.data = talloc(enum_values, DATA_BLOB);
			if (val.data == NULL) {
				result = WERR_NOMEM;
				goto error;
			}
			*val.data = data_blob_talloc(enum_values, data, data_size);
		}

		enum_values[i] = val;
	}

	*pnum_values = num_values;
	if (penum_values) {
		*penum_values = talloc_move(mem_ctx, &enum_values);
	}

	result = WERR_OK;

 error:
	TALLOC_FREE(tmp_ctx);
	return result;
}

/**
 * @internal
 *
 * @brief Enumerate subkeys of an opened key handle and get the names.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  pipe_handle The pipe handle for the rpc connection.
 *
 * @param[in]  key_hnd  The opened key handle.
 *
 * @param[in]  pnum_subkeys A pointer to store the number of found subkeys.
 *
 * @param[in]  psubkeys A pointer to an array to store the found names of
 *                      subkeys.
 *
 * @return                   WERR_OK on success, the corresponding DOS error
 *                           code if something gone wrong.
 */
static WERROR winreg_printer_enumkeys(TALLOC_CTX *mem_ctx,
				      struct rpc_pipe_client *pipe_handle,
				      struct policy_handle *key_hnd,
				      uint32_t *pnum_subkeys,
				      const char ***psubkeys)
{
	TALLOC_CTX *tmp_ctx;
	const char **subkeys;
	uint32_t num_subkeys, max_subkeylen, max_classlen;
	uint32_t num_values, max_valnamelen, max_valbufsize;
	uint32_t i;
	NTTIME last_changed_time;
	uint32_t secdescsize;
	struct winreg_String classname;
	WERROR result = WERR_OK;
	NTSTATUS status;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	ZERO_STRUCT(classname);

	status = rpccli_winreg_QueryInfoKey(pipe_handle,
					    tmp_ctx,
					    key_hnd,
					    &classname,
					    &num_subkeys,
					    &max_subkeylen,
					    &max_classlen,
					    &num_values,
					    &max_valnamelen,
					    &max_valbufsize,
					    &secdescsize,
					    &last_changed_time,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_enumkeys: Could not query info: %s\n",
			  nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			goto error;
		}
		result = ntstatus_to_werror(status);
		goto error;
	}

	subkeys = talloc_zero_array(tmp_ctx, const char *, num_subkeys + 2);
	if (subkeys == NULL) {
		result = WERR_NOMEM;
		goto error;
	}

	if (num_subkeys == 0) {
		subkeys[0] = talloc_strdup(subkeys, "");
		if (subkeys[0] == NULL) {
			result = WERR_NOMEM;
			goto error;
		}
		*pnum_subkeys = 0;
		if (psubkeys) {
			*psubkeys = talloc_move(mem_ctx, &subkeys);
		}

		TALLOC_FREE(tmp_ctx);
		return WERR_OK;
	}

	for (i = 0; i < num_subkeys; i++) {
		char c = '\0';
		char n = '\0';
		char *name = NULL;
		struct winreg_StringBuf class_buf;
		struct winreg_StringBuf name_buf;
		NTTIME modtime;

		class_buf.name = &c;
		class_buf.size = max_classlen + 2;
		class_buf.length = 0;

		name_buf.name = &n;
		name_buf.size = max_subkeylen + 2;
		name_buf.length = 0;

		ZERO_STRUCT(modtime);

		status = rpccli_winreg_EnumKey(pipe_handle,
					       tmp_ctx,
					       key_hnd,
					       i,
					       &name_buf,
					       &class_buf,
					       &modtime,
					       &result);
		if (W_ERROR_EQUAL(result, WERR_NO_MORE_ITEMS) ) {
			result = WERR_OK;
			status = NT_STATUS_OK;
			break;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("winreg_printer_enumkeys: Could not enumerate keys: %s\n",
				  nt_errstr(status)));
			if (!W_ERROR_IS_OK(result)) {
				goto error;
			}
			result = ntstatus_to_werror(status);
			goto error;
		}

		if (name_buf.name == NULL) {
			result = WERR_INVALID_PARAMETER;
			goto error;
		}

		name = talloc_strdup(subkeys, name_buf.name);
		if (name == NULL) {
			result = WERR_NOMEM;
			goto error;
		}

		subkeys[i] = name;
	}

	*pnum_subkeys = num_subkeys;
	if (psubkeys) {
		*psubkeys = talloc_move(mem_ctx, &subkeys);
	}

 error:
	TALLOC_FREE(tmp_ctx);
	return result;
}

/**
 * @internal
 *
 * @brief A function to delete a key and its subkeys recurively.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  pipe_handle The pipe handle for the rpc connection.
 *
 * @param[in]  hive_handle A opened hive handle to the key.
 *
 * @param[in]  access_mask The access mask to access the key.
 *
 * @param[in]  key      The key to delete
 *
 * @return              WERR_OK on success, the corresponding DOS error
 *                      code if something gone wrong.
 */
static WERROR winreg_printer_delete_subkeys(TALLOC_CTX *mem_ctx,
					    struct rpc_pipe_client *pipe_handle,
					    struct policy_handle *hive_handle,
					    uint32_t access_mask,
					    const char *key)
{
	const char **subkeys = NULL;
	uint32_t num_subkeys = 0;
	struct policy_handle key_hnd;
	struct winreg_String wkey;
	WERROR result = WERR_OK;
	NTSTATUS status;
	uint32_t i;

	ZERO_STRUCT(key_hnd);
	wkey.name = key;

	DEBUG(2, ("winreg_printer_delete_subkeys: delete key %s\n", key));
	/* open the key */
	status = rpccli_winreg_OpenKey(pipe_handle,
				       mem_ctx,
				       hive_handle,
				       wkey,
				       0,
				       access_mask,
				       &key_hnd,
				       &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_delete_subkeys: Could not open key %s: %s\n",
			  wkey.name, nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			return result;
		}
		return ntstatus_to_werror(status);
	}

	result = winreg_printer_enumkeys(mem_ctx,
					 pipe_handle,
					 &key_hnd,
					 &num_subkeys,
					 &subkeys);
	if (!W_ERROR_IS_OK(result)) {
		goto done;
	}

	for (i = 0; i < num_subkeys; i++) {
		/* create key + subkey */
		char *subkey = talloc_asprintf(mem_ctx, "%s\\%s", key, subkeys[i]);
		if (subkey == NULL) {
			goto done;
		}

		DEBUG(2, ("winreg_printer_delete_subkeys: delete subkey %s\n", subkey));
		result = winreg_printer_delete_subkeys(mem_ctx,
						       pipe_handle,
						       hive_handle,
						       access_mask,
						       subkey);
		if (!W_ERROR_IS_OK(result)) {
			goto done;
		}
	}

	if (is_valid_policy_hnd(&key_hnd)) {
		rpccli_winreg_CloseKey(pipe_handle, mem_ctx, &key_hnd, NULL);
	}

	wkey.name = key;

	status = rpccli_winreg_DeleteKey(pipe_handle,
					 mem_ctx,
					 hive_handle,
					 wkey,
					 &result);

done:
	if (is_valid_policy_hnd(&key_hnd)) {
		rpccli_winreg_CloseKey(pipe_handle, mem_ctx, &key_hnd, NULL);
	}

	return result;
}

/********************************************************************
 Public winreg function for spoolss
********************************************************************/

/* Set printer data over the winreg pipe. */
WERROR winreg_set_printer_dataex(struct pipes_struct *p,
				 const char *printer,
				 const char *key,
				 const char *value,
				 enum winreg_Type type,
				 uint8_t *data,
				 uint32_t data_size)
{
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	struct rpc_pipe_client *winreg_pipe = NULL;
	struct policy_handle hive_hnd, key_hnd;
	struct winreg_String wvalue;
	char *path;
	WERROR result = WERR_OK;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(p->mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	path = winreg_printer_data_keyname(tmp_ctx, printer);
	if (path == NULL) {
		TALLOC_FREE(tmp_ctx);
		return WERR_NOMEM;
	}

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);

	DEBUG(8, ("winreg_set_printer_dataex: Open printer key %s, value %s, access_mask: 0x%05x for [%s]\n",
			key, value, access_mask, printer));
	result = winreg_printer_openkey(tmp_ctx,
					p->server_info,
					&winreg_pipe,
					path,
					key,
					true,
					access_mask,
					&hive_hnd,
					&key_hnd);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_set_printer_dataex: Could not open key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	wvalue.name = value;
	status = rpccli_winreg_SetValue(winreg_pipe,
					tmp_ctx,
					&key_hnd,
					wvalue,
					type,
					data,
					data_size,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_set_printer_dataex: Could not set value %s: %s\n",
			  value, nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			goto done;
		}
		result = ntstatus_to_werror(status);
		goto done;
	}

	result = WERR_OK;
done:
	if (winreg_pipe != NULL) {
		if (is_valid_policy_hnd(&key_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
		}
		if (is_valid_policy_hnd(&hive_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &hive_hnd, NULL);
		}
	}

	TALLOC_FREE(tmp_ctx);
	return result;
}

/* Get printer data over a winreg pipe. */
WERROR winreg_get_printer_dataex(struct pipes_struct *p,
				 const char *printer,
				 const char *key,
				 const char *value,
				 enum winreg_Type *type,
				 uint8_t **data,
				 uint32_t *data_size)
{
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	struct rpc_pipe_client *winreg_pipe = NULL;
	struct policy_handle hive_hnd, key_hnd;
	struct winreg_String wvalue;
	enum winreg_Type type_in;
	char *path;
	uint8_t *data_in;
	uint32_t data_in_size = 0;
	uint32_t value_len = 0;
	WERROR result = WERR_OK;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(p->mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	path = winreg_printer_data_keyname(tmp_ctx, printer);
	if (path == NULL) {
		TALLOC_FREE(tmp_ctx);
		return WERR_NOMEM;
	}

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);

	result = winreg_printer_openkey(tmp_ctx,
					p->server_info,
					&winreg_pipe,
					path,
					key,
					false,
					access_mask,
					&hive_hnd,
					&key_hnd);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_get_printer_dataex: Could not open key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	wvalue.name = value;

	/*
	 * call QueryValue once with data == NULL to get the
	 * needed memory size to be allocated, then allocate
	 * data buffer and call again.
	 */
	status = rpccli_winreg_QueryValue(winreg_pipe,
					  tmp_ctx,
					  &key_hnd,
					  &wvalue,
					  &type_in,
					  NULL,
					  &data_in_size,
					  &value_len,
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_get_printer_dataex: Could not query value %s: %s\n",
			  value, nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			goto done;
		}
		result = ntstatus_to_werror(status);
		goto done;
	}

	data_in = (uint8_t *) TALLOC(tmp_ctx, data_in_size);
	if (data_in == NULL) {
		result = WERR_NOMEM;
		goto done;
	}
	value_len = 0;

	status = rpccli_winreg_QueryValue(winreg_pipe,
					  tmp_ctx,
					  &key_hnd,
					  &wvalue,
					  &type_in,
					  data_in,
					  &data_in_size,
					  &value_len,
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_get_printer_dataex: Could not query value %s: %s\n",
			  value, nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			result = ntstatus_to_werror(status);
		}
		goto done;
	}

	*type = type_in;
	*data_size = data_in_size;
	if (data_in_size) {
		*data = talloc_move(p->mem_ctx, &data_in);
	}

	result = WERR_OK;
done:
	if (winreg_pipe != NULL) {
		if (is_valid_policy_hnd(&key_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
		}
		if (is_valid_policy_hnd(&hive_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &hive_hnd, NULL);
		}
	}

	TALLOC_FREE(tmp_ctx);
	return result;
}

/* Enumerate on the values of a given key and provide the data. */
WERROR winreg_enum_printer_dataex(struct pipes_struct *p,
				  const char *printer,
				  const char *key,
				  uint32_t *pnum_values,
				  struct spoolss_PrinterEnumValues **penum_values)
{
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	struct rpc_pipe_client *winreg_pipe = NULL;
	struct policy_handle hive_hnd, key_hnd;

	struct spoolss_PrinterEnumValues *enum_values = NULL;
	uint32_t num_values = 0;
	char *path;
	WERROR result = WERR_OK;

	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(p->mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	path = winreg_printer_data_keyname(tmp_ctx, printer);
	if (path == NULL) {
		TALLOC_FREE(tmp_ctx);
		return WERR_NOMEM;
	}

	result = winreg_printer_openkey(tmp_ctx,
					p->server_info,
					&winreg_pipe,
					path,
					key,
					false,
					access_mask,
					&hive_hnd,
					&key_hnd);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_enum_printer_dataex: Could not open key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	result = winreg_printer_enumvalues(tmp_ctx,
					   winreg_pipe,
					   &key_hnd,
					   &num_values,
					   &enum_values);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_enum_printer_dataex: Could not enumerate values in %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	*pnum_values = num_values;
	if (penum_values) {
		*penum_values = talloc_move(p->mem_ctx, &enum_values);
	}

	result = WERR_OK;
done:
	if (winreg_pipe != NULL) {
		if (is_valid_policy_hnd(&key_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
		}
		if (is_valid_policy_hnd(&hive_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &hive_hnd, NULL);
		}
	}

	TALLOC_FREE(tmp_ctx);
	return result;
}

/* Delete printer data over a winreg pipe. */
WERROR winreg_delete_printer_dataex(struct pipes_struct *p,
				    const char *printer,
				    const char *key,
				    const char *value)
{
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	struct rpc_pipe_client *winreg_pipe = NULL;
	struct policy_handle hive_hnd, key_hnd;
	struct winreg_String wvalue;
	char *path;
	WERROR result = WERR_OK;
	NTSTATUS status;

	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(p->mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	path = winreg_printer_data_keyname(tmp_ctx, printer);
	if (path == NULL) {
		TALLOC_FREE(tmp_ctx);
		return WERR_NOMEM;
	}

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);

	result = winreg_printer_openkey(tmp_ctx,
					p->server_info,
					&winreg_pipe,
					path,
					key,
					false,
					access_mask,
					&hive_hnd,
					&key_hnd);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_delete_printer_dataex: Could not open key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	wvalue.name = value;
	status = rpccli_winreg_DeleteValue(winreg_pipe,
					   tmp_ctx,
					   &key_hnd,
					   wvalue,
					   &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_delete_printer_dataex: Could not delete value %s: %s\n",
			  value, nt_errstr(status)));
		if (!W_ERROR_IS_OK(result)) {
			goto done;
		}
		result = ntstatus_to_werror(status);
		goto done;
	}

	result = WERR_OK;
done:
	if (winreg_pipe != NULL) {
		if (is_valid_policy_hnd(&key_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
		}
		if (is_valid_policy_hnd(&hive_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &hive_hnd, NULL);
		}
	}

	TALLOC_FREE(tmp_ctx);
	return result;
}

/* Enumerate on the subkeys of a given key and provide the data. */
WERROR winreg_enum_printer_key(struct pipes_struct *p,
			       const char *printer,
			       const char *key,
			       uint32_t *pnum_subkeys,
			       const char ***psubkeys)
{
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	struct rpc_pipe_client *winreg_pipe = NULL;
	struct policy_handle hive_hnd, key_hnd;
	char *path;
	const char **subkeys = NULL;
	uint32_t num_subkeys = -1;

	WERROR result = WERR_OK;

	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(p->mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	path = winreg_printer_data_keyname(tmp_ctx, printer);
	if (path == NULL) {
		TALLOC_FREE(tmp_ctx);
		return WERR_NOMEM;
	}

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);

	result = winreg_printer_openkey(tmp_ctx,
					p->server_info,
					&winreg_pipe,
					path,
					key,
					false,
					access_mask,
					&hive_hnd,
					&key_hnd);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_enum_printer_key: Could not open key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	result = winreg_printer_enumkeys(tmp_ctx,
					 winreg_pipe,
					 &key_hnd,
					 &num_subkeys,
					 &subkeys);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_enum_printer_key: Could not enumerate subkeys in %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	*pnum_subkeys = num_subkeys;
	if (psubkeys) {
		*psubkeys = talloc_move(p->mem_ctx, &subkeys);
	}

	result = WERR_OK;
done:
	if (winreg_pipe != NULL) {
		if (is_valid_policy_hnd(&key_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
		}
		if (is_valid_policy_hnd(&hive_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &hive_hnd, NULL);
		}
	}

	TALLOC_FREE(tmp_ctx);
	return result;
}

/* Delete a key with subkeys of a given printer. */
WERROR winreg_delete_printer_key(struct pipes_struct *p,
				 const char *printer,
				 const char *key)
{
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	struct rpc_pipe_client *winreg_pipe = NULL;
	struct policy_handle hive_hnd, key_hnd;
	char *keyname;
	char *path;
	WERROR result;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(p->mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOMEM;
	}

	path = winreg_printer_data_keyname(tmp_ctx, printer);
	if (path == NULL) {
		TALLOC_FREE(tmp_ctx);
		return WERR_NOMEM;
	}

	result = winreg_printer_openkey(tmp_ctx,
					p->server_info,
					&winreg_pipe,
					path,
					key,
					false,
					access_mask,
					&hive_hnd,
					&key_hnd);
	if (!W_ERROR_IS_OK(result)) {
		/* key doesn't exist */
		if (W_ERROR_EQUAL(result, WERR_BADFILE)) {
			result = WERR_OK;
			goto done;
		}

		DEBUG(0, ("winreg_delete_printer_key: Could not open key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

	if (is_valid_policy_hnd(&key_hnd)) {
		rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
	}

	keyname = talloc_asprintf(tmp_ctx,
				  "%s\\%s",
				  path,
				  key);
	if (keyname == NULL) {
		result = WERR_NOMEM;
		goto done;
	}

	result = winreg_printer_delete_subkeys(tmp_ctx,
					       winreg_pipe,
					       &hive_hnd,
					       access_mask,
					       keyname);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("winreg_delete_printer_key: Could not delete key %s: %s\n",
			  key, win_errstr(result)));
		goto done;
	}

done:
	if (winreg_pipe != NULL) {
		if (is_valid_policy_hnd(&key_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &key_hnd, NULL);
		}
		if (is_valid_policy_hnd(&hive_hnd)) {
			rpccli_winreg_CloseKey(winreg_pipe, tmp_ctx, &hive_hnd, NULL);
		}
	}

	TALLOC_FREE(tmp_ctx);
	return result;
}
