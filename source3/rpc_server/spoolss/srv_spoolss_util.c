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
#include "rpc_server/rpc_ncacn_np.h"
#include "../lib/tsocket/tsocket.h"
#include "../librpc/gen_ndr/ndr_spoolss.h"
#include "../librpc/gen_ndr/ndr_winreg.h"
#include "srv_spoolss_util.h"
#include "rpc_client/cli_winreg_spoolss.h"

WERROR winreg_printer_binding_handle(TALLOC_CTX *mem_ctx,
				     const struct auth_session_info *session_info,
				     struct messaging_context *msg_ctx,
				     struct dcerpc_binding_handle **winreg_binding_handle)
{
	struct tsocket_address *local;
	NTSTATUS status;
	int rc;

	rc = tsocket_address_inet_from_strings(mem_ctx,
					       "ip",
					       "127.0.0.1",
					       0,
					       &local);
	if (rc < 0) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	status = rpcint_binding_handle(mem_ctx,
				       &ndr_table_winreg,
				       local,
				       NULL,
				       session_info,
				       msg_ctx,
				       winreg_binding_handle);
	talloc_free(local);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_binding_handle: Could not connect to winreg pipe: %s\n",
			  nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	return WERR_OK;
}

WERROR winreg_delete_printer_key_internal(TALLOC_CTX *mem_ctx,
					  const struct auth_session_info *session_info,
					  struct messaging_context *msg_ctx,
					  const char *printer,
					  const char *key)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_delete_printer_key(tmp_ctx,
					   b,
					   printer,
					   key);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_update_changeid_internal(TALLOC_CTX *mem_ctx,
					       const struct auth_session_info *session_info,
					       struct messaging_context *msg_ctx,
					       const char *printer)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_update_changeid(mem_ctx,
						b,
						printer);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_get_changeid_internal(TALLOC_CTX *mem_ctx,
					    const struct auth_session_info *session_info,
					    struct messaging_context *msg_ctx,
					    const char *printer,
					    uint32_t *pchangeid)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_get_changeid(mem_ctx,
					     b,
					     printer,
					     pchangeid);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_printer_internal(TALLOC_CTX *mem_ctx,
				   const struct auth_session_info *session_info,
				   struct messaging_context *msg_ctx,
				   const char *printer,
				   struct spoolss_PrinterInfo2 **pinfo2)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_printer(mem_ctx,
				    b,
				    printer,
				    pinfo2);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_create_printer_internal(TALLOC_CTX *mem_ctx,
				      const struct auth_session_info *session_info,
				      struct messaging_context *msg_ctx,
				      const char *sharename)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_create_printer(mem_ctx,
				       b,
				       sharename);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_update_printer_internal(TALLOC_CTX *mem_ctx,
				      const struct auth_session_info *session_info,
				      struct messaging_context *msg_ctx,
				      const char *sharename,
				      uint32_t info2_mask,
				      struct spoolss_SetPrinterInfo2 *info2,
				      struct spoolss_DeviceMode *devmode,
				      struct security_descriptor *secdesc)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_update_printer(mem_ctx,
				       b,
				       sharename,
				       info2_mask,
				       info2,
				       devmode,
				       secdesc);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_set_printer_dataex_internal(TALLOC_CTX *mem_ctx,
					  const struct auth_session_info *session_info,
					  struct messaging_context *msg_ctx,
					  const char *printer,
					  const char *key,
					  const char *value,
					  enum winreg_Type type,
					  uint8_t *data,
					  uint32_t data_size)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_set_printer_dataex(mem_ctx,
					   b,
					   printer,
					   key,
					   value,
					   type,
					   data,
					   data_size);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_enum_printer_dataex_internal(TALLOC_CTX *mem_ctx,
					   const struct auth_session_info *session_info,
					   struct messaging_context *msg_ctx,
					   const char *printer,
					   const char *key,
					   uint32_t *pnum_values,
					   struct spoolss_PrinterEnumValues **penum_values)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_enum_printer_dataex(mem_ctx,
					    b,
					    printer,
					    key,
					    pnum_values,
					    penum_values);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_printer_dataex_internal(TALLOC_CTX *mem_ctx,
					  const struct auth_session_info *session_info,
					  struct messaging_context *msg_ctx,
					  const char *printer,
					  const char *key,
					  const char *value,
					  enum winreg_Type *type,
					  uint8_t **data,
					  uint32_t *data_size)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_printer_dataex(mem_ctx,
					   b,
					   printer,
					   key,
					   value,
					   type,
					   data,
					   data_size);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_delete_printer_dataex_internal(TALLOC_CTX *mem_ctx,
					     const struct auth_session_info *session_info,
					     struct messaging_context *msg_ctx,
					     const char *printer,
					     const char *key,
					     const char *value)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_delete_printer_dataex(mem_ctx,
					      b,
					      printer,
					      key,
					      value);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_driver_internal(TALLOC_CTX *mem_ctx,
				  const struct auth_session_info *session_info,
				  struct messaging_context *msg_ctx,
				  const char *architecture,
				  const char *driver_name,
				  uint32_t driver_version,
				  struct spoolss_DriverInfo8 **_info8)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_driver(mem_ctx,
				   b,
				   architecture,
				   driver_name,
				   driver_version,
				   _info8);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_driver_list_internal(TALLOC_CTX *mem_ctx,
				       const struct auth_session_info *session_info,
				       struct messaging_context *msg_ctx,
				       const char *architecture,
				       uint32_t version,
				       uint32_t *num_drivers,
				       const char ***drivers_p)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_driver_list(mem_ctx,
					b,
					architecture,
					version,
					num_drivers,
					drivers_p);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_del_driver_internal(TALLOC_CTX *mem_ctx,
				  const struct auth_session_info *session_info,
				  struct messaging_context *msg_ctx,
				  struct spoolss_DriverInfo8 *info8,
				  uint32_t version)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_del_driver(mem_ctx,
				   b,
				   info8,
				   version);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_add_driver_internal(TALLOC_CTX *mem_ctx,
				  const struct auth_session_info *session_info,
				  struct messaging_context *msg_ctx,
				  struct spoolss_AddDriverInfoCtr *r,
				  const char **driver_name,
				  uint32_t *driver_version)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_add_driver(mem_ctx,
				   b,
				   r,
				   driver_name,
				   driver_version);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_core_driver_internal(TALLOC_CTX *mem_ctx,
				       const struct auth_session_info *session_info,
				       struct messaging_context *msg_ctx,
				       const char *architecture,
				       const struct GUID *core_driver_guid,
				       struct spoolss_CorePrinterDriver **core_printer_driver)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_core_driver(mem_ctx,
					b,
					architecture,
					core_driver_guid,
					core_printer_driver);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_add_core_driver_internal(TALLOC_CTX *mem_ctx,
				       const struct auth_session_info *session_info,
				       struct messaging_context *msg_ctx,
				       const char *architecture,
				       const struct spoolss_CorePrinterDriver *core_printer_driver)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_add_core_driver(mem_ctx,
					b,
					architecture,
					core_printer_driver);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_add_driver_package_internal(TALLOC_CTX *mem_ctx,
				          const struct auth_session_info *session_info,
				          struct messaging_context *msg_ctx,
					  const char *package_id,
					  const char *architecture,
					  const char *driver_store_path,
					  const char *cab_path)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_add_driver_package(mem_ctx,
					   b,
					   package_id,
					   architecture,
					   driver_store_path,
					   cab_path);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_driver_package_internal(TALLOC_CTX *mem_ctx,
				          const struct auth_session_info *session_info,
				          struct messaging_context *msg_ctx,
					  const char *package_id,
					  const char *architecture,
					  const char **driver_store_path,
					  const char **cab_path)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_driver_package(mem_ctx,
					   b,
					   package_id,
					   architecture,
					   driver_store_path,
					   cab_path);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_del_driver_package_internal(TALLOC_CTX *mem_ctx,
				          const struct auth_session_info *session_info,
				          struct messaging_context *msg_ctx,
					  const char *package_id,
					  const char *architecture)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_del_driver_package(mem_ctx,
					   b,
					   package_id,
					   architecture);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_get_printer_secdesc_internal(TALLOC_CTX *mem_ctx,
					   const struct auth_session_info *session_info,
					   struct messaging_context *msg_ctx,
					   const char *sharename,
					   struct spoolss_security_descriptor **psecdesc)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_get_printer_secdesc(mem_ctx,
					    b,
					    sharename,
					    psecdesc);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_set_printer_secdesc_internal(TALLOC_CTX *mem_ctx,
					   const struct auth_session_info *session_info,
					   struct messaging_context *msg_ctx,
					   const char *sharename,
					   const struct spoolss_security_descriptor *secdesc)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_set_printer_secdesc(mem_ctx,
					    b,
					    sharename,
					    secdesc);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_enumforms1_internal(TALLOC_CTX *mem_ctx,
					  const struct auth_session_info *session_info,
					  struct messaging_context *msg_ctx,
					  uint32_t *pnum_info,
					  union spoolss_FormInfo **pinfo)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_enumforms1(mem_ctx,
					   b,
					   pnum_info,
					   pinfo);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_getform1_internal(TALLOC_CTX *mem_ctx,
					const struct auth_session_info *session_info,
					struct messaging_context *msg_ctx,
					const char *form_name,
					struct spoolss_FormInfo1 *r)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_getform1(mem_ctx,
					 b,
					 form_name,
					 r);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_addform1_internal(TALLOC_CTX *mem_ctx,
					const struct auth_session_info *session_info,
					struct messaging_context *msg_ctx,
					struct spoolss_AddFormInfo1 *form)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_addform1(mem_ctx,
					 b,
					 form);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_setform1_internal(TALLOC_CTX *mem_ctx,
					const struct auth_session_info *session_info,
					struct messaging_context *msg_ctx,
					const char *form_name,
					struct spoolss_AddFormInfo1 *form)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_setform1(mem_ctx,
					 b,
					 form_name,
					 form);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_printer_deleteform1_internal(TALLOC_CTX *mem_ctx,
					   const struct auth_session_info *session_info,
					   struct messaging_context *msg_ctx,
					   const char *form_name)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_printer_deleteform1(mem_ctx,
					    b,
					    form_name);

	talloc_free(tmp_ctx);
	return result;
}

WERROR winreg_enum_printer_key_internal(TALLOC_CTX *mem_ctx,
					const struct auth_session_info *session_info,
					struct messaging_context *msg_ctx,
					const char *printer,
					const char *key,
					uint32_t *pnum_subkeys,
					const char ***psubkeys)
{
	WERROR result;
	struct dcerpc_binding_handle *b;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_printer_binding_handle(tmp_ctx, session_info, msg_ctx, &b);
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(tmp_ctx);
		return result;
	}

	result = winreg_enum_printer_key(mem_ctx,
					 b,
					 printer,
					 key,
					 pnum_subkeys,
					 psubkeys);

	talloc_free(tmp_ctx);
	return result;
}
