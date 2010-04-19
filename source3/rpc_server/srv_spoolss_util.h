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

#ifndef _SRV_SPOOLSS_UITL_H
#define _SRV_SPOOLSS_UITL_H

/**
 * @internal
 *
 * @brief Set printer data over the winreg pipe.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer data to store the value.
 *
 * @param[in]  value    The value name to save.
 *
 * @param[in]  type     The type of the value to use.
 *
 * @param[in]  data     The data which sould be saved under the given value.
 *
 * @param[in]  data_size The size of the data.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_set_printer_dataex(TALLOC_CTX *mem_ctx,
				 struct auth_serversupplied_info *server_info,
				 const char *printer,
				 const char *key,
				 const char *value,
				 enum winreg_Type type,
				 uint8_t *data,
				 uint32_t data_size);

/**
 * @internal
 *
 * @brief Get printer data over a winreg pipe.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer data to get the value.
 *
 * @param[in]  value    The name of the value to query.
 *
 * @param[in]  type     The type of the value to query.
 *
 * @param[out] data     A pointer to store the data.
 *
 * @param[out] data_size A pointer to store the size of the data.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_get_printer_dataex(TALLOC_CTX *mem_ctx,
				 struct auth_serversupplied_info *server_info,
				 const char *printer,
				 const char *key,
				 const char *value,
				 enum winreg_Type *type,
				 uint8_t **data,
				 uint32_t *data_size);

/**
 * @internal
 *
 * @brief Enumerate on the values of a given key and provide the data.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer data to get the value.
 *
 * @param[out] pnum_values A pointer to store the number of values we found.
 *
 * @param[out] penum_values A pointer to store the values and its data.
 *
 * @return                   WERR_OK on success, the corresponding DOS error
 *                           code if something gone wrong.
 */
WERROR winreg_enum_printer_dataex(TALLOC_CTX *mem_ctx,
				  struct auth_serversupplied_info *server_info,
				  const char *printer,
				  const char *key,
				  uint32_t *pnum_values,
				  struct spoolss_PrinterEnumValues **penum_values);

/**
 * @internal
 *
 * @brief Delete printer data over a winreg pipe.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer data to delete.
 *
 * @param[in]  value    The name of the value to delete.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_delete_printer_dataex(TALLOC_CTX *mem_ctx,
				    struct auth_serversupplied_info *server_info,
				    const char *printer,
				    const char *key,
				    const char *value);

/**
 * @internal
 *
 * @brief Enumerate on the subkeys of a given key and provide the data.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer data to get the value.
 *
 * @param[out] pnum_subkeys A pointer to store the number of subkeys found.
 *
 * @param[in]  psubkeys A pointer to an array to store the names of the subkeys
 *                      found.
 *
 * @return              WERR_OK on success, the corresponding DOS error
 *                      code if something gone wrong.
 */
WERROR winreg_enum_printer_key(TALLOC_CTX *mem_ctx,
			       struct auth_serversupplied_info *server_info,
			       const char *printer,
			       const char *key,
			       uint32_t *pnum_subkeys,
			       const char ***psubkeys);

/**
 * @internal
 *
 * @brief Delete a key with subkeys of a given printer.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer to delete.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_delete_printer_key(TALLOC_CTX *mem_ctx,
				 struct auth_serversupplied_info *server_info,
				 const char *printer,
				 const char *key);

/**
 * @internal
 *
 * @brief This function adds a form to the list of available forms that can be
 * selected for the specified printer.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  form     The form to add.
 *
 * @return              WERR_OK on success.
 *                      WERR_ALREADY_EXISTS if the form already exists or is a
 *                                          builtin form.
 *                      A corresponding DOS error is something went wrong.
 */
WERROR winreg_printer_addform1(TALLOC_CTX *mem_ctx,
			       struct auth_serversupplied_info *server_info,
			       struct spoolss_AddFormInfo1 *form);

/*
 * @brief This function enumerates the forms supported by the specified printer.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[out] pnum_info A pointer to store the FormInfo count.
 *
 * @param[out] pinfo     A pointer to store an array with FormInfo.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_printer_enumforms1(TALLOC_CTX *mem_ctx,
				 struct auth_serversupplied_info *server_info,
				 uint32_t *pnum_info,
				 union spoolss_FormInfo **pinfo);

/**
 * @brief This function removes a form name from the list of supported forms.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  form_name The name of the form to delete.
 *
 * @return              WERR_OK on success.
 *                      WERR_INVALID_PARAM if the form is a builtin form.
 *                      A corresponding DOS error is something went wrong.
 */
WERROR winreg_printer_deleteform1(TALLOC_CTX *mem_ctx,
				  struct auth_serversupplied_info *server_info,
				  const char *form_name);

/**
 * @brief This function sets the form information for the specified printer.
 *
 * If one provides both the name in the API call and inside the FormInfo
 * structure, then the form gets renamed.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  form_name The name of the form to set or rename.
 *
 * @param[in]  form     The FormInfo structure to save.
 *
 * @return              WERR_OK on success.
 *                      WERR_INVALID_PARAM if the form is a builtin form.
 *                      A corresponding DOS error is something went wrong.
 */
WERROR winreg_printer_setform1(TALLOC_CTX *mem_ctx,
			       struct auth_serversupplied_info *server_info,
			       const char *form_name,
			       struct spoolss_AddFormInfo1 *form);

/**
 * @brief This function retrieves information about a specified form.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  form_name The name of the form to query.
 *
 * @param[out] form     A pointer to a form structure to fill out.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_printer_getform1(TALLOC_CTX *mem_ctx,
			       struct auth_serversupplied_info *server_info,
			       const char *form_name,
			       struct spoolss_FormInfo1 *form);

#endif /* _SRV_SPOOLSS_UITL_H */
