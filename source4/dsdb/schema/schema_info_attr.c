/*
   Unix SMB/CIFS implementation.

   SCHEMA::schemaInfo implementation

   Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2010

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

#include "includes.h"
#include "dsdb/common/util.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/ldb/include/ldb_module.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"


/**
 * Creates and initializes new dsdb_schema_info value.
 * Initial schemaInfo values is with:
 *   revision = 0
 *   invocationId = GUID_ZERO
 */
WERROR dsdb_schema_info_new(TALLOC_CTX *mem_ctx, struct dsdb_schema_info **_schema_info)
{
	struct dsdb_schema_info *schema_info;

	schema_info = talloc_zero(mem_ctx, struct dsdb_schema_info);
	W_ERROR_HAVE_NO_MEMORY(schema_info);

	*_schema_info = schema_info;

	return WERR_OK;
}

/**
 * Creates and initializes new dsdb_schema_info blob value.
 * Initial schemaInfo values is with:
 *   revision = 0
 *   invocationId = GUID_ZERO
 */
WERROR dsdb_schema_info_blob_new(TALLOC_CTX *mem_ctx, DATA_BLOB *_schema_info_blob)
{
	DATA_BLOB blob;

	blob = data_blob_talloc_zero(mem_ctx, 21);
	W_ERROR_HAVE_NO_MEMORY(blob.data);

	/* Set the schemaInfo marker to 0xFF */
	blob.data[0] = 0xFF;

	*_schema_info_blob = blob;

	return WERR_OK;
}


/**
 * Parse schemaInfo structure from a data_blob
 * (DATA_BLOB or ldb_val).
 * Suitable for parsing blobs that comes from
 * DRS interface of from LDB database
 */
WERROR dsdb_schema_info_from_blob(const DATA_BLOB *blob,
				  TALLOC_CTX *mem_ctx, struct dsdb_schema_info **_schema_info)
{
	TALLOC_CTX *temp_ctx;
	enum ndr_err_code ndr_err;
	struct dsdb_schema_info *schema_info;
	struct schemaInfoBlob schema_info_blob;

	if (!blob || !blob->data) {
		return WERR_INVALID_PARAMETER;
	}

	if (blob->length != 21) {
		return WERR_INVALID_PARAMETER;
	}

	/* schemaInfo blob should start with 0xFF */
	if (blob->data[0] != 0xFF) {
		return WERR_INVALID_PARAMETER;
	}

	temp_ctx = talloc_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(temp_ctx);

	ndr_err = ndr_pull_struct_blob_all(blob, temp_ctx,
	                                   &schema_info_blob,
	                                   (ndr_pull_flags_fn_t)ndr_pull_schemaInfoBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		talloc_free(temp_ctx);
		return ntstatus_to_werror(nt_status);
	}

	schema_info = talloc(mem_ctx, struct dsdb_schema_info);
	if (!schema_info) {
		talloc_free(temp_ctx);
		return WERR_NOMEM;
	}

	/* note that we accept revision numbers of zero now - w2k8r2
	   sends a revision of zero on initial vampire */
	schema_info->revision      = schema_info_blob.revision;
	schema_info->invocation_id = schema_info_blob.invocation_id;
	*_schema_info = schema_info;

	talloc_free(temp_ctx);
	return WERR_OK;
}

/**
 * Creates a blob from schemaInfo structure
 * Suitable for packing schemaInfo into a blob
 * which is to be used in DRS interface of LDB database
 */
WERROR dsdb_blob_from_schema_info(const struct dsdb_schema_info *schema_info,
				  TALLOC_CTX *mem_ctx, DATA_BLOB *blob)
{
	enum ndr_err_code ndr_err;
	struct schemaInfoBlob schema_info_blob;

	schema_info_blob.marker		= 0xFF;
	schema_info_blob.revision	= schema_info->revision;
	schema_info_blob.invocation_id  = schema_info->invocation_id;

	ndr_err = ndr_push_struct_blob(blob, mem_ctx,
	                               &schema_info_blob,
	                               (ndr_push_flags_fn_t)ndr_push_schemaInfoBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return ntstatus_to_werror(nt_status);
	}

	return WERR_OK;
}


/**
 * Reads schema_info structure from schemaInfo
 * attribute on SCHEMA partition
 *
 * @param dsdb_flags 	DSDB_FLAG_... flag of 0
 */
WERROR dsdb_module_schema_info_blob_read(struct ldb_module *ldb_module,
					 uint32_t dsdb_flags,
					 TALLOC_CTX *mem_ctx, DATA_BLOB *schema_info_blob)
{
	int ldb_err;
	const struct ldb_val *blob_val;
	struct ldb_dn *schema_dn;
	struct ldb_result *schema_res = NULL;
	static const char *schema_attrs[] = {
		"schemaInfo",
		NULL
	};

	schema_dn = ldb_get_schema_basedn(ldb_module_get_ctx(ldb_module));
	if (!schema_dn) {
		DEBUG(0,("dsdb_module_schema_info_blob_read: no schema dn present!\n"));
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	ldb_err = dsdb_module_search(ldb_module, mem_ctx, &schema_res, schema_dn,
	                             LDB_SCOPE_BASE, schema_attrs, dsdb_flags, NULL);
	if (ldb_err == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(0,("dsdb_module_schema_info_blob_read: Schema DN not found!\n"));
		talloc_free(schema_res);
		return WERR_INTERNAL_DB_CORRUPTION;
	} else if (ldb_err != LDB_SUCCESS) {
		DEBUG(0,("dsdb_module_schema_info_blob_read: failed to find schemaInfo attribute\n"));
		talloc_free(schema_res);
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	blob_val = ldb_msg_find_ldb_val(schema_res->msgs[0], "schemaInfo");
	if (!blob_val) {
		DEBUG(0,("dsdb_module_schema_info_blob_read: no schemaInfo attribute found\n"));
		talloc_free(schema_res);
		return WERR_DS_NO_ATTRIBUTE_OR_VALUE;
	}

	/* transfer .data ownership to mem_ctx */
	schema_info_blob->length = blob_val->length;
	schema_info_blob->data = talloc_steal(mem_ctx, blob_val->data);

	talloc_free(schema_res);

	return WERR_OK;
}

/**
 * Prepares ldb_msg to be used for updating schemaInfo value in DB
 */
static WERROR _dsdb_schema_info_write_prepare(struct ldb_context *ldb,
					      DATA_BLOB *schema_info_blob,
					      TALLOC_CTX *mem_ctx,
					      struct ldb_message **_msg)
{
	int ldb_err;
	struct ldb_message *msg;
	struct ldb_dn *schema_dn;
	struct ldb_message_element *return_el;

	schema_dn = ldb_get_schema_basedn(ldb);
	if (!schema_dn) {
		DEBUG(0,("_dsdb_schema_info_write_prepare: no schema dn present\n"));
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	/* prepare ldb_msg to update schemaInfo */
	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn = schema_dn;
	ldb_err = ldb_msg_add_value(msg, "schemaInfo", schema_info_blob, &return_el);
	if (ldb_err != 0) {
		DEBUG(0,("_dsdb_schema_info_write_prepare: ldb_msg_add_value failed - %s\n",
			 ldb_strerror(ldb_err)));
		talloc_free(msg);
		return WERR_INTERNAL_ERROR;
	}

	/* mark schemaInfo element for replacement */
	return_el->flags = LDB_FLAG_MOD_REPLACE;

	*_msg = msg;

	return WERR_OK;
}

/**
 * Writes schema_info structure into schemaInfo
 * attribute on SCHEMA partition
 *
 * @param dsdb_flags 	DSDB_FLAG_... flag of 0
 */
WERROR dsdb_module_schema_info_blob_write(struct ldb_module *ldb_module,
					  uint32_t dsdb_flags,
					  DATA_BLOB *schema_info_blob)
{
	int ldb_err;
	WERROR werr;
	struct ldb_message *msg;
	TALLOC_CTX *temp_ctx;

	temp_ctx = talloc_new(ldb_module);
	W_ERROR_HAVE_NO_MEMORY(temp_ctx);

	/* write serialized schemaInfo into LDB */
	werr = _dsdb_schema_info_write_prepare(ldb_module_get_ctx(ldb_module),
	                                       schema_info_blob,
	                                       temp_ctx, &msg);
	if (!W_ERROR_IS_OK(werr)) {
		talloc_free(temp_ctx);
		return werr;
	}


	ldb_err = dsdb_module_modify(ldb_module, msg, dsdb_flags);

	talloc_free(temp_ctx);

	if (ldb_err != 0) {
		DEBUG(0,("dsdb_module_schema_info_blob_write: dsdb_replace failed: %s (%s)\n",
			 ldb_strerror(ldb_err),
			 ldb_errstring(ldb_module_get_ctx(ldb_module))));
		return WERR_INTERNAL_DB_ERROR;
	}

	return WERR_OK;
}


/**
 * Reads schema_info structure from schemaInfo
 * attribute on SCHEMA partition
 */
static WERROR dsdb_module_schema_info_read(struct ldb_module *ldb_module,
					   uint32_t dsdb_flags,
					   TALLOC_CTX *mem_ctx,
					   struct dsdb_schema_info **_schema_info)
{
	WERROR werr;
	DATA_BLOB ndr_blob;
	TALLOC_CTX *temp_ctx;

	temp_ctx = talloc_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(temp_ctx);

	/* read serialized schemaInfo from LDB  */
	werr = dsdb_module_schema_info_blob_read(ldb_module, dsdb_flags, temp_ctx, &ndr_blob);
	if (!W_ERROR_IS_OK(werr)) {
		talloc_free(temp_ctx);
		return werr;
	}

	/* convert NDR blob to dsdb_schema_info object */
	werr = dsdb_schema_info_from_blob(&ndr_blob,
					  mem_ctx,
					  _schema_info);
	talloc_free(temp_ctx);

	return werr;
}

/**
 * Writes schema_info structure into schemaInfo
 * attribute on SCHEMA partition
 *
 * @param dsdb_flags 	DSDB_FLAG_... flag of 0
 */
static WERROR dsdb_module_schema_info_write(struct ldb_module *ldb_module,
					    uint32_t dsdb_flags,
					    const struct dsdb_schema_info *schema_info)
{
	WERROR werr;
	DATA_BLOB ndr_blob;
	TALLOC_CTX *temp_ctx;

	temp_ctx = talloc_new(ldb_module);
	W_ERROR_HAVE_NO_MEMORY(temp_ctx);

	/* convert schema_info to a blob */
	werr = dsdb_blob_from_schema_info(schema_info, temp_ctx, &ndr_blob);
	if (!W_ERROR_IS_OK(werr)) {
		talloc_free(temp_ctx);
		return werr;
	}

	/* write serialized schemaInfo into LDB */
	werr = dsdb_module_schema_info_blob_write(ldb_module, dsdb_flags, &ndr_blob);

	talloc_free(temp_ctx);

	return werr;
}


/**
 * Increments schemaInfo revision and save it to DB
 * setting our invocationID in the process
 * NOTE: this function should be called in a transaction
 * much in the same way prefixMap update function is called
 *
 * @param ldb_module 	current module
 * @param schema 	schema cache
 * @param dsdb_flags 	DSDB_FLAG_... flag of 0
 */
WERROR dsdb_module_schema_info_update(struct ldb_module *ldb_module,
				      struct dsdb_schema *schema,
				      int dsdb_flags)
{
	WERROR werr;
	const struct GUID *invocation_id;
	DATA_BLOB ndr_blob;
	struct dsdb_schema_info *schema_info;
	const char *schema_info_str;

	TALLOC_CTX *temp_ctx = talloc_new(schema);
	W_ERROR_HAVE_NO_MEMORY(temp_ctx);

	invocation_id = samdb_ntds_invocation_id(ldb_module_get_ctx(ldb_module));
	if (!invocation_id) {
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	/* read serialized schemaInfo from LDB  */
	werr = dsdb_module_schema_info_read(ldb_module, dsdb_flags, temp_ctx, &schema_info);
	if (W_ERROR_EQUAL(werr, WERR_DS_NO_ATTRIBUTE_OR_VALUE)) {
		/* make default value in case
		 * we have no schemaInfo value yet */
		werr = dsdb_schema_info_new(temp_ctx, &schema_info);
	}
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("dsdb_module_schema_info_update: failed to reload schemaInfo - %s\n",
			 win_errstr(werr)));
		talloc_free(temp_ctx);
		return werr;
	}

	/* update schemaInfo */
	schema_info->revision++;
	schema_info->invocation_id = *invocation_id;

	werr = dsdb_module_schema_info_write(ldb_module, dsdb_flags, schema_info);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("dsdb_module_schema_info_update: failed to save schemaInfo - %s\n",
			 win_errstr(werr)));
		talloc_free(temp_ctx);
		return werr;
	}

	/* finally, update schema_info in the cache */
	werr = dsdb_blob_from_schema_info(schema_info, temp_ctx, &ndr_blob);
	W_ERROR_NOT_OK_RETURN(werr);

	schema_info_str = hex_encode_talloc(schema, ndr_blob.data, ndr_blob.length);
	W_ERROR_HAVE_NO_MEMORY(schema_info_str);

	talloc_unlink(schema, discard_const(schema->schema_info));
	schema->schema_info = schema_info_str;

	talloc_free(temp_ctx);
	return WERR_OK;
}
