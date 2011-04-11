/*
 *  Unix SMB/CIFS implementation.
 *  libsmbconf - Samba configuration library
 *  Copyright (C) Michael Adam 2008
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

#ifndef __LIBSMBCONF_H__
#define __LIBSMBCONF_H__

/**
 * @brief Status codes returned from smbconf functions
 */
enum _sbcErrType {
	SBC_ERR_OK = 0,          /**< Successful completion **/
	SBC_ERR_NOT_IMPLEMENTED, /**< Function not implemented **/
	SBC_ERR_NOT_SUPPORTED,   /**< Function not supported **/
	SBC_ERR_UNKNOWN_FAILURE, /**< General failure **/
	SBC_ERR_NOMEM,           /**< Memory allocation error **/
	SBC_ERR_INVALID_PARAM,   /**< An Invalid parameter was supplied **/
	SBC_ERR_BADFILE,         /**< A bad file was supplied **/
	SBC_ERR_NO_SUCH_SERVICE, /**< There is no such service provided **/
	SBC_ERR_IO_FAILURE,      /**< There was an IO error **/
	SBC_ERR_CAN_NOT_COMPLETE,/**< Can not complete action **/
	SBC_ERR_NO_MORE_ITEMS,   /**< No more items left **/
	SBC_ERR_FILE_EXISTS,     /**< File already exists **/
	SBC_ERR_ACCESS_DENIED,   /**< Access has been denied **/
};

typedef enum _sbcErrType sbcErr;

#define SBC_ERROR_IS_OK(x) ((x) == SBC_ERR_OK)
#define SBC_ERROR_EQUAL(x,y) ((x) == (y))

struct smbconf_ctx;

/* the change sequence number */
struct smbconf_csn {
	uint64_t csn;
};

struct smbconf_service {
	char *name;
	uint32_t num_params;
	char **param_names;
	char **param_values;
};

/**
 * @brief Translate an error value into a string
 *
 * @param error
 *
 * @return a pointer to a static string
 **/
const char *sbcErrorString(sbcErr error);

/*
 * the smbconf API functions
 */
bool smbconf_backend_requires_messaging(struct smbconf_ctx *ctx);
bool smbconf_is_writeable(struct smbconf_ctx *ctx);
void smbconf_shutdown(struct smbconf_ctx *ctx);
bool smbconf_changed(struct smbconf_ctx *ctx, struct smbconf_csn *csn,
		     const char *service, const char *param);
sbcErr smbconf_drop(struct smbconf_ctx *ctx);
WERROR smbconf_get_config(struct smbconf_ctx *ctx,
			  TALLOC_CTX *mem_ctx,
			  uint32_t *num_shares,
			  struct smbconf_service ***services);
sbcErr smbconf_get_share_names(struct smbconf_ctx *ctx,
			       TALLOC_CTX *mem_ctx,
			       uint32_t *num_shares,
			       char ***share_names);
bool smbconf_share_exists(struct smbconf_ctx *ctx, const char *servicename);
sbcErr smbconf_create_share(struct smbconf_ctx *ctx, const char *servicename);
sbcErr smbconf_get_share(struct smbconf_ctx *ctx,
			 TALLOC_CTX *mem_ctx,
			 const char *servicename,
			 struct smbconf_service **service);
sbcErr smbconf_delete_share(struct smbconf_ctx *ctx,
			    const char *servicename);
sbcErr smbconf_set_parameter(struct smbconf_ctx *ctx,
			     const char *service,
			     const char *param,
			     const char *valstr);
sbcErr smbconf_set_global_parameter(struct smbconf_ctx *ctx,
				    const char *param, const char *val);
sbcErr smbconf_get_parameter(struct smbconf_ctx *ctx,
			     TALLOC_CTX *mem_ctx,
			     const char *service,
			     const char *param,
			     char **valstr);
sbcErr smbconf_get_global_parameter(struct smbconf_ctx *ctx,
				    TALLOC_CTX *mem_ctx,
				    const char *param,
				    char **valstr);
sbcErr smbconf_delete_parameter(struct smbconf_ctx *ctx,
				const char *service, const char *param);
sbcErr smbconf_delete_global_parameter(struct smbconf_ctx *ctx,
				       const char *param);
sbcErr smbconf_get_includes(struct smbconf_ctx *ctx,
			    TALLOC_CTX *mem_ctx,
			    const char *service,
			    uint32_t *num_includes, char ***includes);
sbcErr smbconf_get_global_includes(struct smbconf_ctx *ctx,
				   TALLOC_CTX *mem_ctx,
				   uint32_t *num_includes, char ***includes);
sbcErr smbconf_set_includes(struct smbconf_ctx *ctx,
			    const char *service,
			    uint32_t num_includes, const char **includes);
sbcErr smbconf_set_global_includes(struct smbconf_ctx *ctx,
				   uint32_t num_includes,
				   const char **includes);
sbcErr smbconf_delete_includes(struct smbconf_ctx *ctx, const char *service);
sbcErr smbconf_delete_global_includes(struct smbconf_ctx *ctx);

sbcErr smbconf_transaction_start(struct smbconf_ctx *ctx);
sbcErr smbconf_transaction_commit(struct smbconf_ctx *ctx);
sbcErr smbconf_transaction_cancel(struct smbconf_ctx *ctx);

#endif /*  _LIBSMBCONF_H_  */
