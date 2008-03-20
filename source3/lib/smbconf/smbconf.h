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

struct smbconf_ctx;

/* the change sequence number */
struct smbconf_csn {
	uint64_t csn;
};

/*
 * WARNING:
 *   Of this API, at least the open function is still subject to change.
 *   (Backends and possibly remote support being added ...)
 */

WERROR smbconf_init(TALLOC_CTX *mem_ctx, struct smbconf_ctx **conf_ctx);
void smbconf_close(struct smbconf_ctx *ctx);
bool smbconf_changed(struct smbconf_ctx *ctx, struct smbconf_csn *csn,
		     const char *service, const char *param);
WERROR smbconf_drop(struct smbconf_ctx *ctx);
WERROR smbconf_get_config(struct smbconf_ctx *ctx,
			  TALLOC_CTX *mem_ctx,
			  uint32_t *num_shares,
			  char ***share_names, uint32_t **num_params,
			  char ****param_names, char ****param_values);
WERROR smbconf_get_share_names(struct smbconf_ctx *ctx,
			       TALLOC_CTX *mem_ctx,
			       uint32_t *num_shares,
			       char ***share_names);
bool smbconf_share_exists(struct smbconf_ctx *ctx, const char *servicename);
WERROR smbconf_create_share(struct smbconf_ctx *ctx, const char *servicename);
WERROR smbconf_get_share(struct smbconf_ctx *ctx,
			 TALLOC_CTX *mem_ctx,
			 const char *servicename, uint32_t *num_params,
			 char ***param_names, char ***param_values);
WERROR smbconf_delete_share(struct smbconf_ctx *ctx,
			    const char *servicename);
WERROR smbconf_set_parameter(struct smbconf_ctx *ctx,
			     const char *service,
			     const char *param,
			     const char *valstr);
WERROR smbconf_set_global_parameter(struct smbconf_ctx *ctx,
				    const char *param, const char *val);
WERROR smbconf_get_parameter(struct smbconf_ctx *ctx,
			     TALLOC_CTX *mem_ctx,
			     const char *service,
			     const char *param,
			     char **valstr);
WERROR smbconf_get_global_parameter(struct smbconf_ctx *ctx,
				    TALLOC_CTX *mem_ctx,
				    const char *param,
				    char **valstr);
WERROR smbconf_delete_parameter(struct smbconf_ctx *ctx,
				const char *service, const char *param);
WERROR smbconf_delete_global_parameter(struct smbconf_ctx *ctx,
				       const char *param);

#endif /*  _LIBSMBCONF_H_  */
