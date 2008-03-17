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

struct libnet_conf_ctx {
	NT_USER_TOKEN *token;
};

/*
 * WARNING:
 *   Of this API, at least the open function is still subject to change.
 *   (Backends and possibly remote support being added ...)
 */

WERROR libnet_conf_open(TALLOC_CTX *mem_ctx, struct libnet_conf_ctx **conf_ctx);
void libnet_conf_close(struct libnet_conf_ctx *ctx);
uint64_t libnet_conf_get_seqnum(struct libnet_conf_ctx *ctx,
				const char *service, const char *param);
WERROR libnet_conf_drop(struct libnet_conf_ctx *ctx);
WERROR libnet_conf_get_config(TALLOC_CTX *mem_ctx,
			      struct libnet_conf_ctx *ctx, uint32_t *num_shares,
			      char ***share_names, uint32_t **num_params,
			      char ****param_names, char ****param_values);
WERROR libnet_conf_get_share_names(TALLOC_CTX *mem_ctx,
				   struct libnet_conf_ctx *ctx,
				   uint32_t *num_shares,
				   char ***share_names);
bool libnet_conf_share_exists(struct libnet_conf_ctx *ctx,
			      const char *servicename);
WERROR libnet_conf_create_share(struct libnet_conf_ctx *ctx,
				const char *servicename);
WERROR libnet_conf_get_share(TALLOC_CTX *mem_ctx, struct libnet_conf_ctx *ctx,
			     const char *servicename, uint32_t *num_params,
			     char ***param_names, char ***param_values);
WERROR libnet_conf_delete_share(struct libnet_conf_ctx *ctx,
				const char *servicename);
WERROR libnet_conf_set_parameter(struct libnet_conf_ctx *ctx,
				 const char *service,
				 const char *param,
				 const char *valstr);
WERROR libnet_conf_set_global_parameter(struct libnet_conf_ctx *ctx,
					const char *param, const char *val);
WERROR libnet_conf_get_parameter(TALLOC_CTX *mem_ctx,
				 struct libnet_conf_ctx *ctx,
				 const char *service,
				 const char *param,
				 char **valstr);
WERROR libnet_conf_get_global_parameter(TALLOC_CTX *mem_ctx,
					struct libnet_conf_ctx *ctx,
					const char *param,
					char **valstr);
WERROR libnet_conf_delete_parameter(struct libnet_conf_ctx *ctx,
				    const char *service, const char *param);
WERROR libnet_conf_delete_global_parameter(struct libnet_conf_ctx *ctx,
					   const char *param);

#endif /*  _LIBSMBCONF_H_  */
