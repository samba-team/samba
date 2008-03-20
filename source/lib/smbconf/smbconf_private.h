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

#ifndef __LIBSMBCONF_PRIVATE_H__
#define __LIBSMBCONF_PRIVATE_H__

struct smbconf_ops {
	WERROR (*init)(struct smbconf_ctx *ctx);
	WERROR (*open_conf)(struct smbconf_ctx *ctx);
	int (*close_conf)(struct smbconf_ctx *ctx);
	void (*get_csn)(struct smbconf_ctx *ctx, struct smbconf_csn *csn,
			const char *service, const char *param);
	WERROR (*drop)(struct smbconf_ctx *ctx);
	WERROR (*get_share_names)(struct smbconf_ctx *ctx,
				  TALLOC_CTX *mem_ctx,
				  uint32_t *num_shares,
				  char ***share_names);
	bool (*share_exists)(struct smbconf_ctx *ctx, const char *service);
	WERROR (*create_share)(struct smbconf_ctx *ctx, const char *service);
	WERROR (*get_share)(struct smbconf_ctx *ctx,
			    TALLOC_CTX *mem_ctx,
			    const char *servicename, uint32_t *num_params,
			    char ***param_names, char ***param_values);
	WERROR (*delete_share)(struct smbconf_ctx *ctx,
				    const char *servicename);
	WERROR (*set_parameter)(struct smbconf_ctx *ctx,
			        const char *service,
			        const char *param,
			        const char *valstr);
	WERROR (*get_parameter)(struct smbconf_ctx *ctx,
			        TALLOC_CTX *mem_ctx,
			        const char *service,
			        const char *param,
			        char **valstr);
	WERROR (*delete_parameter)(struct smbconf_ctx *ctx,
				   const char *service, const char *param);
};

struct smbconf_ctx {
	NT_USER_TOKEN *token;
	struct smbconf_ops *ops;
};

#endif
