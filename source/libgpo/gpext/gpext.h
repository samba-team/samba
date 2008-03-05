/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Support
 *  Copyright (C) Guenther Deschner 2007-2008
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

#define KEY_WINLOGON_GPEXT_PATH "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions"

#define SAMBA_SUBSYSTEM_GPEXT "gpext"

#define SMB_GPEXT_INTERFACE_VERSION 1

struct gp_extension {
	struct GUID *guid;
	const char *name;
	struct gp_extension_methods *methods;
	struct gp_extension *prev, *next;
};

struct gp_extension_reg_table {
	const char *val;
	enum winreg_Type type;
	const char *data;
};

struct gp_extension_reg_entry {
	const char *value;
	struct registry_value *data;
};

struct gp_extension_reg_info_entry {
	struct GUID guid;
	size_t num_entries;
	struct gp_extension_reg_entry *entries;
};

struct gp_extension_reg_info {
	size_t num_entries;
	struct gp_extension_reg_info_entry *entries;
};

struct gp_extension_methods {

	NTSTATUS (*initialize)(TALLOC_CTX *mem_ctx);

	NTSTATUS (*process_group_policy)(ADS_STRUCT *ads,
					 TALLOC_CTX *mem_ctx,
					 uint32_t flags,
					 struct registry_key *root_key,
					 const struct nt_user_token *token,
					 struct GROUP_POLICY_OBJECT *gpo,
					 const char *extension_guid,
					 const char *snapin_guid);

	NTSTATUS (*process_group_policy2)(ADS_STRUCT *ads,
					 TALLOC_CTX *mem_ctx,
					 uint32_t flags,
					 const struct nt_user_token *token,
					 struct GROUP_POLICY_OBJECT *gpo_list,
					 const char *extension_guid);

	NTSTATUS (*get_reg_config)(TALLOC_CTX *mem_ctx,
				   struct gp_extension_reg_info **info);

	NTSTATUS (*shutdown)(void);
};
