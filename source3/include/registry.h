/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *
 *  Copyright (C) Gerald Carter              2002-2005
 *  Copyright (C) Volker Lendecke            2006
 *  Copyright (C) Michael Adam               2006-2010
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

#ifndef _REGISTRY_H
#define _REGISTRY_H

struct registry_value {
	enum winreg_Type type;
	DATA_BLOB data;
};

/* forward declarations. definitions in reg_objects.c */
struct regval_ctr;
struct regsubkey_ctr;

/*
 * container for function pointers to enumeration routines
 * for virtual registry view
 */

struct registry_ops {
	/* functions for enumerating subkeys and values */
	int 	(*fetch_subkeys)( const char *key, struct regsubkey_ctr *subkeys);
	int 	(*fetch_values) ( const char *key, struct regval_ctr *val );
	bool 	(*store_subkeys)( const char *key, struct regsubkey_ctr *subkeys );
	WERROR	(*create_subkey)(const char *key, const char *subkey);
	WERROR	(*delete_subkey)(const char *key, const char *subkey);
	bool 	(*store_values)( const char *key, struct regval_ctr *val );
	bool	(*reg_access_check)( const char *keyname, uint32 requested,
				     uint32 *granted,
				     const NT_USER_TOKEN *token );
	WERROR (*get_secdesc)(TALLOC_CTX *mem_ctx, const char *key,
			      struct security_descriptor **psecdesc);
	WERROR (*set_secdesc)(const char *key,
			      struct security_descriptor *sec_desc);
	bool	(*subkeys_need_update)(struct regsubkey_ctr *subkeys);
	bool	(*values_need_update)(struct regval_ctr *values);
};

/* structure to store the registry handles */

struct registry_key_handle {
	uint32		type;
	char		*name; 		/* full name of registry key */
	uint32 		access_granted;
	struct registry_ops	*ops;
};

struct registry_key {
	struct registry_key_handle *key;
	struct regsubkey_ctr *subkeys;
	struct regval_ctr *values;
	struct nt_user_token *token;
};


/*
 *
 * Macros that used to reside in rpc_reg.h
 *
 */

#define HKEY_CLASSES_ROOT	0x80000000
#define HKEY_CURRENT_USER	0x80000001
#define HKEY_LOCAL_MACHINE 	0x80000002
#define HKEY_USERS         	0x80000003
#define HKEY_PERFORMANCE_DATA	0x80000004

#define KEY_HKLM		"HKLM"
#define KEY_HKU			"HKU"
#define KEY_HKCC		"HKCC"
#define KEY_HKCR		"HKCR"
#define KEY_HKPD		"HKPD"
#define KEY_HKPT		"HKPT"
#define KEY_HKPN		"HKPN"
#define KEY_HKCU		"HKCU"
#define KEY_HKDD		"HKDD"
#define KEY_SERVICES		"HKLM\\SYSTEM\\CurrentControlSet\\Services"
#define KEY_EVENTLOG 		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Eventlog"
#define KEY_SHARES		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares"
#define KEY_NETLOGON_PARAMS	"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"
#define KEY_TCPIP_PARAMS	"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define KEY_PROD_OPTIONS	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
#define KEY_PRINTING 		"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print"
#define KEY_PRINTING_2K		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers"
#define KEY_PRINTING_PORTS	"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports"
#define KEY_CURRENT_VERSION	"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define KEY_PERFLIB		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib"
#define KEY_PERFLIB_009		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009"
#define KEY_GROUP_POLICY	"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Group Policy"
#define KEY_WINLOGON		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
#define KEY_SMBCONF		"HKLM\\SOFTWARE\\Samba\\smbconf"
#define KEY_SAMBA_GROUP_POLICY	"HKLM\\SOFTWARE\\Samba\\Group Policy"
#define KEY_TREE_ROOT		""

#define KEY_GP_MACHINE_POLICY		"HKLM\\Software\\Policies"
#define KEY_GP_MACHINE_WIN_POLICY	"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
#define KEY_GP_USER_POLICY		"HKCU\\Software\\Policies"
#define KEY_GP_USER_WIN_POLICY		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"

/*
 * Registry key types
 *	Most keys are going to be GENERIC -- may need a better name?
 *	HKPD and HKPT are used by reg_perfcount.c
 *		they are special keys that contain performance data
 */
#define REG_KEY_GENERIC		0
#define REG_KEY_HKPD		1
#define REG_KEY_HKPT		2


/* The following definitions come from registry/reg_api.c  */

WERROR reg_openhive(TALLOC_CTX *mem_ctx, const char *hive,
		    uint32 desired_access,
		    const struct nt_user_token *token,
		    struct registry_key **pkey);
WERROR reg_openkey(TALLOC_CTX *mem_ctx, struct registry_key *parent,
		   const char *name, uint32 desired_access,
		   struct registry_key **pkey);
WERROR reg_enumkey(TALLOC_CTX *mem_ctx, struct registry_key *key,
		   uint32 idx, char **name, NTTIME *last_write_time);
WERROR reg_enumvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		     uint32 idx, char **pname, struct registry_value **pval);
WERROR reg_queryvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		      const char *name, struct registry_value **pval);
WERROR reg_querymultiplevalues(TALLOC_CTX *mem_ctx,
			       struct registry_key *key,
			       uint32_t num_names,
			       const char **names,
			       uint32_t *pnum_vals,
			       struct registry_value **pvals);
WERROR reg_queryinfokey(struct registry_key *key, uint32_t *num_subkeys,
			uint32_t *max_subkeylen, uint32_t *max_subkeysize,
			uint32_t *num_values, uint32_t *max_valnamelen,
			uint32_t *max_valbufsize, uint32_t *secdescsize,
			NTTIME *last_changed_time);
WERROR reg_createkey(TALLOC_CTX *ctx, struct registry_key *parent,
		     const char *subkeypath, uint32 desired_access,
		     struct registry_key **pkey,
		     enum winreg_CreateAction *paction);
WERROR reg_deletekey(struct registry_key *parent, const char *path);
WERROR reg_setvalue(struct registry_key *key, const char *name,
		    const struct registry_value *val);
WERROR reg_deletevalue(struct registry_key *key, const char *name);
WERROR reg_getkeysecurity(TALLOC_CTX *mem_ctx, struct registry_key *key,
			  struct security_descriptor **psecdesc);
WERROR reg_setkeysecurity(struct registry_key *key,
			  struct security_descriptor *psecdesc);
WERROR reg_getversion(uint32_t *version);
WERROR reg_restorekey(struct registry_key *key, const char *fname);
WERROR reg_savekey(struct registry_key *key, const char *fname);
WERROR reg_deleteallvalues(struct registry_key *key);
WERROR reg_open_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		     uint32 desired_access, const struct nt_user_token *token,
		     struct registry_key **pkey);
WERROR reg_deletekey_recursive(TALLOC_CTX *ctx,
			       struct registry_key *parent,
			       const char *path);
WERROR reg_deletesubkeys_recursive(TALLOC_CTX *ctx,
				   struct registry_key *parent,
				   const char *path);
WERROR reg_create_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		       uint32 desired_access,
		       const struct nt_user_token *token,
		       enum winreg_CreateAction *paction,
		       struct registry_key **pkey);
WERROR reg_delete_path(const struct nt_user_token *token,
		       const char *orig_path);

/* The following definitions come from registry/reg_init_basic.c  */

WERROR registry_init_common(void);
WERROR registry_init_basic(void);

/* The following definitions come from registry/reg_init_full.c  */

WERROR registry_init_full(void);

/* The following definitions come from registry/reg_init_smbconf.c  */

WERROR registry_init_smbconf(const char *keyname);

#endif /* _REGISTRY_H */
