/* 
 *  Unix SMB/CIFS implementation.
 *  Service Control API Implementation
 * 
 *  Copyright (C) Marcin Krzysztof Porwit         2005.
 *  Largely Rewritten by:
 *  Copyright (C) Gerald (Jerry) Carter           2005.
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
#include "services/services.h"
#include "registry.h"
#include "registry/reg_api_util.h"

struct rcinit_file_information {
	char *description;
};

struct service_display_info {
	const char *servicename;
	const char *daemon;
	const char *dispname;
	const char *description;
};

struct service_display_info builtin_svcs[] = {
  { "Spooler",	      "smbd", 	"Print Spooler", "Internal service for spooling files to print devices" },
  { "NETLOGON",	      "smbd", 	"Net Logon", "File service providing access to policy and profile data (not remotely manageable)" },
  { "RemoteRegistry", "smbd", 	"Remote Registry Service", "Internal service providing remote access to "
				"the Samba registry" },
  { "WINS",           "nmbd", 	"Windows Internet Name Service (WINS)", "Internal service providing a "
				"NetBIOS point-to-point name server (not remotely manageable)" },
  { NULL, NULL, NULL, NULL }
};

struct service_display_info common_unix_svcs[] = {
  { "cups",          NULL, "Common Unix Printing System","Provides unified printing support for all operating systems" },
  { "postfix",       NULL, "Internet Mail Service", 	"Provides support for sending and receiving electonic mail" },
  { "sendmail",      NULL, "Internet Mail Service", 	"Provides support for sending and receiving electonic mail" },
  { "portmap",       NULL, "TCP Port to RPC PortMapper",NULL },
  { "xinetd",        NULL, "Internet Meta-Daemon", 	NULL },
  { "inet",          NULL, "Internet Meta-Daemon", 	NULL },
  { "xntpd",         NULL, "Network Time Service", 	NULL },
  { "ntpd",          NULL, "Network Time Service", 	NULL },
  { "lpd",           NULL, "BSD Print Spooler", 	NULL },
  { "nfsserver",     NULL, "Network File Service", 	NULL },
  { "cron",          NULL, "Scheduling Service", 	NULL },
  { "at",            NULL, "Scheduling Service", 	NULL },
  { "nscd",          NULL, "Name Service Cache Daemon",	NULL },
  { "slapd",         NULL, "LDAP Directory Service", 	NULL },
  { "ldap",          NULL, "LDAP DIrectory Service", 	NULL },
  { "ypbind",        NULL, "NIS Directory Service", 	NULL },
  { "courier-imap",  NULL, "IMAP4 Mail Service", 	NULL },
  { "courier-pop3",  NULL, "POP3 Mail Service", 	NULL },
  { "named",         NULL, "Domain Name Service", 	NULL },
  { "bind",          NULL, "Domain Name Service", 	NULL },
  { "httpd",         NULL, "HTTP Server", 		NULL },
  { "apache",        NULL, "HTTP Server", 		"Provides s highly scalable and flexible web server "
							"capable of implementing various protocols incluing "
							"but not limited to HTTP" },
  { "autofs",        NULL, "Automounter", 		NULL },
  { "squid",         NULL, "Web Cache Proxy ",		NULL },
  { "perfcountd",    NULL, "Performance Monitoring Daemon", NULL },
  { "pgsql",	     NULL, "PgSQL Database Server", 	"Provides service for SQL database from Postgresql.org" },
  { "arpwatch",	     NULL, "ARP Tables watcher", 	"Provides service for monitoring ARP tables for changes" },
  { "dhcpd",	     NULL, "DHCP Server", 		"Provides service for dynamic host configuration and IP assignment" },
  { "nwserv",	     NULL, "NetWare Server Emulator", 	"Provides service for emulating Novell NetWare 3.12 server" },
  { "proftpd",	     NULL, "Professional FTP Server", 	"Provides high configurable service for FTP connection and "
							"file transferring" },
  { "ssh2",	     NULL, "SSH Secure Shell", 		"Provides service for secure connection for remote administration" },
  { "sshd",	     NULL, "SSH Secure Shell", 		"Provides service for secure connection for remote administration" },
  { NULL, NULL, NULL, NULL }
};

static WERROR svcctl_set_secdesc_internal(struct registry_key *key,
					  struct security_descriptor *sec_desc);

/********************************************************************
********************************************************************/

static struct security_descriptor* construct_service_sd( TALLOC_CTX *ctx )
{
	struct security_ace ace[4];
	size_t i = 0;
	struct security_descriptor *sd = NULL;
	struct security_acl *theacl = NULL;
	size_t sd_size;

	/* basic access for Everyone */

	init_sec_ace(&ace[i++], &global_sid_World,
		SEC_ACE_TYPE_ACCESS_ALLOWED, SERVICE_READ_ACCESS, 0);

	init_sec_ace(&ace[i++], &global_sid_Builtin_Power_Users,
			SEC_ACE_TYPE_ACCESS_ALLOWED, SERVICE_EXECUTE_ACCESS, 0);

	init_sec_ace(&ace[i++], &global_sid_Builtin_Server_Operators,
		SEC_ACE_TYPE_ACCESS_ALLOWED, SERVICE_ALL_ACCESS, 0);
	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators,
		SEC_ACE_TYPE_ACCESS_ALLOWED, SERVICE_ALL_ACCESS, 0);

	/* create the security descriptor */

	theacl = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace);
	if (theacl == NULL) {
		return NULL;
	}

	sd = make_sec_desc(ctx, SECURITY_DESCRIPTOR_REVISION_1,
			   SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL,
			   theacl, &sd_size);
	if (sd == NULL) {
		return NULL;
	}

	return sd;
}

/********************************************************************
 This is where we do the dirty work of filling in things like the
 Display name, Description, etc...
********************************************************************/

static char *get_common_service_dispname( const char *servicename )
{
	int i;

	for ( i=0; common_unix_svcs[i].servicename; i++ ) {
		if (strequal(servicename, common_unix_svcs[i].servicename)) {
			char *dispname;
			if (asprintf(&dispname,
				"%s (%s)",
				common_unix_svcs[i].dispname,
				common_unix_svcs[i].servicename) < 0) {
				return NULL;
			}
			return dispname;
		}
	}

	return SMB_STRDUP(servicename );
}

/********************************************************************
********************************************************************/

static char *cleanup_string( const char *string )
{
	char *clean = NULL;
	char *begin, *end;
	TALLOC_CTX *ctx = talloc_tos();

	clean = talloc_strdup(ctx, string);
	if (!clean) {
		return NULL;
	}
	begin = clean;

	/* trim any beginning whilespace */

	while (isspace(*begin)) {
		begin++;
	}

	if (*begin == '\0') {
		return NULL;
	}

	/* trim any trailing whitespace or carriage returns.
	   Start at the end and move backwards */

	end = begin + strlen(begin) - 1;

	while ( isspace(*end) || *end=='\n' || *end=='\r' ) {
		*end = '\0';
		end--;
	}

	return begin;
}

/********************************************************************
********************************************************************/

static bool read_init_file( const char *servicename, struct rcinit_file_information **service_info )
{
	struct rcinit_file_information *info = NULL;
	char *filepath = NULL;
	char str[1024];
	XFILE *f = NULL;
	char *p = NULL;

	info = TALLOC_ZERO_P( NULL, struct rcinit_file_information );
	if (info == NULL) {
		return False;
	}

	/* attempt the file open */

	filepath = talloc_asprintf(info, "%s/%s/%s", get_dyn_MODULESDIR(),
				SVCCTL_SCRIPT_DIR, servicename);
	if (!filepath) {
		TALLOC_FREE(info);
		return false;
	}
	f = x_fopen( filepath, O_RDONLY, 0 );
	if (f == NULL) {
		DEBUG(0,("read_init_file: failed to open [%s]\n", filepath));
		TALLOC_FREE(info);
		return false;
	}

	while ( (x_fgets( str, sizeof(str)-1, f )) != NULL ) {
		/* ignore everything that is not a full line
		   comment starting with a '#' */

		if ( str[0] != '#' )
			continue;

		/* Look for a line like '^#.*Description:' */

		p = strstr( str, "Description:" );
		if (p != NULL) {
			char *desc;

			p += strlen( "Description:" ) + 1;
			if ( !p )
				break;

			desc = cleanup_string(p);
			if (desc != NULL)
				info->description = talloc_strdup( info, desc );
		}
	}

	x_fclose( f );

	if ( !info->description )
		info->description = talloc_strdup( info, "External Unix Service" );

	*service_info = info;
	TALLOC_FREE(filepath);

	return True;
}

/********************************************************************
 This is where we do the dirty work of filling in things like the
 Display name, Description, etc...
********************************************************************/

static WERROR svcctl_setvalue(struct registry_key *key,
			      const char *name,
			      struct registry_value *value)
{
	WERROR wresult;

	wresult = reg_setvalue(key, name, value);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("reg_setvalue failed for %s in key %s: %s\n",
			  name, key->key->name, win_errstr(wresult)));
	}

	return wresult;
}

static WERROR svcctl_setvalue_dword(struct registry_key *key,
				    const char *name,
				    uint32_t dword)
{
	struct registry_value value;

	value.type = REG_DWORD;
	value.data.length = sizeof(uint32_t);
	value.data.data = (uint8_t *)&dword;

	return svcctl_setvalue(key, name, &value);
}

static WERROR svcctl_setvalue_sz(struct registry_key *key,
				 const char *name,
				 const char *sz)
{
	struct registry_value value;
	WERROR wresult;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (!push_reg_sz(mem_ctx, &value.data, sz)) {
		DEBUG(0, ("push_reg_sz failed\n"));
		wresult = WERR_NOMEM;
		goto done;
	}
	value.type = REG_SZ;

	wresult = svcctl_setvalue(key, name, &value);
done:
	talloc_free(mem_ctx);
	return wresult;
}

static void fill_service_values(struct registry_key *key)
{
	char *dname, *ipath, *description;
	int i;
	WERROR wresult;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	char *name = NULL;

	name = strrchr(key->key->name, '\\');
	if (name == NULL) {
		name = key->key->name;
	} else {
		name++;
	}

	/* These values are hardcoded in all QueryServiceConfig() replies.
	   I'm just storing them here for cosmetic purposes */

	wresult = svcctl_setvalue_dword(key, "Start", SVCCTL_AUTO_START);
	if (!W_ERROR_IS_OK(wresult)) {
		goto done;
	}

	wresult = svcctl_setvalue_dword(key, "Type", SERVICE_TYPE_WIN32_OWN_PROCESS);
	if (!W_ERROR_IS_OK(wresult)) {
		goto done;
	}

	wresult = svcctl_setvalue_dword(key, "ErrorControl", SVCCTL_SVC_ERROR_NORMAL);
	if (!W_ERROR_IS_OK(wresult)) {
		goto done;
	}

	/* everything runs as LocalSystem */

	wresult = svcctl_setvalue_sz(key, "ObjectName", "LocalSystem");
	if (!W_ERROR_IS_OK(wresult)) {
		goto done;
	}

	/* special considerations for internal services and the DisplayName value */

	for ( i=0; builtin_svcs[i].servicename; i++ ) {
		if ( strequal( name, builtin_svcs[i].servicename ) ) {
			ipath = talloc_asprintf(mem_ctx, "%s/%s/%s",
						get_dyn_MODULESDIR(),
						SVCCTL_SCRIPT_DIR,
						builtin_svcs[i].daemon);
			description = talloc_strdup(mem_ctx, builtin_svcs[i].description);
			dname = talloc_strdup(mem_ctx, builtin_svcs[i].dispname);
			break;
		}
	}

	/* default to an external service if we haven't found a match */

	if ( builtin_svcs[i].servicename == NULL ) {
		char *dispname = NULL;
		struct rcinit_file_information *init_info = NULL;

		ipath = talloc_asprintf(mem_ctx, "%s/%s/%s",
					get_dyn_MODULESDIR(), SVCCTL_SCRIPT_DIR,
					name);

		/* lookup common unix display names */
		dispname = get_common_service_dispname(name);
		dname = talloc_strdup(mem_ctx, dispname ? dispname : "");
		SAFE_FREE(dispname);

		/* get info from init file itself */
		if ( read_init_file( name, &init_info ) ) {
			description = talloc_strdup(mem_ctx, init_info->description);
			TALLOC_FREE( init_info );
		}
		else {
			description = talloc_strdup(mem_ctx, "External Unix Service");
		}
	}

	/* add the new values */

	wresult = svcctl_setvalue_sz(key, "DisplayName", dname);
	if (!W_ERROR_IS_OK(wresult)) {
		goto done;
	}

	wresult = svcctl_setvalue_sz(key, "ImagePath", ipath);
	if (!W_ERROR_IS_OK(wresult)) {
		goto done;
	}

	wresult = svcctl_setvalue_sz(key, "Description", description);

done:
	talloc_free(mem_ctx);
	return;
}

/********************************************************************
********************************************************************/

static void add_new_svc_name(struct registry_key *key_parent,
			     const char *name)
{
	struct registry_key *key_service = NULL, *key_secdesc = NULL;
	WERROR wresult;
	struct security_descriptor *sd = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	enum winreg_CreateAction action = REG_ACTION_NONE;

	wresult = reg_createkey(mem_ctx, key_parent, name, REG_KEY_ALL,
				&key_service, &action);

	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("add_new_svc_name: reg_createkey failed for %s\\%s: "
			  "%s\n", key_parent->key->name, name,
			  win_errstr(wresult)));
		goto done;
	}

	/* now for the service values */

	fill_service_values(key_service);

	/* now add the security descriptor */

	sd = construct_service_sd(key_secdesc);
	if (sd == NULL) {
		DEBUG(0, ("add_new_svc_name: Failed to create default "
			  "sec_desc!\n"));
		goto done;
	}

	wresult = svcctl_set_secdesc_internal(key_service, sd);

done:
	talloc_free(mem_ctx);
	return;
}

/********************************************************************
********************************************************************/

void svcctl_init_keys( void )
{
	const char **service_list = lp_svcctl_list();
	int i;
	struct registry_key *key = NULL;
	struct registry_key *subkey = NULL;
	WERROR wresult;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	/* bad mojo here if the lookup failed.  Should not happen */

	wresult = reg_open_path(mem_ctx, KEY_SERVICES, REG_KEY_ALL, get_root_nt_token(), &key);

	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("svcctl_init_keys: key lookup failed! (%s)\n",
			win_errstr(wresult)));
		goto done;
	}

	/* the builtin services exist */

	for ( i=0; builtin_svcs[i].servicename; i++ )
		add_new_svc_name(key, builtin_svcs[i].servicename);

	for ( i=0; service_list && service_list[i]; i++ ) {

		/* only add new services */

		wresult = reg_openkey(mem_ctx, key, service_list[i], REG_KEY_ALL, &subkey);
		if (W_ERROR_IS_OK(wresult)) {
			continue;
		}

		/* Add the new service key and initialize the appropriate values */

		add_new_svc_name(key, service_list[i]);
	}

	/* initialize the control hooks */

	init_service_op_table();

done:
	talloc_free(mem_ctx);
	return;
}

/********************************************************************
 This is where we do the dirty work of filling in things like the
 Display name, Description, etc...Always return a default secdesc
 in case of any failure.
********************************************************************/

struct security_descriptor *svcctl_get_secdesc( TALLOC_CTX *ctx, const char *name, struct security_token *token )
{
	struct registry_key *key = NULL;
	struct registry_value *value;
	struct security_descriptor *ret_sd = NULL;
	char *path= NULL;
	WERROR wresult;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	path = talloc_asprintf(mem_ctx, "%s\\%s\\%s", KEY_SERVICES, name,
			       "Security");
	if (path == NULL) {
		goto done;
	}

	wresult = reg_open_path(mem_ctx, path, REG_KEY_ALL, token, &key);
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0,("svcctl_get_secdesc: key lookup failed! [%s] (%s)\n",
			path, win_errstr(wresult)));
		goto done;
	}

	wresult = reg_queryvalue(mem_ctx, key, "Security", &value);
	if (W_ERROR_EQUAL(wresult, WERR_BADFILE)) {
		goto fallback_to_default_sd;
	} else if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("svcctl_get_secdesc: error getting value 'Security': "
			  "%s\n", win_errstr(wresult)));
		goto done;
	}

	status = unmarshall_sec_desc(ctx, value->data.data,
				     value->data.length, &ret_sd);

	if (NT_STATUS_IS_OK(status)) {
		goto done;
	}

fallback_to_default_sd:
	DEBUG(6, ("svcctl_get_secdesc: constructing default secdesc for "
		  "service [%s]\n", name));
	ret_sd = construct_service_sd(ctx);

done:
	talloc_free(mem_ctx);
	return ret_sd;
}

/********************************************************************
 Wrapper to make storing a Service sd easier
********************************************************************/

static WERROR svcctl_set_secdesc_internal(struct registry_key *key,
					  struct security_descriptor *sec_desc)
{
	struct registry_key *key_security = NULL;
	WERROR wresult;
	struct registry_value value;
	NTSTATUS status;
	enum winreg_CreateAction action = REG_ACTION_NONE;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	wresult = reg_createkey(mem_ctx, key, "Security", REG_KEY_ALL, &key_security, &action);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("svcctl_set_secdesc: reg_createkey failed: "
			  "[%s\\Security] (%s)\n", key->key->name,
			  win_errstr(wresult)));
		goto done;
	}

	status = marshall_sec_desc(mem_ctx, sec_desc, &value.data.data,
				   &value.data.length);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("svcctl_set_secdesc: marshall_sec_desc() failed: %s\n",
			  nt_errstr(status)));
		wresult = ntstatus_to_werror(status);
		goto done;
	}

	value.type = REG_BINARY;

	wresult = reg_setvalue(key_security, "Security", &value);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("svcctl_set_secdesc: reg_setvalue failed: %s\n",
			  win_errstr(wresult)));
	}

done:
	talloc_free(mem_ctx);
	return wresult;
}

bool svcctl_set_secdesc(const char *name, struct security_descriptor *sec_desc,
			struct security_token *token)
{
	struct registry_key *key = NULL;
	WERROR wresult;
	char *path = NULL;
	bool ret = false;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	path = talloc_asprintf(mem_ctx, "%s\\%s", KEY_SERVICES, name);
	if (path == NULL) {
		goto done;
	}

	wresult = reg_open_path(mem_ctx, path, REG_KEY_ALL, token, &key);
	if ( !W_ERROR_IS_OK(wresult) ) {
		DEBUG(0, ("svcctl_set_secdesc: key lookup failed! [%s] (%s)\n",
			  path, win_errstr(wresult)));
		goto done;
	}

	wresult = svcctl_set_secdesc_internal(key, sec_desc);

	ret = W_ERROR_IS_OK(wresult);

done:
	talloc_free(mem_ctx);
	return ret;
}

const char *svcctl_get_string_value(TALLOC_CTX *ctx, const char *key_name,
				    const char *value_name,
				    struct security_token *token)
{
	const char *result = NULL;
	struct registry_key *key = NULL;
	struct registry_value *value = NULL;
	char *path = NULL;
	WERROR wresult;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	path = talloc_asprintf(mem_ctx, "%s\\%s", KEY_SERVICES, key_name);
	if (path == NULL) {
		goto done;
	}

	wresult = reg_open_path(mem_ctx, path, REG_KEY_READ, token, &key);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("svcctl_get_string_value: key lookup failed! "
			  "[%s] (%s)\n", path, win_errstr(wresult)));
		goto done;
	}

	wresult = reg_queryvalue(mem_ctx, key, value_name, &value);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(0, ("svcctl_get_string_value: error getting value "
			  "'%s': %s\n", value_name, win_errstr(wresult)));
		goto done;
	}

	if (value->type != REG_SZ) {
		goto done;
	}

	pull_reg_sz(ctx, &value->data, &result);

	goto done;

done:
	talloc_free(mem_ctx);
	return result;
}

/********************************************************************
********************************************************************/

const char *svcctl_lookup_dispname(TALLOC_CTX *ctx, const char *name, struct security_token *token )
{
	const char *display_name = NULL;

	display_name = svcctl_get_string_value(ctx, name, "DisplayName", token);

	if (display_name == NULL) {
		display_name = talloc_strdup(ctx, name);
	}

	return display_name;
}

/********************************************************************
********************************************************************/

const char *svcctl_lookup_description(TALLOC_CTX *ctx, const char *name, struct security_token *token )
{
	const char *description = NULL;

	description = svcctl_get_string_value(ctx, name, "Description", token);

	if (description == NULL) {
		description = talloc_strdup(ctx, "Unix Service");
	}

	return description;
}
