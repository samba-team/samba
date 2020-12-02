/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Michael Adam 2008
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   Copyright (C) Andrew Bartlett 2011

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

/*
 *  Load parameters.
 *
 *  This module provides suitable callback functions for the params
 *  module. It builds the internal table of service details which is
 *  then used by the rest of the server.
 *
 * To add a parameter:
 *
 * 1) add it to the global or service structure definition
 * 2) add it to the parm_table
 * 3) add it to the list of available functions (eg: using FN_GLOBAL_STRING())
 * 4) If it's a global then initialise it in init_globals. If a local
 *    (ie. service) parameter then initialise it in the sDefault structure
 *  
 *
 * Notes:
 *   The configuration file is processed sequentially for speed. It is NOT
 *   accessed randomly as happens in 'real' Windows. For this reason, there
 *   is a fair bit of sequence-dependent code here - ie., code which assumes
 *   that certain things happen before others. In particular, the code which
 *   happens at the boundary between sections is delicately poised, so be
 *   careful!
 *
 */

#define LOADPARM_SUBSTITUTION_INTERNALS 1
#include "includes.h"
#include "system/filesys.h"
#include "util_tdb.h"
#include "lib/param/loadparm.h"
#include "lib/param/param.h"
#include "printing.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_init.h"

#include "ads.h"
#include "../librpc/gen_ndr/svcctl.h"
#include "intl.h"
#include "../libcli/smb/smb_signing.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "../lib/util/bitmap.h"
#include "librpc/gen_ndr/nbt.h"
#include "source4/lib/tls/tls.h"
#include "libcli/auth/ntlm_check.h"
#include "lib/crypto/gnutls_helpers.h"

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

bool bLoaded = false;

extern userdom_struct current_user_info;

/* the special value for the include parameter
 * to be interpreted not as a file name but to
 * trigger loading of the global smb.conf options
 * from registry. */
#ifndef INCLUDE_REGISTRY_NAME
#define INCLUDE_REGISTRY_NAME "registry"
#endif

static bool in_client = false;		/* Not in the client by default */
static struct smbconf_csn conf_last_csn;

static int config_backend = CONFIG_BACKEND_FILE;

/* some helpful bits */
#define LP_SNUM_OK(i) (((i) >= 0) && ((i) < iNumServices) && \
                       (ServicePtrs != NULL) && \
		       (ServicePtrs[(i)] != NULL) && ServicePtrs[(i)]->valid)
#define VALID(i) ((ServicePtrs != NULL) && (ServicePtrs[i]!= NULL) && \
                  ServicePtrs[i]->valid)

#define USERSHARE_VALID 1
#define USERSHARE_PENDING_DELETE 2

static bool defaults_saved = false;

#include "lib/param/param_global.h"

static struct loadparm_global Globals;

/* This is a default service used to prime a services structure */
static const struct loadparm_service _sDefault =
{
	.valid = true,
	.autoloaded = false,
	.usershare = 0,
	.usershare_last_mod = {0, 0},
	.szService = NULL,
	.path = NULL,
	.invalid_users = NULL,
	.valid_users = NULL,
	.admin_users = NULL,
	.copy = NULL,
	.include = NULL,
	.preexec = NULL,
	.postexec = NULL,
	.root_preexec = NULL,
	.root_postexec = NULL,
	.cups_options = NULL,
	.print_command = NULL,
	.lpq_command = NULL,
	.lprm_command = NULL,
	.lppause_command = NULL,
	.lpresume_command = NULL,
	.queuepause_command = NULL,
	.queueresume_command = NULL,
	._printername = NULL,
	.printjob_username = NULL,
	.dont_descend = NULL,
	.hosts_allow = NULL,
	.hosts_deny = NULL,
	.magic_script = NULL,
	.magic_output = NULL,
	.veto_files = NULL,
	.hide_files = NULL,
	.veto_oplock_files = NULL,
	.comment = NULL,
	.force_user = NULL,
	.force_group = NULL,
	.read_list = NULL,
	.write_list = NULL,
	.volume = NULL,
	.fstype = NULL,
	.vfs_objects = NULL,
	.msdfs_proxy = NULL,
	.aio_write_behind = NULL,
	.dfree_command = NULL,
	.min_print_space = 0,
	.max_print_jobs = 1000,
	.max_reported_print_jobs = 0,
	.create_mask = 0744,
	.force_create_mode = 0,
	.directory_mask = 0755,
	.force_directory_mode = 0,
	.max_connections = 0,
	.default_case = CASE_LOWER,
	.printing = DEFAULT_PRINTING,
	.csc_policy = 0,
	.block_size = 1024,
	.dfree_cache_time = 0,
	.preexec_close = false,
	.root_preexec_close = false,
	.case_sensitive = Auto,
	.preserve_case = true,
	.short_preserve_case = true,
	.hide_dot_files = true,
	.hide_special_files = false,
	.hide_unreadable = false,
	.hide_unwriteable_files = false,
	.browseable = true,
	.access_based_share_enum = false,
	.available = true,
	.read_only = true,
	.spotlight = false,
	.guest_only = false,
	.administrative_share = false,
	.guest_ok = false,
	.printable = false,
	.print_notify_backchannel = false,
	.map_system = false,
	.map_hidden = false,
	.map_archive = true,
	.store_dos_attributes = true,
	.dmapi_support = false,
	.locking = true,
	.strict_locking = Auto,
	.posix_locking = true,
	.oplocks = true,
	.kernel_oplocks = false,
	.level2_oplocks = true,
	.mangled_names = MANGLED_NAMES_ILLEGAL,
	.wide_links = false,
	.follow_symlinks = true,
	.sync_always = false,
	.strict_allocate = false,
	.strict_rename = false,
	.strict_sync = true,
	.mangling_char = '~',
	.copymap = NULL,
	.delete_readonly = false,
	.fake_oplocks = false,
	.delete_veto_files = false,
	.dos_filemode = false,
	.dos_filetimes = true,
	.dos_filetime_resolution = false,
	.fake_directory_create_times = false,
	.blocking_locks = true,
	.inherit_permissions = false,
	.inherit_acls = false,
	.inherit_owner = false,
	.msdfs_root = false,
	.msdfs_shuffle_referrals = false,
	.use_client_driver = false,
	.default_devmode = true,
	.force_printername = false,
	.nt_acl_support = true,
	.force_unknown_acl_user = false,
	._use_sendfile = false,
	.map_acl_inherit = false,
	.afs_share = false,
	.ea_support = true,
	.acl_check_permissions = true,
	.acl_map_full_control = true,
	.acl_group_control = false,
	.acl_allow_execute_always = false,
	.aio_read_size = 1,
	.aio_write_size = 1,
	.map_readonly = MAP_READONLY_NO,
	.directory_name_cache_size = 100,
	.smb_encrypt = SMB_SIGNING_DEFAULT,
	.kernel_share_modes = true,
	.durable_handles = true,
	.check_parent_directory_delete_on_close = false,
	.param_opt = NULL,
	.smbd_search_ask_sharemode = true,
	.smbd_getinfo_ask_sharemode = true,
	.spotlight_backend = SPOTLIGHT_BACKEND_NOINDEX,
	.dummy = ""
};

/*
 * This is a copy of the default service structure. Service options in the
 * global section would otherwise overwrite the initial default values.
 */
static struct loadparm_service sDefault;

/* local variables */
static struct loadparm_service **ServicePtrs = NULL;
static int iNumServices = 0;
static int iServiceIndex = 0;
static struct db_context *ServiceHash;
static bool bInGlobalSection = true;
static bool bGlobalOnly = false;
static struct file_lists *file_lists = NULL;
static unsigned int *flags_list = NULL;

static void set_allowed_client_auth(void);

static bool lp_set_cmdline_helper(const char *pszParmName, const char *pszParmValue);
static void free_param_opts(struct parmlist_entry **popts);

/**
 *  Function to return the default value for the maximum number of open
 *  file descriptors permitted.  This function tries to consult the
 *  kernel-level (sysctl) and ulimit (getrlimit()) values and goes
 *  the smaller of those.
 */
static int max_open_files(void)
{
	int sysctl_max = MAX_OPEN_FILES;
	int rlimit_max = MAX_OPEN_FILES;

#ifdef HAVE_SYSCTLBYNAME
	{
		size_t size = sizeof(sysctl_max);
		sysctlbyname("kern.maxfilesperproc", &sysctl_max, &size, NULL,
			     0);
	}
#endif

#if (defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE))
	{
		struct rlimit rl;

		ZERO_STRUCT(rl);

		if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
			rlimit_max = rl.rlim_cur;

#if defined(RLIM_INFINITY)
		if(rl.rlim_cur == RLIM_INFINITY)
			rlimit_max = MAX_OPEN_FILES;
#endif
	}
#endif

	if (sysctl_max < MIN_OPEN_FILES_WINDOWS) {
		DEBUG(2,("max_open_files: increasing sysctl_max (%d) to "
			"minimum Windows limit (%d)\n",
			sysctl_max,
			MIN_OPEN_FILES_WINDOWS));
		sysctl_max = MIN_OPEN_FILES_WINDOWS;
	}

	if (rlimit_max < MIN_OPEN_FILES_WINDOWS) {
		DEBUG(2,("rlimit_max: increasing rlimit_max (%d) to "
			"minimum Windows limit (%d)\n",
			rlimit_max,
			MIN_OPEN_FILES_WINDOWS));
		rlimit_max = MIN_OPEN_FILES_WINDOWS;
	}

	return MIN(sysctl_max, rlimit_max);
}

/**
 * Common part of freeing allocated data for one parameter.
 */
static void free_one_parameter_common(void *parm_ptr,
				      struct parm_struct parm)
{
	if ((parm.type == P_STRING) ||
	    (parm.type == P_USTRING))
	{
		lpcfg_string_free((char**)parm_ptr);
	} else if (parm.type == P_LIST || parm.type == P_CMDLIST) {
		TALLOC_FREE(*((char***)parm_ptr));
	}
}

/**
 * Free the allocated data for one parameter for a share
 * given as a service struct.
 */
static void free_one_parameter(struct loadparm_service *service,
			       struct parm_struct parm)
{
	void *parm_ptr;

	if (parm.p_class != P_LOCAL) {
		return;
	}

	parm_ptr = lp_parm_ptr(service, &parm);

	free_one_parameter_common(parm_ptr, parm);
}

/**
 * Free the allocated parameter data of a share given
 * as a service struct.
 */
static void free_parameters(struct loadparm_service *service)
{
	uint32_t i;

	for (i=0; parm_table[i].label; i++) {
		free_one_parameter(service, parm_table[i]);
	}
}

/**
 * Free the allocated data for one parameter for a given share
 * specified by an snum.
 */
static void free_one_parameter_by_snum(int snum, struct parm_struct parm)
{
	void *parm_ptr;

	if (snum < 0) {
		parm_ptr = lp_parm_ptr(NULL, &parm);
	} else if (parm.p_class != P_LOCAL) {
		return;
	} else {
		parm_ptr = lp_parm_ptr(ServicePtrs[snum], &parm);
	}

	free_one_parameter_common(parm_ptr, parm);
}

/**
 * Free the allocated parameter data for a share specified
 * by an snum.
 */
static void free_parameters_by_snum(int snum)
{
	uint32_t i;

	for (i=0; parm_table[i].label; i++) {
		free_one_parameter_by_snum(snum, parm_table[i]);
	}
}

/**
 * Free the allocated global parameters.
 */
static void free_global_parameters(void)
{
	uint32_t i;
	struct parm_struct *parm;

	free_param_opts(&Globals.param_opt);
	free_parameters_by_snum(GLOBAL_SECTION_SNUM);

	/* Reset references in the defaults because the context is going to be freed */
	for (i=0; parm_table[i].label; i++) {
		parm = &parm_table[i];
		if ((parm->type == P_STRING) ||
		    (parm->type == P_USTRING)) {
			if ((parm->def.svalue != NULL) &&
			    (*(parm->def.svalue) != '\0')) {
				if (talloc_parent(parm->def.svalue) == Globals.ctx) {
					parm->def.svalue = NULL;
				}
			}
		}
	}
	TALLOC_FREE(Globals.ctx);
}

struct lp_stored_option {
	struct lp_stored_option *prev, *next;
	const char *label;
	const char *value;
};

static struct lp_stored_option *stored_options;

/*
  save options set by lp_set_cmdline() into a list. This list is
  re-applied when we do a globals reset, so that cmdline set options
  are sticky across reloads of smb.conf
 */
bool store_lp_set_cmdline(const char *pszParmName, const char *pszParmValue)
{
	struct lp_stored_option *entry, *entry_next;
	for (entry = stored_options; entry != NULL; entry = entry_next) {
		entry_next = entry->next;
		if (strcmp(pszParmName, entry->label) == 0) {
			DLIST_REMOVE(stored_options, entry);
			talloc_free(entry);
			break;
		}
	}

	entry = talloc(NULL, struct lp_stored_option);
	if (!entry) {
		return false;
	}

	entry->label = talloc_strdup(entry, pszParmName);
	if (!entry->label) {
		talloc_free(entry);
		return false;
	}

	entry->value = talloc_strdup(entry, pszParmValue);
	if (!entry->value) {
		talloc_free(entry);
		return false;
	}

	DLIST_ADD_END(stored_options, entry);

	return true;
}

static bool apply_lp_set_cmdline(void)
{
	struct lp_stored_option *entry = NULL;
	for (entry = stored_options; entry != NULL; entry = entry->next) {
		if (!lp_set_cmdline_helper(entry->label, entry->value)) {
			DEBUG(0, ("Failed to re-apply cmdline parameter %s = %s\n",
				  entry->label, entry->value));
			return false;
		}
	}
	return true;
}

/***************************************************************************
 Initialise the global parameter structure.
***************************************************************************/

static void init_globals(struct loadparm_context *lp_ctx, bool reinit_globals)
{
	static bool done_init = false;
	char *s = NULL;
	int i;

        /* If requested to initialize only once and we've already done it... */
        if (!reinit_globals && done_init) {
                /* ... then we have nothing more to do */
                return;
        }

	if (!done_init) {
		/* The logfile can be set before this is invoked. Free it if so. */
		lpcfg_string_free(&Globals.logfile);
		done_init = true;
	} else {
		free_global_parameters();
	}

	/* This memset and the free_global_parameters() above will
	 * wipe out smb.conf options set with lp_set_cmdline().  The
	 * apply_lp_set_cmdline() call puts these values back in the
	 * table once the defaults are set */
	ZERO_STRUCT(Globals);

	Globals.ctx = talloc_pooled_object(NULL, char, 272, 2048);

	/* Initialize the flags list if necessary */
	if (flags_list == NULL) {
		get_flags();
	}

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING))
		{
			lpcfg_string_set(
				Globals.ctx,
				(char **)lp_parm_ptr(NULL, &parm_table[i]),
				"");
		}
	}


	lpcfg_string_set(Globals.ctx, &sDefault.fstype, FSTYPE_STRING);
	lpcfg_string_set(Globals.ctx, &sDefault.printjob_username, "%U");

	init_printer_values(lp_ctx, Globals.ctx, &sDefault);

	sDefault.ntvfs_handler = str_list_make_v3_const(Globals.ctx, "unixuid default", NULL);

	DEBUG(3, ("Initialising global parameters\n"));

	/* Must manually force to upper case here, as this does not go via the handler */
	lpcfg_string_set(Globals.ctx, &Globals.netbios_name,
			 myhostname_upper());

	lpcfg_string_set(Globals.ctx, &Globals.smb_passwd_file,
			 get_dyn_SMB_PASSWD_FILE());
	lpcfg_string_set(Globals.ctx, &Globals.private_dir,
			 get_dyn_PRIVATE_DIR());
	lpcfg_string_set(Globals.ctx, &Globals.binddns_dir,
			 get_dyn_BINDDNS_DIR());

	/* use the new 'hash2' method by default, with a prefix of 1 */
	lpcfg_string_set(Globals.ctx, &Globals.mangling_method, "hash2");
	Globals.mangle_prefix = 1;

	lpcfg_string_set(Globals.ctx, &Globals.guest_account, GUEST_ACCOUNT);

	/* using UTF8 by default allows us to support all chars */
	lpcfg_string_set(Globals.ctx, &Globals.unix_charset,
			 DEFAULT_UNIX_CHARSET);

	/* Use codepage 850 as a default for the dos character set */
	lpcfg_string_set(Globals.ctx, &Globals.dos_charset,
			 DEFAULT_DOS_CHARSET);

	/*
	 * Allow the default PASSWD_CHAT to be overridden in local.h.
	 */
	lpcfg_string_set(Globals.ctx, &Globals.passwd_chat,
			 DEFAULT_PASSWD_CHAT);

	lpcfg_string_set(Globals.ctx, &Globals.workgroup, DEFAULT_WORKGROUP);

	lpcfg_string_set(Globals.ctx, &Globals.passwd_program, "");
	lpcfg_string_set(Globals.ctx, &Globals.lock_directory,
			 get_dyn_LOCKDIR());
	lpcfg_string_set(Globals.ctx, &Globals.state_directory,
			 get_dyn_STATEDIR());
	lpcfg_string_set(Globals.ctx, &Globals.cache_directory,
			 get_dyn_CACHEDIR());
	lpcfg_string_set(Globals.ctx, &Globals.pid_directory,
			 get_dyn_PIDDIR());
	lpcfg_string_set(Globals.ctx, &Globals.nbt_client_socket_address,
			 "0.0.0.0");
	/*
	 * By default support explicit binding to broadcast
 	 * addresses.
 	 */
	Globals.nmbd_bind_explicit_broadcast = true;

	s = talloc_asprintf(talloc_tos(), "Samba %s", samba_version_string());
	if (s == NULL) {
		smb_panic("init_globals: ENOMEM");
	}
	lpcfg_string_set(Globals.ctx, &Globals.server_string, s);
	TALLOC_FREE(s);
#ifdef DEVELOPER
	lpcfg_string_set(Globals.ctx, &Globals.panic_action,
			 "/bin/sleep 999999999");
#endif

	lpcfg_string_set(Globals.ctx, &Globals.socket_options,
			 DEFAULT_SOCKET_OPTIONS);

	lpcfg_string_set(Globals.ctx, &Globals.logon_drive, "");
	/* %N is the NIS auto.home server if -DAUTOHOME is used, else same as %L */
	lpcfg_string_set(Globals.ctx, &Globals.logon_home, "\\\\%N\\%U");
	lpcfg_string_set(Globals.ctx, &Globals.logon_path,
			 "\\\\%N\\%U\\profile");

	Globals.name_resolve_order =
			str_list_make_v3_const(Globals.ctx,
					       DEFAULT_NAME_RESOLVE_ORDER,
					       NULL);
	lpcfg_string_set(Globals.ctx, &Globals.password_server, "*");

	Globals.algorithmic_rid_base = BASE_RID;

	Globals.load_printers = true;
	Globals.printcap_cache_time = 750; 	/* 12.5 minutes */

	Globals.config_backend = config_backend;
	Globals._server_role = ROLE_AUTO;

	/* Was 65535 (0xFFFF). 0x4101 matches W2K and causes major speed improvements... */
	/* Discovered by 2 days of pain by Don McCall @ HP :-). */
	Globals.max_xmit = 0x4104;
	Globals.max_mux = 50;	/* This is *needed* for profile support. */
	Globals.lpq_cache_time = 30;	/* changed to handle large print servers better -- jerry */
	Globals._disable_spoolss = false;
	Globals.max_smbd_processes = 0;/* no limit specified */
	Globals.username_level = 0;
	Globals.deadtime = 10080;
	Globals.getwd_cache = true;
	Globals.large_readwrite = true;
	Globals.max_log_size = 5000;
	Globals.max_open_files = max_open_files();
	Globals.server_max_protocol = PROTOCOL_SMB3_11;
	Globals.server_min_protocol = PROTOCOL_SMB2_02;
	Globals._client_max_protocol = PROTOCOL_DEFAULT;
	Globals.client_min_protocol = PROTOCOL_SMB2_02;
	Globals._client_ipc_max_protocol = PROTOCOL_DEFAULT;
	Globals._client_ipc_min_protocol = PROTOCOL_DEFAULT;
	Globals._security = SEC_AUTO;
	Globals.encrypt_passwords = true;
	Globals.client_schannel = true;
	Globals.winbind_sealed_pipes = true;
	Globals.require_strong_key = true;
	Globals.server_schannel = true;
	Globals.read_raw = true;
	Globals.write_raw = true;
	Globals.null_passwords = false;
	Globals.old_password_allowed_period = 60;
	Globals.obey_pam_restrictions = false;
	Globals.syslog = 1;
	Globals.syslog_only = false;
	Globals.timestamp_logs = true;
	lpcfg_string_set(Globals.ctx, &Globals.log_level, "0");
	Globals.debug_prefix_timestamp = false;
	Globals.debug_hires_timestamp = true;
	Globals.debug_pid = false;
	Globals.debug_uid = false;
	Globals.debug_class = false;
	Globals.enable_core_files = true;
	Globals.max_ttl = 60 * 60 * 24 * 3;	/* 3 days default. */
	Globals.max_wins_ttl = 60 * 60 * 24 * 6;	/* 6 days default. */
	Globals.min_wins_ttl = 60 * 60 * 6;	/* 6 hours default. */
	Globals.machine_password_timeout = 60 * 60 * 24 * 7;	/* 7 days default. */
	Globals.lm_announce = Auto;	/* = Auto: send only if LM clients found */
	Globals.lm_interval = 60;
#if (defined(HAVE_NETGROUP) && defined(WITH_AUTOMOUNT))
	Globals.nis_homedir = false;
#ifdef WITH_NISPLUS_HOME
	lpcfg_string_set(Globals.ctx, &Globals.homedir_map,
			 "auto_home.org_dir");
#else
	lpcfg_string_set(Globals.ctx, &Globals.homedir_map, "auto.home");
#endif
#endif
	Globals.time_server = false;
	Globals.bind_interfaces_only = false;
	Globals.unix_password_sync = false;
	Globals.pam_password_change = false;
	Globals.passwd_chat_debug = false;
	Globals.passwd_chat_timeout = 2; /* 2 second default. */
	Globals.nt_pipe_support = true;	/* Do NT pipes by default. */
	Globals.nt_status_support = true; /* Use NT status by default. */
	Globals.smbd_profiling_level = 0;
	Globals.stat_cache = true;	/* use stat cache by default */
	Globals.max_stat_cache_size = 512; /* 512k by default */
	Globals.restrict_anonymous = 0;
	Globals.client_lanman_auth = false;	/* Do NOT use the LanMan hash if it is available */
	Globals.client_plaintext_auth = false;	/* Do NOT use a plaintext password even if is requested by the server */
	Globals._lanman_auth = false;	/* Do NOT use the LanMan hash, even if it is supplied */
	Globals.ntlm_auth = NTLM_AUTH_NTLMV2_ONLY;	/* Do NOT use NTLMv1 if it is supplied by the client (otherwise NTLMv2) */
	Globals.raw_ntlmv2_auth = false; /* Reject NTLMv2 without NTLMSSP */
	Globals.client_ntlmv2_auth = true; /* Client should always use use NTLMv2, as we can't tell that the server supports it, but most modern servers do */
	/* Note, that we will also use NTLM2 session security (which is different), if it is available */

	Globals.allow_dcerpc_auth_level_connect = false; /* we don't allow this by default */

	Globals.map_to_guest = 0;	/* By Default, "Never" */
	Globals.oplock_break_wait_time = 0;	/* By Default, 0 msecs. */
	Globals.enhanced_browsing = true;
	Globals.lock_spin_time = WINDOWS_MINIMUM_LOCK_TIMEOUT_MS; /* msec. */
	Globals.use_mmap = true;
	Globals.unicode = true;
	Globals.unix_extensions = true;
	Globals.reset_on_zero_vc = false;
	Globals.log_writeable_files_on_exit = false;
	Globals.create_krb5_conf = true;
	Globals.include_system_krb5_conf = true;
	Globals._winbind_max_domain_connections = 1;

	/* hostname lookups can be very expensive and are broken on
	   a large number of sites (tridge) */
	Globals.hostname_lookups = false;

	Globals.change_notify = true,
	Globals.kernel_change_notify = true,

	lpcfg_string_set(Globals.ctx, &Globals.passdb_backend, "tdbsam");
	lpcfg_string_set(Globals.ctx, &Globals.ldap_suffix, "");
	lpcfg_string_set(Globals.ctx, &Globals._ldap_machine_suffix, "");
	lpcfg_string_set(Globals.ctx, &Globals._ldap_user_suffix, "");
	lpcfg_string_set(Globals.ctx, &Globals._ldap_group_suffix, "");
	lpcfg_string_set(Globals.ctx, &Globals._ldap_idmap_suffix, "");

	lpcfg_string_set(Globals.ctx, &Globals.ldap_admin_dn, "");
	Globals.ldap_ssl = LDAP_SSL_START_TLS;
	Globals.ldap_deref = -1;
	Globals.ldap_passwd_sync = LDAP_PASSWD_SYNC_OFF;
	Globals.ldap_delete_dn = false;
	Globals.ldap_replication_sleep = 1000; /* wait 1 sec for replication */
	Globals.ldap_follow_referral = Auto;
	Globals.ldap_timeout = LDAP_DEFAULT_TIMEOUT;
	Globals.ldap_connection_timeout = LDAP_CONNECTION_DEFAULT_TIMEOUT;
	Globals.ldap_page_size = LDAP_PAGE_SIZE;

	Globals.ldap_debug_level = 0;
	Globals.ldap_debug_threshold = 10;

	Globals.client_ldap_sasl_wrapping = ADS_AUTH_SASL_SIGN;

	Globals.ldap_server_require_strong_auth =
		LDAP_SERVER_REQUIRE_STRONG_AUTH_YES;

	/* This is what we tell the afs client. in reality we set the token 
	 * to never expire, though, when this runs out the afs client will 
	 * forget the token. Set to 0 to get NEVERDATE.*/
	Globals.afs_token_lifetime = 604800;
	Globals.cups_connection_timeout = CUPS_DEFAULT_CONNECTION_TIMEOUT;

/* these parameters are set to defaults that are more appropriate
   for the increasing samba install base:

   as a member of the workgroup, that will possibly become a
   _local_ master browser (lm = true).  this is opposed to a forced
   local master browser startup (pm = true).

   doesn't provide WINS server service by default (wsupp = false),
   and doesn't provide domain master browser services by default, either.

*/

	Globals.show_add_printer_wizard = true;
	Globals.os_level = 20;
	Globals.local_master = true;
	Globals._domain_master = Auto;	/* depending on _domain_logons */
	Globals._domain_logons = false;
	Globals.browse_list = true;
	Globals.we_are_a_wins_server = false;
	Globals.wins_proxy = false;

	TALLOC_FREE(Globals.init_logon_delayed_hosts);
	Globals.init_logon_delay = 100; /* 100 ms default delay */

	Globals.wins_dns_proxy = true;

	Globals.allow_trusted_domains = true;
	lpcfg_string_set(Globals.ctx, &Globals.idmap_backend, "tdb");

	lpcfg_string_set(Globals.ctx, &Globals.template_shell, "/bin/false");
	lpcfg_string_set(Globals.ctx, &Globals.template_homedir,
			 "/home/%D/%U");
	lpcfg_string_set(Globals.ctx, &Globals.winbind_separator, "\\");
	lpcfg_string_set(Globals.ctx, &Globals.winbindd_socket_directory,
			 dyn_WINBINDD_SOCKET_DIR);

	lpcfg_string_set(Globals.ctx, &Globals.cups_server, "");
	lpcfg_string_set(Globals.ctx, &Globals.iprint_server, "");

	lpcfg_string_set(Globals.ctx, &Globals._ctdbd_socket, "");

	Globals.cluster_addresses = NULL;
	Globals.clustering = false;
	Globals.ctdb_timeout = 0;
	Globals.ctdb_locktime_warn_threshold = 0;

	Globals.winbind_cache_time = 300;	/* 5 minutes */
	Globals.winbind_reconnect_delay = 30;	/* 30 seconds */
	Globals.winbind_request_timeout = 60;   /* 60 seconds */
	Globals.winbind_max_clients = 200;
	Globals.winbind_enum_users = false;
	Globals.winbind_enum_groups = false;
	Globals.winbind_use_default_domain = false;
	Globals.winbind_nested_groups = true;
	Globals.winbind_expand_groups = 0;
	Globals.winbind_nss_info = str_list_make_v3_const(NULL, "template", NULL);
	Globals.winbind_refresh_tickets = false;
	Globals.winbind_offline_logon = false;
	Globals.winbind_scan_trusted_domains = true;

	Globals.idmap_cache_time = 86400 * 7; /* a week by default */
	Globals.idmap_negative_cache_time = 120; /* 2 minutes by default */

	Globals.passdb_expand_explicit = false;

	Globals.name_cache_timeout = 660; /* In seconds */

	Globals.client_use_spnego = true;

	Globals.client_signing = SMB_SIGNING_DEFAULT;
	Globals._client_ipc_signing = SMB_SIGNING_DEFAULT;
	Globals.server_signing = SMB_SIGNING_DEFAULT;

	Globals.defer_sharing_violations = true;
	Globals.smb_ports = str_list_make_v3_const(NULL, SMB_PORTS, NULL);

	Globals.enable_privileges = true;
	Globals.host_msdfs        = true;
	Globals.enable_asu_support       = false;

	/* User defined shares. */
	s = talloc_asprintf(talloc_tos(), "%s/usershares", get_dyn_STATEDIR());
	if (s == NULL) {
		smb_panic("init_globals: ENOMEM");
	}
	lpcfg_string_set(Globals.ctx, &Globals.usershare_path, s);
	TALLOC_FREE(s);
	lpcfg_string_set(Globals.ctx, &Globals.usershare_template_share, "");
	Globals.usershare_max_shares = 0;
	/* By default disallow sharing of directories not owned by the sharer. */
	Globals.usershare_owner_only = true;
	/* By default disallow guest access to usershares. */
	Globals.usershare_allow_guests = false;

	Globals.keepalive = DEFAULT_KEEPALIVE;

	/* By default no shares out of the registry */
	Globals.registry_shares = false;

	Globals.min_receivefile_size = 0;

	Globals.multicast_dns_register = true;

	Globals.smb2_max_read = DEFAULT_SMB2_MAX_READ;
	Globals.smb2_max_write = DEFAULT_SMB2_MAX_WRITE;
	Globals.smb2_max_trans = DEFAULT_SMB2_MAX_TRANSACT;
	Globals.smb2_max_credits = DEFAULT_SMB2_MAX_CREDITS;
	Globals.smb2_leases = true;

	lpcfg_string_set(Globals.ctx, &Globals.ncalrpc_dir,
			 get_dyn_NCALRPCDIR());

	Globals.server_services = str_list_make_v3_const(NULL, "s3fs rpc nbt wrepl ldap cldap kdc drepl winbindd ntp_signd kcc dnsupdate dns", NULL);

	Globals.dcerpc_endpoint_servers = str_list_make_v3_const(NULL, "epmapper wkssvc rpcecho samr netlogon lsarpc drsuapi dssetup unixinfo browser eventlog6 backupkey dnsserver", NULL);

	Globals.tls_enabled = true;
	Globals.tls_verify_peer = TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE;

	lpcfg_string_set(Globals.ctx, &Globals._tls_keyfile, "tls/key.pem");
	lpcfg_string_set(Globals.ctx, &Globals._tls_certfile, "tls/cert.pem");
	lpcfg_string_set(Globals.ctx, &Globals._tls_cafile, "tls/ca.pem");
	lpcfg_string_set(Globals.ctx,
			 &Globals.tls_priority,
			 "NORMAL:-VERS-SSL3.0");

	lpcfg_string_set(Globals.ctx, &Globals.share_backend, "classic");

	Globals._preferred_master = Auto;

	Globals.allow_dns_updates = DNS_UPDATE_SIGNED;
	Globals.dns_zone_scavenging = false;

	lpcfg_string_set(Globals.ctx, &Globals.ntp_signd_socket_directory,
			 get_dyn_NTP_SIGND_SOCKET_DIR());

	s = talloc_asprintf(talloc_tos(), "%s/samba_kcc", get_dyn_SCRIPTSBINDIR());
	if (s == NULL) {
		smb_panic("init_globals: ENOMEM");
	}
	Globals.samba_kcc_command = str_list_make_v3_const(NULL, s, NULL);
	TALLOC_FREE(s);

#ifdef MIT_KDC_PATH
	Globals.mit_kdc_command = str_list_make_v3_const(NULL, MIT_KDC_PATH, NULL);
#endif

	s = talloc_asprintf(talloc_tos(), "%s/samba_dnsupdate", get_dyn_SCRIPTSBINDIR());
	if (s == NULL) {
		smb_panic("init_globals: ENOMEM");
	}
	Globals.dns_update_command = str_list_make_v3_const(NULL, s, NULL);
	TALLOC_FREE(s);

	s = talloc_asprintf(talloc_tos(), "%s/samba-gpupdate", get_dyn_SCRIPTSBINDIR());
	if (s == NULL) {
		smb_panic("init_globals: ENOMEM");
	}
	Globals.gpo_update_command = str_list_make_v3_const(NULL, s, NULL);
	TALLOC_FREE(s);

	Globals.apply_group_policies = false;

	s = talloc_asprintf(talloc_tos(), "%s/samba_spnupdate", get_dyn_SCRIPTSBINDIR());
	if (s == NULL) {
		smb_panic("init_globals: ENOMEM");
	}
	Globals.spn_update_command = str_list_make_v3_const(NULL, s, NULL);
	TALLOC_FREE(s);

	Globals.nsupdate_command = str_list_make_v3_const(NULL, "/usr/bin/nsupdate -g", NULL);

	Globals.cldap_port = 389;

	Globals.dgram_port = NBT_DGRAM_SERVICE_PORT;

	Globals.nbt_port = NBT_NAME_SERVICE_PORT;

	Globals.krb5_port = 88;

	Globals.kpasswd_port = 464;

	Globals.aio_max_threads = 100;

	lpcfg_string_set(Globals.ctx,
			 &Globals.rpc_server_dynamic_port_range,
			 "49152-65535");
	Globals.rpc_low_port = SERVER_TCP_LOW_PORT;
	Globals.rpc_high_port = SERVER_TCP_HIGH_PORT;
	Globals.prefork_children = 4;
	Globals.prefork_backoff_increment = 10;
	Globals.prefork_maximum_backoff = 120;

	Globals.ldap_max_anonymous_request_size = 256000;
	Globals.ldap_max_authenticated_request_size = 16777216;
	Globals.ldap_max_search_request_size = 256000;

	/* Now put back the settings that were set with lp_set_cmdline() */
	apply_lp_set_cmdline();
}

/* Convenience routine to setup an lp_context with additional s3 variables */
static struct loadparm_context *setup_lp_context(TALLOC_CTX *mem_ctx)
{
	struct loadparm_context *lp_ctx;

	lp_ctx = loadparm_init_s3(mem_ctx,
				  loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DEBUG(0, ("loadparm_init_s3 failed\n"));
		return NULL;
	}

	lp_ctx->sDefault = talloc_zero(lp_ctx, struct loadparm_service);
	if (lp_ctx->sDefault == NULL) {
		DBG_ERR("talloc_zero failed\n");
		TALLOC_FREE(lp_ctx);
		return NULL;
	}

	*lp_ctx->sDefault = _sDefault;
	lp_ctx->services = NULL; /* We do not want to access this directly */
	lp_ctx->bInGlobalSection = bInGlobalSection;
	lp_ctx->flags = flags_list;

	return lp_ctx;
}

/*******************************************************************
 Convenience routine to grab string parameters into talloced memory
 and run standard_sub_basic on them. The buffers can be written to by
 callers without affecting the source string.
********************************************************************/

static char *loadparm_s3_global_substitution_fn(
			TALLOC_CTX *mem_ctx,
			const struct loadparm_substitution *lp_sub,
			const char *s,
			void *private_data)
{
	char *ret;

	/* The follow debug is useful for tracking down memory problems
	   especially if you have an inner loop that is calling a lp_*()
	   function that returns a string.  Perhaps this debug should be
	   present all the time? */

#if 0
	DEBUG(10, ("lp_string(%s)\n", s));
#endif
	if (!s) {
		return NULL;
	}

	ret = talloc_sub_basic(mem_ctx,
			get_current_username(),
			current_user_info.domain,
			s);
	if (trim_char(ret, '\"', '\"')) {
		if (strchr(ret,'\"') != NULL) {
			TALLOC_FREE(ret);
			ret = talloc_sub_basic(mem_ctx,
					get_current_username(),
					current_user_info.domain,
					s);
		}
	}
	return ret;
}

static const struct loadparm_substitution s3_global_substitution = {
	.substituted_string_fn = loadparm_s3_global_substitution_fn,
};

const struct loadparm_substitution *loadparm_s3_global_substitution(void)
{
	return &s3_global_substitution;
}

/*
   In this section all the functions that are used to access the
   parameters from the rest of the program are defined
*/

#define FN_GLOBAL_SUBSTITUTED_STRING(fn_name,ptr) \
char *lp_ ## fn_name(TALLOC_CTX *ctx, const struct loadparm_substitution *lp_sub) \
 {return lpcfg_substituted_string(ctx, lp_sub, *(char **)(&Globals.ptr) ? *(char **)(&Globals.ptr) : "");}
#define FN_GLOBAL_CONST_STRING(fn_name,ptr) \
 const char *lp_ ## fn_name(void) {return(*(const char * const *)(&Globals.ptr) ? *(const char * const *)(&Globals.ptr) : "");}
#define FN_GLOBAL_LIST(fn_name,ptr) \
 const char **lp_ ## fn_name(void) {return(*(const char ***)(&Globals.ptr));}
#define FN_GLOBAL_BOOL(fn_name,ptr) \
 bool lp_ ## fn_name(void) {return(*(bool *)(&Globals.ptr));}
#define FN_GLOBAL_CHAR(fn_name,ptr) \
 char lp_ ## fn_name(void) {return(*(char *)(&Globals.ptr));}
#define FN_GLOBAL_INTEGER(fn_name,ptr) \
 int lp_ ## fn_name(void) {return(*(int *)(&Globals.ptr));}

#define FN_LOCAL_SUBSTITUTED_STRING(fn_name,val) \
char *lp_ ## fn_name(TALLOC_CTX *ctx, const struct loadparm_substitution *lp_sub, int i) \
 {return lpcfg_substituted_string((ctx), lp_sub, (LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_CONST_STRING(fn_name,val) \
 const char *lp_ ## fn_name(int i) {return (const char *)((LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_LIST(fn_name,val) \
 const char **lp_ ## fn_name(int i) {return(const char **)(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_BOOL(fn_name,val) \
 bool lp_ ## fn_name(int i) {return(bool)(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_INTEGER(fn_name,val) \
 int lp_ ## fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}

#define FN_LOCAL_PARM_BOOL(fn_name,val) \
 bool lp_ ## fn_name(const struct share_params *p) {return(bool)(LP_SNUM_OK(p->service)? ServicePtrs[(p->service)]->val : sDefault.val);}
#define FN_LOCAL_PARM_INTEGER(fn_name,val) \
 int lp_ ## fn_name(const struct share_params *p) {return(LP_SNUM_OK(p->service)? ServicePtrs[(p->service)]->val : sDefault.val);}
#define FN_LOCAL_PARM_CHAR(fn_name,val) \
 char lp_ ## fn_name(const struct share_params *p) {return(LP_SNUM_OK(p->service)? ServicePtrs[(p->service)]->val : sDefault.val);}

int lp_winbind_max_domain_connections(void)
{
	if (lp_winbind_offline_logon() &&
	    lp__winbind_max_domain_connections() > 1) {
		DEBUG(1, ("offline logons active, restricting max domain "
			  "connections to 1\n"));
		return 1;
	}
	return MAX(1, lp__winbind_max_domain_connections());
}

/* These functions remain in source3/param for now */

#include "lib/param/param_functions.c"

FN_LOCAL_SUBSTITUTED_STRING(servicename, szService)
FN_LOCAL_CONST_STRING(const_servicename, szService)

/* These functions cannot be auto-generated */
FN_LOCAL_BOOL(autoloaded, autoloaded)
FN_GLOBAL_CONST_STRING(dnsdomain, dnsdomain)

/* local prototypes */

static int map_parameter_canonical(const char *pszParmName, bool *inverse);
static const char *get_boolean(bool bool_value);
static bool do_parameter(const char *pszParmName, const char *pszParmValue,
			 void *userdata);
static bool hash_a_service(const char *name, int number);
static void free_service_byindex(int iService);
static void show_parameter(int parmIndex);
static bool is_synonym_of(int parm1, int parm2, bool *inverse);
static bool lp_parameter_value_is_valid(const char *parm_name, const char *val);

/*
 * This is a helper function for parametrical options support.  It returns a
 * pointer to parametrical option value if it exists or NULL otherwise. Actual
 * parametrical functions are quite simple
 */
static struct parmlist_entry *get_parametrics(int snum, const char *type,
						const char *option)
{
	if (snum >= iNumServices) return NULL;

	if (snum < 0) {
		return get_parametric_helper(NULL, type, option, Globals.param_opt);
	} else {
		return get_parametric_helper(ServicePtrs[snum],
					     type, option, Globals.param_opt);
	}
}

static void discard_whitespace(char *str)
{
	size_t len = strlen(str);
	size_t i = 0;

	while (i < len) {
		if (isspace(str[i])) {
			memmove(&str[i], &str[i+1], len-i);
			len -= 1;
			continue;
		}
		i += 1;
	}
}

/**
 * @brief Go through all global parametric parameters
 *
 * @param regex_str	A regular expression to scan param for
 * @param max_matches   Max number of submatches the regexp expects
 * @param cb		Function to call on match. Should return true
 *                      when it wants wi_scan_global_parametrics to stop
 *                      scanning
 * @param private_data  Anonymous pointer passed to cb
 *
 * @return              0: success, regcomp/regexec return value on error.
 *                      See "man regexec" for possible errors
 */

int lp_wi_scan_global_parametrics(
	const char *regex_str, size_t max_matches,
	bool (*cb)(const char *string, regmatch_t matches[],
		   void *private_data),
	void *private_data)
{
	struct parmlist_entry *data;
	regex_t regex;
	int ret;

	ret = regcomp(&regex, regex_str, REG_ICASE);
	if (ret != 0) {
		return ret;
	}

	for (data = Globals.param_opt; data != NULL; data = data->next) {
		size_t keylen = strlen(data->key);
		char key[keylen+1];
		regmatch_t matches[max_matches];
		bool stop;

		memcpy(key, data->key, sizeof(key));
		discard_whitespace(key);

		ret = regexec(&regex, key, max_matches, matches, 0);
		if (ret == REG_NOMATCH) {
			continue;
		}
		if (ret != 0) {
			goto fail;
		}

		stop = cb(key, matches, private_data);
		if (stop) {
			break;
		}
	}

	ret = 0;
fail:
	regfree(&regex);
	return ret;
}


#define MISSING_PARAMETER(name) \
    DEBUG(0, ("%s(): value is NULL or empty!\n", #name))

/*******************************************************************
convenience routine to return enum parameters.
********************************************************************/
static int lp_enum(const char *s,const struct enum_list *_enum)
{
	int i;

	if (!s || !*s || !_enum) {
		MISSING_PARAMETER(lp_enum);
		return (-1);
	}

	for (i=0; _enum[i].name; i++) {
		if (strequal(_enum[i].name,s))
			return _enum[i].value;
	}

	DEBUG(0,("lp_enum(%s,enum): value is not in enum_list!\n",s));
	return (-1);
}

#undef MISSING_PARAMETER

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
char *lp_parm_substituted_string(TALLOC_CTX *mem_ctx,
				 const struct loadparm_substitution *lp_sub,
				 int snum,
				 const char *type,
				 const char *option,
				 const char *def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	SMB_ASSERT(lp_sub != NULL);

	if (data == NULL||data->value==NULL) {
		if (def) {
			return lpcfg_substituted_string(mem_ctx, lp_sub, def);
		} else {
			return NULL;
		}
	}

	return lpcfg_substituted_string(mem_ctx, lp_sub, data->value);
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
const char *lp_parm_const_string(int snum, const char *type, const char *option, const char *def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data == NULL||data->value==NULL)
		return def;

	return data->value;
}


/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

const char **lp_parm_string_list(int snum, const char *type, const char *option, const char **def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data == NULL||data->value==NULL)
		return (const char **)def;

	if (data->list==NULL) {
		data->list = str_list_make_v3(NULL, data->value, NULL);
	}

	return discard_const_p(const char *, data->list);
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_int(int snum, const char *type, const char *option, int def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value)
		return lp_int(data->value);

	return def;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

unsigned long lp_parm_ulong(int snum, const char *type, const char *option, unsigned long def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value)
		return lp_ulong(data->value);

	return def;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

unsigned long long lp_parm_ulonglong(int snum, const char *type,
				     const char *option, unsigned long long def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value) {
		return lp_ulonglong(data->value);
	}

	return def;
}

/* Return parametric option from a given service. Type is a part of option
 * before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

bool lp_parm_bool(int snum, const char *type, const char *option, bool def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value)
		return lp_bool(data->value);

	return def;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_enum(int snum, const char *type, const char *option,
		 const struct enum_list *_enum, int def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value && _enum)
		return lp_enum(data->value, _enum);

	return def;
}

/**
 * free a param_opts structure.
 * param_opts handling should be moved to talloc;
 * then this whole functions reduces to a TALLOC_FREE().
 */

static void free_param_opts(struct parmlist_entry **popts)
{
	struct parmlist_entry *opt, *next_opt;

	if (*popts != NULL) {
		DEBUG(5, ("Freeing parametrics:\n"));
	}
	opt = *popts;
	while (opt != NULL) {
		lpcfg_string_free(&opt->key);
		lpcfg_string_free(&opt->value);
		TALLOC_FREE(opt->list);
		next_opt = opt->next;
		TALLOC_FREE(opt);
		opt = next_opt;
	}
	*popts = NULL;
}

/***************************************************************************
 Free the dynamically allocated parts of a service struct.
***************************************************************************/

static void free_service(struct loadparm_service *pservice)
{
	if (!pservice)
		return;

	if (pservice->szService)
		DEBUG(5, ("free_service: Freeing service %s\n",
		       pservice->szService));

	free_parameters(pservice);

	lpcfg_string_free(&pservice->szService);
	TALLOC_FREE(pservice->copymap);

	free_param_opts(&pservice->param_opt);

	ZERO_STRUCTP(pservice);
}


/***************************************************************************
 remove a service indexed in the ServicePtrs array from the ServiceHash
 and free the dynamically allocated parts
***************************************************************************/

static void free_service_byindex(int idx)
{
	if ( !LP_SNUM_OK(idx) ) 
		return;

	ServicePtrs[idx]->valid = false;

	/* we have to cleanup the hash record */

	if (ServicePtrs[idx]->szService) {
		char *canon_name = canonicalize_servicename(
			talloc_tos(),
			ServicePtrs[idx]->szService );

		dbwrap_delete_bystring(ServiceHash, canon_name );
		TALLOC_FREE(canon_name);
	}

	free_service(ServicePtrs[idx]);
	TALLOC_FREE(ServicePtrs[idx]);
}

/***************************************************************************
 Add a new service to the services array initialising it with the given 
 service. 
***************************************************************************/

static int add_a_service(const struct loadparm_service *pservice, const char *name)
{
	int i;
	struct loadparm_service **tsp = NULL;

	/* it might already exist */
	if (name) {
		i = getservicebyname(name, NULL);
		if (i >= 0) {
			return (i);
		}
	}

	/* Re use empty slots if any before allocating new one.*/
	for (i=0; i < iNumServices; i++) {
		if (ServicePtrs[i] == NULL) {
			break;
		}
	}
	if (i == iNumServices) {
		/* if not, then create one */
		tsp = talloc_realloc(NULL, ServicePtrs,
				     struct loadparm_service *,
				     iNumServices + 1);
		if (tsp == NULL) {
			DEBUG(0, ("add_a_service: failed to enlarge "
				  "ServicePtrs!\n"));
			return (-1);
		}
		ServicePtrs = tsp;
		iNumServices++;
	}
	ServicePtrs[i] = talloc_zero(ServicePtrs, struct loadparm_service);
	if (!ServicePtrs[i]) {
		DEBUG(0,("add_a_service: out of memory!\n"));
		return (-1);
	}

	ServicePtrs[i]->valid = true;

	copy_service(ServicePtrs[i], pservice, NULL);
	if (name)
		lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->szService,
				 name);

	DEBUG(8,("add_a_service: Creating snum = %d for %s\n", 
		i, ServicePtrs[i]->szService));

	if (!hash_a_service(ServicePtrs[i]->szService, i)) {
		return (-1);
	}

	return (i);
}

/***************************************************************************
  Convert a string to uppercase and remove whitespaces.
***************************************************************************/

char *canonicalize_servicename(TALLOC_CTX *ctx, const char *src)
{
	char *result;

	if ( !src ) {
		DEBUG(0,("canonicalize_servicename: NULL source name!\n"));
		return NULL;
	}

	result = talloc_strdup(ctx, src);
	SMB_ASSERT(result != NULL);

	if (!strlower_m(result)) {
		TALLOC_FREE(result);
		return NULL;
	}
	return result;
}

/***************************************************************************
  Add a name/index pair for the services array to the hash table.
***************************************************************************/

static bool hash_a_service(const char *name, int idx)
{
	char *canon_name;

	if ( !ServiceHash ) {
		DEBUG(10,("hash_a_service: creating servicehash\n"));
		ServiceHash = db_open_rbt(NULL);
		if ( !ServiceHash ) {
			DEBUG(0,("hash_a_service: open tdb servicehash failed!\n"));
			return false;
		}
	}

	DEBUG(10,("hash_a_service: hashing index %d for service name %s\n",
		idx, name));

	canon_name = canonicalize_servicename(talloc_tos(), name );

	dbwrap_store_bystring(ServiceHash, canon_name,
			      make_tdb_data((uint8_t *)&idx, sizeof(idx)),
			      TDB_REPLACE);

	TALLOC_FREE(canon_name);

	return true;
}

/***************************************************************************
 Add a new home service, with the specified home directory, defaults coming
 from service ifrom.
***************************************************************************/

bool lp_add_home(const char *pszHomename, int iDefaultService,
		 const char *user, const char *pszHomedir)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int i;
	char *global_path;

	if (pszHomename == NULL || user == NULL || pszHomedir == NULL ||
			pszHomedir[0] == '\0') {
		return false;
	}

	i = add_a_service(ServicePtrs[iDefaultService], pszHomename);

	if (i < 0)
		return false;

	global_path = lp_path(talloc_tos(), lp_sub, GLOBAL_SECTION_SNUM);
	if (!(*(ServicePtrs[iDefaultService]->path))
	    || strequal(ServicePtrs[iDefaultService]->path, global_path)) {
		lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->path,
				 pszHomedir);
	}
	TALLOC_FREE(global_path);

	if (!(*(ServicePtrs[i]->comment))) {
		char *comment = talloc_asprintf(talloc_tos(), "Home directory of %s", user);
		if (comment == NULL) {
			return false;
		}
		lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->comment,
				 comment);
		TALLOC_FREE(comment);
	}

	/* set the browseable flag from the global default */

	ServicePtrs[i]->browseable = sDefault.browseable;
	ServicePtrs[i]->access_based_share_enum = sDefault.access_based_share_enum;

	ServicePtrs[i]->autoloaded = true;

	DEBUG(3, ("adding home's share [%s] for user '%s' at '%s'\n", pszHomename, 
	       user, ServicePtrs[i]->path ));

	return true;
}

/***************************************************************************
 Add a new service, based on an old one.
***************************************************************************/

int lp_add_service(const char *pszService, int iDefaultService)
{
	if (iDefaultService < 0) {
		return add_a_service(&sDefault, pszService);
	}

	return (add_a_service(ServicePtrs[iDefaultService], pszService));
}

/***************************************************************************
 Add the IPC service.
***************************************************************************/

static bool lp_add_ipc(const char *ipc_name, bool guest_ok)
{
	char *comment = NULL;
	int i = add_a_service(&sDefault, ipc_name);

	if (i < 0)
		return false;

	comment = talloc_asprintf(talloc_tos(), "IPC Service (%s)",
				  Globals.server_string);
	if (comment == NULL) {
		return false;
	}

	lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->path, tmpdir());
	lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->comment, comment);
	lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->fstype, "IPC");
	ServicePtrs[i]->max_connections = 0;
	ServicePtrs[i]->available = true;
	ServicePtrs[i]->read_only = true;
	ServicePtrs[i]->guest_only = false;
	ServicePtrs[i]->administrative_share = true;
	ServicePtrs[i]->guest_ok = guest_ok;
	ServicePtrs[i]->printable = false;
	ServicePtrs[i]->browseable = sDefault.browseable;
	ServicePtrs[i]->autoloaded = false;

	DEBUG(3, ("adding IPC service\n"));

	TALLOC_FREE(comment);
	return true;
}

/***************************************************************************
 Add a new printer service, with defaults coming from service iFrom.
***************************************************************************/

bool lp_add_printer(const char *pszPrintername, int iDefaultService)
{
	const char *comment = "From Printcap";
	int i = add_a_service(ServicePtrs[iDefaultService], pszPrintername);

	if (i < 0)
		return false;

	/* note that we do NOT default the availability flag to true - */
	/* we take it from the default service passed. This allows all */
	/* dynamic printers to be disabled by disabling the [printers] */
	/* entry (if/when the 'available' keyword is implemented!).    */

	/* the printer name is set to the service name. */
	lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->_printername,
			 pszPrintername);
	lpcfg_string_set(ServicePtrs[i], &ServicePtrs[i]->comment, comment);

	/* set the browseable flag from the gloabl default */
	ServicePtrs[i]->browseable = sDefault.browseable;

	/* Printers cannot be read_only. */
	ServicePtrs[i]->read_only = false;
	/* No oplocks on printer services. */
	ServicePtrs[i]->oplocks = false;
	/* Printer services must be printable. */
	ServicePtrs[i]->printable = true;

	DEBUG(3, ("adding printer service %s\n", pszPrintername));

	return true;
}


/***************************************************************************
 Check whether the given parameter name is valid.
 Parametric options (names containing a colon) are considered valid.
***************************************************************************/

bool lp_parameter_is_valid(const char *pszParmName)
{
	return ((lpcfg_map_parameter(pszParmName) != -1) ||
		(strchr(pszParmName, ':') != NULL));
}

/***************************************************************************
 Check whether the given name is the name of a global parameter.
 Returns true for strings belonging to parameters of class
 P_GLOBAL, false for all other strings, also for parametric options
 and strings not belonging to any option.
***************************************************************************/

bool lp_parameter_is_global(const char *pszParmName)
{
	int num = lpcfg_map_parameter(pszParmName);

	if (num >= 0) {
		return (parm_table[num].p_class == P_GLOBAL);
	}

	return false;
}

/**************************************************************************
 Determine the canonical name for a parameter.
 Indicate when it is an inverse (boolean) synonym instead of a
 "usual" synonym.
**************************************************************************/

bool lp_canonicalize_parameter(const char *parm_name, const char **canon_parm,
			       bool *inverse)
{
	int num;

	if (!lp_parameter_is_valid(parm_name)) {
		*canon_parm = NULL;
		return false;
	}

	num = map_parameter_canonical(parm_name, inverse);
	if (num < 0) {
		/* parametric option */
		*canon_parm = parm_name;
	} else {
		*canon_parm = parm_table[num].label;
	}

	return true;

}

/**************************************************************************
 Determine the canonical name for a parameter.
 Turn the value given into the inverse boolean expression when
 the synonym is an invers boolean synonym.

 Return true if
 - parm_name is a valid parameter name and
 - val is a valid value for this parameter and
 - in case the parameter is an inverse boolean synonym, if the val
   string could successfully be converted to the reverse bool.
 Return false in all other cases.
**************************************************************************/

bool lp_canonicalize_parameter_with_value(const char *parm_name,
					  const char *val,
					  const char **canon_parm,
					  const char **canon_val)
{
	int num;
	bool inverse;
	bool ret;

	if (!lp_parameter_is_valid(parm_name)) {
		*canon_parm = NULL;
		*canon_val = NULL;
		return false;
	}

	num = map_parameter_canonical(parm_name, &inverse);
	if (num < 0) {
		/* parametric option */
		*canon_parm = parm_name;
		*canon_val = val;
		return true;
	}

	*canon_parm = parm_table[num].label;
	if (inverse) {
		if (!lp_invert_boolean(val, canon_val)) {
			*canon_val = NULL;
			return false;
		}
	} else {
		*canon_val = val;
	}

	ret = lp_parameter_value_is_valid(*canon_parm, *canon_val);

	return ret;
}

/***************************************************************************
 Map a parameter's string representation to the index of the canonical
 form of the parameter (it might be a synonym).
 Returns -1 if the parameter string is not recognised.
***************************************************************************/

static int map_parameter_canonical(const char *pszParmName, bool *inverse)
{
	int parm_num, canon_num;
	bool loc_inverse = false;

	parm_num = lpcfg_map_parameter(pszParmName);
	if ((parm_num < 0) || !(parm_table[parm_num].flags & FLAG_SYNONYM)) {
		/* invalid, parametric or no canidate for synonyms ... */
		goto done;
	}

	for (canon_num = 0; parm_table[canon_num].label; canon_num++) {
		if (is_synonym_of(parm_num, canon_num, &loc_inverse)) {
			parm_num = canon_num;
			goto done;
		}
	}

done:
	if (inverse != NULL) {
		*inverse = loc_inverse;
	}
	return parm_num;
}

/***************************************************************************
 return true if parameter number parm1 is a synonym of parameter
 number parm2 (parm2 being the principal name).
 set inverse to true if parm1 is P_BOOLREV and parm2 is P_BOOL,
 false otherwise.
***************************************************************************/

static bool is_synonym_of(int parm1, int parm2, bool *inverse)
{
	if ((parm_table[parm1].offset == parm_table[parm2].offset) &&
	    (parm_table[parm1].p_class == parm_table[parm2].p_class) &&
	    (parm_table[parm1].flags & FLAG_SYNONYM) &&
	    !(parm_table[parm2].flags & FLAG_SYNONYM))
	{
		if (inverse != NULL) {
			if ((parm_table[parm1].type == P_BOOLREV) &&
			    (parm_table[parm2].type == P_BOOL))
			{
				*inverse = true;
			} else {
				*inverse = false;
			}
		}
		return true;
	}
	return false;
}

/***************************************************************************
 Show one parameter's name, type, [values,] and flags.
 (helper functions for show_parameter_list)
***************************************************************************/

static void show_parameter(int parmIndex)
{
	size_t enumIndex, flagIndex;
	size_t parmIndex2;
	bool hadFlag;
	bool hadSyn;
	bool inverse;
	const char *type[] = { "P_BOOL", "P_BOOLREV", "P_CHAR", "P_INTEGER",
		"P_OCTAL", "P_LIST", "P_STRING", "P_USTRING",
		"P_ENUM", "P_BYTES", "P_CMDLIST" };
	unsigned flags[] = { FLAG_DEPRECATED, FLAG_SYNONYM };
	const char *flag_names[] = { "FLAG_DEPRECATED", "FLAG_SYNONYM", NULL};

	printf("%s=%s", parm_table[parmIndex].label,
	       type[parm_table[parmIndex].type]);
	if (parm_table[parmIndex].type == P_ENUM) {
		printf(",");
		for (enumIndex=0;
		     parm_table[parmIndex].enum_list[enumIndex].name;
		     enumIndex++)
		{
			printf("%s%s",
			       enumIndex ? "|" : "",
			       parm_table[parmIndex].enum_list[enumIndex].name);
		}
	}
	printf(",");
	hadFlag = false;
	for (flagIndex=0; flag_names[flagIndex]; flagIndex++) {
		if (parm_table[parmIndex].flags & flags[flagIndex]) {
			printf("%s%s",
				hadFlag ? "|" : "",
				flag_names[flagIndex]);
			hadFlag = true;
		}
	}

	/* output synonyms */
	hadSyn = false;
	for (parmIndex2=0; parm_table[parmIndex2].label; parmIndex2++) {
		if (is_synonym_of(parmIndex, parmIndex2, &inverse)) {
			printf(" (%ssynonym of %s)", inverse ? "inverse " : "",
			       parm_table[parmIndex2].label);
		} else if (is_synonym_of(parmIndex2, parmIndex, &inverse)) {
			if (!hadSyn) {
				printf(" (synonyms: ");
				hadSyn = true;
			} else {
				printf(", ");
			}
			printf("%s%s", parm_table[parmIndex2].label,
			       inverse ? "[i]" : "");
		}
	}
	if (hadSyn) {
		printf(")");
	}

	printf("\n");
}

/*
 * Check the value for a P_ENUM
 */
static bool check_enum_parameter(struct parm_struct *parm, const char *value)
{
	int i;

	for (i = 0; parm->enum_list[i].name; i++) {
		if (strwicmp(value, parm->enum_list[i].name) == 0) {
			return true;
		}
	}
	return false;
}

/**************************************************************************
 Check whether the given value is valid for the given parameter name.
**************************************************************************/

static bool lp_parameter_value_is_valid(const char *parm_name, const char *val)
{
	bool ret = false, tmp_bool;
	int num = lpcfg_map_parameter(parm_name), tmp_int;
	uint64_t tmp_int64 = 0;
	struct parm_struct *parm;

	/* parametric options (parameter names containing a colon) cannot
	   be checked and are therefore considered valid. */
	if (strchr(parm_name, ':') != NULL) {
		return true;
	}

	if (num >= 0) {
		parm = &parm_table[num];
		switch (parm->type) {
			case P_BOOL:
			case P_BOOLREV:
				ret = set_boolean(val, &tmp_bool);
				break;

			case P_INTEGER:
				ret = (sscanf(val, "%d", &tmp_int) == 1);
				break;

			case P_OCTAL:
				ret = (sscanf(val, "%o", &tmp_int) == 1);
				break;

			case P_ENUM:
				ret = check_enum_parameter(parm, val);
				break;

			case P_BYTES:
				if (conv_str_size_error(val, &tmp_int64) &&
				    tmp_int64 <= INT_MAX) {
					ret = true;
				}
				break;

			case P_CHAR:
			case P_LIST:
			case P_STRING:
			case P_USTRING:
			case P_CMDLIST:
				ret = true;
				break;
		}
	}
	return ret;
}

/***************************************************************************
 Show all parameter's name, type, [values,] and flags.
***************************************************************************/

void show_parameter_list(void)
{
	int classIndex, parmIndex;
	const char *section_names[] = { "local", "global", NULL};

	for (classIndex=0; section_names[classIndex]; classIndex++) {
		printf("[%s]\n", section_names[classIndex]);
		for (parmIndex = 0; parm_table[parmIndex].label; parmIndex++) {
			if (parm_table[parmIndex].p_class == classIndex) {
				show_parameter(parmIndex);
			}
		}
	}
}

/***************************************************************************
 Get the standard string representation of a boolean value ("yes" or "no")
***************************************************************************/

static const char *get_boolean(bool bool_value)
{
	static const char *yes_str = "yes";
	static const char *no_str = "no";

	return (bool_value ? yes_str : no_str);
}

/***************************************************************************
 Provide the string of the negated boolean value associated to the boolean
 given as a string. Returns false if the passed string does not correctly
 represent a boolean.
***************************************************************************/

bool lp_invert_boolean(const char *str, const char **inverse_str)
{
	bool val;

	if (!set_boolean(str, &val)) {
		return false;
	}

	*inverse_str = get_boolean(!val);
	return true;
}

/***************************************************************************
 Provide the canonical string representation of a boolean value given
 as a string. Return true on success, false if the string given does
 not correctly represent a boolean.
***************************************************************************/

bool lp_canonicalize_boolean(const char *str, const char**canon_str)
{
	bool val;

	if (!set_boolean(str, &val)) {
		return false;
	}

	*canon_str = get_boolean(val);
	return true;
}

/***************************************************************************
Find a service by name. Otherwise works like get_service.
***************************************************************************/

int getservicebyname(const char *pszServiceName, struct loadparm_service *pserviceDest)
{
	int iService = -1;
	char *canon_name;
	TDB_DATA data;
	NTSTATUS status;

	if (ServiceHash == NULL) {
		return -1;
	}

	canon_name = canonicalize_servicename(talloc_tos(), pszServiceName);

	status = dbwrap_fetch_bystring(ServiceHash, canon_name, canon_name,
				       &data);

	if (NT_STATUS_IS_OK(status) &&
	    (data.dptr != NULL) &&
	    (data.dsize == sizeof(iService)))
	{
		memcpy(&iService, data.dptr, sizeof(iService));
	}

	TALLOC_FREE(canon_name);

	if ((iService != -1) && (LP_SNUM_OK(iService))
	    && (pserviceDest != NULL)) {
		copy_service(pserviceDest, ServicePtrs[iService], NULL);
	}

	return (iService);
}

/* Return a pointer to a service by name.  Unlike getservicebyname, it does not copy the service */
struct loadparm_service *lp_service(const char *pszServiceName)
{
	int iService = getservicebyname(pszServiceName, NULL);
	if (iService == -1 || !LP_SNUM_OK(iService)) {
		return NULL;
	}
	return ServicePtrs[iService];
}

struct loadparm_service *lp_servicebynum(int snum)
{
	if ((snum == -1) || !LP_SNUM_OK(snum)) {
		return NULL;
	}
	return ServicePtrs[snum];
}

struct loadparm_service *lp_default_loadparm_service()
{
	return &sDefault;
}

static struct smbconf_ctx *lp_smbconf_ctx(void)
{
	sbcErr err;
	static struct smbconf_ctx *conf_ctx = NULL;

	if (conf_ctx == NULL) {
		err = smbconf_init(NULL, &conf_ctx, "registry:");
		if (!SBC_ERROR_IS_OK(err)) {
			DEBUG(1, ("error initializing registry configuration: "
				  "%s\n", sbcErrorString(err)));
			conf_ctx = NULL;
		}
	}

	return conf_ctx;
}

static bool process_smbconf_service(struct smbconf_service *service)
{
	uint32_t count;
	bool ret;

	if (service == NULL) {
		return false;
	}

	ret = lp_do_section(service->name, NULL);
	if (ret != true) {
		return false;
	}
	for (count = 0; count < service->num_params; count++) {

		if (!bInGlobalSection && bGlobalOnly) {
			ret = true;
		} else {
			const char *pszParmName = service->param_names[count];
			const char *pszParmValue = service->param_values[count];

			DEBUGADD(4, ("doing parameter %s = %s\n", pszParmName, pszParmValue));

			ret = lp_do_parameter(bInGlobalSection ? -2 : iServiceIndex,
					      pszParmName, pszParmValue);
		}

		if (ret != true) {
			return false;
		}
	}
	if (iServiceIndex >= 0) {
		return lpcfg_service_ok(ServicePtrs[iServiceIndex]);
	}
	return true;
}

/**
 * load a service from registry and activate it
 */
bool process_registry_service(const char *service_name)
{
	sbcErr err;
	struct smbconf_service *service = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smbconf_ctx *conf_ctx = lp_smbconf_ctx();
	bool ret = false;

	if (conf_ctx == NULL) {
		goto done;
	}

	DEBUG(5, ("process_registry_service: service name %s\n", service_name));

	if (!smbconf_share_exists(conf_ctx, service_name)) {
		/*
		 * Registry does not contain data for this service (yet),
		 * but make sure lp_load doesn't return false.
		 */
		ret = true;
		goto done;
	}

	err = smbconf_get_share(conf_ctx, mem_ctx, service_name, &service);
	if (!SBC_ERROR_IS_OK(err)) {
		goto done;
	}

	ret = process_smbconf_service(service);
	if (!ret) {
		goto done;
	}

	/* store the csn */
	smbconf_changed(conf_ctx, &conf_last_csn, NULL, NULL);

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/*
 * process_registry_globals
 */
static bool process_registry_globals(void)
{
	bool ret;

	add_to_file_list(NULL, &file_lists, INCLUDE_REGISTRY_NAME, INCLUDE_REGISTRY_NAME);

	if (!bInGlobalSection && bGlobalOnly) {
		ret = true;
	} else {
		const char *pszParmName = "registry shares";
		const char *pszParmValue = "yes";

		DEBUGADD(4, ("doing parameter %s = %s\n", pszParmName, pszParmValue));

		ret = lp_do_parameter(bInGlobalSection ? -2 : iServiceIndex,
				      pszParmName, pszParmValue);
	}

	if (!ret) {
		return ret;
	}

	return process_registry_service(GLOBAL_NAME);
}

bool process_registry_shares(void)
{
	sbcErr err;
	uint32_t count;
	struct smbconf_service **service = NULL;
	uint32_t num_shares = 0;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smbconf_ctx *conf_ctx = lp_smbconf_ctx();
	bool ret = false;

	if (conf_ctx == NULL) {
		goto done;
	}

	err = smbconf_get_config(conf_ctx, mem_ctx, &num_shares, &service);
	if (!SBC_ERROR_IS_OK(err)) {
		goto done;
	}

	ret = true;

	for (count = 0; count < num_shares; count++) {
		if (strequal(service[count]->name, GLOBAL_NAME)) {
			continue;
		}
		ret = process_smbconf_service(service[count]);
		if (!ret) {
			goto done;
		}
	}

	/* store the csn */
	smbconf_changed(conf_ctx, &conf_last_csn, NULL, NULL);

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/**
 * reload those shares from registry that are already
 * activated in the services array.
 */
static bool reload_registry_shares(void)
{
	int i;
	bool ret = true;

	for (i = 0; i < iNumServices; i++) {
		if (!VALID(i)) {
			continue;
		}

		if (ServicePtrs[i]->usershare == USERSHARE_VALID) {
			continue;
		}

		ret = process_registry_service(ServicePtrs[i]->szService);
		if (!ret) {
			goto done;
		}
	}

done:
	return ret;
}


#define MAX_INCLUDE_DEPTH 100

static uint8_t include_depth;

/**
 * Free the file lists
 */
static void free_file_list(void)
{
	struct file_lists *f;
	struct file_lists *next;

	f = file_lists;
	while( f ) {
		next = f->next;
		TALLOC_FREE( f );
		f = next;
	}
	file_lists = NULL;
}


/**
 * Utility function for outsiders to check if we're running on registry.
 */
bool lp_config_backend_is_registry(void)
{
	return (lp_config_backend() == CONFIG_BACKEND_REGISTRY);
}

/**
 * Utility function to check if the config backend is FILE.
 */
bool lp_config_backend_is_file(void)
{
	return (lp_config_backend() == CONFIG_BACKEND_FILE);
}

/*******************************************************************
 Check if a config file has changed date.
********************************************************************/

bool lp_file_list_changed(void)
{
	struct file_lists *f = file_lists;

 	DEBUG(6, ("lp_file_list_changed()\n"));

	while (f) {
		if (strequal(f->name, INCLUDE_REGISTRY_NAME)) {
			struct smbconf_ctx *conf_ctx = lp_smbconf_ctx();

			if (conf_ctx == NULL) {
				return false;
			}
			if (smbconf_changed(conf_ctx, &conf_last_csn, NULL,
					    NULL))
			{
				DEBUGADD(6, ("registry config changed\n"));
				return true;
			}
		} else {
			time_t mod_time;
			char *n2 = NULL;

			n2 = talloc_sub_basic(talloc_tos(),
					      get_current_username(),
					      current_user_info.domain,
					      f->name);
			if (!n2) {
				return false;
			}
			DEBUGADD(6, ("file %s -> %s  last mod_time: %s\n",
				     f->name, n2, ctime(&f->modtime)));

			mod_time = file_modtime(n2);

			if (mod_time &&
			    ((f->modtime != mod_time) ||
			     (f->subfname == NULL) ||
			     (strcmp(n2, f->subfname) != 0)))
			{
				DEBUGADD(6,
					 ("file %s modified: %s\n", n2,
					  ctime(&mod_time)));
				f->modtime = mod_time;
				TALLOC_FREE(f->subfname);
				f->subfname = talloc_strdup(f, n2);
				if (f->subfname == NULL) {
					smb_panic("talloc_strdup failed");
				}
				TALLOC_FREE(n2);
				return true;
			}
			TALLOC_FREE(n2);
		}
		f = f->next;
	}
	return false;
}


/**
 * Initialize iconv conversion descriptors.
 *
 * This is called the first time it is needed, and also called again
 * every time the configuration is reloaded, because the charset or
 * codepage might have changed.
 **/
static void init_iconv(void)
{
	struct smb_iconv_handle *ret = NULL;

	ret = reinit_iconv_handle(NULL,
				  lp_dos_charset(),
				  lp_unix_charset());
	if (ret == NULL) {
		smb_panic("reinit_iconv_handle failed");
	}
}

/***************************************************************************
 Handle the include operation.
***************************************************************************/
static bool bAllowIncludeRegistry = true;

bool lp_include(struct loadparm_context *lp_ctx, struct loadparm_service *service,
	       	const char *pszParmValue, char **ptr)
{
	char *fname;

	if (include_depth >= MAX_INCLUDE_DEPTH) {
		DEBUG(0, ("Error: Maximum include depth (%u) exceeded!\n",
			  include_depth));
		return false;
	}

	if (strequal(pszParmValue, INCLUDE_REGISTRY_NAME)) {
		if (!bAllowIncludeRegistry) {
			return true;
		}
		if (lp_ctx->bInGlobalSection) {
			bool ret;
			include_depth++;
			ret = process_registry_globals();
			include_depth--;
			return ret;
		} else {
			DEBUG(1, ("\"include = registry\" only effective "
				  "in %s section\n", GLOBAL_NAME));
			return false;
		}
	}

	fname = talloc_sub_basic(talloc_tos(), get_current_username(),
				 current_user_info.domain,
				 pszParmValue);

	add_to_file_list(NULL, &file_lists, pszParmValue, fname);

	if (service == NULL) {
		lpcfg_string_set(Globals.ctx, ptr, fname);
	} else {
		lpcfg_string_set(service, ptr, fname);
	}

	if (file_exist(fname)) {
		bool ret;
		include_depth++;
		ret = pm_process(fname, lp_do_section, do_parameter, lp_ctx);
		include_depth--;
		TALLOC_FREE(fname);
		return ret;
	}

	DEBUG(2, ("Can't find include file %s\n", fname));
	TALLOC_FREE(fname);
	return true;
}

bool lp_idmap_range(const char *domain_name, uint32_t *low, uint32_t *high)
{
	char *config_option = NULL;
	const char *range = NULL;
	bool ret = false;

	SMB_ASSERT(low != NULL);
	SMB_ASSERT(high != NULL);

	if ((domain_name == NULL) || (domain_name[0] == '\0')) {
		domain_name = "*";
	}

	config_option = talloc_asprintf(talloc_tos(), "idmap config %s",
					domain_name);
	if (config_option == NULL) {
		DEBUG(0, ("out of memory\n"));
		return false;
	}

	range = lp_parm_const_string(-1, config_option, "range", NULL);
	if (range == NULL) {
		DEBUG(1, ("idmap range not specified for domain '%s'\n", domain_name));
		goto done;
	}

	if (sscanf(range, "%u - %u", low, high) != 2) {
		DEBUG(1, ("error parsing idmap range '%s' for domain '%s'\n",
			  range, domain_name));
		goto done;
	}

	ret = true;

done:
	talloc_free(config_option);
	return ret;

}

bool lp_idmap_default_range(uint32_t *low, uint32_t *high)
{
	return lp_idmap_range("*", low, high);
}

const char *lp_idmap_backend(const char *domain_name)
{
	char *config_option = NULL;
	const char *backend = NULL;

	if ((domain_name == NULL) || (domain_name[0] == '\0')) {
		domain_name = "*";
	}

	config_option = talloc_asprintf(talloc_tos(), "idmap config %s",
					domain_name);
	if (config_option == NULL) {
		DEBUG(0, ("out of memory\n"));
		return false;
	}

	backend = lp_parm_const_string(-1, config_option, "backend", NULL);
	if (backend == NULL) {
		DEBUG(1, ("idmap backend not specified for domain '%s'\n", domain_name));
		goto done;
	}

done:
	talloc_free(config_option);
	return backend;
}

const char *lp_idmap_default_backend(void)
{
	return lp_idmap_backend("*");
}

/***************************************************************************
 Handle ldap suffixes - default to ldapsuffix if sub-suffixes are not defined.
***************************************************************************/

static const char *append_ldap_suffix(TALLOC_CTX *ctx, const char *str )
{
	const char *suffix_string;

	suffix_string = talloc_asprintf(ctx, "%s,%s", str,
					Globals.ldap_suffix );
	if ( !suffix_string ) {
		DEBUG(0,("append_ldap_suffix: talloc_asprintf() failed!\n"));
		return "";
	}

	return suffix_string;
}

const char *lp_ldap_machine_suffix(TALLOC_CTX *ctx)
{
	if (Globals._ldap_machine_suffix[0])
		return append_ldap_suffix(ctx, Globals._ldap_machine_suffix);

	return talloc_strdup(ctx, Globals.ldap_suffix);
}

const char *lp_ldap_user_suffix(TALLOC_CTX *ctx)
{
	if (Globals._ldap_user_suffix[0])
		return append_ldap_suffix(ctx, Globals._ldap_user_suffix);

	return talloc_strdup(ctx, Globals.ldap_suffix);
}

const char *lp_ldap_group_suffix(TALLOC_CTX *ctx)
{
	if (Globals._ldap_group_suffix[0])
		return append_ldap_suffix(ctx, Globals._ldap_group_suffix);

	return talloc_strdup(ctx, Globals.ldap_suffix);
}

const char *lp_ldap_idmap_suffix(TALLOC_CTX *ctx)
{
	if (Globals._ldap_idmap_suffix[0])
		return append_ldap_suffix(ctx, Globals._ldap_idmap_suffix);

	return talloc_strdup(ctx, Globals.ldap_suffix);
}

/**
  return the parameter pointer for a parameter
*/
void *lp_parm_ptr(struct loadparm_service *service, struct parm_struct *parm)
{
	if (service == NULL) {
		if (parm->p_class == P_LOCAL)
			return (void *)(((char *)&sDefault)+parm->offset);
		else if (parm->p_class == P_GLOBAL)
			return (void *)(((char *)&Globals)+parm->offset);
		else return NULL;
	} else {
		return (void *)(((char *)service) + parm->offset);
	}
}

/***************************************************************************
 Process a parameter for a particular service number. If snum < 0
 then assume we are in the globals.
***************************************************************************/

bool lp_do_parameter(int snum, const char *pszParmName, const char *pszParmValue)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx;
	bool ok;

	lp_ctx = setup_lp_context(frame);
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return false;
	}

	if (snum < 0) {
		ok = lpcfg_do_global_parameter(lp_ctx, pszParmName, pszParmValue);
	} else {
		ok = lpcfg_do_service_parameter(lp_ctx, ServicePtrs[snum],
						pszParmName, pszParmValue);
	}

	TALLOC_FREE(frame);

	return ok;
}

/***************************************************************************
set a parameter, marking it with FLAG_CMDLINE. Parameters marked as
FLAG_CMDLINE won't be overridden by loads from smb.conf.
***************************************************************************/

static bool lp_set_cmdline_helper(const char *pszParmName, const char *pszParmValue)
{
	int parmnum, i;
	parmnum = lpcfg_map_parameter(pszParmName);
	if (parmnum >= 0) {
		flags_list[parmnum] &= ~FLAG_CMDLINE;
		if (!lp_do_parameter(-1, pszParmName, pszParmValue)) {
			return false;
		}
		flags_list[parmnum] |= FLAG_CMDLINE;

		/* we have to also set FLAG_CMDLINE on aliases.  Aliases must
		 * be grouped in the table, so we don't have to search the
		 * whole table */
		for (i=parmnum-1;
		     i>=0 && parm_table[i].offset == parm_table[parmnum].offset
			     && parm_table[i].p_class == parm_table[parmnum].p_class;
		     i--) {
			flags_list[i] |= FLAG_CMDLINE;
		}
		for (i=parmnum+1;i<num_parameters() && parm_table[i].offset == parm_table[parmnum].offset
			     && parm_table[i].p_class == parm_table[parmnum].p_class;i++) {
			flags_list[i] |= FLAG_CMDLINE;
		}

		return true;
	}

	/* it might be parametric */
	if (strchr(pszParmName, ':') != NULL) {
		set_param_opt(NULL, &Globals.param_opt, pszParmName, pszParmValue, FLAG_CMDLINE);
		return true;
	}

	DEBUG(0, ("Ignoring unknown parameter \"%s\"\n",  pszParmName));
	return false;
}

bool lp_set_cmdline(const char *pszParmName, const char *pszParmValue)
{
	bool ret;
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx;

	lp_ctx = setup_lp_context(frame);
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return false;
	}

	ret = lpcfg_set_cmdline(lp_ctx, pszParmName, pszParmValue);

	TALLOC_FREE(frame);
	return ret;
}

/***************************************************************************
 Process a parameter.
***************************************************************************/

static bool do_parameter(const char *pszParmName, const char *pszParmValue,
			 void *userdata)
{
	if (!bInGlobalSection && bGlobalOnly)
		return true;

	DEBUGADD(4, ("doing parameter %s = %s\n", pszParmName, pszParmValue));

	if (bInGlobalSection) {
		return lpcfg_do_global_parameter(userdata, pszParmName, pszParmValue);
	} else {
		return lpcfg_do_service_parameter(userdata, ServicePtrs[iServiceIndex],
						  pszParmName, pszParmValue);
	}
}


static const char *ad_dc_req_vfs_mods[] = {"dfs_samba4", "acl_xattr", NULL};

/*
 * check that @vfs_objects includes all vfs modules required by an AD DC.
 */
static bool check_ad_dc_required_mods(const char **vfs_objects)
{
	int i;
	int j;
	int got_req;

	for (i = 0; ad_dc_req_vfs_mods[i] != NULL; i++) {
		got_req = false;
		for (j = 0; vfs_objects[j] != NULL; j++) {
			if (!strwicmp(ad_dc_req_vfs_mods[i], vfs_objects[j])) {
				got_req = true;
				break;
			}
		}
		if (!got_req) {
			DEBUG(0, ("vfs objects specified without required AD "
				  "DC module: %s\n", ad_dc_req_vfs_mods[i]));
			return false;
		}
	}

	DEBUG(6, ("vfs objects specified with all required AD DC modules\n"));
	return true;
}


/***************************************************************************
 Initialize any local variables in the sDefault table, after parsing a
 [globals] section.
***************************************************************************/

static void init_locals(void)
{
	/*
	 * We run this check once the [globals] is parsed, to force
	 * the VFS objects and other per-share settings we need for
	 * the standard way a AD DC is operated.  We may change these
	 * as our code evolves, which is why we force these settings.
	 *
	 * We can't do this at the end of lp_load_ex(), as by that
	 * point the services have been loaded and they will already
	 * have "" as their vfs objects.
	 */
	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		const char **vfs_objects = lp_vfs_objects(-1);
		if (vfs_objects != NULL) {
			/* ignore return, only warn if modules are missing */
			check_ad_dc_required_mods(vfs_objects);
		} else {
			if (lp_parm_const_string(-1, "xattr_tdb", "file", NULL)) {
				lp_do_parameter(-1, "vfs objects", "dfs_samba4 acl_xattr xattr_tdb");
			} else if (lp_parm_const_string(-1, "posix", "eadb", NULL)) {
				lp_do_parameter(-1, "vfs objects", "dfs_samba4 acl_xattr posix_eadb");
			} else {
				lp_do_parameter(-1, "vfs objects", "dfs_samba4 acl_xattr");
			}
		}

		lp_do_parameter(-1, "map hidden", "no");
		lp_do_parameter(-1, "map system", "no");
		lp_do_parameter(-1, "map readonly", "no");
		lp_do_parameter(-1, "map archive", "no");
		lp_do_parameter(-1, "store dos attributes", "yes");
	}
}

/***************************************************************************
 Process a new section (service). At this stage all sections are services.
 Later we'll have special sections that permit server parameters to be set.
 Returns true on success, false on failure.
***************************************************************************/

bool lp_do_section(const char *pszSectionName, void *userdata)
{
	struct loadparm_context *lp_ctx = (struct loadparm_context *)userdata;
	bool bRetval;
	bool isglobal = ((strwicmp(pszSectionName, GLOBAL_NAME) == 0) ||
			 (strwicmp(pszSectionName, GLOBAL_NAME2) == 0));

	/* if we were in a global section then do the local inits */
	if (bInGlobalSection && !isglobal)
		init_locals();

	/* if we've just struck a global section, note the fact. */
	bInGlobalSection = isglobal;
	if (lp_ctx != NULL) {
		lp_ctx->bInGlobalSection = isglobal;
	}

	/* check for multiple global sections */
	if (bInGlobalSection) {
		DEBUG(3, ("Processing section \"[%s]\"\n", pszSectionName));
		return true;
	}

	if (!bInGlobalSection && bGlobalOnly)
		return true;

	/* if we have a current service, tidy it up before moving on */
	bRetval = true;

	if (iServiceIndex >= 0)
		bRetval = lpcfg_service_ok(ServicePtrs[iServiceIndex]);

	/* if all is still well, move to the next record in the services array */
	if (bRetval) {
		/* We put this here to avoid an odd message order if messages are */
		/* issued by the post-processing of a previous section. */
		DEBUG(2, ("Processing section \"[%s]\"\n", pszSectionName));

		iServiceIndex = add_a_service(&sDefault, pszSectionName);
		if (iServiceIndex < 0) {
			DEBUG(0, ("Failed to add a new service\n"));
			return false;
		}
		/* Clean all parametric options for service */
		/* They will be added during parsing again */
		free_param_opts(&ServicePtrs[iServiceIndex]->param_opt);
	}

	return bRetval;
}

/***************************************************************************
 Display the contents of a parameter of a single services record.
***************************************************************************/

bool dump_a_parameter(int snum, char *parm_name, FILE * f, bool isGlobal)
{
	bool result = false;
	struct loadparm_context *lp_ctx;

	lp_ctx = setup_lp_context(talloc_tos());
	if (lp_ctx == NULL) {
		return false;
	}

	if (isGlobal) {
		result = lpcfg_dump_a_parameter(lp_ctx, NULL, parm_name, f);
	} else {
		result = lpcfg_dump_a_parameter(lp_ctx, ServicePtrs[snum], parm_name, f);
	}
	TALLOC_FREE(lp_ctx);
	return result;
}

#if 0
/***************************************************************************
 Display the contents of a single copy structure.
***************************************************************************/
static void dump_copy_map(bool *pcopymap)
{
	int i;
	if (!pcopymap)
		return;

	printf("\n\tNon-Copied parameters:\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_LOCAL &&
		    parm_table[i].ptr && !pcopymap[i] &&
		    (i == 0 || (parm_table[i].ptr != parm_table[i - 1].ptr)))
		{
			printf("\t\t%s\n", parm_table[i].label);
		}
}
#endif

/***************************************************************************
 Return TRUE if the passed service number is within range.
***************************************************************************/

bool lp_snum_ok(int iService)
{
	return (LP_SNUM_OK(iService) && ServicePtrs[iService]->available);
}

/***************************************************************************
 Auto-load some home services.
***************************************************************************/

static void lp_add_auto_services(const char *str)
{
	char *s;
	char *p;
	int homes;
	char *saveptr;

	if (!str)
		return;

	s = talloc_strdup(talloc_tos(), str);
	if (!s) {
		smb_panic("talloc_strdup failed");
		return;
	}

	homes = lp_servicenumber(HOMES_NAME);

	for (p = strtok_r(s, LIST_SEP, &saveptr); p;
	     p = strtok_r(NULL, LIST_SEP, &saveptr)) {
		char *home;

		if (lp_servicenumber(p) >= 0)
			continue;

		home = get_user_home_dir(talloc_tos(), p);

		if (home && home[0] && homes >= 0)
			lp_add_home(p, homes, p, home);

		TALLOC_FREE(home);
	}
	TALLOC_FREE(s);
}

/***************************************************************************
 Auto-load one printer.
***************************************************************************/

void lp_add_one_printer(const char *name, const char *comment,
			const char *location, void *pdata)
{
	int printers = lp_servicenumber(PRINTERS_NAME);
	int i;

	if (lp_servicenumber(name) < 0) {
		lp_add_printer(name, printers);
		if ((i = lp_servicenumber(name)) >= 0) {
			lpcfg_string_set(ServicePtrs[i],
					 &ServicePtrs[i]->comment, comment);
			ServicePtrs[i]->autoloaded = true;
		}
	}
}

/***************************************************************************
 Have we loaded a services file yet?
***************************************************************************/

bool lp_loaded(void)
{
	return (bLoaded);
}

/***************************************************************************
 Unload unused services.
***************************************************************************/

void lp_killunused(struct smbd_server_connection *sconn,
		   bool (*snumused) (struct smbd_server_connection *, int))
{
	int i;
	for (i = 0; i < iNumServices; i++) {
		if (!VALID(i))
			continue;

		/* don't kill autoloaded or usershare services */
		if ( ServicePtrs[i]->autoloaded ||
				ServicePtrs[i]->usershare == USERSHARE_VALID) {
			continue;
		}

		if (!snumused || !snumused(sconn, i)) {
			free_service_byindex(i);
		}
	}
}

/**
 * Kill all except autoloaded and usershare services - convenience wrapper
 */
void lp_kill_all_services(void)
{
	lp_killunused(NULL, NULL);
}

/***************************************************************************
 Unload a service.
***************************************************************************/

void lp_killservice(int iServiceIn)
{
	if (VALID(iServiceIn)) {
		free_service_byindex(iServiceIn);
	}
}

/***************************************************************************
 Save the curent values of all global and sDefault parameters into the 
 defaults union. This allows testparm to show only the
 changed (ie. non-default) parameters.
***************************************************************************/

static void lp_save_defaults(void)
{
	int i;
	struct parmlist_entry * parm;
	for (i = 0; parm_table[i].label; i++) {
		if (!(flags_list[i] & FLAG_CMDLINE)) {
			flags_list[i] |= FLAG_DEFAULT;
		}

		if (i > 0 && parm_table[i].offset == parm_table[i - 1].offset
		    && parm_table[i].p_class == parm_table[i - 1].p_class)
			continue;
		switch (parm_table[i].type) {
			case P_LIST:
			case P_CMDLIST:
				parm_table[i].def.lvalue = str_list_copy(
					NULL, *(const char ***)lp_parm_ptr(NULL, &parm_table[i]));
				break;
			case P_STRING:
			case P_USTRING:
				lpcfg_string_set(
					Globals.ctx,
					&parm_table[i].def.svalue,
					*(char **)lp_parm_ptr(
						NULL, &parm_table[i]));
				if (parm_table[i].def.svalue == NULL) {
					smb_panic("lpcfg_string_set() failed");
				}
				break;
			case P_BOOL:
			case P_BOOLREV:
				parm_table[i].def.bvalue =
					*(bool *)lp_parm_ptr(NULL, &parm_table[i]);
				break;
			case P_CHAR:
				parm_table[i].def.cvalue =
					*(char *)lp_parm_ptr(NULL, &parm_table[i]);
				break;
			case P_INTEGER:
			case P_OCTAL:
			case P_ENUM:
			case P_BYTES:
				parm_table[i].def.ivalue =
					*(int *)lp_parm_ptr(NULL, &parm_table[i]);
				break;
		}
	}

	for (parm=Globals.param_opt; parm; parm=parm->next) {
		if (!(parm->priority & FLAG_CMDLINE)) {
			parm->priority |= FLAG_DEFAULT;
		}
	}

	for (parm=sDefault.param_opt; parm; parm=parm->next) {
		if (!(parm->priority & FLAG_CMDLINE)) {
			parm->priority |= FLAG_DEFAULT;
		}
	}

	defaults_saved = true;
}

/***********************************************************
 If we should send plaintext/LANMAN passwords in the clinet
************************************************************/

static void set_allowed_client_auth(void)
{
	if (Globals.client_ntlmv2_auth) {
		Globals.client_lanman_auth = false;
	}
	if (!Globals.client_lanman_auth) {
		Globals.client_plaintext_auth = false;
	}
}

/***************************************************************************
 JRA.
 The following code allows smbd to read a user defined share file.
 Yes, this is my intent. Yes, I'm comfortable with that...

 THE FOLLOWING IS SECURITY CRITICAL CODE.

 It washes your clothes, it cleans your house, it guards you while you sleep...
 Do not f%^k with it....
***************************************************************************/

#define MAX_USERSHARE_FILE_SIZE (10*1024)

/***************************************************************************
 Check allowed stat state of a usershare file.
 Ensure we print out who is dicking with us so the admin can
 get their sorry ass fired.
***************************************************************************/

static bool check_usershare_stat(const char *fname,
				 const SMB_STRUCT_STAT *psbuf)
{
	if (!S_ISREG(psbuf->st_ex_mode)) {
		DEBUG(0,("check_usershare_stat: file %s owned by uid %u is "
			"not a regular file\n",
			fname, (unsigned int)psbuf->st_ex_uid ));
		return false;
	}

	/* Ensure this doesn't have the other write bit set. */
	if (psbuf->st_ex_mode & S_IWOTH) {
		DEBUG(0,("check_usershare_stat: file %s owned by uid %u allows "
			"public write. Refusing to allow as a usershare file.\n",
			fname, (unsigned int)psbuf->st_ex_uid ));
		return false;
	}

	/* Should be 10k or less. */
	if (psbuf->st_ex_size > MAX_USERSHARE_FILE_SIZE) {
		DEBUG(0,("check_usershare_stat: file %s owned by uid %u is "
			"too large (%u) to be a user share file.\n",
			fname, (unsigned int)psbuf->st_ex_uid,
			(unsigned int)psbuf->st_ex_size ));
		return false;
	}

	return true;
}

/***************************************************************************
 Parse the contents of a usershare file.
***************************************************************************/

enum usershare_err parse_usershare_file(TALLOC_CTX *ctx,
			SMB_STRUCT_STAT *psbuf,
			const char *servicename,
			int snum,
			char **lines,
			int numlines,
			char **pp_sharepath,
			char **pp_comment,
			char **pp_cp_servicename,
			struct security_descriptor **ppsd,
			bool *pallow_guest)
{
	const char **prefixallowlist = lp_usershare_prefix_allow_list();
	const char **prefixdenylist = lp_usershare_prefix_deny_list();
	int us_vers;
	DIR *dp;
	SMB_STRUCT_STAT sbuf;
	char *sharepath = NULL;
	char *comment = NULL;

	*pp_sharepath = NULL;
	*pp_comment = NULL;

	*pallow_guest = false;

	if (numlines < 4) {
		return USERSHARE_MALFORMED_FILE;
	}

	if (strcmp(lines[0], "#VERSION 1") == 0) {
		us_vers = 1;
	} else if (strcmp(lines[0], "#VERSION 2") == 0) {
		us_vers = 2;
		if (numlines < 5) {
			return USERSHARE_MALFORMED_FILE;
		}
	} else {
		return USERSHARE_BAD_VERSION;
	}

	if (strncmp(lines[1], "path=", 5) != 0) {
		return USERSHARE_MALFORMED_PATH;
	}

	sharepath = talloc_strdup(ctx, &lines[1][5]);
	if (!sharepath) {
		return USERSHARE_POSIX_ERR;
	}
	trim_string(sharepath, " ", " ");

	if (strncmp(lines[2], "comment=", 8) != 0) {
		return USERSHARE_MALFORMED_COMMENT_DEF;
	}

	comment = talloc_strdup(ctx, &lines[2][8]);
	if (!comment) {
		return USERSHARE_POSIX_ERR;
	}
	trim_string(comment, " ", " ");
	trim_char(comment, '"', '"');

	if (strncmp(lines[3], "usershare_acl=", 14) != 0) {
		return USERSHARE_MALFORMED_ACL_DEF;
	}

	if (!parse_usershare_acl(ctx, &lines[3][14], ppsd)) {
		return USERSHARE_ACL_ERR;
	}

	if (us_vers == 2) {
		if (strncmp(lines[4], "guest_ok=", 9) != 0) {
			return USERSHARE_MALFORMED_ACL_DEF;
		}
		if (lines[4][9] == 'y') {
			*pallow_guest = true;
		}

		/* Backwards compatible extension to file version #2. */
		if (numlines > 5) {
			if (strncmp(lines[5], "sharename=", 10) != 0) {
				return USERSHARE_MALFORMED_SHARENAME_DEF;
			}
			if (!strequal(&lines[5][10], servicename)) {
				return USERSHARE_BAD_SHARENAME;
			}
			*pp_cp_servicename = talloc_strdup(ctx, &lines[5][10]);
			if (!*pp_cp_servicename) {
				return USERSHARE_POSIX_ERR;
			}
		}
	}

	if (*pp_cp_servicename == NULL) {
		*pp_cp_servicename = talloc_strdup(ctx, servicename);
		if (!*pp_cp_servicename) {
			return USERSHARE_POSIX_ERR;
		}
	}

	if (snum != -1 && (strcmp(sharepath, ServicePtrs[snum]->path) == 0)) {
		/* Path didn't change, no checks needed. */
		*pp_sharepath = sharepath;
		*pp_comment = comment;
		return USERSHARE_OK;
	}

	/* The path *must* be absolute. */
	if (sharepath[0] != '/') {
		DEBUG(2,("parse_usershare_file: share %s: path %s is not an absolute path.\n",
			servicename, sharepath));
		return USERSHARE_PATH_NOT_ABSOLUTE;
	}

	/* If there is a usershare prefix deny list ensure one of these paths
	   doesn't match the start of the user given path. */
	if (prefixdenylist) {
		int i;
		for ( i=0; prefixdenylist[i]; i++ ) {
			DEBUG(10,("parse_usershare_file: share %s : checking prefixdenylist[%d]='%s' against %s\n",
				servicename, i, prefixdenylist[i], sharepath ));
			if (memcmp( sharepath, prefixdenylist[i], strlen(prefixdenylist[i])) == 0) {
				DEBUG(2,("parse_usershare_file: share %s path %s starts with one of the "
					"usershare prefix deny list entries.\n",
					servicename, sharepath));
				return USERSHARE_PATH_IS_DENIED;
			}
		}
	}

	/* If there is a usershare prefix allow list ensure one of these paths
	   does match the start of the user given path. */

	if (prefixallowlist) {
		int i;
		for ( i=0; prefixallowlist[i]; i++ ) {
			DEBUG(10,("parse_usershare_file: share %s checking prefixallowlist[%d]='%s' against %s\n",
				servicename, i, prefixallowlist[i], sharepath ));
			if (memcmp( sharepath, prefixallowlist[i], strlen(prefixallowlist[i])) == 0) {
				break;
			}
		}
		if (prefixallowlist[i] == NULL) {
			DEBUG(2,("parse_usershare_file: share %s path %s doesn't start with one of the "
				"usershare prefix allow list entries.\n",
				servicename, sharepath));
			return USERSHARE_PATH_NOT_ALLOWED;
		}
        }

	/* Ensure this is pointing to a directory. */
	dp = opendir(sharepath);

	if (!dp) {
		DEBUG(2,("parse_usershare_file: share %s path %s is not a directory.\n",
			servicename, sharepath));
		return USERSHARE_PATH_NOT_DIRECTORY;
	}

	/* Ensure the owner of the usershare file has permission to share
	   this directory. */

	if (sys_stat(sharepath, &sbuf, false) == -1) {
		DEBUG(2,("parse_usershare_file: share %s : stat failed on path %s. %s\n",
			servicename, sharepath, strerror(errno) ));
		closedir(dp);
		return USERSHARE_POSIX_ERR;
	}

	closedir(dp);

	if (!S_ISDIR(sbuf.st_ex_mode)) {
		DEBUG(2,("parse_usershare_file: share %s path %s is not a directory.\n",
			servicename, sharepath ));
		return USERSHARE_PATH_NOT_DIRECTORY;
	}

	/* Check if sharing is restricted to owner-only. */
	/* psbuf is the stat of the usershare definition file,
	   sbuf is the stat of the target directory to be shared. */

	if (lp_usershare_owner_only()) {
		/* root can share anything. */
		if ((psbuf->st_ex_uid != 0) && (sbuf.st_ex_uid != psbuf->st_ex_uid)) {
			return USERSHARE_PATH_NOT_ALLOWED;
		}
	}

	*pp_sharepath = sharepath;
	*pp_comment = comment;
	return USERSHARE_OK;
}

/***************************************************************************
 Deal with a usershare file.
 Returns:
	>= 0 - snum
	-1 - Bad name, invalid contents.
	   - service name already existed and not a usershare, problem
	    with permissions to share directory etc.
***************************************************************************/

static int process_usershare_file(const char *dir_name, const char *file_name, int snum_template)
{
	SMB_STRUCT_STAT sbuf;
	SMB_STRUCT_STAT lsbuf;
	char *fname = NULL;
	char *sharepath = NULL;
	char *comment = NULL;
	char *cp_service_name = NULL;
	char **lines = NULL;
	int numlines = 0;
	int fd = -1;
	int iService = -1;
	TALLOC_CTX *ctx = talloc_stackframe();
	struct security_descriptor *psd = NULL;
	bool guest_ok = false;
	char *canon_name = NULL;
	bool added_service = false;
	int ret = -1;
	NTSTATUS status;

	/* Ensure share name doesn't contain invalid characters. */
	if (!validate_net_name(file_name, INVALID_SHARENAME_CHARS, strlen(file_name))) {
		DEBUG(0,("process_usershare_file: share name %s contains "
			"invalid characters (any of %s)\n",
			file_name, INVALID_SHARENAME_CHARS ));
		goto out;
	}

	canon_name = canonicalize_servicename(ctx, file_name);
	if (!canon_name) {
		goto out;
	}

	fname = talloc_asprintf(ctx, "%s/%s", dir_name, file_name);
	if (!fname) {
		goto out;
	}

	/* Minimize the race condition by doing an lstat before we
	   open and fstat. Ensure this isn't a symlink link. */

	if (sys_lstat(fname, &lsbuf, false) != 0) {
		if (errno == ENOENT) {
			/* Unknown share requested. Just ignore. */
			goto out;
		}
		/* Only log messages for meaningful problems. */
		DEBUG(0,("process_usershare_file: stat of %s failed. %s\n",
			fname, strerror(errno) ));
		goto out;
	}

	/* This must be a regular file, not a symlink, directory or
	   other strange filetype. */
	if (!check_usershare_stat(fname, &lsbuf)) {
		goto out;
	}

	{
		TDB_DATA data;

		status = dbwrap_fetch_bystring(ServiceHash, canon_name,
					       canon_name, &data);

		iService = -1;

		if (NT_STATUS_IS_OK(status) &&
		    (data.dptr != NULL) &&
		    (data.dsize == sizeof(iService))) {
			memcpy(&iService, data.dptr, sizeof(iService));
		}
	}

	if (iService != -1 &&
	    timespec_compare(&ServicePtrs[iService]->usershare_last_mod,
			     &lsbuf.st_ex_mtime) == 0) {
		/* Nothing changed - Mark valid and return. */
		DEBUG(10,("process_usershare_file: service %s not changed.\n",
			canon_name ));
		ServicePtrs[iService]->usershare = USERSHARE_VALID;
		ret = iService;
		goto out;
	}

	/* Try and open the file read only - no symlinks allowed. */
#ifdef O_NOFOLLOW
	fd = open(fname, O_RDONLY|O_NOFOLLOW, 0);
#else
	fd = open(fname, O_RDONLY, 0);
#endif

	if (fd == -1) {
		DEBUG(0,("process_usershare_file: unable to open %s. %s\n",
			fname, strerror(errno) ));
		goto out;
	}

	/* Now fstat to be *SURE* it's a regular file. */
	if (sys_fstat(fd, &sbuf, false) != 0) {
		close(fd);
		DEBUG(0,("process_usershare_file: fstat of %s failed. %s\n",
			fname, strerror(errno) ));
		goto out;
	}

	/* Is it the same dev/inode as was lstated ? */
	if (!check_same_stat(&lsbuf, &sbuf)) {
		close(fd);
		DEBUG(0,("process_usershare_file: fstat of %s is a different file from lstat. "
			"Symlink spoofing going on ?\n", fname ));
		goto out;
	}

	/* This must be a regular file, not a symlink, directory or
	   other strange filetype. */
	if (!check_usershare_stat(fname, &sbuf)) {
		close(fd);
		goto out;
	}

	lines = fd_lines_load(fd, &numlines, MAX_USERSHARE_FILE_SIZE, NULL);

	close(fd);
	if (lines == NULL) {
		DEBUG(0,("process_usershare_file: loading file %s owned by %u failed.\n",
			fname, (unsigned int)sbuf.st_ex_uid ));
		goto out;
	}

	if (parse_usershare_file(ctx, &sbuf, file_name,
			iService, lines, numlines, &sharepath,
			&comment, &cp_service_name,
			&psd, &guest_ok) != USERSHARE_OK) {
		goto out;
	}

	/* Everything ok - add the service possibly using a template. */
	if (iService < 0) {
		const struct loadparm_service *sp = &sDefault;
		if (snum_template != -1) {
			sp = ServicePtrs[snum_template];
		}

		if ((iService = add_a_service(sp, cp_service_name)) < 0) {
			DEBUG(0, ("process_usershare_file: Failed to add "
				"new service %s\n", cp_service_name));
			goto out;
		}

		added_service = true;

		/* Read only is controlled by usershare ACL below. */
		ServicePtrs[iService]->read_only = false;
	}

	/* Write the ACL of the new/modified share. */
	status = set_share_security(canon_name, psd);
	if (!NT_STATUS_IS_OK(status)) {
		 DEBUG(0, ("process_usershare_file: Failed to set share "
			"security for user share %s\n",
			canon_name ));
		goto out;
	}

	/* If from a template it may be marked invalid. */
	ServicePtrs[iService]->valid = true;

	/* Set the service as a valid usershare. */
	ServicePtrs[iService]->usershare = USERSHARE_VALID;

	/* Set guest access. */
	if (lp_usershare_allow_guests()) {
		ServicePtrs[iService]->guest_ok = guest_ok;
	}

	/* And note when it was loaded. */
	ServicePtrs[iService]->usershare_last_mod = sbuf.st_ex_mtime;
	lpcfg_string_set(ServicePtrs[iService], &ServicePtrs[iService]->path,
			 sharepath);
	lpcfg_string_set(ServicePtrs[iService],
			 &ServicePtrs[iService]->comment, comment);

	ret = iService;

  out:

	if (ret == -1 && iService != -1 && added_service) {
		lp_remove_service(iService);
	}

	TALLOC_FREE(lines);
	TALLOC_FREE(ctx);
	return ret;
}

/***************************************************************************
 Checks if a usershare entry has been modified since last load.
***************************************************************************/

static bool usershare_exists(int iService, struct timespec *last_mod)
{
	SMB_STRUCT_STAT lsbuf;
	const char *usersharepath = Globals.usershare_path;
	char *fname;

	fname = talloc_asprintf(talloc_tos(),
				"%s/%s",
				usersharepath,
				ServicePtrs[iService]->szService);
	if (fname == NULL) {
		return false;
	}

	if (sys_lstat(fname, &lsbuf, false) != 0) {
		TALLOC_FREE(fname);
		return false;
	}

	if (!S_ISREG(lsbuf.st_ex_mode)) {
		TALLOC_FREE(fname);
		return false;
	}

	TALLOC_FREE(fname);
	*last_mod = lsbuf.st_ex_mtime;
	return true;
}

static bool usershare_directory_is_root(uid_t uid)
{
	if (uid == 0) {
		return true;
	}

	if (uid_wrapper_enabled()) {
		return true;
	}

	return false;
}

/***************************************************************************
 Load a usershare service by name. Returns a valid servicenumber or -1.
***************************************************************************/

int load_usershare_service(const char *servicename)
{
	SMB_STRUCT_STAT sbuf;
	const char *usersharepath = Globals.usershare_path;
	int max_user_shares = Globals.usershare_max_shares;
	int snum_template = -1;

	if (servicename[0] == '\0') {
		/* Invalid service name. */
		return -1;
	}

	if (*usersharepath == 0 ||  max_user_shares == 0) {
		return -1;
	}

	if (sys_stat(usersharepath, &sbuf, false) != 0) {
		DEBUG(0,("load_usershare_service: stat of %s failed. %s\n",
			usersharepath, strerror(errno) ));
		return -1;
	}

	if (!S_ISDIR(sbuf.st_ex_mode)) {
		DEBUG(0,("load_usershare_service: %s is not a directory.\n",
			usersharepath ));
		return -1;
	}

	/*
	 * This directory must be owned by root, and have the 't' bit set.
	 * It also must not be writable by "other".
	 */

#ifdef S_ISVTX
	if (!usershare_directory_is_root(sbuf.st_ex_uid) ||
	    !(sbuf.st_ex_mode & S_ISVTX) || (sbuf.st_ex_mode & S_IWOTH)) {
#else
	if (!usershare_directory_is_root(sbuf.st_ex_uid) ||
	    (sbuf.st_ex_mode & S_IWOTH)) {
#endif
		DEBUG(0,("load_usershare_service: directory %s is not owned by root "
			"or does not have the sticky bit 't' set or is writable by anyone.\n",
			usersharepath ));
		return -1;
	}

	/* Ensure the template share exists if it's set. */
	if (Globals.usershare_template_share[0]) {
		/* We can't use lp_servicenumber here as we are recommending that
		   template shares have -valid=false set. */
		for (snum_template = iNumServices - 1; snum_template >= 0; snum_template--) {
			if (ServicePtrs[snum_template]->szService &&
					strequal(ServicePtrs[snum_template]->szService,
						Globals.usershare_template_share)) {
				break;
			}
		}

		if (snum_template == -1) {
			DEBUG(0,("load_usershare_service: usershare template share %s "
				"does not exist.\n",
				Globals.usershare_template_share ));
			return -1;
		}
	}

	return process_usershare_file(usersharepath, servicename, snum_template);
}

/***************************************************************************
 Load all user defined shares from the user share directory.
 We only do this if we're enumerating the share list.
 This is the function that can delete usershares that have
 been removed.
***************************************************************************/

int load_usershare_shares(struct smbd_server_connection *sconn,
			  bool (*snumused) (struct smbd_server_connection *, int))
{
	DIR *dp;
	SMB_STRUCT_STAT sbuf;
	struct dirent *de;
	int num_usershares = 0;
	int max_user_shares = Globals.usershare_max_shares;
	unsigned int num_dir_entries, num_bad_dir_entries, num_tmp_dir_entries;
	unsigned int allowed_bad_entries = ((2*max_user_shares)/10);
	unsigned int allowed_tmp_entries = ((2*max_user_shares)/10);
	int iService;
	int snum_template = -1;
	const char *usersharepath = Globals.usershare_path;
	int ret = lp_numservices();
	TALLOC_CTX *tmp_ctx;

	if (max_user_shares == 0 || *usersharepath == '\0') {
		return lp_numservices();
	}

	if (sys_stat(usersharepath, &sbuf, false) != 0) {
		DEBUG(0,("load_usershare_shares: stat of %s failed. %s\n",
			usersharepath, strerror(errno) ));
		return ret;
	}

	/*
	 * This directory must be owned by root, and have the 't' bit set.
	 * It also must not be writable by "other".
	 */

#ifdef S_ISVTX
	if (sbuf.st_ex_uid != 0 || !(sbuf.st_ex_mode & S_ISVTX) || (sbuf.st_ex_mode & S_IWOTH)) {
#else
	if (sbuf.st_ex_uid != 0 || (sbuf.st_ex_mode & S_IWOTH)) {
#endif
		DEBUG(0,("load_usershare_shares: directory %s is not owned by root "
			"or does not have the sticky bit 't' set or is writable by anyone.\n",
			usersharepath ));
		return ret;
	}

	/* Ensure the template share exists if it's set. */
	if (Globals.usershare_template_share[0]) {
		/* We can't use lp_servicenumber here as we are recommending that
		   template shares have -valid=false set. */
		for (snum_template = iNumServices - 1; snum_template >= 0; snum_template--) {
			if (ServicePtrs[snum_template]->szService &&
					strequal(ServicePtrs[snum_template]->szService,
						Globals.usershare_template_share)) {
				break;
			}
		}

		if (snum_template == -1) {
			DEBUG(0,("load_usershare_shares: usershare template share %s "
				"does not exist.\n",
				Globals.usershare_template_share ));
			return ret;
		}
	}

	/* Mark all existing usershares as pending delete. */
	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && ServicePtrs[iService]->usershare) {
			ServicePtrs[iService]->usershare = USERSHARE_PENDING_DELETE;
		}
	}

	dp = opendir(usersharepath);
	if (!dp) {
		DEBUG(0,("load_usershare_shares:: failed to open directory %s. %s\n",
			usersharepath, strerror(errno) ));
		return ret;
	}

	for (num_dir_entries = 0, num_bad_dir_entries = 0, num_tmp_dir_entries = 0;
			(de = readdir(dp));
			num_dir_entries++ ) {
		int r;
		const char *n = de->d_name;

		/* Ignore . and .. */
		if (*n == '.') {
			if ((n[1] == '\0') || (n[1] == '.' && n[2] == '\0')) {
				continue;
			}
		}

		if (n[0] == ':') {
			/* Temporary file used when creating a share. */
			num_tmp_dir_entries++;
		}

		/* Allow 20% tmp entries. */
		if (num_tmp_dir_entries > allowed_tmp_entries) {
			DEBUG(0,("load_usershare_shares: too many temp entries (%u) "
				"in directory %s\n",
				num_tmp_dir_entries, usersharepath));
			break;
		}

		r = process_usershare_file(usersharepath, n, snum_template);
		if (r == 0) {
			/* Update the services count. */
			num_usershares++;
			if (num_usershares >= max_user_shares) {
				DEBUG(0,("load_usershare_shares: max user shares reached "
					"on file %s in directory %s\n",
					n, usersharepath ));
				break;
			}
		} else if (r == -1) {
			num_bad_dir_entries++;
		}

		/* Allow 20% bad entries. */
		if (num_bad_dir_entries > allowed_bad_entries) {
			DEBUG(0,("load_usershare_shares: too many bad entries (%u) "
				"in directory %s\n",
				num_bad_dir_entries, usersharepath));
			break;
		}

		/* Allow 20% bad entries. */
		if (num_dir_entries > max_user_shares + allowed_bad_entries) {
			DEBUG(0,("load_usershare_shares: too many total entries (%u) "
			"in directory %s\n",
			num_dir_entries, usersharepath));
			break;
		}
	}

	closedir(dp);

	/* Sweep through and delete any non-refreshed usershares that are
	   not currently in use. */
	tmp_ctx = talloc_stackframe();
	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && (ServicePtrs[iService]->usershare == USERSHARE_PENDING_DELETE)) {
			const struct loadparm_substitution *lp_sub =
				loadparm_s3_global_substitution();
			char *servname;

			if (snumused && snumused(sconn, iService)) {
				continue;
			}

			servname = lp_servicename(tmp_ctx, lp_sub, iService);

			/* Remove from the share ACL db. */
			DEBUG(10,("load_usershare_shares: Removing deleted usershare %s\n",
				  servname ));
			delete_share_security(servname);
			free_service_byindex(iService);
		}
	}
	talloc_free(tmp_ctx);

	return lp_numservices();
}

/********************************************************
 Destroy global resources allocated in this file
********************************************************/

void gfree_loadparm(void)
{
	int i;

	free_file_list();

	/* Free resources allocated to services */

	for ( i = 0; i < iNumServices; i++ ) {
		if ( VALID(i) ) {
			free_service_byindex(i);
		}
	}

	TALLOC_FREE( ServicePtrs );
	iNumServices = 0;

	/* Now release all resources allocated to global
	   parameters and the default service */

	free_global_parameters();
}


/***************************************************************************
 Allow client apps to specify that they are a client
***************************************************************************/
static void lp_set_in_client(bool b)
{
    in_client = b;
}


/***************************************************************************
 Determine if we're running in a client app
***************************************************************************/
static bool lp_is_in_client(void)
{
    return in_client;
}

static void lp_enforce_ad_dc_settings(void)
{
	lp_do_parameter(GLOBAL_SECTION_SNUM, "passdb backend", "samba_dsdb");
	lp_do_parameter(GLOBAL_SECTION_SNUM,
			"winbindd:use external pipes", "true");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:default", "external");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:svcctl", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:srvsvc", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:eventlog", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:ntsvcs", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:winreg", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:spoolss", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_daemon:spoolssd", "embedded");
	lp_do_parameter(GLOBAL_SECTION_SNUM, "rpc_server:tcpip", "no");
}

/***************************************************************************
 Load the services array from the services file. Return true on success,
 false on failure.
***************************************************************************/

static bool lp_load_ex(const char *pszFname,
		       bool global_only,
		       bool save_defaults,
		       bool add_ipc,
		       bool reinit_globals,
		       bool allow_include_registry,
		       bool load_all_shares)
{
	char *n2 = NULL;
	bool bRetval;
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx;
	int max_protocol, min_protocol;

	DEBUG(3, ("lp_load_ex: refreshing parameters\n"));

	bInGlobalSection = true;
	bGlobalOnly = global_only;
	bAllowIncludeRegistry = allow_include_registry;
	sDefault = _sDefault;

	lp_ctx = setup_lp_context(talloc_tos());

	init_globals(lp_ctx, reinit_globals);

	free_file_list();

	if (save_defaults) {
		init_locals();
		lp_save_defaults();
	}

	if (!reinit_globals) {
		free_param_opts(&Globals.param_opt);
		apply_lp_set_cmdline();
	}

	lp_do_parameter(-1, "idmap config * : backend", Globals.idmap_backend);

	/* We get sections first, so have to start 'behind' to make up */
	iServiceIndex = -1;

	if (lp_config_backend_is_file()) {
		n2 = talloc_sub_basic(talloc_tos(), get_current_username(),
					current_user_info.domain,
					pszFname);
		if (!n2) {
			smb_panic("lp_load_ex: out of memory");
		}

		add_to_file_list(NULL, &file_lists, pszFname, n2);

		bRetval = pm_process(n2, lp_do_section, do_parameter, lp_ctx);
		TALLOC_FREE(n2);

		/* finish up the last section */
		DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
		if (bRetval) {
			if (iServiceIndex >= 0) {
				bRetval = lpcfg_service_ok(ServicePtrs[iServiceIndex]);
			}
		}

		if (lp_config_backend_is_registry()) {
			bool ok;
			/* config backend changed to registry in config file */
			/*
			 * We need to use this extra global variable here to
			 * survive restart: init_globals uses this as a default
			 * for config_backend. Otherwise, init_globals would
			 *  send us into an endless loop here.
			 */

			config_backend = CONFIG_BACKEND_REGISTRY;
			/* start over */
			DEBUG(1, ("lp_load_ex: changing to config backend "
				  "registry\n"));
			init_globals(lp_ctx, true);

			TALLOC_FREE(lp_ctx);

			lp_kill_all_services();
			ok = lp_load_ex(pszFname, global_only, save_defaults,
					add_ipc, reinit_globals,
					allow_include_registry,
					load_all_shares);
			TALLOC_FREE(frame);
			return ok;
		}
	} else if (lp_config_backend_is_registry()) {
		bRetval = process_registry_globals();
	} else {
		DEBUG(0, ("Illegal config  backend given: %d\n",
			  lp_config_backend()));
		bRetval = false;
	}

	if (bRetval && lp_registry_shares()) {
		if (load_all_shares) {
			bRetval = process_registry_shares();
		} else {
			bRetval = reload_registry_shares();
		}
	}

	{
		const struct loadparm_substitution *lp_sub =
			loadparm_s3_global_substitution();
		char *serv = lp_auto_services(talloc_tos(), lp_sub);
		lp_add_auto_services(serv);
		TALLOC_FREE(serv);
	}

	if (add_ipc) {
		/* When 'restrict anonymous = 2' guest connections to ipc$
		   are denied */
		lp_add_ipc("IPC$", (lp_restrict_anonymous() < 2));
		if ( lp_enable_asu_support() ) {
			lp_add_ipc("ADMIN$", false);
		}
	}

	set_allowed_client_auth();

	if (lp_security() == SEC_ADS && strchr(lp_password_server(), ':')) {
		DEBUG(1, ("WARNING: The optional ':port' in password server = %s is deprecated\n",
			  lp_password_server()));
	}

	bLoaded = true;

	/* Now we check we_are_a_wins_server and set szWINSserver to 127.0.0.1 */
	/* if we_are_a_wins_server is true and we are in the client            */
	if (lp_is_in_client() && Globals.we_are_a_wins_server) {
		lp_do_parameter(GLOBAL_SECTION_SNUM, "wins server", "127.0.0.1");
	}

	init_iconv();

	fault_configure(smb_panic_s3);

	/*
	 * We run this check once the whole smb.conf is parsed, to
	 * force some settings for the standard way a AD DC is
	 * operated.  We may change these as our code evolves, which
	 * is why we force these settings.
	 */
	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		lp_enforce_ad_dc_settings();
	}

	bAllowIncludeRegistry = true;

	/* Check if command line max protocol < min protocol, if so
	 * report a warning to the user.
	 */
	max_protocol = lp_client_max_protocol();
	min_protocol = lp_client_min_protocol();
	if (max_protocol < min_protocol) {
		const char *max_protocolp, *min_protocolp;
		max_protocolp = lpcfg_get_smb_protocol(max_protocol);
		min_protocolp = lpcfg_get_smb_protocol(min_protocol);
		DBG_ERR("Max protocol %s is less than min protocol %s.\n",
			max_protocolp, min_protocolp);
	}

	TALLOC_FREE(frame);
	return (bRetval);
}

static bool lp_load(const char *pszFname,
		    bool global_only,
		    bool save_defaults,
		    bool add_ipc,
		    bool reinit_globals)
{
	return lp_load_ex(pszFname,
			  global_only,
			  save_defaults,
			  add_ipc,
			  reinit_globals,
			  true,   /* allow_include_registry */
			  false); /* load_all_shares*/
}

bool lp_load_initial_only(const char *pszFname)
{
	return lp_load_ex(pszFname,
			  true,   /* global only */
			  true,   /* save_defaults */
			  false,  /* add_ipc */
			  true,   /* reinit_globals */
			  false,  /* allow_include_registry */
			  false); /* load_all_shares*/
}

/**
 * most common lp_load wrapper, loading only the globals
 *
 * If this is used in a daemon or client utility it should be called
 * after processing popt.
 */
bool lp_load_global(const char *file_name)
{
	return lp_load(file_name,
		       true,   /* global_only */
		       false,  /* save_defaults */
		       false,  /* add_ipc */
		       true);  /* reinit_globals */
}

/**
 * The typical lp_load wrapper with shares, loads global and
 * shares, including IPC, but does not force immediate
 * loading of all shares from registry.
 */
bool lp_load_with_shares(const char *file_name)
{
	return lp_load(file_name,
		       false,  /* global_only */
		       false,  /* save_defaults */
		       true,   /* add_ipc */
		       true);  /* reinit_globals */
}

/**
 * lp_load wrapper, especially for clients
 */
bool lp_load_client(const char *file_name)
{
	lp_set_in_client(true);

	return lp_load_global(file_name);
}

/**
 * lp_load wrapper, loading only globals, but intended
 * for subsequent calls, not reinitializing the globals
 * to default values
 */
bool lp_load_global_no_reinit(const char *file_name)
{
	return lp_load(file_name,
		       true,   /* global_only */
		       false,  /* save_defaults */
		       false,  /* add_ipc */
		       false); /* reinit_globals */
}

/**
 * lp_load wrapper, loading globals and shares,
 * intended for subsequent calls, i.e. not reinitializing
 * the globals to default values.
 */
bool lp_load_no_reinit(const char *file_name)
{
	return lp_load(file_name,
		       false,  /* global_only */
		       false,  /* save_defaults */
		       false,  /* add_ipc */
		       false); /* reinit_globals */
}


/**
 * lp_load wrapper, especially for clients, no reinitialization
 */
bool lp_load_client_no_reinit(const char *file_name)
{
	lp_set_in_client(true);

	return lp_load_global_no_reinit(file_name);
}

bool lp_load_with_registry_shares(const char *pszFname)
{
	return lp_load_ex(pszFname,
			  false, /* global_only */
			  true,  /* save_defaults */
			  false, /* add_ipc */
			  true, /* reinit_globals */
			  true,  /* allow_include_registry */
			  true); /* load_all_shares*/
}

/***************************************************************************
 Return the max number of services.
***************************************************************************/

int lp_numservices(void)
{
	return (iNumServices);
}

/***************************************************************************
Display the contents of the services array in human-readable form.
***************************************************************************/

void lp_dump(FILE *f, bool show_defaults, int maxtoprint)
{
	int iService;
	struct loadparm_context *lp_ctx;

	if (show_defaults)
		defaults_saved = false;

	lp_ctx = setup_lp_context(talloc_tos());
	if (lp_ctx == NULL) {
		return;
	}

	lpcfg_dump_globals(lp_ctx, f, !defaults_saved);

	lpcfg_dump_a_service(&sDefault, &sDefault, f, flags_list, show_defaults);

	for (iService = 0; iService < maxtoprint; iService++) {
		fprintf(f,"\n");
		lp_dump_one(f, show_defaults, iService);
	}
	TALLOC_FREE(lp_ctx);
}

/***************************************************************************
Display the contents of one service in human-readable form.
***************************************************************************/

void lp_dump_one(FILE * f, bool show_defaults, int snum)
{
	if (VALID(snum)) {
		if (ServicePtrs[snum]->szService[0] == '\0')
			return;
		lpcfg_dump_a_service(ServicePtrs[snum], &sDefault, f,
				     flags_list, show_defaults);
	}
}

/***************************************************************************
Return the number of the service with the given name, or -1 if it doesn't
exist. Note that this is a DIFFERENT ANIMAL from the internal function
getservicebyname()! This works ONLY if all services have been loaded, and
does not copy the found service.
***************************************************************************/

int lp_servicenumber(const char *pszServiceName)
{
	int iService;
        fstring serviceName;

        if (!pszServiceName) {
        	return GLOBAL_SECTION_SNUM;
	}

	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && ServicePtrs[iService]->szService) {
			/*
			 * The substitution here is used to support %U in
			 * service names
			 */
			fstrcpy(serviceName, ServicePtrs[iService]->szService);
			standard_sub_basic(get_current_username(),
					   current_user_info.domain,
					   serviceName,sizeof(serviceName));
			if (strequal(serviceName, pszServiceName)) {
				break;
			}
		}
	}

	if (iService >= 0 && ServicePtrs[iService]->usershare == USERSHARE_VALID) {
		struct timespec last_mod;

		if (!usershare_exists(iService, &last_mod)) {
			/* Remove the share security tdb entry for it. */
			delete_share_security(lp_const_servicename(iService));
			/* Remove it from the array. */
			free_service_byindex(iService);
			/* Doesn't exist anymore. */
			return GLOBAL_SECTION_SNUM;
		}

		/* Has it been modified ? If so delete and reload. */
		if (timespec_compare(&ServicePtrs[iService]->usershare_last_mod,
				     &last_mod) < 0) {
			/* Remove it from the array. */
			free_service_byindex(iService);
			/* and now reload it. */
			iService = load_usershare_service(pszServiceName);
		}
	}

	if (iService < 0) {
		DEBUG(7,("lp_servicenumber: couldn't find %s\n", pszServiceName));
		return GLOBAL_SECTION_SNUM;
	}

	return (iService);
}

/*******************************************************************
 A useful volume label function. 
********************************************************************/

const char *volume_label(TALLOC_CTX *ctx, int snum)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *ret;
	const char *label = lp_volume(ctx, lp_sub, snum);
	size_t end = 32;

	if (!*label) {
		label = lp_servicename(ctx, lp_sub, snum);
	}

	/*
	 * Volume label can be a max of 32 bytes. Make sure to truncate
	 * it at a codepoint boundary if it's longer than 32 and contains
	 * multibyte characters. Windows insists on a volume label being
	 * a valid mb sequence, and errors out if not.
	 */
	if (strlen(label) > 32) {
		/*
		 * A MB char can be a max of 5 bytes, thus
		 * we should have a valid mb character at a
		 * minimum position of (32-5) = 27.
		 */
		while (end >= 27) {
			/*
			 * Check if a codepoint starting from next byte
			 * is valid. If yes, then the current byte is the
			 * end of a MB or ascii sequence and the label can
			 * be safely truncated here. If not, keep going
			 * backwards till a valid codepoint is found.
			 */
			size_t len = 0;
			const char *s = &label[end];
			codepoint_t c = next_codepoint(s, &len);
			if (c != INVALID_CODEPOINT) {
				break;
			}
			end--;
		}
	}

	/* This returns a max of 33 byte guarenteed null terminated string. */
	ret = talloc_strndup(ctx, label, end);
	if (!ret) {
		return "";
	}
	return ret;
}

/*******************************************************************
 Get the default server type we will announce as via nmbd.
********************************************************************/

int lp_default_server_announce(void)
{
	int default_server_announce = 0;
	default_server_announce |= SV_TYPE_WORKSTATION;
	default_server_announce |= SV_TYPE_SERVER;
	default_server_announce |= SV_TYPE_SERVER_UNIX;

	/* note that the flag should be set only if we have a 
	   printer service but nmbd doesn't actually load the 
	   services so we can't tell   --jerry */

	default_server_announce |= SV_TYPE_PRINTQ_SERVER;

	default_server_announce |= SV_TYPE_SERVER_NT;
	default_server_announce |= SV_TYPE_NT;

	switch (lp_server_role()) {
		case ROLE_DOMAIN_MEMBER:
			default_server_announce |= SV_TYPE_DOMAIN_MEMBER;
			break;
		case ROLE_DOMAIN_PDC:
			default_server_announce |= SV_TYPE_DOMAIN_CTRL;
			break;
		case ROLE_DOMAIN_BDC:
			default_server_announce |= SV_TYPE_DOMAIN_BAKCTRL;
			break;
		case ROLE_STANDALONE:
		default:
			break;
	}
	if (lp_time_server())
		default_server_announce |= SV_TYPE_TIME_SOURCE;

	if (lp_host_msdfs())
		default_server_announce |= SV_TYPE_DFS_SERVER;

	return default_server_announce;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

bool lp_domain_master(void)
{
	if (Globals._domain_master == Auto)
		return (lp_server_role() == ROLE_DOMAIN_PDC);

	return (bool)Globals._domain_master;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

static bool lp_domain_master_true_or_auto(void)
{
	if (Globals._domain_master) /* auto or yes */
		return true;

	return false;
}

/***********************************************************
 If we are DMB then prefer us as LMB
************************************************************/

bool lp_preferred_master(void)
{
	int preferred_master = lp__preferred_master();

	if (preferred_master == Auto)
		return (lp_local_master() && lp_domain_master());

	return (bool)preferred_master;
}

/*******************************************************************
 Remove a service.
********************************************************************/

void lp_remove_service(int snum)
{
	ServicePtrs[snum]->valid = false;
}

const char *lp_printername(TALLOC_CTX *ctx,
			   const struct loadparm_substitution *lp_sub,
			   int snum)
{
	const char *ret = lp__printername(ctx, lp_sub, snum);

	if (ret == NULL || *ret == '\0') {
		ret = lp_const_servicename(snum);
	}

	return ret;
}


/***********************************************************
 Allow daemons such as winbindd to fix their logfile name.
************************************************************/

void lp_set_logfile(const char *name)
{
	lpcfg_string_set(Globals.ctx, &Globals.logfile, name);
	debug_set_logfile(name);
}

/*******************************************************************
 Return the max print jobs per queue.
********************************************************************/

int lp_maxprintjobs(int snum)
{
	int maxjobs = lp_max_print_jobs(snum);

	if (maxjobs <= 0 || maxjobs >= PRINT_MAX_JOBID)
		maxjobs = PRINT_MAX_JOBID - 1;

	return maxjobs;
}

const char *lp_printcapname(void)
{
	const char *printcap_name = lp_printcap_name();

	if ((printcap_name != NULL) &&
	    (printcap_name[0] != '\0'))
		return printcap_name;

	if (sDefault.printing == PRINT_CUPS) {
		return "cups";
	}

	if (sDefault.printing == PRINT_BSD)
		return "/etc/printcap";

	return PRINTCAP_NAME;
}

static uint32_t spoolss_state;

bool lp_disable_spoolss( void )
{
	if ( spoolss_state == SVCCTL_STATE_UNKNOWN )
		spoolss_state = lp__disable_spoolss() ? SVCCTL_STOPPED : SVCCTL_RUNNING;

	return spoolss_state == SVCCTL_STOPPED ? true : false;
}

void lp_set_spoolss_state( uint32_t state )
{
	SMB_ASSERT( (state == SVCCTL_STOPPED) || (state == SVCCTL_RUNNING) );

	spoolss_state = state;
}

uint32_t lp_get_spoolss_state( void )
{
	return lp_disable_spoolss() ? SVCCTL_STOPPED : SVCCTL_RUNNING;
}

/*******************************************************************
 Turn off sendfile if we find the underlying OS doesn't support it.
********************************************************************/

void set_use_sendfile(int snum, bool val)
{
	if (LP_SNUM_OK(snum))
		ServicePtrs[snum]->_use_sendfile = val;
	else
		sDefault._use_sendfile = val;
}

void lp_set_mangling_method(const char *new_method)
{
	lpcfg_string_set(Globals.ctx, &Globals.mangling_method, new_method);
}

/*******************************************************************
 Global state for POSIX pathname processing.
********************************************************************/

static bool posix_pathnames;

bool lp_posix_pathnames(void)
{
	return posix_pathnames;
}

/*******************************************************************
 Change everything needed to ensure POSIX pathname processing (currently
 not much).
********************************************************************/

void lp_set_posix_pathnames(void)
{
	posix_pathnames = true;
}

/*******************************************************************
 Global state for POSIX lock processing - CIFS unix extensions.
********************************************************************/

bool posix_default_lock_was_set;
static enum brl_flavour posix_cifsx_locktype; /* By default 0 == WINDOWS_LOCK */

enum brl_flavour lp_posix_cifsu_locktype(files_struct *fsp)
{
	if (posix_default_lock_was_set) {
		return posix_cifsx_locktype;
	} else {
		return (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) ?
			POSIX_LOCK : WINDOWS_LOCK;
	}
}

/*******************************************************************
********************************************************************/

void lp_set_posix_default_cifsx_readwrite_locktype(enum brl_flavour val)
{
	posix_default_lock_was_set = true;
	posix_cifsx_locktype = val;
}

int lp_min_receive_file_size(void)
{
	int min_receivefile_size = lp_min_receivefile_size();

	if (min_receivefile_size < 0) {
		return 0;
	}
	return min_receivefile_size;
}

/*******************************************************************
 Safe wide links checks.
 This helper function always verify the validity of wide links,
 even after a configuration file reload.
********************************************************************/

void widelinks_warning(int snum)
{
	if (lp_allow_insecure_wide_links()) {
		return;
	}

	if (lp_unix_extensions() && lp_wide_links(snum)) {
		DBG_ERR("Share '%s' has wide links and unix extensions enabled. "
			"These parameters are incompatible. "
			"Wide links will be disabled for this share.\n",
			 lp_const_servicename(snum));
	}
}

bool lp_widelinks(int snum)
{
	/* wide links is always incompatible with unix extensions */
	if (lp_unix_extensions()) {
		/*
		 * Unless we have "allow insecure widelinks"
		 * turned on.
		 */
		if (!lp_allow_insecure_wide_links()) {
			return false;
		}
	}

	return lp_wide_links(snum);
}

int lp_server_role(void)
{
	return lp_find_server_role(lp__server_role(),
				   lp__security(),
				   lp__domain_logons(),
				   lp_domain_master_true_or_auto());
}

int lp_security(void)
{
	return lp_find_security(lp__server_role(),
				lp__security());
}

int lp_client_max_protocol(void)
{
	int client_max_protocol = lp__client_max_protocol();
	if (client_max_protocol == PROTOCOL_DEFAULT) {
		return PROTOCOL_LATEST;
	}
	return client_max_protocol;
}

int lp_client_ipc_min_protocol(void)
{
	int client_ipc_min_protocol = lp__client_ipc_min_protocol();
	if (client_ipc_min_protocol == PROTOCOL_DEFAULT) {
		client_ipc_min_protocol = lp_client_min_protocol();
	}
	if (client_ipc_min_protocol < PROTOCOL_NT1) {
		return PROTOCOL_NT1;
	}
	return client_ipc_min_protocol;
}

int lp_client_ipc_max_protocol(void)
{
	int client_ipc_max_protocol = lp__client_ipc_max_protocol();
	if (client_ipc_max_protocol == PROTOCOL_DEFAULT) {
		return PROTOCOL_LATEST;
	}
	if (client_ipc_max_protocol < PROTOCOL_NT1) {
		return PROTOCOL_NT1;
	}
	return client_ipc_max_protocol;
}

int lp_client_ipc_signing(void)
{
	int client_ipc_signing = lp__client_ipc_signing();
	if (client_ipc_signing == SMB_SIGNING_DEFAULT) {
		return SMB_SIGNING_REQUIRED;
	}
	return client_ipc_signing;
}

int lp_rpc_low_port(void)
{
	return Globals.rpc_low_port;
}

int lp_rpc_high_port(void)
{
	return Globals.rpc_high_port;
}

/*
 * Do not allow LanMan auth if unless NTLMv1 is also allowed
 *
 * This also ensures it is disabled if NTLM is totally disabled
 */
bool lp_lanman_auth(void)
{
	enum ntlm_auth_level ntlm_auth_level = lp_ntlm_auth();

	if (ntlm_auth_level == NTLM_AUTH_ON) {
		return lp__lanman_auth();
	} else {
		return false;
	}
}

struct loadparm_global * get_globals(void)
{
	return &Globals;
}

unsigned int * get_flags(void)
{
	if (flags_list == NULL) {
		flags_list = talloc_zero_array(NULL, unsigned int, num_parameters());
	}

	return flags_list;
}

enum samba_weak_crypto lp_weak_crypto()
{
	if (Globals.weak_crypto == SAMBA_WEAK_CRYPTO_UNKNOWN) {
		Globals.weak_crypto = SAMBA_WEAK_CRYPTO_DISALLOWED;

		if (samba_gnutls_weak_crypto_allowed()) {
			Globals.weak_crypto = SAMBA_WEAK_CRYPTO_ALLOWED;
		}
	}

	return Globals.weak_crypto;
}
