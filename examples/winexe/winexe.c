/*
 * Samba Unix/Linux CIFS implementation
 *
 * winexe
 *
 * Copyright (C) 2018 Volker Lendecke <vl@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include <tevent.h>
#include <popt.h>
#include "version.h"
#include "lib/param/param.h"
#include "auth/credentials/credentials.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/sys_rw.h"
#include "libsmb/proto.h"
#include "librpc/gen_ndr/ndr_svcctl_c.h"
#include "rpc_client/cli_pipe.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/util/werror.h"
#include "lib/async_req/async_sock.h"
#include "client.h"

#define SVC_INTERACTIVE 1
#define SVC_IGNORE_INTERACTIVE 2
#define SVC_INTERACTIVE_MASK 3
#define SVC_FORCE_UPLOAD 4
#define SVC_OS64BIT 8
#define SVC_OSCHOOSE 16
#define SVC_UNINSTALL 32
#define SVC_SYSTEM 64

#define SERVICE_NAME "winexesvc"

#define PIPE_NAME "ahexec"
#define PIPE_NAME_IN "ahexec_stdin%08X"
#define PIPE_NAME_OUT "ahexec_stdout%08X"
#define PIPE_NAME_ERR "ahexec_stderr%08X"

static const char version_message_fmt[] = "winexe version %d.%d\n"
	"This program may be freely redistributed under the terms of the "
	"GNU GPLv3\n";

struct program_options {
	char *hostname;
	int port;
	char *cmd;
	struct cli_credentials *credentials;
	char *runas;
	char *runas_file;
	int flags;
};

static void parse_args(int argc, const char *argv[],
		       TALLOC_CTX *mem_ctx,
		       struct program_options *options,
		       struct loadparm_context *lp_ctx)
{
	poptContext pc;
	int opt, i;
	struct cli_credentials *cred;

	int argc_new;
	char **argv_new;

	int port = 445;
	char *port_str = NULL;

	int flag_interactive = SVC_IGNORE_INTERACTIVE;
	int flag_ostype = 2;
	int flag_reinstall = 0;
	int flag_uninstall = 0;
	int flag_help = 0;
	int flag_version = 0;
	int flag_nopass = 0;
	char *opt_user = NULL;
	char *opt_kerberos = NULL;
	char *opt_auth_file = NULL;
	char *opt_debuglevel = NULL;
	struct poptOption long_options[] = {
		{
			.longName = "help",
			.shortName = 'h',
			.argInfo = POPT_ARG_NONE,
			.arg = &flag_help,
			.val = 0,
			.descrip = "Display help message",
			.argDescrip = NULL,
		},{
			.longName = "version",
			.shortName = 'V',
			.argInfo = POPT_ARG_NONE,
			.arg = &flag_version,
			.val = 0,
			.descrip = "Display version number",
			.argDescrip = NULL,
		},{
			.longName = "user",
			.shortName = 'U',
			.argInfo = POPT_ARG_STRING,
			.arg = &opt_user,
			.val = 0,
			.descrip = "Set the network username",
			.argDescrip = "[DOMAIN/]USERNAME[%PASSWORD]",
		},{
			.longName = "authentication-file",
			.shortName = 'A',
			.argInfo = POPT_ARG_STRING,
			.arg = &opt_auth_file,
			.val = 0,
			.descrip = "Get the credentials from a file",
			.argDescrip = "FILE",
		},{
			.longName = "no-pass",
			.shortName = 'N',
			.argInfo = POPT_ARG_NONE,
			.arg = &flag_nopass,
			.val = 0,
			.descrip = "Do not ask for a password",
			.argDescrip = NULL
		},{
			.longName = "kerberos",
			.shortName = 'k',
			.argInfo = POPT_ARG_STRING,
			.arg = &opt_kerberos,
			.val = 0,
			.descrip = "Use Kerberos",
			.argDescrip = "[yes|no]",
		},{
			.longName = "debuglevel",
			.shortName = 'd',
			.argInfo = POPT_ARG_STRING,
			.arg = &opt_debuglevel,
			.val = 0,
			.descrip = "Set debug level",
			.argDescrip = "DEBUGLEVEL",
		},{
			.longName = "uninstall",
			.shortName = 0,
			.argInfo = POPT_ARG_NONE,
			.arg = &flag_uninstall,
			.val = 0,
			.descrip = "Uninstall winexe service after "
				   "remote execution",
			.argDescrip = NULL,
		},{
			.longName = "reinstall",
			.shortName = 0,
			.argInfo = POPT_ARG_NONE,
			.arg = &flag_reinstall,
			.val = 0,
			.descrip = "Reinstall winexe service before "
				   "remote execution",
			.argDescrip = NULL,
		},{
			.longName = "runas",
			.shortName = 0,
			.argInfo = POPT_ARG_STRING,
			.arg = &options->runas,
			.val = 0,
			.descrip = "Run as the given user (BEWARE: this "
				   "password is sent in cleartext over "
				   "the network!)",
			.argDescrip = "[DOMAIN\\]USERNAME%PASSWORD",
		},{
			.longName = "runas-file",
			.shortName = 0,
			.argInfo = POPT_ARG_STRING,
			.arg = &options->runas_file,
			.val = 0,
			.descrip = "Run as user options defined in a file",
			.argDescrip = "FILE",
		},{
			.longName = "interactive",
			.shortName = 0,
			.argInfo = POPT_ARG_INT,
			.arg = &flag_interactive,
			.val = 0,
			.descrip = "Desktop interaction: 0 - disallow, "
				   "1 - allow. If allow, also use the "
				   "--system switch (Windows requirement). "
				   "Vista does not support this option.",
			.argDescrip = "0|1",
		},{
			.longName = "ostype",
			.shortName = 0,
			.argInfo = POPT_ARG_INT,
			.arg = &flag_ostype,
			.val = 0,
			.descrip = "OS type: 0 - 32-bit, 1 - 64-bit, "
				   "2 - winexe will decide. "
				   "Determines which version (32-bit or 64-bit)"
				   " of service will be installed.",
			.argDescrip = "0|1|2",
		},
		POPT_TABLEEND
	};

	ZERO_STRUCTP(options);

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,
			    0);

	poptSetOtherOptionHelp(pc, "[OPTION]... //HOST[:PORT] COMMAND\nOptions:");

	if (((opt = poptGetNextOpt(pc)) != -1) || flag_help || flag_version) {
		fprintf(stderr, version_message_fmt, SAMBA_VERSION_MAJOR,
			SAMBA_VERSION_MINOR);
		if (flag_version) {
			exit(0);
		}
		poptPrintHelp(pc, stdout, 0);
		if (flag_help) {
			exit(0);
		}
		exit(1);
	}

	argv_new = discard_const_p(char *, poptGetArgs(pc));

	argc_new = argc;
	for (i = 0; i < argc; i++) {
		if (!argv_new || argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (argc_new != 2 || argv_new[0][0] != '/' || argv_new[0][1] != '/') {
		fprintf(stderr, version_message_fmt, SAMBA_VERSION_MAJOR,
			SAMBA_VERSION_MINOR);
		poptPrintHelp(pc, stdout, 0);
		exit(1);
	}

	port_str = strchr(argv_new[0], ':');
	if (port_str) {
		if (sscanf(port_str + 1, "%d", &port) != 1 || port <= 0) {
			fprintf(stderr, version_message_fmt,
				SAMBA_VERSION_MAJOR, SAMBA_VERSION_MINOR);
			poptPrintHelp(pc, stdout, 0);
			exit(1);
		}
		*port_str = '\0';
	}

	if (opt_debuglevel) {
		lp_set_cmdline("log level", opt_debuglevel);
	}

	cred = cli_credentials_init(mem_ctx);

	if (opt_user) {
		cli_credentials_parse_string(cred, opt_user, CRED_SPECIFIED);
	} else if (opt_auth_file) {
		cli_credentials_parse_file(cred, opt_auth_file,
					   CRED_SPECIFIED);
	}

	cli_credentials_guess(cred, lp_ctx);
	if (!cli_credentials_get_password(cred) && !flag_nopass) {
		char *p = getpass("Enter password: ");
		if (*p) {
			cli_credentials_set_password(cred, p, CRED_SPECIFIED);
		}
	}

	if (opt_kerberos) {
		cli_credentials_set_kerberos_state(cred,
		                                   strcmp(opt_kerberos, "yes")
		                                   ? CRED_MUST_USE_KERBEROS
		                                   : CRED_DONT_USE_KERBEROS);
	}

	if (options->runas == NULL && options->runas_file != NULL) {
		struct cli_credentials *runas_cred;
		const char *user;
		const char *pass;

		runas_cred = cli_credentials_init(mem_ctx);
		cli_credentials_parse_file(runas_cred, options->runas_file,
					   CRED_SPECIFIED);

		user = cli_credentials_get_username(runas_cred);
		pass = cli_credentials_get_password(runas_cred);

		if (user && pass) {
			char buffer[1024];
			const char *dom;

			dom = cli_credentials_get_domain(runas_cred);
			if (dom) {
				snprintf(buffer, sizeof(buffer), "%s\\%s%%%s",
					 dom, user, pass);
			} else {
				snprintf(buffer, sizeof(buffer), "%s%%%s",
					 user, pass);
			}
			buffer[sizeof(buffer)-1] = '\0';
			options->runas = talloc_strdup(mem_ctx, buffer);
		}
	}

	options->credentials = cred;

	options->hostname = argv_new[0] + 2;
	options->port = port;
	options->cmd = argv_new[1];

	options->flags = flag_interactive;
	if (flag_reinstall) {
		options->flags |= SVC_FORCE_UPLOAD;
	}
	if (flag_ostype == 1) {
		options->flags |= SVC_OS64BIT;
	}
	if (flag_ostype == 2) {
		options->flags |= SVC_OSCHOOSE;
	}
	if (flag_uninstall) {
		options->flags |= SVC_UNINSTALL;
	}
}

static NTSTATUS winexe_svc_upload(
	const char *hostname,
	int port,
	const char *service_filename,
	const DATA_BLOB *svc32_exe,
	const DATA_BLOB *svc64_exe,
	struct cli_credentials *credentials,
	int flags)
{
	struct cli_state *cli;
	uint16_t fnum;
	NTSTATUS status;
	const DATA_BLOB *binary = NULL;

	status = cli_full_connection_creds(
		&cli,
		NULL,
		hostname,
		NULL,
		port,
		"ADMIN$",
		"?????",
		credentials,
		0,
		0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("cli_full_connection_creds failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	if (flags & SVC_FORCE_UPLOAD) {
		status = cli_unlink(cli, service_filename, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("cli_unlink failed: %s\n",
				    nt_errstr(status));
		}
	}

	if (flags & SVC_OSCHOOSE) {
		status = cli_chkpath(cli, "SysWoW64");
		if (NT_STATUS_IS_OK(status)) {
			flags |= SVC_OS64BIT;
		}
	}

	if (flags & SVC_OS64BIT) {
		binary = svc64_exe;
	} else {
		binary = svc32_exe;
	}

	if (binary == NULL) {
		//TODO
	}

	status = cli_ntcreate(
		cli,
		service_filename,
		0,			/* CreatFlags */
		SEC_FILE_WRITE_DATA,    /* DesiredAccess */
		FILE_ATTRIBUTE_NORMAL,  /* FileAttributes */
		FILE_SHARE_WRITE|FILE_SHARE_READ, /* ShareAccess */
		FILE_OPEN_IF,		 /* CreateDisposition */
		FILE_NON_DIRECTORY_FILE, /* CreateOptions */
		0,			 /* SecurityFlags */
		&fnum,
		NULL);		/* CreateReturns */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Could not create %s: %s\n", service_filename,
			    nt_errstr(status));
		goto done;
	}

	status = cli_writeall(
		cli,
		fnum,
		0,
		binary->data,
		0,
		binary->length,
		NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Could not write file: %s\n", nt_errstr(status));
		goto close_done;
	}

close_done:
	status = cli_close(cli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Close(%"PRIu16") failed for %s: %s\n", fnum,
			    service_filename, nt_errstr(status));
	}
done:
	TALLOC_FREE(cli);
	return status;
}

static NTSTATUS winexe_svc_install(
	struct cli_state *cli,
	const char *hostname,
	int port,
	const char *service_name,
	const char *service_filename,
	const DATA_BLOB *svc32_exe,
	const DATA_BLOB *svc64_exe,
	struct cli_credentials *credentials,
	int flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *rpccli;
	struct policy_handle scmanager_handle;
	struct policy_handle service_handle;
	struct SERVICE_STATUS service_status;
	bool need_start = false;
	bool need_conf = false;
	NTSTATUS status;
	WERROR werr;

	status = cli_rpc_pipe_open_noauth_transport(
		cli,
		NCACN_NP,
		&ndr_table_svcctl,
		&rpccli);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("cli_rpc_pipe_open_noauth_transport failed: %s\n",
			    nt_errstr(status));
		goto done;
	}

	status = dcerpc_svcctl_OpenSCManagerW(
		rpccli->binding_handle,
		frame,
		smbXcli_conn_remote_name(cli->conn),
		NULL,
		SEC_FLAG_MAXIMUM_ALLOWED,
		&scmanager_handle,
		&werr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_OpenSCManagerW failed: %s\n",
			    nt_errstr(status));
		goto done;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("dcerpc_svcctl_OpenSCManagerW failed: %s\n",
			    win_errstr(werr));
		goto done;
	}

	status = dcerpc_svcctl_OpenServiceW(
		rpccli->binding_handle,
		frame,
		&scmanager_handle,
		service_name,
		SERVICE_ALL_ACCESS,
		&service_handle,
		&werr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_OpenServiceW failed: %s\n",
			    nt_errstr(status));
		goto close_scmanager;
	}

	if (W_ERROR_EQUAL(werr,  WERR_SERVICE_DOES_NOT_EXIST)) {
		status = dcerpc_svcctl_CreateServiceW(
			rpccli->binding_handle,
			frame,
			&scmanager_handle,
			service_name,
			NULL,
			SERVICE_ALL_ACCESS,
			SERVICE_TYPE_WIN32_OWN_PROCESS |
			((flags & SVC_INTERACTIVE) ?
			 SERVICE_TYPE_INTERACTIVE_PROCESS : 0),
			SVCCTL_DEMAND_START,
			SVCCTL_SVC_ERROR_NORMAL,
			service_filename,
			NULL,
			NULL,
			NULL,
			0,
			NULL,
			NULL,
			0,
			&service_handle,
			&werr);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dcerpc_svcctl_CreateServiceW "
				    "failed: %s\n", nt_errstr(status));
			goto close_scmanager;
		}
		if (!W_ERROR_IS_OK(werr)) {
			DBG_WARNING("dcerpc_svcctl_CreateServiceW "
				    "failed: %s\n", win_errstr(werr));
			status = werror_to_ntstatus(werr);
			goto close_scmanager;
		}
	}

	status = dcerpc_svcctl_QueryServiceStatus(
		rpccli->binding_handle,
		frame,
		&service_handle,
		&service_status,
		&werr);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
			    "failed: %s\n", nt_errstr(status));
		goto close_service;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
			    "failed: %s\n", win_errstr(werr));
		status = werror_to_ntstatus(werr);
		goto close_service;
	}

	if (!(flags & SVC_IGNORE_INTERACTIVE)) {
		need_conf =
			!(service_status.type &
			  SERVICE_TYPE_INTERACTIVE_PROCESS) ^
			!(flags & SVC_INTERACTIVE);
	}

	if (service_status.state == SVCCTL_STOPPED) {
		need_start = true;
	} else if (need_conf) {
		status = dcerpc_svcctl_ControlService(
			rpccli->binding_handle,
			frame,
			&service_handle,
			SVCCTL_CONTROL_STOP,
			&service_status,
			&werr);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dcerpc_svcctl_ControlServiceStatus "
			    "failed: %s\n", nt_errstr(status));
			goto close_service;
		}
		if (!W_ERROR_IS_OK(werr)) {
			DBG_WARNING("dcerpc_svcctl_ControlServiceStatus "
				    "failed: %s\n", win_errstr(werr));
			status = werror_to_ntstatus(werr);
			goto close_service;
		}

		do {
			smb_msleep(100);

			status = dcerpc_svcctl_QueryServiceStatus(
				rpccli->binding_handle,
				frame,
				&service_handle,
				&service_status,
				&werr);

			if (!NT_STATUS_IS_OK(status)) {
				DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
					    "failed: %s\n", nt_errstr(status));
				goto close_service;
			}
			if (!W_ERROR_IS_OK(werr)) {
				DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
					    "failed: %s\n", win_errstr(werr));
				status = werror_to_ntstatus(werr);
				goto close_service;
			}
		} while (service_status.state == SVCCTL_STOP_PENDING);

		need_start = 1;
	}

	if (need_conf) {
		status = dcerpc_svcctl_ChangeServiceConfigW(
			rpccli->binding_handle,
			frame,
			&service_handle,
			SERVICE_TYPE_WIN32_OWN_PROCESS |
			((flags & SVC_INTERACTIVE) ?
			 SERVICE_TYPE_INTERACTIVE_PROCESS : 0), /* type */
			UINT32_MAX, /* start_type, SERVICE_NO_CHANGE */
			UINT32_MAX, /* error_control, SERVICE_NO_CHANGE */
			NULL,	    /* binary_path */
			NULL,	    /* load_order_group */
			NULL,	    /* tag_id */
			NULL,	    /* dependencies */
			0,	    /* dwDependSize */
			NULL,	    /* service_start_name */
			NULL,	    /* password */
			0,	    /* dwPwSize */
			NULL,	    /* display_name */
			&werr);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dcerpc_svcctl_ChangeServiceConfigW "
				    "failed: %s\n", nt_errstr(status));
			goto close_service;
		}
		if (!W_ERROR_IS_OK(werr)) {
			DBG_WARNING("dcerpc_svcctl_ChangeServiceConfigW "
				    "failed: %s\n", win_errstr(werr));
			status = werror_to_ntstatus(werr);
			goto close_service;
		}
	}

	if (need_start) {
		status = winexe_svc_upload(
			hostname,
			port,
			service_filename,
			svc32_exe,
			svc64_exe,
			credentials,
			flags);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("winexe_svc_upload failed: %s\n",
				    nt_errstr(status));
			goto close_service;
		}

		status = dcerpc_svcctl_StartServiceW(
			rpccli->binding_handle,
			frame,
			&service_handle,
			0,	/* num_args */
			NULL,	/* arguments */
			&werr);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dcerpc_svcctl_StartServiceW "
				    "failed: %s\n", nt_errstr(status));
			goto close_service;
		}
		if (!W_ERROR_IS_OK(werr)) {
			DBG_WARNING("dcerpc_svcctl_StartServiceW "
				    "failed: %s\n", win_errstr(werr));
			status = werror_to_ntstatus(werr);
			goto close_service;
		}

		do {
			smb_msleep(100);

			status = dcerpc_svcctl_QueryServiceStatus(
				rpccli->binding_handle,
				frame,
				&service_handle,
				&service_status,
				&werr);

			if (!NT_STATUS_IS_OK(status)) {
				DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
					    "failed: %s\n", nt_errstr(status));
				goto close_service;
			}
			if (!W_ERROR_IS_OK(werr)) {
				DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
					    "failed: %s\n", win_errstr(werr));
				status = werror_to_ntstatus(werr);
				goto close_service;
			}
		} while (service_status.state == SVCCTL_START_PENDING);

		if (service_status.state != SVCCTL_RUNNING) {
			DBG_WARNING("Failed to start service\n");
			status = NT_STATUS_UNSUCCESSFUL;
			goto close_service;
		}
	}

close_service:
	{
		NTSTATUS close_status;
		WERROR close_werr;

		close_status = dcerpc_svcctl_CloseServiceHandle(
			rpccli->binding_handle,
			frame,
			&service_handle,
			&close_werr);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    "failed: %s\n", nt_errstr(close_status));
			goto done;
		}
		if (!W_ERROR_IS_OK(close_werr)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    " failed: %s\n", win_errstr(close_werr));
			goto done;
		}
	}

close_scmanager:
	{
		NTSTATUS close_status;
		WERROR close_werr;

		close_status = dcerpc_svcctl_CloseServiceHandle(
			rpccli->binding_handle,
			frame,
			&scmanager_handle,
			&close_werr);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    "failed: %s\n", nt_errstr(close_status));
			goto done;
		}
		if (!W_ERROR_IS_OK(close_werr)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    " failed: %s\n", win_errstr(close_werr));
			goto done;
		}
	}

done:
	TALLOC_FREE(rpccli);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS winexe_svc_uninstall(
	struct cli_state *cli,
	const char *service_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *rpccli;
	struct policy_handle scmanager_handle;
	struct policy_handle service_handle;
	struct SERVICE_STATUS service_status;
	NTSTATUS status;
	WERROR werr;

	status = cli_rpc_pipe_open_noauth_transport(
		cli,
		NCACN_NP,
		&ndr_table_svcctl,
		&rpccli);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("cli_rpc_pipe_open_noauth_transport failed: %s\n",
			    nt_errstr(status));
		goto done;
	}

	status = dcerpc_svcctl_OpenSCManagerW(
		rpccli->binding_handle,
		frame,
		smbXcli_conn_remote_name(cli->conn),
		NULL,
		SEC_FLAG_MAXIMUM_ALLOWED,
		&scmanager_handle,
		&werr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_OpenSCManagerW failed: %s\n",
			    nt_errstr(status));
		goto done;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("dcerpc_svcctl_OpenSCManagerW failed: %s\n",
			    win_errstr(werr));
		goto done;
	}

	status = dcerpc_svcctl_OpenServiceW(
		rpccli->binding_handle,
		frame,
		&scmanager_handle,
		service_name,
		SERVICE_ALL_ACCESS,
		&service_handle,
		&werr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_OpenServiceW failed: %s\n",
			    nt_errstr(status));
		goto close_scmanager;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("dcerpc_svcctl_OpenServiceW failed: %s\n",
			    win_errstr(werr));
		status = werror_to_ntstatus(werr);
		goto close_scmanager;
	}

	status = dcerpc_svcctl_ControlService(
		rpccli->binding_handle,
		frame,
		&service_handle,
		SVCCTL_CONTROL_STOP,
		&service_status,
		&werr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_ControlServiceStatus "
			    "failed: %s\n", nt_errstr(status));
		goto close_service;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("dcerpc_svcctl_ControlServiceStatus "
			    "failed: %s\n", win_errstr(werr));
		status = werror_to_ntstatus(werr);
		goto close_service;
	}

	do {
		smb_msleep(100);

		status = dcerpc_svcctl_QueryServiceStatus(
			rpccli->binding_handle,
			frame,
			&service_handle,
			&service_status,
			&werr);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
				    "failed: %s\n", nt_errstr(status));
			goto close_service;
		}
		if (!W_ERROR_IS_OK(werr)) {
			DBG_WARNING("dcerpc_svcctl_QueryServiceStatus "
				    "failed: %s\n", win_errstr(werr));
			status = werror_to_ntstatus(werr);
			goto close_service;
		}
	} while (service_status.state != SVCCTL_STOPPED);

	status = dcerpc_svcctl_DeleteService(
		rpccli->binding_handle,
		frame,
		&service_handle,
		&werr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dcerpc_svcctl_DeleteService "
			    "failed: %s\n", nt_errstr(status));
		goto close_service;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("dcerpc_svcctl_DeleteService "
			    "failed: %s\n", win_errstr(werr));
		status = werror_to_ntstatus(werr);
		goto close_service;
	}

close_service:
	{
		NTSTATUS close_status;
		WERROR close_werr;

		close_status = dcerpc_svcctl_CloseServiceHandle(
			rpccli->binding_handle,
			frame,
			&service_handle,
			&close_werr);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    "failed: %s\n", nt_errstr(close_status));
			goto done;
		}
		if (!W_ERROR_IS_OK(close_werr)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    " failed: %s\n", win_errstr(close_werr));
			goto done;
		}
	}

close_scmanager:
	{
		NTSTATUS close_status;
		WERROR close_werr;

		close_status = dcerpc_svcctl_CloseServiceHandle(
			rpccli->binding_handle,
			frame,
			&scmanager_handle,
			&close_werr);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    "failed: %s\n", nt_errstr(close_status));
			goto done;
		}
		if (!W_ERROR_IS_OK(close_werr)) {
			DBG_WARNING("dcerpc_svcctl_CloseServiceHandle "
				    " failed: %s\n", win_errstr(close_werr));
			goto done;
		}
	}

done:
	TALLOC_FREE(rpccli);
	TALLOC_FREE(frame);
	return status;
}

struct winexe_out_pipe_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t out_pipe;
	int out_fd;
	char out_inbuf[256];
};

static void winexe_out_pipe_opened(struct tevent_req *subreq);
static void winexe_out_pipe_got_data(struct tevent_req *subreq);
static void winexe_out_pipe_closed(struct tevent_req *subreq);

static struct tevent_req *winexe_out_pipe_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *pipe_name,
	int out_fd)
{
	struct tevent_req *req, *subreq;
	struct winexe_out_pipe_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winexe_out_pipe_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->out_fd = out_fd;

	subreq = cli_ntcreate_send(
		state,
		state->ev,
		state->cli,
		pipe_name,
		0,
		SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE|
		SEC_RIGHTS_FILE_EXECUTE,
		0,		/* FileAttributes */
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,	/* CreateDisposition */
		0,		/* CreateOptions */
		SMB2_IMPERSONATION_IMPERSONATION,
		0);		/* SecurityFlags */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winexe_out_pipe_opened, req);
	return req;
}

static void winexe_out_pipe_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_out_pipe_state *state = tevent_req_data(
		req, struct winexe_out_pipe_state);
	int timeout;
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->out_pipe, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	timeout = state->cli->timeout;
	state->cli->timeout = 0;

	subreq = cli_read_send(
		state,
		state->ev,
		state->cli,
		state->out_pipe,
		state->out_inbuf,
		0,
		sizeof(state->out_inbuf));

	state->cli->timeout = timeout;

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_out_pipe_got_data, req);
}

static void winexe_out_pipe_got_data(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_out_pipe_state *state = tevent_req_data(
		req, struct winexe_out_pipe_state);
	NTSTATUS status;
	int timeout;
	size_t received;
	ssize_t written;

	status = cli_read_recv(subreq, &received);
	TALLOC_FREE(subreq);

	DBG_DEBUG("cli_read for %d gave %s\n",
		  state->out_fd,
		  nt_errstr(status));

	if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_DISCONNECTED)) {
		subreq = cli_close_send(
			state,
			state->ev,
			state->cli,
			state->out_pipe);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, winexe_out_pipe_closed, req);
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (received > 0) {
		written = sys_write(state->out_fd, state->out_inbuf, received);
		if (written == -1) {
			tevent_req_nterror(req, map_nt_error_from_unix(errno));
			return;
		}
	}

	timeout = state->cli->timeout;
	state->cli->timeout = 0;

	subreq = cli_read_send(
		state,
		state->ev,
		state->cli,
		state->out_pipe,
		state->out_inbuf,
		0,
		sizeof(state->out_inbuf));

	state->cli->timeout = timeout;

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_out_pipe_got_data, req);
}

static void winexe_out_pipe_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS winexe_out_pipe_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct winexe_in_pipe_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct tevent_req *fd_read_req;
	bool close_requested;
	bool closing;
	uint16_t in_pipe;
	int in_fd;
	char inbuf[256];
};

static void winexe_in_pipe_opened(struct tevent_req *subreq);
static void winexe_in_pipe_got_data(struct tevent_req *subreq);
static void winexe_in_pipe_written(struct tevent_req *subreq);
static void winexe_in_pipe_closed(struct tevent_req *subreq);

static struct tevent_req *winexe_in_pipe_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *pipe_name,
	int in_fd)
{
	struct tevent_req *req, *subreq;
	struct winexe_in_pipe_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winexe_in_pipe_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->in_fd = in_fd;

	subreq = cli_ntcreate_send(
		state,
		state->ev,
		state->cli,
		pipe_name,
		0,
		SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE|
		SEC_RIGHTS_FILE_EXECUTE,
		0,		/* FileAttributes */
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,	/* CreateDisposition */
		0,		/* CreateOptions */
		SMB2_IMPERSONATION_IMPERSONATION,
		0);		/* SecurityFlags */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winexe_in_pipe_opened, req);
	return req;
}

static void winexe_in_pipe_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_in_pipe_state *state = tevent_req_data(
		req, struct winexe_in_pipe_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->in_pipe, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = wait_for_read_send(
		state,
		state->ev,
		state->in_fd,
		true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_in_pipe_got_data, req);

	state->fd_read_req = subreq;
}

static void winexe_in_pipe_got_data(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_in_pipe_state *state = tevent_req_data(
		req, struct winexe_in_pipe_state);
	int err;
	bool ok;
	int timeout;
	ssize_t nread;

	ok = wait_for_read_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	state->fd_read_req = NULL;

	nread = sys_read(state->in_fd, &state->inbuf, sizeof(state->inbuf));
	if (nread == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return;
	}
	if (nread == 0) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return;
	}

	timeout = state->cli->timeout;
	state->cli->timeout = 0;

	subreq = cli_writeall_send(
		state,
		state->ev,
		state->cli,
		state->in_pipe,
		0,
		(uint8_t *)state->inbuf,
		0,
		nread);

	state->cli->timeout = timeout;

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_in_pipe_written, req);
}

static void winexe_in_pipe_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_in_pipe_state *state = tevent_req_data(
		req, struct winexe_in_pipe_state);
	NTSTATUS status;

	status = cli_writeall_recv(subreq, NULL);
	TALLOC_FREE(subreq);

	DBG_DEBUG("cli_writeall for %d gave %s\n",
		  state->in_fd,
		  nt_errstr(status));

	if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_DISCONNECTED) ||
	    state->close_requested) {
		subreq = cli_close_send(
			state,
			state->ev,
			state->cli,
			state->in_pipe);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, winexe_in_pipe_closed, req);
		state->closing = true;
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = wait_for_read_send(
		state,
		state->ev,
		state->in_fd,
		true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_in_pipe_got_data, req);

	state->fd_read_req = subreq;
}

static void winexe_in_pipe_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	return tevent_req_done(req);
}

static NTSTATUS winexe_in_pipe_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static bool winexe_in_pipe_close(struct tevent_req *req)
{
	struct winexe_in_pipe_state *state = tevent_req_data(
		req, struct winexe_in_pipe_state);
	struct tevent_req *subreq;

	if (state->closing) {
		return true;
	}

	if (state->fd_read_req == NULL) {
		/*
		 * cli_writeall active, wait for it to return
		 */
		state->close_requested = true;
		return true;
	}

	TALLOC_FREE(state->fd_read_req);

	subreq = cli_close_send(
		state,
		state->ev,
		state->cli,
		state->in_pipe);
	if (subreq == NULL) {
		return false;
	}
	tevent_req_set_callback(subreq, winexe_in_pipe_closed, req);
	state->closing = true;

	return true;
}

struct winexe_pipes_state {
	struct tevent_req *pipes[3];
};

static void winexe_pipes_stdin_done(struct tevent_req *subreq);
static void winexe_pipes_stdout_done(struct tevent_req *subreq);
static void winexe_pipes_stderr_done(struct tevent_req *subreq);

static struct tevent_req *winexe_pipes_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *pipe_postfix)
{
	struct tevent_req *req;
	struct winexe_pipes_state *state;
	char *pipe_name;

	req = tevent_req_create(mem_ctx, &state, struct winexe_pipes_state);
	if (req == NULL) {
		return NULL;
	}

	pipe_name = talloc_asprintf(state, "\\ahexec_stdin%s", pipe_postfix);
	if (tevent_req_nomem(pipe_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->pipes[0] = winexe_in_pipe_send(
		state,
		ev,
		cli,
		pipe_name,
		0);
	if (tevent_req_nomem(state->pipes[0], req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->pipes[0], winexe_pipes_stdin_done, req);

	pipe_name = talloc_asprintf(state, "\\ahexec_stdout%s", pipe_postfix);
	if (tevent_req_nomem(pipe_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->pipes[1] = winexe_out_pipe_send(
		state,
		ev,
		cli,
		pipe_name,
		1);
	if (tevent_req_nomem(state->pipes[1], req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->pipes[1], winexe_pipes_stdout_done,
				req);

	pipe_name = talloc_asprintf(state, "\\ahexec_stderr%s", pipe_postfix);
	if (tevent_req_nomem(pipe_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->pipes[2] = winexe_out_pipe_send(
		state,
		ev,
		cli,
		pipe_name,
		2);
	if (tevent_req_nomem(state->pipes[2], req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->pipes[2], winexe_pipes_stderr_done,
				req);

	DBG_DEBUG("pipes = %p %p %p\n",
		  state->pipes[0],
		  state->pipes[1],
		  state->pipes[2]);

	return req;
}

static void winexe_pipes_stdin_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_pipes_state *state = tevent_req_data(
		req, struct winexe_pipes_state);
	NTSTATUS status;

	status = winexe_in_pipe_recv(subreq);
	TALLOC_FREE(subreq);

	DBG_DEBUG("stdin returned %s\n", nt_errstr(status));

	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->pipes[0] = NULL;

	DBG_DEBUG("pipes = %p %p %p\n",
		  state->pipes[0],
		  state->pipes[1],
		  state->pipes[2]);

	if ((state->pipes[1] == NULL) && (state->pipes[2] == NULL)) {
		tevent_req_done(req);
	}
}

static void winexe_pipes_stdout_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_pipes_state *state = tevent_req_data(
		req, struct winexe_pipes_state);
	NTSTATUS status;

	status = winexe_out_pipe_recv(subreq);
	TALLOC_FREE(subreq);

	DBG_DEBUG("stdout returned %s\n", nt_errstr(status));

	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->pipes[0] != NULL) {
		winexe_in_pipe_close(state->pipes[0]);
	}

	state->pipes[1] = NULL;

	DBG_DEBUG("pipes = %p %p %p\n",
		  state->pipes[0],
		  state->pipes[1],
		  state->pipes[2]);

	if ((state->pipes[0] == NULL) && (state->pipes[2] == NULL)) {
		tevent_req_done(req);
	}
}

static void winexe_pipes_stderr_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_pipes_state *state = tevent_req_data(
		req, struct winexe_pipes_state);
	NTSTATUS status;

	status = winexe_out_pipe_recv(subreq);
	TALLOC_FREE(subreq);

	DBG_DEBUG("stderr returned %s\n", nt_errstr(status));

	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->pipes[0] != NULL) {
		winexe_in_pipe_close(state->pipes[0]);
	}

	state->pipes[2] = NULL;

	DBG_DEBUG("pipes = %p %p %p\n",
		  state->pipes[0],
		  state->pipes[1],
		  state->pipes[2]);

	if ((state->pipes[0] == NULL) && (state->pipes[1] == NULL)) {
		tevent_req_done(req);
	}
}

static NTSTATUS winexe_pipes_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct winexe_ctrl_state {
	struct tevent_context *ev;
	struct cli_state *cli;

	uint16_t ctrl_pipe;
	bool ctrl_pipe_done;

	char ctrl_inbuf[256];
	char *cmd;
	int return_code;

	struct tevent_req *pipes_req;
};

static void winexe_ctrl_opened(struct tevent_req *subreq);
static void winexe_ctrl_got_read(struct tevent_req *subreq);
static void winexe_ctrl_wrote_version(struct tevent_req *subreq);
static void winexe_ctrl_wrote_cmd(struct tevent_req *subreq);
static void winexe_ctrl_pipes_done(struct tevent_req *subreq);
static void winexe_ctrl_pipe_closed(struct tevent_req *subreq);

static struct tevent_req *winexe_ctrl_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *cmd)
{
	struct tevent_req *req, *subreq;
	struct winexe_ctrl_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winexe_ctrl_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	state->cmd = talloc_asprintf(state, "run %s\n", cmd);
	if (tevent_req_nomem(state->cmd, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_ntcreate_send(
		state,
		state->ev,
		state->cli,
		"\\" PIPE_NAME,
		0,
		SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE|
		SEC_RIGHTS_FILE_EXECUTE,
		0,		/* FileAttributes */
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,	/* CreateDisposition */
		0,		/* CreateOptions */
		SMB2_IMPERSONATION_IMPERSONATION,
		0);		/* SecurityFlags */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winexe_ctrl_opened, req);
	return req;
}

static void winexe_ctrl_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_ctrl_state *state = tevent_req_data(
		req, struct winexe_ctrl_state);
	int timeout;
	NTSTATUS status;
	static const char cmd[] = "get codepage\nget version\n";

	status = cli_ntcreate_recv(subreq, &state->ctrl_pipe, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	timeout = state->cli->timeout;
	state->cli->timeout = 0;

	subreq = cli_read_send(
		state,
		state->ev,
		state->cli,
		state->ctrl_pipe,
		state->ctrl_inbuf,
		0,
		sizeof(state->ctrl_inbuf)-1);

	state->cli->timeout = timeout;

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_ctrl_got_read, req);

	subreq = cli_writeall_send(
		state,
		state->ev,
		state->cli,
		state->ctrl_pipe,
		0,
		(const uint8_t *)cmd,
		0,
		strlen(cmd));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_ctrl_wrote_version, req);
}

static void winexe_ctrl_got_read(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_ctrl_state *state = tevent_req_data(
		req, struct winexe_ctrl_state);
	NTSTATUS status;
	int timeout;
	size_t received;
	unsigned int version, return_code;
	int ret;

	status = cli_read_recv(subreq, &received);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_DISCONNECTED)) {
		subreq = cli_close_send(
			state,
			state->ev,
			state->cli,
			state->ctrl_pipe);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, winexe_ctrl_pipe_closed, req);
		return;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	DBG_DEBUG("Got %zu bytes\n", received);

	timeout = state->cli->timeout;
	state->cli->timeout = 0;

	subreq = cli_read_send(
		state,
		state->ev,
		state->cli,
		state->ctrl_pipe,
		state->ctrl_inbuf,
		0,
		sizeof(state->ctrl_inbuf)-1);

	state->cli->timeout = timeout;

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winexe_ctrl_got_read, req);

	ret = sscanf(state->ctrl_inbuf, "version 0x%x\n", &version);
	if (ret == 1) {
		DBG_DEBUG("Got version %x\n", version);

		subreq = cli_writeall_send(
			state,
			state->ev,
			state->cli,
			state->ctrl_pipe,
			0,
			(const uint8_t *)state->cmd,
			0,
			strlen(state->cmd));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, winexe_ctrl_wrote_cmd, req);
		return;
	}

	ret = strncmp(state->ctrl_inbuf, "std_io_err ", strlen("std_io_err "));
	if (ret == 0) {
		char *p = state->ctrl_inbuf + 11;
		char *q = strchr(state->ctrl_inbuf, '\n');
		char *postfix;
		size_t postfix_len;

		if (q == NULL) {
			DBG_DEBUG("Got invalid pipe postfix\n");
			return;
		}

		postfix_len = q - p;

		postfix = talloc_strndup(state, p, postfix_len);
		if (tevent_req_nomem(postfix, req)) {
			return;
		}

		DBG_DEBUG("Got pipe postfix %s\n", postfix);

		subreq = winexe_pipes_send(
			state,
			state->ev,
			state->cli,
			postfix);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, winexe_ctrl_pipes_done, req);

		state->pipes_req = subreq;

		return;
	}

	ret = strncmp(state->ctrl_inbuf, "error ", strlen("error "));
	if (ret == 0) {
		printf("Error: %s", state->ctrl_inbuf);
		return;
	}

	ret = sscanf(state->ctrl_inbuf, "version 0x%x\n", &return_code);
	if (ret == 1) {
		state->return_code = return_code;
		return;
	}
}

static void winexe_ctrl_wrote_version(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_writeall_recv(subreq, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static void winexe_ctrl_wrote_cmd(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_writeall_recv(subreq, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static void winexe_ctrl_pipe_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_ctrl_state *state = tevent_req_data(
		req, struct winexe_ctrl_state);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->ctrl_pipe_done = true;
	if (state->pipes_req == NULL) {
		tevent_req_done(req);
	}
}

static void winexe_ctrl_pipes_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winexe_ctrl_state *state = tevent_req_data(
		req, struct winexe_ctrl_state);
	NTSTATUS status;

	status = winexe_pipes_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->pipes_req = NULL;
	if (state->ctrl_pipe_done) {
		tevent_req_done(req);
	}
}

static NTSTATUS winexe_ctrl_recv(struct tevent_req *req,
				 int *preturn_code)
{
	struct winexe_ctrl_state *state = tevent_req_data(
		req, struct winexe_ctrl_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (preturn_code != NULL) {
		*preturn_code = state->return_code;
	}
	return NT_STATUS_OK;
}

static NTSTATUS winexe_ctrl(struct cli_state *cli,
			    const char *cmd,
			    int *preturn_code)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool ok;

	ev = samba_tevent_context_init(cli);
	if (ev == NULL) {
		goto done;
	}
	req = winexe_ctrl_send(ev, ev, cli, cmd);
	if (req == NULL) {
		goto done;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto done;
	}
	status = winexe_ctrl_recv(req, preturn_code);
done:
	TALLOC_FREE(req);
	TALLOC_FREE(ev);
	return status;
}

#ifdef HAVE_WINEXE_CC_WIN32
const DATA_BLOB *winexesvc32_exe_binary(void);
#endif

#ifdef HAVE_WINEXE_CC_WIN64
const DATA_BLOB *winexesvc64_exe_binary(void);
#endif

int main(int argc, const char *argv[])
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct program_options options = {0};
	struct loadparm_context *lp_ctx;
	struct cli_state *cli;
	const char *service_name = SERVICE_NAME;
	char *service_filename = NULL;
#ifdef HAVE_WINEXE_CC_WIN32
	const DATA_BLOB *winexesvc32_exe = winexesvc32_exe_binary();
#else
	const DATA_BLOB *winexesvc32_exe = NULL;
#endif
#ifdef HAVE_WINEXE_CC_WIN64
	const DATA_BLOB *winexesvc64_exe = winexesvc64_exe_binary();
#else
	const DATA_BLOB *winexesvc64_exe = NULL;
#endif
	NTSTATUS status;
	int ret = 1;
	int return_code = 0;

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		fprintf(stderr, "loadparm_init_s3 failed\n");
		goto done;
	}

	smb_init_locale();
	setup_logging("winexe", DEBUG_STDOUT);

	lp_load_global(get_dyn_CONFIGFILE());

	parse_args(argc, argv, frame, &options, lp_ctx);

	if (options.cmd == NULL) {
		fprintf(stderr, "no cmd given\n");
		goto done;
	}

	service_filename = talloc_asprintf(frame, "%s.exe", service_name);
	if (service_filename == NULL) {
		DBG_WARNING("talloc_asprintf failed\n");
		goto done;
	}

	status = cli_full_connection_creds(
		&cli,
		NULL,
		options.hostname,
		NULL,
		options.port,
		"IPC$",
		"?????",
		options.credentials,
		0,
		0);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("cli_full_connection_creds failed: %s\n",
			    nt_errstr(status));
		goto done;
	}

	status = winexe_svc_install(
		cli,
		options.hostname,
		options.port,
		service_name,
		service_filename,
		winexesvc32_exe,
		winexesvc64_exe,
		options.credentials,
		options.flags);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("winexe_svc_install failed: %s\n",
			    nt_errstr(status));
		goto done;
	}

	status = winexe_ctrl(cli, options.cmd, &return_code);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_DISCONNECTED)) {
		/* Normal finish */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("cli_ctrl failed: %s\n",
			    nt_errstr(status));
		goto done;
	}

	if (options.flags & SVC_UNINSTALL) {
		status = winexe_svc_uninstall(
			cli,
			service_name);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("winexe_svc_uninstall failed: %s\n",
				    nt_errstr(status));
			goto done;
		}
	}

	ret = return_code;
done:
	TALLOC_FREE(frame);
	return ret;
}
