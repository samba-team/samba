/*
   Unix SMB/CIFS implementation.
   SMB backend for the Common UNIX Printing System ("CUPS")

   Copyright (C) Michael R Sweet            1999
   Copyright (C) Andrew Tridgell	    1994-1998
   Copyright (C) Andrew Bartlett	    2002
   Copyright (C) Rodrigo Fernandez-Vizarra  2005
   Copyright (C) James Peach		    2008

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
#include "system/filesys.h"
#include "system/passwd.h"
#include "system/kerberos.h"
#include "libsmb/libsmb.h"
#include "lib/param/param.h"
#include "lib/krb5_wrap/krb5_samba.h"

/*
 * Starting with CUPS 1.3, Kerberos support is provided by cupsd including
 * the forwarding of user credentials via the authenticated session between
 * user and server and the KRB5CCNAME environment variable which will point
 * to a temporary file or an in-memory representation depending on the version
 * of Kerberos you use.  As a result, all of the ticket code that used to
 * live here has been removed, and we depend on the user session (if you
 * run smbspool by hand) or cupsd to provide the necessary Kerberos info.
 *
 * Also, the AUTH_USERNAME and AUTH_PASSWORD environment variables provide
 * for per-job authentication for non-Kerberized printing.  We use those
 * if there is no username and password specified in the device URI.
 *
 * Finally, if we have an authentication failure we return exit code 2
 * which tells CUPS to hold the job for authentication and bug the user
 * to get the necessary credentials.
 */

#define MAX_RETRY_CONNECT        3


/*
 * Globals...
 */



/*
 * Local functions...
 */

static int      get_exit_code(NTSTATUS nt_status);
static void     list_devices(void);
static NTSTATUS
smb_connect(struct cli_state **output_cli,
	    const char *workgroup,
	    const char *server,
	    const int port,
	    const char *share,
	    const char *username,
	    const char *password,
	    const char *jobusername);
static int      smb_print(struct cli_state *, const char *, FILE *);
static char    *uri_unescape_alloc(const char *);
#if 0
static bool     smb_encrypt;
#endif

static const char *auth_info_required;

/*
 * 'main()' - Main entry for SMB backend.
 */

int				/* O - Exit status */
main(int argc,			/* I - Number of command-line arguments */
     char *argv[])
{				/* I - Command-line arguments */
	int             i;	/* Looping var */
	int             copies;	/* Number of copies */
	int             port;	/* Port number */
	char            uri[1024],	/* URI */
	               *sep,	/* Pointer to separator */
	               *tmp, *tmp2;	/* Temp pointers to do escaping */
	const char     *password = NULL;	/* Password */
	const char     *username = NULL;	/* Username */
	char           *server,	/* Server name */
	               *printer;/* Printer name */
	const char     *workgroup;	/* Workgroup */
	FILE           *fp;	/* File to print */
	int             status = 1;	/* Status of LPD job */
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct cli_state *cli = NULL;	/* SMB interface */
	int             tries = 0;
	const char     *dev_uri = NULL;
	const char     *env = NULL;
	const char     *config_file = NULL;
	TALLOC_CTX     *frame = talloc_stackframe();
	const char *print_user = NULL;
	const char *print_title = NULL;
	const char *print_file = NULL;
	const char *print_copies = NULL;
	int cmp;
	int len;

	if (argc == 1) {
		/*
	         * NEW!  In CUPS 1.1 the backends are run with no arguments
		 * to list the available devices.  These can be devices
		 * served by this backend or any other backends (i.e. you
		 * can have an SNMP backend that is only used to enumerate
		 * the available network printers... :)
	         */

		list_devices();
		status = 0;
		goto done;
	}

	/*
	 * We need at least 5 options if the DEVICE_URI is passed via an env
	 * variable and printing data comes via stdin.
	 * We don't accept more than 7 options in total, including optional.
	 */
	if (argc < 5 || argc > 8) {
		fprintf(stderr,
"Usage: %s [DEVICE_URI] job-id user title copies options [file]\n"
"       The DEVICE_URI environment variable can also contain the\n"
"       destination printer:\n"
"\n"
"           smb://[username:password@][workgroup/]server[:port]/printer\n",
			argv[0]);
		goto done;
	}

	/*
	 * Find out if we have the device_uri in the command line.
	 *
	 * If we are started as a CUPS backend argv[0] is normally the
	 * device_uri!
	 */
	if (argc == 8) {
		/*
		 * smbspool <uri> <job> <user> <title> <copies> <options> <file>
		 * 0        1     2     3      4       5        6         7
		 */

		dev_uri = argv[1];

		print_user = argv[3];
		print_title = argv[4];
		print_copies = argv[5];
		print_file = argv[7];
	} else if (argc == 7) {
		int cmp1;
		int cmp2;

		/*
		 * <uri>    <job> <user> <title> <copies> <options> <file>
		 * smbspool <uri> <job>  <user>  <title>  <copies>  <options>
		 * smbspool <job> <user> <title> <copies> <options> <file> | DEVICE_URI
		 */
		cmp1 = strncmp(argv[0], "smb://", 6);
		cmp2 = strncmp(argv[1], "smb://", 6);

		if (cmp1 == 0) {
			/*
			 * <uri>    <job> <user> <title> <copies> <options> <file>
			 * 0        1     2      3       4        5         6
			 */
			dev_uri = argv[0];

			print_user = argv[2];
			print_title = argv[3];
			print_copies = argv[4];
			print_file = argv[6];
		} else if (cmp2 == 0) {
			/*
			 * smbspool <uri> <job>  <user>  <title>  <copies>  <options>
			 * 0        1     2      3       4        5         6
			 */
			dev_uri = argv[1];

			print_user = argv[3];
			print_title = argv[4];
			print_copies = argv[5];
			print_file = NULL;
		} else {
			/*
			 * smbspool <job> <user> <title> <copies> <options> <file> | DEVICE_URI
			 * 0        1     2      3       4        5         6
			 */
			print_user = argv[2];
			print_title = argv[3];
			print_copies = argv[4];
			print_file = argv[6];
		}
	} else if (argc == 6) {
		/*
		 * <uri>    <job> <user> <title> <copies> <options>
		 * smbspool <job> <user> <title> <copies> <options> | DEVICE_URI
		 * 0        1     2      3       4        5
		 */
		cmp = strncmp(argv[0], "smb://", 6);
		if (cmp == 0) {
			dev_uri = argv[0];
		}

		print_user = argv[2];
		print_title = argv[3];
		print_copies = argv[4];
	}

	if (print_file != NULL) {
		char *endp;

		fp = fopen(print_file, "rb");
		if (fp == NULL) {
			fprintf(stderr,
				"ERROR: Unable to open print file: %s",
				print_file);
			goto done;
		}

		copies = strtol(print_copies, &endp, 10);
		if (print_copies == endp) {
			perror("ERROR: Unable to determine number of copies");
			goto done;
		}
	} else {
		fp = stdin;
		copies = 1;
	}

	/*
	 * Find the URI ...
         *
         * The URI in argv[0] is sanitized to remove username/password, so
         * use DEVICE_URI if available. Otherwise keep the URI already
         * discovered in argv.
         */
        env = getenv("DEVICE_URI");
        if (env != NULL && env[0] != '\0') {
          dev_uri = env;
        }

	if (dev_uri == NULL) {
		fprintf(stderr,
			"ERROR: No valid device URI has been specified\n");
		goto done;
	}

	cmp = strncmp(dev_uri, "smb://", 6);
	if (cmp != 0) {
		fprintf(stderr,
			"ERROR: No valid device URI has been specified\n");
		goto done;
	}
	len = snprintf(uri, sizeof(uri), "%s", dev_uri);
	if (len >= sizeof(uri)) {
		fprintf(stderr,
			"ERROR: The URI is too long.\n");
		goto done;
	}

	auth_info_required = getenv("AUTH_INFO_REQUIRED");
	if (auth_info_required == NULL) {
		auth_info_required = "samba";
	}

	/*
         * Extract the destination from the URI...
         */

	if ((sep = strrchr_m(uri, '@')) != NULL) {
		tmp = uri + 6;
		*sep++ = '\0';

		/* username is in tmp */

		server = sep;

		/*
	         * Extract password as needed...
	         */

		if ((tmp2 = strchr_m(tmp, ':')) != NULL) {
			*tmp2++ = '\0';
			password = uri_unescape_alloc(tmp2);
		}
		username = uri_unescape_alloc(tmp);
	} else {
		env = getenv("AUTH_USERNAME");
		if (env != NULL && strlen(env) > 0) {
			username = env;
		}

		env = getenv("AUTH_PASSWORD");
		if (env != NULL && strlen(env) > 0) {
			password = env;
		}

		server = uri + 6;
	}

	if (password != NULL) {
		auth_info_required = "username,password";
	}

	tmp = server;

	if ((sep = strchr_m(tmp, '/')) == NULL) {
		fputs("ERROR: Bad URI - need printer name!\n", stderr);
		goto done;
	}

	*sep++ = '\0';
	tmp2 = sep;

	if ((sep = strchr_m(tmp2, '/')) != NULL) {
		/*
	         * Convert to smb://[username:password@]workgroup/server/printer...
	         */

		*sep++ = '\0';

		workgroup = uri_unescape_alloc(tmp);
		server = uri_unescape_alloc(tmp2);
		printer = uri_unescape_alloc(sep);
	} else {
		workgroup = NULL;
		server = uri_unescape_alloc(tmp);
		printer = uri_unescape_alloc(tmp2);
	}

	if ((sep = strrchr_m(server, ':')) != NULL) {
		*sep++ = '\0';

		port = atoi(sep);
	} else {
		port = 0;
	}

	/*
         * Setup the SAMBA server state...
         */

	setup_logging("smbspool", DEBUG_STDERR);

	smb_init_locale();

	config_file = lp_default_path();
	if (!lp_load_client(config_file)) {
		fprintf(stderr,
			"ERROR: Can't load %s - run testparm to debug it\n",
			config_file);
		goto done;
	}

	if (workgroup == NULL) {
		workgroup = lp_workgroup();
	}

	load_interfaces();

	do {
		nt_status = smb_connect(&cli,
					workgroup,
					server,
					port,
					printer,
					username,
					password,
					print_user);
		if (!NT_STATUS_IS_OK(nt_status)) {
			status = get_exit_code(nt_status);
			if (status == 2) {
				fprintf(stderr,
					"DEBUG: Unable to connect to CIFS "
					"host: %s",
					nt_errstr(nt_status));
				goto done;
			} else if (getenv("CLASS") == NULL) {
				fprintf(stderr,
					"ERROR: Unable to connect to CIFS "
					"host: %s. Will retry in 60 "
					"seconds...\n",
					nt_errstr(nt_status));
				sleep(60);
				tries++;
			} else {
				fprintf(stderr,
					"ERROR: Unable to connect to CIFS "
					"host: %s. Trying next printer...\n",
					nt_errstr(nt_status));
				goto done;
			}
		}
	} while (!NT_STATUS_IS_OK(nt_status) && (tries < MAX_RETRY_CONNECT));

	if (cli == NULL) {
		fprintf(stderr, "ERROR: Unable to connect to CIFS host after (tried %d times)\n", tries);
		goto done;
	}

	/*
         * Now that we are connected to the server, ignore SIGTERM so that we
         * can finish out any page data the driver sends (e.g. to eject the
         * current page...  Only ignore SIGTERM if we are printing data from
         * stdin (otherwise you can't cancel raw jobs...)
         */

	if (argc < 7) {
		CatchSignal(SIGTERM, SIG_IGN);
	}

	/*
         * Queue the job...
         */

	for (i = 0; i < copies; i++) {
		status = smb_print(cli, print_title, fp);
		if (status != 0) {
			break;
		}
	}

	cli_shutdown(cli);

	/*
         * Return the queue status...
         */

done:

	TALLOC_FREE(frame);
	return (status);
}


/*
 * 'get_exit_code()' - Get the backend exit code based on the current error.
 */

static int
get_exit_code(NTSTATUS nt_status)
{
	size_t i;

	/* List of NTSTATUS errors that are considered
	 * authentication errors
	 */
	static const NTSTATUS auth_errors[] =
	{
		NT_STATUS_ACCESS_DENIED,
		NT_STATUS_ACCESS_VIOLATION,
		NT_STATUS_ACCOUNT_DISABLED,
		NT_STATUS_ACCOUNT_LOCKED_OUT,
		NT_STATUS_ACCOUNT_RESTRICTION,
		NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND,
		NT_STATUS_INVALID_ACCOUNT_NAME,
		NT_STATUS_INVALID_COMPUTER_NAME,
		NT_STATUS_INVALID_LOGON_HOURS,
		NT_STATUS_INVALID_WORKSTATION,
		NT_STATUS_LOGON_FAILURE,
		NT_STATUS_NO_SUCH_USER,
		NT_STATUS_NO_SUCH_DOMAIN,
		NT_STATUS_NO_LOGON_SERVERS,
		NT_STATUS_PASSWORD_EXPIRED,
		NT_STATUS_PRIVILEGE_NOT_HELD,
		NT_STATUS_SHARING_VIOLATION,
		NT_STATUS_WRONG_PASSWORD,
	};


	fprintf(stderr,
		"DEBUG: get_exit_code(nt_status=%s [%x])\n",
		nt_errstr(nt_status), NT_STATUS_V(nt_status));

	for (i = 0; i < ARRAY_SIZE(auth_errors); i++) {
		if (!NT_STATUS_EQUAL(nt_status, auth_errors[i])) {
			continue;
		}

		fprintf(stderr, "ATTR: auth-info-required=%s\n", auth_info_required);

		/*
		 * 2 = authentication required...
		 */

		return (2);

	}

	/*
         * 1 = fail
         */

	return (1);
}


/*
 * 'list_devices()' - List the available printers seen on the network...
 */

static void
list_devices(void)
{
	/*
         * Eventually, search the local workgroup for available hosts and printers.
         */

	puts("network smb \"Unknown\" \"Windows Printer via SAMBA\"");
}


static NTSTATUS
smb_complete_connection(struct cli_state **output_cli,
			const char *myname,
			const char *server,
			int port,
			const char *username,
			const char *password,
			const char *workgroup,
			const char *share,
			bool use_kerberos,
			bool fallback_after_kerberos)
{
	struct cli_state *cli;	/* New connection */
	NTSTATUS        nt_status;
	struct cli_credentials *creds = NULL;

	/* Start the SMB connection */
	nt_status = cli_start_connection(&cli, myname, server, NULL, port,
					 SMB_SIGNING_DEFAULT, 0);
	if (!NT_STATUS_IS_OK(nt_status)) {
		fprintf(stderr, "ERROR: Connection failed: %s\n", nt_errstr(nt_status));
		return nt_status;
	}

	creds = cli_session_creds_init(cli,
				       username,
				       workgroup,
				       NULL, /* realm */
				       password,
				       use_kerberos,
				       fallback_after_kerberos,
				       false, /* use_ccache */
				       false); /* password_is_nt_hash */
	if (creds == NULL) {
		fprintf(stderr, "ERROR: cli_session_creds_init failed\n");
		cli_shutdown(cli);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = cli_session_setup_creds(cli, creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		fprintf(stderr, "ERROR: Session setup failed: %s\n", nt_errstr(nt_status));

		cli_shutdown(cli);

		return nt_status;
	}

	nt_status = cli_tree_connect_creds(cli, share, "?????", creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		fprintf(stderr, "ERROR: Tree connect failed (%s)\n",
			nt_errstr(nt_status));

		cli_shutdown(cli);

		return nt_status;
	}
#if 0
	/* Need to work out how to specify this on the URL. */
	if (smb_encrypt) {
		if (!cli_cm_force_encryption_creds(cli, creds, share)) {
			fprintf(stderr, "ERROR: encryption setup failed\n");
			cli_shutdown(cli);
			return NULL;
		}
	}
#endif

	*output_cli = cli;
	return NT_STATUS_OK;
}

static bool kerberos_ccache_is_valid(void) {
	krb5_context ctx;
	const char *ccache_name = NULL;
	krb5_ccache ccache = NULL;
	krb5_error_code code;

	code = smb_krb5_init_context_common(&ctx);
	if (code != 0) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(code));
		return false;
	}

	ccache_name = krb5_cc_default_name(ctx);
	if (ccache_name == NULL) {
		DBG_ERR("Failed to get default ccache name\n");
		krb5_free_context(ctx);
		return false;
	}

	code = krb5_cc_resolve(ctx, ccache_name, &ccache);
	if (code != 0) {
		DBG_ERR("Failed to resolve ccache name: %s\n",
			ccache_name);
		krb5_free_context(ctx);
		return false;
	} else {
		krb5_principal default_princ = NULL;
		char *princ_name = NULL;

		code = krb5_cc_get_principal(ctx,
					     ccache,
					     &default_princ);
		if (code != 0) {
			DBG_ERR("Failed to get default principal from "
				"ccache: %s\n",
				ccache_name);
			krb5_cc_close(ctx, ccache);
			krb5_free_context(ctx);
			return false;
		}

		code = krb5_unparse_name(ctx,
					 default_princ,
					 &princ_name);
		if (code == 0) {
			fprintf(stderr,
				"DEBUG: Try to authenticate as %s\n",
				princ_name);
			krb5_free_unparsed_name(ctx, princ_name);
		}
		krb5_free_principal(ctx, default_princ);
	}
	krb5_cc_close(ctx, ccache);
	krb5_free_context(ctx);

	return true;
}

/*
 * 'smb_connect()' - Return a connection to a server.
 */

static NTSTATUS
smb_connect(struct cli_state **output_cli,
	    const char *workgroup,	/* I - Workgroup */
	    const char *server,	/* I - Server */
	    const int port,	/* I - Port */
	    const char *share,	/* I - Printer */
	    const char *username,	/* I - Username */
	    const char *password,	/* I - Password */
	    const char *jobusername)	/* I - User who issued the print job */
{
	struct cli_state *cli = NULL;	/* New connection */
	char           *myname = NULL;	/* Client name */
	struct passwd  *pwd;
	bool use_kerberos = false;
	bool fallback_after_kerberos = false;
	const char *user = username;
	NTSTATUS nt_status;

	/*
         * Get the names and addresses of the client and server...
         */
	myname = get_myname(talloc_tos());
	if (!myname) {
		return NT_STATUS_NO_MEMORY;
	}


	if (strcmp(auth_info_required, "negotiate") == 0) {
		if (!kerberos_ccache_is_valid()) {
			fprintf(stderr,
				"ERROR: No valid Kerberos credential cache found! "
				"Using smbspool_krb5_wrapper may help.\n");
			return NT_STATUS_LOGON_FAILURE;
		}
		user = jobusername;

		use_kerberos = true;
		fprintf(stderr,
			"DEBUG: Try to connect using Kerberos ...\n");
	} else if (strcmp(auth_info_required, "username,password") == 0) {
		if (username == NULL) {
			return NT_STATUS_INVALID_ACCOUNT_NAME;
		}

		/* Fallback to NTLM */
		fallback_after_kerberos = true;

		fprintf(stderr,
			"DEBUG: Try to connect using username/password ...\n");
	} else if (strcmp(auth_info_required, "none") == 0) {
		goto anonymous;
	} else if (strcmp(auth_info_required, "samba") == 0) {
		if (username != NULL) {
			fallback_after_kerberos = true;
		} else if (kerberos_ccache_is_valid()) {
			auth_info_required = "negotiate";

			user = jobusername;
			use_kerberos = true;
		} else {
			fprintf(stderr,
				"DEBUG: This backend requires credentials!\n");
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		return NT_STATUS_ACCESS_DENIED;
	}

	nt_status = smb_complete_connection(&cli,
					    myname,
					    server,
					    port,
					    user,
					    password,
					    workgroup,
					    share,
					    true, /* try kerberos */
					    fallback_after_kerberos);
	if (NT_STATUS_IS_OK(nt_status)) {
		fprintf(stderr, "DEBUG: SMB connection established.\n");

		*output_cli = cli;
		return NT_STATUS_OK;
	}

	if (!use_kerberos) {
		fprintf(stderr, "ERROR: SMB connection failed!\n");
		return nt_status;
	}

	/* give a chance for a passwordless NTLMSSP session setup */
	pwd = getpwuid(geteuid());
	if (pwd == NULL) {
		return NT_STATUS_ACCESS_DENIED;
	}

	nt_status = smb_complete_connection(&cli,
					    myname,
					    server,
					    port,
					    pwd->pw_name,
					    "",
					    workgroup,
					    share,
					    false, false);
	if (NT_STATUS_IS_OK(nt_status)) {
		fputs("DEBUG: Connected with NTLMSSP...\n", stderr);

		*output_cli = cli;
		return NT_STATUS_OK;
	}

	/*
         * last try. Use anonymous authentication
         */

anonymous:
	nt_status = smb_complete_connection(&cli,
					    myname,
					    server,
					    port,
					    "",
					    "",
					    workgroup,
					    share,
					    false, false);
	if (NT_STATUS_IS_OK(nt_status)) {
		*output_cli = cli;
		return NT_STATUS_OK;
	}

	return nt_status;
}


/*
 * 'smb_print()' - Queue a job for printing using the SMB protocol.
 */

static int			/* O - 0 = success, non-0 = failure */
smb_print(struct cli_state * cli,	/* I - SMB connection */
	  const char *print_title,		/* I - Title/job name */
	  FILE * fp)
{				/* I - File to print */
	uint16_t             fnum;	/* File number */
	int             nbytes,	/* Number of bytes read */
	                tbytes;	/* Total bytes read */
	char            buffer[8192],	/* Buffer for copy */
	               *ptr;	/* Pointer into title */
	char title[1024] = {0};
	int len;
	NTSTATUS nt_status;


	/*
	 * Sanitize the title...
	 */
	len = snprintf(title, sizeof(title), "%s", print_title);
	if (len != strlen(print_title)) {
		return 2;
	}

	for (ptr = title; *ptr; ptr++) {
		if (!isalnum((int) *ptr) && !isspace((int) *ptr)) {
			*ptr = '_';
		}
	}

	/*
         * Open the printer device...
         */

	nt_status = cli_open(cli, title, O_RDWR | O_CREAT | O_TRUNC, DENY_NONE,
			  &fnum);
	if (!NT_STATUS_IS_OK(nt_status)) {
		fprintf(stderr, "ERROR: %s opening remote spool %s\n",
			nt_errstr(nt_status), title);
		return get_exit_code(nt_status);
	}

	/*
         * Copy the file to the printer...
         */

	if (fp != stdin)
		rewind(fp);

	tbytes = 0;

	while ((nbytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		NTSTATUS status;

		status = cli_writeall(cli, fnum, 0, (uint8_t *)buffer,
				      tbytes, nbytes, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			int ret = get_exit_code(status);
			fprintf(stderr, "ERROR: Error writing spool: %s\n",
				nt_errstr(status));
			fprintf(stderr, "DEBUG: Returning status %d...\n",
				ret);
			cli_close(cli, fnum);

			return (ret);
		}
		tbytes += nbytes;
	}

	nt_status = cli_close(cli, fnum);
	if (!NT_STATUS_IS_OK(nt_status)) {
		fprintf(stderr, "ERROR: %s closing remote spool %s\n",
			nt_errstr(nt_status), title);
		return get_exit_code(nt_status);
	} else {
		return (0);
	}
}

static char *
uri_unescape_alloc(const char *uritok)
{
	char *ret;
	char *end;
	ret = (char *) SMB_STRDUP(uritok);
	if (!ret) {
		return NULL;
	}

	end = rfc1738_unescape(ret);
	if (end == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}
