/*
   Unix SMB/CIFS implementation.
   test suite for spoolss rpc notify operations

   Copyright (C) Jelmer Vernooij 2007
   Copyright (C) Guenther Deschner 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/dir.h"
#include "system/filesys.h"
#include "system/network.h"
#include "lib/events/events.h"
#include "librpc/gen_ndr/ndr_spoolss_c.h"
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "torture/rpc/torture_rpc.h"
#include "lib/socket/netif.h"
#include "lib/util/samba_util.h"
#include "lib/util/util_file.h"
#include "dynconfig.h"
#include "auth/credentials/credentials.h"
#include "libcli/resolve/resolve.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "param/param.h"

/*
 * The print-change-notification callback the server sends back to us is
 * captured by a separate helper process (rpcd_spoolss_notify_test, see
 * source3/rpc_server/rpcd_spoolss_notify_test.c), reached the same way a
 * real client would be: over SMB, via a throwaway smbd+samba-dcerpcd pair
 * we spawn for the duration of this test. The helper logs the opnums it
 * was called with to a file we read back below.
 */

static bool test_OpenPrinter(struct torture_context *tctx,
			     struct dcerpc_pipe *p,
			     struct policy_handle *handle,
			     const char *printername)
{
	struct spoolss_OpenPrinter r;
	struct dcerpc_binding_handle *b = p->binding_handle;

	ZERO_STRUCT(r);

	r.in.printername	= printername;
	r.in.datatype		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.access_mask	= SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle		= handle;

	torture_comment(tctx, "Testing OpenPrinter(%s)\n", r.in.printername);

	torture_assert_ntstatus_ok(tctx, dcerpc_spoolss_OpenPrinter_r(b, tctx, &r),
		"OpenPrinter failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"OpenPrinter failed");

	return true;
}

static struct spoolss_NotifyOption *setup_printserver_NotifyOption(struct torture_context *tctx)
{
	struct spoolss_NotifyOption *o;

	o = talloc_zero(tctx, struct spoolss_NotifyOption);

	o->version = 2;
	o->flags = PRINTER_NOTIFY_OPTIONS_REFRESH;

	o->count = 2;
	o->types = talloc_zero_array(o, struct spoolss_NotifyOptionType, o->count);

	o->types[0].type = PRINTER_NOTIFY_TYPE;
	o->types[0].count = 1;
	o->types[0].fields = talloc_array(o->types, union spoolss_Field, o->types[0].count);
	o->types[0].fields[0].field = PRINTER_NOTIFY_FIELD_SERVER_NAME;

	o->types[1].type = JOB_NOTIFY_TYPE;
	o->types[1].count = 1;
	o->types[1].fields = talloc_array(o->types, union spoolss_Field, o->types[1].count);
	o->types[1].fields[0].field = JOB_NOTIFY_FIELD_MACHINE_NAME;

	return o;
}

#if 0
static struct spoolss_NotifyOption *setup_printer_NotifyOption(struct torture_context *tctx)
{
	struct spoolss_NotifyOption *o;

	o = talloc_zero(tctx, struct spoolss_NotifyOption);

	o->version = 2;
	o->flags = PRINTER_NOTIFY_OPTIONS_REFRESH;

	o->count = 1;
	o->types = talloc_zero_array(o, struct spoolss_NotifyOptionType, o->count);

	o->types[0].type = PRINTER_NOTIFY_TYPE;
	o->types[0].count = 1;
	o->types[0].fields = talloc_array(o->types, union spoolss_Field, o->types[0].count);
	o->types[0].fields[0].field = PRINTER_NOTIFY_FIELD_COMMENT;

	return o;
}
#endif

static bool test_RemoteFindFirstPrinterChangeNotifyEx(struct torture_context *tctx,
						      struct dcerpc_binding_handle *b,
						      struct policy_handle *handle,
						      const char *address,
						      struct spoolss_NotifyOption *option)
{
	struct spoolss_RemoteFindFirstPrinterChangeNotifyEx r;
	const char *local_machine = talloc_asprintf(tctx, "\\\\%s", address);

	torture_comment(tctx, "Testing RemoteFindFirstPrinterChangeNotifyEx(%s)\n", local_machine);

	r.in.flags = 0;
	r.in.local_machine = local_machine;
	r.in.options = 0;
	r.in.printer_local = 0;
	r.in.notify_options = option;
	r.in.handle = handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_spoolss_RemoteFindFirstPrinterChangeNotifyEx_r(b, tctx, &r),
		"RemoteFindFirstPrinterChangeNotifyEx failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"error return code for RemoteFindFirstPrinterChangeNotifyEx");

	return true;
}

static bool test_RouterRefreshPrinterChangeNotify(struct torture_context *tctx,
						  struct dcerpc_binding_handle *b,
						  struct policy_handle *handle,
						  struct spoolss_NotifyOption *options,
						  struct spoolss_NotifyInfo **info)
{
	struct spoolss_RouterRefreshPrinterChangeNotify r;

	torture_comment(tctx, "Testing RouterRefreshPrinterChangeNotify\n");

	r.in.handle = handle;
	r.in.change_low = 0;
	r.in.options = options;
	r.out.info = info;

	torture_assert_ntstatus_ok(tctx, dcerpc_spoolss_RouterRefreshPrinterChangeNotify_r(b, tctx, &r),
		"RouterRefreshPrinterChangeNotify failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"error return code for RouterRefreshPrinterChangeNotify");

	return true;
}

#if 0
static bool test_SetPrinter(struct torture_context *tctx,
			    struct dcerpc_pipe *p,
			    struct policy_handle *handle)
{
	union spoolss_PrinterInfo info;
	struct spoolss_SetPrinter r;
	struct spoolss_SetPrinterInfo2 info2;
	struct spoolss_SetPrinterInfoCtr info_ctr;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct sec_desc_buf secdesc_ctr;
	struct dcerpc_binding_handle *b = p->binding_handle;

	torture_assert(tctx, test_GetPrinter_level(tctx, b, handle, 2, &info), "");

	ZERO_STRUCT(devmode_ctr);
	ZERO_STRUCT(secdesc_ctr);

	info2.servername	= info.info2.servername;
	info2.printername	= info.info2.printername;
	info2.sharename		= info.info2.sharename;
	info2.portname		= info.info2.portname;
	info2.drivername	= info.info2.drivername;
	info2.comment		= talloc_asprintf(tctx, "torture_comment %d\n", (int)time(NULL));
	info2.location		= info.info2.location;
	info2.devmode_ptr	= 0;
	info2.sepfile		= info.info2.sepfile;
	info2.printprocessor	= info.info2.printprocessor;
	info2.datatype		= info.info2.datatype;
	info2.parameters	= info.info2.parameters;
	info2.secdesc_ptr	= 0;
	info2.attributes	= info.info2.attributes;
	info2.priority		= info.info2.priority;
	info2.defaultpriority	= info.info2.defaultpriority;
	info2.starttime		= info.info2.starttime;
	info2.untiltime		= info.info2.untiltime;
	info2.status		= info.info2.status;
	info2.cjobs		= info.info2.cjobs;
	info2.averageppm	= info.info2.averageppm;

	info_ctr.level = 2;
	info_ctr.info.info2 = &info2;

	r.in.handle = handle;
	r.in.info_ctr = &info_ctr;
	r.in.devmode_ctr = &devmode_ctr;
	r.in.secdesc_ctr = &secdesc_ctr;
	r.in.command = 0;

	torture_assert_ntstatus_ok(tctx, dcerpc_spoolss_SetPrinter_r(b, tctx, &r), "SetPrinter failed");
	torture_assert_werr_ok(tctx, r.out.result, "SetPrinter failed");

	return true;
}
#endif

struct notify_test_env {
	const char *address;
	const char *packet_log;
	char *tempdir;
	struct tevent_req *dcerpcd_req;
	struct tevent_req *smbd_req;
};

/*
 * Short tempdir for the throwaway smbd environment to store the np
 * sockets
 */
static bool notify_test_short_temp_dir(struct torture_context *tctx,
				       TALLOC_CTX *mem_ctx,
				       char **tempdir)
{
	const char *base = getenv("SELFTEST_TMPDIR");
	char *path = NULL;

	torture_assert(tctx,
		       base != NULL,
		       "SELFTEST_TMPDIR not set in the environment");

	path = talloc_asprintf(mem_ctx, "%s/XXXXXXXX", base);
	torture_assert(tctx, path != NULL, "out of memory");
	torture_assert(tctx,
		       mkdtemp(path) != NULL,
		       "mkdtemp() failed for throwaway spoolss_notify dir");

	*tempdir = path;
	return true;
}

static bool write_notify_test_smbconf(struct torture_context *tctx,
				      const char *tempdir,
				      const char *address,
				      const char *packet_log,
				      const char **conf_path)
{
	char *path = talloc_asprintf(tctx, "%s/smb.conf", tempdir);
	FILE *f;

	torture_assert(tctx, path != NULL, "out of memory");

	f = fopen(path, "w");
	torture_assert(tctx, f != NULL, "unable to create throwaway smb.conf");

	fprintf(f,
		"[global]\n"
		"\tserver role = standalone\n"
		"\tsecurity = user\n"
		"\tmap to guest = bad user\n"
		"\tload printers = no\n"
		"\tinterfaces = %s/24\n"
		"\tbind interfaces only = yes\n"
		"\tprivate dir = %s/private\n"
		"\tlock directory = %s/lock\n"
		"\tstate directory = %s/lock\n"
		"\tcache directory = %s/lock\n"
		"\tpid directory = %s/pid\n"
		"\tncalrpc dir = %s/n\n" /* no "ncalrpc" for brevity */
		"\tlog file = %s/log.%%m\n"
		"\tlog level = 3\n"
		"\trpc start on demand helpers = no\n"
		"\tspoolss_notify_test:packet_log = %s\n",
		address,
		tempdir,
		tempdir,
		tempdir,
		tempdir,
		tempdir,
		tempdir,
		tempdir,
		packet_log);
	fclose(f);

	*conf_path = path;
	return true;
}

static void notify_test_timer_done(struct tevent_context *ev,
				   struct tevent_timer *te,
				   struct timeval current_time,
				   void *private_data)
{
	bool *fired = (bool *)private_data;
	*fired = true;
}

/*
 * samba_runcmd_send() is tevent-based. Wait for the subprocess to
 * settle while at the same time allow tevent_loop_once to catch
 * stdout/stderr from it.
 */
static void notify_test_wait(struct tevent_context *ev, unsigned seconds)
{
	bool fired = false;
	struct tevent_timer *te = NULL;

	te = tevent_add_timer(ev,
			      ev,
			      timeval_current_ofs(seconds, 0),
			      notify_test_timer_done,
			      &fired);
	if (te == NULL) {
		sleep(seconds);
		return;
	}

	while (!fired) {
		if (tevent_loop_once(ev) != 0) {
			break;
		}
	}
}

/*
 * Log when the throwaway smbd/samba-dcerpcd children exit before we
 * expect them to - without this, an early crash or exec failure is
 * silently invisible until (and unless) a later torture_assert() names
 * a symptom several steps downstream of the real cause.
 */
struct notify_test_child_state {
	struct torture_context *tctx;
	const char *label;
};

static void notify_test_child_exited(struct tevent_req *req)
{
	struct notify_test_child_state *state = tevent_req_callback_data(
		req, struct notify_test_child_state);
	int ret, sys_errno = 0;

	ret = samba_runcmd_recv(req, &sys_errno);
	torture_comment(state->tctx,
			"%s exited unexpectedly (ret=%d, errno=%d: %s)\n",
			state->label,
			ret,
			sys_errno,
			strerror(sys_errno));
}

static void notify_test_watch_child(struct torture_context *tctx,
				    struct tevent_req *req,
				    const char *label)
{
	struct notify_test_child_state *state = NULL;

	state = talloc(req, struct notify_test_child_state);
	if (state == NULL) {
		return;
	}
	state->tctx = tctx;
	state->label = label;

	tevent_req_set_callback(req, notify_test_child_exited, state);
}

/*
 * Dump one of the throwaway daemons' own debug logs (as opposed to what
 * they printed to stdout/stderr, which samba_runcmd_send() already
 * echoes into our own output) so a failure here doesn't require pulling
 * a separate log archive to see why.
 */
static void dump_notify_test_log(struct torture_context *tctx,
				 const char *tempdir,
				 const char *name)
{
	char *path = talloc_asprintf(tctx, "%s/%s", tempdir, name);
	char *contents = NULL;
	size_t size = 0;

	if (path == NULL) {
		return;
	}

	contents = file_load(path, &size, 0, tctx);
	if (contents == NULL) {
		torture_comment(tctx, "---- %s: not present ----\n", path);
		return;
	}

	torture_comment(tctx,
			"---- %s (%zu bytes) ----\n%s---- end %s ----\n",
			path,
			size,
			contents,
			path);
}

static void dump_notify_test_dir(struct torture_context *tctx,
				 const char *path)
{
	DIR *d = NULL;
	struct dirent *de = NULL;

	d = opendir(path);
	if (d == NULL) {
		torture_comment(tctx,
				"opendir(%s) failed: %s\n",
				path,
				strerror(errno));
		return;
	}

	torture_comment(tctx, "contents of %s:\n", path);
	while ((de = readdir(d)) != NULL) {
		torture_comment(tctx, "  %s\n", de->d_name);
	}
	closedir(d);
}

static void dump_notify_test_diagnostics(struct torture_context *tctx,
					 const char *tempdir)
{
	torture_comment(tctx,
			"dumping notify test diagnostics from %s\n",
			tempdir);

	dump_notify_test_dir(tctx, talloc_asprintf(tctx, "%s/n", tempdir));
	dump_notify_test_dir(tctx, talloc_asprintf(tctx, "%s/n/np", tempdir));
	dump_notify_test_log(tctx, tempdir, "log.samba-dcerpcd");
	dump_notify_test_log(tctx, tempdir, "log.rpcd_spoolss_notify_test");
	dump_notify_test_log(tctx, tempdir, "log.smbd");
}

static bool wait_for_unix_socket(struct torture_context *tctx,
				 const char *path)
{
	unsigned i;

	for (i = 0; i < 30; i++) {
		struct sockaddr_un sun = {.sun_family = AF_UNIX};
		int fd, ret;

		strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);

		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		torture_assert(tctx, fd != -1, "socket() failed");

		ret = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
		close(fd);
		if (ret == 0) {
			torture_comment(tctx,
					"wait_for_unix_socket(%s): "
					"connected after %u attempt(s)\n",
					path,
					i + 1);
			return true;
		}

		torture_comment(tctx,
				"wait_for_unix_socket(%s): attempt %u: "
				"connect failed: %s\n",
				path,
				i + 1,
				strerror(errno));

		notify_test_wait(tctx->ev, 1);
	}

	return false;
}

static bool wait_for_smb_ready(struct torture_context *tctx,
			       const char *address)
{
	unsigned i;

	for (i = 0; i < 30; i++) {
		TALLOC_CTX *tmp_ctx = talloc_new(tctx);
		struct cli_credentials *anon_creds = NULL;
		struct smbcli_options options;
		struct smb2_tree *tree = NULL;
		struct dcerpc_pipe *p = NULL;
		NTSTATUS status;

		torture_assert(tctx, tmp_ctx != NULL, "out of memory");

		anon_creds = cli_credentials_init_anon(tmp_ctx);
		torture_assert(tctx,
			       anon_creds != NULL,
			       "cli_credentials_init_anon failed");

		lpcfg_smbcli_options(tctx->lp_ctx, &options);

		status = smb2_connect(tmp_ctx,
				      address,
				      "IPC$",
				      tctx->lp_ctx,
				      lpcfg_resolve_context(tctx->lp_ctx,
							    tctx),
				      anon_creds,
				      &tree,
				      tctx->ev,
				      &options,
				      lpcfg_socket_options(tctx->lp_ctx),
				      lpcfg_gensec_settings(tctx,
							    tctx->lp_ctx));
		if (NT_STATUS_IS_OK(status)) {
			/*
			 * The IPC$ session is up - now make sure the RPC
			 * daemon behind \PIPE\spoolss is actually reachable
			 * (samba-dcerpcd may still be registering its
			 * endpoints at this point).
			 */
			p = dcerpc_pipe_init(tmp_ctx, tctx->ev);
			if (p == NULL) {
				status = NT_STATUS_NO_MEMORY;
			} else {
				status = dcerpc_pipe_open_smb2(p,
							       tree,
							       "spoolss");
			}
		}
		TALLOC_FREE(tmp_ctx);
		if (NT_STATUS_IS_OK(status)) {
			torture_comment(tctx,
					"wait_for_smb_ready(%s): ready after "
					"%u attempt(s)\n",
					address,
					i + 1);
			return true;
		}

		torture_comment(tctx,
				"wait_for_smb_ready(%s): attempt %u: %s\n",
				address,
				i + 1,
				nt_errstr(status));

		notify_test_wait(tctx->ev, 1);
	}

	return false;
}

/*
 * Spin up a throwaway smbd + samba-dcerpcd pair that plays the role of the
 * "client machine" a real spoolss server calls back to (over SMB, via
 * \PIPE\spoolss) after RemoteFindFirstPrinterChangeNotifyEx. The callback
 * itself is handled by the rpcd_spoolss_notify_test helper (source3), which
 * logs the opnums it receives to env->packet_log.
 */
static bool test_start_dcerpc_server(struct torture_context *tctx,
				     struct tevent_context *event_ctx,
				     struct notify_test_env *env)
{
	char *tempdir = NULL;
	const char *conf_path = NULL;
	const char *ncalrpc_np;
	struct interface *ifaces;
	const char *dcerpcd_path, *smbd_path;

	torture_assert(tctx,
		       notify_test_short_temp_dir(tctx, env, &tempdir),
		       "");
	env->tempdir = tempdir;

	torture_assert(tctx,
		       mkdir(talloc_asprintf(tctx, "%s/private", tempdir),
			     0700) == 0,
		       "mkdir private failed");
	torture_assert(tctx,
		       mkdir(talloc_asprintf(tctx, "%s/lock", tempdir),
			     0700) == 0,
		       "mkdir lock failed");
	torture_assert(tctx,
		       mkdir(talloc_asprintf(tctx, "%s/pid", tempdir), 0700) ==
			       0,
		       "mkdir pid failed");

	load_interface_list(tctx, tctx->lp_ctx, &ifaces);
	env->address = iface_list_first_v4(ifaces);
	torture_comment(tctx, "Listening for callbacks on %s\n", env->address);

	env->packet_log = talloc_asprintf(tctx, "%s/packets.log", tempdir);
	torture_assert(tctx, env->packet_log != NULL, "out of memory");

	torture_assert(tctx,
		       write_notify_test_smbconf(tctx,
						 tempdir,
						 env->address,
						 env->packet_log,
						 &conf_path),
		       "unable to write throwaway smb.conf");

	/*
	 * rpcd_spoolss_notify_test listens on \spoolss, so we have to
	 * start samba-dcerpcd manually without --libexec-rpcds. This
	 * would race with rpcd_spoolss.
	 */
	dcerpcd_path = talloc_asprintf(tctx,
				       "%s/samba-dcerpcd",
				       dyn_SAMBA_LIBEXECDIR);
	torture_assert(tctx, dcerpcd_path != NULL, "out of memory");

	env->dcerpcd_req = samba_runcmd_send(
		env,
		event_ctx,
		timeval_zero(),
		0,
		0,
		(const char *const[]){dcerpcd_path, NULL},
		talloc_asprintf(tctx, "--configfile=%s", conf_path),
		"--foreground",
		talloc_asprintf(tctx,
				"%s/rpcd_spoolss_notify_test",
				dyn_SAMBA_LIBEXECDIR),
		NULL);
	torture_assert(tctx,
		       env->dcerpcd_req != NULL,
		       "unable to start samba-dcerpcd");
	notify_test_watch_child(tctx, env->dcerpcd_req, "samba-dcerpcd");

	ncalrpc_np = talloc_asprintf(tctx, "%s/n/np/spoolss", tempdir);
	if (!wait_for_unix_socket(tctx, ncalrpc_np)) {
		dump_notify_test_diagnostics(tctx, tempdir);
		torture_fail(tctx,
			     "samba-dcerpcd never registered a spoolss "
			     "listener");
	}

	smbd_path = talloc_asprintf(tctx, "%s/smbd", dyn_SBINDIR);
	torture_assert(tctx, smbd_path != NULL, "out of memory");

	env->smbd_req = samba_runcmd_send(
		env,
		event_ctx,
		timeval_zero(),
		0,
		0,
		(const char *const[]){smbd_path, NULL},
		talloc_asprintf(tctx, "--configfile=%s", conf_path),
		"--foreground",
		"--option=server role check:inhibit=yes",
		NULL);
	torture_assert(tctx, env->smbd_req != NULL, "unable to start smbd");
	notify_test_watch_child(tctx, env->smbd_req, "smbd");

	if (!wait_for_smb_ready(tctx, env->address)) {
		dump_notify_test_diagnostics(tctx, tempdir);
		torture_fail(tctx,
			     "throwaway smbd never became ready to service "
			     "an anonymous IPC$ connection");
	}

	return true;
}

static bool read_notify_test_opnums(struct torture_context *tctx,
				    const char *packet_log,
				    uint16_t *first,
				    uint16_t *last)
{
	char **lines;
	int numlines;

	lines = file_lines_load(packet_log, &numlines, 0, tctx);
	if (lines == NULL || numlines == 0) {
		talloc_free(lines);
		return false;
	}

	*first = (uint16_t)strtoul(lines[0], NULL, 10);
	*last = (uint16_t)strtoul(lines[numlines - 1], NULL, 10);
	talloc_free(lines);

	return true;
}

static bool test_RFFPCNEx(struct torture_context *tctx,
			  struct dcerpc_pipe *p)
{
	struct notify_test_env *env = talloc_zero(tctx,
						  struct notify_test_env);
	struct policy_handle handle;
	uint16_t first_opnum, last_opnum;
	struct spoolss_NotifyOption *server_option = setup_printserver_NotifyOption(tctx);
#if 0
	struct spoolss_NotifyOption *printer_option = setup_printer_NotifyOption(tctx);
#endif
	struct dcerpc_binding_handle *b = p->binding_handle;
	const char *printername = NULL;
	struct spoolss_NotifyInfo *info = NULL;

	torture_assert(tctx, env != NULL, "out of memory");

	/* Start the fake "client machine" smbd/samba-dcerpcd pair */
	torture_assert(tctx,
		       test_start_dcerpc_server(tctx, tctx->ev, env),
		       "");

	printername	= talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	torture_assert(tctx, test_OpenPrinter(tctx, p, &handle, printername), "");
	torture_assert(tctx,
		       test_RemoteFindFirstPrinterChangeNotifyEx(
			       tctx, b, &handle, env->address, server_option),
		       "");
	torture_assert(tctx,
		       read_notify_test_opnums(tctx,
					       env->packet_log,
					       &first_opnum,
					       &last_opnum),
		       "no packets received");
	torture_assert_int_equal(tctx,
				 first_opnum,
				 NDR_SPOOLSS_REPLYOPENPRINTER,
				 "no ReplyOpenPrinter packet after "
				 "RemoteFindFirstPrinterChangeNotifyEx");
	torture_assert(tctx, test_RouterRefreshPrinterChangeNotify(tctx, b, &handle, NULL, &info), "");
	torture_assert(tctx, test_RouterRefreshPrinterChangeNotify(tctx, b, &handle, server_option, &info), "");
	torture_assert(tctx, test_ClosePrinter(tctx, b, &handle), "");
	torture_assert(tctx,
		       read_notify_test_opnums(tctx,
					       env->packet_log,
					       &first_opnum,
					       &last_opnum),
		       "no packets received");
	torture_assert_int_equal(
		tctx,
		last_opnum,
		NDR_SPOOLSS_REPLYCLOSEPRINTER,
		"no ReplyClosePrinter packet after ClosePrinter");
#if 0
	printername	= talloc_asprintf(tctx, "\\\\%s\\%s", dcerpc_server_name(p), name);

	torture_assert(tctx, test_OpenPrinter(tctx, p, &handle, "Epson AL-2600"), "");
	torture_assert(tctx, test_RemoteFindFirstPrinterChangeNotifyEx(tctx, p, &handle, address, printer_option), "");
	tmp = last_packet(received_packets);
	torture_assert_int_equal(tctx, tmp->opnum, NDR_SPOOLSS_REPLYOPENPRINTER,
		"no ReplyOpenPrinter packet after RemoteFindFirstPrinterChangeNotifyEx");
	torture_assert(tctx, test_RouterRefreshPrinterChangeNotify(tctx, p, &handle, NULL, &info), "");
	torture_assert(tctx, test_RouterRefreshPrinterChangeNotify(tctx, p, &handle, printer_option, &info), "");
	torture_assert(tctx, test_SetPrinter(tctx, p, &handle), "");
	tmp = last_packet(received_packets);
	torture_assert_int_equal(tctx, tmp->opnum, NDR_SPOOLSS_ROUTERREPLYPRINTEREX,
		"no RouterReplyPrinterEx packet after ClosePrinter");
	torture_assert(tctx, test_ClosePrinter(tctx, p, &handle), "");
	tmp = last_packet(received_packets);
	torture_assert_int_equal(tctx, tmp->opnum, NDR_SPOOLSS_REPLYCLOSEPRINTER,
		"no ReplyClosePrinter packet after ClosePrinter");
#endif
	{
		char *tempdir = talloc_move(tctx, &env->tempdir);

		TALLOC_FREE(env); /* shut down throwaway smbd/samba-dcerpcd */
		torture_local_deltree(tempdir);
		TALLOC_FREE(tempdir);
	}

	return true;
}

/** Test that makes sure that calling ReplyOpenPrinter()
 * on Samba 4 will cause an irpc broadcast call.
 */
static bool test_ReplyOpenPrinter(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	struct spoolss_ReplyOpenPrinter r;
	struct spoolss_ReplyClosePrinter s;
	struct policy_handle h;
	struct dcerpc_binding_handle *b = p->binding_handle;

	if (torture_setting_bool(tctx, "samba3", false)) {
		torture_skip(tctx, "skipping ReplyOpenPrinter server implementation test against s3\n");
	}

	r.in.server_name = "earth";
	r.in.printer_local = 2;
	r.in.type = REG_DWORD;
	r.in.bufsize = 0;
	r.in.buffer = NULL;
	r.out.handle = &h;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_spoolss_ReplyOpenPrinter_r(b, tctx, &r),
			"spoolss_ReplyOpenPrinter call failed");

	torture_assert_werr_ok(tctx, r.out.result, "error return code");

	s.in.handle = &h;
	s.out.handle = &h;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_spoolss_ReplyClosePrinter_r(b, tctx, &s),
			"spoolss_ReplyClosePrinter call failed");

	torture_assert_werr_ok(tctx, r.out.result, "error return code");

	return true;
}

struct torture_suite *torture_rpc_spoolss_notify(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "spoolss.notify");

	struct torture_rpc_tcase *tcase = torture_suite_add_rpc_iface_tcase(suite,
							"notify", &ndr_table_spoolss);

	torture_rpc_tcase_add_test(tcase, "testRFFPCNEx", test_RFFPCNEx);
	torture_rpc_tcase_add_test(tcase, "testReplyOpenPrinter", test_ReplyOpenPrinter);

	return suite;
}
