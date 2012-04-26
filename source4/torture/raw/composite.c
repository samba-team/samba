/* 
   Unix SMB/CIFS implementation.

   libcli composite function testing

   Copyright (C) Andrew Tridgell 2005
   
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
#include "torture/torture.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "libcli/security/security.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/cmdline/popt_common.h"
#include "torture/util.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "torture/raw/proto.h"

#define BASEDIR "\\composite"

static void loadfile_complete(struct composite_context *c)
{
	int *count = talloc_get_type(c->async.private_data, int);
	(*count)++;
}

/*
  test a simple savefile/loadfile combination
*/
static bool test_loadfile(struct torture_context *tctx, struct smbcli_state *cli)
{
	const char *fname = BASEDIR "\\test.txt";
	NTSTATUS status;
	struct smb_composite_savefile io1;
	struct smb_composite_loadfile *io2;
	struct composite_context **c;
	uint8_t *data;
	size_t len = random() % 100000;
	const int num_ops = 50;
	int i;
	int *count = talloc_zero(tctx, int);

	data = talloc_array(tctx, uint8_t, len);

	generate_random_buffer(data, len);

	io1.in.fname = fname;
	io1.in.data  = data;
	io1.in.size  = len;

	torture_comment(tctx, "Testing savefile\n");

	status = smb_composite_savefile(cli->tree, &io1);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "savefile failed");

	torture_comment(tctx, "Testing parallel loadfile with %d ops\n", num_ops);

	c = talloc_array(tctx, struct composite_context *, num_ops);
	io2 = talloc_zero_array(tctx, struct smb_composite_loadfile, num_ops);

	for (i=0;i<num_ops;i++) {
		io2[i].in.fname = fname;
		c[i] = smb_composite_loadfile_send(cli->tree, &io2[i]);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	torture_comment(tctx, "waiting for completion\n");
	while (*count != num_ops) {
		tevent_loop_once(tctx->ev);
		if (torture_setting_bool(tctx, "progress", true)) {
			torture_comment(tctx, "(%s) count=%d\r", __location__, *count);
			fflush(stdout);
		}
	}
	torture_comment(tctx, "count=%d\n", *count);
	
	for (i=0;i<num_ops;i++) {
		status = smb_composite_loadfile_recv(c[i], tctx);
		torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "loadfile failed");

		torture_assert_int_equal(tctx, io2[i].out.size, len, "wrong length in returned data");
		torture_assert_mem_equal(tctx, io2[i].out.data, data, len, "wrong data in loadfile");
	}

	talloc_free(data);

	return true;
}

static bool test_loadfile_t(struct torture_context *tctx, struct smbcli_state *cli)
{
	int ret;
	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "failed to setup " BASEDIR);

	ret = test_loadfile(tctx, cli);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
  test a simple savefile/loadfile combination
*/
static bool test_fetchfile(struct torture_context *tctx, struct smbcli_state *cli)
{
	const char *fname = BASEDIR "\\test.txt";
	NTSTATUS status;
	struct smb_composite_savefile io1;
	struct smb_composite_fetchfile io2;
	struct composite_context **c;
	uint8_t *data;
	int i;
	size_t len = random() % 10000;
	extern int torture_numops;
	struct tevent_context *event_ctx;
	int *count = talloc_zero(tctx, int);
	bool ret = true;

	data = talloc_array(tctx, uint8_t, len);

	generate_random_buffer(data, len);

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.data  = data;
	io1.in.size  = len;

	torture_comment(tctx, "Testing savefile\n");

	status = smb_composite_savefile(cli->tree, &io1);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "savefile failed");

	ZERO_STRUCT(io2);

	io2.in.dest_host = torture_setting_string(tctx, "host", NULL);
	io2.in.ports = lpcfg_smb_ports(tctx->lp_ctx);
	io2.in.called_name = torture_setting_string(tctx, "host", NULL);
	io2.in.service = torture_setting_string(tctx, "share", NULL);
	io2.in.service_type = "A:";
	io2.in.socket_options = lpcfg_socket_options(tctx->lp_ctx);

	io2.in.credentials = cmdline_credentials;
	io2.in.workgroup  = lpcfg_workgroup(tctx->lp_ctx);
	io2.in.filename = fname;
	lpcfg_smbcli_options(tctx->lp_ctx, &io2.in.options);
	lpcfg_smbcli_session_options(tctx->lp_ctx, &io2.in.session_options);
	io2.in.resolve_ctx = lpcfg_resolve_context(tctx->lp_ctx);
	io2.in.gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);

	torture_comment(tctx, "Testing parallel fetchfile with %d ops\n", torture_numops);

	event_ctx = tctx->ev;
	c = talloc_array(tctx, struct composite_context *, torture_numops);

	for (i=0; i<torture_numops; i++) {
		c[i] = smb_composite_fetchfile_send(&io2, event_ctx);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	torture_comment(tctx, "waiting for completion\n");

	while (*count != torture_numops) {
		tevent_loop_once(event_ctx);
		if (torture_setting_bool(tctx, "progress", true)) {
			torture_comment(tctx, "(%s) count=%d\r", __location__, *count);
			fflush(stdout);
		}
	}
	torture_comment(tctx, "count=%d\n", *count);

	for (i=0;i<torture_numops;i++) {
		status = smb_composite_fetchfile_recv(c[i], tctx);
		torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "loadfile failed");

		torture_assert_int_equal(tctx, io2.out.size, len, "wrong length in returned data");
		torture_assert_mem_equal(tctx, io2.out.data, data, len, "wrong data in loadfile");
	}

	return ret;
}

static bool test_fetchfile_t(struct torture_context *tctx, struct smbcli_state *cli)
{
	int ret;
	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "failed to setup " BASEDIR);
	ret = test_fetchfile(tctx, cli);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
  test setfileacl
*/
static bool test_appendacl(struct torture_context *tctx, struct smbcli_state *cli)
{
	struct smb_composite_appendacl **io;
	struct smb_composite_appendacl **io_orig;
	struct composite_context **c;
	struct tevent_context *event_ctx;

	struct security_descriptor *test_sd;
	struct security_ace *ace;
	struct dom_sid *test_sid;

	const int num_ops = 50;
	int *count = talloc_zero(tctx, int);
	struct smb_composite_savefile io1;

	NTSTATUS status;
	int i;

	io_orig = talloc_array(tctx, struct smb_composite_appendacl *, num_ops);

	printf ("creating %d empty files and getting their acls with appendacl\n", num_ops);

	for (i = 0; i < num_ops; i++) {
		io1.in.fname = talloc_asprintf(io_orig, BASEDIR "\\test%d.txt", i);
		io1.in.data  = NULL;
		io1.in.size  = 0;
	  
		status = smb_composite_savefile(cli->tree, &io1);
		torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "savefile failed");

		io_orig[i] = talloc (io_orig, struct smb_composite_appendacl);
		io_orig[i]->in.fname = talloc_steal(io_orig[i], io1.in.fname);
		io_orig[i]->in.sd = security_descriptor_initialise(io_orig[i]);
		status = smb_composite_appendacl(cli->tree, io_orig[i], io_orig[i]);
		torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "appendacl failed");
	}
	

	/* fill Security Descriptor with aces to be added */

	test_sd = security_descriptor_initialise(tctx);
	test_sid = dom_sid_parse_talloc (tctx, "S-1-5-32-1234-5432");

	ace = talloc_zero(tctx, struct security_ace);

	ace->type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace->flags = 0;
	ace->access_mask = SEC_STD_ALL;
	ace->trustee = *test_sid;

	status = security_descriptor_dacl_add(test_sd, ace);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "appendacl failed");

	/* set parameters for appendacl async call */

	torture_comment(tctx, "Testing parallel appendacl with %d ops\n", num_ops);

	c = talloc_array(tctx, struct composite_context *, num_ops);
	io = talloc_array(tctx, struct  smb_composite_appendacl *, num_ops);

	for (i=0; i < num_ops; i++) {
		io[i] = talloc (io, struct smb_composite_appendacl);
		io[i]->in.sd = test_sd;
		io[i]->in.fname = talloc_asprintf(io[i], BASEDIR "\\test%d.txt", i);

		c[i] = smb_composite_appendacl_send(cli->tree, io[i]);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	event_ctx = tctx->ev;
	torture_comment(tctx, "waiting for completion\n");
	while (*count != num_ops) {
		tevent_loop_once(event_ctx);
		if (torture_setting_bool(tctx, "progress", true)) {
			torture_comment(tctx, "(%s) count=%d\r", __location__, *count);
			fflush(stdout);
		}
	}
	torture_comment(tctx, "count=%d\n", *count);

	for (i=0; i < num_ops; i++) {
		status = smb_composite_appendacl_recv(c[i], io[i]);
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(tctx, "(%s) appendacl[%d] failed - %s\n", __location__, i, nt_errstr(status));
			return false;
		}
		
		security_descriptor_dacl_add(io_orig[i]->out.sd, ace);
		torture_assert(tctx,
			       security_acl_equal(io_orig[i]->out.sd->dacl,
						  io[i]->out.sd->dacl),
			       "appendacl failed - needed acl isn't set");
	}
	

	talloc_free (ace);
	talloc_free (test_sid);
	talloc_free (test_sd);
		
	return true;
}

static bool test_appendacl_t(struct torture_context *tctx, struct smbcli_state *cli)
{
	int ret;
	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "failed to setup " BASEDIR);
	ret = test_appendacl(tctx, cli);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/* test a query FS info by asking for share's GUID */
static bool test_fsinfo(struct torture_context *tctx, struct smbcli_state *cli)
{
	char *guid = NULL;
	NTSTATUS status;
	struct smb_composite_fsinfo io1;
	struct composite_context **c;

	int i;
	extern int torture_numops;
	struct tevent_context *event_ctx;
	int *count = talloc_zero(tctx, int);
	bool ret = true;

	io1.in.dest_host = torture_setting_string(tctx, "host", NULL);
	io1.in.dest_ports = lpcfg_smb_ports(tctx->lp_ctx);
	io1.in.socket_options = lpcfg_socket_options(tctx->lp_ctx);
	io1.in.called_name = torture_setting_string(tctx, "host", NULL);
	io1.in.service = torture_setting_string(tctx, "share", NULL);
	io1.in.service_type = "A:";
	io1.in.credentials = cmdline_credentials;
	io1.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
	io1.in.level = RAW_QFS_OBJECTID_INFORMATION;
	io1.in.gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);

	torture_comment(tctx, "Testing parallel queryfsinfo [Object ID] with %d ops\n",
			torture_numops);

	event_ctx = tctx->ev;
	c = talloc_array(tctx, struct composite_context *, torture_numops);

	for (i=0; i<torture_numops; i++) {
		c[i] = smb_composite_fsinfo_send(cli->tree, &io1, lpcfg_resolve_context(tctx->lp_ctx), event_ctx);
		torture_assert(tctx, c[i], "smb_composite_fsinfo_send failed!");
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	torture_comment(tctx, "waiting for completion\n");

	while (*count < torture_numops) {
		tevent_loop_once(event_ctx);
		if (torture_setting_bool(tctx, "progress", true)) {
			torture_comment(tctx, "(%s) count=%d\r", __location__, *count);
			fflush(stdout);
		}
	}
	torture_comment(tctx, "count=%d\n", *count);

	for (i=0;i<torture_numops;i++) {
		status = smb_composite_fsinfo_recv(c[i], tctx);
		torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK, "smb_composite_fsinfo_recv failed");

		torture_assert_int_equal(tctx, io1.out.fsinfo->generic.level, RAW_QFS_OBJECTID_INFORMATION, "wrong level in returned info");

		guid=GUID_string(tctx, &io1.out.fsinfo->objectid_information.out.guid);
		torture_comment(tctx, "[%d] GUID: %s\n", i, guid);
	}

	return ret;
}

static bool test_fsinfo_t(struct torture_context *tctx, struct smbcli_state *cli)
{
	int ret;
	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "failed to setup " BASEDIR);
	ret = test_fsinfo(tctx, cli);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
   basic testing of all RAW_SEARCH_* calls using a single file
*/
struct torture_suite *torture_raw_composite(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "composite");

	torture_suite_add_1smb_test(suite, "fetchfile", test_fetchfile_t);
	torture_suite_add_1smb_test(suite, "loadfile", test_loadfile_t);
	torture_suite_add_1smb_test(suite, "appendacl", test_appendacl_t);
	torture_suite_add_1smb_test(suite, "fsinfo", test_fsinfo_t);

	return suite;
}
