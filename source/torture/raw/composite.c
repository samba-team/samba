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

#define BASEDIR "\\composite"

static void loadfile_complete(struct composite_context *c)
{
	int *count = talloc_get_type(c->async.private_data, int);
	(*count)++;
}

/*
  test a simple savefile/loadfile combination
*/
static BOOL test_loadfile(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	const char *fname = BASEDIR "\\test.txt";
	NTSTATUS status;
	struct smb_composite_savefile io1;
	struct smb_composite_loadfile io2;
	struct composite_context **c;
	uint8_t *data;
	size_t len = random() % 100000;
	const int num_ops = 50;
	int i;
	int *count = talloc_zero(mem_ctx, int);

	data = talloc_array(mem_ctx, uint8_t, len);

	generate_random_buffer(data, len);

	io1.in.fname = fname;
	io1.in.data  = data;
	io1.in.size  = len;

	printf("testing savefile\n");

	status = smb_composite_savefile(cli->tree, &io1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("savefile failed: %s\n", nt_errstr(status));
		return False;
	}

	io2.in.fname = fname;

	printf("testing parallel loadfile with %d ops\n", num_ops);

	c = talloc_array(mem_ctx, struct composite_context *, num_ops);

	for (i=0;i<num_ops;i++) {
		c[i] = smb_composite_loadfile_send(cli->tree, &io2);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	printf("waiting for completion\n");
	while (*count != num_ops) {
		event_loop_once(cli->transport->socket->event.ctx);
		if (lp_parm_bool(-1, "torture", "progress", true)) {
			printf("count=%d\r", *count);
			fflush(stdout);
		}
	}
	printf("count=%d\n", *count);
	
	for (i=0;i<num_ops;i++) {
		status = smb_composite_loadfile_recv(c[i], mem_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			printf("loadfile[%d] failed - %s\n", i, nt_errstr(status));
			return False;
		}

		if (io2.out.size != len) {
			printf("wrong length in returned data - %d should be %d\n",
			       io2.out.size, (int)len);
			return False;
		}
		
		if (memcmp(io2.out.data, data, len) != 0) {
			printf("wrong data in loadfile!\n");
			return False;
		}
	}

	talloc_free(data);

	return True;
}

/*
  test a simple savefile/loadfile combination
*/
static BOOL test_fetchfile(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
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
	struct event_context *event_ctx;
	int *count = talloc_zero(mem_ctx, int);
	BOOL ret = True;

	data = talloc_array(mem_ctx, uint8_t, len);

	generate_random_buffer(data, len);

	io1.in.fname = fname;
	io1.in.data  = data;
	io1.in.size  = len;

	printf("testing savefile\n");

	status = smb_composite_savefile(cli->tree, &io1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("savefile failed: %s\n", nt_errstr(status));
		return False;
	}

	io2.in.dest_host = lp_parm_string(-1, "torture", "host");
	io2.in.port = 0;
	io2.in.called_name = lp_parm_string(-1, "torture", "host");
	io2.in.service = lp_parm_string(-1, "torture", "share");
	io2.in.service_type = "A:";

	io2.in.credentials = cmdline_credentials;
	io2.in.workgroup  = lp_workgroup();
	io2.in.filename = fname;

	printf("testing parallel fetchfile with %d ops\n", torture_numops);

	event_ctx = cli->transport->socket->event.ctx;
	c = talloc_array(mem_ctx, struct composite_context *, torture_numops);

	for (i=0; i<torture_numops; i++) {
		c[i] = smb_composite_fetchfile_send(&io2, event_ctx);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	printf("waiting for completion\n");

	while (*count != torture_numops) {
		event_loop_once(event_ctx);
		if (lp_parm_bool(-1, "torture", "progress", true)) {
			printf("count=%d\r", *count);
			fflush(stdout);
		}
	}
	printf("count=%d\n", *count);

	for (i=0;i<torture_numops;i++) {
		status = smb_composite_fetchfile_recv(c[i], mem_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			printf("loadfile[%d] failed - %s\n", i,
			       nt_errstr(status));
			ret = False;
			continue;
		}

		if (io2.out.size != len) {
			printf("wrong length in returned data - %d "
			       "should be %d\n",
			       io2.out.size, (int)len);
			ret = False;
			continue;
		}
		
		if (memcmp(io2.out.data, data, len) != 0) {
			printf("wrong data in loadfile!\n");
			ret = False;
			continue;
		}
	}

	return ret;
}

/*
  test setfileacl
*/
static BOOL test_appendacl(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct smb_composite_appendacl **io;
	struct smb_composite_appendacl **io_orig;
	struct composite_context **c;
	struct event_context *event_ctx;

	struct security_descriptor *test_sd;
	struct security_ace *ace;
	struct dom_sid *test_sid;

	const int num_ops = 50;
	int *count = talloc_zero(mem_ctx, int);
	struct smb_composite_savefile io1;

	NTSTATUS status;
	int i;

	io_orig = talloc_array(mem_ctx, struct smb_composite_appendacl *, num_ops);

	printf ("creating %d empty files and getting their acls with appendacl\n", num_ops);

	for (i = 0; i < num_ops; i++) {
		io1.in.fname = talloc_asprintf(io_orig, BASEDIR "\\test%d.txt", i);
		io1.in.data  = NULL;
		io1.in.size  = 0;
	  
		status = smb_composite_savefile(cli->tree, &io1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("savefile failed: %s\n", nt_errstr(status));
			return False;
		}

		io_orig[i] = talloc (io_orig, struct smb_composite_appendacl);
		io_orig[i]->in.fname = talloc_steal(io_orig[i], io1.in.fname);
		io_orig[i]->in.sd = security_descriptor_initialise(io_orig[i]);
		status = smb_composite_appendacl(cli->tree, io_orig[i], io_orig[i]);
		if (!NT_STATUS_IS_OK(status)) {
			printf("appendacl failed: %s\n", nt_errstr(status));
			return False;
		}
	}
	

	/* fill Security Descriptor with aces to be added */

	test_sd = security_descriptor_initialise(mem_ctx);
	test_sid = dom_sid_parse_talloc (mem_ctx, "S-1-5-32-1234-5432");

	ace = talloc_zero(mem_ctx, struct security_ace);

	ace->type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace->flags = 0;
	ace->access_mask = SEC_STD_ALL;
	ace->trustee = *test_sid;

	status = security_descriptor_dacl_add(test_sd, ace);
	if (!NT_STATUS_IS_OK(status)) {
		printf("appendacl failed: %s\n", nt_errstr(status));
		return False;
	}

	/* set parameters for appendacl async call */

	printf("testing parallel appendacl with %d ops\n", num_ops);

	c = talloc_array(mem_ctx, struct composite_context *, num_ops);
	io = talloc_array(mem_ctx, struct  smb_composite_appendacl *, num_ops);

	for (i=0; i < num_ops; i++) {
		io[i] = talloc (io, struct smb_composite_appendacl);
		io[i]->in.sd = test_sd;
		io[i]->in.fname = talloc_asprintf(io[i], BASEDIR "\\test%d.txt", i);

		c[i] = smb_composite_appendacl_send(cli->tree, io[i]);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	event_ctx = talloc_reference(mem_ctx, cli->tree->session->transport->socket->event.ctx);
	printf("waiting for completion\n");
	while (*count != num_ops) {
		event_loop_once(event_ctx);
		if (lp_parm_bool(-1, "torture", "progress", true)) {
			printf("count=%d\r", *count);
			fflush(stdout);
		}
	}
	printf("count=%d\n", *count);

	for (i=0; i < num_ops; i++) {
		status = smb_composite_appendacl_recv(c[i], io[i]);
		if (!NT_STATUS_IS_OK(status)) {
			printf("appendacl[%d] failed - %s\n", i, nt_errstr(status));
			return False;
		}
		
		security_descriptor_dacl_add(io_orig[i]->out.sd, ace);
		if (!security_acl_equal(io_orig[i]->out.sd->dacl, io[i]->out.sd->dacl)) {
			printf("appendacl[%d] failed - needed acl isn't set\n", i);
			return False;
		}
	}
	

	talloc_free (ace);
	talloc_free (test_sid);
	talloc_free (test_sd);
		
	return True;
}

/* test a query FS info by asking for share's GUID */
static BOOL test_fsinfo(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	char *guid = NULL;
	NTSTATUS status;
	struct smb_composite_fsinfo io1;
	struct composite_context **c;

	int i;
	extern int torture_numops;
	struct event_context *event_ctx;
	int *count = talloc_zero(mem_ctx, int);
	BOOL ret = True;

	io1.in.dest_host = lp_parm_string(-1, "torture", "host");
	io1.in.port = 0;
	io1.in.called_name = lp_parm_string(-1, "torture", "host");
	io1.in.service = lp_parm_string(-1, "torture", "share");
	io1.in.service_type = "A:";
	io1.in.credentials = cmdline_credentials;
	io1.in.workgroup = lp_workgroup();
	io1.in.level = RAW_QFS_OBJECTID_INFORMATION;

	printf("testing parallel queryfsinfo [Object ID] with %d ops\n", torture_numops);

	event_ctx = talloc_reference(mem_ctx, cli->tree->session->transport->socket->event.ctx);
	c = talloc_array(mem_ctx, struct composite_context *, torture_numops);

	for (i=0; i<torture_numops; i++) {
		c[i] = smb_composite_fsinfo_send(cli->tree,&io1);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private_data = count;
	}

	printf("waiting for completion\n");

	while (*count < torture_numops) {
		event_loop_once(event_ctx);
		if (lp_parm_bool(-1, "torture", "progress", true)) {
			printf("count=%d\r", *count);
			fflush(stdout);
		}
	}
	printf("count=%d\n", *count);

	for (i=0;i<torture_numops;i++) {
		status = smb_composite_fsinfo_recv(c[i], mem_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			printf("fsinfo[%d] failed - %s\n", i, nt_errstr(status));
			ret = False;
			continue;
		}

		if (io1.out.fsinfo->generic.level != RAW_QFS_OBJECTID_INFORMATION) {
			printf("wrong level in returned info - %d "
			       "should be %d\n",
			       io1.out.fsinfo->generic.level, RAW_QFS_OBJECTID_INFORMATION);
			ret = False;
			continue;
		}

		guid=GUID_string(mem_ctx, &io1.out.fsinfo->objectid_information.out.guid);
		printf("[%d] GUID: %s\n", i, guid);

		
	}

	return ret;
}


/* 
   basic testing of libcli composite calls
*/
bool torture_raw_composite(struct torture_context *tctx, 
						   struct smbcli_state *cli)
{
	bool ret = true;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_fetchfile(cli, tctx);
	ret &= test_loadfile(cli, tctx);
 	ret &= test_appendacl(cli, tctx);
	ret &= test_fsinfo(cli, tctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}
