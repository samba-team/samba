/* 
   Unix SMB/CIFS implementation.

   libcli composite function testing

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
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
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

#define BASEDIR "\\composite"

static void loadfile_complete(struct smbcli_composite *c)
{
	int *count = talloc_get_type(c->async.private, int);
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
	struct smbcli_composite **c;
	char *data;
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

	c = talloc_array(mem_ctx, struct smbcli_composite *, num_ops);

	for (i=0;i<num_ops;i++) {
		c[i] = smb_composite_loadfile_send(cli->tree, &io2);
		c[i]->async.fn = loadfile_complete;
		c[i]->async.private = count;
	}

	printf("waiting for completion\n");
	while (*count != num_ops) {
		event_loop_once(cli->transport->socket->event.ctx);
		printf("count=%d\r", *count);
		fflush(stdout);
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
			       io2.out.size, len);
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
   basic testing of libcli composite calls
*/
BOOL torture_raw_composite(void)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_composite");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_loadfile(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
