/* 
   Unix SMB/CIFS implementation.

   test alternate data streams

   Copyright (C) Andrew Tridgell 2004
   
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
#include "libcli/raw/libcliraw.h"
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "torture/util.h"

#define BASEDIR "\\teststreams"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, (int)v, (int)correct); \
		ret = false; \
	}} while (0)

/*
  check that a stream has the right contents
*/
static bool check_stream(struct smbcli_state *cli, const char *location,
			 TALLOC_CTX *mem_ctx,
			 const char *fname, const char *sname, 
			 const char *value)
{
	int fnum;
	const char *full_name;
	uint8_t *buf;
	ssize_t ret;

	full_name = talloc_asprintf(mem_ctx, "%s:%s", fname, sname);

	fnum = smbcli_open(cli->tree, full_name, O_RDONLY, DENY_NONE);

	if (value == NULL) {
		if (fnum != -1) {
			printf("(%s) should have failed stream open of %s\n",
			       location, full_name);
			return false;
		}
		return true;
	}
	    
	if (fnum == -1) {
		printf("(%s) Failed to open stream '%s' - %s\n",
		       location, full_name, smbcli_errstr(cli->tree));
		return false;
	}

	buf = talloc_array(mem_ctx, uint8_t, strlen(value)+11);
	
	ret = smbcli_read(cli->tree, fnum, buf, 0, strlen(value)+11);
	if (ret != strlen(value)) {
		printf("(%s) Failed to read %lu bytes from stream '%s' - got %d\n",
		       location, (long)strlen(value), full_name, (int)ret);
		return false;
	}

	if (memcmp(buf, value, strlen(value)) != 0) {
		printf("(%s) Bad data in stream\n", location);
		return false;
	}

	smbcli_close(cli->tree, fnum);
	return true;
}

static int qsort_string(const void *v1, const void *v2)
{
	char * const *s1 = v1;
	char * const *s2 = v2;
	return strcmp(*s1, *s2);
}

static int qsort_stream(const void *v1, const void *v2)
{
	const struct stream_struct * s1 = v1;
	const struct stream_struct * s2 = v2;
	return strcmp(s1->stream_name.s, s2->stream_name.s);
}

static bool check_stream_list(struct smbcli_state *cli, const char *fname,
			      int num_exp, const char **exp)
{
	union smb_fileinfo finfo;
	NTSTATUS status;
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(cli);
	char **exp_sort;
	struct stream_struct *stream_sort;
	bool ret = false;

	finfo.generic.level = RAW_FILEINFO_STREAM_INFO;
	finfo.generic.in.file.path = fname;

	status = smb_raw_pathinfo(cli->tree, tmp_ctx, &finfo);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "(%s) smb_raw_pathinfo failed: %s\n",
			  __location__, nt_errstr(status));
		goto fail;
	}

	if (finfo.stream_info.out.num_streams != num_exp) {
		d_fprintf(stderr, "(%s) expected %d streams, got %d\n",
			  __location__, num_exp,
			  finfo.stream_info.out.num_streams);
		goto fail;
	}

	exp_sort = talloc_memdup(tmp_ctx, exp, num_exp * sizeof(*exp));

	if (exp_sort == NULL) {
		goto fail;
	}

	qsort(exp_sort, num_exp, sizeof(*exp_sort), qsort_string);

	stream_sort = talloc_memdup(tmp_ctx, finfo.stream_info.out.streams,
				    finfo.stream_info.out.num_streams *
				    sizeof(*stream_sort));

	if (stream_sort == NULL) {
		goto fail;
	}

	qsort(stream_sort, finfo.stream_info.out.num_streams,
	      sizeof(*stream_sort), qsort_stream);

	for (i=0; i<num_exp; i++) {
		if (strcmp(exp_sort[i], stream_sort[i].stream_name.s) != 0) {
			d_fprintf(stderr, "(%s) expected stream name %s, got "
				  "%s\n", __location__, exp_sort[i],
				  stream_sort[i].stream_name.s);
			goto fail;
		}
	}

	ret = true;
 fail:
	talloc_free(tmp_ctx);
	return ret;
}

/*
  test basic io on streams
*/
static bool test_stream_io(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\stream.txt";
	const char *sname1, *sname2;
	bool ret = true;
	int fnum = -1;
	ssize_t retsize;

	const char *one[] = { "::$DATA" };
	const char *two[] = { "::$DATA", ":Second Stream:$DATA" };
	const char *three[] = { "::$DATA", ":Stream One:$DATA",
				":Second Stream:$DATA" };

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");
	sname2 = talloc_asprintf(mem_ctx, "%s:%s:$DaTa", fname, "Second Stream");

	printf("(%s) opening non-existant directory stream\n", __location__);
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = sname1;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);

	printf("(%s) creating a stream on a non-existant file\n", __location__);
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.fname = sname1;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	ret &= check_stream(cli, __location__, mem_ctx, fname, "Stream One", NULL);

	printf("(%s) check that open of base file is allowed\n", __location__);
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	printf("(%s) writing to stream\n", __location__);
	retsize = smbcli_write(cli->tree, fnum, 0, "test data", 0, 9);
	CHECK_VALUE(retsize, 9);

	smbcli_close(cli->tree, fnum);

	ret &= check_stream(cli, __location__, mem_ctx, fname, "Stream One", "test data");

	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.fname = sname1;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	printf("(%s) modifying stream\n", __location__);
	retsize = smbcli_write(cli->tree, fnum, 0, "MORE DATA ", 5, 10);
	CHECK_VALUE(retsize, 10);

	smbcli_close(cli->tree, fnum);

	ret &= check_stream(cli, __location__, mem_ctx, fname, "Stream One:$FOO", NULL);

	printf("(%s) creating a stream2 on a existing file\n", __location__);
	io.ntcreatex.in.fname = sname2;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	printf("(%s) modifying stream\n", __location__);
	retsize = smbcli_write(cli->tree, fnum, 0, "SECOND STREAM", 0, 13);
	CHECK_VALUE(retsize, 13);

	smbcli_close(cli->tree, fnum);

	ret &= check_stream(cli, __location__, mem_ctx, fname, "Stream One", "test MORE DATA ");
	ret &= check_stream(cli, __location__, mem_ctx, fname, "Stream One:$DATA", "test MORE DATA ");
	ret &= check_stream(cli, __location__, mem_ctx, fname, "Stream One:", NULL);
	ret &= check_stream(cli, __location__, mem_ctx, fname, "Second Stream", "SECOND STREAM");
	ret &= check_stream(cli, __location__, mem_ctx, fname, "Second Stream:$DATA", "SECOND STREAM");
	ret &= check_stream(cli, __location__, mem_ctx, fname, "Second Stream:", NULL);
	ret &= check_stream(cli, __location__, mem_ctx, fname, "Second Stream:$FOO", NULL);

	check_stream_list(cli, fname, 3, three);

	printf("(%s) deleting stream\n", __location__);
	status = smbcli_unlink(cli->tree, sname1);
	CHECK_STATUS(status, NT_STATUS_OK);

	check_stream_list(cli, fname, 2, two);

	printf("(%s) delete a stream via delete-on-close\n", __location__);
	io.ntcreatex.in.fname = sname2;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	
	smbcli_close(cli->tree, fnum);
	status = smbcli_unlink(cli->tree, sname2);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	check_stream_list(cli, fname, 1, one);

	printf("(%s) deleting file\n", __location__);
	status = smbcli_unlink(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}

/* 
   basic testing of streams calls
*/
bool torture_raw_streams(struct torture_context *torture, 
			 struct smbcli_state *cli)
{
	bool ret = true;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	ret &= test_stream_io(cli, torture);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}
