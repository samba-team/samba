/* 
   Unix SMB/CIFS implementation.
   RAW_SEARCH_* individual test suite
   Copyright (C) Andrew Tridgell 2003
   
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


/*
  callback function for single_search
*/
static BOOL single_search_callback(void *private, union smb_search_data *file)
{
	union smb_search_data *data = private;

	*data = *file;

	return True;
}

/*
  do a single file (non-wildcard) search 
*/
static NTSTATUS single_search(struct cli_state *cli, 
			      TALLOC_CTX *mem_ctx,
			      const char *pattern,
			      enum search_level level,
			      union smb_search_data *data)
{
	union smb_search_first io;
	NTSTATUS status;

	io.generic.level = level;
	if (level == RAW_SEARCH_SEARCH) {
		io.search_first.in.max_count = 1;
		io.search_first.in.search_attrib = 0;
		io.search_first.in.pattern = pattern;
	} else {
		io.t2ffirst.in.search_attrib = 0;
		io.t2ffirst.in.max_count = 1;
		io.t2ffirst.in.flags = FLAG_TRANS2_FIND_CLOSE;
		io.t2ffirst.in.storage_type = 0;
		io.t2ffirst.in.pattern = pattern;
	}

	status = smb_raw_search_first(cli->tree, mem_ctx,
				      &io, (void *)data, single_search_callback);
	
	return status;
}


static struct {
	const char *name;
	enum search_level level;
	NTSTATUS status;
	union smb_search_data data;
} levels[] = {
	{"SEARCH",              RAW_SEARCH_SEARCH, },
	{"STANDARD",            RAW_SEARCH_STANDARD, },
	{"EA_SIZE",             RAW_SEARCH_EA_SIZE, },
	{"DIRECTORY_INFO",      RAW_SEARCH_DIRECTORY_INFO, },
	{"FULL_DIRECTORY_INFO", RAW_SEARCH_FULL_DIRECTORY_INFO, },
	{"NAME_INFO",           RAW_SEARCH_NAME_INFO, },
	{"BOTH_DIRECTORY_INFO", RAW_SEARCH_BOTH_DIRECTORY_INFO, },
	{"ID_FULL_DIRECTORY_INFO", RAW_SEARCH_ID_FULL_DIRECTORY_INFO, },
	{"ID_BOTH_DIRECTORY_INFO", RAW_SEARCH_ID_BOTH_DIRECTORY_INFO, }
};

/* find a level in the table by name */
static union smb_search_data *find(const char *name)
{
	int i;
	for (i=0;levels[i].name;i++) {
		if (NT_STATUS_IS_OK(levels[i].status) && 
		    strcmp(levels[i].name, name) == 0) {
			return &levels[i].data;
		}
	}
	return NULL;
}

/* 
   basic testing of all RAW_SEARCH_* calls 
*/
BOOL torture_search(int dummy)
{
	struct cli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	int fnum;
	const char *fname = "\\torture_search.txt";
	NTSTATUS status;
	int i;
	union smb_fileinfo all_info, alt_info, name_info;
	union smb_search_data *s;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_search");

	fnum = create_complex_file(cli, mem_ctx, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, cli_errstr(cli));
		ret = False;
		goto done;
	}

	/* call all the levels */
	for (i=0;levels[i].name;i++) {
		levels[i].status = single_search(cli, mem_ctx, fname, 
						 levels[i].level, &levels[i].data);
		if (!NT_STATUS_IS_OK(levels[i].status)) {
			printf("search level %s(%d) failed - %s\n",
			       levels[i].name, (int)levels[i].level, 
			       nt_errstr(levels[i].status));
			ret = False;
		}
	}

	/* get the all_info file into to check against */
	all_info.generic.level = RAW_FILEINFO_ALL_INFO;
	all_info.generic.in.fname = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &all_info);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RAW_FILEINFO_ALL_INFO failed - %s\n", nt_errstr(status));
		ret = False;
		goto done;
	}

	alt_info.generic.level = RAW_FILEINFO_ALT_NAME_INFO;
	alt_info.generic.in.fname = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &alt_info);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RAW_FILEINFO_ALT_NAME_INFO failed - %s\n", nt_errstr(status));
		ret = False;
		goto done;
	}

	name_info.generic.level = RAW_FILEINFO_NAME_INFO;
	name_info.generic.in.fname = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &name_info);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RAW_FILEINFO_NAME_INFO failed - %s\n", nt_errstr(status));
		ret = False;
		goto done;
	}

#define CHECK_VAL(name, sname1, field1, v, sname2, field2) do { \
	s = find(name); \
	if (s) { \
		if (s->sname1.field1 != v.sname2.out.field2) { \
			printf("(%d) %s/%s [%d] != %s/%s [%d]\n", \
			       __LINE__, \
				#sname1, #field1, (int)s->sname1.field1, \
				#sname2, #field2, (int)v.sname2.out.field2); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_TIME(name, sname1, field1, v, sname2, field2) do { \
	s = find(name); \
	if (s) { \
		if (s->sname1.field1 != (~1 & nt_time_to_unix(&v.sname2.out.field2))) { \
			printf("(%d) %s/%s [%s] != %s/%s [%s]\n", \
			       __LINE__, \
				#sname1, #field1, time_string(mem_ctx, s->sname1.field1), \
				#sname2, #field2, nt_time_string(mem_ctx, &v.sname2.out.field2)); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_NTTIME(name, sname1, field1, v, sname2, field2) do { \
	s = find(name); \
	if (s) { \
		if (memcmp(&s->sname1.field1, &v.sname2.out.field2, sizeof(NTTIME))) { \
			printf("(%d) %s/%s [%s] != %s/%s [%s]\n", \
			       __LINE__, \
				#sname1, #field1, nt_time_string(mem_ctx, &s->sname1.field1), \
				#sname2, #field2, nt_time_string(mem_ctx, &v.sname2.out.field2)); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_STR(name, sname1, field1, v, sname2, field2) do { \
	s = find(name); \
	if (s) { \
		if (!s->sname1.field1 || strcmp(s->sname1.field1, v.sname2.out.field2.s)) { \
			printf("(%d) %s/%s [%s] != %s/%s [%s]\n", \
			       __LINE__, \
				#sname1, #field1, s->sname1.field1, \
				#sname2, #field2, v.sname2.out.field2.s); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_WSTR(name, sname1, field1, v, sname2, field2, flags) do { \
	s = find(name); \
	if (s) { \
		if (!s->sname1.field1.s || \
		    strcmp(s->sname1.field1.s, v.sname2.out.field2.s) || \
		    wire_bad_flags(&s->sname1.field1, flags)) { \
			printf("(%d) %s/%s [%s] != %s/%s [%s]\n", \
			       __LINE__, \
				#sname1, #field1, s->sname1.field1.s, \
				#sname2, #field2, v.sname2.out.field2.s); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_NAME(name, sname1, field1, fname, flags) do { \
	s = find(name); \
	if (s) { \
		if (!s->sname1.field1.s || \
		    strcmp(s->sname1.field1.s, fname) || \
		    wire_bad_flags(&s->sname1.field1, flags)) { \
			printf("(%d) %s/%s [%s] != %s\n", \
			       __LINE__, \
				#sname1, #field1, s->sname1.field1.s, \
				fname); \
			ret = False; \
		} \
	}} while (0)
	
	/* check that all the results are as expected */
	CHECK_VAL("SEARCH",              search,              attrib, all_info, all_info, attrib);
	CHECK_VAL("STANDARD",            standard,            attrib, all_info, all_info, attrib);
	CHECK_VAL("EA_SIZE",             ea_size,             attrib, all_info, all_info, attrib);
	CHECK_VAL("DIRECTORY_INFO",      directory_info,      attrib, all_info, all_info, attrib);
	CHECK_VAL("FULL_DIRECTORY_INFO", full_directory_info, attrib, all_info, all_info, attrib);
	CHECK_VAL("BOTH_DIRECTORY_INFO", both_directory_info, attrib, all_info, all_info, attrib);
	CHECK_VAL("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           attrib, all_info, all_info, attrib);
	CHECK_VAL("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           attrib, all_info, all_info, attrib);

	CHECK_TIME("SEARCH",             search,              write_time, all_info, all_info, write_time);
	CHECK_TIME("STANDARD",           standard,            write_time, all_info, all_info, write_time);
	CHECK_TIME("EA_SIZE",            ea_size,             write_time, all_info, all_info, write_time);
	CHECK_TIME("STANDARD",           standard,            create_time, all_info, all_info, create_time);
	CHECK_TIME("EA_SIZE",            ea_size,             create_time, all_info, all_info, create_time);
	CHECK_TIME("STANDARD",           standard,            access_time, all_info, all_info, access_time);
	CHECK_TIME("EA_SIZE",            ea_size,             access_time, all_info, all_info, access_time);

	CHECK_NTTIME("DIRECTORY_INFO",      directory_info,      write_time, all_info, all_info, write_time);
	CHECK_NTTIME("FULL_DIRECTORY_INFO", full_directory_info, write_time, all_info, all_info, write_time);
	CHECK_NTTIME("BOTH_DIRECTORY_INFO", both_directory_info, write_time, all_info, all_info, write_time);
	CHECK_NTTIME("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           write_time, all_info, all_info, write_time);
	CHECK_NTTIME("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           write_time, all_info, all_info, write_time);

	CHECK_NTTIME("DIRECTORY_INFO",      directory_info,      create_time, all_info, all_info, create_time);
	CHECK_NTTIME("FULL_DIRECTORY_INFO", full_directory_info, create_time, all_info, all_info, create_time);
	CHECK_NTTIME("BOTH_DIRECTORY_INFO", both_directory_info, create_time, all_info, all_info, create_time);
	CHECK_NTTIME("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           create_time, all_info, all_info, create_time);
	CHECK_NTTIME("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           create_time, all_info, all_info, create_time);

	CHECK_NTTIME("DIRECTORY_INFO",      directory_info,      access_time, all_info, all_info, access_time);
	CHECK_NTTIME("FULL_DIRECTORY_INFO", full_directory_info, access_time, all_info, all_info, access_time);
	CHECK_NTTIME("BOTH_DIRECTORY_INFO", both_directory_info, access_time, all_info, all_info, access_time);
	CHECK_NTTIME("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           access_time, all_info, all_info, access_time);
	CHECK_NTTIME("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           access_time, all_info, all_info, access_time);

	CHECK_NTTIME("DIRECTORY_INFO",      directory_info,      create_time, all_info, all_info, create_time);
	CHECK_NTTIME("FULL_DIRECTORY_INFO", full_directory_info, create_time, all_info, all_info, create_time);
	CHECK_NTTIME("BOTH_DIRECTORY_INFO", both_directory_info, create_time, all_info, all_info, create_time);
	CHECK_NTTIME("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           create_time, all_info, all_info, create_time);
	CHECK_NTTIME("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           create_time, all_info, all_info, create_time);

	CHECK_VAL("SEARCH",              search,              size, all_info, all_info, size);
	CHECK_VAL("STANDARD",            standard,            size, all_info, all_info, size);
	CHECK_VAL("EA_SIZE",             ea_size,             size, all_info, all_info, size);
	CHECK_VAL("DIRECTORY_INFO",      directory_info,      size, all_info, all_info, size);
	CHECK_VAL("FULL_DIRECTORY_INFO", full_directory_info, size, all_info, all_info, size);
	CHECK_VAL("BOTH_DIRECTORY_INFO", both_directory_info, size, all_info, all_info, size);
	CHECK_VAL("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           size, all_info, all_info, size);
	CHECK_VAL("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           size, all_info, all_info, size);

	CHECK_VAL("STANDARD",            standard,            alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("EA_SIZE",             ea_size,             alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("DIRECTORY_INFO",      directory_info,      alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("FULL_DIRECTORY_INFO", full_directory_info, alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("BOTH_DIRECTORY_INFO", both_directory_info, alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           alloc_size, all_info, all_info, alloc_size);

	CHECK_VAL("EA_SIZE",             ea_size,             ea_size, all_info, all_info, ea_size);
	CHECK_VAL("FULL_DIRECTORY_INFO", full_directory_info, ea_size, all_info, all_info, ea_size);
	CHECK_VAL("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           ea_size, all_info, all_info, ea_size);
	CHECK_VAL("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           ea_size, all_info, all_info, ea_size);

	CHECK_STR("SEARCH", search, name, alt_info, alt_name_info, fname);
	CHECK_WSTR("BOTH_DIRECTORY_INFO", both_directory_info, short_name, alt_info, alt_name_info, fname, STR_UNICODE);

	CHECK_NAME("STANDARD",            standard,            name, fname+1, 0);
	CHECK_NAME("EA_SIZE",             ea_size,             name, fname+1, 0);
	CHECK_NAME("DIRECTORY_INFO",      directory_info,      name, fname+1, STR_TERMINATE_ASCII);
	CHECK_NAME("FULL_DIRECTORY_INFO", full_directory_info, name, fname+1, STR_TERMINATE_ASCII);
	CHECK_NAME("NAME_INFO",           name_info,           name, fname+1, STR_TERMINATE_ASCII);
	CHECK_NAME("BOTH_DIRECTORY_INFO", both_directory_info, name, fname+1, STR_TERMINATE_ASCII);
	CHECK_NAME("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           name, fname+1, STR_TERMINATE_ASCII);
	CHECK_NAME("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           name, fname+1, STR_TERMINATE_ASCII);

done:
	cli_close(cli, fnum);
	cli_unlink(cli, fname);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
