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


#define BASEDIR "\\testsearch"

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
static NTSTATUS single_search(struct smbcli_state *cli, 
			      TALLOC_CTX *mem_ctx,
			      const char *pattern,
			      enum smb_search_level level,
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
	enum smb_search_level level;
	uint32_t capability_mask;
	NTSTATUS status;
	union smb_search_data data;
} levels[] = {
	{"SEARCH",                 RAW_SEARCH_SEARCH, },
	{"STANDARD",               RAW_SEARCH_STANDARD, },
	{"EA_SIZE",                RAW_SEARCH_EA_SIZE, },
	{"DIRECTORY_INFO",         RAW_SEARCH_DIRECTORY_INFO, },
	{"FULL_DIRECTORY_INFO",    RAW_SEARCH_FULL_DIRECTORY_INFO, },
	{"NAME_INFO",              RAW_SEARCH_NAME_INFO, },
	{"BOTH_DIRECTORY_INFO",    RAW_SEARCH_BOTH_DIRECTORY_INFO, },
	{"ID_FULL_DIRECTORY_INFO", RAW_SEARCH_ID_FULL_DIRECTORY_INFO, },
	{"ID_BOTH_DIRECTORY_INFO", RAW_SEARCH_ID_BOTH_DIRECTORY_INFO, },
	{"UNIX_INFO",              RAW_SEARCH_UNIX_INFO, CAP_UNIX}
};

/* find a level in the table by name */
static union smb_search_data *find(const char *name)
{
	int i;
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		if (NT_STATUS_IS_OK(levels[i].status) && 
		    strcmp(levels[i].name, name) == 0) {
			return &levels[i].data;
		}
	}
	return NULL;
}

/* 
   basic testing of all RAW_SEARCH_* calls using a single file
*/
static BOOL test_one_file(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	int fnum;
	const char *fname = "\\torture_search.txt";
	NTSTATUS status;
	int i;
	union smb_fileinfo all_info, alt_info, name_info, internal_info;
	union smb_search_data *s;

	printf("Testing one file searches\n");

	fnum = create_complex_file(cli, mem_ctx, fname);
	if (fnum == -1) {
		printf("ERROR: open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	/* call all the levels */
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		uint32_t cap = cli->transport->negotiate.capabilities;

		printf("testing %s\n", levels[i].name);

		levels[i].status = single_search(cli, mem_ctx, fname, 
						 levels[i].level, &levels[i].data);

		/* see if this server claims to support this level */
		if ((cap & levels[i].capability_mask) != levels[i].capability_mask) {
			printf("search level %s(%d) not supported by server\n",
			       levels[i].name, (int)levels[i].level);
			continue;
		}

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

	internal_info.generic.level = RAW_FILEINFO_INTERNAL_INFORMATION;
	internal_info.generic.in.fname = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &internal_info);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RAW_FILEINFO_INTERNAL_INFORMATION failed - %s\n", nt_errstr(status));
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
		if (s->sname1.field1 != (~1 & nt_time_to_unix(v.sname2.out.field2))) { \
			printf("(%d) %s/%s [%s] != %s/%s [%s]\n", \
			       __LINE__, \
				#sname1, #field1, timestring(mem_ctx, s->sname1.field1), \
				#sname2, #field2, nt_time_string(mem_ctx, v.sname2.out.field2)); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_NTTIME(name, sname1, field1, v, sname2, field2) do { \
	s = find(name); \
	if (s) { \
		if (s->sname1.field1 != v.sname2.out.field2) { \
			printf("(%d) %s/%s [%s] != %s/%s [%s]\n", \
			       __LINE__, \
				#sname1, #field1, nt_time_string(mem_ctx, s->sname1.field1), \
				#sname2, #field2, nt_time_string(mem_ctx, v.sname2.out.field2)); \
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
		    wire_bad_flags(&s->sname1.field1, flags, cli)) { \
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
		    wire_bad_flags(&s->sname1.field1, flags, cli)) { \
			printf("(%d) %s/%s [%s] != %s\n", \
			       __LINE__, \
				#sname1, #field1, s->sname1.field1.s, \
				fname); \
			ret = False; \
		} \
	}} while (0)

#define CHECK_UNIX_NAME(name, sname1, field1, fname, flags) do { \
	s = find(name); \
	if (s) { \
		if (!s->sname1.field1 || \
		    strcmp(s->sname1.field1, fname)) { \
			printf("(%d) %s/%s [%s] != %s\n", \
			       __LINE__, \
				#sname1, #field1, s->sname1.field1, \
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
	CHECK_VAL("UNIX_INFO",           unix_info,           size, all_info, all_info, size);

	CHECK_VAL("STANDARD",            standard,            alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("EA_SIZE",             ea_size,             alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("DIRECTORY_INFO",      directory_info,      alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("FULL_DIRECTORY_INFO", full_directory_info, alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("BOTH_DIRECTORY_INFO", both_directory_info, alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("ID_FULL_DIRECTORY_INFO", id_full_directory_info,           alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("ID_BOTH_DIRECTORY_INFO", id_both_directory_info,           alloc_size, all_info, all_info, alloc_size);
	CHECK_VAL("UNIX_INFO",           unix_info,           alloc_size, all_info, all_info, alloc_size);

	CHECK_VAL("EA_SIZE",             ea_size,             ea_size, all_info, all_info, ea_size);
	CHECK_VAL("FULL_DIRECTORY_INFO", full_directory_info, ea_size, all_info, all_info, ea_size);
	CHECK_VAL("BOTH_DIRECTORY_INFO", both_directory_info, ea_size, all_info, all_info, ea_size);
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
	CHECK_UNIX_NAME("UNIX_INFO",           unix_info,           name, fname+1, STR_TERMINATE_ASCII);

	CHECK_VAL("ID_FULL_DIRECTORY_INFO", id_full_directory_info, file_id, internal_info, internal_information, file_id);
	CHECK_VAL("ID_BOTH_DIRECTORY_INFO", id_both_directory_info, file_id, internal_info, internal_information, file_id);

done:
	smb_raw_exit(cli->session);
	smbcli_unlink(cli->tree, fname);

	return ret;
}


struct multiple_result {
	TALLOC_CTX *mem_ctx;
	int count;
	union smb_search_data *list;
};

/*
  callback function for multiple_search
*/
static BOOL multiple_search_callback(void *private, union smb_search_data *file)
{
	struct multiple_result *data = private;


	data->count++;
	data->list = talloc_realloc(data->mem_ctx, 
				    data->list, 
				    data->count * (sizeof(data->list[0])));

	data->list[data->count-1] = *file;

	return True;
}

enum continue_type {CONT_FLAGS, CONT_NAME, CONT_RESUME_KEY};

/*
  do a single file (non-wildcard) search 
*/
static NTSTATUS multiple_search(struct smbcli_state *cli, 
				TALLOC_CTX *mem_ctx,
				const char *pattern,
				enum smb_search_level level,
				enum continue_type cont_type,
				void *data)
{
	union smb_search_first io;
	union smb_search_next io2;
	NTSTATUS status;
	const int per_search = 300;
	struct multiple_result *result = data;

	io.generic.level = level;
	if (level == RAW_SEARCH_SEARCH) {
		io.search_first.in.max_count = per_search;
		io.search_first.in.search_attrib = 0;
		io.search_first.in.pattern = pattern;
	} else {
		io.t2ffirst.in.search_attrib = 0;
		io.t2ffirst.in.max_count = per_search;
		io.t2ffirst.in.flags = 0;
		io.t2ffirst.in.storage_type = 0;
		io.t2ffirst.in.pattern = pattern;
		if (cont_type == CONT_RESUME_KEY) {
			io.t2ffirst.in.flags = FLAG_TRANS2_FIND_REQUIRE_RESUME | 
				FLAG_TRANS2_FIND_BACKUP_INTENT;
		}
	}

	status = smb_raw_search_first(cli->tree, mem_ctx,
				      &io, data, multiple_search_callback);
	

	while (NT_STATUS_IS_OK(status)) {
		io2.generic.level = level;
		if (level == RAW_SEARCH_SEARCH) {
			io2.search_next.in.max_count = per_search;
			io2.search_next.in.search_attrib = 0;
			io2.search_next.in.search_id = result->list[result->count-1].search.search_id;
		} else {
			io2.t2fnext.in.handle = io.t2ffirst.out.handle;
			io2.t2fnext.in.max_count = per_search;
			io2.t2fnext.in.resume_key = 0;
			io2.t2fnext.in.flags = 0;
			io2.t2fnext.in.last_name = "";
			switch (cont_type) {
			case CONT_RESUME_KEY:
				if (level == RAW_SEARCH_STANDARD) {
					io2.t2fnext.in.resume_key = 
						result->list[result->count-1].standard.resume_key;
				} else if (level == RAW_SEARCH_EA_SIZE) {
					io2.t2fnext.in.resume_key = 
						result->list[result->count-1].ea_size.resume_key;
				} else if (level == RAW_SEARCH_DIRECTORY_INFO) {
					io2.t2fnext.in.resume_key = 
						result->list[result->count-1].directory_info.file_index;
				} else {
					io2.t2fnext.in.resume_key = 
						result->list[result->count-1].both_directory_info.file_index;
				}
				io2.t2fnext.in.flags = FLAG_TRANS2_FIND_REQUIRE_RESUME |
					FLAG_TRANS2_FIND_BACKUP_INTENT;
				break;
			case CONT_NAME:
				if (level == RAW_SEARCH_STANDARD) {
					io2.t2fnext.in.last_name = 
						result->list[result->count-1].standard.name.s;
				} else if (level == RAW_SEARCH_EA_SIZE) {
					io2.t2fnext.in.last_name = 
						result->list[result->count-1].ea_size.name.s;
				} else if (level == RAW_SEARCH_DIRECTORY_INFO) {
					io2.t2fnext.in.last_name = 
						result->list[result->count-1].directory_info.name.s;
				} else {
					io2.t2fnext.in.last_name = 
						result->list[result->count-1].both_directory_info.name.s;
				}
				break;
			case CONT_FLAGS:
				io2.t2fnext.in.flags = FLAG_TRANS2_FIND_CONTINUE;
				break;
			}
		}

		status = smb_raw_search_next(cli->tree, mem_ctx,
					     &io2, data, multiple_search_callback);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
		if (level == RAW_SEARCH_SEARCH) {
			if (io2.search_next.out.count == 0) {
				break;
			}
		} else if (io2.t2fnext.out.count == 0 ||
			   io2.t2fnext.out.end_of_search) {
			break;
		}
	}

	return status;
}

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%d) Incorrect value %s=%d - should be %d\n", \
		       __LINE__, #v, v, correct); \
		ret = False; \
	}} while (0)


static int search_both_compare(union smb_search_data *d1, union smb_search_data *d2)
{
	return strcmp_safe(d1->both_directory_info.name.s, d2->both_directory_info.name.s);
}

static int search_standard_compare(union smb_search_data *d1, union smb_search_data *d2)
{
	return strcmp_safe(d1->standard.name.s, d2->standard.name.s);
}

static int search_ea_size_compare(union smb_search_data *d1, union smb_search_data *d2)
{
	return strcmp_safe(d1->ea_size.name.s, d2->ea_size.name.s);
}

static int search_directory_info_compare(union smb_search_data *d1, union smb_search_data *d2)
{
	return strcmp_safe(d1->directory_info.name.s, d2->directory_info.name.s);
}

static int search_old_compare(union smb_search_data *d1, union smb_search_data *d2)
{
	return strcmp_safe(d1->search.name, d2->search.name);
}


/* 
   basic testing of search calls using many files
*/
static BOOL test_many_files(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	const int num_files = 700;
	int i, fnum, t;
	char *fname;
	BOOL ret = True;
	NTSTATUS status;
	struct multiple_result result;
	struct {
		const char *name;
		const char *cont_name;
		enum smb_search_level level;
		enum continue_type cont_type;
	} search_types[] = {
		{"BOTH_DIRECTORY_INFO", "NAME",  RAW_SEARCH_BOTH_DIRECTORY_INFO, CONT_NAME},
		{"BOTH_DIRECTORY_INFO", "FLAGS", RAW_SEARCH_BOTH_DIRECTORY_INFO, CONT_FLAGS},
		{"BOTH_DIRECTORY_INFO", "KEY",   RAW_SEARCH_BOTH_DIRECTORY_INFO, CONT_RESUME_KEY},
		{"STANDARD",            "FLAGS", RAW_SEARCH_STANDARD,            CONT_FLAGS},
		{"STANDARD",            "KEY",   RAW_SEARCH_STANDARD,            CONT_RESUME_KEY},
		{"STANDARD",            "NAME",  RAW_SEARCH_STANDARD,            CONT_NAME},
		{"EA_SIZE",             "FLAGS", RAW_SEARCH_EA_SIZE,             CONT_FLAGS},
		{"EA_SIZE",             "KEY",   RAW_SEARCH_EA_SIZE,             CONT_RESUME_KEY},
		{"EA_SIZE",             "NAME",  RAW_SEARCH_EA_SIZE,             CONT_NAME},
		{"DIRECTORY_INFO",      "FLAGS", RAW_SEARCH_DIRECTORY_INFO,      CONT_FLAGS},
		{"DIRECTORY_INFO",      "KEY",   RAW_SEARCH_DIRECTORY_INFO,      CONT_RESUME_KEY},
		{"DIRECTORY_INFO",      "NAME",  RAW_SEARCH_DIRECTORY_INFO,      CONT_NAME},
		{"SEARCH",              "ID",    RAW_SEARCH_SEARCH,              CONT_RESUME_KEY}
	};

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 || 
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	printf("Creating %d files\n", num_files);

	for (i=0;i<num_files;i++) {
		asprintf(&fname, BASEDIR "\\t%03d-%d.txt", i, i);
		fnum = smbcli_open(cli->tree, fname, O_CREAT|O_RDWR, DENY_NONE);
		if (fnum == -1) {
			printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
			ret = False;
			goto done;
		}
		free(fname);
		smbcli_close(cli->tree, fnum);
	}


	for (t=0;t<ARRAY_SIZE(search_types);t++) {
		ZERO_STRUCT(result);
		result.mem_ctx = mem_ctx;
	
		printf("Continue %s via %s\n", search_types[t].name, search_types[t].cont_name);

		status = multiple_search(cli, mem_ctx, BASEDIR "\\*.*", 
					 search_types[t].level,
					 search_types[t].cont_type,
					 &result);
	
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_VALUE(result.count, num_files);

		if (search_types[t].level == RAW_SEARCH_BOTH_DIRECTORY_INFO) {
			qsort(result.list, result.count, sizeof(result.list[0]), 
			      QSORT_CAST  search_both_compare);
		} else if (search_types[t].level == RAW_SEARCH_STANDARD) {
			qsort(result.list, result.count, sizeof(result.list[0]), 
			      QSORT_CAST search_standard_compare);
		} else if (search_types[t].level == RAW_SEARCH_EA_SIZE) {
			qsort(result.list, result.count, sizeof(result.list[0]), 
			      QSORT_CAST search_ea_size_compare);
		} else if (search_types[t].level == RAW_SEARCH_DIRECTORY_INFO) {
			qsort(result.list, result.count, sizeof(result.list[0]), 
			      QSORT_CAST search_directory_info_compare);
		} else {
			qsort(result.list, result.count, sizeof(result.list[0]), 
			      QSORT_CAST search_old_compare);
		}

		for (i=0;i<num_files;i++) {
			const char *s;
			if (search_types[t].level == RAW_SEARCH_BOTH_DIRECTORY_INFO) {
				s = result.list[i].both_directory_info.name.s;
			} else if (search_types[t].level == RAW_SEARCH_STANDARD) {
				s = result.list[i].standard.name.s;
			} else if (search_types[t].level == RAW_SEARCH_EA_SIZE) {
				s = result.list[i].ea_size.name.s;
			} else if (search_types[t].level == RAW_SEARCH_DIRECTORY_INFO) {
				s = result.list[i].directory_info.name.s;
			} else {
				s = result.list[i].search.name;
			}
			asprintf(&fname, "t%03d-%d.txt", i, i);
			if (strcmp(fname, s)) {
				printf("Incorrect name %s at entry %d\n", s, i);
				ret = False;
				break;
			}
			free(fname);
		}
	}

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}


/* 
   basic testing of all RAW_SEARCH_* calls using a single file
*/
BOOL torture_raw_search(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_search");

	if (!test_one_file(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_many_files(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	
	return ret;
}
