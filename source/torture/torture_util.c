/* 
   Unix SMB/CIFS implementation.
   SMB torture tester utility functions
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
#include "libcli/raw/libcliraw.h"
#include "system/shmem.h"
#include "system/time.h"


/*
  create a directory, returning a handle to it
*/
int create_directory_handle(struct smbcli_tree *tree, const char *dname)
{
	NTSTATUS status;
	union smb_open io;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("create_directory_handle");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SA_RIGHT_FILE_ALL_ACCESS;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = dname;

	status = smb_raw_open(tree, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return -1;
	}

	talloc_destroy(mem_ctx);
	return io.ntcreatex.out.fnum;
}

/*
  sometimes we need a fairly complex file to work with, so we can test
  all possible attributes. 
*/
int create_complex_file(struct smbcli_state *cli, TALLOC_CTX *mem_ctx, const char *fname)
{
	int fnum;
	char buf[7] = "abc";
	union smb_setfileinfo setfile;
	union smb_fileinfo fileinfo;
	time_t t = (time(NULL) & ~1);
	NTSTATUS status;

	smbcli_unlink(cli->tree, fname);
	fnum = smbcli_nt_create_full(cli->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS,
				  FILE_ATTRIBUTE_NORMAL,
				  NTCREATEX_SHARE_ACCESS_DELETE|
				  NTCREATEX_SHARE_ACCESS_READ|
				  NTCREATEX_SHARE_ACCESS_WRITE, 
				  NTCREATEX_DISP_OVERWRITE_IF,
				  0, 0);
	if (fnum == -1) return -1;

	smbcli_write(cli->tree, fnum, 0, buf, 0, sizeof(buf));

	/* setup some EAs */
	setfile.generic.level = RAW_SFILEINFO_EA_SET;
	setfile.generic.file.fnum = fnum;
	setfile.ea_set.in.ea.flags = 0;
	setfile.ea_set.in.ea.name.s = "EAONE";
	setfile.ea_set.in.ea.value = data_blob_talloc(mem_ctx, "VALUE1", 6);

	status = smb_raw_setfileinfo(cli->tree, &setfile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup EAs\n");
	}

	setfile.ea_set.in.ea.name.s = "SECONDEA";
	setfile.ea_set.in.ea.value = data_blob_talloc(mem_ctx, "ValueTwo", 8);
	status = smb_raw_setfileinfo(cli->tree, &setfile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup EAs\n");
	}

	/* make sure all the timestamps aren't the same, and are also 
	   in different DST zones*/
	setfile.generic.level = RAW_SFILEINFO_SETATTRE;
	setfile.generic.file.fnum = fnum;

	setfile.setattre.in.create_time = t + 9*30*24*60*60;
	setfile.setattre.in.access_time = t + 6*30*24*60*60;
	setfile.setattre.in.write_time  = t + 3*30*24*60*60;

	status = smb_raw_setfileinfo(cli->tree, &setfile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup file times - %s\n", nt_errstr(status));
	}

	/* make sure all the timestamps aren't the same */
	fileinfo.generic.level = RAW_FILEINFO_GETATTRE;
	fileinfo.generic.in.fnum = fnum;

	status = smb_raw_fileinfo(cli->tree, mem_ctx, &fileinfo);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to query file times - %s\n", nt_errstr(status));
	}

	if (setfile.setattre.in.create_time != fileinfo.getattre.out.create_time) {
		printf("create_time not setup correctly\n");
	}
	if (setfile.setattre.in.access_time != fileinfo.getattre.out.access_time) {
		printf("access_time not setup correctly\n");
	}
	if (setfile.setattre.in.write_time != fileinfo.getattre.out.write_time) {
		printf("write_time not setup correctly\n");
	}

	return fnum;
}



/* return a pointer to a anonymous shared memory segment of size "size"
   which will persist across fork() but will disappear when all processes
   exit 

   The memory is not zeroed 

   This function uses system5 shared memory. It takes advantage of a property
   that the memory is not destroyed if it is attached when the id is removed
   */
void *shm_setup(int size)
{
	int shmid;
	void *ret;

	shmid = shmget(IPC_PRIVATE, size, SHM_R | SHM_W);
	if (shmid == -1) {
		printf("can't get shared memory\n");
		exit(1);
	}
	ret = (void *)shmat(shmid, 0, 0);
	if (!ret || ret == (void *)-1) {
		printf("can't attach to shared memory\n");
		return NULL;
	}
	/* the following releases the ipc, but note that this process
	   and all its children will still have access to the memory, its
	   just that the shmid is no longer valid for other shm calls. This
	   means we don't leave behind lots of shm segments after we exit 

	   See Stevens "advanced programming in unix env" for details
	   */
	shmctl(shmid, IPC_RMID, 0);
	
	return ret;
}


/*
  check that a wire string matches the flags specified 
  not 100% accurate, but close enough for testing
*/
BOOL wire_bad_flags(WIRE_STRING *str, int flags, struct smbcli_state *cli)
{
	BOOL server_unicode;
	int len;
	if (!str || !str->s) return True;
	len = strlen(str->s);
	if (flags & STR_TERMINATE) len++;

	server_unicode = (cli->transport->negotiate.capabilities&CAP_UNICODE)?True:False;
	if (getenv("CLI_FORCE_ASCII") || !lp_unicode()) {
		server_unicode = False;
	}

	if ((flags & STR_UNICODE) || server_unicode) {
		len *= 2;
	} else if (flags & STR_TERMINATE_ASCII) {
		len++;
	}
	if (str->private_length != len) {
		printf("Expected wire_length %d but got %d for '%s'\n", 
		       len, str->private_length, str->s);
		return True;
	}
	return False;
}

/*
  check if 2 NTTIMEs are equal
*/
BOOL nt_time_equal(NTTIME *t1, NTTIME *t2)
{
	return *t1 == *t2;
}

/*
  dump a all_info QFILEINFO structure
*/
void dump_all_info(TALLOC_CTX *mem_ctx, union smb_fileinfo *finfo)
{
	d_printf("\tcreate_time:    %s\n", nt_time_string(mem_ctx, finfo->all_info.out.create_time));
	d_printf("\taccess_time:    %s\n", nt_time_string(mem_ctx, finfo->all_info.out.access_time));
	d_printf("\twrite_time:     %s\n", nt_time_string(mem_ctx, finfo->all_info.out.write_time));
	d_printf("\tchange_time:    %s\n", nt_time_string(mem_ctx, finfo->all_info.out.change_time));
	d_printf("\tattrib:         0x%x\n", finfo->all_info.out.attrib);
	d_printf("\talloc_size:     %llu\n", (uint64_t)finfo->all_info.out.alloc_size);
	d_printf("\tsize:           %llu\n", (uint64_t)finfo->all_info.out.size);
	d_printf("\tnlink:          %u\n", finfo->all_info.out.nlink);
	d_printf("\tdelete_pending: %u\n", finfo->all_info.out.delete_pending);
	d_printf("\tdirectory:      %u\n", finfo->all_info.out.directory);
	d_printf("\tea_size:        %u\n", finfo->all_info.out.ea_size);
	d_printf("\tfname:          '%s'\n", finfo->all_info.out.fname.s);
}

/*
  dump file infor by name
*/
void torture_all_info(struct smbcli_tree *tree, const char *fname)
{
	TALLOC_CTX *mem_ctx = talloc_init("%s", fname);
	union smb_fileinfo finfo;
	NTSTATUS status;

	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.fname = fname;
	status = smb_raw_pathinfo(tree, mem_ctx, &finfo);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s - %s\n", fname, nt_errstr(status));
		return;
	}

	d_printf("%s:\n", fname);
	dump_all_info(mem_ctx, &finfo);
	talloc_destroy(mem_ctx);
}


/*
  split a UNC name into server and share names
*/
BOOL split_unc_name(const char *unc, char **server, char **share)
{
	char *p = strdup(unc);
	if (!p) return False;
	all_string_sub(p, "\\", "/", 0);
	if (strncmp(p, "//", 2) != 0) return False;

	(*server) = p+2;
	p = strchr(*server, '/');
	if (!p) return False;

	*p = 0;
	(*share) = p+1;
	
	return True;
}

/*
  split a USER%PASS pair into username and password
*/
BOOL split_username(const char *pair, char **user, char **pass)
{
	char *p = strdup(pair);
	if (!p) return False;

	(*user) = p;

	p = strchr(*user, '%');
	if (!p) return False;

	*p = 0;
	(*pass) = p+1;
	
	return True;
}

/*
  set a attribute on a file
*/
BOOL torture_set_file_attribute(struct smbcli_tree *tree, const char *fname, uint16_t attrib)
{
	union smb_setfileinfo sfinfo;
	NTSTATUS status;

	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.generic.file.fname = fname;

	ZERO_STRUCT(sfinfo.basic_info.in);
	sfinfo.basic_info.in.attrib = attrib;
	status = smb_raw_setpathinfo(tree, &sfinfo);
	return NT_STATUS_IS_OK(status);
}


/*
  set a file descriptor as sparse
*/
NTSTATUS torture_set_sparse(struct smbcli_tree *tree, int fnum)
{
	union smb_ioctl nt;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("torture_set_sparse");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	nt.ntioctl.level = RAW_IOCTL_NTIOCTL;
	nt.ntioctl.in.function = 0x900c4;
	nt.ntioctl.in.fnum = fnum;
	nt.ntioctl.in.fsctl = True;
	nt.ntioctl.in.filter = 0;

	status = smb_raw_ioctl(tree, mem_ctx, &nt);

	talloc_destroy(mem_ctx);

	return status;
}
