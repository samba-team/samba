/* 
   Unix SMB/CIFS implementation.
   SMB torture tester - DFS tests
   Copyright (C) James J Myers 2003  <myersjj@samba.org>
   
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

#define DFS_SERVER_COUNT 6
#define DFS_FILE_COUNT 8
extern char *host, *share, *password, *username;
static struct smbcli_client context;
static const char *sockops="TCP_NODELAY";

/*
 checks for correct DFS cluster support
 */
BOOL torture_dfs_basic(void)
{
	int current_server = 0;
	char *fname[DFS_FILE_COUNT];
	int file_server[DFS_FILE_COUNT];
	int fnum[DFS_FILE_COUNT];
	int i;
	const char *template = "\\\\%s\\%s\\dfstest%d.tmp";
	char *filedata;
	int server_count = 0;
	int connection_flags = SMBCLI_FULL_CONNECTION_USE_KERBEROS
				| SMBCLI_FULL_CONNECTION_USE_DFS
				;
	
	printf("starting dfs_basic_test\n");
	smbcli_client_initialize(&context, sockops, username, password, lp_workgroup(), connection_flags);

	if ((current_server = smbcli_dfs_open_connection(&context, host, share, connection_flags) < 0))
		return False;

	for (i=0; i < DFS_FILE_COUNT ; i++) {
		file_server[i] = 0;
		DEBUG(4,("host=%s share=%s cli host=%s cli share=%s\n",
			host, share, smbcli_state_get_host(context.cli[file_server[i]]),
			smbcli_state_get_share(context.cli[file_server[i]])));
		host = smbcli_state_get_host(context.cli[file_server[i]]);
		share = smbcli_state_get_share(context.cli[file_server[i]]);
		asprintf(&fname[i], template, host, share, i);
		DEBUG(3,("unlinking %s\n", fname[i]));
		smbcli_nt_unlink(&context, &file_server[i], fname[i], 0);
	}
	
	for (i=0; i < DFS_FILE_COUNT ; i++) {
		host = smbcli_state_get_host(context.cli[file_server[i]]);
		share = smbcli_state_get_share(context.cli[file_server[i]]);
		asprintf(&fname[i], template, host, share, i);
		DEBUG(3,("open %s on server %s(%d)\n",
			fname[i], host, file_server[i]));
		fnum[i] = smbcli_dfs_open(&context, &file_server[i], fname[i], O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
		if (fnum[i] == -1)
		{
			printf("open of %s failed (%s)\n", fname[i], smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}
		asprintf(&filedata, "%s %d", fname[i], fnum[i]);
		DEBUG(3,("write %d bytes (%s) to %s (fid %d) on server %s(%d)\n",
			strlen(filedata), filedata, fname[i], fnum[i],
			host, file_server[i]));
		if (smbcli_write(context.cli[file_server[i]], fnum[i], 0, filedata, 0, strlen(filedata)) != strlen(filedata))
		{
			printf("write failed (%s)\n", smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}

		if (!smbcli_close(context.cli[file_server[i]], fnum[i])) {
			printf("close of %s failed (%s)\n", fname[i], smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}
	}
	DEBUG(3,("used Dfs servers:"));
	for (i=0; i < DFS_SERVER_COUNT ; i++) {
		server_count++;
		DEBUG(3,(" %s(%d)",	smbcli_state_get_host(context.cli[file_server[i]]), i));
		if (!torture_close_connection(context.cli[i]))
			return False;
	}
	DEBUG(3,("\n"));

	printf("Passed dfstest, found and used %d Dfs servers\n", server_count);
	return True;
}

/*
 Check for correct DFS rename support.
 First test is simple rename, a la command line, explorer.
 Second test is simulation of MS Word edit/save file.
 */
BOOL torture_dfs_rename(int dummy)
{
	int current_server = -1;
	char *fname[DFS_FILE_COUNT];
	int file_server[DFS_FILE_COUNT];
	int fnum[DFS_FILE_COUNT];
	int i;
	const char *template = "\\\\%s\\%s\\dfstest%d.tmp";
	const char *template2orig = "\\\\%s\\%s\\dfstestorig.txt";
	const char *template2old = "\\\\%s\\%s\\~dfstestold.txt";
	const char *template2new = "\\\\%s\\%s\\~dfstestnew.txt";
	char *filedata, *newdata;
	int server_count = 0;
	int connection_flags = SMBCLI_FULL_CONNECTION_USE_KERBEROS
				| SMBCLI_FULL_CONNECTION_USE_DFS
				;

	printf("starting dfs_rename_test\n");
	smbcli_client_initialize(&context, sockops, username, password,
			      lp_workgroup(), connection_flags);
	
	if ((current_server = smbcli_dfs_open_connection(&context, host, share, connection_flags)) < 0)
		return False;
	
	for (i=0; i < DFS_FILE_COUNT ; i++) {
		file_server[i] = 0;
		slprintf(fname[i],sizeof(fstring)-1,template, host, share, i);
		DEBUG(3,("unlinking %s\n", fname[i]));
		smbcli_nt_unlink(&context, &file_server[i], fname[i], 0);
	}
	/* Simple rename test */
	for (i=0; i < 1 ; i++) {
		slprintf(fname[i],sizeof(fstring)-1,template,
			smbcli_state_get_host(context.cli[file_server[i]]),
			smbcli_state_get_share(context.cli[file_server[i]]), i);
		DEBUG(3,("open %s on server %s(%d)\n",
			fname[i], smbcli_state_get_host(context.cli[file_server[i]]), file_server[i]));
			
		fnum[i] = smbcli_dfs_open(&context, &file_server[i], fname[i], O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
		if (fnum[i] == -1) {
			printf("open of %s failed (%s)\n", fname[i], smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}
		asprintf(&filedata, "%s %d", fname[i], (int)getpid());
		DEBUG(3,("write %d bytes (%s) to %s (fid %d) on server %s(%d)\n",
			strlen(filedata), filedata, fname[i], fnum[i],
			smbcli_state_get_host(context.cli[file_server[i]]), file_server[i]));
		if (smbcli_write(context.cli[file_server[i]], fnum[i], 0, filedata, 0, strlen(filedata)) != strlen(filedata))
		{
			printf("write failed (%s)\n", smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}

		if (!smbcli_close(context.cli[file_server[i]], fnum[i])) {
			printf("close of %s failed (%s)\n", fname[i], smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}
	}
	// now attempt to rename the file
	DEBUG(3,("rename %s to %s on server %s(%d)\n",
			fname[0], fname[1], smbcli_state_get_host(context.cli[file_server[i]]), file_server[0]));
	if (!smbcli_dfs_rename(&context, &file_server[0], fname[0], fname[1])) {
		printf("rename of %s to %s failed (%s)\n", fname[0], fname[1], smbcli_errstr(context.cli[file_server[0]]));
		return False;
	}
	// clean up
	DEBUG(3,("used Dfs servers:"));
	for (i=0; i < DFS_SERVER_COUNT ; i++) {
		server_count++;
		DEBUG(3,(" %s(%d)",	smbcli_state_get_host(context.cli[file_server[i]]), i));
		if (!torture_close_connection(context.cli[i]))
			return False;
	}
	DEBUG(3,("\n"));
	printf("Dfstest: passed simple rename test\n");
	
	/* Now try more complicated test, a la MS Word.
	 * Open existing file (x) and read file and close.
	 * Then open, write to new temp name file (~x.new), close.
	 * Then rename old file name to old temp name file (~x.old).
	 * Then rename new temp name file to oroginal name (x). */
	smbcli_client_initialize(&context, sockops, username, password,
			      lp_workgroup(), connection_flags);
	
	if ((current_server = smbcli_dfs_open_connection(&context, host, share, connection_flags)) < 0)
		return False;	 
	slprintf(fname[0],sizeof(fname[0])-1,template2orig, host, share);
	slprintf(fname[1],sizeof(fname[1])-1,template2old, host, share);
	slprintf(fname[2],sizeof(fname[2])-1,template2new, host, share);
	for (i=0; i < DFS_FILE_COUNT ; i++) {
		file_server[i] = 0;
		fnum[i] = 0;
		DEBUG(3,("unlinking %s\n", fname[i]));
		smbcli_nt_unlink(&context, &file_server[i], fname[i], 0);
	}
	asprintf(&fname[0],template2orig,
			smbcli_state_get_host(context.cli[0]),
			smbcli_state_get_share(context.cli[0]), 0);
	asprintf(&fname[1],template2old,
			smbcli_state_get_host(context.cli[1]),
			smbcli_state_get_share(context.cli[1]), 1);
	asprintf(&fname[2],template2new,
			smbcli_state_get_host(context.cli[2]),
			smbcli_state_get_share(context.cli[2]), 2);
	DEBUG(3,("edit(MS Word) %s on server %s(%d)\n",
			fname[0], smbcli_state_get_host(context.cli[0]), file_server[0]));
	DEBUG(3,("open %s on server %s(%d)\n",
		fname[0], smbcli_state_get_host(context.cli[0]), file_server[0]));
			
	fnum[0] = smbcli_dfs_open(&context, &file_server[0], fname[0], O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum[0] == -1)
	{
		printf("open of %s failed (%s)\n", fname[0], smbcli_errstr(context.cli[file_server[0]]));
		return False;
	}
	slprintf(filedata, sizeof(fstring)-1, "%s %d", fname[0], (int)getpid());
	DEBUG(3,("write %d bytes (%s) to %s (fid %d) on server %s(%d)\n",
		strlen(filedata), filedata, fname[0], fnum[0],
		smbcli_state_get_host(context.cli[0]), file_server[0]));
	if (smbcli_write(context.cli[file_server[0]], fnum[0], 0, filedata, 0, strlen(filedata)) != strlen(filedata))
	{
		printf("write failed (%s)\n", smbcli_errstr(context.cli[file_server[0]]));
		return False;
	}
	// read data from original file
	DEBUG(3,("read %s (fid %d) on server %s(%d)\n",
		fname[0], fnum[0], smbcli_state_get_host(context.cli[0]), file_server[0]));
	if (smbcli_read(context.cli[file_server[0]], fnum[0], filedata, 0, strlen(filedata)) != strlen(filedata))
	{
		printf("read failed (%s)", smbcli_errstr(context.cli[file_server[0]]));
		return False;
	}
	DEBUG(3,("close %s on server %s(%d)\n",
		fname[0], smbcli_state_get_host(context.cli[0]), file_server[0]));
	if (!smbcli_close(context.cli[file_server[0]], fnum[0])) {
		printf("close of %s failed (%s)\n", fname[0], smbcli_errstr(context.cli[file_server[0]]));
		return False;
	}
	// open new temp file, write data
	DEBUG(3,("open %s on server %s(%d)\n",
		fname[2], smbcli_state_get_host(context.cli[2]), file_server[2]));
	fnum[2] = smbcli_dfs_open(&context, &file_server[2], fname[2], O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum[2] == -1)
	{
		printf("open of %s failed (%s)\n", fname[2], smbcli_errstr(context.cli[file_server[2]]));
		return False;
	}
	DEBUG(3,("write %d bytes (%s) to %s (fid %d) on server %s(%d)\n",
		strlen(filedata), filedata, fname[2], fnum[2],
		smbcli_state_get_host(context.cli[2]), file_server[2]));
	if (smbcli_write(context.cli[file_server[2]], fnum[2], 0, filedata, 0, strlen(filedata)) != strlen(filedata))
	{
		printf("write failed (%s)\n", smbcli_errstr(context.cli[file_server[2]]));
		return False;
	}
	slprintf(newdata, sizeof(fstring)-1, "new data: %s %d", fname[0], (int)getpid());
	DEBUG(3,("write new data %d bytes (%s) to %s (fid %d) on server %s(%d)\n",
		strlen(newdata), newdata, fname[2], fnum[2],
		smbcli_state_get_host(context.cli[2]), file_server[2]));
	if (smbcli_write(context.cli[file_server[2]], fnum[2], 0, newdata, strlen(filedata), strlen(newdata)) != strlen(newdata))
	{
		printf("write failed (%s)\n", smbcli_errstr(context.cli[file_server[2]]));
		return False;
	}
	DEBUG(3,("close %s on server %s(%d)\n",
		fname[2], smbcli_state_get_host(context.cli[2]), file_server[2]));
	if (!smbcli_close(context.cli[file_server[2]], fnum[2])) {
		printf("close of %s failed (%s)\n", fname[2], smbcli_errstr(context.cli[file_server[2]]));
		return False;
	}
	DEBUG(3,("close successful %s on server %s(%d)\n",
		fname[2], smbcli_state_get_host(context.cli[2]), file_server[2]));
	// rename original file to temp	
	DEBUG(4,("file_server[0]=%d\n", file_server[0]));
	DEBUG(4,("context.cli[file_server[0]].desthost=%s\n", smbcli_state_get_host(context.cli[0])));
	DEBUG(3,("rename %s to %s on server %s(%d)\n",
			fname[0], fname[1], smbcli_state_get_host(context.cli[0]), file_server[0]));
	if (!smbcli_dfs_rename(&context, &file_server[0], fname[0], fname[1])) {
		printf("rename of %s to %s failed (%s)\n", fname[0], fname[1], smbcli_errstr(context.cli[file_server[0]]));
		return False;
	}
	// name new temp file to original
	DEBUG(3,("rename %s to %s on server %s(%d)\n",
			fname[2], fname[0], smbcli_state_get_host(context.cli[2]), file_server[2]));
	if (!smbcli_dfs_rename(&context, &file_server[2], fname[2], fname[0])) {
		printf("rename of %s to %s failed (%s)\n", fname[2], fname[0], smbcli_errstr(context.cli[file_server[2]]));
		return False;
	}
	printf("Dfstest: passed MS Word rename test\n");
	// clean up
	DEBUG(3,("used Dfs servers:"));
	for (i=0; i < DFS_SERVER_COUNT ; i++) {
		server_count++;
		DEBUG(3,(" %s(%d)",	smbcli_state_get_host(context.cli[i]), i));
		if (!torture_close_connection(context.cli[i]))
			return False;
	}
	DEBUG(3,("\n"));

	printf("Passed dfs_rename_test\n");
	return True;
}
struct list_fn_parms {
	struct smbcli_client *context;
	char* rname;
} list_fn_parms;

void dfs_list_fn(file_info *finfo, const char *rname, void* parmsp);
void delete_file(file_info *finfo, const char *rname)
{
	int server = 0;
	char *fname;
	
	DEBUG(3,("deleting file %s in %s\n", finfo->name, rname));
	asprintf(&fname, "%s\\%s", rname, finfo->name);
	smbcli_nt_unlink(&context, &server, fname, 0);
}
void delete_directory(file_info *finfo, const char *rname)
{
	int server = 0;
	char *dname, *rname2;
	
	DEBUG(3,("deleting directory %s in %s\n", finfo->name, rname));
	asprintf(&dname, "%s%s\\*", rname, finfo->name);
	smbcli_nt_unlink(&context, &server, dname, 0);
	asprintf(&dname, "%s%s\\*", rname, finfo->name);
	asprintf(&rname2, "%s%s", rname, finfo->name);			
	smbcli_search(context.cli[0], dname, FILE_ATTRIBUTE_DIRECTORY,
		dfs_list_fn, (void*)rname2);
	smbcli_dfs_rmdir(&context, &server, rname2);
}

void dfs_list_fn(file_info *finfo, const char *name, void* parmsp)
{
	struct list_fn_parms *parms = (struct list_fn_parms*)parmsp;
	
	DEBUG(4,("processing %s in %s\n", finfo->name, parms->rname));
	if (finfo->mode & FILE_ATTRIBUTE_DIRECTORY) {
		delete_directory(finfo, parms->rname);
	}
	else {
		delete_file(finfo, parms->rname);
	}
}

/*
 checks for correct DFS cluster support creating random dirs/files.
 */
#define DFS_RANDOM_FILE_COUNT 10
#define DFS_RANDOM_DIR_COUNT 3
#define DFS_RANDOM_DIR_LEVELS 2  
BOOL torture_dfs_random(void)
{
	char *fname[DFS_RANDOM_FILE_COUNT];
	int file_server[DFS_RANDOM_FILE_COUNT];
	char *dname[DFS_RANDOM_DIR_COUNT];
	int dir_server[DFS_RANDOM_DIR_COUNT];
	char *rname;
	int fnum[DFS_FILE_COUNT];
	int i;
	const char *ftemplate = "%s\\dfsfile%d.tmp";
	const char *alltemplate = "\\\\%s\\%s\\dfs*.tmp";
	char *filedata;
	int server_count = 0;
	int file_count;
	int connection_flags = SMBCLI_FULL_CONNECTION_USE_KERBEROS
				| SMBCLI_FULL_CONNECTION_USE_DFS
				;
	
	printf("starting dfs_random_test\n");
	smbcli_client_initialize(&context, sockops, username, password,
			      lp_workgroup(), connection_flags);

	if ((dir_server[0] = smbcli_dfs_open_connection(&context, host, share, connection_flags)) < 0)
		return False;

	// get list of directories named dfsdir*.
	// delete all files in these directories using wild card,
	// then delete directory.
	asprintf(&rname, "\\\\%s\\%s\\",
			smbcli_state_get_host(context.cli[0]),
			smbcli_state_get_share(context.cli[0]));
	asprintf(&fname[0], alltemplate,
			smbcli_state_get_host(context.cli[0]),
			smbcli_state_get_share(context.cli[0]));
	DEBUG(3,("deleting files %s in %s on server %s(%d)\n",
		fname[0], rname, smbcli_state_get_host(context.cli[0]), dir_server[0]));
	file_count = smbcli_search(context.cli[0], fname[0], FILE_ATTRIBUTE_DIRECTORY, dfs_list_fn, (void*)rname);

	// create random directory names with 0-n levels
	asprintf(&dname[0], "\\\\%s\\%s\\",
			smbcli_state_get_host(context.cli[0]),
			smbcli_state_get_share(context.cli[0]));
	DEBUG(3,("creating directories in %s on server %s(%d)\n",
		rname, smbcli_state_get_host(context.cli[0]), dir_server[0]));
	for (i=1; i < DFS_RANDOM_DIR_COUNT; i++) {
		dir_server[i] = 0;
		asprintf(&dname[i],
			"\\\\%s\\%s\\dfsdir%d.tmp",
			smbcli_state_get_host(context.cli[dir_server[i]]),
			smbcli_state_get_share(context.cli[dir_server[i]]),
			(int)sys_random()%10000);
		DEBUG(3,("mkdir %s on server %s(%d)\n",
			dname[i], smbcli_state_get_host(context.cli[dir_server[i]]), dir_server[i]));
		if (!smbcli_dfs_mkdir(&context, &dir_server[i], dname[i])) {
			printf("mkdir of %s failed (%s)\n", dname[i], smbcli_errstr(context.cli[dir_server[i]]));
			return False;
		}
	}

	for (i=0; i < DFS_RANDOM_FILE_COUNT ; i++) {
		// select a directory randomly, create a file in it.
		int dn = (int)sys_random()%DFS_RANDOM_DIR_COUNT;
		file_server[i] = dir_server[dn];
		asprintf(&fname[i], ftemplate, dname[dn], i);
		DEBUG(3,("open %s on server %s(%d)\n",
			fname[i], smbcli_state_get_host(context.cli[dir_server[i]]), file_server[i]));
		fnum[i] = smbcli_dfs_open(&context, &file_server[i], fname[i], O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
		if (fnum[i] == -1)
		{
			printf("open of %s failed (%s)\n", fname[i], smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}

		asprintf(&filedata, "%s %d", fname[i], fnum[i]);
		DEBUG(3,("write %d bytes (%s) to %s (fid %d) on server %s(%d)\n",
			strlen(filedata), filedata, fname[i], fnum[i],
			smbcli_state_get_host(context.cli[dir_server[i]]), file_server[i]));
		if (smbcli_write(context.cli[file_server[i]], fnum[i], 0, filedata, 0, strlen(filedata)) != strlen(filedata))
		{
			printf("write failed (%s)\n", smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}

		if (!smbcli_close(context.cli[file_server[i]], fnum[i])) {
			printf("close of %s failed (%s)\n", fname[i], smbcli_errstr(context.cli[file_server[i]]));
			return False;
		}
	}
	DEBUG(3,("used Dfs servers:"));
	for (i=0; i < DFS_SERVER_COUNT ; i++) {
		server_count++;
		DEBUG(3,(" %s(%d)",	smbcli_state_get_host(context.cli[i]), i));
		if (!torture_close_connection(context.cli[i]))
			return False;
	}
	DEBUG(3,("\n"));
	
	printf("Passed dfs_random_test\n");
	return True;
}
