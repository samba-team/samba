/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2000

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
#include "rpcclient.h"

/* Check DFS is supported by the remote server */

static NTSTATUS cmd_dfs_exist(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                              int argc, char **argv)
{
	BOOL dfs_exists;
	NTSTATUS result;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_dfs_exist(cli, mem_ctx, &dfs_exists);

	if (NT_STATUS_IS_OK(result))
		printf("dfs is %spresent\n", dfs_exists ? "" : "not ");

	return result;
}

static NTSTATUS cmd_dfs_add(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            int argc, char **argv)
{
	NTSTATUS result;
	char *entrypath, *servername, *sharename, *comment;
	uint32 flags = 0;

	if (argc != 5) {
		printf("Usage: %s entrypath servername sharename comment\n", 
		       argv[0]);
		return NT_STATUS_OK;
	}

	entrypath = argv[1];
	servername = argv[2];
	sharename = argv[3];
	comment = argv[4];

	result = cli_dfs_add(cli, mem_ctx, entrypath, servername, 
			     sharename, comment, flags);

	return result;
}

static NTSTATUS cmd_dfs_remove(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                               int argc, char **argv)
{
	NTSTATUS result;
	char *entrypath, *servername, *sharename;

	if (argc != 4) {
		printf("Usage: %s entrypath servername sharename\n", argv[0]);
		return NT_STATUS_OK;
	}

	entrypath = argv[1];
	servername = argv[2];
	sharename = argv[3];

	result = cli_dfs_remove(cli, mem_ctx, entrypath, servername, 
				sharename);

	return result;
}

/* Display a DFS_INFO_1 structure */

static void display_dfs_info_1(DFS_INFO_1 *info1)
{
	fstring temp;

	unistr2_to_unix(temp, &info1->entrypath, sizeof(temp) - 1);
	printf("entrypath: %s\n", temp);
}

/* Display a DFS_INFO_2 structure */

static void display_dfs_info_2(DFS_INFO_2 *info2)
{
	fstring temp;

	unistr2_to_unix(temp, &info2->entrypath, sizeof(temp) - 1);
	printf("entrypath: %s\n", temp);

	unistr2_to_unix(temp, &info2->comment, sizeof(temp) - 1);
	printf("\tcomment: %s\n", temp);

	printf("\tstate: %d\n", info2->state);
	printf("\tnum_storages: %d\n", info2->num_storages);
}

/* Display a DFS_INFO_3 structure */

static void display_dfs_info_3(DFS_INFO_3 *info3)
{
	fstring temp;
	int i;

	unistr2_to_unix(temp, &info3->entrypath, sizeof(temp) - 1);
	printf("entrypath: %s\n", temp);

	unistr2_to_unix(temp, &info3->comment, sizeof(temp) - 1);
	printf("\tcomment: %s\n", temp);

	printf("\tstate: %d\n", info3->state);
	printf("\tnum_storages: %d\n", info3->num_storages);

	for (i = 0; i < info3->num_storages; i++) {
		DFS_STORAGE_INFO *dsi = &info3->storages[i];

		unistr2_to_unix(temp, &dsi->servername, sizeof(temp) - 1);
		printf("\t\tstorage[%d] servername: %s\n", i, temp);

		unistr2_to_unix(temp, &dsi->sharename, sizeof(temp) - 1);
		printf("\t\tstorage[%d] sharename: %s\n", i, temp);
	}
}

/* Display a DFS_INFO_CTR structure */

static void display_dfs_info_ctr(DFS_INFO_CTR *ctr)
{
	int i;

	for (i = 0; i < ctr->num_entries; i++) {
		switch (ctr->switch_value) {
		case 0x01:
			display_dfs_info_1(&ctr->dfs.info1[i]);
			break;
		case 0x02:
			display_dfs_info_2(&ctr->dfs.info2[i]);
			break;
		case 0x03:
			display_dfs_info_3(&ctr->dfs.info3[i]);
			break;
		default:
			printf("unsupported info level %d\n", 
			       ctr->switch_value);
			break;
		}
	}
}

/* Enumerate dfs shares */

static NTSTATUS cmd_dfs_enum(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             int argc, char **argv)
{
	DFS_INFO_CTR ctr;
	NTSTATUS result;
	uint32 info_level = 1;

	if (argc > 2) {
		printf("Usage: %s [info_level]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	result = cli_dfs_enum(cli, mem_ctx, info_level, &ctr);

	if (NT_STATUS_IS_OK(result))
		display_dfs_info_ctr(&ctr);

	return result;
}

static NTSTATUS cmd_dfs_getinfo(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                int argc, char **argv)
{
	NTSTATUS result;
	char *entrypath, *servername, *sharename;
	uint32 info_level = 1;
	DFS_INFO_CTR ctr;

	if (argc < 4 || argc > 5) {
		printf("Usage: %s entrypath servername sharename "
                       "[info_level]\n", argv[0]);
		return NT_STATUS_OK;
	}

	entrypath = argv[1];
	servername = argv[2];
	sharename = argv[3];

	if (argc == 5)
		info_level = atoi(argv[4]);

	result = cli_dfs_get_info(cli, mem_ctx, entrypath, servername, 
				  sharename, info_level, &ctr);

	if (NT_STATUS_IS_OK(result))
		display_dfs_info_ctr(&ctr);

	return result;
}

/* List of commands exported by this module */

struct cmd_set dfs_commands[] = {

	{ "DFS" },

	{ "dfsexist",   cmd_dfs_exist,   PIPE_NETDFS, "Query DFS support",    "" },
	{ "dfsadd",     cmd_dfs_add,     PIPE_NETDFS, "Add a DFS share",      "" },
	{ "dfsremove",  cmd_dfs_remove,  PIPE_NETDFS, "Remove a DFS share",   "" },
	{ "dfsgetinfo", cmd_dfs_getinfo, PIPE_NETDFS, "Query DFS share info", "" },
	{ "dfsenum",    cmd_dfs_enum,    PIPE_NETDFS, "Enumerate dfs shares", "" },

	{ NULL }
};
