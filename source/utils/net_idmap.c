/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2003 Andrew Bartlett (abartlet@samba.org)

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"
#include "../utils/net.h"


/***********************************************************
 Helper function for net_idmap_dump. Dump one entry.
 **********************************************************/
static int net_idmap_dump_one_entry(TDB_CONTEXT *tdb,
				    TDB_DATA key,
				    TDB_DATA data,
				    void *unused)
{
	if (strcmp(key.dptr, "USER HWM") == 0) {
		printf("USER HWM %d\n", IVAL(data.dptr,0));
		return 0;
	}

	if (strcmp(key.dptr, "GROUP HWM") == 0) {
		printf("GROUP HWM %d\n", IVAL(data.dptr,0));
		return 0;
	}

	if (strncmp(key.dptr, "S-", 2) != 0)
		return 0;

	printf("%s %s\n", data.dptr, key.dptr);
	return 0;
}

/***********************************************************
 Dump the current idmap
 **********************************************************/
static int net_idmap_dump(int argc, const char **argv)
{
	TDB_CONTEXT *idmap_tdb;

	if ( argc != 1 )
		return net_help_idmap( argc, argv );

	idmap_tdb = tdb_open_log(argv[0], 0, TDB_DEFAULT, O_RDONLY, 0);

	if (idmap_tdb == NULL) {
		d_printf("Could not open idmap: %s\n", argv[0]);
		return -1;
	}

	tdb_traverse(idmap_tdb, net_idmap_dump_one_entry, NULL);

	tdb_close(idmap_tdb);

	return 0;
}

/***********************************************************
 Write entries from stdin to current local idmap
 **********************************************************/
static int net_idmap_restore(int argc, const char **argv)
{
	if (!idmap_init(lp_idmap_backend())) {
		d_printf("Could not init idmap\n");
		return -1;
	}

	while (!feof(stdin)) {
		fstring line, sid_string;
		int len;
		unid_t id;
		int type = ID_EMPTY;
		DOM_SID sid;

		if (fgets(line, sizeof(line)-1, stdin) == NULL)
			break;

		len = strlen(line);

		if ( (len > 0) && (line[len-1] == '\n') )
			line[len-1] = '\0';

		/* Yuck - this is broken for sizeof(gid_t) != sizeof(int) */

		if (sscanf(line, "GID %d %s", &id.gid, sid_string) == 2) {
			type = ID_GROUPID;
		}

		/* Yuck - this is broken for sizeof(uid_t) != sizeof(int) */

		if (sscanf(line, "UID %d %s", &id.uid, sid_string) == 2) {
			type = ID_USERID;
		}

		if (type == ID_EMPTY) {
			d_printf("ignoring invalid line [%s]\n", line);
			continue;
		}

		if (!string_to_sid(&sid, sid_string)) {
			d_printf("ignoring invalid sid [%s]\n", sid_string);
			continue;
		}

		if (!NT_STATUS_IS_OK(idmap_set_mapping(&sid, id, type))) {
			d_printf("Could not set mapping of %s %lu to sid %s\n",
				 (type == ID_GROUPID) ? "GID" : "UID",
				 (type == ID_GROUPID) ? (unsigned long)id.gid:
				 (unsigned long)id.uid, 
				 sid_string_static(&sid));
			continue;
		}
				 
	}

	idmap_close();
	return 0;
}

int net_help_idmap(int argc, const char **argv)
{
	d_printf("net idmap dump filename"\
		 "\n  Dump current id mapping\n");

	d_printf("net idmap restore"\
		 "\n  Restore entries from stdin to current local idmap\n");

	return -1;
}

/***********************************************************
 Look at the current idmap
 **********************************************************/
int net_idmap(int argc, const char **argv)
{
	struct functable func[] = {
		{"dump", net_idmap_dump},
		{"restore", net_idmap_restore},
		{"help", net_help_idmap},
		{NULL, NULL}
	};

	return net_run_function(argc, argv, func, net_help_idmap);
}


