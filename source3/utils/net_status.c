/* 
   Samba Unix/Linux SMB client library 
   net status command -- possible replacement for smbstatus
   Copyright (C) 2003 Volker Lendecke (vl@samba.org)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "includes.h"
#include "utils/net.h"

static int show_session(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
			void *state)
{
	bool *parseable = (bool *)state;
	struct sessionid sessionid;

	if (dbuf.dsize != sizeof(sessionid))
		return 0;

	memcpy(&sessionid, dbuf.dptr, sizeof(sessionid));

	if (!process_exists(sessionid.pid)) {
		return 0;
	}

	if (*parseable) {
		d_printf("%s\\%s\\%s\\%s\\%s\n",
			 procid_str_static(&sessionid.pid), uidtoname(sessionid.uid),
			 gidtoname(sessionid.gid), 
			 sessionid.remote_machine, sessionid.hostname);
	} else {
		d_printf("%7s   %-12s  %-12s  %-12s (%s)\n",
			 procid_str_static(&sessionid.pid), uidtoname(sessionid.uid),
			 gidtoname(sessionid.gid), 
			 sessionid.remote_machine, sessionid.hostname);
	}

	return 0;
}

static int net_status_sessions(int argc, const char **argv)
{
	TDB_CONTEXT *tdb;
	bool parseable;

	if (argc == 0) {
		parseable = False;
	} else if ((argc == 1) && strequal(argv[0], "parseable")) {
		parseable = True;
	} else {
		return net_help_status(argc, argv);
	}

	if (!parseable) {
		d_printf("PID     Username      Group         Machine"
			 "                        \n");
		d_printf("-------------------------------------------"
			 "------------------------\n");
	}

	tdb = tdb_open_log(lock_path("sessionid.tdb"), 0,
			   TDB_DEFAULT, O_RDONLY, 0);

	if (tdb == NULL) {
		d_fprintf(stderr, "%s not initialised\n", lock_path("sessionid.tdb"));
		return -1;
	}

	tdb_traverse(tdb, show_session, &parseable);
	tdb_close(tdb);

	return 0;
}

static int show_share(struct db_record *rec,
		      const struct connections_key *key,
		      const struct connections_data *crec,
		      void *state)
{
	if (crec->cnum == -1)
		return 0;

	if (!process_exists(crec->pid)) {
		return 0;
	}

	d_printf("%-10.10s   %s   %-12s  %s",
	       crec->servicename, procid_str_static(&crec->pid),
	       crec->machine,
	       time_to_asc(crec->start));

	return 0;
}

struct sessionids {
	int num_entries;
	struct sessionid *entries;
};

static int collect_pid(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
		       void *state)
{
	struct sessionids *ids = (struct sessionids *)state;
	struct sessionid sessionid;

	if (dbuf.dsize != sizeof(sessionid))
		return 0;

	memcpy(&sessionid, dbuf.dptr, sizeof(sessionid));

	if (!process_exists(sessionid.pid)) 
		return 0;

	ids->num_entries += 1;
	ids->entries = SMB_REALLOC_ARRAY(ids->entries, struct sessionid, ids->num_entries);
	if (!ids->entries) {
		ids->num_entries = 0;
		return 0;
	}
	ids->entries[ids->num_entries-1] = sessionid;

	return 0;
}

static int show_share_parseable(struct db_record *rec,
				const struct connections_key *key,
				const struct connections_data *crec,
				void *state)
{
	struct sessionids *ids = (struct sessionids *)state;
	int i;
	bool guest = True;

	if (crec->cnum == -1)
		return 0;

	if (!process_exists(crec->pid)) {
		return 0;
	}

	for (i=0; i<ids->num_entries; i++) {
		struct server_id id = ids->entries[i].pid;
		if (procid_equal(&id, &crec->pid)) {
			guest = False;
			break;
		}
	}

	d_printf("%s\\%s\\%s\\%s\\%s\\%s\\%s",
		 crec->servicename,procid_str_static(&crec->pid),
		 guest ? "" : uidtoname(ids->entries[i].uid),
		 guest ? "" : gidtoname(ids->entries[i].gid),
		 crec->machine, 
		 guest ? "" : ids->entries[i].hostname,
		 time_to_asc(crec->start));

	return 0;
}

static int net_status_shares_parseable(int argc, const char **argv)
{
	struct sessionids ids;
	TDB_CONTEXT *tdb;

	ids.num_entries = 0;
	ids.entries = NULL;

	tdb = tdb_open_log(lock_path("sessionid.tdb"), 0,
			   TDB_DEFAULT, O_RDONLY, 0);

	if (tdb == NULL) {
		d_fprintf(stderr, "%s not initialised\n", lock_path("sessionid.tdb"));
		return -1;
	}

	tdb_traverse(tdb, collect_pid, &ids);
	tdb_close(tdb);

	connections_forall(show_share_parseable, &ids);

	SAFE_FREE(ids.entries);

	return 0;
}

static int net_status_shares(int argc, const char **argv)
{
	if (argc == 0) {

		d_printf("\nService      pid     machine       "
			 "Connected at\n");
		d_printf("-------------------------------------"
			 "------------------\n");

		connections_forall(show_share, NULL);

		return 0;
	}

	if ((argc != 1) || !strequal(argv[0], "parseable")) {
		return net_help_status(argc, argv);
	}

	return net_status_shares_parseable(argc, argv);
}

int net_status(int argc, const char **argv)
{
	struct functable func[] = {
		{"sessions", net_status_sessions},
		{"shares", net_status_shares},
		{NULL, NULL}
	};
	return net_run_function(argc, argv, func, net_help_status);
}
