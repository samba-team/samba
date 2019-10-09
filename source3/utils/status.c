/* 
   Unix SMB/CIFS implementation.
   status reporting
   Copyright (C) Andrew Tridgell 1994-1998

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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   21-Jul-1998: rsharpe@ns.aus.com (Richard Sharpe)
   Added -L (locks only) -S (shares only) flags and code

*/

/*
 * This program reports current SMB connections
 */

#include "includes.h"
#include "lib/util/server_id.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "popt_common.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "session.h"
#include "locking/proto.h"
#include "messages.h"
#include "librpc/gen_ndr/open_files.h"
#include "smbd/smbd.h"
#include "librpc/gen_ndr/notify.h"
#include "conn_tdb.h"
#include "serverid.h"
#include "status_profile.h"
#include "smbd/notifyd/notifyd.h"
#include "cmdline_contexts.h"
#include "locking/leases_db.h"

#define SMB_MAXPIDS		2048
static uid_t 		Ucrit_uid = 0;               /* added by OH */
static struct server_id	Ucrit_pid[SMB_MAXPIDS];  /* Ugly !!! */   /* added by OH */
static int		Ucrit_MaxPid=0;                    /* added by OH */
static unsigned int	Ucrit_IsActive = 0;                /* added by OH */

static bool verbose, brief;
static bool shares_only;            /* Added by RJS */
static bool locks_only;            /* Added by RJS */
static bool processes_only;
static bool show_brl;
static bool numeric_only;
static bool do_checks = true;

const char *username = NULL;

/* added by OH */
static void Ucrit_addUid(uid_t uid)
{
	Ucrit_uid = uid;
	Ucrit_IsActive = 1;
}

static unsigned int Ucrit_checkUid(uid_t uid)
{
	if ( !Ucrit_IsActive ) 
		return 1;

	if ( uid == Ucrit_uid ) 
		return 1;

	return 0;
}

static unsigned int Ucrit_checkPid(struct server_id pid)
{
	int i;

	if ( !Ucrit_IsActive ) 
		return 1;

	for (i=0;i<Ucrit_MaxPid;i++) {
		if (server_id_equal(&pid, &Ucrit_pid[i])) {
			return 1;
		}
	}

	return 0;
}

static bool Ucrit_addPid( struct server_id pid )
{
	if ( !Ucrit_IsActive )
		return True;

	if ( Ucrit_MaxPid >= SMB_MAXPIDS ) {
		d_printf("ERROR: More than %d pids for user %s!\n",
			 SMB_MAXPIDS, uidtoname(Ucrit_uid));

		return False;
	}

	Ucrit_pid[Ucrit_MaxPid++] = pid;

	return True;
}

static int print_share_mode(struct file_id fid,
			    const struct share_mode_data *d,
			    const struct share_mode_entry *e,
			    void *private_data)
{
	bool resolve_uids = *((bool *)private_data);
	static int count;

	if (do_checks && !is_valid_share_mode_entry(e)) {
		return 0;
	}

	if (count==0) {
		d_printf("Locked files:\n");
		d_printf("Pid          User(ID)   DenyMode   Access      R/W        Oplock           SharePath   Name   Time\n");
		d_printf("--------------------------------------------------------------------------------------------------\n");
	}
	count++;

	if (do_checks && !serverid_exists(&e->pid)) {
		/* the process for this entry does not exist any more */
		return 0;
	}

	if (Ucrit_checkPid(e->pid)) {
		struct server_id_buf tmp;
		d_printf("%-11s  ", server_id_str_buf(e->pid, &tmp));
		if (resolve_uids) {
			d_printf("%-14s  ", uidtoname(e->uid));
		} else {
			d_printf("%-9u  ", (unsigned int)e->uid);
		}
		switch (map_share_mode_to_deny_mode(e->share_access,
						    e->private_options)) {
			case DENY_NONE: d_printf("DENY_NONE  "); break;
			case DENY_ALL:  d_printf("DENY_ALL   "); break;
			case DENY_DOS:  d_printf("DENY_DOS   "); break;
			case DENY_READ: d_printf("DENY_READ  "); break;
			case DENY_WRITE:d_printf("DENY_WRITE "); break;
			case DENY_FCB:  d_printf("DENY_FCB   "); break;
			default: {
				d_printf("unknown-please report ! "
					 "e->share_access = 0x%x, "
					 "e->private_options = 0x%x\n",
					 (unsigned int)e->share_access,
					 (unsigned int)e->private_options );
				break;
			}
		}
		d_printf("0x%-8x  ",(unsigned int)e->access_mask);
		if ((e->access_mask & (FILE_READ_DATA|FILE_WRITE_DATA))==
				(FILE_READ_DATA|FILE_WRITE_DATA)) {
			d_printf("RDWR       ");
		} else if (e->access_mask & FILE_WRITE_DATA) {
			d_printf("WRONLY     ");
		} else {
			d_printf("RDONLY     ");
		}

		if((e->op_type & (EXCLUSIVE_OPLOCK|BATCH_OPLOCK)) == 
					(EXCLUSIVE_OPLOCK|BATCH_OPLOCK)) {
			d_printf("EXCLUSIVE+BATCH ");
		} else if (e->op_type & EXCLUSIVE_OPLOCK) {
			d_printf("EXCLUSIVE       ");
		} else if (e->op_type & BATCH_OPLOCK) {
			d_printf("BATCH           ");
		} else if (e->op_type & LEVEL_II_OPLOCK) {
			d_printf("LEVEL_II        ");
		} else if (e->op_type == LEASE_OPLOCK) {
			NTSTATUS status;
			uint32_t lstate;

			status = leases_db_get(
				&e->client_guid,
				&e->lease_key,
				&d->id,
				&lstate, /* current_state */
				NULL, /* breaking */
				NULL, /* breaking_to_requested */
				NULL, /* breaking_to_required */
				NULL, /* lease_version */
				NULL); /* epoch */

			if (NT_STATUS_IS_OK(status)) {
				d_printf("LEASE(%s%s%s)%s%s%s      ",
					 (lstate & SMB2_LEASE_READ)?"R":"",
					 (lstate & SMB2_LEASE_WRITE)?"W":"",
					 (lstate & SMB2_LEASE_HANDLE)?"H":"",
					 (lstate & SMB2_LEASE_READ)?"":" ",
					 (lstate & SMB2_LEASE_WRITE)?"":" ",
					 (lstate & SMB2_LEASE_HANDLE)?"":" ");
			} else {
				d_printf("LEASE STATE UNKNOWN");
			}
		} else {
			d_printf("NONE            ");
		}

		d_printf(" %s   %s%s   %s",
			 d->servicepath, d->base_name,
			 (d->stream_name != NULL) ? d->stream_name : "",
			 time_to_asc((time_t)e->time.tv_sec));
	}

	return 0;
}

static void print_brl(struct file_id id,
			struct server_id pid, 
			enum brl_type lock_type,
			enum brl_flavour lock_flav,
			br_off start,
			br_off size,
			void *private_data)
{
	static int count;
	unsigned int i;
	static const struct {
		enum brl_type lock_type;
		const char *desc;
	} lock_types[] = {
		{ READ_LOCK, "R" },
		{ WRITE_LOCK, "W" },
		{ UNLOCK_LOCK, "U" }
	};
	const char *desc="X";
	const char *sharepath = "";
	char *fname = NULL;
	struct share_mode_lock *share_mode;
	struct server_id_buf tmp;
	struct file_id_buf ftmp;

	if (count==0) {
		d_printf("Byte range locks:\n");
		d_printf("Pid        dev:inode       R/W  start     size      SharePath               Name\n");
		d_printf("--------------------------------------------------------------------------------\n");
	}
	count++;

	share_mode = fetch_share_mode_unlocked(NULL, id);
	if (share_mode) {
		bool has_stream = share_mode->data->stream_name != NULL;

		fname = talloc_asprintf(NULL, "%s%s%s",
					share_mode->data->base_name,
					has_stream ? ":" : "",
					has_stream ?
					share_mode->data->stream_name :
					"");
	} else {
		fname = talloc_strdup(NULL, "");
		if (fname == NULL) {
			return;
		}
	}

	for (i=0;i<ARRAY_SIZE(lock_types);i++) {
		if (lock_type == lock_types[i].lock_type) {
			desc = lock_types[i].desc;
		}
	}

	d_printf("%-10s %-15s %-4s %-9jd %-9jd %-24s %-24s\n",
		 server_id_str_buf(pid, &tmp),
		 file_id_str_buf(id, &ftmp),
		 desc,
		 (intmax_t)start, (intmax_t)size,
		 sharepath, fname);

	TALLOC_FREE(fname);
	TALLOC_FREE(share_mode);
}

static const char *session_dialect_str(uint16_t dialect)
{
	static fstring unkown_dialect;

	switch(dialect){
	case SMB2_DIALECT_REVISION_000:
		return "NT1";
	case SMB2_DIALECT_REVISION_202:
		return "SMB2_02";
	case SMB2_DIALECT_REVISION_210:
		return "SMB2_10";
	case SMB2_DIALECT_REVISION_222:
		return "SMB2_22";
	case SMB2_DIALECT_REVISION_224:
		return "SMB2_24";
	case SMB3_DIALECT_REVISION_300:
		return "SMB3_00";
	case SMB3_DIALECT_REVISION_302:
		return "SMB3_02";
	case SMB3_DIALECT_REVISION_310:
		return "SMB3_10";
	case SMB3_DIALECT_REVISION_311:
		return "SMB3_11";
	}

	fstr_sprintf(unkown_dialect, "Unknown (0x%04x)", dialect);
	return unkown_dialect;
}

static int traverse_connections(const struct connections_key *key,
				const struct connections_data *crec,
				void *private_data)
{
	TALLOC_CTX *mem_ctx = (TALLOC_CTX *)private_data;
	struct server_id_buf tmp;
	char *timestr = NULL;
	int result = 0;
	const char *encryption = "-";
	const char *signing = "-";

	if (crec->cnum == TID_FIELD_INVALID)
		return 0;

	if (do_checks &&
	    (!process_exists(crec->pid) || !Ucrit_checkUid(crec->uid))) {
		return 0;
	}

	timestr = timestring(mem_ctx, crec->start);
	if (timestr == NULL) {
		return -1;
	}

	if (smbXsrv_is_encrypted(crec->encryption_flags)) {
		switch (crec->cipher) {
		case SMB_ENCRYPTION_GSSAPI:
			encryption = "GSSAPI";
			break;
		case SMB2_ENCRYPTION_AES128_CCM:
			encryption = "AES-128-CCM";
			break;
		case SMB2_ENCRYPTION_AES128_GCM:
			encryption = "AES-128-GCM";
			break;
		default:
			encryption = "???";
			result = -1;
			break;
		}
	}

	if (smbXsrv_is_signed(crec->signing_flags)) {
		if (crec->dialect >= SMB3_DIALECT_REVISION_302) {
			signing = "AES-128-CMAC";
		} else if (crec->dialect >= SMB2_DIALECT_REVISION_202) {
			signing = "HMAC-SHA256";
		} else {
			signing = "HMAC-MD5";
		}
	}

	d_printf("%-12s %-7s %-13s %-32s %-12s %-12s\n",
		 crec->servicename, server_id_str_buf(crec->pid, &tmp),
		 crec->machine,
		 timestr,
		 encryption,
		 signing);

	TALLOC_FREE(timestr);

	return result;
}

static int traverse_sessionid(const char *key, struct sessionid *session,
			      void *private_data)
{
	TALLOC_CTX *mem_ctx = (TALLOC_CTX *)private_data;
	fstring uid_gid_str;
	struct server_id_buf tmp;
	char *machine_hostname = NULL;
	int result = 0;
	const char *encryption = "-";
	const char *signing = "-";

	if (do_checks &&
	    (!process_exists(session->pid) ||
	     !Ucrit_checkUid(session->uid))) {
		return 0;
	}

	Ucrit_addPid(session->pid);

	if (numeric_only) {
		fstr_sprintf(uid_gid_str, "%-12u %-12u",
			     (unsigned int)session->uid,
			     (unsigned int)session->gid);
	} else {
		if (session->uid == -1 && session->gid == -1) {
			/*
			 * The session is not fully authenticated yet.
			 */
			fstrcpy(uid_gid_str, "(auth in progress)");
		} else {
			/*
			 * In theory it should not happen that one of
			 * session->uid and session->gid is valid (ie != -1)
			 * while the other is not (ie = -1), so we a check for
			 * that case that bails out would be reasonable.
			 */
			const char *uid_name = "-1";
			const char *gid_name = "-1";

			if (session->uid != -1) {
				uid_name = uidtoname(session->uid);
				if (uid_name == NULL) {
					return -1;
				}
			}
			if (session->gid != -1) {
				gid_name = gidtoname(session->gid);
				if (gid_name == NULL) {
					return -1;
				}
			}
			fstr_sprintf(uid_gid_str, "%-12s %-12s",
				     uid_name, gid_name);
		}
	}

	machine_hostname = talloc_asprintf(mem_ctx, "%s (%s)",
					   session->remote_machine,
					   session->hostname);
	if (machine_hostname == NULL) {
		return -1;
	}

	if (smbXsrv_is_encrypted(session->encryption_flags)) {
		switch (session->cipher) {
		case SMB2_ENCRYPTION_AES128_CCM:
			encryption = "AES-128-CCM";
			break;
		case SMB2_ENCRYPTION_AES128_GCM:
			encryption = "AES-128-GCM";
			break;
		default:
			encryption = "???";
			result = -1;
			break;
		}
	} else if (smbXsrv_is_partially_encrypted(session->encryption_flags)) {
		switch (session->cipher) {
		case SMB_ENCRYPTION_GSSAPI:
			encryption = "partial(GSSAPI)";
			break;
		case SMB2_ENCRYPTION_AES128_CCM:
			encryption = "partial(AES-128-CCM)";
			break;
		case SMB2_ENCRYPTION_AES128_GCM:
			encryption = "partial(AES-128-GCM)";
			break;
		default:
			encryption = "???";
			result = -1;
			break;
		}
	}

	if (smbXsrv_is_signed(session->signing_flags)) {
		if (session->connection_dialect >= SMB3_DIALECT_REVISION_302) {
			signing = "AES-128-CMAC";
		} else if (session->connection_dialect >= SMB2_DIALECT_REVISION_202) {
			signing = "HMAC-SHA256";
		} else {
			signing = "HMAC-MD5";
		}
	} else if (smbXsrv_is_partially_signed(session->signing_flags)) {
		if (session->connection_dialect >= SMB3_DIALECT_REVISION_302) {
			signing = "partial(AES-128-CMAC)";
		} else if (session->connection_dialect >= SMB2_DIALECT_REVISION_202) {
			signing = "partial(HMAC-SHA256)";
		} else {
			signing = "partial(HMAC-MD5)";
		}
	}


	d_printf("%-7s %-25s %-41s %-17s %-20s %-21s\n",
		 server_id_str_buf(session->pid, &tmp),
		 uid_gid_str,
		 machine_hostname,
		 session_dialect_str(session->connection_dialect),
		 encryption,
		 signing);

	TALLOC_FREE(machine_hostname);

	return result;
}


static bool print_notify_rec(const char *path, struct server_id server,
			     const struct notify_instance *instance,
			     void *private_data)
{
	struct server_id_buf idbuf;

	d_printf("%s\\%s\\%x\\%x\n", path, server_id_str_buf(server, &idbuf),
		 (unsigned)instance->filter,
		 (unsigned)instance->subdir_filter);

	return true;
}

enum {
	OPT_RESOLVE_UIDS = 1000,
};

int main(int argc, const char *argv[])
{
	int c;
	int profile_only = 0;
	bool show_processes, show_locks, show_shares;
	bool show_notify = false;
	bool resolve_uids = false;
	poptContext pc = NULL;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "processes",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'p',
			.descrip    = "Show processes only",
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'v',
			.descrip    = "Be verbose",
		},
		{
			.longName   = "locks",
			.shortName  = 'L',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'L',
			.descrip    = "Show locks only",
		},
		{
			.longName   = "shares",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'S',
			.descrip    = "Show shares only",
		},
		{
			.longName   = "notify",
			.shortName  = 'N',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'N',
			.descrip    = "Show notifies",
		},
		{
			.longName   = "user",
			.shortName  = 'u',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &username,
			.val        = 'u',
			.descrip    = "Switch to user",
		},
		{
			.longName   = "brief",
			.shortName  = 'b',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'b',
			.descrip    = "Be brief",
		},
		{
			.longName   = "profile",
			.shortName  =     'P',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'P',
			.descrip    = "Do profiling",
		},
		{
			.longName   = "profile-rates",
			.shortName  = 'R',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'R',
			.descrip    = "Show call rates",
		},
		{
			.longName   = "byterange",
			.shortName  = 'B',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'B',
			.descrip    = "Include byte range locks"
		},
		{
			.longName   = "numeric",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'n',
			.descrip    = "Numeric uid/gid"
		},
		{
			.longName   = "fast",
			.shortName  = 'f',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'f',
			.descrip    = "Skip checks if processes still exist"
		},
		{
			.longName   = "resolve-uids",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_RESOLVE_UIDS,
			.descrip    = "Try to resolve UIDs to usernames"
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = 0;
	struct messaging_context *msg_ctx = NULL;
	char *db_path;
	bool ok;

	sec_init();
	smb_init_locale();

	setup_logging(argv[0], DEBUG_STDERR);
	lp_set_cmdline("log level", "0");

	if (getuid() != geteuid()) {
		d_printf("smbstatus should not be run setuid\n");
		ret = 1;
		goto done;
	}

	if (getuid() != 0) {
		d_printf("smbstatus only works as root!\n");
		ret = 1;
		goto done;
	}


	pc = poptGetContext(NULL, argc, argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c) {
		case 'p':
			processes_only = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'L':
			locks_only = true;
			break;
		case 'S':
			shares_only = true;
			break;
		case 'N':
			show_notify = true;
			break;
		case 'b':
			brief = true;
			break;
		case 'u':
			Ucrit_addUid(nametouid(poptGetOptArg(pc)));
			break;
		case 'P':
		case 'R':
			profile_only = c;
			break;
		case 'B':
			show_brl = true;
			break;
		case 'n':
			numeric_only = true;
			break;
		case 'f':
			do_checks = false;
			break;
		case OPT_RESOLVE_UIDS:
			resolve_uids = true;
			break;
		}
	}

	/* setup the flags based on the possible combincations */

	show_processes = !(shares_only || locks_only || profile_only) || processes_only;
	show_locks     = !(shares_only || processes_only || profile_only) || locks_only;
	show_shares    = !(processes_only || locks_only || profile_only) || shares_only;

	if ( username )
		Ucrit_addUid( nametouid(username) );

	if (verbose) {
		d_printf("using configfile = %s\n", get_dyn_CONFIGFILE());
	}

	msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());
	if (msg_ctx == NULL) {
		fprintf(stderr, "Could not initialize messaging, not root?\n");
		ret = -1;
		goto done;
	}

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n",
			get_dyn_CONFIGFILE());
		ret = -1;
		goto done;
	}

	switch (profile_only) {
		case 'P':
			/* Dump profile data */
			ok = status_profile_dump(verbose);
			ret = ok ? 0 : 1;
			goto done;
		case 'R':
			/* Continuously display rate-converted data */
			ok = status_profile_rates(verbose);
			ret = ok ? 0 : 1;
			goto done;
		default:
			break;
	}

	if ( show_processes ) {
		d_printf("\nSamba version %s\n",samba_version_string());
		d_printf("%-7s %-12s %-12s %-41s %-17s %-20s %-21s\n", "PID", "Username", "Group", "Machine", "Protocol Version", "Encryption", "Signing");
		d_printf("----------------------------------------------------------------------------------------------------------------------------------------\n");

		sessionid_traverse_read(traverse_sessionid, frame);

		if (processes_only) {
			goto done;
		}
	}

	if ( show_shares ) {
		if (brief) {
			goto done;
		}

		d_printf("\n%-12s %-7s %-13s %-32s %-12s %-12s\n", "Service", "pid", "Machine", "Connected at", "Encryption", "Signing");
		d_printf("---------------------------------------------------------------------------------------------\n");

		connections_forall_read(traverse_connections, frame);

		d_printf("\n");

		if ( shares_only ) {
			goto done;
		}
	}

	if ( show_locks ) {
		int result;
		struct db_context *db;

		db_path = lock_path(talloc_tos(), "locking.tdb");
		if (db_path == NULL) {
			d_printf("Out of memory - exiting\n");
			ret = -1;
			goto done;
		}

		db = db_open(NULL, db_path, 0,
			     TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH, O_RDONLY, 0,
			     DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);

		if (!db) {
			d_printf("%s not initialised\n", db_path);
			d_printf("This is normal if an SMB client has never "
				 "connected to your server.\n");
			TALLOC_FREE(db_path);
			exit(0);
		} else {
			TALLOC_FREE(db);
			TALLOC_FREE(db_path);
		}

		if (!locking_init_readonly()) {
			d_printf("Can't initialise locking module - exiting\n");
			ret = 1;
			goto done;
		}

		result = share_entry_forall(print_share_mode, &resolve_uids);

		if (result == 0) {
			d_printf("No locked files\n");
		} else if (result < 0) {
			d_printf("locked file list truncated\n");
		}

		d_printf("\n");

		if (show_brl) {
			brl_forall(print_brl, NULL);
		}

		locking_end();
	}

	if (show_notify) {
		struct notify_context *n;

		n = notify_init(talloc_tos(), msg_ctx,
				NULL, NULL);
		if (n == NULL) {
			goto done;
		}
		notify_walk(n, print_notify_rec, NULL);
		TALLOC_FREE(n);
	}

done:
	poptFreeContext(pc);
	TALLOC_FREE(frame);
	return ret;
}
