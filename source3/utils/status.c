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
#include "lib/cmdline/cmdline.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "session.h"
#include "locking/share_mode_lock.h"
#include "locking/proto.h"
#include "messages.h"
#include "librpc/gen_ndr/open_files.h"
#include "smbd/smbd.h"
#include "librpc/gen_ndr/notify.h"
#include "conn_tdb.h"
#include "serverid.h"
#include "status_profile.h"
#include "status.h"
#include "status_json.h"
#include "smbd/notifyd/notifyd_db.h"
#include "cmdline_contexts.h"
#include "locking/leases_db.h"
#include "lib/util/string_wrappers.h"
#include "lib/param/param.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"
#endif /* HAVE_JANSSON */

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
		fprintf(stderr, "ERROR: More than %d pids for user %s!\n",
			 SMB_MAXPIDS, uidtoname(Ucrit_uid));

		return False;
	}

	Ucrit_pid[Ucrit_MaxPid++] = pid;

	return True;
}

static int print_share_mode_stdout(struct traverse_state *state,
				   const char *pid,
				   const char *user_name,
				   const char *denymode,
				   int access_mask,
				   const char *rw,
				   const char *oplock,
				   const char *servicepath,
				   const char *filename,
				   const char *timestr)
{
	if (state->first) {
		d_printf("\nLocked files:\n");
		d_printf("Pid          User(ID)   DenyMode   Access      R/W        Oplock           SharePath   Name   Time\n");
		d_printf("--------------------------------------------------------------------------------------------------\n");

		state->first = false;
	}

	d_printf("%-11s  %-9s  %-10s 0x%-8x  %-10s %-14s   %s   %s   %s",
		 pid, user_name, denymode, access_mask, rw, oplock,
		 servicepath, filename, timestr);
	return 0;
}

static int prepare_share_mode(struct traverse_state *state)
{
	if (!state->json_output) {
		/* only print header line if there are open files */
		state->first = true;
	} else {
		add_section_to_json(state, "open_files");
	}
	return 0;
}

static uint32_t map_share_mode_to_deny_mode(
	uint32_t share_access, uint16_t flags)
{
	switch (share_access & ~FILE_SHARE_DELETE) {
	case FILE_SHARE_NONE:
		return DENY_ALL;
	case FILE_SHARE_READ:
		return DENY_WRITE;
	case FILE_SHARE_WRITE:
		return DENY_READ;
	case FILE_SHARE_READ|FILE_SHARE_WRITE:
		return DENY_NONE;
	}
	if (flags & SHARE_ENTRY_FLAG_DENY_DOS) {
		return DENY_DOS;
	} else if (flags & SHARE_ENTRY_FLAG_DENY_FCB) {
		return DENY_FCB;
	}

	return (uint32_t)-1;
}

static int print_share_mode(struct file_id fid,
			    const struct share_mode_data *d,
			    const struct share_mode_entry *e,
			    void *private_data)
{
	const char *denymode = NULL;
	uint denymode_int;
	const char *oplock = NULL;
	const char *pid = NULL;
	const char *rw = NULL;
	const char *filename = NULL;
	const char *timestr = NULL;
	const char *user_str = NULL;
	uint32_t lstate;
	struct traverse_state *state = (struct traverse_state *)private_data;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	if (do_checks && !is_valid_share_mode_entry(e)) {
		TALLOC_FREE(tmp_ctx);
		return 0;
	}

	if (do_checks && !serverid_exists(&e->pid)) {
		/* the process for this entry does not exist any more */
		TALLOC_FREE(tmp_ctx);
		return 0;
	}

	if (Ucrit_checkPid(e->pid)) {
		struct server_id_buf tmp;
		pid = server_id_str_buf(e->pid, &tmp);
		if (state->resolve_uids) {
			user_str = talloc_asprintf(tmp_ctx, "%s", uidtoname(e->uid));
		} else {
			user_str = talloc_asprintf(tmp_ctx, "%u", (unsigned int)e->uid);
		}
		if (user_str == NULL) {
			TALLOC_FREE(tmp_ctx);
			return -1;
		}

		denymode_int = map_share_mode_to_deny_mode(e->share_access,
							   e->flags);
		switch (denymode_int) {
			case DENY_NONE:
				denymode = "DENY_NONE";
				break;
			case DENY_ALL:
				denymode = "DENY_ALL";
				break;
			case DENY_DOS:
				denymode = "DENY_DOS";
				break;
			case DENY_READ:
				denymode = "DENY_READ";
				break;
			case DENY_WRITE:
				denymode = "DENY_WRITE";
				break;
			case DENY_FCB:
				denymode = "DENY_FCB";
				break;
			default: {
				denymode = talloc_asprintf(tmp_ctx,
							   "UNKNOWN(0x%08x)",
							   denymode_int);
				if (denymode == NULL) {
					TALLOC_FREE(tmp_ctx);
					return -1;
				}
				fprintf(stderr,
					"unknown-please report ! "
					"e->share_access = 0x%x, "
					"e->flags = 0x%x\n",
					(unsigned int)e->share_access,
					(unsigned int)e->flags);
				break;
			}
		}
		filename = talloc_asprintf(tmp_ctx,
					   "%s%s",
					   d->base_name,
					   (d->stream_name != NULL) ? d->stream_name : "");
		if (filename == NULL) {
			TALLOC_FREE(tmp_ctx);
			return -1;
		}
		if ((e->access_mask & (FILE_READ_DATA|FILE_WRITE_DATA))==
				(FILE_READ_DATA|FILE_WRITE_DATA)) {
			rw = "RDWR";
		} else if (e->access_mask & FILE_WRITE_DATA) {
			rw = "WRONLY";
		} else {
			rw = "RDONLY";
		}

		if (e->op_type & BATCH_OPLOCK) {
			oplock = "BATCH";
		} else if (e->op_type & EXCLUSIVE_OPLOCK) {
			oplock = "EXCLUSIVE";
		} else if (e->op_type & LEVEL_II_OPLOCK) {
			oplock = "LEVEL_II";
		} else if (e->op_type == LEASE_OPLOCK) {
			NTSTATUS status;

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
				oplock = talloc_asprintf(tmp_ctx, "LEASE(%s%s%s)%s%s%s",
						 (lstate & SMB2_LEASE_READ)?"R":"",
						 (lstate & SMB2_LEASE_WRITE)?"W":"",
						 (lstate & SMB2_LEASE_HANDLE)?"H":"",
						 (lstate & SMB2_LEASE_READ)?"":" ",
						 (lstate & SMB2_LEASE_WRITE)?"":" ",
						 (lstate & SMB2_LEASE_HANDLE)?"":" ");
			} else {
				oplock = "LEASE STATE UNKNOWN";
			}
		} else {
			oplock = "NONE";
		}

		timestr = time_to_asc((time_t)e->time.tv_sec);

		if (!state->json_output) {
			print_share_mode_stdout(state,
						pid,
						user_str,
						denymode,
						(unsigned int)e->access_mask,
						rw,
						oplock,
						d->servicepath,
						filename,
						timestr);
		} else {
			print_share_mode_json(state,
					      d,
					      e,
					      fid,
					      user_str,
					      oplock,
					      lstate,
					      filename);
		}
	}
	TALLOC_FREE(tmp_ctx);
	return 0;
}

static void print_brl_stdout(struct traverse_state *state,
			     char *pid,
			     char *id,
			     const char *desc,
			     intmax_t start,
			     intmax_t size,
			     const char *sharepath,
			     char *fname)
{
	if (state->first) {
		d_printf("Byte range locks:\n");
		d_printf("Pid        dev:inode       R/W  start     size      SharePath               Name\n");
		d_printf("--------------------------------------------------------------------------------\n");

		state->first = false;
	}
	d_printf("%-10s %-15s %-4s %-9jd %-9jd %-24s %-24s\n",
		 pid, id, desc, start, size, sharepath, fname);
}

static int prepare_brl(struct traverse_state *state)
{
	if (!state->json_output) {
		/* only print header line if there are locked files */
		state->first = true;
	} else {
		add_section_to_json(state, "byte_range_locks");
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
	struct traverse_state *state = (struct traverse_state *)private_data;

	share_mode = fetch_share_mode_unlocked(NULL, id);
	if (share_mode) {
		fname = share_mode_filename(NULL, share_mode);
		sharepath = share_mode_servicepath(share_mode);
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

	if (!state->json_output) {
		print_brl_stdout(state,
				 server_id_str_buf(pid, &tmp),
				 file_id_str_buf(id, &ftmp),
				 desc,
				 (intmax_t)start,
				 (intmax_t)size,
				 sharepath,
				 fname);
	} else {
		print_brl_json(state,
			       pid,
			       id,
			       desc,
			       lock_flav,
			       (intmax_t)start,
			       (intmax_t)size,
			       sharepath,
			       fname);

	}

	TALLOC_FREE(fname);
	TALLOC_FREE(share_mode);
}

static const char *session_dialect_str(uint16_t dialect)
{
	static fstring unknown_dialect;

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

	fstr_sprintf(unknown_dialect, "Unknown (0x%04x)", dialect);
	return unknown_dialect;
}

static int traverse_connections_stdout(struct traverse_state *state,
				       const char *servicename,
				       char *server_id,
				       const char *machine,
				       const char *timestr,
				       const char *encryption_cipher,
				       enum crypto_degree encryption_degree,
				       const char *signing_cipher,
				       enum crypto_degree signing_degree)
{
	fstring encryption;
	fstring signing;

	if (encryption_degree == CRYPTO_DEGREE_FULL) {
		fstr_sprintf(encryption, "%s", encryption_cipher);
	} else if (encryption_degree == CRYPTO_DEGREE_ANONYMOUS) {
		fstr_sprintf(encryption, "anonymous(%s)", encryption_cipher);
	} else if (encryption_degree == CRYPTO_DEGREE_PARTIAL) {
		fstr_sprintf(encryption, "partial(%s)", encryption_cipher);
	} else {
		fstr_sprintf(encryption, "-");
	}
	if (signing_degree == CRYPTO_DEGREE_FULL) {
		fstr_sprintf(signing, "%s", signing_cipher);
	} else if (signing_degree == CRYPTO_DEGREE_ANONYMOUS) {
		fstr_sprintf(signing, "anonymous(%s)", signing_cipher);
	} else if (signing_degree == CRYPTO_DEGREE_PARTIAL) {
		fstr_sprintf(signing, "partial(%s)", signing_cipher);
	} else {
		fstr_sprintf(signing, "-");
	}

	d_printf("%-12s %-7s %-13s %-32s %-12s %-12s\n",
		 servicename, server_id, machine, timestr, encryption, signing);

	return 0;
}

static int prepare_connections(struct traverse_state *state)
{
	if (!state->json_output) {
		/* always print header line */
		d_printf("\n%-12s %-7s %-13s %-32s %-12s %-12s\n", "Service", "pid", "Machine", "Connected at", "Encryption", "Signing");
		d_printf("---------------------------------------------------------------------------------------------\n");
	} else {
		add_section_to_json(state, "tcons");
	}
	return 0;
}

static int traverse_connections(const struct connections_data *crec,
				void *private_data)
{
	struct server_id_buf tmp;
	char *timestr = NULL;
	int result = 0;
	const char *encryption = "-";
	enum crypto_degree encryption_degree = CRYPTO_DEGREE_NONE;
	const char *signing = "-";
	enum crypto_degree signing_degree = CRYPTO_DEGREE_NONE;
	struct traverse_state *state = (struct traverse_state *)private_data;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	if (crec->cnum == TID_FIELD_INVALID) {
		TALLOC_FREE(tmp_ctx);
		return 0;
	}

	if (do_checks &&
	    (!process_exists(crec->pid) || !Ucrit_checkUid(crec->uid))) {
		TALLOC_FREE(tmp_ctx);
		return 0;
	}

	timestr = timestring(tmp_ctx, nt_time_to_unix(crec->start));
	if (timestr == NULL) {
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (smbXsrv_is_encrypted(crec->encryption_flags) ||
	    smbXsrv_is_partially_encrypted(crec->encryption_flags))
	{
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
		case SMB2_ENCRYPTION_AES256_CCM:
			encryption = "AES-256-CCM";
			break;
		case SMB2_ENCRYPTION_AES256_GCM:
			encryption = "AES-256-GCM";
			break;
		default:
			encryption = "???";
			break;
		}
		if (smbXsrv_is_encrypted(crec->encryption_flags)) {
			encryption_degree = CRYPTO_DEGREE_FULL;
		} else if (smbXsrv_is_partially_encrypted(crec->encryption_flags)) {
			encryption_degree = CRYPTO_DEGREE_PARTIAL;
		}
		if (encryption_degree != CRYPTO_DEGREE_NONE &&
		    !crec->authenticated)
		{
			encryption_degree = CRYPTO_DEGREE_ANONYMOUS;
		}
	}

	if (smbXsrv_is_signed(crec->signing_flags) ||
	    smbXsrv_is_partially_signed(crec->signing_flags))
	{
		switch (crec->signing) {
		case SMB2_SIGNING_MD5_SMB1:
			signing = "HMAC-MD5";
			break;
		case SMB2_SIGNING_HMAC_SHA256:
			signing = "HMAC-SHA256";
			break;
		case SMB2_SIGNING_AES128_CMAC:
			signing = "AES-128-CMAC";
			break;
		case SMB2_SIGNING_AES128_GMAC:
			signing = "AES-128-GMAC";
			break;
		default:
			signing = "???";
			break;
		}
		if (smbXsrv_is_signed(crec->signing_flags)) {
			signing_degree = CRYPTO_DEGREE_FULL;
		} else if (smbXsrv_is_partially_signed(crec->signing_flags)) {
			signing_degree = CRYPTO_DEGREE_PARTIAL;
		}
		if (signing_degree != CRYPTO_DEGREE_NONE &&
		    !crec->authenticated)
		{
			signing_degree = CRYPTO_DEGREE_ANONYMOUS;
		}
	}

	if (!state->json_output) {
		result = traverse_connections_stdout(state,
						     crec->servicename,
						     server_id_str_buf(crec->pid, &tmp),
						     crec->machine,
						     timestr,
						     encryption,
						     encryption_degree,
						     signing,
						     signing_degree);
	} else {
		result = traverse_connections_json(state,
						   crec,
						   encryption,
						   encryption_degree,
						   signing,
						   signing_degree);
	}

	TALLOC_FREE(timestr);
	TALLOC_FREE(tmp_ctx);

	return result;
}

static int traverse_sessionid_stdout(struct traverse_state *state,
				     char *server_id,
				     char *uid_gid_str,
				     char *machine_hostname,
				     const char *dialect,
				     const char *encryption_cipher,
				     enum crypto_degree encryption_degree,
				     const char *signing_cipher,
				     enum crypto_degree signing_degree)
{
	fstring encryption;
	fstring signing;

	if (encryption_degree == CRYPTO_DEGREE_FULL) {
		fstr_sprintf(encryption, "%s", encryption_cipher);
	} else if (encryption_degree == CRYPTO_DEGREE_ANONYMOUS) {
		fstr_sprintf(encryption, "anonymous(%s)", encryption_cipher);
	} else if (encryption_degree == CRYPTO_DEGREE_PARTIAL) {
		fstr_sprintf(encryption, "partial(%s)", encryption_cipher);
	} else {
		fstr_sprintf(encryption, "-");
	}
	if (signing_degree == CRYPTO_DEGREE_FULL) {
		fstr_sprintf(signing, "%s", signing_cipher);
	} else if (signing_degree == CRYPTO_DEGREE_ANONYMOUS) {
		fstr_sprintf(signing, "anonymous(%s)", signing_cipher);
	} else if (signing_degree == CRYPTO_DEGREE_PARTIAL) {
		fstr_sprintf(signing, "partial(%s)", signing_cipher);
	} else {
		fstr_sprintf(signing, "-");
	}

	d_printf("%-7s %-25s %-41s %-17s %-20s %-21s\n",
		 server_id, uid_gid_str, machine_hostname, dialect, encryption,
		 signing);

	return 0;
}

static int prepare_sessionid(struct traverse_state *state)
{
	if (!state->json_output) {
		/* always print header line */
		d_printf("\nSamba version %s\n",samba_version_string());
		d_printf("%-7s %-12s %-12s %-41s %-17s %-20s %-21s\n", "PID", "Username", "Group", "Machine", "Protocol Version", "Encryption", "Signing");
		d_printf("----------------------------------------------------------------------------------------------------------------------------------------\n");
	} else {
		add_section_to_json(state, "sessions");
	}
	return 0;

}

static int traverse_sessionid(const char *key, struct sessionid *session,
			      void *private_data)
{
	fstring uid_gid_str;
	fstring uid_str;
	fstring gid_str;
	struct server_id_buf tmp;
	char *machine_hostname = NULL;
	int result = 0;
	const char *encryption = "-";
	enum crypto_degree encryption_degree = CRYPTO_DEGREE_NONE;
	const char *signing = "-";
	enum crypto_degree signing_degree = CRYPTO_DEGREE_NONE;
	struct traverse_state *state = (struct traverse_state *)private_data;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	if (do_checks &&
	    (!process_exists(session->pid) ||
	     !Ucrit_checkUid(session->uid))) {
		TALLOC_FREE(tmp_ctx);
		return 0;
	}

	Ucrit_addPid(session->pid);

	if (numeric_only) {
		fstr_sprintf(gid_str, "%u", (unsigned int)session->gid);
		fstr_sprintf(uid_str, "%u", (unsigned int)session->uid);
		fstr_sprintf(uid_gid_str, "%-12u %-12u",
			     (unsigned int)session->uid,
			     (unsigned int)session->gid);
	} else {
		if (session->uid == -1 && session->gid == -1) {
			/*
			 * The session is not fully authenticated yet.
			 */
			fstrcpy(uid_gid_str, "(auth in progress)");
			fstrcpy(gid_str, "(auth in progress)");
			fstrcpy(uid_str, "(auth in progress)");
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
					TALLOC_FREE(tmp_ctx);
					return -1;
				}
			}
			if (session->gid != -1) {
				gid_name = gidtoname(session->gid);
				if (gid_name == NULL) {
					TALLOC_FREE(tmp_ctx);
					return -1;
				}
			}
			fstr_sprintf(gid_str, "%s", gid_name);
			fstr_sprintf(uid_str, "%s", uid_name);
			fstr_sprintf(uid_gid_str, "%-12s %-12s",
				     uid_name, gid_name);
		}
	}

	machine_hostname = talloc_asprintf(tmp_ctx, "%s (%s)",
					   session->remote_machine,
					   session->hostname);
	if (machine_hostname == NULL) {
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (smbXsrv_is_encrypted(session->encryption_flags) ||
			smbXsrv_is_partially_encrypted(session->encryption_flags)) {
		switch (session->cipher) {
		case SMB2_ENCRYPTION_AES128_CCM:
			encryption = "AES-128-CCM";
			break;
		case SMB2_ENCRYPTION_AES128_GCM:
			encryption = "AES-128-GCM";
			break;
		case SMB2_ENCRYPTION_AES256_CCM:
			encryption = "AES-256-CCM";
			break;
		case SMB2_ENCRYPTION_AES256_GCM:
			encryption = "AES-256-GCM";
			break;
		default:
			encryption = "???";
			result = -1;
			break;
		}
		if (smbXsrv_is_encrypted(session->encryption_flags)) {
			encryption_degree = CRYPTO_DEGREE_FULL;
		} else if (smbXsrv_is_partially_encrypted(session->encryption_flags)) {
			encryption_degree = CRYPTO_DEGREE_PARTIAL;
		}
		if (encryption_degree != CRYPTO_DEGREE_NONE &&
		    !session->authenticated)
		{
			encryption_degree = CRYPTO_DEGREE_ANONYMOUS;
		}
	}

	if (smbXsrv_is_signed(session->signing_flags) ||
			smbXsrv_is_partially_signed(session->signing_flags)) {
		switch (session->signing) {
		case SMB2_SIGNING_MD5_SMB1:
			signing = "HMAC-MD5";
			break;
		case SMB2_SIGNING_HMAC_SHA256:
			signing = "HMAC-SHA256";
			break;
		case SMB2_SIGNING_AES128_CMAC:
			signing = "AES-128-CMAC";
			break;
		case SMB2_SIGNING_AES128_GMAC:
			signing = "AES-128-GMAC";
			break;
		default:
			signing = "???";
			result = -1;
			break;
		}
		if (smbXsrv_is_signed(session->signing_flags)) {
			signing_degree = CRYPTO_DEGREE_FULL;
		} else if (smbXsrv_is_partially_signed(session->signing_flags)) {
			signing_degree = CRYPTO_DEGREE_PARTIAL;
		}
		if (signing_degree != CRYPTO_DEGREE_NONE &&
		    !session->authenticated)
		{
			signing_degree = CRYPTO_DEGREE_ANONYMOUS;
		}
	}


	if (!state->json_output) {
		traverse_sessionid_stdout(state,
			 server_id_str_buf(session->pid, &tmp),
			 uid_gid_str,
			 machine_hostname,
			 session_dialect_str(session->connection_dialect),
			 encryption,
			 encryption_degree,
			 signing,
			 signing_degree);
	} else {
		result = traverse_sessionid_json(state,
						 session,
						 uid_str,
						 gid_str,
						 encryption,
						 encryption_degree,
						 signing,
						 signing_degree,
						 session_dialect_str(session->connection_dialect));
	}

	TALLOC_FREE(machine_hostname);
	TALLOC_FREE(tmp_ctx);

	return result;
}


static bool print_notify_rec_stdout(struct traverse_state *state,
				    const char *path,
				    char *server_id_str,
				    unsigned filter,
				    unsigned subdir_filter)
{
	d_printf("%s\\%s\\%x\\%x\n", path, server_id_str,
		 filter, subdir_filter);

	return true;
}

static int prepare_notify(struct traverse_state *state)
{
	if (!state->json_output) {
		/* don't print header line */
	} else {
		add_section_to_json(state, "notifies");
	}
	return 0;
}

static bool print_notify_rec(const char *path, struct server_id server,
			     const struct notify_instance *instance,
			     void *private_data)
{
	struct server_id_buf idbuf;
	struct traverse_state *state = (struct traverse_state *)private_data;
	bool result;

	if (!state->json_output) {
		result = print_notify_rec_stdout(state,
						 path,
						 server_id_str_buf(server, &idbuf),
						 (unsigned)instance->filter,
						 (unsigned)instance->subdir_filter);

	} else {
		result = print_notify_rec_json(state,
					       instance,
					       server,
					       path);
	}

	return result;
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
	poptContext pc = NULL;
	struct traverse_state state = {0};
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
			.longName   = "json",
			.shortName  = 'j',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'j',
			.descrip    = "JSON output"
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
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = 0;
	struct messaging_context *msg_ctx = NULL;
	char *db_path;
	bool ok;
	struct loadparm_context *lp_ctx = NULL;

	state.first = true;
	state.json_output = false;
	state.resolve_uids = false;

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	lp_ctx = samba_cmdline_get_lp_ctx();
	lpcfg_set_cmdline(lp_ctx, "log level", "0");

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    POPT_CONTEXT_KEEP_FIRST);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

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
		case 'j':
			state.json_output = true;
			break;
		case 'f':
			do_checks = false;
			break;
		case OPT_RESOLVE_UIDS:
			state.resolve_uids = true;
			break;
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(c));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	sec_init();

#ifdef HAVE_JANSSON
	state.root_json = json_new_object();
	if (!json_is_invalid(&state.root_json)) {
		add_general_information_to_json(&state);
	}
#else /* HAVE_JANSSON */
	if (state.json_output) {
		fprintf(stderr, "JSON support not available, please install lib Jansson\n");
		goto done;
	}
#endif /* HAVE_JANSSON */

	if (getuid() != geteuid()) {
		fprintf(stderr, "smbstatus should not be run setuid\n");
		ret = 1;
		goto done;
	}

	if (getuid() != 0) {
		fprintf(stderr, "smbstatus only works as root!\n");
		ret = 1;
		goto done;
	}

	/* setup the flags based on the possible combincations */

	show_processes = !(shares_only || locks_only || profile_only) || processes_only;
	show_locks     = !(shares_only || processes_only || profile_only) || locks_only;
	show_shares    = !(processes_only || locks_only || profile_only) || shares_only;

	if ( username )
		Ucrit_addUid( nametouid(username) );

	if (verbose && !state.json_output) {
		d_printf("using configfile = %s\n", get_dyn_CONFIGFILE());
	}

	msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());
	if (msg_ctx == NULL) {
		fprintf(stderr, "Could not initialize messaging, not root?\n");
		ret = -1;
		goto done;
	}

	switch (profile_only) {
		case 'P':
			/* Dump profile data */
			ok = status_profile_dump(verbose, &state);
			ret = ok ? 0 : 1;
			goto done;
		case 'R':
			/* Continuously display rate-converted data */
			if (!state.json_output) {
				ok = status_profile_rates(verbose);
				ret = ok ? 0 : 1;
			} else {
				fprintf(stderr, "Call rates not available in a json output.\n");
				ret = 1;
			}
			goto done;
		default:
			break;
	}

	if ( show_processes ) {
		prepare_sessionid(&state);
		sessionid_traverse_read(traverse_sessionid, &state);

		if (processes_only) {
			goto done;
		}
	}

	if ( show_shares ) {
		if (brief) {
			goto done;
		}
		prepare_connections(&state);
		connections_forall_read(traverse_connections, &state);

		if (!state.json_output) {
			d_printf("\n");
		}

		if ( shares_only ) {
			goto done;
		}
	}

	if ( show_locks ) {
		int result;
		struct db_context *db;

		db_path = lock_path(talloc_tos(), "locking.tdb");
		if (db_path == NULL) {
			fprintf(stderr, "Out of memory - exiting\n");
			ret = -1;
			goto done;
		}

		db = db_open(NULL, db_path, 0,
			     TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH, O_RDONLY, 0,
			     DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);

		if (!db) {
			fprintf(stderr, "%s not initialised\n", db_path);
			fprintf(stderr, "This is normal if an SMB client has never "
				 "connected to your server.\n");
			TALLOC_FREE(db_path);
			ret = 0;
			goto done;
		} else {
			TALLOC_FREE(db);
			TALLOC_FREE(db_path);
		}

		if (!locking_init_readonly()) {
			fprintf(stderr, "Can't initialise locking module - exiting\n");
			ret = 1;
			goto done;
		}

		prepare_share_mode(&state);
		result = share_entry_forall_read(print_share_mode, &state);

		if (result == 0 && !state.json_output) {
			fprintf(stderr, "No locked files\n");
		} else if (result < 0 && !state.json_output) {
			fprintf(stderr, "locked file list truncated\n");
		}

		if (!state.json_output) {
			d_printf("\n");
		}

		if (show_brl) {
			prepare_brl(&state);
			brl_forall(print_brl, &state);
		}

		locking_end();
	}

	if (show_notify) {
		prepare_notify(&state);
		notify_walk(msg_ctx, print_notify_rec, &state);
	}

done:
	cmdline_messaging_context_free();
	poptFreeContext(pc);
#ifdef HAVE_JANSSON
	if (state.json_output) {
		d_printf("%s\n", json_to_string(frame, &state.root_json));
	}
	json_free(&state.root_json);
#endif /* HAVE_JANSSON */
	TALLOC_FREE(frame);
	return ret;
}
