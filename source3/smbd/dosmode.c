/*
   Unix SMB/CIFS implementation.
   dos mode handling functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) James Peach 2006

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
#include "globals.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "librpc/gen_ndr/ioctl.h"
#include "../libcli/security/security.h"
#include "smbd/smbd.h"
#include "lib/param/loadparm.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/string_wrappers.h"
#include "fake_file.h"

static void dos_mode_debug_print(const char *func, uint32_t mode)
{
	fstring modestr;

	if (DEBUGLEVEL < DBGLVL_INFO) {
		return;
	}

	modestr[0] = '\0';

	if (mode & FILE_ATTRIBUTE_HIDDEN) {
		fstrcat(modestr, "h");
	}
	if (mode & FILE_ATTRIBUTE_READONLY) {
		fstrcat(modestr, "r");
	}
	if (mode & FILE_ATTRIBUTE_SYSTEM) {
		fstrcat(modestr, "s");
	}
	if (mode & FILE_ATTRIBUTE_DIRECTORY) {
		fstrcat(modestr, "d");
	}
	if (mode & FILE_ATTRIBUTE_ARCHIVE) {
		fstrcat(modestr, "a");
	}
	if (mode & FILE_ATTRIBUTE_SPARSE) {
		fstrcat(modestr, "[sparse]");
	}
	if (mode & FILE_ATTRIBUTE_OFFLINE) {
		fstrcat(modestr, "[offline]");
	}
	if (mode & FILE_ATTRIBUTE_COMPRESSED) {
		fstrcat(modestr, "[compressed]");
	}
	if (mode & FILE_ATTRIBUTE_REPARSE_POINT) {
		fstrcat(modestr, "[reparse_point]");
	}

	DBG_INFO("%s returning (0x%" PRIx32 "): \"%s\"\n",
		 func,
		 mode,
		 modestr);
}

static uint32_t filter_mode_by_protocol(enum protocol_types protocol,
					uint32_t mode)
{
	if (protocol <= PROTOCOL_LANMAN2) {
		DEBUG(10,("filter_mode_by_protocol: "
			"filtering result 0x%x to 0x%x\n",
			(unsigned int)mode,
			(unsigned int)(mode & 0x3f) ));
		mode &= 0x3f;
	}
	return mode;
}

mode_t apply_conf_file_mask(struct connection_struct *conn, mode_t mode)
{
	mode &= lp_create_mask(SNUM(conn));
	mode |= lp_force_create_mode(SNUM(conn));
	return mode;
}

mode_t apply_conf_dir_mask(struct connection_struct *conn, mode_t mode)
{
	mode &= lp_directory_mask(SNUM(conn));
	mode |= lp_force_directory_mode(SNUM(conn));
	return mode;
}

/****************************************************************************
 Change a dos mode to a unix mode.
    Base permission for files:
         if creating file and inheriting (i.e. parent_dir != NULL)
           apply read/write bits from parent directory.
         else
           everybody gets read bit set
         dos readonly is represented in unix by removing everyone's write bit
         dos archive is represented in unix by the user's execute bit
         dos system is represented in unix by the group's execute bit
         dos hidden is represented in unix by the other's execute bit
         if !inheriting {
           Then apply create mask,
           then add force bits.
         }
    Base permission for directories:
         dos directory is represented in unix by unix's dir bit and the exec bit
         if !inheriting {
           Then apply create mask,
           then add force bits.
         }
****************************************************************************/

mode_t unix_mode(connection_struct *conn, int dosmode,
		 const struct smb_filename *smb_fname,
		 struct files_struct *parent_dirfsp)
{
	mode_t result = (S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
	mode_t dir_mode = 0; /* Mode of the inherit_from directory if
			      * inheriting. */

	if ((dosmode & FILE_ATTRIBUTE_READONLY) &&
	    !lp_store_dos_attributes(SNUM(conn))) {
		result &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
	}

	if ((parent_dirfsp != NULL) && lp_inherit_permissions(SNUM(conn))) {
		struct stat_ex sbuf = { .st_ex_nlink = 0, };
		int ret;

		DBG_DEBUG("[%s] inheriting from [%s]\n",
			  smb_fname_str_dbg(smb_fname),
			  smb_fname_str_dbg(parent_dirfsp->fsp_name));

		ret = SMB_VFS_FSTAT(parent_dirfsp, &sbuf);
		if (ret != 0) {
			DBG_ERR("fstat failed [%s]: %s\n",
				smb_fname_str_dbg(parent_dirfsp->fsp_name),
				strerror(errno));
			return(0);      /* *** shouldn't happen! *** */
		}

		/* Save for later - but explicitly remove setuid bit for safety. */
		dir_mode = sbuf.st_ex_mode & ~S_ISUID;
		DEBUG(2,("unix_mode(%s) inherit mode %o\n",
			 smb_fname_str_dbg(smb_fname), (int)dir_mode));
		/* Clear "result" */
		result = 0;
	}

	if (dosmode & FILE_ATTRIBUTE_DIRECTORY) {
		/* We never make directories read only for the owner as under DOS a user
		can always create a file in a read-only directory. */
		result |= (S_IFDIR | S_IWUSR);

		if (dir_mode) {
			/* Inherit mode of parent directory. */
			result |= dir_mode;
		} else {
			/* Provisionally add all 'x' bits */
			result |= (S_IXUSR | S_IXGRP | S_IXOTH);
			result = apply_conf_dir_mask(conn, result);
		}
	} else {
		if ((dosmode & FILE_ATTRIBUTE_ARCHIVE) &&
		    lp_map_archive(SNUM(conn))) {
			result |= S_IXUSR;
		}

		if ((dosmode & FILE_ATTRIBUTE_SYSTEM) &&
		    lp_map_system(SNUM(conn))) {
			result |= S_IXGRP;
		}

		if ((dosmode & FILE_ATTRIBUTE_HIDDEN) &&
		    lp_map_hidden(SNUM(conn))) {
			result |= S_IXOTH;
		}

		if (dir_mode) {
			/* Inherit 666 component of parent directory mode */
			result |= dir_mode & (S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
		} else {
			result = apply_conf_file_mask(conn, result);
		}
	}

	DBG_INFO("unix_mode(%s) returning 0%o\n",
		 smb_fname_str_dbg(smb_fname), (int)result);

	return(result);
}

/****************************************************************************
 Change a unix mode to a dos mode.
****************************************************************************/

static uint32_t dos_mode_from_sbuf(connection_struct *conn,
				   const struct stat_ex *st,
				   struct files_struct *fsp)
{
	int result = 0;
	enum mapreadonly_options ro_opts =
		(enum mapreadonly_options)lp_map_readonly(SNUM(conn));

#if defined(UF_IMMUTABLE) && defined(SF_IMMUTABLE)
	/* if we can find out if a file is immutable we should report it r/o */
	if (st->st_ex_flags & (UF_IMMUTABLE | SF_IMMUTABLE)) {
		result |= FILE_ATTRIBUTE_READONLY;
	}
#endif
	if (ro_opts == MAP_READONLY_YES) {
		/* Original Samba method - map inverse of user "w" bit. */
		if ((st->st_ex_mode & S_IWUSR) == 0) {
			result |= FILE_ATTRIBUTE_READONLY;
		}
	}
	if (ro_opts == MAP_READONLY_PERMISSIONS) {
		/* smb_fname->fsp can be NULL for an MS-DFS link. */
		/* Check actual permissions for read-only. */
		if ((fsp != NULL) && !can_write_to_fsp(fsp)) {
			result |= FILE_ATTRIBUTE_READONLY;
		}
	}

	if (MAP_ARCHIVE(conn) && ((st->st_ex_mode & S_IXUSR) != 0)) {
		result |= FILE_ATTRIBUTE_ARCHIVE;
	}

	if (MAP_SYSTEM(conn) && ((st->st_ex_mode & S_IXGRP) != 0)) {
		result |= FILE_ATTRIBUTE_SYSTEM;
	}

	if (MAP_HIDDEN(conn) && ((st->st_ex_mode & S_IXOTH) != 0)) {
		result |= FILE_ATTRIBUTE_HIDDEN;
	}

	if (S_ISDIR(st->st_ex_mode)) {
		result = FILE_ATTRIBUTE_DIRECTORY |
			 (result & FILE_ATTRIBUTE_READONLY);
	}

	dos_mode_debug_print(__func__, result);

	return result;
}

/****************************************************************************
 Get DOS attributes from an EA.
 This can also pull the create time into the stat struct inside smb_fname.
****************************************************************************/

NTSTATUS parse_dos_attribute_blob(struct smb_filename *smb_fname,
				  DATA_BLOB blob,
				  uint32_t *pattr)
{
	struct xattr_DOSATTRIB dosattrib;
	enum ndr_err_code ndr_err;
	uint32_t dosattr;

	ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &dosattrib,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_DOSATTRIB);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("bad ndr decode "
			    "from EA on file %s: Error = %s\n",
			    smb_fname_str_dbg(smb_fname),
			    ndr_errstr(ndr_err));
		return ndr_map_error2ntstatus(ndr_err);
	}

	DBG_DEBUG("%s attr = %s\n",
		  smb_fname_str_dbg(smb_fname), dosattrib.attrib_hex);

	switch (dosattrib.version) {
	case 0xFFFF:
		dosattr = dosattrib.info.compatinfoFFFF.attrib;
		break;
	case 1:
		dosattr = dosattrib.info.info1.attrib;
		if (!null_nttime(dosattrib.info.info1.create_time)) {
			struct timespec create_time =
				nt_time_to_unix_timespec(
					dosattrib.info.info1.create_time);

			update_stat_ex_create_time(&smb_fname->st,
						   create_time);

			DBG_DEBUG("file %s case 1 set btime %s",
				  smb_fname_str_dbg(smb_fname),
				  time_to_asc(convert_timespec_to_time_t(
						      create_time)));
		}
		break;
	case 2:
		dosattr = dosattrib.info.oldinfo2.attrib;
		/* Don't know what flags to check for this case. */
		break;
	case 3:
		dosattr = dosattrib.info.info3.attrib;
		if ((dosattrib.info.info3.valid_flags & XATTR_DOSINFO_CREATE_TIME) &&
		    !null_nttime(dosattrib.info.info3.create_time)) {
			struct timespec create_time =
				nt_time_to_full_timespec(
					dosattrib.info.info3.create_time);

			update_stat_ex_create_time(&smb_fname->st,
						   create_time);

			DBG_DEBUG("file %s case 3 set btime %s",
				  smb_fname_str_dbg(smb_fname),
				  time_to_asc(convert_timespec_to_time_t(
						      create_time)));
		}
		break;
	case 4:
	case 5:
	{
		uint32_t info_valid_flags;
		NTTIME info_create_time;

		if (dosattrib.version == 4) {
			info_valid_flags = dosattrib.info.info4.valid_flags;
			info_create_time = dosattrib.info.info4.create_time;
			dosattr = dosattrib.info.info4.attrib;
		} else {
			info_valid_flags = dosattrib.info.info5.valid_flags;
			info_create_time = dosattrib.info.info5.create_time;
			dosattr = dosattrib.info.info5.attrib;
		}

		if ((info_valid_flags & XATTR_DOSINFO_CREATE_TIME) &&
		    !null_nttime(info_create_time))
		{
			struct timespec creat_time;

			creat_time = nt_time_to_full_timespec(info_create_time);
			update_stat_ex_create_time(&smb_fname->st, creat_time);

			DBG_DEBUG("file [%s] creation time [%s]\n",
				smb_fname_str_dbg(smb_fname),
				nt_time_string(talloc_tos(), info_create_time));
		}

		break;
	}
	default:
		DBG_WARNING("Badly formed DOSATTRIB on file %s - %s\n",
			    smb_fname_str_dbg(smb_fname), blob.data);
		/* Should this be INTERNAL_ERROR? */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		dosattr |= FILE_ATTRIBUTE_DIRECTORY;
	}

	/*
	 * _SPARSE and _REPARSE_POINT are valid on get but not on
	 * set. Both are created via special fcntls.
	 */

	dosattr &= (SAMBA_ATTRIBUTES_MASK|
		    FILE_ATTRIBUTE_SPARSE|
		    FILE_ATTRIBUTE_REPARSE_POINT);

	*pattr |= dosattr;

	dos_mode_debug_print(__func__, *pattr);

	return NT_STATUS_OK;
}

NTSTATUS fget_ea_dos_attribute(struct files_struct *fsp,
			      uint32_t *pattr)
{
	DATA_BLOB blob;
	ssize_t sizeret;
	fstring attrstr;
	NTSTATUS status;

	if (!lp_store_dos_attributes(SNUM(fsp->conn))) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* Don't reset pattr to zero as we may already have filename-based attributes we
	   need to preserve. */

	sizeret = SMB_VFS_FGETXATTR(fsp,
				    SAMBA_XATTR_DOS_ATTRIB,
				    attrstr,
				    sizeof(attrstr));
	if (sizeret == -1 && ( errno == EPERM || errno == EACCES )) {
		/* we may also retrieve dos attribs for unreadable files, this
		   is why we'll retry as root. We don't use root in the first
		   run because in cases like NFS, root might have even less
		   rights than the real user
		*/
		become_root();
		sizeret = SMB_VFS_FGETXATTR(fsp,
					    SAMBA_XATTR_DOS_ATTRIB,
					    attrstr,
					    sizeof(attrstr));
		unbecome_root();
	}
	if (sizeret == -1) {
		DBG_INFO("Cannot get attribute "
			 "from EA on file %s: Error = %s\n",
			 fsp_str_dbg(fsp), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	blob.data = (uint8_t *)attrstr;
	blob.length = sizeret;

	status = parse_dos_attribute_blob(fsp->fsp_name, blob, pattr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Set DOS attributes in an EA.
 Also sets the create time.
****************************************************************************/

NTSTATUS set_ea_dos_attribute(connection_struct *conn,
			      struct smb_filename *smb_fname,
			      uint32_t dosmode)
{
	struct xattr_DOSATTRIB dosattrib = { .version = 0, };
	enum ndr_err_code ndr_err;
	DATA_BLOB blob = { .data = NULL, };
	struct timespec btime;
	int ret;

	if (!lp_store_dos_attributes(SNUM(conn))) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (smb_fname->fsp == NULL) {
		/* symlink */
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	/*
	 * Don't store FILE_ATTRIBUTE_OFFLINE, it's dealt with in
	 * vfs_default via DMAPI if that is enabled.
	 */
	dosmode &= ~FILE_ATTRIBUTE_OFFLINE;

	dosattrib.version = 5;
	dosattrib.info.info5.valid_flags = XATTR_DOSINFO_ATTRIB |
					XATTR_DOSINFO_CREATE_TIME;
	dosattrib.info.info5.attrib = dosmode;
	dosattrib.info.info5.create_time = full_timespec_to_nt_time(
		&smb_fname->st.st_ex_btime);

	DBG_DEBUG("set attribute 0x%" PRIx32 ", btime = %s on file %s\n",
		  dosmode,
		  time_to_asc(convert_timespec_to_time_t(
			  smb_fname->st.st_ex_btime)),
		  smb_fname_str_dbg(smb_fname));

	ndr_err = ndr_push_struct_blob(
			&blob, talloc_tos(), &dosattrib,
			(ndr_push_flags_fn_t)ndr_push_xattr_DOSATTRIB);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("create_acl_blob: ndr_push_xattr_DOSATTRIB failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (blob.data == NULL || blob.length == 0) {
		/* Should this be INTERNAL_ERROR? */
		return NT_STATUS_INVALID_PARAMETER;
	}

	ret = SMB_VFS_FSETXATTR(smb_fname->fsp,
			       SAMBA_XATTR_DOS_ATTRIB,
			       blob.data, blob.length, 0);
	if (ret != 0) {
		NTSTATUS status = NT_STATUS_OK;
		bool set_dosmode_ok = false;

		if ((errno != EPERM) && (errno != EACCES)) {
			DBG_INFO("Cannot set "
				 "attribute EA on file %s: Error = %s\n",
				 smb_fname_str_dbg(smb_fname), strerror(errno));
			return map_nt_error_from_unix(errno);
		}

		/* We want DOS semantics, ie allow non owner with write permission to change the
			bits on a file. Just like file_ntimes below.
		*/

		/* Check if we have write access. */
		if (!CAN_WRITE(conn)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		status = smbd_check_access_rights_fsp(conn->cwd_fsp,
					smb_fname->fsp,
					false,
					FILE_WRITE_ATTRIBUTES);
		if (NT_STATUS_IS_OK(status)) {
			set_dosmode_ok = true;
		}

		if (!set_dosmode_ok && lp_dos_filemode(SNUM(conn))) {
			set_dosmode_ok = can_write_to_fsp(smb_fname->fsp);
		}

		if (!set_dosmode_ok) {
			return NT_STATUS_ACCESS_DENIED;
		}

		become_root();
		ret = SMB_VFS_FSETXATTR(smb_fname->fsp,
					SAMBA_XATTR_DOS_ATTRIB,
					blob.data, blob.length, 0);
		if (ret == 0) {
			status = NT_STATUS_OK;
		}
		unbecome_root();
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/*
	 * We correctly stored the create time.
	 * We *always* set XATTR_DOSINFO_CREATE_TIME,
	 * so now it can no longer be considered
	 * calculated. Make sure to use the value rounded
	 * to NTTIME granularity we've stored in the xattr.
	 */
	btime = nt_time_to_full_timespec(dosattrib.info.info5.create_time);
	update_stat_ex_create_time(&smb_fname->st, btime);

	DBG_DEBUG("set EA 0x%" PRIx32 " on file %s\n",
		  dosmode,
		  smb_fname_str_dbg(smb_fname));
	return NT_STATUS_OK;
}

static uint32_t
dos_mode_from_name(connection_struct *conn, const char *name, uint32_t dosmode)
{
	const char *p = NULL;
	uint32_t result = dosmode;

	if (!(result & FILE_ATTRIBUTE_HIDDEN) &&
	    lp_hide_dot_files(SNUM(conn)))
	{
		p = strrchr_m(name, '/');
		if (p) {
			p++;
		} else {
			p = name;
		}

		/* Only . and .. are not hidden. */
		if ((p[0] == '.') && !(ISDOT(p) || ISDOTDOT(p))) {
			result |= FILE_ATTRIBUTE_HIDDEN;
		}
	}

	if (!(result & FILE_ATTRIBUTE_HIDDEN) && IS_HIDDEN_PATH(conn, name)) {
		result |= FILE_ATTRIBUTE_HIDDEN;
	}

	return result;
}

/****************************************************************************
 Change a unix mode to a dos mode for an ms dfs link.
****************************************************************************/

uint32_t dos_mode_msdfs(connection_struct *conn,
			const char *name,
			const struct stat_ex *st)
{
	uint32_t result = 0;

	DEBUG(8, ("dos_mode_msdfs: %s\n", name));

	if (!VALID_STAT(*st)) {
		return 0;
	}

	result = dos_mode_from_name(conn, name, result);
	result |= dos_mode_from_sbuf(conn, st, NULL);

	if (result == 0) {
		result = FILE_ATTRIBUTE_NORMAL;
	}

	result = filter_mode_by_protocol(conn_protocol(conn->sconn), result);

	/*
	 * Add in that it is a reparse point
	 */
	result |= FILE_ATTRIBUTE_REPARSE_POINT;

	dos_mode_debug_print(__func__, result);

	return(result);
}

/*
 * check whether a file or directory is flagged as compressed.
 */
static NTSTATUS dos_mode_check_compressed(struct files_struct *fsp,
					  bool *is_compressed)
{
	NTSTATUS status;
	uint16_t compression_fmt;

	status = SMB_VFS_FGET_COMPRESSION(
		fsp->conn, talloc_tos(), fsp, &compression_fmt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (compression_fmt == COMPRESSION_FORMAT_LZNT1) {
		*is_compressed = true;
	} else {
		*is_compressed = false;
	}
	return NT_STATUS_OK;
}

static uint32_t dos_mode_post(uint32_t dosmode,
			      struct files_struct *fsp,
			      const char *func)
{
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	if (fsp != NULL) {
		smb_fname = fsp->fsp_name;
	}
	SMB_ASSERT(smb_fname != NULL);

	/*
	 * According to MS-FSA a stream name does not have
	 * separate DOS attribute metadata, so we must return
	 * the DOS attribute from the base filename. With one caveat,
	 * a non-default stream name can never be a directory.
	 *
	 * As this is common to all streams data stores, we handle
	 * it here instead of inside all stream VFS modules.
	 *
	 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13380
	 */

	if (is_named_stream(smb_fname)) {
		/* is_ntfs_stream_smb_fname() returns false for a POSIX path. */
		dosmode &= ~(FILE_ATTRIBUTE_DIRECTORY);
	}

	if (fsp->conn->fs_capabilities & FILE_FILE_COMPRESSION) {
		bool compressed = false;

		status = dos_mode_check_compressed(fsp, &compressed);
		if (NT_STATUS_IS_OK(status) && compressed) {
			dosmode |= FILE_ATTRIBUTE_COMPRESSED;
		}
	}

	dosmode |= dos_mode_from_name(fsp->conn, smb_fname->base_name, dosmode);

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		dosmode |= FILE_ATTRIBUTE_DIRECTORY;
	} else if (dosmode == 0) {
		dosmode = FILE_ATTRIBUTE_NORMAL;
	}

	dosmode = filter_mode_by_protocol(conn_protocol(fsp->conn->sconn),
					  dosmode);

	dos_mode_debug_print(func, dosmode);
	return dosmode;
}

/****************************************************************************
 Change a unix mode to a dos mode.
 May also read the create timespec into the stat struct in smb_fname
 if "store dos attributes" is true.
****************************************************************************/

uint32_t fdos_mode(struct files_struct *fsp)
{
	uint32_t result = 0;
	NTSTATUS status = NT_STATUS_OK;

	DBG_DEBUG("%s\n", fsp_str_dbg(fsp));

	if (fsp->fake_file_handle != NULL) {
		return dosmode_from_fake_filehandle(fsp->fake_file_handle);
	}

	if (!VALID_STAT(fsp->fsp_name->st)) {
		return 0;
	}

	switch (fsp->fsp_name->st.st_ex_mode & S_IFMT) {
	case S_IFLNK:
		return FILE_ATTRIBUTE_NORMAL;
		break;
	case S_IFIFO:
	case S_IFSOCK:
	case S_IFBLK:
	case S_IFCHR:
		return FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_REPARSE_POINT;
		break;
	default:
		break;
	}

	if (fsp->fsp_name->st.cached_dos_attributes != FILE_ATTRIBUTE_INVALID) {
		return fsp->fsp_name->st.cached_dos_attributes;
	}

	/* Get the DOS attributes via the VFS if we can */
	status = SMB_VFS_FGET_DOS_ATTRIBUTES(fsp->conn,
					     metadata_fsp(fsp),
					     &result);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
		result |= dos_mode_from_sbuf(fsp->conn,
					     &fsp->fsp_name->st,
					     fsp);
	}

	fsp->fsp_name->st.cached_dos_attributes = dos_mode_post(result, fsp, __func__);
	return fsp->fsp_name->st.cached_dos_attributes;
}

struct dos_mode_at_state {
	files_struct *dir_fsp;
	struct smb_filename *smb_fname;
	uint32_t dosmode;
};

static void dos_mode_at_vfs_get_dosmode_done(struct tevent_req *subreq);

struct tevent_req *dos_mode_at_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    files_struct *dir_fsp,
				    struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct dos_mode_at_state *state = NULL;
	struct tevent_req *subreq = NULL;

	DBG_DEBUG("%s\n", smb_fname_str_dbg(smb_fname));

	req = tevent_req_create(mem_ctx, &state,
				struct dos_mode_at_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct dos_mode_at_state) {
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
	};

	if (!VALID_STAT(smb_fname->st)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (smb_fname->fsp == NULL) {
		if (ISDOTDOT(smb_fname->base_name)) {
			/*
			 * smb_fname->fsp is explicitly closed
			 * for ".." to prevent meta-data leakage.
			 */
			state->dosmode = FILE_ATTRIBUTE_DIRECTORY;
		} else {
			/*
			 * This is a symlink in POSIX context.
			 * FIXME ? Should we move to returning
			 * FILE_ATTRIBUTE_REPARSE_POINT here ?
			 */
			state->dosmode = FILE_ATTRIBUTE_NORMAL;
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_GET_DOS_ATTRIBUTES_SEND(state,
						 ev,
						 dir_fsp,
						 smb_fname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dos_mode_at_vfs_get_dosmode_done, req);

	return req;
}

static void dos_mode_at_vfs_get_dosmode_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct dos_mode_at_state *state =
		tevent_req_data(req,
		struct dos_mode_at_state);
	struct vfs_aio_state aio_state;
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->dir_fsp);
	SMB_ASSERT(ok);

	status = SMB_VFS_GET_DOS_ATTRIBUTES_RECV(subreq,
						 &aio_state,
						 &state->dosmode);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Both the sync dos_mode() as well as the async
		 * dos_mode_at_[send|recv] have no real error return, the only
		 * unhandled error is when the stat info in smb_fname is not
		 * valid (cf the checks in dos_mode() and dos_mode_at_send().
		 *
		 * If SMB_VFS_GET_DOS_ATTRIBUTES[_SEND|_RECV] fails we must call
		 * dos_mode_post() which also does the mapping of a last resort
		 * from S_IFMT(st_mode).
		 *
		 * Only if we get NT_STATUS_NOT_IMPLEMENTED or
		 * NT_STATUS_NOT_SUPPORTED from a stacked VFS module we must
		 * fallback to sync processing.
		 */
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED))
		{
			/*
			 * state->dosmode should still be 0, but reset
			 * it to be sure.
			 */
			state->dosmode = 0;
			status = NT_STATUS_OK;
		}
	}
	if (NT_STATUS_IS_OK(status)) {
		state->dosmode = dos_mode_post(state->dosmode,
					       state->smb_fname->fsp,
					       __func__);
		tevent_req_done(req);
		return;
	}

	/*
	 * Fall back to sync dos_mode() if we got NOT_IMPLEMENTED.
	 */

	state->dosmode = fdos_mode(state->smb_fname->fsp);
	tevent_req_done(req);
	return;
}

NTSTATUS dos_mode_at_recv(struct tevent_req *req, uint32_t *dosmode)
{
	struct dos_mode_at_state *state =
		tevent_req_data(req,
		struct dos_mode_at_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*dosmode = state->dosmode;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*******************************************************************
 chmod a file - but preserve some bits.
 If "store dos attributes" is also set it will store the create time
 from the stat struct in smb_fname (in NTTIME format) in the EA
 attribute also.
********************************************************************/

int file_set_dosmode(connection_struct *conn,
		     struct smb_filename *smb_fname,
		     uint32_t dosmode,
		     struct smb_filename *parent_dir,
		     bool newfile)
{
	int mask=0;
	mode_t tmp;
	mode_t unixmode;
	int ret = -1;
	NTSTATUS status;

	if (!CAN_WRITE(conn)) {
		errno = EROFS;
		return -1;
	}

	if (S_ISLNK(smb_fname->st.st_ex_mode)) {
		/* A symlink in POSIX context, ignore */
		return 0;
	}

	if ((S_ISDIR(smb_fname->st.st_ex_mode)) &&
	    (dosmode & FILE_ATTRIBUTE_TEMPORARY))
	{
		errno = EINVAL;
		return -1;
	}

	dosmode &= SAMBA_ATTRIBUTES_MASK;

	DEBUG(10,("file_set_dosmode: setting dos mode 0x%x on file %s\n",
		  dosmode, smb_fname_str_dbg(smb_fname)));

	if (smb_fname->fsp == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (smb_fname->fsp->fsp_flags.posix_open &&
	    !lp_store_dos_attributes(SNUM(conn)))
	{
		return 0;
	}

	unixmode = smb_fname->st.st_ex_mode;

	get_acl_group_bits(conn, smb_fname->fsp, &smb_fname->st.st_ex_mode);

	if (S_ISDIR(smb_fname->st.st_ex_mode))
		dosmode |= FILE_ATTRIBUTE_DIRECTORY;
	else
		dosmode &= ~FILE_ATTRIBUTE_DIRECTORY;

	/* Store the DOS attributes in an EA by preference. */
	status = SMB_VFS_FSET_DOS_ATTRIBUTES(conn,
					     metadata_fsp(smb_fname->fsp),
					     dosmode);
	if (NT_STATUS_IS_OK(status)) {
		smb_fname->st.cached_dos_attributes = dosmode;
		ret = 0;
		goto done;
	}

	/*
	 * Only fall back to using UNIX modes if
	 * we get NOT_IMPLEMENTED.
	 */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	/* Fall back to UNIX modes. */
	unixmode = unix_mode(
		conn,
		dosmode,
		smb_fname,
		parent_dir != NULL ? parent_dir->fsp : NULL);

	/* preserve the file type bits */
	mask |= S_IFMT;

	/* preserve the s bits */
	mask |= (S_ISUID | S_ISGID);

	/* preserve the t bit */
#ifdef S_ISVTX
	mask |= S_ISVTX;
#endif

	/* possibly preserve the x bits */
	if (!MAP_ARCHIVE(conn))
		mask |= S_IXUSR;
	if (!MAP_SYSTEM(conn))
		mask |= S_IXGRP;
	if (!MAP_HIDDEN(conn))
		mask |= S_IXOTH;

	unixmode |= (smb_fname->st.st_ex_mode & mask);

	/* if we previously had any r bits set then leave them alone */
	if ((tmp = smb_fname->st.st_ex_mode & (S_IRUSR|S_IRGRP|S_IROTH))) {
		unixmode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
		unixmode |= tmp;
	}

	/* if we previously had any w bits set then leave them alone
		whilst adding in the new w bits, if the new mode is not rdonly */
	if (!(dosmode & FILE_ATTRIBUTE_READONLY)) {
		unixmode |= (smb_fname->st.st_ex_mode & (S_IWUSR|S_IWGRP|S_IWOTH));
	}

	/*
	 * From the chmod 2 man page:
	 *
	 * "If the calling process is not privileged, and the group of the file
	 * does not match the effective group ID of the process or one of its
	 * supplementary group IDs, the S_ISGID bit will be turned off, but
	 * this will not cause an error to be returned."
	 *
	 * Simply refuse to do the chmod in this case.
	 */

	if (S_ISDIR(smb_fname->st.st_ex_mode) &&
	    (unixmode & S_ISGID) &&
	    geteuid() != sec_initial_uid() &&
	    !current_user_in_group(conn, smb_fname->st.st_ex_gid))
	{
		DEBUG(3,("file_set_dosmode: setgid bit cannot be "
			"set for directory %s\n",
			smb_fname_str_dbg(smb_fname)));
		errno = EPERM;
		return -1;
	}

	ret = SMB_VFS_FCHMOD(smb_fname->fsp, unixmode);
	if (ret == 0) {
		goto done;
	}

	if((errno != EPERM) && (errno != EACCES))
		return -1;

	if(!lp_dos_filemode(SNUM(conn)))
		return -1;

	/* We want DOS semantics, ie allow non owner with write permission to change the
		bits on a file. Just like file_ntimes below.
	*/

	if (!can_write_to_fsp(smb_fname->fsp))
	{
		errno = EACCES;
		return -1;
	}

	become_root();
	ret = SMB_VFS_FCHMOD(smb_fname->fsp, unixmode);
	unbecome_root();

done:
	if (!newfile) {
		notify_fname(conn,
			     NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     smb_fname,
			     NULL);
	}
	if (ret == 0) {
		smb_fname->st.st_ex_mode = unixmode;
	}

	return( ret );
}


NTSTATUS file_set_sparse(connection_struct *conn,
			 files_struct *fsp,
			 bool sparse)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uint32_t old_dosmode;
	uint32_t new_dosmode;
	NTSTATUS status;

	if (!CAN_WRITE(conn)) {
		DEBUG(9,("file_set_sparse: fname[%s] set[%u] "
			"on readonly share[%s]\n",
			smb_fname_str_dbg(fsp->fsp_name),
			sparse,
			lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	/*
	 * Windows Server 2008 & 2012 permit FSCTL_SET_SPARSE if any of the
	 * following access flags are granted.
	 */
	status = check_any_access_fsp(fsp,
				  FILE_WRITE_DATA
				  | FILE_WRITE_ATTRIBUTES
				  | SEC_FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fname[%s] set[%u] "
			  "access_mask[0x%08X] - access denied\n",
			  smb_fname_str_dbg(fsp->fsp_name),
			  sparse,
			  fsp->access_mask);
		return status;
	}

	if (fsp->fsp_flags.is_directory) {
		DEBUG(9, ("invalid attempt to %s sparse flag on dir %s\n",
			  (sparse ? "set" : "clear"),
			  smb_fname_str_dbg(fsp->fsp_name)));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (IS_IPC(conn) || IS_PRINT(conn)) {
		DEBUG(9, ("attempt to %s sparse flag over invalid conn\n",
			  (sparse ? "set" : "clear")));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp_is_alternate_stream(fsp)) {
		/*
		 * MS-FSA 2.1.1.5 IsSparse
		 *
		 * This is a per stream attribute, but our backends don't
		 * support it a consistent way, therefore just pretend
		 * success and ignore the request.
		 */
		DBG_DEBUG("Ignoring request to set FILE_ATTRIBUTE_SPARSE on "
			  "[%s]\n", fsp_str_dbg(fsp));
		return NT_STATUS_OK;
	}

	DEBUG(10,("file_set_sparse: setting sparse bit %u on file %s\n",
		  sparse, smb_fname_str_dbg(fsp->fsp_name)));

	if (!lp_store_dos_attributes(SNUM(conn))) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	old_dosmode = fdos_mode(fsp);

	if (sparse && !(old_dosmode & FILE_ATTRIBUTE_SPARSE)) {
		new_dosmode = old_dosmode | FILE_ATTRIBUTE_SPARSE;
	} else if (!sparse && (old_dosmode & FILE_ATTRIBUTE_SPARSE)) {
		new_dosmode = old_dosmode & ~FILE_ATTRIBUTE_SPARSE;
	} else {
		return NT_STATUS_OK;
	}

	/* Store the DOS attributes in an EA. */
	status = SMB_VFS_FSET_DOS_ATTRIBUTES(conn, fsp, new_dosmode);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	notify_fname(conn,
		     NOTIFY_ACTION_MODIFIED,
		     FILE_NOTIFY_CHANGE_ATTRIBUTES,
		     fsp->fsp_name,
		     NULL);

	fsp->fsp_name->st.cached_dos_attributes = new_dosmode;
	fsp->fsp_flags.is_sparse = sparse;

	return NT_STATUS_OK;
}

/*******************************************************************
 Wrapper around the VFS ntimes that possibly allows DOS semantics rather
 than POSIX.
*******************************************************************/

int file_ntimes(connection_struct *conn,
		files_struct *fsp,
		struct smb_file_time *ft)
{
	int ret = -1;

	errno = 0;

	DBG_INFO("actime: %s",
		 time_to_asc(convert_timespec_to_time_t(ft->atime)));
	DBG_INFO("modtime: %s",
		 time_to_asc(convert_timespec_to_time_t(ft->mtime)));
	DBG_INFO("ctime: %s",
		 time_to_asc(convert_timespec_to_time_t(ft->ctime)));
	DBG_INFO("createtime: %s",
		 time_to_asc(convert_timespec_to_time_t(ft->create_time)));

	/* Don't update the time on read-only shares */
	/* We need this as set_filetime (which can be called on
	   close and other paths) can end up calling this function
	   without the NEED_WRITE protection. Found by :
	   Leo Weppelman <leo@wau.mis.ah.nl>
	*/

	if (!CAN_WRITE(conn)) {
		return 0;
	}

	if (SMB_VFS_FNTIMES(fsp, ft) == 0) {
		ret = 0;
		goto done;
	}

	if((errno != EPERM) && (errno != EACCES)) {
		return -1;
	}

	if(!lp_dos_filetimes(SNUM(conn))) {
		return -1;
	}

	/* We have permission (given by the Samba admin) to
	   break POSIX semantics and allow a user to change
	   the time on a file they don't own but can write to
	   (as DOS does).
	 */

	/* Check if we have write access. */
	if (can_write_to_fsp(fsp)) {
		/* We are allowed to become root and change the filetime. */
		become_root();
		ret = SMB_VFS_FNTIMES(fsp, ft);
		unbecome_root();
	}

done:
	if (ret == 0) {
		copy_stat_ex_timestamps(&fsp->fsp_name->st, ft);
	}

	return ret;
}

/******************************************************************
 Force a "sticky" write time on an fsp. This will always be
 returned on all future write time queries and set on close.
******************************************************************/

bool set_sticky_write_time_fsp(struct files_struct *fsp, struct timespec mtime)
{
	bool ok;

	if (is_omit_timespec(&mtime)) {
		return true;
	}

	fsp->fsp_flags.write_time_forced = true;
	TALLOC_FREE(fsp->update_write_time_event);

	ok = set_sticky_write_time(fsp->file_id, mtime);
	return ok;
}

/******************************************************************
 Set a create time EA.
******************************************************************/

NTSTATUS set_create_timespec_ea(struct files_struct *fsp,
				struct timespec create_time)
{
	uint32_t dosmode;
	int ret;

	if (!lp_store_dos_attributes(SNUM(fsp->conn))) {
		return NT_STATUS_OK;
	}

	dosmode = fdos_mode(fsp);

	fsp->fsp_name->st.st_ex_btime = create_time;
	ret = file_set_dosmode(fsp->conn, fsp->fsp_name, dosmode, NULL, false);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	DBG_DEBUG("wrote create time EA for file %s\n",
		smb_fname_str_dbg(fsp->fsp_name));

	return NT_STATUS_OK;
}

/******************************************************************
 Return a create time.
******************************************************************/

struct timespec get_create_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname)
{
	if (fsp != NULL) {
		struct files_struct *meta_fsp = metadata_fsp(fsp);
		return meta_fsp->fsp_name->st.st_ex_btime;
	}
	return smb_fname->st.st_ex_btime;
}

/******************************************************************
 Return a change time (may look at EA in future).
******************************************************************/

struct timespec get_change_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname)
{
	return smb_fname->st.st_ex_mtime;
}
