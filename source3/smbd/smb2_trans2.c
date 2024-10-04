/*
   Unix SMB/CIFS implementation.
   SMB transaction2 handling
   Copyright (C) Jeremy Allison			1994-2007
   Copyright (C) Stefan (metze) Metzmacher	2003
   Copyright (C) Volker Lendecke		2005-2007
   Copyright (C) Steve French			2005
   Copyright (C) James Peach			2006-2007

   Extensively modified by Andrew Tridgell, 1995

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
#include "ntioctl.h"
#include "system/filesys.h"
#include "lib/util/time_basic.h"
#include "version.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/xattr.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../librpc/gen_ndr/ndr_smb3posix.h"
#include "libcli/security/security.h"
#include "trans2.h"
#include "auth.h"
#include "smbprofile.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "printing.h"
#include "lib/util_ea.h"
#include "lib/readdir_attr.h"
#include "messages.h"
#include "libcli/smb/smb2_posix.h"
#include "lib/util/string_wrappers.h"
#include "source3/lib/substitute.h"
#include "source3/lib/adouble.h"
#include "source3/smbd/dir.h"
#include "source3/modules/util_reparse.h"

#define DIR_ENTRY_SAFETY_MARGIN 4096

static uint32_t generate_volume_serial_number(
				const struct loadparm_substitution *lp_sub,
				int snum);

/****************************************************************************
 Check if an open file handle is a symlink.
****************************************************************************/

NTSTATUS refuse_symlink_fsp(const files_struct *fsp)
{

	if (!VALID_STAT(fsp->fsp_name->st)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	if (S_ISLNK(fsp->fsp_name->st.st_ex_mode)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	if (fsp_get_pathref_fd(fsp) == -1) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

/**
 * Check that one or more of the rights in access mask are
 * allowed. Iow, access_requested can contain more then one right and
 * it is sufficient having only one of those granted to pass.
 **/
NTSTATUS check_any_access_fsp(struct files_struct *fsp,
			      uint32_t access_requested)
{
	const uint32_t ro_access = SEC_RIGHTS_FILE_READ | SEC_FILE_EXECUTE;
	uint32_t ro_access_granted = 0;
	uint32_t access_granted = 0;
	NTSTATUS status;

	if (fsp->fsp_flags.is_fsa) {
		access_granted = fsp->access_mask;
	} else {
		uint32_t mask = 1;

		while (mask != 0) {
			if (!(mask & access_requested)) {
				mask <<= 1;
				continue;
			}

			status = smbd_check_access_rights_fsp(
							fsp->conn->cwd_fsp,
							fsp,
							false,
							mask);
			if (NT_STATUS_IS_OK(status)) {
				access_granted |= mask;
				if (fsp->fsp_name->twrp == 0) {
					/*
					 * We can only optimize
					 * the non-snapshot case
					 */
					break;
				}
			}
			mask <<= 1;
		}
	}
	if ((access_granted & access_requested) == 0) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (fsp->fsp_name->twrp == 0) {
		return NT_STATUS_OK;
	}

	ro_access_granted = access_granted & ro_access;
	if ((ro_access_granted & access_requested) == 0) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	return NT_STATUS_OK;
}

/********************************************************************
 Roundup a value to the nearest allocation roundup size boundary.
 Only do this for Windows clients.
********************************************************************/

uint64_t smb_roundup(connection_struct *conn, uint64_t val)
{
	uint64_t rval = lp_allocation_roundup_size(SNUM(conn));

	/* Only roundup for Windows clients. */
	enum remote_arch_types ra_type = get_remote_arch();
	if (rval && (ra_type != RA_SAMBA) && (ra_type != RA_CIFSFS)) {
		val = SMB_ROUNDUP(val,rval);
	}
	return val;
}

/****************************************************************************
 Utility functions for dealing with extended attributes.
****************************************************************************/

/****************************************************************************
 Refuse to allow clients to overwrite our private xattrs.
****************************************************************************/

bool samba_private_attr_name(const char *unix_ea_name)
{
	bool prohibited = false;

	prohibited |= strequal(unix_ea_name, SAMBA_POSIX_INHERITANCE_EA_NAME);
	prohibited |= strequal(unix_ea_name, SAMBA_XATTR_DOS_ATTRIB);
	prohibited |= strequal(unix_ea_name, SAMBA_XATTR_MARKER);
	prohibited |= strequal(unix_ea_name, SAMBA_XATTR_REPARSE_ATTRIB);
	prohibited |= strequal(unix_ea_name, XATTR_NTACL_NAME);
	prohibited |= strequal(unix_ea_name, AFPINFO_EA_NETATALK);

	if (prohibited) {
		return true;
	}

	if (strncasecmp_m(unix_ea_name, SAMBA_XATTR_DOSSTREAM_PREFIX,
			strlen(SAMBA_XATTR_DOSSTREAM_PREFIX)) == 0) {
		return true;
	}
	return false;
}

/****************************************************************************
 Get one EA value. Fill in a struct ea_struct.
****************************************************************************/

NTSTATUS get_ea_value_fsp(TALLOC_CTX *mem_ctx,
			  files_struct *fsp,
			  const char *ea_name,
			  struct ea_struct *pea)
{
	/* Get the value of this xattr. Max size is 64k. */
	size_t attr_size = 256;
	char *val = NULL;
	ssize_t sizeret;
	size_t max_xattr_size = 0;
	NTSTATUS status;

	if (fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}
	status = refuse_symlink_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	max_xattr_size = lp_smbd_max_xattr_size(SNUM(fsp->conn));

 again:

	val = talloc_realloc(mem_ctx, val, char, attr_size);
	if (!val) {
		return NT_STATUS_NO_MEMORY;
	}

	sizeret = SMB_VFS_FGETXATTR(fsp, ea_name, val, attr_size);
	if (sizeret == -1 && errno == ERANGE && attr_size < max_xattr_size) {
		attr_size = max_xattr_size;
		goto again;
	}

	if (sizeret == -1) {
		return map_nt_error_from_unix(errno);
	}

	DBG_DEBUG("EA %s is of length %zd\n", ea_name, sizeret);
	dump_data(10, (uint8_t *)val, sizeret);

	pea->flags = 0;
	if (strnequal(ea_name, "user.", 5)) {
		pea->name = talloc_strdup(mem_ctx, &ea_name[5]);
	} else {
		pea->name = talloc_strdup(mem_ctx, ea_name);
	}
	if (pea->name == NULL) {
		TALLOC_FREE(val);
		return NT_STATUS_NO_MEMORY;
	}
	pea->value.data = (unsigned char *)val;
	pea->value.length = (size_t)sizeret;
	return NT_STATUS_OK;
}

NTSTATUS get_ea_names_from_fsp(TALLOC_CTX *mem_ctx,
				files_struct *fsp,
				char ***pnames,
				size_t *pnum_names)
{
	char smallbuf[1024];
	/* Get a list of all xattrs. Max namesize is 64k. */
	size_t ea_namelist_size = 1024;
	char *ea_namelist = smallbuf;
	char *to_free = NULL;

	char *p;
	char **names;
	size_t num_names;
	ssize_t sizeret = -1;
	NTSTATUS status;

	if (pnames) {
		*pnames = NULL;
	}
	*pnum_names = 0;

	if ((fsp == NULL) || !NT_STATUS_IS_OK(refuse_symlink_fsp(fsp))) {
		/*
		 * Callers may pass fsp == NULL when passing smb_fname->fsp of a
		 * symlink. This is ok, handle it here, by just return no EA's
		 * on a symlink.
		 */
		return NT_STATUS_OK;
	}

	sizeret = SMB_VFS_FLISTXATTR(fsp, ea_namelist,
				     ea_namelist_size);

	if ((sizeret == -1) && (errno == ERANGE)) {
		ea_namelist_size = 65536;
		ea_namelist = talloc_array(mem_ctx, char, ea_namelist_size);
		if (ea_namelist == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		to_free = ea_namelist;

		sizeret = SMB_VFS_FLISTXATTR(fsp, ea_namelist,
					     ea_namelist_size);
	}

	if (sizeret == -1) {
		status = map_nt_error_from_unix(errno);
		TALLOC_FREE(to_free);
		return status;
	}

	DBG_DEBUG("ea_namelist size = %zd\n", sizeret);

	if (sizeret == 0) {
		TALLOC_FREE(to_free);
		return NT_STATUS_OK;
	}

	/*
	 * Ensure the result is 0-terminated
	 */

	if (ea_namelist[sizeret-1] != '\0') {
		TALLOC_FREE(to_free);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * count the names
	 */
	num_names = 0;

	for (p = ea_namelist; p - ea_namelist < sizeret; p += strlen(p)+1) {
		num_names += 1;
	}

	*pnum_names = num_names;

	if (pnames == NULL) {
		TALLOC_FREE(to_free);
		return NT_STATUS_OK;
	}

	names = talloc_array(mem_ctx, char *, num_names);
	if (names == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(to_free);
		return NT_STATUS_NO_MEMORY;
	}

	if (ea_namelist == smallbuf) {
		ea_namelist = talloc_memdup(names, smallbuf, sizeret);
		if (ea_namelist == NULL) {
			TALLOC_FREE(names);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		talloc_steal(names, ea_namelist);

		ea_namelist = talloc_realloc(names, ea_namelist, char,
					     sizeret);
		if (ea_namelist == NULL) {
			TALLOC_FREE(names);
			return NT_STATUS_NO_MEMORY;
		}
	}

	num_names = 0;

	for (p = ea_namelist; p - ea_namelist < sizeret; p += strlen(p)+1) {
		names[num_names++] = p;
	}

	*pnames = names;

	return NT_STATUS_OK;
}

/****************************************************************************
 Return a linked list of the total EA's. Plus the total size
****************************************************************************/

static NTSTATUS get_ea_list_from_fsp(TALLOC_CTX *mem_ctx,
				files_struct *fsp,
				size_t *pea_total_len,
				struct ea_list **ea_list)
{
	/* Get a list of all xattrs. Max namesize is 64k. */
	size_t i, num_names;
	char **names;
	struct ea_list *ea_list_head = NULL;
	bool posix_pathnames = false;
	NTSTATUS status;

	*pea_total_len = 0;
	*ea_list = NULL;

	/* symlink */
	if (fsp == NULL) {
		return NT_STATUS_OK;
	}

	if (!lp_ea_support(SNUM(fsp->conn))) {
		return NT_STATUS_OK;
	}

	if (fsp_is_alternate_stream(fsp)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	posix_pathnames = (fsp->fsp_name->flags & SMB_FILENAME_POSIX_PATH);

	status = get_ea_names_from_fsp(talloc_tos(),
				fsp,
				&names,
				&num_names);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_names == 0) {
		return NT_STATUS_OK;
	}

	for (i=0; i<num_names; i++) {
		struct ea_list *listp;
		fstring dos_ea_name;

		/*
		 * POSIX EA names are divided into several namespaces by
		 * means of string prefixes. Usually, the system controls
		 * semantics for each namespace, but the 'user' namespace is
		 * available for arbitrary use, which comes closest to
		 * Windows EA semantics. Hence, we map POSIX EAs from the
		 * 'user' namespace to Windows EAs, and just ignore all the
		 * other namespaces. Also, a few specific names in the 'user'
		 * namespace are used by Samba internally. Filter them out as
		 * well, and only present the EAs that are available for
		 * arbitrary use.
		 */
		if (!strnequal(names[i], "user.", 5)
		    || samba_private_attr_name(names[i]))
			continue;

		/*
		 * Filter out any underlying POSIX EA names
		 * that a Windows client can't handle.
		 */
		if (!posix_pathnames &&
				is_invalid_windows_ea_name(names[i])) {
			continue;
		}

		listp = talloc(mem_ctx, struct ea_list);
		if (listp == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = get_ea_value_fsp(listp,
					  fsp,
					  names[i],
					  &listp->ea);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(listp);
			return status;
		}

		if (listp->ea.value.length == 0) {
			/*
			 * We can never return a zero length EA.
			 * Windows reports the EA's as corrupted.
			 */
			TALLOC_FREE(listp);
			continue;
		}
		if (listp->ea.value.length > 65536) {
			/*
			 * SMB clients may report error with file
			 * if large EA is presented to them.
			 */
			DBG_ERR("EA [%s] on file [%s] exceeds "
				"maximum permitted EA size of 64KiB: %zu\n.",
				listp->ea.name, fsp_str_dbg(fsp),
				listp->ea.value.length);
			TALLOC_FREE(listp);
			continue;
		}

		push_ascii_fstring(dos_ea_name, listp->ea.name);

		*pea_total_len +=
			4 + strlen(dos_ea_name) + 1 + listp->ea.value.length;

		DBG_DEBUG("total_len = %zu, %s, val len = %zu\n",
			  *pea_total_len,
			  dos_ea_name,
			  listp->ea.value.length);

		DLIST_ADD_END(ea_list_head, listp);

	}

	/* Add on 4 for total length. */
	if (*pea_total_len) {
		*pea_total_len += 4;
	}

	DBG_DEBUG("total_len = %zu\n", *pea_total_len);

	*ea_list = ea_list_head;
	return NT_STATUS_OK;
}

/****************************************************************************
 Fill a qfilepathinfo buffer with EA's. Returns the length of the buffer
 that was filled.
****************************************************************************/

static unsigned int fill_ea_buffer(TALLOC_CTX *mem_ctx, char *pdata, unsigned int total_data_size,
	connection_struct *conn, struct ea_list *ea_list)
{
	unsigned int ret_data_size = 4;
	char *p = pdata;

	SMB_ASSERT(total_data_size >= 4);

	if (!lp_ea_support(SNUM(conn))) {
		SIVAL(pdata,4,0);
		return 4;
	}

	for (p = pdata + 4; ea_list; ea_list = ea_list->next) {
		size_t dos_namelen;
		fstring dos_ea_name;
		push_ascii_fstring(dos_ea_name, ea_list->ea.name);
		dos_namelen = strlen(dos_ea_name);
		if (dos_namelen > 255 || dos_namelen == 0) {
			break;
		}
		if (ea_list->ea.value.length > 65535) {
			break;
		}
		if (4 + dos_namelen + 1 + ea_list->ea.value.length > total_data_size) {
			break;
		}

		/* We know we have room. */
		SCVAL(p,0,ea_list->ea.flags);
		SCVAL(p,1,dos_namelen);
		SSVAL(p,2,ea_list->ea.value.length);
		strlcpy(p+4, dos_ea_name, dos_namelen+1);
		if (ea_list->ea.value.length > 0) {
			memcpy(p + 4 + dos_namelen + 1,
			       ea_list->ea.value.data,
			       ea_list->ea.value.length);
		}

		total_data_size -= 4 + dos_namelen + 1 + ea_list->ea.value.length;
		p += 4 + dos_namelen + 1 + ea_list->ea.value.length;
	}

	ret_data_size = PTR_DIFF(p, pdata);
	DEBUG(10,("fill_ea_buffer: data_size = %u\n", ret_data_size ));
	SIVAL(pdata,0,ret_data_size);
	return ret_data_size;
}

static NTSTATUS fill_ea_chained_buffer(TALLOC_CTX *mem_ctx,
				       char *pdata,
				       unsigned int total_data_size,
				       unsigned int *ret_data_size,
				       connection_struct *conn,
				       struct ea_list *ea_list)
{
	uint8_t *p = (uint8_t *)pdata;
	uint8_t *last_start = NULL;
	bool do_store_data = (pdata != NULL);

	*ret_data_size = 0;

	if (!lp_ea_support(SNUM(conn))) {
		return NT_STATUS_NO_EAS_ON_FILE;
	}

	for (; ea_list; ea_list = ea_list->next) {
		size_t dos_namelen;
		fstring dos_ea_name;
		size_t this_size;
		size_t pad = 0;

		if (last_start != NULL && do_store_data) {
			SIVAL(last_start, 0, PTR_DIFF(p, last_start));
		}
		last_start = p;

		push_ascii_fstring(dos_ea_name, ea_list->ea.name);
		dos_namelen = strlen(dos_ea_name);
		if (dos_namelen > 255 || dos_namelen == 0) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		if (ea_list->ea.value.length > 65535) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		this_size = 0x08 + dos_namelen + 1 + ea_list->ea.value.length;

		if (ea_list->next) {
			pad = (4 - (this_size % 4)) % 4;
			this_size += pad;
		}

		if (do_store_data) {
			if (this_size > total_data_size) {
				return NT_STATUS_INFO_LENGTH_MISMATCH;
			}

			/* We know we have room. */
			SIVAL(p, 0x00, 0); /* next offset */
			SCVAL(p, 0x04, ea_list->ea.flags);
			SCVAL(p, 0x05, dos_namelen);
			SSVAL(p, 0x06, ea_list->ea.value.length);
			strlcpy((char *)(p+0x08), dos_ea_name, dos_namelen+1);
			memcpy(p + 0x08 + dos_namelen + 1, ea_list->ea.value.data, ea_list->ea.value.length);
			if (pad) {
				memset(p + 0x08 + dos_namelen + 1 + ea_list->ea.value.length,
					'\0',
					pad);
			}
			total_data_size -= this_size;
		}

		p += this_size;
	}

	*ret_data_size = PTR_DIFF(p, pdata);
	DEBUG(10,("fill_ea_chained_buffer: data_size = %u\n", *ret_data_size));
	return NT_STATUS_OK;
}

unsigned int estimate_ea_size(files_struct *fsp)
{
	size_t total_ea_len = 0;
	TALLOC_CTX *mem_ctx;
	struct ea_list *ea_list = NULL;
	NTSTATUS status;

	/* symlink */
	if (fsp == NULL) {
		return 0;
	}

	if (!lp_ea_support(SNUM(fsp->conn))) {
		return 0;
	}

	mem_ctx = talloc_stackframe();

	/* If this is a stream fsp, then we need to instead find the
	 * estimated ea len from the main file, not the stream
	 * (streams cannot have EAs), but the estimate isn't just 0 in
	 * this case! */
	fsp = metadata_fsp(fsp);
	(void)get_ea_list_from_fsp(mem_ctx,
				   fsp,
				   &total_ea_len,
				   &ea_list);

	if(conn_using_smb2(fsp->conn->sconn)) {
		unsigned int ret_data_size;
		/*
		 * We're going to be using fill_ea_chained_buffer() to
		 * marshall EA's - this size is significantly larger
		 * than the SMB1 buffer. Re-calculate the size without
		 * marshalling.
		 */
		status = fill_ea_chained_buffer(mem_ctx,
						NULL,
						0,
						&ret_data_size,
						fsp->conn,
						ea_list);
		if (!NT_STATUS_IS_OK(status)) {
			ret_data_size = 0;
		}
		total_ea_len = ret_data_size;
	}
	TALLOC_FREE(mem_ctx);
	return total_ea_len;
}

/****************************************************************************
 Ensure the EA name is case insensitive by matching any existing EA name.
****************************************************************************/

static void canonicalize_ea_name(files_struct *fsp,
			fstring unix_ea_name)
{
	size_t total_ea_len;
	TALLOC_CTX *mem_ctx = talloc_tos();
	struct ea_list *ea_list;
	NTSTATUS status = get_ea_list_from_fsp(mem_ctx,
					       fsp,
					       &total_ea_len,
					       &ea_list);
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	for (; ea_list; ea_list = ea_list->next) {
		if (strequal(&unix_ea_name[5], ea_list->ea.name)) {
			DEBUG(10,("canonicalize_ea_name: %s -> %s\n",
				&unix_ea_name[5], ea_list->ea.name));
			strlcpy(&unix_ea_name[5], ea_list->ea.name, sizeof(fstring)-5);
			break;
		}
	}
}

/****************************************************************************
 Set or delete an extended attribute.
****************************************************************************/

NTSTATUS set_ea(connection_struct *conn, files_struct *fsp,
		struct ea_list *ea_list)
{
	NTSTATUS status;
	bool posix_pathnames = false;

	if (!lp_ea_support(SNUM(conn))) {
		return NT_STATUS_EAS_NOT_SUPPORTED;
	}

	if (fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	posix_pathnames = (fsp->fsp_name->flags & SMB_FILENAME_POSIX_PATH);

	status = refuse_symlink_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_EA);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Setting EAs on streams isn't supported. */
	if (fsp_is_alternate_stream(fsp)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Filter out invalid Windows EA names - before
	 * we set *any* of them.
	 */

	if (!posix_pathnames && ea_list_has_invalid_name(ea_list)) {
		return STATUS_INVALID_EA_NAME;
	}

	for (;ea_list; ea_list = ea_list->next) {
		int ret;
		fstring unix_ea_name;

		/*
		 * Complementing the forward mapping from POSIX EAs to
		 * Windows EAs in get_ea_list_from_fsp(), here we map in the
		 * opposite direction from Windows EAs to the 'user' namespace
		 * of POSIX EAs. Hence, all POSIX EA names the we set here must
		 * start with a 'user.' prefix.
		 */
		fstrcpy(unix_ea_name, "user.");
		fstrcat(unix_ea_name, ea_list->ea.name);

		canonicalize_ea_name(fsp, unix_ea_name);

		DBG_DEBUG("ea_name %s ealen = %zu\n",
			  unix_ea_name,
			  ea_list->ea.value.length);

		if (samba_private_attr_name(unix_ea_name)) {
			DBG_DEBUG("ea name %s is a private Samba name.\n",
				  unix_ea_name);
			return NT_STATUS_ACCESS_DENIED;
		}

		if (ea_list->ea.value.length == 0) {
			/* Remove the attribute. */
			DBG_DEBUG("deleting ea name %s on "
				  "file %s by file descriptor.\n",
				  unix_ea_name, fsp_str_dbg(fsp));
			ret = SMB_VFS_FREMOVEXATTR(fsp, unix_ea_name);
#ifdef ENOATTR
			/* Removing a non existent attribute always succeeds. */
			if (ret == -1 && errno == ENOATTR) {
				DBG_DEBUG("deleting ea name %s didn't exist - "
					  "succeeding by default.\n",
					  unix_ea_name);
				ret = 0;
			}
#endif
		} else {
			DBG_DEBUG("setting ea name %s on file "
				  "%s by file descriptor.\n",
				  unix_ea_name,
				  fsp_str_dbg(fsp));
			ret = SMB_VFS_FSETXATTR(fsp, unix_ea_name,
						ea_list->ea.value.data, ea_list->ea.value.length, 0);
		}

		if (ret == -1) {
#ifdef ENOTSUP
			if (errno == ENOTSUP) {
				return NT_STATUS_EAS_NOT_SUPPORTED;
			}
#endif
			return map_nt_error_from_unix(errno);
		}

	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Read a list of EA names and data from an incoming data buffer. Create an ea_list with them.
****************************************************************************/

struct ea_list *read_ea_list(TALLOC_CTX *ctx, const char *pdata, size_t data_size)
{
	struct ea_list *ea_list_head = NULL;
	size_t offset = 0;
	size_t bytes_used = 0;

	while (offset < data_size) {
		struct ea_list *eal = read_ea_list_entry(ctx, pdata + offset, data_size - offset, &bytes_used);

		if (!eal) {
			return NULL;
		}

		DLIST_ADD_END(ea_list_head, eal);
		offset += bytes_used;
	}

	return ea_list_head;
}

/****************************************************************************
 Count the total EA size needed.
****************************************************************************/

static size_t ea_list_size(struct ea_list *ealist)
{
	fstring dos_ea_name;
	struct ea_list *listp;
	size_t ret = 0;

	for (listp = ealist; listp; listp = listp->next) {
		push_ascii_fstring(dos_ea_name, listp->ea.name);
		ret += 4 + strlen(dos_ea_name) + 1 + listp->ea.value.length;
	}
	/* Add on 4 for total length. */
	if (ret) {
		ret += 4;
	}

	return ret;
}

/****************************************************************************
 Return a union of EA's from a file list and a list of names.
 The TALLOC context for the two lists *MUST* be identical as we steal
 memory from one list to add to another. JRA.
****************************************************************************/

static struct ea_list *ea_list_union(struct ea_list *name_list, struct ea_list *file_list, size_t *total_ea_len)
{
	struct ea_list *nlistp, *flistp;

	for (nlistp = name_list; nlistp; nlistp = nlistp->next) {
		for (flistp = file_list; flistp; flistp = flistp->next) {
			if (strequal(nlistp->ea.name, flistp->ea.name)) {
				break;
			}
		}

		if (flistp) {
			/* Copy the data from this entry. */
			nlistp->ea.flags = flistp->ea.flags;
			nlistp->ea.value = flistp->ea.value;
		} else {
			/* Null entry. */
			nlistp->ea.flags = 0;
			ZERO_STRUCT(nlistp->ea.value);
		}
	}

	*total_ea_len = ea_list_size(name_list);
	return name_list;
}

/****************************************************************************
 Map wire perms onto standard UNIX permissions. Obey share restrictions.
****************************************************************************/

NTSTATUS unix_perms_from_wire(connection_struct *conn,
			      const SMB_STRUCT_STAT *psbuf,
			      uint32_t perms,
			      mode_t *ret_perms)
{
	mode_t ret = 0;

	if (perms == SMB_MODE_NO_CHANGE) {
		if (!VALID_STAT(*psbuf)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		*ret_perms = psbuf->st_ex_mode;
		return NT_STATUS_OK;
	}

	ret = wire_perms_to_unix(perms);

	*ret_perms = ret;
	return NT_STATUS_OK;
}

/****************************************************************************
 Get a level dependent lanman2 dir entry.
****************************************************************************/

struct smbd_dirptr_lanman2_state {
	connection_struct *conn;
	uint32_t info_level;
	bool check_mangled_names;
	bool case_sensitive;
};

static bool smbd_dirptr_lanman2_match_fn(TALLOC_CTX *ctx,
					 void *private_data,
					 const char *dname,
					 const char *mask,
					 char **_fname)
{
	struct smbd_dirptr_lanman2_state *state =
		(struct smbd_dirptr_lanman2_state *)private_data;
	bool ok;
	char mangled_name[13]; /* mangled 8.3 name. */
	bool got_match;
	const char *fname;

	/* Mangle fname if it's an illegal name. */
	if (mangle_must_mangle(dname, state->conn->params)) {
		/*
		 * Slow path - ensure we can push the original name as UCS2. If
		 * not, then just don't return this name.
		 */
		NTSTATUS status;
		size_t ret_len = 0;
		size_t len = (strlen(dname) + 2) * 4; /* Allow enough space. */
		uint8_t *tmp = talloc_array(talloc_tos(),
					uint8_t,
					len);

		status = srvstr_push(NULL,
			FLAGS2_UNICODE_STRINGS,
			tmp,
			dname,
			len,
			STR_TERMINATE,
			&ret_len);

		TALLOC_FREE(tmp);

		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = name_to_8_3(dname, mangled_name,
				 true, state->conn->params);
		if (!ok) {
			return false;
		}
		fname = mangled_name;
	} else {
		fname = dname;
	}

	got_match = mask_match(fname, mask,
			       state->case_sensitive);

	if(!got_match && state->check_mangled_names &&
	   !mangle_is_8_3(fname, false, state->conn->params)) {
		/*
		 * It turns out that NT matches wildcards against
		 * both long *and* short names. This may explain some
		 * of the wildcard weirdness from old DOS clients
		 * that some people have been seeing.... JRA.
		 */
		/* Force the mangling into 8.3. */
		ok = name_to_8_3(fname, mangled_name,
				 false, state->conn->params);
		if (!ok) {
			return false;
		}

		got_match = mask_match(mangled_name, mask,
				       state->case_sensitive);
	}

	if (!got_match) {
		return false;
	}

	*_fname = talloc_strdup(ctx, fname);
	if (*_fname == NULL) {
		return false;
	}

	return true;
}

static uint32_t get_dirent_ea_size(uint32_t mode, files_struct *fsp)
{
	uint32_t ea_size = IO_REPARSE_TAG_DFS;

	if (mode & FILE_ATTRIBUTE_REPARSE_POINT) {
		(void)fsctl_get_reparse_tag(fsp, &ea_size);
	} else {
		ea_size = estimate_ea_size(fsp);
	}

	return ea_size;
}

static NTSTATUS smbd_marshall_dir_entry(TALLOC_CTX *ctx,
				    connection_struct *conn,
				    uint16_t flags2,
				    uint32_t info_level,
				    struct ea_list *name_list,
				    bool check_mangled_names,
				    bool requires_resume_key,
				    uint32_t mode,
				    const char *fname,
				    const struct smb_filename *smb_fname,
				    int space_remaining,
				    uint8_t align,
				    bool do_pad,
				    char *base_data,
				    char **ppdata,
				    char *end_data,
				    uint64_t *last_entry_off)
{
	char *p, *q, *pdata = *ppdata;
	uint32_t reskey=0;
	uint64_t file_size = 0;
	uint64_t allocation_size = 0;
	uint64_t file_id = 0;
	size_t len = 0;
	struct timespec mdate_ts = {0};
	struct timespec adate_ts = {0};
	struct timespec cdate_ts = {0};
	struct timespec create_date_ts = {0};
	char *nameptr;
	char *last_entry_ptr;
	bool was_8_3;
	int off;
	int pad = 0;
	NTSTATUS status;
	struct readdir_attr_data *readdir_attr_data = NULL;
	uint32_t ea_size;

	if (!(mode & FILE_ATTRIBUTE_DIRECTORY)) {
		file_size = get_file_size_stat(&smb_fname->st);
	}
	allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn, NULL, &smb_fname->st);

	/*
	 * Skip SMB_VFS_FREADDIR_ATTR if the directory entry is a symlink or
	 * a DFS symlink.
	 */
	if (smb_fname->fsp != NULL &&
	    !(mode & FILE_ATTRIBUTE_REPARSE_POINT)) {
		status = SMB_VFS_FREADDIR_ATTR(smb_fname->fsp,
					       ctx,
					       &readdir_attr_data);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(NT_STATUS_NOT_SUPPORTED,
					     status)) {
				return status;
			}
		}
	}

	file_id = SMB_VFS_FS_FILE_ID(conn, &smb_fname->st);

	mdate_ts = smb_fname->st.st_ex_mtime;
	adate_ts = smb_fname->st.st_ex_atime;
	create_date_ts = get_create_timespec(conn, NULL, smb_fname);
	cdate_ts = get_change_timespec(conn, NULL, smb_fname);

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		dos_filetime_timespec(&create_date_ts);
		dos_filetime_timespec(&mdate_ts);
		dos_filetime_timespec(&adate_ts);
		dos_filetime_timespec(&cdate_ts);
	}

	/* align the record */
	SMB_ASSERT(align >= 1);

	off = (int)PTR_DIFF(pdata, base_data);
	pad = (off + (align-1)) & ~(align-1);
	pad -= off;

	if (pad && pad > space_remaining) {
		DEBUG(9,("smbd_marshall_dir_entry: out of space "
			"for padding (wanted %u, had %d)\n",
			(unsigned int)pad,
			space_remaining ));
		return STATUS_MORE_ENTRIES; /* Not finished - just out of space */
	}

	off += pad;
	/* initialize padding to 0 */
	if (pad) {
		memset(pdata, 0, pad);
	}
	space_remaining -= pad;

	DBG_DEBUG("space_remaining = %d\n", space_remaining);

	pdata += pad;
	p = pdata;
	last_entry_ptr = p;

	pad = 0;
	off = 0;

	switch (info_level) {
	case SMB_FIND_INFO_STANDARD:
		DBG_DEBUG("SMB_FIND_INFO_STANDARD\n");
		if(requires_resume_key) {
			SIVAL(p,0,reskey);
			p += 4;
		}
		srv_put_dos_date2_ts(p, 0, create_date_ts);
		srv_put_dos_date2_ts(p, 4, adate_ts);
		srv_put_dos_date2_ts(p, 8, mdate_ts);
		SIVAL(p,12,(uint32_t)file_size);
		SIVAL(p,16,(uint32_t)allocation_size);
		SSVAL(p,20,mode);
		p += 23;
		nameptr = p;
		if (flags2 & FLAGS2_UNICODE_STRINGS) {
			p += ucs2_align(base_data, p, 0);
		}
		status = srvstr_push(base_data, flags2, p,
				  fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (flags2 & FLAGS2_UNICODE_STRINGS) {
			if (len > 2) {
				SCVAL(nameptr, -1, len - 2);
			} else {
				SCVAL(nameptr, -1, 0);
			}
		} else {
			if (len > 1) {
				SCVAL(nameptr, -1, len - 1);
			} else {
				SCVAL(nameptr, -1, 0);
			}
		}
		p += len;
		break;

	case SMB_FIND_EA_SIZE:
		DBG_DEBUG("SMB_FIND_EA_SIZE\n");
		if (requires_resume_key) {
			SIVAL(p,0,reskey);
			p += 4;
		}
		srv_put_dos_date2_ts(p, 0, create_date_ts);
		srv_put_dos_date2_ts(p, 4, adate_ts);
		srv_put_dos_date2_ts(p, 8, mdate_ts);
		SIVAL(p,12,(uint32_t)file_size);
		SIVAL(p,16,(uint32_t)allocation_size);
		SSVAL(p,20,mode);
		{
			ea_size = estimate_ea_size(smb_fname->fsp);
			SIVAL(p,22,ea_size); /* Extended attributes */
		}
		p += 27;
		nameptr = p - 1;
		status = srvstr_push(base_data, flags2,
				  p, fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE | STR_NOALIGN, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (flags2 & FLAGS2_UNICODE_STRINGS) {
			if (len > 2) {
				len -= 2;
			} else {
				len = 0;
			}
		} else {
			if (len > 1) {
				len -= 1;
			} else {
				len = 0;
			}
		}
		SCVAL(nameptr,0,len);
		p += len;
		SCVAL(p,0,0); p += 1; /* Extra zero byte ? - why.. */
		break;

	case SMB_FIND_EA_LIST:
	{
		struct ea_list *file_list = NULL;
		size_t ea_len = 0;

		DBG_DEBUG("SMB_FIND_EA_LIST\n");
		if (!name_list) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (requires_resume_key) {
			SIVAL(p,0,reskey);
			p += 4;
		}
		srv_put_dos_date2_ts(p, 0, create_date_ts);
		srv_put_dos_date2_ts(p, 4, adate_ts);
		srv_put_dos_date2_ts(p, 8, mdate_ts);
		SIVAL(p,12,(uint32_t)file_size);
		SIVAL(p,16,(uint32_t)allocation_size);
		SSVAL(p,20,mode);
		p += 22; /* p now points to the EA area. */

		status = get_ea_list_from_fsp(ctx,
					       smb_fname->fsp,
					       &ea_len, &file_list);
		if (!NT_STATUS_IS_OK(status)) {
			file_list = NULL;
		}
		name_list = ea_list_union(name_list, file_list, &ea_len);

		/* We need to determine if this entry will fit in the space available. */
		/* Max string size is 255 bytes. */
		if (PTR_DIFF(p + 255 + ea_len,pdata) > space_remaining) {
			DEBUG(9,("smbd_marshall_dir_entry: out of space "
				"(wanted %u, had %d)\n",
				(unsigned int)PTR_DIFF(p + 255 + ea_len,pdata),
				space_remaining ));
			return STATUS_MORE_ENTRIES; /* Not finished - just out of space */
		}

		/* Push the ea_data followed by the name. */
		p += fill_ea_buffer(ctx, p, space_remaining, conn, name_list);
		nameptr = p;
		status = srvstr_push(base_data, flags2,
				  p + 1, fname, PTR_DIFF(end_data, p+1),
				  STR_TERMINATE | STR_NOALIGN, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (flags2 & FLAGS2_UNICODE_STRINGS) {
			if (len > 2) {
				len -= 2;
			} else {
				len = 0;
			}
		} else {
			if (len > 1) {
				len -= 1;
			} else {
				len = 0;
			}
		}
		SCVAL(nameptr,0,len);
		p += len + 1;
		SCVAL(p,0,0); p += 1; /* Extra zero byte ? - why.. */
		break;
	}

	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		DBG_DEBUG("SMB_FIND_FILE_BOTH_DIRECTORY_INFO\n");
		was_8_3 = mangle_is_8_3(fname, True, conn->params);
		p += 4;
		SIVAL(p,0,reskey); p += 4;
		put_long_date_full_timespec(conn->ts_res,p,&create_date_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&adate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&mdate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&cdate_ts); p += 8;
		SOFF_T(p,0,file_size); p += 8;
		SOFF_T(p,0,allocation_size); p += 8;
		SIVAL(p,0,mode); p += 4;
		q = p; p += 4; /* q is placeholder for name length. */
		ea_size = get_dirent_ea_size(mode, smb_fname->fsp);
		SIVAL(p, 0, ea_size);
		p += 4;
		/* Clear the short name buffer. This is
		 * IMPORTANT as not doing so will trigger
		 * a Win2k client bug. JRA.
		 */
		if (!was_8_3 && check_mangled_names) {
			char mangled_name[13]; /* mangled 8.3 name. */
			if (!name_to_8_3(fname,mangled_name,True,
					   conn->params)) {
				/* Error - mangle failed ! */
				memset(mangled_name,'\0',12);
			}
			mangled_name[12] = 0;
			status = srvstr_push(base_data, flags2,
					  p+2, mangled_name, 24,
					  STR_UPPER|STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			if (len < 24) {
				memset(p + 2 + len,'\0',24 - len);
			}
			SSVAL(p, 0, len);
		} else {
			memset(p,'\0',26);
		}
		p += 2 + 24;
		status = srvstr_push(base_data, flags2, p,
				  fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE_ASCII, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		SIVAL(q,0,len);
		p += len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		break;

	case SMB_FIND_FILE_DIRECTORY_INFO:
		DBG_DEBUG("SMB_FIND_FILE_DIRECTORY_INFO\n");
		p += 4;
		SIVAL(p,0,reskey); p += 4;
		put_long_date_full_timespec(conn->ts_res,p,&create_date_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&adate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&mdate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&cdate_ts); p += 8;
		SOFF_T(p,0,file_size); p += 8;
		SOFF_T(p,0,allocation_size); p += 8;
		SIVAL(p,0,mode); p += 4;
		status = srvstr_push(base_data, flags2,
				  p + 4, fname, PTR_DIFF(end_data, p+4),
				  STR_TERMINATE_ASCII, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		SIVAL(p,0,len);
		p += 4 + len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		break;

	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		DBG_DEBUG("SMB_FIND_FILE_FULL_DIRECTORY_INFO\n");
		p += 4;
		SIVAL(p,0,reskey); p += 4;
		put_long_date_full_timespec(conn->ts_res,p,&create_date_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&adate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&mdate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&cdate_ts); p += 8;
		SOFF_T(p,0,file_size); p += 8;
		SOFF_T(p,0,allocation_size); p += 8;
		SIVAL(p,0,mode); p += 4;
		q = p; p += 4; /* q is placeholder for name length. */
		ea_size = get_dirent_ea_size(mode, smb_fname->fsp);
		SIVAL(p, 0, ea_size);
		p +=4;
		status = srvstr_push(base_data, flags2, p,
				  fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE_ASCII, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		SIVAL(q, 0, len);
		p += len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		break;

	case SMB_FIND_FILE_NAMES_INFO:
		DBG_DEBUG("SMB_FIND_FILE_NAMES_INFO\n");
		p += 4;
		SIVAL(p,0,reskey); p += 4;
		p += 4;
		/* this must *not* be null terminated or w2k gets in a loop trying to set an
		   acl on a dir (tridge) */
		status = srvstr_push(base_data, flags2, p,
				  fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE_ASCII, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		SIVAL(p, -4, len);
		p += len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		break;

	case SMB_FIND_ID_FULL_DIRECTORY_INFO:
		DBG_DEBUG("SMB_FIND_ID_FULL_DIRECTORY_INFO\n");
		p += 4;
		SIVAL(p,0,reskey); p += 4;
		put_long_date_full_timespec(conn->ts_res,p,&create_date_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&adate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&mdate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&cdate_ts); p += 8;
		SOFF_T(p,0,file_size); p += 8;
		SOFF_T(p,0,allocation_size); p += 8;
		SIVAL(p,0,mode); p += 4;
		q = p; p += 4; /* q is placeholder for name length. */
		ea_size = get_dirent_ea_size(mode, smb_fname->fsp);
		SIVAL(p, 0, ea_size);
		p += 4;
		SIVAL(p,0,0); p += 4; /* Unknown - reserved ? */
		SBVAL(p,0,file_id); p += 8;
		status = srvstr_push(base_data, flags2, p,
				  fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE_ASCII, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		SIVAL(q, 0, len);
		p += len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		break;

	case SMB_FIND_ID_BOTH_DIRECTORY_INFO:
		DBG_DEBUG("SMB_FIND_ID_BOTH_DIRECTORY_INFO\n");
		was_8_3 = mangle_is_8_3(fname, True, conn->params);
		p += 4;
		SIVAL(p,0,reskey); p += 4;
		put_long_date_full_timespec(conn->ts_res,p,&create_date_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&adate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&mdate_ts); p += 8;
		put_long_date_full_timespec(conn->ts_res,p,&cdate_ts); p += 8;
		SOFF_T(p,0,file_size); p += 8;
		SOFF_T(p,0,allocation_size); p += 8;
		SIVAL(p,0,mode); p += 4;
		q = p; p += 4; /* q is placeholder for name length */
		if (readdir_attr_data &&
		    readdir_attr_data->type == RDATTR_AAPL) {
			/*
			 * OS X specific SMB2 extension negotiated via
			 * AAPL create context: return max_access in
			 * ea_size field.
			 */
			ea_size = readdir_attr_data->attr_data.aapl.max_access;
		} else {
			ea_size = get_dirent_ea_size(mode, smb_fname->fsp);
		}
		SIVAL(p,0,ea_size); /* Extended attributes */
		p += 4;

		if (readdir_attr_data &&
		    readdir_attr_data->type == RDATTR_AAPL) {
			/*
			 * OS X specific SMB2 extension negotiated via
			 * AAPL create context: return resource fork
			 * length and compressed FinderInfo in
			 * shortname field.
			 *
			 * According to documentation short_name_len
			 * should be 0, but on the wire behaviour
			 * shows its set to 24 by clients.
			 */
			SSVAL(p, 0, 24);

			/* Resourefork length */
			SBVAL(p, 2, readdir_attr_data->attr_data.aapl.rfork_size);

			/* Compressed FinderInfo */
			memcpy(p + 10, &readdir_attr_data->attr_data.aapl.finder_info, 16);
		} else if (!was_8_3 && check_mangled_names) {
			char mangled_name[13]; /* mangled 8.3 name. */
			if (!name_to_8_3(fname,mangled_name,True,
					conn->params)) {
				/* Error - mangle failed ! */
				memset(mangled_name,'\0',12);
			}
			mangled_name[12] = 0;
			status = srvstr_push(base_data, flags2,
					  p+2, mangled_name, 24,
					  STR_UPPER|STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SSVAL(p, 0, len);
			if (len < 24) {
				memset(p + 2 + len,'\0',24 - len);
			}
			SSVAL(p, 0, len);
		} else {
			/* Clear the short name buffer. This is
			 * IMPORTANT as not doing so will trigger
			 * a Win2k client bug. JRA.
			 */
			memset(p,'\0',26);
		}
		p += 26;

		/* Reserved ? */
		if (readdir_attr_data &&
		    readdir_attr_data->type == RDATTR_AAPL) {
			/*
			 * OS X specific SMB2 extension negotiated via
			 * AAPL create context: return UNIX mode in
			 * reserved field.
			 */
			uint16_t aapl_mode = (uint16_t)readdir_attr_data->attr_data.aapl.unix_mode;
			SSVAL(p, 0, aapl_mode);
		} else {
			SSVAL(p, 0, 0);
		}
		p += 2;

		SBVAL(p,0,file_id); p += 8;
		status = srvstr_push(base_data, flags2, p,
				  fname, PTR_DIFF(end_data, p),
				  STR_TERMINATE_ASCII, &len);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		SIVAL(q,0,len);
		p += len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		break;

	/* CIFS UNIX Extension. */

	case SMB_FIND_FILE_UNIX:
	case SMB_FIND_FILE_UNIX_INFO2:
		p+= 4;
		SIVAL(p,0,reskey); p+= 4;    /* Used for continuing search. */

		/* Begin of SMB_QUERY_FILE_UNIX_BASIC */

		if (info_level == SMB_FIND_FILE_UNIX) {
			DBG_DEBUG("SMB_FIND_FILE_UNIX\n");
			p = store_file_unix_basic(conn, p,
						NULL, &smb_fname->st);
			status = srvstr_push(base_data, flags2, p,
					  fname, PTR_DIFF(end_data, p),
					  STR_TERMINATE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		} else {
			DBG_DEBUG("SMB_FIND_FILE_UNIX_INFO2\n");
			p = store_file_unix_basic_info2(conn, p,
						NULL, &smb_fname->st);
			nameptr = p;
			p += 4;
			status = srvstr_push(base_data, flags2, p, fname,
					  PTR_DIFF(end_data, p), 0, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SIVAL(nameptr, 0, len);
		}

		p += len;

		len = PTR_DIFF(p, pdata);
		pad = (len + (align-1)) & ~(align-1);
		/*
		 * offset to the next entry, the caller
		 * will overwrite it for the last entry
		 * that's why we always include the padding
		 */
		SIVAL(pdata,0,pad);
		/*
		 * set padding to zero
		 */
		if (do_pad) {
			memset(p, 0, pad - len);
			p = pdata + pad;
		} else {
			p = pdata + len;
		}
		/* End of SMB_QUERY_FILE_UNIX_BASIC */

		break;

	/* SMB2 UNIX Extension. */

	case SMB2_FILE_POSIX_INFORMATION:
		{
			struct smb3_file_posix_information info = {};
			uint8_t buf[sizeof(info)];
			struct ndr_push ndr = {
				.data = buf,
				.alloc_size = sizeof(buf),
				.fixed_buf_size = true,
			};
			enum ndr_err_code ndr_err;
			uint32_t tag = 0;

			DBG_DEBUG("SMB2_FILE_POSIX_INFORMATION\n");

			p+= 4;
			SIVAL(p,0,reskey); p+= 4;

			if (!conn_using_smb2(conn->sconn)) {
				return NT_STATUS_INVALID_LEVEL;
			}

			if (mode & FILE_ATTRIBUTE_REPARSE_POINT) {
				status = fsctl_get_reparse_tag(smb_fname->fsp,
							       &tag);
				if (!NT_STATUS_IS_OK(status)) {
					DBG_DEBUG("Could not get reparse "
						  "tag for %s: %s\n",
						  smb_fname_str_dbg(smb_fname),
						  nt_errstr(status));
					return status;
				}
			}

			smb3_file_posix_information_init(
				conn, &smb_fname->st, tag, mode, &info);

			ndr_err = ndr_push_smb3_file_posix_information(
				&ndr, NDR_SCALARS|NDR_BUFFERS, &info);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return NT_STATUS_INSUFFICIENT_RESOURCES;
			}

			memcpy(p, buf, ndr.offset);
			p += ndr.offset;

			nameptr = p;
			p += 4;
			status = srvstr_push(base_data, flags2, p, fname,
					PTR_DIFF(end_data, p), 0, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SIVAL(nameptr, 0, len);

			p += len;

			len = PTR_DIFF(p, pdata);
			pad = (len + (align-1)) & ~(align-1);
			/*
			 * offset to the next entry, the caller
			 * will overwrite it for the last entry
			 * that's why we always include the padding
			 */
			SIVAL(pdata,0,pad);
			break;
		}

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	if (PTR_DIFF(p,pdata) > space_remaining) {
		DEBUG(9,("smbd_marshall_dir_entry: out of space "
			"(wanted %u, had %d)\n",
			(unsigned int)PTR_DIFF(p,pdata),
			space_remaining ));
		return STATUS_MORE_ENTRIES; /* Not finished - just out of space */
	}

	/* Setup the last entry pointer, as an offset from base_data */
	*last_entry_off = PTR_DIFF(last_entry_ptr,base_data);
	/* Advance the data pointer to the next slot */
	*ppdata = p;

	return NT_STATUS_OK;
}

NTSTATUS smbd_dirptr_lanman2_entry(TALLOC_CTX *ctx,
			       connection_struct *conn,
			       struct dptr_struct *dirptr,
			       uint16_t flags2,
			       const char *path_mask,
			       uint32_t dirtype,
			       int info_level,
			       int requires_resume_key,
			       bool dont_descend,
			       bool ask_sharemode,
			       bool get_dosmode,
			       uint8_t align,
			       bool do_pad,
			       char **ppdata,
			       char *base_data,
			       char *end_data,
			       int space_remaining,
			       struct smb_filename **_smb_fname,
			       int *_last_entry_off,
			       struct ea_list *name_list,
			       struct file_id *file_id)
{
	const char *p;
	const char *mask = NULL;
	uint32_t mode = 0;
	char *fname = NULL;
	struct smb_filename *smb_fname = NULL;
	struct smbd_dirptr_lanman2_state state;
	bool ok;
	uint64_t last_entry_off = 0;
	NTSTATUS status;
	enum mangled_names_options mangled_names;
	bool marshall_with_83_names;

	mangled_names = lp_mangled_names(conn->params);

	ZERO_STRUCT(state);
	state.conn = conn;
	state.info_level = info_level;
	if (mangled_names != MANGLED_NAMES_NO) {
		state.check_mangled_names = true;
	}
	state.case_sensitive = dptr_case_sensitive(dirptr);

	p = strrchr_m(path_mask,'/');
	if(p != NULL) {
		if(p[1] == '\0') {
			mask = "*.*";
		} else {
			mask = p+1;
		}
	} else {
		mask = path_mask;
	}

	ok = smbd_dirptr_get_entry(ctx,
				   dirptr,
				   mask,
				   dirtype,
				   dont_descend,
				   ask_sharemode,
				   get_dosmode,
				   smbd_dirptr_lanman2_match_fn,
				   &state,
				   &fname,
				   &smb_fname,
				   &mode);
	if (!ok) {
		return NT_STATUS_END_OF_FILE;
	}

	marshall_with_83_names = (mangled_names == MANGLED_NAMES_YES);

	status = smbd_marshall_dir_entry(ctx,
				     conn,
				     flags2,
				     info_level,
				     name_list,
				     marshall_with_83_names,
				     requires_resume_key,
				     mode,
				     fname,
				     smb_fname,
				     space_remaining,
				     align,
				     do_pad,
				     base_data,
				     ppdata,
				     end_data,
				     &last_entry_off);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ILLEGAL_CHARACTER)) {
		DEBUG(1,("Conversion error: illegal character: %s\n",
			 smb_fname_str_dbg(smb_fname)));
	}

	if (file_id != NULL) {
		*file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	}

	if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		smbd_dirptr_push_overflow(dirptr, &fname, &smb_fname, mode);
	}

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb_fname);
		TALLOC_FREE(fname);
		return status;
	}

	smbd_dirptr_set_last_name_sent(dirptr, &smb_fname->base_name);

	if (_smb_fname != NULL) {
		/*
		 * smb_fname is already talloc'ed off ctx.
		 * We just need to make sure we don't return
		 * any stream_name, and replace base_name
		 * with fname in case base_name got mangled.
		 * This allows us to preserve any smb_fname->fsp
		 * for asynchronous handle lookups.
		 */
		TALLOC_FREE(smb_fname->stream_name);

		/*
		 * smbd_dirptr_set_last_name_sent() above consumed
		 * base_name
		 */
		smb_fname->base_name = talloc_strdup(smb_fname, fname);

		if (smb_fname->base_name == NULL) {
			TALLOC_FREE(smb_fname);
			TALLOC_FREE(fname);
			return NT_STATUS_NO_MEMORY;
		}
		*_smb_fname = smb_fname;
	} else {
		TALLOC_FREE(smb_fname);
	}
	TALLOC_FREE(fname);

	*_last_entry_off = last_entry_off;
	return NT_STATUS_OK;
}

unsigned char *create_volume_objectid(connection_struct *conn, unsigned char objid[16])
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	E_md4hash(lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),objid);
	return objid;
}

static void samba_extended_info_version(struct smb_extended_info *extended_info)
{
	SMB_ASSERT(extended_info != NULL);

	extended_info->samba_magic = SAMBA_EXTENDED_INFO_MAGIC;
	extended_info->samba_version = ((SAMBA_VERSION_MAJOR & 0xff) << 24)
				       | ((SAMBA_VERSION_MINOR & 0xff) << 16)
				       | ((SAMBA_VERSION_RELEASE & 0xff) << 8);
#ifdef SAMBA_VERSION_REVISION
	extended_info->samba_version |= (tolower(*SAMBA_VERSION_REVISION) - 'a' + 1) & 0xff;
#endif
	extended_info->samba_subversion = 0;
#ifdef SAMBA_VERSION_RC_RELEASE
	extended_info->samba_subversion |= (SAMBA_VERSION_RC_RELEASE & 0xff) << 24;
#else
#ifdef SAMBA_VERSION_PRE_RELEASE
	extended_info->samba_subversion |= (SAMBA_VERSION_PRE_RELEASE & 0xff) << 16;
#endif
#endif
#ifdef SAMBA_VERSION_VENDOR_PATCH
	extended_info->samba_subversion |= (SAMBA_VERSION_VENDOR_PATCH & 0xffff);
#endif
	extended_info->samba_gitcommitdate = 0;
#ifdef SAMBA_VERSION_COMMIT_TIME
	unix_to_nt_time(&extended_info->samba_gitcommitdate, SAMBA_VERSION_COMMIT_TIME);
#endif

	memset(extended_info->samba_version_string, 0,
	       sizeof(extended_info->samba_version_string));

	snprintf (extended_info->samba_version_string,
		  sizeof(extended_info->samba_version_string),
		  "%s", samba_version_string());
}

static bool fsinfo_unix_valid_level(connection_struct *conn,
				    struct files_struct *fsp,
				    uint16_t info_level)
{
	if (conn_using_smb2(conn->sconn) &&
	    fsp->fsp_flags.posix_open &&
	    info_level == SMB2_FS_POSIX_INFORMATION_INTERNAL)
	{
		return true;
	}
#if defined(SMB1SERVER)
	if (lp_smb1_unix_extensions() &&
			info_level == SMB_QUERY_POSIX_FS_INFO) {
		return true;
	}
#endif
	return false;
}

/*
 * fsp is only valid for SMB2.
 */
NTSTATUS smbd_do_qfsinfo(struct smbXsrv_connection *xconn,
			 connection_struct *conn,
			 TALLOC_CTX *mem_ctx,
			 uint16_t info_level,
			 uint16_t flags2,
			 unsigned int max_data_bytes,
			 size_t *fixed_portion,
			 struct files_struct *fsp,
			 struct smb_filename *fname,
			 char **ppdata,
			 int *ret_data_len)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *pdata, *end_data;
	int data_len = 0;
	size_t len = 0;
	const char *vname = volume_label(talloc_tos(), SNUM(conn));
	int snum = SNUM(conn);
	const char *fstype = lp_fstype(SNUM(conn));
	const char *filename = NULL;
	uint64_t bytes_per_sector = 512;
	struct smb_filename smb_fname;
	SMB_STRUCT_STAT st;
	NTSTATUS status = NT_STATUS_OK;
	uint64_t df_ret;
	uint32_t serial;

	if (fname == NULL || fname->base_name == NULL) {
		filename = ".";
	} else {
		filename = fname->base_name;
	}

	if (IS_IPC(conn)) {
		if (info_level != SMB_QUERY_CIFS_UNIX_INFO) {
			DEBUG(0,("smbd_do_qfsinfo: not an allowed "
				"info level (0x%x) on IPC$.\n",
				(unsigned int)info_level));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	DEBUG(3,("smbd_do_qfsinfo: level = %d\n", info_level));

	smb_fname = (struct smb_filename) {
		.base_name = discard_const_p(char, filename),
		.flags = fname ? fname->flags : 0,
		.twrp = fname ? fname->twrp : 0,
	};

	if(info_level != SMB_FS_QUOTA_INFORMATION
	   && SMB_VFS_STAT(conn, &smb_fname) != 0) {
		DEBUG(2,("stat of . failed (%s)\n", strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	st = smb_fname.st;

	if (max_data_bytes + DIR_ENTRY_SAFETY_MARGIN < max_data_bytes) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*ppdata = (char *)SMB_REALLOC(
		*ppdata, max_data_bytes + DIR_ENTRY_SAFETY_MARGIN);
	if (*ppdata == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pdata = *ppdata;
	memset((char *)pdata,'\0',max_data_bytes + DIR_ENTRY_SAFETY_MARGIN);
	end_data = pdata + max_data_bytes + DIR_ENTRY_SAFETY_MARGIN - 1;

	*fixed_portion = 0;

	switch (info_level) {
		case SMB_INFO_ALLOCATION:
		{
			uint64_t dfree,dsize,bsize,block_size,sectors_per_unit;
			data_len = 18;
			df_ret = get_dfree_info(conn, &smb_fname, &bsize,
						&dfree, &dsize);
			if (df_ret == (uint64_t)-1) {
				return map_nt_error_from_unix(errno);
			}

			block_size = lp_block_size(snum);
			if (bsize < block_size) {
				uint64_t factor = block_size/bsize;
				bsize = block_size;
				dsize /= factor;
				dfree /= factor;
			}
			if (bsize > block_size) {
				uint64_t factor = bsize/block_size;
				bsize = block_size;
				dsize *= factor;
				dfree *= factor;
			}
			sectors_per_unit = bsize/bytes_per_sector;

			DEBUG(5,("smbd_do_qfsinfo : SMB_INFO_ALLOCATION id=%x, bsize=%u, cSectorUnit=%u, \
cBytesSector=%u, cUnitTotal=%u, cUnitAvail=%d\n", (unsigned int)st.st_ex_dev, (unsigned int)bsize, (unsigned int)sectors_per_unit,
				(unsigned int)bytes_per_sector, (unsigned int)dsize, (unsigned int)dfree));

			/*
			 * For large drives, return max values and not modulo.
			 */
			dsize = MIN(dsize, UINT32_MAX);
			dfree = MIN(dfree, UINT32_MAX);

			SIVAL(pdata,l1_idFileSystem,st.st_ex_dev);
			SIVAL(pdata,l1_cSectorUnit,sectors_per_unit);
			SIVAL(pdata,l1_cUnit,dsize);
			SIVAL(pdata,l1_cUnitAvail,dfree);
			SSVAL(pdata,l1_cbSector,bytes_per_sector);
			break;
		}

		case SMB_INFO_VOLUME:
			/* Return volume name */
			/*
			 * Add volume serial number - hash of a combination of
			 * the called hostname and the service name.
			 */
			serial = generate_volume_serial_number(lp_sub, snum);
			SIVAL(pdata,0,serial);
			/*
			 * Win2k3 and previous mess this up by sending a name length
			 * one byte short. I believe only older clients (OS/2 Win9x) use
			 * this call so try fixing this by adding a terminating null to
			 * the pushed string. The change here was adding the STR_TERMINATE. JRA.
			 */
			status = srvstr_push(
				pdata, flags2,
				pdata+l2_vol_szVolLabel, vname,
				PTR_DIFF(end_data, pdata+l2_vol_szVolLabel),
				STR_NOALIGN|STR_TERMINATE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SCVAL(pdata,l2_vol_cch,len);
			data_len = l2_vol_szVolLabel + len;
			DEBUG(5,("smbd_do_qfsinfo : time = %x, namelen = %u, "
				 "name = %s serial = 0x%04"PRIx32"\n",
				 (unsigned)convert_timespec_to_time_t(st.st_ex_ctime),
				 (unsigned)len, vname, serial));
			break;

		case SMB_QUERY_FS_ATTRIBUTE_INFO:
		case SMB_FS_ATTRIBUTE_INFORMATION:

			SIVAL(pdata,0,FILE_CASE_PRESERVED_NAMES|FILE_CASE_SENSITIVE_SEARCH|
				FILE_SUPPORTS_OBJECT_IDS|FILE_UNICODE_ON_DISK|
				conn->fs_capabilities); /* FS ATTRIBUTES */

			SIVAL(pdata,4,255); /* Max filename component length */
			/* NOTE! the fstype must *not* be null terminated or win98 won't recognise it
				and will think we can't do long filenames */
			status = srvstr_push(pdata, flags2, pdata+12, fstype,
					  PTR_DIFF(end_data, pdata+12),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SIVAL(pdata,8,len);
			data_len = 12 + len;
			if (max_data_bytes >= 16 && data_len > max_data_bytes) {
				/* the client only requested a portion of the
				   file system name */
				data_len = max_data_bytes;
				status = STATUS_BUFFER_OVERFLOW;
			}
			*fixed_portion = 16;
			break;

		case SMB_QUERY_FS_LABEL_INFO:
		case SMB_FS_LABEL_INFORMATION:
			status = srvstr_push(pdata, flags2, pdata+4, vname,
					  PTR_DIFF(end_data, pdata+4), 0, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			data_len = 4 + len;
			SIVAL(pdata,0,len);
			break;

		case SMB_QUERY_FS_VOLUME_INFO:
		case SMB_FS_VOLUME_INFORMATION:
			put_long_date_full_timespec(TIMESTAMP_SET_NT_OR_BETTER,
						    pdata, &st.st_ex_btime);
			/*
			 * Add volume serial number - hash of a combination of
			 * the called hostname and the service name.
			 */
			serial = generate_volume_serial_number(lp_sub, snum);
			SIVAL(pdata,8,serial);

			/* Max label len is 32 characters. */
			status = srvstr_push(pdata, flags2, pdata+18, vname,
					  PTR_DIFF(end_data, pdata+18),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SIVAL(pdata,12,len);
			data_len = 18+len;

			DEBUG(5,("smbd_do_qfsinfo : SMB_QUERY_FS_VOLUME_INFO "
				 "namelen = %d, vol=%s serv=%s "
				 "serial=0x%04"PRIx32"\n",
				 (int)strlen(vname),vname,
				 lp_servicename(talloc_tos(), lp_sub, snum),
				 serial));
			if (max_data_bytes >= 24 && data_len > max_data_bytes) {
				/* the client only requested a portion of the
				   volume label */
				data_len = max_data_bytes;
				status = STATUS_BUFFER_OVERFLOW;
			}
			*fixed_portion = 24;
			break;

		case SMB_QUERY_FS_SIZE_INFO:
		case SMB_FS_SIZE_INFORMATION:
		{
			uint64_t dfree,dsize,bsize,block_size,sectors_per_unit;
			data_len = 24;
			df_ret = get_dfree_info(conn, &smb_fname, &bsize,
						&dfree, &dsize);
			if (df_ret == (uint64_t)-1) {
				return map_nt_error_from_unix(errno);
			}
			block_size = lp_block_size(snum);
			if (bsize < block_size) {
				uint64_t factor = block_size/bsize;
				bsize = block_size;
				dsize /= factor;
				dfree /= factor;
			}
			if (bsize > block_size) {
				uint64_t factor = bsize/block_size;
				bsize = block_size;
				dsize *= factor;
				dfree *= factor;
			}
			sectors_per_unit = bsize/bytes_per_sector;
			DEBUG(5,("smbd_do_qfsinfo : SMB_QUERY_FS_SIZE_INFO bsize=%u, cSectorUnit=%u, \
cBytesSector=%u, cUnitTotal=%u, cUnitAvail=%d\n", (unsigned int)bsize, (unsigned int)sectors_per_unit,
				(unsigned int)bytes_per_sector, (unsigned int)dsize, (unsigned int)dfree));
			SBIG_UINT(pdata,0,dsize);
			SBIG_UINT(pdata,8,dfree);
			SIVAL(pdata,16,sectors_per_unit);
			SIVAL(pdata,20,bytes_per_sector);
			*fixed_portion = 24;
			break;
		}

		case SMB_FS_FULL_SIZE_INFORMATION:
		{
			uint64_t dfree,dsize,bsize,block_size,sectors_per_unit;
			data_len = 32;
			df_ret = get_dfree_info(conn, &smb_fname, &bsize,
						&dfree, &dsize);
			if (df_ret == (uint64_t)-1) {
				return map_nt_error_from_unix(errno);
			}
			block_size = lp_block_size(snum);
			if (bsize < block_size) {
				uint64_t factor = block_size/bsize;
				bsize = block_size;
				dsize /= factor;
				dfree /= factor;
			}
			if (bsize > block_size) {
				uint64_t factor = bsize/block_size;
				bsize = block_size;
				dsize *= factor;
				dfree *= factor;
			}
			sectors_per_unit = bsize/bytes_per_sector;
			DEBUG(5,("smbd_do_qfsinfo : SMB_QUERY_FS_FULL_SIZE_INFO bsize=%u, cSectorUnit=%u, \
cBytesSector=%u, cUnitTotal=%u, cUnitAvail=%d\n", (unsigned int)bsize, (unsigned int)sectors_per_unit,
				(unsigned int)bytes_per_sector, (unsigned int)dsize, (unsigned int)dfree));
			SBIG_UINT(pdata,0,dsize); /* Total Allocation units. */
			SBIG_UINT(pdata,8,dfree); /* Caller available allocation units. */
			SBIG_UINT(pdata,16,dfree); /* Actual available allocation units. */
			SIVAL(pdata,24,sectors_per_unit); /* Sectors per allocation unit. */
			SIVAL(pdata,28,bytes_per_sector); /* Bytes per sector. */
			*fixed_portion = 32;
			break;
		}

		case SMB_QUERY_FS_DEVICE_INFO:
		case SMB_FS_DEVICE_INFORMATION:
		{
			uint32_t characteristics = FILE_DEVICE_IS_MOUNTED;

			if (!CAN_WRITE(conn)) {
				characteristics |= FILE_READ_ONLY_DEVICE;
			}
			data_len = 8;
			SIVAL(pdata,0,FILE_DEVICE_DISK); /* dev type */
			SIVAL(pdata,4,characteristics);
			*fixed_portion = 8;
			break;
		}

#ifdef HAVE_SYS_QUOTAS
		case SMB_FS_QUOTA_INFORMATION:
		/*
		 * what we have to send --metze:
		 *
		 * Unknown1: 		24 NULL bytes
		 * Soft Quota Threshold: 8 bytes seems like uint64_t or so
		 * Hard Quota Limit:	8 bytes seems like uint64_t or so
		 * Quota Flags:		2 byte :
		 * Unknown3:		6 NULL bytes
		 *
		 * 48 bytes total
		 *
		 * details for Quota Flags:
		 *
		 * 0x0020 Log Limit: log if the user exceeds his Hard Quota
		 * 0x0010 Log Warn:  log if the user exceeds his Soft Quota
		 * 0x0002 Deny Disk: deny disk access when the user exceeds his Hard Quota
		 * 0x0001 Enable Quotas: enable quota for this fs
		 *
		 */
		{
			/* we need to fake up a fsp here,
			 * because its not send in this call
			 */
			files_struct tmpfsp = {
				.conn = conn,
				.fnum = FNUM_FIELD_INVALID,
			};
			SMB_NTQUOTA_STRUCT quotas = {};

			/* access check */
			if (get_current_uid(conn) != 0) {
				DEBUG(0,("get_user_quota: access_denied "
					 "service [%s] user [%s]\n",
					 lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
					 conn->session_info->unix_info->unix_name));
				return NT_STATUS_ACCESS_DENIED;
			}

			status = vfs_get_ntquota(&tmpfsp, SMB_USER_FS_QUOTA_TYPE,
						 NULL, &quotas);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0,("vfs_get_ntquota() failed for service [%s]\n",lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));
				return status;
			}

			data_len = 48;

			DEBUG(10,("SMB_FS_QUOTA_INFORMATION: for service [%s]\n",
				  lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));

			/* Unknown1 24 NULL bytes*/
			SBIG_UINT(pdata,0,(uint64_t)0);
			SBIG_UINT(pdata,8,(uint64_t)0);
			SBIG_UINT(pdata,16,(uint64_t)0);

			/* Default Soft Quota 8 bytes */
			SBIG_UINT(pdata,24,quotas.softlim);

			/* Default Hard Quota 8 bytes */
			SBIG_UINT(pdata,32,quotas.hardlim);

			/* Quota flag 2 bytes */
			SSVAL(pdata,40,quotas.qflags);

			/* Unknown3 6 NULL bytes */
			SSVAL(pdata,42,0);
			SIVAL(pdata,44,0);

			break;
		}
#endif /* HAVE_SYS_QUOTAS */
		case SMB_FS_OBJECTID_INFORMATION:
		{
			unsigned char objid[16];
			struct smb_extended_info extended_info;
			memcpy(pdata,create_volume_objectid(conn, objid),16);
			samba_extended_info_version (&extended_info);
			SIVAL(pdata,16,extended_info.samba_magic);
			SIVAL(pdata,20,extended_info.samba_version);
			SIVAL(pdata,24,extended_info.samba_subversion);
			SBIG_UINT(pdata,28,extended_info.samba_gitcommitdate);
			memcpy(pdata+36,extended_info.samba_version_string,28);
			data_len = 64;
			break;
		}

		case SMB_FS_SECTOR_SIZE_INFORMATION:
		{
			uint32_t bps_logical = lp_parm_ulong(
				SNUM(conn),
				"fs", "logical bytes per sector",
				bytes_per_sector);
			uint32_t bps_aligned = lp_parm_ulong(
				SNUM(conn),
				"fs", "aligned bytes per sector",
				bytes_per_sector);
			uint32_t bps_performance = lp_parm_ulong(
				SNUM(conn),
				"fs", "performance bytes per sector",
				bytes_per_sector);
			uint32_t bps_effective = lp_parm_ulong(
				SNUM(conn),
				"fs", "effective aligned bytes per sector",
				bytes_per_sector);

			data_len = 28;
			/*
			 * These values match a physical Windows Server 2012
			 * share backed by NTFS atop spinning rust.
			 */
			DEBUG(5, ("SMB_FS_SECTOR_SIZE_INFORMATION:"));
			/* logical_bytes_per_sector */
			SIVAL(pdata, 0, bps_logical);
			/* phys_bytes_per_sector_atomic */
			SIVAL(pdata, 4, bps_aligned);
			/* phys_bytes_per_sector_perf */
			SIVAL(pdata, 8, bps_performance);
			/* fs_effective_phys_bytes_per_sector_atomic */
			SIVAL(pdata, 12, bps_effective);
			/* flags */
			SIVAL(pdata, 16, SSINFO_FLAGS_ALIGNED_DEVICE
				| SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
			/* byte_off_sector_align */
			SIVAL(pdata, 20, 0);
			/* byte_off_partition_align */
			SIVAL(pdata, 24, 0);
			*fixed_portion = 28;
			break;
		}


#if defined(WITH_SMB1SERVER)
		/*
		 * Query the version and capabilities of the CIFS UNIX extensions
		 * in use.
		 */

		case SMB_QUERY_CIFS_UNIX_INFO:
		{
			bool large_write = lp_min_receive_file_size() &&
					!smb1_srv_is_signing_active(xconn);
			bool large_read = !smb1_srv_is_signing_active(xconn);
			int encrypt_caps = 0;

			if (!lp_smb1_unix_extensions()) {
				return NT_STATUS_INVALID_LEVEL;
			}

			switch (conn->encrypt_level) {
			case SMB_SIGNING_OFF:
				encrypt_caps = 0;
				break;
			case SMB_SIGNING_DESIRED:
			case SMB_SIGNING_IF_REQUIRED:
			case SMB_SIGNING_DEFAULT:
				encrypt_caps = CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP;
				break;
			case SMB_SIGNING_REQUIRED:
				encrypt_caps = CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP|
						CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP;
				large_write = false;
				large_read = false;
				break;
			}

			data_len = 12;
			SSVAL(pdata,0,CIFS_UNIX_MAJOR_VERSION);
			SSVAL(pdata,2,CIFS_UNIX_MINOR_VERSION);

			/* We have POSIX ACLs, pathname, encryption,
			 * large read/write, and locking capability. */

			SBIG_UINT(pdata,4,((uint64_t)(
					CIFS_UNIX_POSIX_ACLS_CAP|
					CIFS_UNIX_POSIX_PATHNAMES_CAP|
					CIFS_UNIX_FCNTL_LOCKS_CAP|
					CIFS_UNIX_EXTATTR_CAP|
					CIFS_UNIX_POSIX_PATH_OPERATIONS_CAP|
					encrypt_caps|
					(large_read ? CIFS_UNIX_LARGE_READ_CAP : 0) |
					(large_write ?
					CIFS_UNIX_LARGE_WRITE_CAP : 0))));
			break;
		}
#endif

		case SMB_QUERY_POSIX_FS_INFO:
		case SMB2_FS_POSIX_INFORMATION_INTERNAL:
		{
			int rc;
			struct vfs_statvfs_struct svfs;

			if (!fsinfo_unix_valid_level(conn, fsp, info_level)) {
				return NT_STATUS_INVALID_LEVEL;
			}

			rc = SMB_VFS_STATVFS(conn, &smb_fname, &svfs);

			if (!rc) {
				data_len = 56;
				SIVAL(pdata,0,svfs.OptimalTransferSize);
				SIVAL(pdata,4,svfs.BlockSize);
				SBIG_UINT(pdata,8,svfs.TotalBlocks);
				SBIG_UINT(pdata,16,svfs.BlocksAvail);
				SBIG_UINT(pdata,24,svfs.UserBlocksAvail);
				SBIG_UINT(pdata,32,svfs.TotalFileNodes);
				SBIG_UINT(pdata,40,svfs.FreeFileNodes);
				SBIG_UINT(pdata,48,svfs.FsIdentifier);
				DEBUG(5,("smbd_do_qfsinfo : SMB_QUERY_POSIX_FS_INFO successful\n"));
#ifdef EOPNOTSUPP
			} else if (rc == EOPNOTSUPP) {
				return NT_STATUS_INVALID_LEVEL;
#endif /* EOPNOTSUPP */
			} else {
				DEBUG(0,("vfs_statvfs() failed for service [%s]\n",lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));
				return NT_STATUS_DOS(ERRSRV, ERRerror);
			}
			break;
		}

		case SMB_QUERY_POSIX_WHOAMI:
		{
			uint32_t flags = 0;
			uint32_t sid_bytes;
			uint32_t i;

			if (!lp_smb1_unix_extensions()) {
				return NT_STATUS_INVALID_LEVEL;
			}

			if (max_data_bytes < 40) {
				return NT_STATUS_BUFFER_TOO_SMALL;
			}

			if (security_session_user_level(conn->session_info, NULL) < SECURITY_USER) {
				flags |= SMB_WHOAMI_GUEST;
			}

			/* NOTE: 8 bytes for UID/GID, irrespective of native
			 * platform size. This matches
			 * SMB_QUERY_FILE_UNIX_BASIC and friends.
			 */
			data_len = 4 /* flags */
			    + 4 /* flag mask */
			    + 8 /* uid */
			    + 8 /* gid */
			    + 4 /* ngroups */
			    + 4 /* num_sids */
			    + 4 /* SID bytes */
			    + 4 /* pad/reserved */
			    + (conn->session_info->unix_token->ngroups * 8)
				/* groups list */
			    + (conn->session_info->security_token->num_sids *
				    SID_MAX_SIZE)
				/* SID list */;

			SIVAL(pdata, 0, flags);
			SIVAL(pdata, 4, SMB_WHOAMI_MASK);
			SBIG_UINT(pdata, 8,
				  (uint64_t)conn->session_info->unix_token->uid);
			SBIG_UINT(pdata, 16,
				  (uint64_t)conn->session_info->unix_token->gid);


			if (data_len >= max_data_bytes) {
				/* Potential overflow, skip the GIDs and SIDs. */

				SIVAL(pdata, 24, 0); /* num_groups */
				SIVAL(pdata, 28, 0); /* num_sids */
				SIVAL(pdata, 32, 0); /* num_sid_bytes */
				SIVAL(pdata, 36, 0); /* reserved */

				data_len = 40;
				break;
			}

			SIVAL(pdata, 24, conn->session_info->unix_token->ngroups);
			SIVAL(pdata, 28, conn->session_info->security_token->num_sids);

			/* We walk the SID list twice, but this call is fairly
			 * infrequent, and I don't expect that it's performance
			 * sensitive -- jpeach
			 */
			for (i = 0, sid_bytes = 0;
			     i < conn->session_info->security_token->num_sids; ++i) {
				sid_bytes += ndr_size_dom_sid(
					&conn->session_info->security_token->sids[i],
					0);
			}

			/* SID list byte count */
			SIVAL(pdata, 32, sid_bytes);

			/* 4 bytes pad/reserved - must be zero */
			SIVAL(pdata, 36, 0);
			data_len = 40;

			/* GID list */
			for (i = 0; i < conn->session_info->unix_token->ngroups; ++i) {
				SBIG_UINT(pdata, data_len,
					  (uint64_t)conn->session_info->unix_token->groups[i]);
				data_len += 8;
			}

			/* SID list */
			for (i = 0;
			    i < conn->session_info->security_token->num_sids; ++i) {
				int sid_len = ndr_size_dom_sid(
					&conn->session_info->security_token->sids[i],
					0);

				sid_linearize((uint8_t *)(pdata + data_len),
					      sid_len,
				    &conn->session_info->security_token->sids[i]);
				data_len += sid_len;
			}

			break;
		}

		case SMB_MAC_QUERY_FS_INFO:
			/*
			 * Thursby MAC extension... ONLY on NTFS filesystems
			 * once we do streams then we don't need this
			 */
			if (strequal(lp_fstype(SNUM(conn)),"NTFS")) {
				data_len = 88;
				SIVAL(pdata,84,0x100); /* Don't support mac... */
				break;
			}

			FALL_THROUGH;
		default:
			return NT_STATUS_INVALID_LEVEL;
	}

	*ret_data_len = data_len;
	return status;
}

NTSTATUS smb_set_fsquota(connection_struct *conn,
			 struct smb_request *req,
			 files_struct *fsp,
			 const DATA_BLOB *qdata)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	NTSTATUS status;
	SMB_NTQUOTA_STRUCT quotas;

	ZERO_STRUCT(quotas);

	/* access check */
	if ((get_current_uid(conn) != 0) || !CAN_WRITE(conn)) {
		DBG_NOTICE("access_denied service [%s] user [%s]\n",
			   lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
			   conn->session_info->unix_info->unix_name);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!check_fsp_ntquota_handle(conn, req,
				      fsp)) {
		DBG_WARNING("no valid QUOTA HANDLE\n");
		return NT_STATUS_INVALID_HANDLE;
	}

	/* note: normally there're 48 bytes,
	 * but we didn't use the last 6 bytes for now
	 * --metze
	 */
	if (qdata->length < 42) {
		DBG_ERR("requires total_data(%zu) >= 42 bytes!\n",
			qdata->length);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* unknown_1 24 NULL bytes in pdata*/

	/* the soft quotas 8 bytes (uint64_t)*/
	quotas.softlim = BVAL(qdata->data,24);

	/* the hard quotas 8 bytes (uint64_t)*/
	quotas.hardlim = BVAL(qdata->data,32);

	/* quota_flags 2 bytes **/
	quotas.qflags = SVAL(qdata->data,40);

	/* unknown_2 6 NULL bytes follow*/

	/* now set the quotas */
	if (vfs_set_ntquota(fsp, SMB_USER_FS_QUOTA_TYPE, NULL, &quotas)!=0) {
		DBG_WARNING("vfs_set_ntquota() failed for service [%s]\n",
			    lp_servicename(talloc_tos(), lp_sub, SNUM(conn)));
		status =  map_nt_error_from_unix(errno);
	} else {
		status = NT_STATUS_OK;
	}
	return status;
}

NTSTATUS smbd_do_setfsinfo(connection_struct *conn,
                                struct smb_request *req,
                                TALLOC_CTX *mem_ctx,
                                uint16_t info_level,
                                files_struct *fsp,
				const DATA_BLOB *pdata)
{
	switch (info_level) {
		case SMB_FS_QUOTA_INFORMATION:
		{
			return smb_set_fsquota(conn,
						req,
						fsp,
						pdata);
		}

		default:
			break;
	}
	return NT_STATUS_INVALID_LEVEL;
}

/****************************************************************************
 Store the FILE_UNIX_BASIC info.
****************************************************************************/

char *store_file_unix_basic(connection_struct *conn,
			    char *pdata,
			    files_struct *fsp,
			    const SMB_STRUCT_STAT *psbuf)
{
	dev_t devno;

	DBG_DEBUG("SMB_QUERY_FILE_UNIX_BASIC\n");
	DBG_NOTICE("st_mode=%o\n", (int)psbuf->st_ex_mode);

	SOFF_T(pdata,0,get_file_size_stat(psbuf));             /* File size 64 Bit */
	pdata += 8;

	SOFF_T(pdata,0,SMB_VFS_GET_ALLOC_SIZE(conn,fsp,psbuf)); /* Number of bytes used on disk - 64 Bit */
	pdata += 8;

	put_long_date_full_timespec(TIMESTAMP_SET_NT_OR_BETTER, pdata, &psbuf->st_ex_ctime);       /* Change Time 64 Bit */
	put_long_date_full_timespec(TIMESTAMP_SET_NT_OR_BETTER ,pdata+8, &psbuf->st_ex_atime);     /* Last access time 64 Bit */
	put_long_date_full_timespec(TIMESTAMP_SET_NT_OR_BETTER, pdata+16, &psbuf->st_ex_mtime);    /* Last modification time 64 Bit */
	pdata += 24;

	SIVAL(pdata,0,psbuf->st_ex_uid);               /* user id for the owner */
	SIVAL(pdata,4,0);
	pdata += 8;

	SIVAL(pdata,0,psbuf->st_ex_gid);               /* group id of owner */
	SIVAL(pdata,4,0);
	pdata += 8;

	SIVAL(pdata, 0, unix_filetype_to_wire(psbuf->st_ex_mode));
	pdata += 4;

	if (S_ISBLK(psbuf->st_ex_mode) || S_ISCHR(psbuf->st_ex_mode)) {
		devno = psbuf->st_ex_rdev;
	} else {
		devno = psbuf->st_ex_dev;
	}

	SIVAL(pdata,0,unix_dev_major(devno));   /* Major device number if type is device */
	SIVAL(pdata,4,0);
	pdata += 8;

	SIVAL(pdata,0,unix_dev_minor(devno));   /* Minor device number if type is device */
	SIVAL(pdata,4,0);
	pdata += 8;

	SINO_T_VAL(pdata, 0, psbuf->st_ex_ino);   /* inode number */
	pdata += 8;

	SIVAL(pdata,0, unix_perms_to_wire(psbuf->st_ex_mode));     /* Standard UNIX file permissions */
	SIVAL(pdata,4,0);
	pdata += 8;

	SIVAL(pdata,0,psbuf->st_ex_nlink);             /* number of hard links */
	SIVAL(pdata,4,0);
	pdata += 8;

	return pdata;
}

/* Forward and reverse mappings from the UNIX_INFO2 file flags field and
 * the chflags(2) (or equivalent) flags.
 *
 * XXX: this really should be behind the VFS interface. To do this, we would
 * need to alter SMB_STRUCT_STAT so that it included a flags and a mask field.
 * Each VFS module could then implement its own mapping as appropriate for the
 * platform. We would then pass the SMB flags into SMB_VFS_CHFLAGS.
 */
static const struct {unsigned stat_fflag; unsigned smb_fflag;}
	info2_flags_map[] =
{
#ifdef UF_NODUMP
    { UF_NODUMP, EXT_DO_NOT_BACKUP },
#endif

#ifdef UF_IMMUTABLE
    { UF_IMMUTABLE, EXT_IMMUTABLE },
#endif

#ifdef UF_APPEND
    { UF_APPEND, EXT_OPEN_APPEND_ONLY },
#endif

#ifdef UF_HIDDEN
    { UF_HIDDEN, EXT_HIDDEN },
#endif

    /* Do not remove. We need to guarantee that this array has at least one
     * entry to build on HP-UX.
     */
    { 0, 0 }

};

static void map_info2_flags_from_sbuf(const SMB_STRUCT_STAT *psbuf,
				uint32_t *smb_fflags, uint32_t *smb_fmask)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(info2_flags_map); ++i) {
	    *smb_fmask |= info2_flags_map[i].smb_fflag;
	    if (psbuf->st_ex_flags & info2_flags_map[i].stat_fflag) {
		    *smb_fflags |= info2_flags_map[i].smb_fflag;
	    }
	}
}

bool map_info2_flags_to_sbuf(const SMB_STRUCT_STAT *psbuf,
			     const uint32_t smb_fflags,
			     const uint32_t smb_fmask,
			     int *stat_fflags)
{
	uint32_t max_fmask = 0;
	size_t i;

	*stat_fflags = psbuf->st_ex_flags;

	/* For each flags requested in smb_fmask, check the state of the
	 * corresponding flag in smb_fflags and set or clear the matching
	 * stat flag.
	 */

	for (i = 0; i < ARRAY_SIZE(info2_flags_map); ++i) {
	    max_fmask |= info2_flags_map[i].smb_fflag;
	    if (smb_fmask & info2_flags_map[i].smb_fflag) {
		    if (smb_fflags & info2_flags_map[i].smb_fflag) {
			    *stat_fflags |= info2_flags_map[i].stat_fflag;
		    } else {
			    *stat_fflags &= ~info2_flags_map[i].stat_fflag;
		    }
	    }
	}

	/* If smb_fmask is asking to set any bits that are not supported by
	 * our flag mappings, we should fail.
	 */
	if ((smb_fmask & max_fmask) != smb_fmask) {
		return False;
	}

	return True;
}


/* Just like SMB_QUERY_FILE_UNIX_BASIC, but with the addition
 * of file flags and birth (create) time.
 */
char *store_file_unix_basic_info2(connection_struct *conn,
				  char *pdata,
				  files_struct *fsp,
				  const SMB_STRUCT_STAT *psbuf)
{
	uint32_t file_flags = 0;
	uint32_t flags_mask = 0;

	pdata = store_file_unix_basic(conn, pdata, fsp, psbuf);

	/* Create (birth) time 64 bit */
	put_long_date_full_timespec(TIMESTAMP_SET_NT_OR_BETTER,pdata, &psbuf->st_ex_btime);
	pdata += 8;

	map_info2_flags_from_sbuf(psbuf, &file_flags, &flags_mask);
	SIVAL(pdata, 0, file_flags); /* flags */
	SIVAL(pdata, 4, flags_mask); /* mask */
	pdata += 8;

	return pdata;
}

static NTSTATUS marshall_stream_info(unsigned int num_streams,
				     const struct stream_struct *streams,
				     char *data,
				     unsigned int max_data_bytes,
				     unsigned int *data_size)
{
	unsigned int i;
	unsigned int ofs = 0;

	if (max_data_bytes < 32) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	for (i = 0; i < num_streams; i++) {
		unsigned int next_offset;
		size_t namelen;
		smb_ucs2_t *namebuf;

		if (!push_ucs2_talloc(talloc_tos(), &namebuf,
				      streams[i].name, &namelen) ||
		    namelen <= 2)
		{
			return NT_STATUS_INVALID_PARAMETER;
		}

		/*
		 * name_buf is now null-terminated, we need to marshall as not
		 * terminated
		 */

		namelen -= 2;

		/*
		 * We cannot overflow ...
		 */
		if ((ofs + 24 + namelen) > max_data_bytes) {
			DEBUG(10, ("refusing to overflow reply at stream %u\n",
				i));
			TALLOC_FREE(namebuf);
			return STATUS_BUFFER_OVERFLOW;
		}

		SIVAL(data, ofs+4, namelen);
		SOFF_T(data, ofs+8, streams[i].size);
		SOFF_T(data, ofs+16, streams[i].alloc_size);
		memcpy(data+ofs+24, namebuf, namelen);
		TALLOC_FREE(namebuf);

		next_offset = ofs + 24 + namelen;

		if (i == num_streams-1) {
			SIVAL(data, ofs, 0);
		}
		else {
			unsigned int align = ndr_align_size(next_offset, 8);

			if ((next_offset + align) > max_data_bytes) {
				DEBUG(10, ("refusing to overflow align "
					"reply at stream %u\n",
					i));
				TALLOC_FREE(namebuf);
				return STATUS_BUFFER_OVERFLOW;
			}

			memset(data+next_offset, 0, align);
			next_offset += align;

			SIVAL(data, ofs, next_offset - ofs);
			ofs = next_offset;
		}

		ofs = next_offset;
	}

	DEBUG(10, ("max_data: %u, data_size: %u\n", max_data_bytes, ofs));

	*data_size = ofs;

	return NT_STATUS_OK;
}

NTSTATUS smbd_do_qfilepathinfo(connection_struct *conn,
			       TALLOC_CTX *mem_ctx,
			       struct smb_request *req,
			       uint16_t info_level,
			       files_struct *fsp,
			       struct smb_filename *smb_fname,
			       bool delete_pending,
			       struct timespec write_time_ts,
			       struct ea_list *ea_list,
			       uint16_t flags2,
			       unsigned int max_data_bytes,
			       size_t *fixed_portion,
			       char **ppdata,
			       unsigned int *pdata_size)
{
	char *pdata = *ppdata;
	char *dstart, *dend;
	unsigned int data_size;
	struct timespec create_time_ts, mtime_ts, atime_ts, ctime_ts;
	SMB_STRUCT_STAT *psbuf = NULL;
	SMB_STRUCT_STAT *base_sp = NULL;
	char *p;
	char *base_name;
	char *dos_fname;
	int mode;
	int nlink;
	NTSTATUS status;
	uint64_t file_size = 0;
	uint64_t pos = 0;
	uint64_t allocation_size = 0;
	uint64_t file_id = 0;
	uint32_t access_mask = 0;
	size_t len = 0;

	if (INFO_LEVEL_IS_UNIX(info_level)) {
		bool ok = false;

		if (lp_smb1_unix_extensions() && req->posix_pathnames) {
			DBG_DEBUG("SMB1 unix extensions activated\n");
			ok = true;
		}

		if (conn_using_smb2(conn->sconn) &&
		    fsp->fsp_flags.posix_open)
		{
			DBG_DEBUG("SMB2 posix open\n");
			ok = true;
		}

		if (!ok) {
			return NT_STATUS_INVALID_LEVEL;
		}
	}

	DBG_INFO("%s (%s) level=%d max_data=%u\n",
		 smb_fname_str_dbg(smb_fname),
		 fsp_fnum_dbg(fsp),
		 info_level, max_data_bytes);

	/*
	 * In case of querying a symlink in POSIX context,
	 * fsp will be NULL. fdos_mode() deals with it.
	 */
	if (fsp != NULL) {
		smb_fname = fsp->fsp_name;
	}
	mode = fdos_mode(fsp);
	psbuf = &smb_fname->st;

	if (fsp != NULL) {
		base_sp = fsp->base_fsp ?
			&fsp->base_fsp->fsp_name->st :
			&fsp->fsp_name->st;
	} else {
		base_sp = &smb_fname->st;
	}

	nlink = psbuf->st_ex_nlink;

	if (nlink && (mode&FILE_ATTRIBUTE_DIRECTORY)) {
		nlink = 1;
	}

	if ((nlink > 0) && delete_pending) {
		nlink -= 1;
	}

	if (max_data_bytes + DIR_ENTRY_SAFETY_MARGIN < max_data_bytes) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	data_size = max_data_bytes + DIR_ENTRY_SAFETY_MARGIN;
	*ppdata = (char *)SMB_REALLOC(*ppdata, data_size);
	if (*ppdata == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	pdata = *ppdata;
	dstart = pdata;
	dend = dstart + data_size - 1;

	if (!is_omit_timespec(&write_time_ts) &&
	    !INFO_LEVEL_IS_UNIX(info_level))
	{
		update_stat_ex_mtime(psbuf, write_time_ts);
	}

	create_time_ts = get_create_timespec(conn, fsp, smb_fname);
	mtime_ts = psbuf->st_ex_mtime;
	atime_ts = psbuf->st_ex_atime;
	ctime_ts = get_change_timespec(conn, fsp, smb_fname);

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		dos_filetime_timespec(&create_time_ts);
		dos_filetime_timespec(&mtime_ts);
		dos_filetime_timespec(&atime_ts);
		dos_filetime_timespec(&ctime_ts);
	}

	p = strrchr_m(smb_fname->base_name,'/');
	if (p == NULL) {
		base_name = smb_fname->base_name;
	} else {
		base_name = p+1;
	}

	/* NT expects the name to be in an exact form of the *full*
	   filename. See the trans2 torture test */
	if (ISDOT(base_name)) {
		dos_fname = talloc_strdup(mem_ctx, "\\");
		if (!dos_fname) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		dos_fname = talloc_asprintf(mem_ctx,
				"\\%s",
				smb_fname->base_name);
		if (!dos_fname) {
			return NT_STATUS_NO_MEMORY;
		}
		if (is_named_stream(smb_fname)) {
			dos_fname = talloc_asprintf(dos_fname, "%s",
						    smb_fname->stream_name);
			if (!dos_fname) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		string_replace(dos_fname, '/', '\\');
	}

	allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn, fsp, psbuf);

	if (fsp == NULL || !fsp->fsp_flags.is_fsa) {
		/* Do we have this path open ? */
		struct file_id fileid = vfs_file_id_from_sbuf(conn, psbuf);
		files_struct *fsp1 = file_find_di_first(
			conn->sconn, fileid, true);
		if (fsp1 && fsp1->initial_allocation_size) {
			allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn, fsp1, psbuf);
		}
	}

	if (!(mode & FILE_ATTRIBUTE_DIRECTORY)) {
		file_size = get_file_size_stat(psbuf);
	}

	if (fsp) {
		pos = fh_get_position_information(fsp->fh);
	}

	if (fsp) {
		access_mask = fsp->access_mask;
	} else {
		/* GENERIC_EXECUTE mapping from Windows */
		access_mask = 0x12019F;
	}

	/* This should be an index number - looks like
	   dev/ino to me :-)

	   I think this causes us to fail the IFSKIT
	   BasicFileInformationTest. -tpot */
	file_id = SMB_VFS_FS_FILE_ID(conn, base_sp);

	*fixed_portion = 0;

	switch (info_level) {
		case SMB_INFO_STANDARD:
			DBG_DEBUG("SMB_INFO_STANDARD\n");
			data_size = 22;
			srv_put_dos_date2_ts(pdata,
					     l1_fdateCreation,
					     create_time_ts);
			srv_put_dos_date2_ts(pdata,
					     l1_fdateLastAccess,
					     atime_ts);
			srv_put_dos_date2_ts(pdata,
					     l1_fdateLastWrite,
					     mtime_ts); /* write time */
			SIVAL(pdata,l1_cbFile,(uint32_t)file_size);
			SIVAL(pdata,l1_cbFileAlloc,(uint32_t)allocation_size);
			SSVAL(pdata,l1_attrFile,mode);
			break;

		case SMB_INFO_QUERY_EA_SIZE:
		{
			unsigned int ea_size =
			    estimate_ea_size(smb_fname->fsp);
			DBG_DEBUG("SMB_INFO_QUERY_EA_SIZE\n");
			data_size = 26;
			srv_put_dos_date2_ts(pdata, 0, create_time_ts);
			srv_put_dos_date2_ts(pdata, 4, atime_ts);
			srv_put_dos_date2_ts(pdata,
					     8,
					     mtime_ts); /* write time */
			SIVAL(pdata,12,(uint32_t)file_size);
			SIVAL(pdata,16,(uint32_t)allocation_size);
			SSVAL(pdata,20,mode);
			SIVAL(pdata,22,ea_size);
			break;
		}

		case SMB_INFO_IS_NAME_VALID:
			DBG_DEBUG("SMB_INFO_IS_NAME_VALID\n");
			if (fsp) {
				/* os/2 needs this ? really ?*/
				return NT_STATUS_DOS(ERRDOS, ERRbadfunc);
			}
			/* This is only reached for qpathinfo */
			data_size = 0;
			break;

		case SMB_INFO_QUERY_EAS_FROM_LIST:
		{
			size_t total_ea_len = 0;
			struct ea_list *ea_file_list = NULL;
			DBG_DEBUG("SMB_INFO_QUERY_EAS_FROM_LIST\n");

			status =
			    get_ea_list_from_fsp(mem_ctx,
						  smb_fname->fsp,
						  &total_ea_len, &ea_file_list);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}

			ea_list = ea_list_union(ea_list, ea_file_list, &total_ea_len);

			if (!ea_list || (total_ea_len > data_size)) {
				data_size = 4;
				SIVAL(pdata,0,4);   /* EA List Length must be set to 4 if no EA's. */
				break;
			}

			data_size = fill_ea_buffer(mem_ctx, pdata, data_size, conn, ea_list);
			break;
		}

		case SMB_INFO_QUERY_ALL_EAS:
		{
			/* We have data_size bytes to put EA's into. */
			size_t total_ea_len = 0;
			DBG_DEBUG(" SMB_INFO_QUERY_ALL_EAS\n");

			status = get_ea_list_from_fsp(mem_ctx,
							smb_fname->fsp,
							&total_ea_len, &ea_list);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}

			if (!ea_list || (total_ea_len > data_size)) {
				data_size = 4;
				SIVAL(pdata,0,4);   /* EA List Length must be set to 4 if no EA's. */
				break;
			}

			data_size = fill_ea_buffer(mem_ctx, pdata, data_size, conn, ea_list);
			break;
		}

		case SMB2_FILE_FULL_EA_INFORMATION:
		{
			/* We have data_size bytes to put EA's into. */
			size_t total_ea_len = 0;
			struct ea_list *ea_file_list = NULL;

			DBG_DEBUG("SMB2_INFO_QUERY_ALL_EAS\n");

			/*TODO: add filtering and index handling */

			status  =
				get_ea_list_from_fsp(mem_ctx,
						  smb_fname->fsp,
						  &total_ea_len, &ea_file_list);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			if (!ea_file_list) {
				return NT_STATUS_NO_EAS_ON_FILE;
			}

			status = fill_ea_chained_buffer(mem_ctx,
							pdata,
							data_size,
							&data_size,
							conn, ea_file_list);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			break;
		}

		case SMB_FILE_BASIC_INFORMATION:
		case SMB_QUERY_FILE_BASIC_INFO:

			if (info_level == SMB_QUERY_FILE_BASIC_INFO) {
				DBG_DEBUG("SMB_QUERY_FILE_BASIC_INFO\n");
				data_size = 36; /* w95 returns 40 bytes not 36 - why ?. */
			} else {
				DBG_DEBUG("SMB_FILE_BASIC_INFORMATION\n");
				data_size = 40;
				SIVAL(pdata,36,0);
			}
			put_long_date_full_timespec(conn->ts_res,pdata,&create_time_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+8,&atime_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+16,&mtime_ts); /* write time */
			put_long_date_full_timespec(conn->ts_res,pdata+24,&ctime_ts); /* change time */
			SIVAL(pdata,32,mode);

			DBG_INFO("SMB_QFBI - create: %s access: %s "
				 "write: %s change: %s mode: %x\n",
				 ctime(&create_time_ts.tv_sec),
				 ctime(&atime_ts.tv_sec),
				 ctime(&mtime_ts.tv_sec),
				 ctime(&ctime_ts.tv_sec),
				 mode);
			*fixed_portion = data_size;
			break;

		case SMB_FILE_STANDARD_INFORMATION:
		case SMB_QUERY_FILE_STANDARD_INFO:

			DBG_DEBUG("SMB_FILE_STANDARD_INFORMATION\n");
			data_size = 24;
			SOFF_T(pdata,0,allocation_size);
			SOFF_T(pdata,8,file_size);
			SIVAL(pdata,16,nlink);
			SCVAL(pdata,20,delete_pending?1:0);
			SCVAL(pdata,21,(mode&FILE_ATTRIBUTE_DIRECTORY)?1:0);
			SSVAL(pdata,22,0); /* Padding. */
			*fixed_portion = 24;
			break;

		case SMB_FILE_EA_INFORMATION:
		case SMB_QUERY_FILE_EA_INFO:
		{
			unsigned int ea_size =
			    estimate_ea_size(smb_fname->fsp);
			DBG_DEBUG("SMB_FILE_EA_INFORMATION\n");
			data_size = 4;
			*fixed_portion = 4;
			SIVAL(pdata,0,ea_size);
			break;
		}

		/* Get the 8.3 name - used if NT SMB was negotiated. */
		case SMB_QUERY_FILE_ALT_NAME_INFO:
		case SMB_FILE_ALTERNATE_NAME_INFORMATION:
		{
			char mangled_name[13];
			DBG_DEBUG("SMB_FILE_ALTERNATE_NAME_INFORMATION\n");
			if (!name_to_8_3(base_name,mangled_name,
						True,conn->params)) {
				return NT_STATUS_NO_MEMORY;
			}
			status = srvstr_push(dstart, flags2,
					  pdata+4, mangled_name,
					  PTR_DIFF(dend, pdata+4),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			data_size = 4 + len;
			SIVAL(pdata,0,len);
			*fixed_portion = 8;
			break;
		}

		case SMB_QUERY_FILE_NAME_INFO:
		{
			/*
			  this must be *exactly* right for ACLs on mapped drives to work
			 */
			status = srvstr_push(dstart, flags2,
					  pdata+4, dos_fname,
					  PTR_DIFF(dend, pdata+4),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			DBG_DEBUG("SMB_QUERY_FILE_NAME_INFO\n");
			data_size = 4 + len;
			SIVAL(pdata,0,len);
			break;
		}

		case SMB_FILE_NORMALIZED_NAME_INFORMATION:
		{
			char *nfname = NULL;

			if (fsp == NULL ||
			    !conn_using_smb2(fsp->conn->sconn)) {
				return NT_STATUS_INVALID_LEVEL;
			}

			nfname = talloc_strdup(mem_ctx, smb_fname->base_name);
			if (nfname == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			if (ISDOT(nfname)) {
				nfname[0] = '\0';
			}
			string_replace(nfname, '/', '\\');

			if (fsp_is_alternate_stream(fsp)) {
				const char *s = smb_fname->stream_name;
				const char *e = NULL;
				size_t n;

				SMB_ASSERT(s[0] != '\0');

				/*
				 * smb_fname->stream_name is in form
				 * of ':StrEam:$DATA', but we should only
				 * append ':StrEam' here.
				 */

				e = strchr(&s[1], ':');
				if (e == NULL) {
					n = strlen(s);
				} else {
					n = PTR_DIFF(e, s);
				}
				nfname = talloc_strndup_append(nfname, s, n);
				if (nfname == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
			}

			status = srvstr_push(dstart, flags2,
					  pdata+4, nfname,
					  PTR_DIFF(dend, pdata+4),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			DBG_DEBUG("SMB_FILE_NORMALIZED_NAME_INFORMATION\n");
			data_size = 4 + len;
			SIVAL(pdata,0,len);
			*fixed_portion = 8;
			break;
		}

		case SMB_FILE_ALLOCATION_INFORMATION:
		case SMB_QUERY_FILE_ALLOCATION_INFO:
			DBG_DEBUG("SMB_FILE_ALLOCATION_INFORMATION\n");
			data_size = 8;
			SOFF_T(pdata,0,allocation_size);
			break;

		case SMB_FILE_END_OF_FILE_INFORMATION:
		case SMB_QUERY_FILE_END_OF_FILEINFO:
			DBG_DEBUG("SMB_FILE_END_OF_FILE_INFORMATION\n");
			data_size = 8;
			SOFF_T(pdata,0,file_size);
			break;

		case SMB_QUERY_FILE_ALL_INFO:
		case SMB_FILE_ALL_INFORMATION:
		{
			unsigned int ea_size =
			    estimate_ea_size(smb_fname->fsp);
			DBG_DEBUG("SMB_FILE_ALL_INFORMATION\n");
			put_long_date_full_timespec(conn->ts_res,pdata,&create_time_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+8,&atime_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+16,&mtime_ts); /* write time */
			put_long_date_full_timespec(conn->ts_res,pdata+24,&ctime_ts); /* change time */
			SIVAL(pdata,32,mode);
			SIVAL(pdata,36,0); /* padding. */
			pdata += 40;
			SOFF_T(pdata,0,allocation_size);
			SOFF_T(pdata,8,file_size);
			SIVAL(pdata,16,nlink);
			SCVAL(pdata,20,delete_pending);
			SCVAL(pdata,21,(mode&FILE_ATTRIBUTE_DIRECTORY)?1:0);
			SSVAL(pdata,22,0);
			pdata += 24;
			SIVAL(pdata,0,ea_size);
			pdata += 4; /* EA info */
			status = srvstr_push(dstart, flags2,
					  pdata+4, dos_fname,
					  PTR_DIFF(dend, pdata+4),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SIVAL(pdata,0,len);
			pdata += 4 + len;
			data_size = PTR_DIFF(pdata,(*ppdata));
			*fixed_portion = 10;
			break;
		}

		case SMB2_FILE_ALL_INFORMATION:
		{
			unsigned int ea_size =
			    estimate_ea_size(smb_fname->fsp);
			DBG_DEBUG("SMB2_FILE_ALL_INFORMATION\n");
			put_long_date_full_timespec(conn->ts_res,pdata+0x00,&create_time_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+0x08,&atime_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+0x10,&mtime_ts); /* write time */
			put_long_date_full_timespec(conn->ts_res,pdata+0x18,&ctime_ts); /* change time */
			SIVAL(pdata,	0x20, mode);
			SIVAL(pdata,	0x24, 0); /* padding. */
			SBVAL(pdata,	0x28, allocation_size);
			SBVAL(pdata,	0x30, file_size);
			SIVAL(pdata,	0x38, nlink);
			SCVAL(pdata,	0x3C, delete_pending);
			SCVAL(pdata,	0x3D, (mode&FILE_ATTRIBUTE_DIRECTORY)?1:0);
			SSVAL(pdata,	0x3E, 0); /* padding */
			SBVAL(pdata,	0x40, file_id);
			SIVAL(pdata,	0x48, ea_size);
			SIVAL(pdata,	0x4C, access_mask);
			SBVAL(pdata,	0x50, pos);
			SIVAL(pdata,	0x58, mode); /*TODO: mode != mode fix this!!! */
			SIVAL(pdata,	0x5C, 0); /* No alignment needed. */

			pdata += 0x60;

			status = srvstr_push(dstart, flags2,
					  pdata+4, dos_fname,
					  PTR_DIFF(dend, pdata+4),
					  STR_UNICODE, &len);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			SIVAL(pdata,0,len);
			pdata += 4 + len;
			data_size = PTR_DIFF(pdata,(*ppdata));
			*fixed_portion = 104;
			break;
		}
		case SMB_FILE_INTERNAL_INFORMATION:

			DBG_DEBUG("SMB_FILE_INTERNAL_INFORMATION\n");
			SBVAL(pdata, 0, file_id);
			data_size = 8;
			*fixed_portion = 8;
			break;

		case SMB_FILE_ACCESS_INFORMATION:
			DBG_DEBUG("SMB_FILE_ACCESS_INFORMATION\n");
			SIVAL(pdata, 0, access_mask);
			data_size = 4;
			*fixed_portion = 4;
			break;

		case SMB_FILE_NAME_INFORMATION:
			/* Pathname with leading '\'. */
			{
				size_t byte_len;
				byte_len = dos_PutUniCode(pdata+4,dos_fname,(size_t)max_data_bytes,False);
				DBG_DEBUG("SMB_FILE_NAME_INFORMATION\n");
				SIVAL(pdata,0,byte_len);
				data_size = 4 + byte_len;
				break;
			}

		case SMB_FILE_DISPOSITION_INFORMATION:
			DBG_DEBUG("SMB_FILE_DISPOSITION_INFORMATION\n");
			data_size = 1;
			SCVAL(pdata,0,delete_pending);
			*fixed_portion = 1;
			break;

		case SMB_FILE_POSITION_INFORMATION:
			DBG_DEBUG("SMB_FILE_POSITION_INFORMATION\n");
			data_size = 8;
			SOFF_T(pdata,0,pos);
			*fixed_portion = 8;
			break;

		case SMB_FILE_MODE_INFORMATION:
			DBG_DEBUG("SMB_FILE_MODE_INFORMATION\n");
			SIVAL(pdata,0,mode);
			data_size = 4;
			*fixed_portion = 4;
			break;

		case SMB_FILE_ALIGNMENT_INFORMATION:
			DBG_DEBUG("SMB_FILE_ALIGNMENT_INFORMATION\n");
			SIVAL(pdata,0,0); /* No alignment needed. */
			data_size = 4;
			*fixed_portion = 4;
			break;

		/*
		 * NT4 server just returns "invalid query" to this - if we try
		 * to answer it then NTws gets a BSOD! (tridge).  W2K seems to
		 * want this. JRA.
		 */
		/* The first statement above is false - verified using Thursby
		 * client against NT4 -- gcolley.
		 */
		case SMB_QUERY_FILE_STREAM_INFO:
		case SMB_FILE_STREAM_INFORMATION: {
			unsigned int num_streams = 0;
			struct stream_struct *streams = NULL;

			DBG_DEBUG("SMB_FILE_STREAM_INFORMATION\n");

			if (is_ntfs_stream_smb_fname(smb_fname)) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			status = vfs_fstreaminfo(fsp,
						mem_ctx,
						&num_streams,
						&streams);

			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("could not get stream info: %s\n",
					  nt_errstr(status));
				return status;
			}

			status = marshall_stream_info(num_streams, streams,
						      pdata, max_data_bytes,
						      &data_size);

			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("marshall_stream_info failed: %s\n",
					  nt_errstr(status));
				TALLOC_FREE(streams);
				return status;
			}

			TALLOC_FREE(streams);

			*fixed_portion = 32;

			break;
		}
		case SMB_QUERY_COMPRESSION_INFO:
		case SMB_FILE_COMPRESSION_INFORMATION:
			DBG_DEBUG("SMB_FILE_COMPRESSION_INFORMATION\n");
			SOFF_T(pdata,0,file_size);
			SIVAL(pdata,8,0); /* ??? */
			SIVAL(pdata,12,0); /* ??? */
			data_size = 16;
			*fixed_portion = 16;
			break;

		case SMB_FILE_NETWORK_OPEN_INFORMATION:
			DBG_DEBUG("SMB_FILE_NETWORK_OPEN_INFORMATION\n");
			put_long_date_full_timespec(conn->ts_res,pdata,&create_time_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+8,&atime_ts);
			put_long_date_full_timespec(conn->ts_res,pdata+16,&mtime_ts); /* write time */
			put_long_date_full_timespec(conn->ts_res,pdata+24,&ctime_ts); /* change time */
			SOFF_T(pdata,32,allocation_size);
			SOFF_T(pdata,40,file_size);
			SIVAL(pdata,48,mode);
			SIVAL(pdata,52,0); /* ??? */
			data_size = 56;
			*fixed_portion = 56;
			break;

		case SMB_FILE_ATTRIBUTE_TAG_INFORMATION: {
			uint32_t tag = 0;

			DBG_DEBUG("SMB_FILE_ATTRIBUTE_TAG_INFORMATION\n");

			(void)fsctl_get_reparse_tag(fsp, &tag);

			DBG_DEBUG("tag=%"PRIu32"\n", tag);

			SIVAL(pdata, 0, mode);
			SIVAL(pdata, 4, tag);
			data_size = 8;
			*fixed_portion = 8;
			break;
		}
		/*
		 * SMB2 UNIX Extensions.
		 */
		case SMB2_FILE_POSIX_INFORMATION_INTERNAL:
		{
			struct smb3_file_posix_information info = {};
			uint8_t buf[sizeof(info)];
			struct ndr_push ndr = {
				.data = buf,
				.alloc_size = sizeof(buf),
				.fixed_buf_size = true,
			};
			enum ndr_err_code ndr_err;

			if (!conn_using_smb2(conn->sconn)) {
				return NT_STATUS_INVALID_LEVEL;
			}
			if (fsp == NULL) {
				return NT_STATUS_INVALID_HANDLE;
			}
			if (!fsp->fsp_flags.posix_open) {
				return NT_STATUS_INVALID_LEVEL;
			}

			smb3_file_posix_information_init(
				conn, &smb_fname->st, 0, mode, &info);

			ndr_err = ndr_push_smb3_file_posix_information(
				&ndr, NDR_SCALARS|NDR_BUFFERS, &info);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return NT_STATUS_INSUFFICIENT_RESOURCES;
			}

			memcpy(pdata, buf, ndr.offset);
			data_size = ndr.offset;
			break;
		}

		default:
			return NT_STATUS_INVALID_LEVEL;
	}

	*pdata_size = data_size;
	return NT_STATUS_OK;
}

/****************************************************************************
 Set a hard link (called by UNIX extensions and by NT rename with HARD link
 code.
****************************************************************************/

NTSTATUS hardlink_internals(TALLOC_CTX *ctx,
		connection_struct *conn,
		struct smb_request *req,
		bool overwrite_if_exists,
		const struct smb_filename *smb_fname_old,
		struct smb_filename *smb_fname_new)
{
	NTSTATUS status = NT_STATUS_OK;
	int ret;
	bool ok;
	struct smb_filename *parent_fname_old = NULL;
	struct smb_filename *base_name_old = NULL;
	struct smb_filename *parent_fname_new = NULL;
	struct smb_filename *base_name_new = NULL;

	/* source must already exist. */
	if (!VALID_STAT(smb_fname_old->st)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	/* No links from a directory. */
	if (S_ISDIR(smb_fname_old->st.st_ex_mode)) {
		status = NT_STATUS_FILE_IS_A_DIRECTORY;
		goto out;
	}

	/* Setting a hardlink to/from a stream isn't currently supported. */
	ok = is_ntfs_stream_smb_fname(smb_fname_old);
	if (ok) {
		DBG_DEBUG("Old name has streams\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	ok = is_ntfs_stream_smb_fname(smb_fname_new);
	if (ok) {
		DBG_DEBUG("New name has streams\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (smb_fname_old->twrp != 0) {
		status = NT_STATUS_NOT_SAME_DEVICE;
		goto out;
	}

	status = parent_pathref(talloc_tos(),
				conn->cwd_fsp,
				smb_fname_old,
				&parent_fname_old,
				&base_name_old);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = parent_pathref(talloc_tos(),
				conn->cwd_fsp,
				smb_fname_new,
				&parent_fname_new,
				&base_name_new);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (VALID_STAT(smb_fname_new->st)) {
		if (overwrite_if_exists) {
			if (S_ISDIR(smb_fname_new->st.st_ex_mode)) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
				goto out;
			}
			status = unlink_internals(conn,
						req,
						FILE_ATTRIBUTE_NORMAL,
						NULL, /* new_dirfsp */
						smb_fname_new);
			if (!NT_STATUS_IS_OK(status)) {
				goto out;
			}
		} else {
			/* Disallow if newname already exists. */
			status = NT_STATUS_OBJECT_NAME_COLLISION;
			goto out;
		}
	}

	DEBUG(10,("hardlink_internals: doing hard link %s -> %s\n",
		  smb_fname_old->base_name, smb_fname_new->base_name));

	ret = SMB_VFS_LINKAT(conn,
			parent_fname_old->fsp,
			base_name_old,
			parent_fname_new->fsp,
			base_name_new,
			0);

	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		DEBUG(3,("hardlink_internals: Error %s hard link %s -> %s\n",
			 nt_errstr(status), smb_fname_old->base_name,
			 smb_fname_new->base_name));
	}

  out:

	TALLOC_FREE(parent_fname_old);
	TALLOC_FREE(parent_fname_new);
	return status;
}

/****************************************************************************
 Deal with setting the time from any of the setfilepathinfo functions.
 NOTE !!!! The check for FILE_WRITE_ATTRIBUTES access must be done *before*
 calling this function.
****************************************************************************/

NTSTATUS smb_set_file_time(connection_struct *conn,
			   files_struct *fsp,
			   struct smb_filename *smb_fname,
			   struct smb_file_time *ft,
			   bool setting_write_time)
{
	struct files_struct *set_fsp = NULL;
	struct timeval_buf tbuf[4];
	uint32_t action =
		FILE_NOTIFY_CHANGE_LAST_ACCESS
		|FILE_NOTIFY_CHANGE_LAST_WRITE
		|FILE_NOTIFY_CHANGE_CREATION;
	int ret;

	if (!VALID_STAT(smb_fname->st)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (fsp == NULL) {
		/* A symlink */
		return NT_STATUS_OK;
	}

	set_fsp = metadata_fsp(fsp);

	/* get some defaults (no modifications) if any info is zero or -1. */
	if (is_omit_timespec(&ft->create_time)) {
		action &= ~FILE_NOTIFY_CHANGE_CREATION;
	}

	if (is_omit_timespec(&ft->atime)) {
		action &= ~FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}

	if (is_omit_timespec(&ft->mtime)) {
		action &= ~FILE_NOTIFY_CHANGE_LAST_WRITE;
	}

	if (!setting_write_time) {
		/* ft->mtime comes from change time, not write time. */
		action &= ~FILE_NOTIFY_CHANGE_LAST_WRITE;
	}

	/* Ensure the resolution is the correct for
	 * what we can store on this filesystem. */

	round_timespec(conn->ts_res, &ft->create_time);
	round_timespec(conn->ts_res, &ft->ctime);
	round_timespec(conn->ts_res, &ft->atime);
	round_timespec(conn->ts_res, &ft->mtime);

	DBG_DEBUG("actime: %s\n ",
		  timespec_string_buf(&ft->atime, true, &tbuf[0]));
	DBG_DEBUG("modtime: %s\n ",
		  timespec_string_buf(&ft->mtime, true, &tbuf[1]));
	DBG_DEBUG("ctime: %s\n ",
		  timespec_string_buf(&ft->ctime, true, &tbuf[2]));
	DBG_DEBUG("createtime: %s\n ",
		  timespec_string_buf(&ft->create_time, true, &tbuf[3]));

	if (setting_write_time) {
		/*
		 * This was a Windows setfileinfo on an open file.
		 * NT does this a lot. We also need to
		 * set the time here, as it can be read by
		 * FindFirst/FindNext and with the patch for bug #2045
		 * in smbd/fileio.c it ensures that this timestamp is
		 * kept sticky even after a write. We save the request
		 * away and will set it on file close and after a write. JRA.
		 */

		DBG_DEBUG("setting pending modtime to %s\n",
			  timespec_string_buf(&ft->mtime, true, &tbuf[0]));

		set_sticky_write_time_fsp(set_fsp, ft->mtime);
	}

	DBG_DEBUG("setting utimes to modified values.\n");

	ret = file_ntimes(conn, set_fsp, ft);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	notify_fname(conn, NOTIFY_ACTION_MODIFIED, action,
		     smb_fname->base_name);
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with setting the dosmode from any of the setfilepathinfo functions.
 NB. The check for FILE_WRITE_ATTRIBUTES access on this path must have been
 done before calling this function.
****************************************************************************/

static NTSTATUS smb_set_file_dosmode(connection_struct *conn,
				     struct files_struct *fsp,
				     uint32_t dosmode)
{
	struct files_struct *dos_fsp = NULL;
	uint32_t current_dosmode;
	int ret;

	if (!VALID_STAT(fsp->fsp_name->st)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	dos_fsp = metadata_fsp(fsp);

	if (dosmode != 0) {
		if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
			dosmode |= FILE_ATTRIBUTE_DIRECTORY;
		} else {
			dosmode &= ~FILE_ATTRIBUTE_DIRECTORY;
		}
	}

	DBG_DEBUG("dosmode: 0x%" PRIx32 "\n", dosmode);

	/* check the mode isn't different, before changing it */
	if (dosmode == 0) {
		return NT_STATUS_OK;
	}
	current_dosmode = fdos_mode(dos_fsp);
	if (dosmode == current_dosmode) {
		return NT_STATUS_OK;
	}

	DBG_DEBUG("file %s : setting dos mode 0x%" PRIx32 "\n",
		  fsp_str_dbg(dos_fsp), dosmode);

	ret = file_set_dosmode(conn, dos_fsp->fsp_name, dosmode, NULL, false);
	if (ret != 0) {
		DBG_WARNING("file_set_dosmode of %s failed: %s\n",
			    fsp_str_dbg(dos_fsp), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with setting the size from any of the setfilepathinfo functions.
****************************************************************************/

NTSTATUS smb_set_file_size(connection_struct *conn,
			   struct smb_request *req,
			   files_struct *fsp,
			   struct smb_filename *smb_fname,
			   const SMB_STRUCT_STAT *psbuf,
			   off_t size,
			   bool fail_after_createfile)
{
	NTSTATUS status = NT_STATUS_OK;
	files_struct *new_fsp = NULL;

	if (!VALID_STAT(*psbuf)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DBG_INFO("size: %"PRIu64", file_size_stat=%"PRIu64"\n",
		 (uint64_t)size,
		 get_file_size_stat(psbuf));

	if (size == get_file_size_stat(psbuf)) {
		if (fsp == NULL) {
			return NT_STATUS_OK;
		}
		if (!fsp->fsp_flags.modified) {
			return NT_STATUS_OK;
		}
		trigger_write_time_update_immediate(fsp);
		return NT_STATUS_OK;
	}

	DEBUG(10,("smb_set_file_size: file %s : setting new size to %.0f\n",
		  smb_fname_str_dbg(smb_fname), (double)size));

	if (fsp &&
	    !fsp->fsp_flags.is_pathref &&
	    fsp_get_io_fd(fsp) != -1)
	{
		/* Handle based call. */
		status = check_any_access_fsp(fsp, FILE_WRITE_DATA);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (vfs_set_filelen(fsp, size) == -1) {
			return map_nt_error_from_unix(errno);
		}
		trigger_write_time_update_immediate(fsp);
		return NT_STATUS_OK;
	}

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		NULL,					/* dirfsp */
		smb_fname,				/* fname */
		FILE_WRITE_DATA,			/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		0,					/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&new_fsp,				/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		/* NB. We check for open_was_deferred in the caller. */
		return status;
	}

	/* See RAW-SFILEINFO-END-OF-FILE */
	if (fail_after_createfile) {
		close_file_free(req, &new_fsp, NORMAL_CLOSE);
		return NT_STATUS_INVALID_LEVEL;
	}

	if (vfs_set_filelen(new_fsp, size) == -1) {
		status = map_nt_error_from_unix(errno);
		close_file_free(req, &new_fsp, NORMAL_CLOSE);
		return status;
	}

	trigger_write_time_update_immediate(new_fsp);
	close_file_free(req, &new_fsp, NORMAL_CLOSE);
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_INFO_SET_EA.
****************************************************************************/

static NTSTATUS smb_info_set_ea(connection_struct *conn,
				const char *pdata,
				int total_data,
				files_struct *fsp,
				struct smb_filename *smb_fname)
{
	struct ea_list *ea_list = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (total_data < 10) {

		/* OS/2 workplace shell seems to send SET_EA requests of "null"
		   length. They seem to have no effect. Bug #3212. JRA */

		if ((total_data == 4) && (IVAL(pdata,0) == 4)) {
			/* We're done. We only get EA info in this call. */
			return NT_STATUS_OK;
		}

		return NT_STATUS_INVALID_PARAMETER;
	}

	if (IVAL(pdata,0) > total_data) {
		DEBUG(10,("smb_info_set_ea: bad total data size (%u) > %u\n",
			IVAL(pdata,0), (unsigned int)total_data));
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx = talloc_tos();
	ea_list = read_ea_list(ctx, pdata + 4, total_data - 4);
	if (!ea_list) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp == NULL) {
		/*
		 * The only way fsp can be NULL here is if
		 * smb_fname points at a symlink and
		 * and we're in POSIX context.
		 * Ensure this is the case.
		 *
		 * In this case we cannot set the EA.
		 */
		SMB_ASSERT(smb_fname->flags & SMB_FILENAME_POSIX_PATH);
		return NT_STATUS_ACCESS_DENIED;
	}

	status = set_ea(conn, fsp, ea_list);

	return status;
}

/****************************************************************************
 Deal with SMB_FILE_FULL_EA_INFORMATION set.
****************************************************************************/

static NTSTATUS smb_set_file_full_ea_info(connection_struct *conn,
				const char *pdata,
				int total_data,
				files_struct *fsp)
{
	struct ea_list *ea_list = NULL;
	NTSTATUS status;

	if (fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!lp_ea_support(SNUM(conn))) {
		DEBUG(10, ("smb_set_file_full_ea_info - ea_len = %u but "
			"EA's not supported.\n",
			(unsigned int)total_data));
		return NT_STATUS_EAS_NOT_SUPPORTED;
	}

	if (total_data < 10) {
		DEBUG(10, ("smb_set_file_full_ea_info - ea_len = %u "
			"too small.\n",
			(unsigned int)total_data));
		return NT_STATUS_INVALID_PARAMETER;
	}

	ea_list = read_nttrans_ea_list(talloc_tos(),
				pdata,
				total_data);

	if (!ea_list) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = set_ea(conn, fsp, ea_list);

	DEBUG(10, ("smb_set_file_full_ea_info on file %s returned %s\n",
		smb_fname_str_dbg(fsp->fsp_name),
		nt_errstr(status) ));

	return status;
}


/****************************************************************************
 Deal with SMB_SET_FILE_DISPOSITION_INFO.
****************************************************************************/

NTSTATUS smb_set_file_disposition_info(connection_struct *conn,
				       const char *pdata,
				       int total_data,
				       files_struct *fsp,
				       struct smb_filename *smb_fname)
{
	NTSTATUS status = NT_STATUS_OK;
	bool delete_on_close;
	uint32_t dosmode = 0;

	if (total_data < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	delete_on_close = (CVAL(pdata,0) ? True : False);
	dosmode = fdos_mode(fsp);

	DEBUG(10,("smb_set_file_disposition_info: file %s, dosmode = %u, "
		"delete_on_close = %u\n",
		smb_fname_str_dbg(smb_fname),
		(unsigned int)dosmode,
		(unsigned int)delete_on_close ));

	if (delete_on_close) {
		status = can_set_delete_on_close(fsp, dosmode);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* The set is across all open files on this dev/inode pair. */
	if (!set_delete_on_close(fsp, delete_on_close,
				 conn->session_info->security_token,
				 conn->session_info->unix_token)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_FILE_POSITION_INFORMATION.
****************************************************************************/

static NTSTATUS smb_file_position_information(connection_struct *conn,
				const char *pdata,
				int total_data,
				files_struct *fsp)
{
	uint64_t position_information;

	if (total_data < 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp == NULL) {
		/* Ignore on pathname based set. */
		return NT_STATUS_OK;
	}

	position_information = (uint64_t)IVAL(pdata,0);
	position_information |= (((uint64_t)IVAL(pdata,4)) << 32);

	DEBUG(10,("smb_file_position_information: Set file position "
		  "information for file %s to %.0f\n", fsp_str_dbg(fsp),
		  (double)position_information));
	fh_set_position_information(fsp->fh, position_information);
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_FILE_MODE_INFORMATION.
****************************************************************************/

static NTSTATUS smb_file_mode_information(connection_struct *conn,
				const char *pdata,
				int total_data)
{
	uint32_t mode;

	if (total_data < 4) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	mode = IVAL(pdata,0);
	if (mode != 0 && mode != 2 && mode != 4 && mode != 6) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB2_FILE_RENAME_INFORMATION_INTERNAL
****************************************************************************/

static NTSTATUS smb2_file_rename_information(connection_struct *conn,
					    struct smb_request *req,
					    const char *pdata,
					    int total_data,
					    files_struct *fsp,
					    struct smb_filename *smb_fname_src)
{
	bool overwrite;
	uint32_t len;
	char *newname = NULL;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	const char *dst_original_lcomp = NULL;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTSTATUS status = NT_STATUS_OK;
	TALLOC_CTX *ctx = talloc_tos();

	if (!fsp) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (total_data < 20) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	overwrite = (CVAL(pdata,0) ? True : False);
	len = IVAL(pdata,16);

	if (len > (total_data - 20) || (len == 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	(void)srvstr_pull_talloc(ctx,
				 pdata,
				 req->flags2,
				 &newname,
				 &pdata[20],
				 len,
				 STR_TERMINATE);

	if (newname == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* SMB2 rename paths are never DFS. */
	req->flags2 &= ~FLAGS2_DFS_PATHNAMES;
	ucf_flags &= ~UCF_DFS_PATHNAME;

	status = check_path_syntax(newname,
			fsp->fsp_name->flags & SMB_FILENAME_POSIX_PATH);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DBG_DEBUG("got name |%s|\n", newname);

	if (newname[0] == ':') {
		/* Create an smb_fname to call rename_internals_fsp() with. */
		smb_fname_dst = synthetic_smb_fname(talloc_tos(),
					fsp->base_fsp->fsp_name->base_name,
					newname,
					NULL,
					fsp->base_fsp->fsp_name->twrp,
					fsp->base_fsp->fsp_name->flags);
		if (smb_fname_dst == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	} else {
		status = filename_convert_dirfsp(ctx,
						 conn,
						 newname,
						 ucf_flags,
						 0, /* Never a TWRP. */
						 &dst_dirfsp,
						 &smb_fname_dst);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	/*
	 * Set the original last component, since
	 * rename_internals_fsp() requires it.
	 */
	dst_original_lcomp = get_original_lcomp(smb_fname_dst,
					conn,
					newname,
					ucf_flags);
	if (dst_original_lcomp == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	DBG_DEBUG("SMB_FILE_RENAME_INFORMATION (%s) %s -> %s\n",
		  fsp_fnum_dbg(fsp),
		  fsp_str_dbg(fsp),
		  smb_fname_str_dbg(smb_fname_dst));

	status = rename_internals_fsp(conn,
				fsp,
				smb_fname_dst,
				dst_original_lcomp,
				(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM),
				overwrite);

 out:
	TALLOC_FREE(smb_fname_dst);
	return status;
}

static NTSTATUS smb2_file_link_information(connection_struct *conn,
					    struct smb_request *req,
					    const char *pdata,
					    int total_data,
					    files_struct *fsp,
					    struct smb_filename *smb_fname_src)
{
	bool overwrite;
	uint32_t len;
	char *newname = NULL;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	NTSTATUS status = NT_STATUS_OK;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	size_t ret;
	TALLOC_CTX *ctx = talloc_tos();

	if (!fsp) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (total_data < 20) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	overwrite = (CVAL(pdata,0) ? true : false);
	len = IVAL(pdata,16);

	if (len > (total_data - 20) || (len == 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ret = srvstr_pull_talloc(ctx,
				 pdata,
				 req->flags2,
				 &newname,
				 &pdata[20],
                                 len,
				 STR_TERMINATE);

        if (ret == (size_t)-1 || newname == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* SMB2 hardlink paths are never DFS. */
	req->flags2 &= ~FLAGS2_DFS_PATHNAMES;
	ucf_flags &= ~UCF_DFS_PATHNAME;

	status = check_path_syntax(newname,
			fsp->fsp_name->flags & SMB_FILENAME_POSIX_PATH);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DBG_DEBUG("got name |%s|\n", newname);

	status = filename_convert_dirfsp(ctx,
					 conn,
					 newname,
					 ucf_flags,
					 0, /* No TWRP. */
					 &dst_dirfsp,
					 &smb_fname_dst);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (fsp->base_fsp) {
		/* No stream names. */
		return NT_STATUS_NOT_SUPPORTED;
	}

	DBG_DEBUG("SMB_FILE_LINK_INFORMATION (%s) %s -> %s\n",
		  fsp_fnum_dbg(fsp), fsp_str_dbg(fsp),
		  smb_fname_str_dbg(smb_fname_dst));
	status = hardlink_internals(ctx,
				conn,
				req,
				overwrite,
				fsp->fsp_name,
				smb_fname_dst);

	TALLOC_FREE(smb_fname_dst);
	return status;
}

static NTSTATUS smb_file_link_information(connection_struct *conn,
					    struct smb_request *req,
					    const char *pdata,
					    int total_data,
					    files_struct *fsp,
					    struct smb_filename *smb_fname_src)
{
	bool overwrite;
	uint32_t len;
	char *newname = NULL;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	NTSTATUS status = NT_STATUS_OK;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME dst_twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	if (!fsp) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (total_data < 20) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	overwrite = (CVAL(pdata,0) ? true : false);
	len = IVAL(pdata,16);

	if (len > (total_data - 20) || (len == 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (smb_fname_src->flags & SMB_FILENAME_POSIX_PATH) {
		srvstr_get_path_posix(ctx,
				pdata,
				req->flags2,
				&newname,
				&pdata[20],
				len,
				STR_TERMINATE,
				&status);
		ucf_flags |= UCF_POSIX_PATHNAMES;
	} else {
		srvstr_get_path(ctx,
				pdata,
				req->flags2,
				&newname,
				&pdata[20],
				len,
				STR_TERMINATE,
				&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10,("smb_file_link_information: got name |%s|\n",
				newname));

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(newname, &dst_twrp);
	}
	/* hardlink paths are never DFS. */
	ucf_flags &= ~UCF_DFS_PATHNAME;

	status = filename_convert_dirfsp(ctx,
					 conn,
					 newname,
					 ucf_flags,
					 dst_twrp,
					 &dst_dirfsp,
					 &smb_fname_dst);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (fsp->base_fsp) {
		/* No stream names. */
		return NT_STATUS_NOT_SUPPORTED;
	}

	DEBUG(10,("smb_file_link_information: "
		  "SMB_FILE_LINK_INFORMATION (%s) %s -> %s\n",
		  fsp_fnum_dbg(fsp), fsp_str_dbg(fsp),
		  smb_fname_str_dbg(smb_fname_dst)));
	status = hardlink_internals(ctx,
				conn,
				req,
				overwrite,
				fsp->fsp_name,
				smb_fname_dst);

	TALLOC_FREE(smb_fname_dst);
	return status;
}


/****************************************************************************
 Deal with SMB_FILE_RENAME_INFORMATION.
****************************************************************************/

static NTSTATUS smb_file_rename_information(connection_struct *conn,
					    struct smb_request *req,
					    const char *pdata,
					    int total_data,
					    files_struct *fsp,
					    struct smb_filename *smb_fname_src)
{
	bool overwrite;
	uint32_t root_fid;
	uint32_t len;
	char *newname = NULL;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	const char *dst_original_lcomp = NULL;
	NTSTATUS status = NT_STATUS_OK;
	char *p;
	TALLOC_CTX *ctx = talloc_tos();

	if (total_data < 13) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	overwrite = (CVAL(pdata,0) != 0);
	root_fid = IVAL(pdata,4);
	len = IVAL(pdata,8);

	if (len > (total_data - 12) || (len == 0) || (root_fid != 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
				pdata,
				req->flags2,
				&newname,
				&pdata[12],
				len,
				0,
				&status);
	} else {
		srvstr_get_path(ctx,
				pdata,
				req->flags2,
				&newname,
				&pdata[12],
				len,
				0,
				&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10,("smb_file_rename_information: got name |%s|\n",
				newname));

	/* Check the new name has no '/' characters. */
	if (strchr_m(newname, '/')) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp && fsp->base_fsp) {
		/* newname must be a stream name. */
		if (newname[0] != ':') {
			return NT_STATUS_NOT_SUPPORTED;
		}

		/* Create an smb_fname to call rename_internals_fsp() with. */
		smb_fname_dst = synthetic_smb_fname(talloc_tos(),
					fsp->base_fsp->fsp_name->base_name,
					newname,
					NULL,
					fsp->base_fsp->fsp_name->twrp,
					fsp->base_fsp->fsp_name->flags);
		if (smb_fname_dst == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		/*
		 * Get the original last component, since
		 * rename_internals_fsp() requires it.
		 */
		dst_original_lcomp = get_original_lcomp(smb_fname_dst,
					conn,
					newname,
					0);
		if (dst_original_lcomp == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

	} else {
		/*
		 * Build up an smb_fname_dst based on the filename passed in.
		 * We basically just strip off the last component, and put on
		 * the newname instead.
		 */
		char *base_name = NULL;
		uint32_t ucf_flags = ucf_flags_from_smb_request(req);
		NTTIME dst_twrp = 0;

		/* newname must *not* be a stream name. */
		if (newname[0] == ':') {
			return NT_STATUS_NOT_SUPPORTED;
		}

		/*
		 * Strip off the last component (filename) of the path passed
		 * in.
		 */
		base_name = talloc_strdup(ctx, smb_fname_src->base_name);
		if (!base_name) {
			return NT_STATUS_NO_MEMORY;
		}
		p = strrchr_m(base_name, '/');
		if (p) {
			p[1] = '\0';
		} else {
			base_name = talloc_strdup(ctx, "");
			if (!base_name) {
				return NT_STATUS_NO_MEMORY;
			}
		}
		/* Append the new name. */
		base_name = talloc_asprintf_append(base_name,
				"%s",
				newname);
		if (!base_name) {
			return NT_STATUS_NO_MEMORY;
		}

		if (ucf_flags & UCF_GMT_PATHNAME) {
			extract_snapshot_token(base_name, &dst_twrp);
		}

		/* The newname is *not* a DFS path. */
		ucf_flags &= ~UCF_DFS_PATHNAME;

		status = filename_convert_dirfsp(ctx,
					 conn,
					 base_name,
					 ucf_flags,
					 dst_twrp,
					 &dst_dirfsp,
					 &smb_fname_dst);

		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		dst_original_lcomp = get_original_lcomp(smb_fname_dst,
					conn,
					newname,
					ucf_flags);
		if (dst_original_lcomp == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if (fsp != NULL && fsp->fsp_flags.is_fsa) {
		DEBUG(10,("smb_file_rename_information: "
			  "SMB_FILE_RENAME_INFORMATION (%s) %s -> %s\n",
			  fsp_fnum_dbg(fsp), fsp_str_dbg(fsp),
			  smb_fname_str_dbg(smb_fname_dst)));
		status = rename_internals_fsp(conn,
					fsp,
					smb_fname_dst,
					dst_original_lcomp,
					0,
					overwrite);
	} else {
		DEBUG(10,("smb_file_rename_information: "
			  "SMB_FILE_RENAME_INFORMATION %s -> %s\n",
			  smb_fname_str_dbg(smb_fname_src),
			  smb_fname_str_dbg(smb_fname_dst)));
		status = rename_internals(ctx,
					conn,
					req,
					NULL, /* src_dirfsp */
					smb_fname_src,
					smb_fname_dst,
					dst_original_lcomp,
					0,
					overwrite,
					FILE_WRITE_ATTRIBUTES);
	}
 out:
	TALLOC_FREE(smb_fname_dst);
	return status;
}

/****************************************************************************
 Deal with SMB_SET_FILE_BASIC_INFO.
****************************************************************************/

static NTSTATUS smb_set_file_basic_info(connection_struct *conn,
					const char *pdata,
					int total_data,
					files_struct *fsp,
					struct smb_filename *smb_fname)
{
	/* Patch to do this correctly from Paul Eggert <eggert@twinsun.com>. */
	struct smb_file_time ft;
	uint32_t dosmode = 0;
	NTSTATUS status = NT_STATUS_OK;

	init_smb_file_time(&ft);

	if (total_data < 36) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_ATTRIBUTES);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Set the attributes */
	dosmode = IVAL(pdata,32);
	status = smb_set_file_dosmode(conn, fsp, dosmode);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* create time */
	ft.create_time = pull_long_date_full_timespec(pdata);

	/* access time */
	ft.atime = pull_long_date_full_timespec(pdata+8);

	/* write time. */
	ft.mtime = pull_long_date_full_timespec(pdata+16);

	/* change time. */
	ft.ctime = pull_long_date_full_timespec(pdata+24);

	DEBUG(10, ("smb_set_file_basic_info: file %s\n",
		   smb_fname_str_dbg(smb_fname)));

	status = smb_set_file_time(conn, fsp, smb_fname, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (fsp->fsp_flags.modified) {
		trigger_write_time_update_immediate(fsp);
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_INFO_STANDARD.
****************************************************************************/

static NTSTATUS smb_set_info_standard(connection_struct *conn,
					const char *pdata,
					int total_data,
					files_struct *fsp,
					struct smb_filename *smb_fname)
{
	NTSTATUS status;
	struct smb_file_time ft;

	init_smb_file_time(&ft);

	if (total_data < 12) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* create time */
	ft.create_time = time_t_to_full_timespec(srv_make_unix_date2(pdata));
	/* access time */
	ft.atime = time_t_to_full_timespec(srv_make_unix_date2(pdata+4));
	/* write time */
	ft.mtime = time_t_to_full_timespec(srv_make_unix_date2(pdata+8));

	DEBUG(10,("smb_set_info_standard: file %s\n",
		smb_fname_str_dbg(smb_fname)));

	status = check_any_access_fsp(fsp, FILE_WRITE_ATTRIBUTES);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smb_set_file_time(conn, fsp, smb_fname, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (fsp->fsp_flags.modified) {
		trigger_write_time_update_immediate(fsp);
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_SET_FILE_ALLOCATION_INFO.
****************************************************************************/

static NTSTATUS smb_set_file_allocation_info(connection_struct *conn,
					     struct smb_request *req,
					const char *pdata,
					int total_data,
					files_struct *fsp,
					struct smb_filename *smb_fname)
{
	uint64_t allocation_size = 0;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *new_fsp = NULL;

	if (!VALID_STAT(smb_fname->st)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (total_data < 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	allocation_size = (uint64_t)IVAL(pdata,0);
	allocation_size |= (((uint64_t)IVAL(pdata,4)) << 32);
	DEBUG(10,("smb_set_file_allocation_info: Set file allocation info for "
		  "file %s to %.0f\n", smb_fname_str_dbg(smb_fname),
		  (double)allocation_size));

	if (allocation_size) {
		allocation_size = smb_roundup(conn, allocation_size);
	}

	DEBUG(10,("smb_set_file_allocation_info: file %s : setting new "
		  "allocation size to %.0f\n", smb_fname_str_dbg(smb_fname),
		  (double)allocation_size));

	if (fsp &&
	    !fsp->fsp_flags.is_pathref &&
	    fsp_get_io_fd(fsp) != -1)
	{
		/* Open file handle. */
		status = check_any_access_fsp(fsp, FILE_WRITE_DATA);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* Only change if needed. */
		if (allocation_size != get_file_size_stat(&smb_fname->st)) {
			if (vfs_allocate_file_space(fsp, allocation_size) == -1) {
				return map_nt_error_from_unix(errno);
			}
		}
		/* But always update the time. */
		/*
		 * This is equivalent to a write. Ensure it's seen immediately
		 * if there are no pending writes.
		 */
		trigger_write_time_update_immediate(fsp);
		return NT_STATUS_OK;
	}

	/* Pathname or stat or directory file. */
	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		NULL,					/* dirfsp */
		smb_fname,				/* fname */
		FILE_WRITE_DATA,			/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		0,					/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&new_fsp,				/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		/* NB. We check for open_was_deferred in the caller. */
		return status;
	}

	/* Only change if needed. */
	if (allocation_size != get_file_size_stat(&smb_fname->st)) {
		if (vfs_allocate_file_space(new_fsp, allocation_size) == -1) {
			status = map_nt_error_from_unix(errno);
			close_file_free(req, &new_fsp, NORMAL_CLOSE);
			return status;
		}
	}

	/* Changing the allocation size should set the last mod time. */
	/*
	 * This is equivalent to a write. Ensure it's seen immediately
	 * if there are no pending writes.
	 */
	trigger_write_time_update_immediate(new_fsp);
	close_file_free(req, &new_fsp, NORMAL_CLOSE);
	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_SET_FILE_END_OF_FILE_INFO.
****************************************************************************/

static NTSTATUS smb_set_file_end_of_file_info(connection_struct *conn,
					      struct smb_request *req,
					const char *pdata,
					int total_data,
					files_struct *fsp,
					struct smb_filename *smb_fname,
					bool fail_after_createfile)
{
	off_t size;

	if (total_data < 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	size = IVAL(pdata,0);
	size |= (((off_t)IVAL(pdata,4)) << 32);
	DEBUG(10,("smb_set_file_end_of_file_info: Set end of file info for "
		  "file %s to %.0f\n", smb_fname_str_dbg(smb_fname),
		  (double)size));

	return smb_set_file_size(conn, req,
				fsp,
				smb_fname,
				&smb_fname->st,
				size,
				fail_after_createfile);
}

NTSTATUS smbd_do_setfilepathinfo(connection_struct *conn,
				struct smb_request *req,
				TALLOC_CTX *mem_ctx,
				uint16_t info_level,
				files_struct *fsp,
				struct smb_filename *smb_fname,
				char **ppdata, int total_data,
				int *ret_data_size)
{
	char *pdata = *ppdata;
	NTSTATUS status = NT_STATUS_OK;
	int data_return_size = 0;

	*ret_data_size = 0;

	DEBUG(3,("smbd_do_setfilepathinfo: %s (%s) info_level=%d "
		 "totdata=%d\n", smb_fname_str_dbg(smb_fname),
		 fsp_fnum_dbg(fsp),
		 info_level, total_data));

	SMB_ASSERT(fsp != NULL);

	switch (info_level) {

		case SMB_INFO_STANDARD:
		{
			status = smb_set_info_standard(conn,
					pdata,
					total_data,
					fsp,
					smb_fname);
			break;
		}

		case SMB_INFO_SET_EA:
		{
			status = smb_info_set_ea(conn,
						pdata,
						total_data,
						fsp,
						smb_fname);
			break;
		}

		case SMB_SET_FILE_BASIC_INFO:
		case SMB_FILE_BASIC_INFORMATION:
		{
			status = smb_set_file_basic_info(conn,
							pdata,
							total_data,
							fsp,
							smb_fname);
			break;
		}

		case SMB_FILE_ALLOCATION_INFORMATION:
		case SMB_SET_FILE_ALLOCATION_INFO:
		{
			status = smb_set_file_allocation_info(conn, req,
								pdata,
								total_data,
								fsp,
								smb_fname);
			break;
		}

		case SMB_FILE_END_OF_FILE_INFORMATION:
		case SMB_SET_FILE_END_OF_FILE_INFO:
		{
			/*
			 * XP/Win7 both fail after the createfile with
			 * SMB_SET_FILE_END_OF_FILE_INFO but not
			 * SMB_FILE_END_OF_FILE_INFORMATION (pass-through).
			 * The level is known here, so pass it down
			 * appropriately.
			 */
			bool should_fail =
			    (info_level == SMB_SET_FILE_END_OF_FILE_INFO);

			status = smb_set_file_end_of_file_info(conn, req,
								pdata,
								total_data,
								fsp,
								smb_fname,
								should_fail);
			break;
		}

		case SMB_FILE_DISPOSITION_INFORMATION:
		case SMB_SET_FILE_DISPOSITION_INFO: /* Set delete on close for open file. */
		{
			status = smb_set_file_disposition_info(conn,
						pdata,
						total_data,
						fsp,
						smb_fname);
			break;
		}

		case SMB_FILE_POSITION_INFORMATION:
		{
			status = smb_file_position_information(conn,
						pdata,
						total_data,
						fsp);
			break;
		}

		case SMB_FILE_FULL_EA_INFORMATION:
		{
			status = smb_set_file_full_ea_info(conn,
						pdata,
						total_data,
						fsp);
			break;
		}

		/* From tridge Samba4 :
		 * MODE_INFORMATION in setfileinfo (I have no
		 * idea what "mode information" on a file is - it takes a value of 0,
		 * 2, 4 or 6. What could it be?).
		 */

		case SMB_FILE_MODE_INFORMATION:
		{
			status = smb_file_mode_information(conn,
						pdata,
						total_data);
			break;
		}

		/* [MS-SMB2] 3.3.5.21.1 states we MUST fail with STATUS_NOT_SUPPORTED. */
		case SMB_FILE_VALID_DATA_LENGTH_INFORMATION:
		case SMB_FILE_SHORT_NAME_INFORMATION:
			return NT_STATUS_NOT_SUPPORTED;

		case SMB_FILE_RENAME_INFORMATION:
		{
			status = smb_file_rename_information(conn, req,
							     pdata, total_data,
							     fsp, smb_fname);
			break;
		}

		case SMB2_FILE_RENAME_INFORMATION_INTERNAL:
		{
			/* SMB2 rename information. */
			status = smb2_file_rename_information(conn, req,
							     pdata, total_data,
							     fsp, smb_fname);
			break;
		}

		case SMB_FILE_LINK_INFORMATION:
		{
			if (conn_using_smb2(conn->sconn)) {
				status = smb2_file_link_information(conn,
							req,
							pdata,
							total_data,
							fsp,
							smb_fname);
			} else {
				status = smb_file_link_information(conn,
							req,
							pdata,
							total_data,
							fsp,
							smb_fname);
			}
			break;
		}

		default:
			return NT_STATUS_INVALID_LEVEL;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*ret_data_size = data_return_size;
	return NT_STATUS_OK;
}

static uint32_t generate_volume_serial_number(
			const struct loadparm_substitution *lp_sub,
			int snum)
{
	int serial = lp_volume_serial_number(snum);
	return serial != -1 ? serial:
		str_checksum(lp_servicename(talloc_tos(), lp_sub, snum)) ^
		(str_checksum(get_local_machine_name())<<16);
}
