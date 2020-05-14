/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
 *  Copyright (C) Gerald Carter                2002-2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "printing/nt_printing_tdb.h"
#include "../librpc/gen_ndr/ndr_spoolss.h"
#include "rpc_server/spoolss/srv_spoolss_util.h"
#include "nt_printing.h"
#include "secrets.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"
#include "passdb/machine_sid.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "auth.h"
#include "messages.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "rpc_client/cli_winreg_spoolss.h"

/* Map generic permissions to printer object specific permissions */

const struct generic_mapping printer_generic_mapping = {
	PRINTER_READ,
	PRINTER_WRITE,
	PRINTER_EXECUTE,
	PRINTER_ALL_ACCESS
};

/* Map generic permissions to print server object specific permissions */

const struct generic_mapping printserver_generic_mapping = {
	SERVER_READ,
	SERVER_WRITE,
	SERVER_EXECUTE,
	SERVER_ALL_ACCESS
};

/* Map generic permissions to job object specific permissions */

const struct generic_mapping job_generic_mapping = {
	JOB_READ,
	JOB_WRITE,
	JOB_EXECUTE,
	JOB_ALL_ACCESS
};

static const struct print_architecture_table_node archi_table[]= {

	{"Windows 4.0",          SPL_ARCH_WIN40,	0 },
	{"Windows NT x86",       SPL_ARCH_W32X86,	2 },
	{"Windows NT R4000",     SPL_ARCH_W32MIPS,	2 },
	{"Windows NT Alpha_AXP", SPL_ARCH_W32ALPHA,	2 },
	{"Windows NT PowerPC",   SPL_ARCH_W32PPC,	2 },
	{"Windows IA64",   	 SPL_ARCH_IA64,		3 },
	{"Windows x64",   	 SPL_ARCH_X64,		3 },
	{NULL,                   "",		-1 }
};

static bool print_driver_directories_init(void)
{
	int service, i;
	char *driver_path;
	bool ok;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	const char *dir_list[] = {
		"W32X86/PCC",
		"x64/PCC",
		"color"
	};

	service = lp_servicenumber("print$");
	if (service < 0) {
		/* We don't have a print$ share */
		DEBUG(5, ("No print$ share has been configured.\n"));
		talloc_free(mem_ctx);
		return true;
	}

	driver_path = lp_path(mem_ctx, lp_sub, service);
	if (driver_path == NULL) {
		talloc_free(mem_ctx);
		return false;
	}

	ok = directory_create_or_exist(driver_path, 0755);
	if (!ok) {
		DEBUG(1, ("Failed to create printer driver directory %s\n",
			  driver_path));
		talloc_free(mem_ctx);
		return false;
	}

	for (i = 0; archi_table[i].long_archi != NULL; i++) {
		const char *arch_path;

		arch_path = talloc_asprintf(mem_ctx,
					    "%s/%s",
					    driver_path,
					    archi_table[i].short_archi);
		if (arch_path == NULL) {
			talloc_free(mem_ctx);
			return false;
		}

		ok = directory_create_or_exist(arch_path, 0755);
		if (!ok) {
			DEBUG(1, ("Failed to create printer driver "
				  "architecture directory %s\n",
				  arch_path));
			talloc_free(mem_ctx);
			return false;
		}
	}

	for (i = 0; i < ARRAY_SIZE(dir_list); i++) {
		const char *path;

		path = talloc_asprintf(mem_ctx,
				       "%s/%s",
				       driver_path,
				       dir_list[i]);
		if (path == NULL) {
			talloc_free(mem_ctx);
			return false;
		}

		ok = directory_create_or_exist(path, 0755);
		if (!ok) {
			DEBUG(1, ("Failed to create printer driver "
				  "architecture directory %s\n",
				  path));
			talloc_free(mem_ctx);
			return false;
		}
	}

	driver_path = state_path(talloc_tos(), "DriverStore");
	if (driver_path == NULL) {
		talloc_free(mem_ctx);
		return false;
	}

	ok = directory_create_or_exist(driver_path, 0755);
	if (!ok) {
		DEBUG(1,("failed to create path %s\n", driver_path));
		talloc_free(mem_ctx);
		return false;
	}

	driver_path = state_path(talloc_tos(), "DriverStore/FileRepository");
	if (driver_path == NULL) {
		talloc_free(mem_ctx);
		return false;
	}

	ok = directory_create_or_exist(driver_path, 0755);
	if (!ok) {
		DEBUG(1,("failed to create path %s\n", driver_path));
		talloc_free(mem_ctx);
		return false;
	}

	driver_path = state_path(talloc_tos(), "DriverStore/Temp");
	if (driver_path == NULL) {
		talloc_free(mem_ctx);
		return false;
	}

	ok = directory_create_or_exist(driver_path, 0755);
	if (!ok) {
		DEBUG(1,("failed to create path %s\n", driver_path));
		talloc_free(mem_ctx);
		return false;
	}

	talloc_free(mem_ctx);
	return true;
}

/****************************************************************************
 Forward a MSG_PRINTER_DRVUPGRADE message from another smbd to the
 background lpq updater.
****************************************************************************/

static void forward_drv_upgrade_printer_msg(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	extern pid_t background_lpq_updater_pid;

	if (background_lpq_updater_pid == -1) {
		DEBUG(3,("no background lpq queue updater\n"));
		return;
	}

	messaging_send_buf(msg,
			pid_to_procid(background_lpq_updater_pid),
			MSG_PRINTER_DRVUPGRADE,
			data->data,
			data->length);
}

/****************************************************************************
 Open the NT printing tdbs. Done once before fork().
****************************************************************************/

bool nt_printing_init(struct messaging_context *msg_ctx)
{
	WERROR win_rc;

	if (!print_driver_directories_init()) {
		return false;
	}

	if (!nt_printing_tdb_upgrade()) {
		return false;
	}

	/*
	 * register callback to handle updating printers as new
	 * drivers are installed. Forwards to background lpq updater.
	 */
	messaging_register(msg_ctx, NULL, MSG_PRINTER_DRVUPGRADE,
			forward_drv_upgrade_printer_msg);

	if ( lp_security() == SEC_ADS ) {
		win_rc = check_published_printers(msg_ctx);
		if (!W_ERROR_IS_OK(win_rc))
			DEBUG(0, ("nt_printing_init: error checking published printers: %s\n", win_errstr(win_rc)));
	}

	return true;
}

/*******************************************************************
 Function to allow filename parsing "the old way".
********************************************************************/

static NTSTATUS driver_unix_convert(connection_struct *conn,
				    const char *old_name,
				    struct smb_filename **smb_fname)
{
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	char *name = talloc_strdup(ctx, old_name);

	if (!name) {
		return NT_STATUS_NO_MEMORY;
	}
	unix_format(name);
	name = unix_clean_name(ctx, name);
	if (!name) {
		return NT_STATUS_NO_MEMORY;
	}
	trim_string(name,"/","/");

	status = unix_convert(ctx, conn, name, 0, smb_fname, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Function to do the mapping between the long architecture name and
 the short one.
****************************************************************************/

const char *get_short_archi(const char *long_archi)
{
        int i=-1;

        DEBUG(107,("Getting architecture dependent directory\n"));
        do {
                i++;
        } while ( (archi_table[i].long_archi!=NULL ) &&
                  strcasecmp_m(long_archi, archi_table[i].long_archi) );

        if (archi_table[i].long_archi==NULL) {
                DEBUGADD(10,("Unknown architecture [%s] !\n", long_archi));
                return NULL;
        }

	/* this might be client code - but shouldn't this be an fstrcpy etc? */

        DEBUGADD(108,("index: [%d]\n", i));
        DEBUGADD(108,("long architecture: [%s]\n", archi_table[i].long_archi));
        DEBUGADD(108,("short architecture: [%s]\n", archi_table[i].short_archi));

	return archi_table[i].short_archi;
}

/****************************************************************************
 Read data from fsp on the vfs.
****************************************************************************/

static ssize_t printing_pread_data(files_struct *fsp,
				char *buf,
				off_t *poff,
				size_t byte_count)
{
	size_t total=0;
	off_t in_pos = *poff;

	/* Don't allow integer wrap on read. */
	if (in_pos + byte_count < in_pos) {
		return -1;
	}

	while (total < byte_count) {
		ssize_t ret = read_file(fsp,
					buf + total,
					in_pos,
					byte_count - total);

		if (ret == 0) {
			*poff = in_pos;
			return total;
		}
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				return -1;
			}
		}
		in_pos += ret;
		total += ret;
	}
	*poff = in_pos;
	return (ssize_t)total;
}

/****************************************************************************
 Detect the major and minor version of a PE file.
 Returns:

 1 if file is a PE file and we got version numbers,
 0 if this file is a PE file and we couldn't get the version numbers,
 -1 on error.

 NB. buf is passed into and freed inside this function. This is a
 bad API design, but fixing this is a task for another day.
****************************************************************************/

static int handle_pe_file(files_struct *fsp,
				off_t in_pos,
				char *fname,
				char *buf,
				uint32_t *major,
				uint32_t *minor)
{
	unsigned int i;
	unsigned int num_sections;
	unsigned int section_table_bytes;
	ssize_t byte_count;
	off_t rel_pos;
	int ret = -1;

	/* Just skip over optional header to get to section table */
	rel_pos = SVAL(buf,PE_HEADER_OPTIONAL_HEADER_SIZE)-
		(NE_HEADER_SIZE-PE_HEADER_SIZE);

	if (in_pos + rel_pos < in_pos) {
		/* Integer wrap. */
		goto out;
	}
	in_pos = rel_pos + in_pos;

	/* get the section table */
	num_sections        = SVAL(buf,PE_HEADER_NUMBER_OF_SECTIONS);

	if (num_sections >= (UINT_MAX / PE_HEADER_SECT_HEADER_SIZE)) {
		/* Integer wrap. */
		goto out;
	}

	section_table_bytes = num_sections * PE_HEADER_SECT_HEADER_SIZE;
	if (section_table_bytes == 0) {
		goto out;
	}

	SAFE_FREE(buf);
	buf = (char *)SMB_MALLOC(section_table_bytes);
	if (buf == NULL) {
		DBG_ERR("PE file [%s] section table malloc "
			"failed bytes = %d\n",
			fname,
			section_table_bytes);
		goto out;
	}

	byte_count = printing_pread_data(fsp, buf, &in_pos, section_table_bytes);
	if (byte_count < section_table_bytes) {
		DBG_NOTICE("PE file [%s] Section header too short, "
			"bytes read = %lu\n",
			fname,
			(unsigned long)byte_count);
		goto out;
	}

	/*
	 * Iterate the section table looking for
	 * the resource section ".rsrc"
	 */
	for (i = 0; i < num_sections; i++) {
		int sec_offset = i * PE_HEADER_SECT_HEADER_SIZE;

		if (strcmp(".rsrc",
			&buf[sec_offset+ PE_HEADER_SECT_NAME_OFFSET]) == 0) {
			unsigned int section_pos = IVAL(buf,
					sec_offset+
					PE_HEADER_SECT_PTR_DATA_OFFSET);
			unsigned int section_bytes = IVAL(buf,
					sec_offset+
					PE_HEADER_SECT_SIZE_DATA_OFFSET);

			if (section_bytes == 0) {
				goto out;
			}

			SAFE_FREE(buf);
			buf=(char *)SMB_MALLOC(section_bytes);
			if (buf == NULL) {
				DBG_ERR("PE file [%s] version malloc "
					"failed bytes = %d\n",
					fname,
					section_bytes);
				goto out;
			}

			/*
			 * Read from the start of the .rsrc
			 * section info
			 */
			in_pos = section_pos;

			byte_count = printing_pread_data(fsp,
						buf,
						&in_pos,
						section_bytes);
			if (byte_count < section_bytes) {
				DBG_NOTICE("PE file "
					"[%s] .rsrc section too short, "
					"bytes read = %lu\n",
					 fname,
					(unsigned long)byte_count);
				goto out;
			}

			if (section_bytes < VS_VERSION_INFO_UNICODE_SIZE) {
				goto out;
			}

			for (i=0;
				i< section_bytes - VS_VERSION_INFO_UNICODE_SIZE;
					i++) {
				/*
				 * Scan for 1st 3 unicoded bytes
				 * followed by word aligned magic
				 * value.
				 */
				int mpos;
				bool magic_match = false;

				if (buf[i] == 'V' &&
						buf[i+1] == '\0' &&
						buf[i+2] == 'S') {
					magic_match = true;
				}

				if (magic_match == false) {
					continue;
				}

				/* Align to next long address */
				mpos = (i + sizeof(VS_SIGNATURE)*2 +
					3) & 0xfffffffc;

				if (IVAL(buf,mpos) == VS_MAGIC_VALUE) {
					*major = IVAL(buf,
							mpos+ VS_MAJOR_OFFSET);
					*minor = IVAL(buf,
							mpos+ VS_MINOR_OFFSET);

					DBG_INFO("PE file [%s] Version = "
						"%08x:%08x (%d.%d.%d.%d)\n",
						fname,
						*major,
						*minor,
						(*major>>16)&0xffff,
						*major&0xffff,
						(*minor>>16)&0xffff,
						*minor&0xffff);
					ret = 1;
					goto out;
				}
			}
		}
	}

	/* Version info not found, fall back to origin date/time */
	DBG_DEBUG("PE file [%s] has no version info\n", fname);
	ret = 0;

  out:

	SAFE_FREE(buf);
	return ret;
}

/****************************************************************************
 Detect the major and minor version of an NE file.
 Returns:

 1 if file is an NE file and we got version numbers,
 0 if this file is an NE file and we couldn't get the version numbers,
 -1 on error.

 NB. buf is passed into and freed inside this function. This is a
 bad API design, but fixing this is a task for another day.
****************************************************************************/

static int handle_ne_file(files_struct *fsp,
				off_t in_pos,
				char *fname,
				char *buf,
				uint32_t *major,
				uint32_t *minor)
{
	unsigned int i;
	ssize_t byte_count;
	int ret = -1;

	if (CVAL(buf,NE_HEADER_TARGET_OS_OFFSET) != NE_HEADER_TARGOS_WIN ) {
		DBG_NOTICE("NE file [%s] wrong target OS = 0x%x\n",
			fname,
			CVAL(buf,NE_HEADER_TARGET_OS_OFFSET));
		/*
		 * At this point, we assume the file is in error.
		 * It still could be something else besides a NE file,
		 * but it unlikely at this point.
		 */
		goto out;
	}

	/* Allocate a bit more space to speed up things */
	SAFE_FREE(buf);
	buf=(char *)SMB_MALLOC(VS_NE_BUF_SIZE);
	if (buf == NULL) {
		DBG_ERR("NE file [%s] malloc failed bytes  = %d\n",
			fname,
			PE_HEADER_SIZE);
		goto out;
	}

	/*
	 * This is a HACK! I got tired of trying to sort through the
	 * messy 'NE' file format. If anyone wants to clean this up
	 * please have at it, but this works. 'NE' files will
	 * eventually fade away. JRR
	 */
	byte_count = printing_pread_data(fsp, buf, &in_pos, VS_NE_BUF_SIZE);
	while (byte_count > 0) {
		/*
		 * Cover case that should not occur in a well
		 * formed 'NE' .dll file
		 */
		if (byte_count-VS_VERSION_INFO_SIZE <= 0) {
			break;
		}

		for(i=0; i<byte_count; i++) {
			/*
			 * Fast skip past data that can't
			 * possibly match
			 */
			if (buf[i] != 'V') {
				byte_count = printing_pread_data(fsp,
						buf,
						&in_pos,
						VS_NE_BUF_SIZE);
				continue;
			}

			/*
			 * Potential match data crosses buf boundry,
			 * move it to beginning of buf, and fill the
			 * buf with as much as it will hold.
			 */
			if (i>byte_count-VS_VERSION_INFO_SIZE) {
				ssize_t amount_read;
				ssize_t amount_unused = byte_count-i;

				memmove(buf, &buf[i], amount_unused);
				amount_read = printing_pread_data(fsp,
						&buf[amount_unused],
						&in_pos,
						VS_NE_BUF_SIZE- amount_unused);
				if (amount_read < 0) {
					DBG_ERR("NE file [%s] Read "
						"error, errno=%d\n",
						fname,
						errno);
					goto out;
				}

				if (amount_read + amount_unused <
						amount_read) {
					/* Check for integer wrap. */
					break;
				}

				byte_count = amount_read +
					     amount_unused;
				if (byte_count < VS_VERSION_INFO_SIZE) {
					break;
				}

				i = 0;
			}

			/*
			 * Check that the full signature string and
			 * the magic number that follows exist (not
			 * a perfect solution, but the chances that this
			 * occurs in code is, well, remote. Yes I know
			 * I'm comparing the 'V' twice, as it is
			 * simpler to read the code.
			 */
			if (strcmp(&buf[i], VS_SIGNATURE) == 0) {
				/*
				 * Compute skip alignment to next
				 * long address.
				 */
				off_t cpos = in_pos;
				int skip = -(cpos - (byte_count - i) +
					 sizeof(VS_SIGNATURE)) & 3;
				if (IVAL(buf,
					i+sizeof(VS_SIGNATURE)+skip)
						!= 0xfeef04bd) {
					byte_count = printing_pread_data(fsp,
							buf,
							&in_pos,
							VS_NE_BUF_SIZE);
					continue;
				}

				*major = IVAL(buf,
					i+sizeof(VS_SIGNATURE)+
					skip+VS_MAJOR_OFFSET);
				*minor = IVAL(buf,
					i+sizeof(VS_SIGNATURE)+
					skip+VS_MINOR_OFFSET);
				DBG_INFO("NE file [%s] Version "
					"= %08x:%08x (%d.%d.%d.%d)\n",
					fname,
					*major,
					*minor,
					(*major>>16)&0xffff,
					*major&0xffff,
					(*minor>>16)&0xffff,
					*minor&0xffff);
				ret = 1;
				goto out;
			}
		}
	}

	/* Version info not found, fall back to origin date/time */
	DBG_ERR("NE file [%s] Version info not found\n", fname);
	ret = 0;

  out:

	SAFE_FREE(buf);
	return ret;
}

/****************************************************************************
 Version information in Microsoft files is held in a VS_VERSION_INFO structure.
 There are two case to be covered here: PE (Portable Executable) and NE (New
 Executable) files. Both files support the same INFO structure, but PE files
 store the signature in unicode, and NE files store it as !unicode.
 returns -1 on error, 1 on version info found, and 0 on no version info found.
****************************************************************************/

static int get_file_version(files_struct *fsp,
				char *fname,
				uint32_t *major,
				uint32_t *minor)
{
	char    *buf = NULL;
	ssize_t byte_count;
	off_t in_pos = fsp->fh->pos;

	buf=(char *)SMB_MALLOC(DOS_HEADER_SIZE);
	if (buf == NULL) {
		DBG_ERR("PE file [%s] DOS Header malloc failed bytes = %d\n",
			fname,
			DOS_HEADER_SIZE);
		goto error_exit;
	}

	byte_count = printing_pread_data(fsp, buf, &in_pos, DOS_HEADER_SIZE);
	if (byte_count < DOS_HEADER_SIZE) {
		DBG_NOTICE("File [%s] DOS header too short, bytes read = %lu\n",
			 fname,
			(unsigned long)byte_count);
		goto no_version_info;
	}

	/* Is this really a DOS header? */
	if (SVAL(buf,DOS_HEADER_MAGIC_OFFSET) != DOS_HEADER_MAGIC) {
		DBG_INFO("File [%s] bad DOS magic = 0x%x\n",
			fname,
			SVAL(buf,DOS_HEADER_MAGIC_OFFSET));
		goto no_version_info;
	}

	/*
	 * Skip OEM header (if any) and the
	 * DOS stub to start of Windows header.
	 */
	in_pos = SVAL(buf,DOS_HEADER_LFANEW_OFFSET);

	/* Note: DOS_HEADER_SIZE and NE_HEADER_SIZE are incidentally same */
	byte_count = printing_pread_data(fsp, buf, &in_pos, NE_HEADER_SIZE);
	if (byte_count < NE_HEADER_SIZE) {
		DBG_NOTICE("File [%s] Windows header too short, "
			"bytes read = %lu\n",
			fname,
			(unsigned long)byte_count);
		/*
		 * Assume this isn't an error...
		 * the file just looks sort of like a PE/NE file
		 */
		goto no_version_info;
	}

	/*
	 * The header may be a PE (Portable Executable)
	 * or an NE (New Executable).
	 */
	if (IVAL(buf,PE_HEADER_SIGNATURE_OFFSET) == PE_HEADER_SIGNATURE) {
		return handle_pe_file(fsp,
					in_pos,
					fname,
					buf,
					major,
					minor);
	} else if (SVAL(buf,NE_HEADER_SIGNATURE_OFFSET) ==
			NE_HEADER_SIGNATURE) {
		return handle_ne_file(fsp,
					in_pos,
					fname,
					buf,
					major,
					minor);
	} else {
		/*
		 * Assume this isn't an error... the file just
		 * looks sort of like a PE/NE file.
		 */
		DBG_NOTICE("File [%s] unknown file format, signature = 0x%x\n",
			fname,
			IVAL(buf,PE_HEADER_SIGNATURE_OFFSET));
		/* Fallthrough into no_version_info: */
	}

	no_version_info:
		SAFE_FREE(buf);
		return 0;

	error_exit:
		SAFE_FREE(buf);
		return -1;
}

/****************************************************************************
Drivers for Microsoft systems contain multiple files. Often, multiple drivers
share one or more files. During the MS installation process files are checked
to insure that only a newer version of a shared file is installed over an
older version. There are several possibilities for this comparison. If there
is no previous version, the new one is newer (obviously). If either file is
missing the version info structure, compare the creation date (on Unix use
the modification date). Otherwise chose the numerically larger version number.
****************************************************************************/

static int file_version_is_newer(connection_struct *conn, fstring new_file, fstring old_file)
{
	bool use_version = true;

	uint32_t new_major;
	uint32_t new_minor;
	time_t new_create_time;

	uint32_t old_major;
	uint32_t old_minor;
	time_t old_create_time;

	struct smb_filename *smb_fname = NULL;
	files_struct    *fsp = NULL;
	SMB_STRUCT_STAT st;

	NTSTATUS status;
	int ret;

	SET_STAT_INVALID(st);
	new_create_time = (time_t)0;
	old_create_time = (time_t)0;

	/* Get file version info (if available) for previous file (if it exists) */
	status = driver_unix_convert(conn, old_file, &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		goto error_exit;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		&conn->cwd_fsp,				/* dirfsp */
		smb_fname,				/* fname */
		FILE_GENERIC_READ,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);                            /* create context */

	if (!NT_STATUS_IS_OK(status)) {
		/* Old file not found, so by definition new file is in fact newer */
		DEBUG(10,("file_version_is_newer: Can't open old file [%s], "
			  "errno = %d\n", smb_fname_str_dbg(smb_fname),
			  errno));
		ret = 1;
		goto done;

	} else {
		ret = get_file_version(fsp, old_file, &old_major, &old_minor);
		if (ret == -1) {
			goto error_exit;
		}

		if (!ret) {
			DEBUG(6,("file_version_is_newer: Version info not found [%s], use mod time\n",
					 old_file));
			use_version = false;
			if (SMB_VFS_FSTAT(fsp, &st) == -1) {
				 goto error_exit;
			}
			old_create_time = convert_timespec_to_time_t(st.st_ex_mtime);
			DEBUGADD(6,("file_version_is_newer: mod time = %ld sec\n",
				(long)old_create_time));
		}
	}
	close_file(NULL, fsp, NORMAL_CLOSE);
	fsp = NULL;

	/* Get file version info (if available) for new file */
	status = driver_unix_convert(conn, new_file, &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		goto error_exit;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		&conn->cwd_fsp,				/* dirfsp */
		smb_fname,				/* fname */
		FILE_GENERIC_READ,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		/* New file not found, this shouldn't occur if the caller did its job */
		DEBUG(3,("file_version_is_newer: Can't open new file [%s], "
			 "errno = %d\n", smb_fname_str_dbg(smb_fname), errno));
		goto error_exit;

	} else {
		ret = get_file_version(fsp, new_file, &new_major, &new_minor);
		if (ret == -1) {
			goto error_exit;
		}

		if (!ret) {
			DEBUG(6,("file_version_is_newer: Version info not found [%s], use mod time\n",
					 new_file));
			use_version = false;
			if (SMB_VFS_FSTAT(fsp, &st) == -1) {
				goto error_exit;
			}
			new_create_time = convert_timespec_to_time_t(st.st_ex_mtime);
			DEBUGADD(6,("file_version_is_newer: mod time = %ld sec\n",
				(long)new_create_time));
		}
	}
	close_file(NULL, fsp, NORMAL_CLOSE);
	fsp = NULL;

	if (use_version && (new_major != old_major || new_minor != old_minor)) {
		/* Compare versions and choose the larger version number */
		if (new_major > old_major ||
			(new_major == old_major && new_minor > old_minor)) {

			DEBUG(6,("file_version_is_newer: Replacing [%s] with [%s]\n", old_file, new_file));
			ret = 1;
			goto done;
		}
		else {
			DEBUG(6,("file_version_is_newer: Leaving [%s] unchanged\n", old_file));
			ret = 0;
			goto done;
		}

	} else {
		/* Compare modification time/dates and choose the newest time/date */
		if (new_create_time > old_create_time) {
			DEBUG(6,("file_version_is_newer: Replacing [%s] with [%s]\n", old_file, new_file));
			ret = 1;
			goto done;
		}
		else {
			DEBUG(6,("file_version_is_newer: Leaving [%s] unchanged\n", old_file));
			ret = 0;
			goto done;
		}
	}

 error_exit:
	if(fsp)
		close_file(NULL, fsp, NORMAL_CLOSE);
	ret = -1;
 done:
	TALLOC_FREE(smb_fname);
	return ret;
}

/****************************************************************************
Determine the correct cVersion associated with an architecture and driver
****************************************************************************/
static uint32_t get_correct_cversion(const struct auth_session_info *session_info,
				   const char *architecture,
				   const char *driverpath_in,
				   const char *driver_directory,
				   WERROR *perr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int cversion = -1;
	NTSTATUS          nt_status;
	struct smb_filename *smb_fname = NULL;
	files_struct      *fsp = NULL;
	struct conn_struct_tos *c = NULL;
	connection_struct *conn = NULL;
	char *printdollar = NULL;
	char *printdollar_path = NULL;
	char *working_dir = NULL;
	int printdollar_snum;

	*perr = WERR_INVALID_PARAMETER;

	/* If architecture is Windows 95/98/ME, the version is always 0. */
	if (strcmp(architecture, SPL_ARCH_WIN40) == 0) {
		DEBUG(10,("get_correct_cversion: Driver is Win9x, cversion = 0\n"));
		*perr = WERR_OK;
		TALLOC_FREE(frame);
		return 0;
	}

	/* If architecture is Windows x64, the version is always 3. */
	if (strcmp(architecture, SPL_ARCH_X64) == 0) {
		DEBUG(10,("get_correct_cversion: Driver is x64, cversion = 3\n"));
		*perr = WERR_OK;
		TALLOC_FREE(frame);
		return 3;
	}

	printdollar_snum = find_service(frame, "print$", &printdollar);
	if (!printdollar) {
		*perr = WERR_NOT_ENOUGH_MEMORY;
		TALLOC_FREE(frame);
		return -1;
	}
	if (printdollar_snum == -1) {
		*perr = WERR_BAD_NET_NAME;
		TALLOC_FREE(frame);
		return -1;
	}

	printdollar_path = lp_path(frame, lp_sub, printdollar_snum);
	if (printdollar_path == NULL) {
		*perr = WERR_NOT_ENOUGH_MEMORY;
		TALLOC_FREE(frame);
		return -1;
	}

	working_dir = talloc_asprintf(frame,
				      "%s/%s",
				      printdollar_path,
				      architecture);
	/*
	 * If the driver has been uploaded into a temorpary driver
	 * directory, switch to the driver directory.
	 */
	if (driver_directory != NULL) {
		working_dir = talloc_asprintf(frame, "%s/%s/%s",
					      printdollar_path,
					      architecture,
					      driver_directory);
	}

	nt_status = create_conn_struct_tos_cwd(global_messaging_context(),
					       printdollar_snum,
					       working_dir,
					       session_info,
					       &c);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("get_correct_cversion: create_conn_struct "
			 "returned %s\n", nt_errstr(nt_status)));
		*perr = ntstatus_to_werror(nt_status);
		TALLOC_FREE(frame);
		return -1;
	}
	conn = c->conn;

	nt_status = set_conn_force_user_group(conn, printdollar_snum);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("failed set force user / group\n"));
		*perr = ntstatus_to_werror(nt_status);
		goto error_free_conn;
	}

	if (!become_user_without_service_by_session(conn, session_info)) {
		DEBUG(0, ("failed to become user\n"));
		*perr = WERR_ACCESS_DENIED;
		goto error_free_conn;
	}

	/*
	 * We switch to the directory where the driver files are located,
	 * so only work on the file names
	 */
	nt_status = driver_unix_convert(conn, driverpath_in, &smb_fname);
	if (!NT_STATUS_IS_OK(nt_status)) {
		*perr = ntstatus_to_werror(nt_status);
		goto error_exit;
	}

	nt_status = vfs_file_exist(conn, smb_fname);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("get_correct_cversion: vfs_file_exist failed\n"));
		*perr = WERR_FILE_NOT_FOUND;
		goto error_exit;
	}

	nt_status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		&conn->cwd_fsp,				/* dirfsp */
		smb_fname,				/* fname */
		FILE_GENERIC_READ,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* private_flags */
		0,					/* allocation_size */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("get_correct_cversion: Can't open file [%s], errno = "
			 "%d\n", smb_fname_str_dbg(smb_fname), errno));
		*perr = WERR_ACCESS_DENIED;
		goto error_exit;
	} else {
		uint32_t major;
		uint32_t minor;
		int    ret;

		ret = get_file_version(fsp, smb_fname->base_name, &major, &minor);
		if (ret == -1) {
			*perr = WERR_INVALID_PARAMETER;
			goto error_exit;
		} else if (!ret) {
			DEBUG(6,("get_correct_cversion: Version info not "
				 "found [%s]\n",
				 smb_fname_str_dbg(smb_fname)));
			*perr = WERR_INVALID_PARAMETER;
			goto error_exit;
		}

		/*
		 * This is a Microsoft'ism. See references in MSDN to VER_FILEVERSION
		 * for more details. Version in this case is not just the version of the
		 * file, but the version in the sense of kernal mode (2) vs. user mode
		 * (3) drivers. Other bits of the version fields are the version info.
		 * JRR 010716
		*/
		cversion = major & 0x0000ffff;
		switch (cversion) {
			case 2: /* WinNT drivers */
			case 3: /* Win2K drivers */
				break;

			default:
				DEBUG(6,("get_correct_cversion: cversion "
					 "invalid [%s]  cversion = %d\n",
					 smb_fname_str_dbg(smb_fname),
					 cversion));
				goto error_exit;
		}

		DEBUG(10,("get_correct_cversion: Version info found [%s] major"
			  " = 0x%x  minor = 0x%x\n",
			  smb_fname_str_dbg(smb_fname), major, minor));
	}

	DEBUG(10,("get_correct_cversion: Driver file [%s] cversion = %d\n",
		  smb_fname_str_dbg(smb_fname), cversion));
	*perr = WERR_OK;

 error_exit:
	unbecome_user_without_service();
 error_free_conn:
	if (fsp != NULL) {
		close_file(NULL, fsp, NORMAL_CLOSE);
	}
	if (!W_ERROR_IS_OK(*perr)) {
		cversion = -1;
	}

	TALLOC_FREE(frame);
	return cversion;
}

/****************************************************************************
****************************************************************************/

#define strip_driver_path(_mem_ctx, _element) do { \
	if (_element && ((_p = strrchr((_element), '\\')) != NULL)) { \
		(_element) = talloc_asprintf((_mem_ctx), "%s", _p+1); \
		W_ERROR_HAVE_NO_MEMORY((_element)); \
	} \
} while (0);

static WERROR clean_up_driver_struct_level(TALLOC_CTX *mem_ctx,
					   const struct auth_session_info *session_info,
					   const char *architecture,
					   const char **driver_path,
					   const char **data_file,
					   const char **config_file,
					   const char **help_file,
					   struct spoolss_StringArray *dependent_files,
					   enum spoolss_DriverOSVersion *version,
					   uint32_t flags,
					   const char **driver_directory)
{
	const char *short_architecture;
	int i;
	WERROR err;
	char *_p;

	if (!*driver_path || !*data_file) {
		return WERR_INVALID_PARAMETER;
	}

	if (!strequal(architecture, SPOOLSS_ARCHITECTURE_4_0) && !*config_file) {
		return WERR_INVALID_PARAMETER;
	}

	if (flags & APD_COPY_FROM_DIRECTORY) {
		char *path;
		char *q;

		/*
		 * driver_path is set to:
		 *
		 * \\PRINTSRV\print$\x64\{279245b0-a8bd-4431-bf6f-baee92ac15c0}\pscript5.dll
		 */
		path = talloc_strdup(mem_ctx, *driver_path);
		if (path == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		/* Remove pscript5.dll */
		q = strrchr_m(path, '\\');
		if (q == NULL) {
			return WERR_INVALID_PARAMETER;
		}
		*q = '\0';

		/* Get \{279245b0-a8bd-4431-bf6f-baee92ac15c0} */
		q = strrchr_m(path, '\\');
		if (q == NULL) {
			return WERR_INVALID_PARAMETER;
		}

		/*
		 * Set driver_directory to:
		 *
		 * {279245b0-a8bd-4431-bf6f-baee92ac15c0}
		 *
		 * This is the directory where all the files have been uploaded
		 */
		*driver_directory = q + 1;
	}

	/* clean up the driver name.
	 * we can get .\driver.dll
	 * or worse c:\windows\system\driver.dll !
	 */
	/* using an intermediate string to not have overlaping memcpy()'s */

	strip_driver_path(mem_ctx, *driver_path);
	strip_driver_path(mem_ctx, *data_file);
	if (*config_file) {
		strip_driver_path(mem_ctx, *config_file);
	}
	if (help_file) {
		strip_driver_path(mem_ctx, *help_file);
	}

	if (dependent_files && dependent_files->string) {
		for (i=0; dependent_files->string[i]; i++) {
			strip_driver_path(mem_ctx, dependent_files->string[i]);
		}
	}

	short_architecture = get_short_archi(architecture);
	if (!short_architecture) {
		return WERR_UNKNOWN_PRINTER_DRIVER;
	}

	/* jfm:7/16/2000 the client always sends the cversion=0.
	 * The server should check which version the driver is by reading
	 * the PE header of driver->driverpath.
	 *
	 * For Windows 95/98 the version is 0 (so the value sent is correct)
	 * For Windows NT (the architecture doesn't matter)
	 *	NT 3.1: cversion=0
	 *	NT 3.5/3.51: cversion=1
	 *	NT 4: cversion=2
	 *	NT2K: cversion=3
	 */

	*version = get_correct_cversion(session_info,
					short_architecture,
					*driver_path,
					*driver_directory,
					&err);
	if (*version == -1) {
		return err;
	}

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR clean_up_driver_struct(TALLOC_CTX *mem_ctx,
			      const struct auth_session_info *session_info,
			      const struct spoolss_AddDriverInfoCtr *r,
			      uint32_t flags,
			      const char **driver_directory)
{
	switch (r->level) {
	case 3:
		return clean_up_driver_struct_level(mem_ctx, session_info,
						    r->info.info3->architecture,
						    &r->info.info3->driver_path,
						    &r->info.info3->data_file,
						    &r->info.info3->config_file,
						    &r->info.info3->help_file,
						    r->info.info3->dependent_files,
						    &r->info.info3->version,
						    flags,
						    driver_directory);
	case 6:
		return clean_up_driver_struct_level(mem_ctx, session_info,
						    r->info.info6->architecture,
						    &r->info.info6->driver_path,
						    &r->info.info6->data_file,
						    &r->info.info6->config_file,
						    &r->info.info6->help_file,
						    r->info.info6->dependent_files,
						    &r->info.info6->version,
						    flags,
						    driver_directory);
	case 8:
		return clean_up_driver_struct_level(mem_ctx, session_info,
						    r->info.info8->architecture,
						    &r->info.info8->driver_path,
						    &r->info.info8->data_file,
						    &r->info.info8->config_file,
						    &r->info.info8->help_file,
						    r->info.info8->dependent_files,
						    &r->info.info8->version,
						    flags,
						    driver_directory);
	default:
		return WERR_NOT_SUPPORTED;
	}
}

/****************************************************************************
 This function sucks and should be replaced. JRA.
****************************************************************************/

static void convert_level_6_to_level3(struct spoolss_AddDriverInfo3 *dst,
				      const struct spoolss_AddDriverInfo6 *src)
{
	dst->version		= src->version;

	dst->driver_name	= src->driver_name;
	dst->architecture 	= src->architecture;
	dst->driver_path	= src->driver_path;
	dst->data_file		= src->data_file;
	dst->config_file	= src->config_file;
	dst->help_file		= src->help_file;
	dst->monitor_name	= src->monitor_name;
	dst->default_datatype	= src->default_datatype;
	dst->_ndr_size_dependent_files = src->_ndr_size_dependent_files;
	dst->dependent_files	= src->dependent_files;
}

static void convert_level_8_to_level3(struct spoolss_AddDriverInfo3 *dst,
				      const struct spoolss_AddDriverInfo8 *src)
{
	dst->version		= src->version;

	dst->driver_name	= src->driver_name;
	dst->architecture	= src->architecture;
	dst->driver_path	= src->driver_path;
	dst->data_file		= src->data_file;
	dst->config_file	= src->config_file;
	dst->help_file		= src->help_file;
	dst->monitor_name	= src->monitor_name;
	dst->default_datatype	= src->default_datatype;
	dst->_ndr_size_dependent_files = src->_ndr_size_dependent_files;
	dst->dependent_files	= src->dependent_files;
}

/****************************************************************************
****************************************************************************/

static WERROR move_driver_file_to_download_area(TALLOC_CTX *mem_ctx,
						connection_struct *conn,
						const char *driver_file,
						const char *short_architecture,
						uint32_t driver_version,
						uint32_t version,
						const char *driver_directory)
{
	struct smb_filename *smb_fname_old = NULL;
	struct smb_filename *smb_fname_new = NULL;
	char *old_name = NULL;
	char *new_name = NULL;
	NTSTATUS status;
	WERROR ret;

	if (driver_directory != NULL) {
		old_name = talloc_asprintf(mem_ctx,
					   "%s/%s/%s",
					   short_architecture,
					   driver_directory,
					   driver_file);
	} else {
		old_name = talloc_asprintf(mem_ctx,
					   "%s/%s",
					   short_architecture,
					   driver_file);
	}
	if (old_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	new_name = talloc_asprintf(mem_ctx, "%s/%d/%s",
				   short_architecture, driver_version, driver_file);
	if (new_name == NULL) {
		TALLOC_FREE(old_name);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (version != -1 && (version = file_version_is_newer(conn, old_name, new_name)) > 0) {

		status = driver_unix_convert(conn, old_name, &smb_fname_old);
		if (!NT_STATUS_IS_OK(status)) {
			ret = WERR_NOT_ENOUGH_MEMORY;
			goto out;
		}

		/* Setup a synthetic smb_filename struct */
		smb_fname_new = talloc_zero(mem_ctx, struct smb_filename);
		if (!smb_fname_new) {
			ret = WERR_NOT_ENOUGH_MEMORY;
			goto out;
		}

		smb_fname_new->base_name = new_name;

		DEBUG(10,("move_driver_file_to_download_area: copying '%s' to "
			  "'%s'\n", smb_fname_old->base_name,
			  smb_fname_new->base_name));

		status = copy_file(mem_ctx, conn, smb_fname_old, smb_fname_new,
				   OPENX_FILE_EXISTS_TRUNCATE |
				   OPENX_FILE_CREATE_IF_NOT_EXIST,
				   0, false);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("move_driver_file_to_download_area: Unable "
				 "to rename [%s] to [%s]: %s\n",
				 smb_fname_old->base_name, new_name,
				 nt_errstr(status)));
			ret = WERR_APP_INIT_FAILURE;
			goto out;
		}
	}

	ret = WERR_OK;
 out:
	TALLOC_FREE(smb_fname_old);
	TALLOC_FREE(smb_fname_new);
	return ret;
}

WERROR move_driver_to_download_area(const struct auth_session_info *session_info,
				    const struct spoolss_AddDriverInfoCtr *r,
				    const char *driver_directory)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct spoolss_AddDriverInfo3 *driver;
	struct spoolss_AddDriverInfo3 converted_driver;
	const char *short_architecture;
	struct smb_filename *smb_dname = NULL;
	char *new_dir = NULL;
	struct conn_struct_tos *c = NULL;
	connection_struct *conn = NULL;
	NTSTATUS nt_status;
	int i;
	int ver = 0;
	char *printdollar = NULL;
	int printdollar_snum;
	WERROR err = WERR_OK;

	switch (r->level) {
	case 3:
		driver = r->info.info3;
		break;
	case 6:
		convert_level_6_to_level3(&converted_driver, r->info.info6);
		driver = &converted_driver;
		break;
	case 8:
		convert_level_8_to_level3(&converted_driver, r->info.info8);
		driver = &converted_driver;
		break;
	default:
		DEBUG(0,("move_driver_to_download_area: Unknown info level (%u)\n", (unsigned int)r->level));
		TALLOC_FREE(frame);
		return WERR_INVALID_LEVEL;
	}

	short_architecture = get_short_archi(driver->architecture);
	if (!short_architecture) {
		TALLOC_FREE(frame);
		return WERR_UNKNOWN_PRINTER_DRIVER;
	}

	printdollar_snum = find_service(frame, "print$", &printdollar);
	if (!printdollar) {
		TALLOC_FREE(frame);
		return WERR_NOT_ENOUGH_MEMORY;
	}
	if (printdollar_snum == -1) {
		TALLOC_FREE(frame);
		return WERR_BAD_NET_NAME;
	}

	nt_status = create_conn_struct_tos_cwd(global_messaging_context(),
					       printdollar_snum,
					       lp_path(frame, lp_sub, printdollar_snum),
					       session_info,
					       &c);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("move_driver_to_download_area: create_conn_struct "
			 "returned %s\n", nt_errstr(nt_status)));
		err = ntstatus_to_werror(nt_status);
		TALLOC_FREE(frame);
		return err;
	}
	conn = c->conn;

	nt_status = set_conn_force_user_group(conn, printdollar_snum);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("failed set force user / group\n"));
		err = ntstatus_to_werror(nt_status);
		goto err_free_conn;
	}

	if (!become_user_without_service_by_session(conn, session_info)) {
		DEBUG(0, ("failed to become user\n"));
		err = WERR_ACCESS_DENIED;
		goto err_free_conn;
	}

	new_dir = talloc_asprintf(frame,
				"%s/%d",
				short_architecture,
				driver->version);
	if (!new_dir) {
		err = WERR_NOT_ENOUGH_MEMORY;
		goto err_exit;
	}
	nt_status = driver_unix_convert(conn, new_dir, &smb_dname);
	if (!NT_STATUS_IS_OK(nt_status)) {
		err = WERR_NOT_ENOUGH_MEMORY;
		goto err_exit;
	}

	DEBUG(5,("Creating first directory: %s\n", smb_dname->base_name));

	nt_status = create_directory(conn, NULL, smb_dname);
	if (!NT_STATUS_IS_OK(nt_status)
	 && !NT_STATUS_EQUAL(nt_status, NT_STATUS_OBJECT_NAME_COLLISION)) {
		DEBUG(0, ("failed to create driver destination directory: %s\n",
			  nt_errstr(nt_status)));
		err = ntstatus_to_werror(nt_status);
		goto err_exit;
	}

	/* For each driver file, archi\filexxx.yyy, if there is a duplicate file
	 * listed for this driver which has already been moved, skip it (note:
	 * drivers may list the same file name several times. Then check if the
	 * file already exists in archi\version\, if so, check that the version
	 * info (or time stamps if version info is unavailable) is newer (or the
	 * date is later). If it is, move it to archi\version\filexxx.yyy.
	 * Otherwise, delete the file.
	 *
	 * If a file is not moved to archi\version\ because of an error, all the
	 * rest of the 'unmoved' driver files are removed from archi\. If one or
	 * more of the driver's files was already moved to archi\version\, it
	 * potentially leaves the driver in a partially updated state. Version
	 * trauma will most likely occur if an client attempts to use any printer
	 * bound to the driver. Perhaps a rewrite to make sure the moves can be
	 * done is appropriate... later JRR
	 */

	DEBUG(5,("Moving files now !\n"));

	if (driver->driver_path && strlen(driver->driver_path)) {

		err = move_driver_file_to_download_area(frame,
							conn,
							driver->driver_path,
							short_architecture,
							driver->version,
							ver,
							driver_directory);
		if (!W_ERROR_IS_OK(err)) {
			goto err_exit;
		}
	}

	if (driver->data_file && strlen(driver->data_file)) {
		if (!strequal(driver->data_file, driver->driver_path)) {

			err = move_driver_file_to_download_area(frame,
								conn,
								driver->data_file,
								short_architecture,
								driver->version,
								ver,
								driver_directory);
			if (!W_ERROR_IS_OK(err)) {
				goto err_exit;
			}
		}
	}

	if (driver->config_file && strlen(driver->config_file)) {
		if (!strequal(driver->config_file, driver->driver_path) &&
		    !strequal(driver->config_file, driver->data_file)) {

			err = move_driver_file_to_download_area(frame,
								conn,
								driver->config_file,
								short_architecture,
								driver->version,
								ver,
								driver_directory);
			if (!W_ERROR_IS_OK(err)) {
				goto err_exit;
			}
		}
	}

	if (driver->help_file && strlen(driver->help_file)) {
		if (!strequal(driver->help_file, driver->driver_path) &&
		    !strequal(driver->help_file, driver->data_file) &&
		    !strequal(driver->help_file, driver->config_file)) {

			err = move_driver_file_to_download_area(frame,
								conn,
								driver->help_file,
								short_architecture,
								driver->version,
								ver,
								driver_directory);
			if (!W_ERROR_IS_OK(err)) {
				goto err_exit;
			}
		}
	}

	if (driver->dependent_files && driver->dependent_files->string) {
		for (i=0; driver->dependent_files->string[i]; i++) {
			if (!strequal(driver->dependent_files->string[i], driver->driver_path) &&
			    !strequal(driver->dependent_files->string[i], driver->data_file) &&
			    !strequal(driver->dependent_files->string[i], driver->config_file) &&
			    !strequal(driver->dependent_files->string[i], driver->help_file)) {
				int j;
				for (j=0; j < i; j++) {
					if (strequal(driver->dependent_files->string[i], driver->dependent_files->string[j])) {
						goto NextDriver;
					}
				}

				err = move_driver_file_to_download_area(frame,
									conn,
									driver->dependent_files->string[i],
									short_architecture,
									driver->version,
									ver,
									driver_directory);
				if (!W_ERROR_IS_OK(err)) {
					goto err_exit;
				}
			}
		NextDriver: ;
		}
	}

	err = WERR_OK;
 err_exit:
	unbecome_user_without_service();
 err_free_conn:
	TALLOC_FREE(frame);
	return err;
}

/****************************************************************************
  Determine whether or not a particular driver is currently assigned
  to a printer
****************************************************************************/

bool printer_driver_in_use(TALLOC_CTX *mem_ctx,
			   struct dcerpc_binding_handle *b,
			   const struct spoolss_DriverInfo8 *r)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int snum;
	int n_services = lp_numservices();
	bool in_use = false;
	struct spoolss_PrinterInfo2 *pinfo2 = NULL;
	WERROR result;

	if (!r) {
		return false;
	}

	DEBUG(10,("printer_driver_in_use: Beginning search through ntprinters.tdb...\n"));

	/* loop through the printers.tdb and check for the drivername */

	for (snum=0; snum<n_services && !in_use; snum++) {
		if (!lp_snum_ok(snum) || !lp_printable(snum)) {
			continue;
		}

		result = winreg_get_printer(mem_ctx, b,
					    lp_servicename(talloc_tos(), lp_sub, snum),
					    &pinfo2);
		if (!W_ERROR_IS_OK(result)) {
			continue; /* skip */
		}

		if (strequal(r->driver_name, pinfo2->drivername)) {
			in_use = true;
		}

		TALLOC_FREE(pinfo2);
	}

	DEBUG(10,("printer_driver_in_use: Completed search through ntprinters.tdb...\n"));

	if ( in_use ) {
		struct spoolss_DriverInfo8 *driver = NULL;
		WERROR werr;

		DEBUG(5,("printer_driver_in_use: driver \"%s\" is currently in use\n", r->driver_name));

		/* we can still remove the driver if there is one of
		   "Windows NT x86" version 2 or 3 left */

		if (strequal(SPOOLSS_ARCHITECTURE_NT_X86, r->architecture)) {
			if (r->version == 2) {
				werr = winreg_get_driver(mem_ctx, b,
							 r->architecture,
							 r->driver_name,
							 3, &driver);
			} else if (r->version == 3) {
				werr = winreg_get_driver(mem_ctx, b,
							 r->architecture,
							 r->driver_name,
							 2, &driver);
			} else {
				DBG_ERR("Unknown driver version (%d)\n",
					r->version);
				werr = WERR_UNKNOWN_PRINTER_DRIVER;
			}
		} else if (strequal(SPOOLSS_ARCHITECTURE_x64, r->architecture)) {
			werr = winreg_get_driver(mem_ctx, b,
						 SPOOLSS_ARCHITECTURE_NT_X86,
						 r->driver_name,
						 DRIVER_ANY_VERSION,
						 &driver);
		} else {
			DBG_ERR("Unknown driver architecture: %s\n",
				r->architecture);
			werr = WERR_UNKNOWN_PRINTER_DRIVER;
		}

		/* now check the error code */

		if ( W_ERROR_IS_OK(werr) ) {
			/* it's ok to remove the driver, we have other architctures left */
			in_use = false;
			talloc_free(driver);
		}
	}

	/* report that the driver is not in use by default */

	return in_use;
}


/**********************************************************************
 Check to see if a ogiven file is in use by *info
 *********************************************************************/

static bool drv_file_in_use(const char *file, const struct spoolss_DriverInfo8 *info)
{
	int i = 0;

	if ( !info )
		return False;

	/* mz: skip files that are in the list but already deleted */
	if (!file || !file[0]) {
		return false;
	}

	if (strequal(file, info->driver_path))
		return True;

	if (strequal(file, info->data_file))
		return True;

	if (strequal(file, info->config_file))
		return True;

	if (strequal(file, info->help_file))
		return True;

	/* see of there are any dependent files to examine */

	if (!info->dependent_files)
		return False;

	while (info->dependent_files[i] && *info->dependent_files[i]) {
		if (strequal(file, info->dependent_files[i]))
			return True;
		i++;
	}

	return False;

}

/**********************************************************************
 Utility function to remove the dependent file pointed to by the
 input parameter from the list
 *********************************************************************/

static void trim_dependent_file(TALLOC_CTX *mem_ctx, const char **files, int idx)
{

	/* bump everything down a slot */

	while (files && files[idx+1]) {
		files[idx] = talloc_strdup(mem_ctx, files[idx+1]);
		idx++;
	}

	files[idx] = NULL;

	return;
}

/**********************************************************************
 Check if any of the files used by src are also used by drv
 *********************************************************************/

static bool trim_overlap_drv_files(TALLOC_CTX *mem_ctx,
				   struct spoolss_DriverInfo8 *src,
				   const struct spoolss_DriverInfo8 *drv)
{
	bool 	in_use = False;
	int 	i = 0;

	if ( !src || !drv )
		return False;

	/* check each file.  Remove it from the src structure if it overlaps */

	if (drv_file_in_use(src->driver_path, drv)) {
		in_use = True;
		DEBUG(10,("Removing driverfile [%s] from list\n", src->driver_path));
		src->driver_path = talloc_strdup(mem_ctx, "");
		if (!src->driver_path) { return false; }
	}

	if (drv_file_in_use(src->data_file, drv)) {
		in_use = True;
		DEBUG(10,("Removing datafile [%s] from list\n", src->data_file));
		src->data_file = talloc_strdup(mem_ctx, "");
		if (!src->data_file) { return false; }
	}

	if (drv_file_in_use(src->config_file, drv)) {
		in_use = True;
		DEBUG(10,("Removing configfile [%s] from list\n", src->config_file));
		src->config_file = talloc_strdup(mem_ctx, "");
		if (!src->config_file) { return false; }
	}

	if (drv_file_in_use(src->help_file, drv)) {
		in_use = True;
		DEBUG(10,("Removing helpfile [%s] from list\n", src->help_file));
		src->help_file = talloc_strdup(mem_ctx, "");
		if (!src->help_file) { return false; }
	}

	/* are there any dependentfiles to examine? */

	if (!src->dependent_files)
		return in_use;

	while (src->dependent_files[i] && *src->dependent_files[i]) {
		if (drv_file_in_use(src->dependent_files[i], drv)) {
			in_use = True;
			DEBUG(10,("Removing [%s] from dependent file list\n", src->dependent_files[i]));
			trim_dependent_file(mem_ctx, src->dependent_files, i);
		} else
			i++;
	}

	return in_use;
}

/****************************************************************************
  Determine whether or not a particular driver files are currently being
  used by any other driver.

  Return value is True if any files were in use by other drivers
  and False otherwise.

  Upon return, *info has been modified to only contain the driver files
  which are not in use

  Fix from mz:

  This needs to check all drivers to ensure that all files in use
  have been removed from *info, not just the ones in the first
  match.
****************************************************************************/

bool printer_driver_files_in_use(TALLOC_CTX *mem_ctx,
				 struct dcerpc_binding_handle *b,
				 struct spoolss_DriverInfo8 *info)
{
	int 				i;
	uint32_t 				version;
	struct spoolss_DriverInfo8 	*driver;
	bool in_use = false;
	uint32_t num_drivers;
	const char **drivers;
	WERROR result;

	if ( !info )
		return False;

	version = info->version;

	/* loop over all driver versions */

	DEBUG(5,("printer_driver_files_in_use: Beginning search of drivers...\n"));

	/* get the list of drivers */

	result = winreg_get_driver_list(mem_ctx, b,
					info->architecture, version,
					&num_drivers, &drivers);
	if (!W_ERROR_IS_OK(result)) {
		return true;
	}

	DEBUGADD(4, ("we have:[%d] drivers in environment [%s] and version [%d]\n",
		     num_drivers, info->architecture, version));

	/* check each driver for overlap in files */

	for (i = 0; i < num_drivers; i++) {
		DEBUGADD(5,("\tdriver: [%s]\n", drivers[i]));

		driver = NULL;

		result = winreg_get_driver(mem_ctx, b,
					   info->architecture, drivers[i],
					   version, &driver);
		if (!W_ERROR_IS_OK(result)) {
			talloc_free(drivers);
			return True;
		}

		/* check if d2 uses any files from d1 */
		/* only if this is a different driver than the one being deleted */

		if (!strequal(info->driver_name, driver->driver_name)) {
			if (trim_overlap_drv_files(mem_ctx, info, driver)) {
				/* mz: Do not instantly return -
				 * we need to ensure this file isn't
				 * also in use by other drivers. */
				in_use = true;
			}
		}

		talloc_free(driver);
	}

	talloc_free(drivers);

	DEBUG(5,("printer_driver_files_in_use: Completed search of drivers...\n"));

	return in_use;
}

static NTSTATUS driver_unlink_internals(connection_struct *conn,
					const char *short_arch,
					int vers,
					const char *fname)
{
	TALLOC_CTX *tmp_ctx = talloc_new(conn);
	struct smb_filename *smb_fname = NULL;
	char *print_dlr_path;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	print_dlr_path = talloc_asprintf(tmp_ctx, "%s/%d/%s",
					 short_arch, vers, fname);
	if (print_dlr_path == NULL) {
		goto err_out;
	}

	smb_fname = synthetic_smb_fname(tmp_ctx,
					print_dlr_path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		goto err_out;
	}

	status = unlink_internals(conn, NULL, 0, smb_fname, false);
err_out:
	talloc_free(tmp_ctx);
	return status;
}

/****************************************************************************
  Actually delete the driver files.  Make sure that
  printer_driver_files_in_use() return False before calling
  this.
****************************************************************************/

bool delete_driver_files(const struct auth_session_info *session_info,
			 const struct spoolss_DriverInfo8 *r)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *short_arch;
	struct conn_struct_tos *c = NULL;
	connection_struct *conn = NULL;
	NTSTATUS nt_status;
	char *printdollar = NULL;
	int printdollar_snum;
	bool ret = false;

	if (!r) {
		TALLOC_FREE(frame);
		return false;
	}

	DEBUG(6,("delete_driver_files: deleting driver [%s] - version [%d]\n",
		r->driver_name, r->version));

	printdollar_snum = find_service(frame, "print$", &printdollar);
	if (!printdollar) {
		TALLOC_FREE(frame);
		return false;
	}
	if (printdollar_snum == -1) {
		TALLOC_FREE(frame);
		return false;
	}

	nt_status = create_conn_struct_tos_cwd(global_messaging_context(),
					       printdollar_snum,
					       lp_path(frame, lp_sub, printdollar_snum),
					       session_info,
					       &c);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("delete_driver_files: create_conn_struct "
			 "returned %s\n", nt_errstr(nt_status)));
		TALLOC_FREE(frame);
		return false;
	}
	conn = c->conn;

	nt_status = set_conn_force_user_group(conn, printdollar_snum);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("failed set force user / group\n"));
		ret = false;
		goto err_free_conn;
	}

	if (!become_user_without_service_by_session(conn, session_info)) {
		DEBUG(0, ("failed to become user\n"));
		ret = false;
		goto err_free_conn;
	}

	if ( !CAN_WRITE(conn) ) {
		DEBUG(3,("delete_driver_files: Cannot delete print driver when [print$] is read-only\n"));
		ret = false;
		goto err_out;
	}

	short_arch = get_short_archi(r->architecture);
	if (short_arch == NULL) {
		DEBUG(0, ("bad architecture %s\n", r->architecture));
		ret = false;
		goto err_out;
	}

	/* now delete the files */

	if (r->driver_path && r->driver_path[0]) {
		DEBUG(10,("deleting driverfile [%s]\n", r->driver_path));
		driver_unlink_internals(conn, short_arch, r->version, r->driver_path);
	}

	if (r->config_file && r->config_file[0]) {
		DEBUG(10,("deleting configfile [%s]\n", r->config_file));
		driver_unlink_internals(conn, short_arch, r->version, r->config_file);
	}

	if (r->data_file && r->data_file[0]) {
		DEBUG(10,("deleting datafile [%s]\n", r->data_file));
		driver_unlink_internals(conn, short_arch, r->version, r->data_file);
	}

	if (r->help_file && r->help_file[0]) {
		DEBUG(10,("deleting helpfile [%s]\n", r->help_file));
		driver_unlink_internals(conn, short_arch, r->version, r->help_file);
	}

	if (r->dependent_files) {
		int i = 0;
		while (r->dependent_files[i] && r->dependent_files[i][0]) {
			DEBUG(10,("deleting dependent file [%s]\n", r->dependent_files[i]));
			driver_unlink_internals(conn, short_arch, r->version, r->dependent_files[i]);
			i++;
		}
	}

	ret = true;
 err_out:
	unbecome_user_without_service();
 err_free_conn:
	TALLOC_FREE(frame);
	return ret;
}

/* error code:
	0: everything OK
	1: level not implemented
	2: file doesn't exist
	3: can't allocate memory
	4: can't free memory
	5: non existent struct
*/

/*
	A printer and a printer driver are 2 different things.
	NT manages them separatelly, Samba does the same.
	Why ? Simply because it's easier and it makes sense !

	Now explanation: You have 3 printers behind your samba server,
	2 of them are the same make and model (laser A and B). But laser B
	has an 3000 sheet feeder and laser A doesn't such an option.
	Your third printer is an old dot-matrix model for the accounting :-).

	If the /usr/local/samba/lib directory (default dir), you will have
	5 files to describe all of this.

	3 files for the printers (1 by printer):
		NTprinter_laser A
		NTprinter_laser B
		NTprinter_accounting
	2 files for the drivers (1 for the laser and 1 for the dot matrix)
		NTdriver_printer model X
		NTdriver_printer model Y

jfm: I should use this comment for the text file to explain
	same thing for the forms BTW.
	Je devrais mettre mes commentaires en francais, ca serait mieux :-)

*/

/* Convert generic access rights to printer object specific access rights.
   It turns out that NT4 security descriptors use generic access rights and
   NT5 the object specific ones. */

void map_printer_permissions(struct security_descriptor *sd)
{
	int i;

	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		se_map_generic(&sd->dacl->aces[i].access_mask,
			       &printer_generic_mapping);
	}
}

void map_job_permissions(struct security_descriptor *sd)
{
	int i;

	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		se_map_generic(&sd->dacl->aces[i].access_mask,
			       &job_generic_mapping);
	}
}


/****************************************************************************
 Check a user has permissions to perform the given operation.  We use the
 permission constants defined in include/rpc_spoolss.h to check the various
 actions we perform when checking printer access.

   PRINTER_ACCESS_ADMINISTER:
       print_queue_pause, print_queue_resume, update_printer_sec,
       update_printer, spoolss_addprinterex_level_2,
       _spoolss_setprinterdata

   PRINTER_ACCESS_USE:
       print_job_start

   JOB_ACCESS_ADMINISTER:
       print_job_delete, print_job_pause, print_job_resume,
       print_queue_purge

  Try access control in the following order (for performance reasons):
    1)  root and SE_PRINT_OPERATOR can do anything (easy check)
    2)  check security descriptor (bit comparisons in memory)
    3)  "printer admins" (may result in numerous calls to winbind)

 ****************************************************************************/
WERROR print_access_check(const struct auth_session_info *session_info,
			  struct messaging_context *msg_ctx, int snum,
			  int access_type)
{
	struct spoolss_security_descriptor *secdesc = NULL;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uint32_t access_granted;
	size_t sd_size;
	NTSTATUS status;
	WERROR result;
	const char *pname;
	TALLOC_CTX *mem_ctx = NULL;

	/* If user is NULL then use the current_user structure */

	/* Always allow root or SE_PRINT_OPERATROR to do anything */

	if ((session_info->unix_token->uid == sec_initial_uid())
	    || security_token_has_privilege(session_info->security_token,
					    SEC_PRIV_PRINT_OPERATOR)) {
		return WERR_OK;
	}

	/* Get printer name */

	pname = lp_printername(talloc_tos(), lp_sub, snum);

	if (!pname || !*pname) {
		return WERR_ACCESS_DENIED;
	}

	/* Get printer security descriptor */

	if(!(mem_ctx = talloc_init("print_access_check"))) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_get_printer_secdesc_internal(mem_ctx,
					    get_session_info_system(),
					    msg_ctx,
					    pname,
					    &secdesc);
	if (!W_ERROR_IS_OK(result)) {
		talloc_destroy(mem_ctx);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (access_type == JOB_ACCESS_ADMINISTER) {
		struct spoolss_security_descriptor *parent_secdesc = secdesc;

		/* Create a child security descriptor to check permissions
		   against.  This is because print jobs are child objects
		   objects of a printer. */
		status = se_create_child_secdesc(mem_ctx,
						 &secdesc,
						 &sd_size,
						 parent_secdesc,
						 parent_secdesc->owner_sid,
						 parent_secdesc->group_sid,
						 false);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_destroy(mem_ctx);
			return ntstatus_to_werror(status);
		}

		map_job_permissions(secdesc);
	} else {
		map_printer_permissions(secdesc);
	}

	/* Check access */
	status = se_access_check(secdesc, session_info->security_token, access_type,
				 &access_granted);

	DEBUG(4, ("access check was %s\n", NT_STATUS_IS_OK(status) ? "SUCCESS" : "FAILURE"));

	talloc_destroy(mem_ctx);

	return ntstatus_to_werror(status);
}

/****************************************************************************
 Check the time parameters allow a print operation.
*****************************************************************************/

bool print_time_access_check(const struct auth_session_info *session_info,
			     struct messaging_context *msg_ctx,
			     const char *servicename)
{
	struct spoolss_PrinterInfo2 *pinfo2 = NULL;
	WERROR result;
	bool ok = False;
	time_t now = time(NULL);
	struct tm *t;
	uint32_t mins;

	result = winreg_get_printer_internal(NULL, session_info, msg_ctx,
				    servicename, &pinfo2);
	if (!W_ERROR_IS_OK(result)) {
		return False;
	}

	if (pinfo2->starttime == 0 && pinfo2->untiltime == 0) {
		ok = True;
	}

	t = gmtime(&now);
	mins = (uint32_t)t->tm_hour*60 + (uint32_t)t->tm_min;

	if (mins >= pinfo2->starttime && mins <= pinfo2->untiltime) {
		ok = True;
	}

	TALLOC_FREE(pinfo2);

	if (!ok) {
		errno = EACCES;
	}

	return ok;
}

void nt_printer_remove(TALLOC_CTX *mem_ctx,
			const struct auth_session_info *session_info,
			struct messaging_context *msg_ctx,
			const char *printer)
{
	WERROR result;

	result = winreg_delete_printer_key_internal(mem_ctx, session_info, msg_ctx,
					   printer, "");
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("nt_printer_remove: failed to remove printer %s: "
		"%s\n", printer, win_errstr(result)));
	}
}

void nt_printer_add(TALLOC_CTX *mem_ctx,
		    const struct auth_session_info *session_info,
		    struct messaging_context *msg_ctx,
		    const char *printer)
{
	WERROR result;

	result = winreg_create_printer_internal(mem_ctx, session_info, msg_ctx,
						printer);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("nt_printer_add: failed to add printer %s: %s\n",
			  printer, win_errstr(result)));
	}
}
