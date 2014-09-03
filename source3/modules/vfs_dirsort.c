/*
 * VFS module to provide a sorted directory list.
 *
 * Copyright (C) Andy Kelk (andy@mopoke.co.uk), 2009
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"

static int compare_dirent (const struct dirent *da, const struct dirent *db)
{
	return strcasecmp_m(da->d_name, db->d_name);
}

struct dirsort_privates {
	struct dirsort_privates *prev, *next;
	long pos;
	struct dirent *directory_list;
	unsigned int number_of_entries;
	struct timespec mtime;
	DIR *source_directory;
	files_struct *fsp; /* If open via FDOPENDIR. */
	struct smb_filename *smb_fname; /* If open via OPENDIR */
};

static bool get_sorted_dir_mtime(vfs_handle_struct *handle,
				struct dirsort_privates *data,
				struct timespec *ret_mtime)
{
	int ret;
	struct timespec mtime;

	if (data->fsp) {
		ret = fsp_stat(data->fsp);
		mtime = data->fsp->fsp_name->st.st_ex_mtime;
	} else {
		ret = SMB_VFS_STAT(handle->conn, data->smb_fname);
		mtime = data->smb_fname->st.st_ex_mtime;
	}

	if (ret == -1) {
		return false;
	}

	*ret_mtime = mtime;

	return true;
}

static bool open_and_sort_dir(vfs_handle_struct *handle,
				struct dirsort_privates *data)
{
	unsigned int i = 0;
	unsigned int total_count = 0;

	data->number_of_entries = 0;

	if (get_sorted_dir_mtime(handle, data, &data->mtime) == false) {
		return false;
	}

	while (SMB_VFS_NEXT_READDIR(handle, data->source_directory, NULL)
	       != NULL) {
		total_count++;
	}

	if (total_count == 0) {
		return false;
	}

	/* Open the underlying directory and count the number of entries
	   Skip back to the beginning as we'll read it again */
	SMB_VFS_NEXT_REWINDDIR(handle, data->source_directory);

	/* Set up an array and read the directory entries into it */
	TALLOC_FREE(data->directory_list); /* destroy previous cache if needed */
	data->directory_list = talloc_zero_array(data,
					struct dirent,
					total_count);
	if (!data->directory_list) {
		return false;
	}
	for (i = 0; i < total_count; i++) {
		struct dirent *dp = SMB_VFS_NEXT_READDIR(handle,
						data->source_directory,
						NULL);
		if (dp == NULL) {
			break;
		}
		data->directory_list[i] = *dp;
	}

	data->number_of_entries = i;

	/* Sort the directory entries by name */
	TYPESAFE_QSORT(data->directory_list, data->number_of_entries, compare_dirent);
	return true;
}

static DIR *dirsort_opendir(vfs_handle_struct *handle,
				       const char *fname, const char *mask,
				       uint32 attr)
{
	struct dirsort_privates *list_head = NULL;
	struct dirsort_privates *data = NULL;

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		/* Find the list head of all open directories. */
		SMB_VFS_HANDLE_GET_DATA(handle, list_head, struct dirsort_privates,
				return NULL);
	}

	/* set up our private data about this directory */
	data = talloc_zero(handle->conn, struct dirsort_privates);
	if (!data) {
		return NULL;
	}

	data->smb_fname = synthetic_smb_fname(data, fname, NULL, NULL);
	if (data->smb_fname == NULL) {
		TALLOC_FREE(data);
		return NULL;
	}

	/* Open the underlying directory and count the number of entries */
	data->source_directory = SMB_VFS_NEXT_OPENDIR(handle, fname, mask,
						      attr);

	if (data->source_directory == NULL) {
		TALLOC_FREE(data);
		return NULL;
	}

	if (!open_and_sort_dir(handle, data)) {
		SMB_VFS_NEXT_CLOSEDIR(handle,data->source_directory);
		TALLOC_FREE(data);
		return NULL;
	}

	/* Add to the private list of all open directories. */
	DLIST_ADD(list_head, data);
	SMB_VFS_HANDLE_SET_DATA(handle, list_head, NULL,
				struct dirsort_privates, return NULL);

	return data->source_directory;
}

static DIR *dirsort_fdopendir(vfs_handle_struct *handle,
					files_struct *fsp,
					const char *mask,
					uint32 attr)
{
	struct dirsort_privates *list_head = NULL;
	struct dirsort_privates *data = NULL;

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		/* Find the list head of all open directories. */
		SMB_VFS_HANDLE_GET_DATA(handle, list_head, struct dirsort_privates,
				return NULL);
	}

	/* set up our private data about this directory */
	data = talloc_zero(handle->conn, struct dirsort_privates);
	if (!data) {
		return NULL;
	}

	data->fsp = fsp;

	/* Open the underlying directory and count the number of entries */
	data->source_directory = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask,
						      attr);

	if (data->source_directory == NULL) {
		TALLOC_FREE(data);
		return NULL;
	}

	if (!open_and_sort_dir(handle, data)) {
		SMB_VFS_NEXT_CLOSEDIR(handle,data->source_directory);
		TALLOC_FREE(data);
		/* fd is now closed. */
		fsp->fh->fd = -1;
		return NULL;
	}

	/* Add to the private list of all open directories. */
	DLIST_ADD(list_head, data);
	SMB_VFS_HANDLE_SET_DATA(handle, list_head, NULL,
				struct dirsort_privates, return NULL);

	return data->source_directory;
}

static struct dirent *dirsort_readdir(vfs_handle_struct *handle,
					  DIR *dirp,
					  SMB_STRUCT_STAT *sbuf)
{
	struct dirsort_privates *data = NULL;
	struct timespec current_mtime;

	SMB_VFS_HANDLE_GET_DATA(handle, data, struct dirsort_privates,
				return NULL);

	while(data && (data->source_directory != dirp)) {
		data = data->next;
	}
	if (data == NULL) {
		return NULL;
	}

	if (get_sorted_dir_mtime(handle, data, &current_mtime) == false) {
		return NULL;
	}

	/* throw away cache and re-read the directory if we've changed */
	if (timespec_compare(&current_mtime, &data->mtime)) {
		SMB_VFS_NEXT_REWINDDIR(handle, data->source_directory);
		open_and_sort_dir(handle, data);
	}

	if (data->pos >= data->number_of_entries) {
		return NULL;
	}

	return &data->directory_list[data->pos++];
}

static void dirsort_seekdir(vfs_handle_struct *handle, DIR *dirp,
			    long offset)
{
	struct timespec current_mtime;
	struct dirsort_privates *data = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, data, struct dirsort_privates, return);

	/* Find the entry holding dirp. */
	while(data && (data->source_directory != dirp)) {
		data = data->next;
	}
	if (data == NULL) {
		return;
	}
	if (offset >= data->number_of_entries) {
		return;
	}
	data->pos = offset;

	if (get_sorted_dir_mtime(handle, data, &current_mtime) == false) {
		return;
	}

	if (timespec_compare(&current_mtime, &data->mtime)) {
		/* Directory changed. We must re-read the
		   cache and search for the name that was
		   previously stored at the offset being
		   requested, otherwise after the re-sort
		   we will point to the wrong entry. The
		   OS/2 incremental delete code relies on
		   this. */
		unsigned int i;
		char *wanted_name = talloc_strdup(handle->conn,
					data->directory_list[offset].d_name);
		if (wanted_name == NULL) {
			return;
		}
		SMB_VFS_NEXT_REWINDDIR(handle, data->source_directory);
		open_and_sort_dir(handle, data);
		/* Now search for where we were. */
		data->pos = 0;
		for (i = 0; i < data->number_of_entries; i++) {
			if(strcmp(wanted_name, data->directory_list[i].d_name) == 0) {
				data->pos = i;
				break;
			}
		}
		TALLOC_FREE(wanted_name);
	}
}

static long dirsort_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	struct dirsort_privates *data = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, data, struct dirsort_privates,
				return -1);

	/* Find the entry holding dirp. */
	while(data && (data->source_directory != dirp)) {
		data = data->next;
	}
	if (data == NULL) {
		return -1;
	}
	return data->pos;
}

static void dirsort_rewinddir(vfs_handle_struct *handle, DIR *dirp)
{
	struct dirsort_privates *data = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, data, struct dirsort_privates, return);

	/* Find the entry holding dirp. */
	while(data && (data->source_directory != dirp)) {
		data = data->next;
	}
	if (data == NULL) {
		return;
	}
	data->pos = 0;
}

static int dirsort_closedir(vfs_handle_struct *handle, DIR *dirp)
{
	struct dirsort_privates *list_head = NULL;
	struct dirsort_privates *data = NULL;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, list_head, struct dirsort_privates, return -1);
	/* Find the entry holding dirp. */
	for(data = list_head; data && (data->source_directory != dirp); data = data->next) {
		;
	}
	if (data == NULL) {
		return -1;
	}
	/* Remove from the list and re-store the list head. */
	DLIST_REMOVE(list_head, data);
	SMB_VFS_HANDLE_SET_DATA(handle, list_head, NULL,
				struct dirsort_privates, return -1);

	ret = SMB_VFS_NEXT_CLOSEDIR(handle, dirp);
	TALLOC_FREE(data);
	return ret;
}

static struct vfs_fn_pointers vfs_dirsort_fns = {
	.opendir_fn = dirsort_opendir,
	.fdopendir_fn = dirsort_fdopendir,
	.readdir_fn = dirsort_readdir,
	.seekdir_fn = dirsort_seekdir,
	.telldir_fn = dirsort_telldir,
	.rewind_dir_fn = dirsort_rewinddir,
	.closedir_fn = dirsort_closedir,
};

NTSTATUS vfs_dirsort_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "dirsort",
				&vfs_dirsort_fns);
}
