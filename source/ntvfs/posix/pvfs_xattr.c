/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - xattr support

   Copyright (C) Andrew Tridgell 2004

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
#include "system/filesys.h"
#include "vfs_posix.h"
#include "librpc/gen_ndr/ndr_xattr.h"

/*
  pull a xattr as a blob, from either a file or a file descriptor
*/
static NTSTATUS pull_xattr_blob(struct pvfs_state *pvfs,
				TALLOC_CTX *mem_ctx,
				const char *attr_name, 
				const char *fname, 
				int fd, 
				size_t estimated_size,
				DATA_BLOB *blob)
{
#if HAVE_XATTR_SUPPORT
	int ret;

	*blob = data_blob_talloc(mem_ctx, NULL, estimated_size);
	if (blob->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	if (fd != -1) {
		ret = fgetxattr(fd, attr_name, blob->data, estimated_size);
	} else {
		ret = getxattr(fname, attr_name, blob->data, estimated_size);
	}
	if (ret == -1 && errno == ERANGE) {
		estimated_size *= 2;
		blob->data = talloc_realloc(mem_ctx, blob->data, estimated_size);
		if (blob->data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		blob->length = estimated_size;
		goto again;
	}

	if (ret == -1) {
		data_blob_free(blob);
		return pvfs_map_errno(pvfs, errno);
	}

	blob->length = ret;

	return NT_STATUS_OK;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}

/*
  push a xattr as a blob, from either a file or a file descriptor
*/
static NTSTATUS push_xattr_blob(struct pvfs_state *pvfs,
				const char *attr_name, 
				const char *fname, 
				int fd, 
				const DATA_BLOB *blob)
{
#if HAVE_XATTR_SUPPORT
	int ret;

	if (fd != -1) {
		ret = fsetxattr(fd, attr_name, blob->data, blob->length, 0);
	} else {
		ret = setxattr(fname, attr_name, blob->data, blob->length, 0);
	}
	if (ret == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	return NT_STATUS_OK;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}


/*
  delete a xattr
*/
static NTSTATUS delete_xattr(struct pvfs_state *pvfs, const char *attr_name, 
			     const char *fname, int fd)
{
#if HAVE_XATTR_SUPPORT
	int ret;

	if (fd != -1) {
		ret = fremovexattr(fd, attr_name);
	} else {
		ret = removexattr(fname, attr_name);
	}
	if (ret == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	return NT_STATUS_OK;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}

/*
  load a NDR structure from a xattr
*/
static NTSTATUS pvfs_xattr_ndr_load(struct pvfs_state *pvfs,
				    TALLOC_CTX *mem_ctx,
				    const char *fname, int fd, const char *attr_name,
				    void *p, ndr_pull_flags_fn_t pull_fn)
{
	NTSTATUS status;
	DATA_BLOB blob;

	status = pull_xattr_blob(pvfs, mem_ctx, attr_name, fname, 
				 fd, XATTR_DOSATTRIB_ESTIMATED_SIZE, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* pull the blob */
	status = ndr_pull_struct_blob(&blob, mem_ctx, p, pull_fn);

	data_blob_free(&blob);

	return status;
}

/*
  save a NDR structure into a xattr
*/
static NTSTATUS pvfs_xattr_ndr_save(struct pvfs_state *pvfs,
				    const char *fname, int fd, const char *attr_name, 
				    void *p, ndr_push_flags_fn_t push_fn)
{
	TALLOC_CTX *mem_ctx = talloc(NULL, 0);
	DATA_BLOB blob;
	NTSTATUS status;

	status = ndr_push_struct_blob(&blob, mem_ctx, p, (ndr_push_flags_fn_t)push_fn);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return status;
	}

	status = push_xattr_blob(pvfs, attr_name, fname, fd, &blob);
	talloc_free(mem_ctx);

	return status;
}


/*
  fill in file attributes from extended attributes
*/
NTSTATUS pvfs_dosattrib_load(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd)
{
	NTSTATUS status;
	struct xattr_DosAttrib attrib;
	TALLOC_CTX *mem_ctx = talloc(name, 0);
	struct xattr_DosInfo1 *info1;

	if (name->stream_name != NULL) {
		name->stream_exists = False;
	} else {
		name->stream_exists = True;
	}

	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}

	status = pvfs_xattr_ndr_load(pvfs, mem_ctx, name->full_name, 
				     fd, XATTR_DOSATTRIB_NAME,
				     &attrib, 
				     (ndr_pull_flags_fn_t)ndr_pull_xattr_DosAttrib);

	/* if the filesystem doesn't support them, then tell pvfs not to try again */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		DEBUG(5,("pvfs_xattr: xattr not supported in filesystem\n"));
		pvfs->flags &= ~PVFS_FLAG_XATTR_ENABLE;
		talloc_free(mem_ctx);
		return NT_STATUS_OK;
	}

	/* not having a DosAttrib is not an error */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		talloc_free(mem_ctx);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return status;
	}

	switch (attrib.version) {
	case 1:
		info1 = &attrib.info.info1;
		name->dos.attrib = pvfs_attrib_normalise(info1->attrib);
		name->dos.ea_size = info1->ea_size;
		if (name->st.st_size == info1->size) {
			name->dos.alloc_size = 
				pvfs_round_alloc_size(pvfs, info1->alloc_size);
		}
		if (info1->create_time != 0) {
			name->dos.create_time = info1->create_time;
		}
		if (info1->change_time != 0) {
			name->dos.change_time = info1->change_time;
		}
		break;

	default:
		DEBUG(0,("ERROR: Unsupported xattr DosAttrib version %d on '%s'\n",
			 attrib.version, name->full_name));
		talloc_free(mem_ctx);
		return NT_STATUS_INVALID_LEVEL;
	}
	talloc_free(mem_ctx);
	
	status = pvfs_stream_info(pvfs, name, fd);

	return status;
}


/*
  save the file attribute into the xattr
*/
NTSTATUS pvfs_dosattrib_save(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd)
{
	struct xattr_DosAttrib attrib;
	struct xattr_DosInfo1 *info1;

	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}

	attrib.version = 1;
	info1 = &attrib.info.info1;

	name->dos.attrib = pvfs_attrib_normalise(name->dos.attrib);

	info1->attrib      = name->dos.attrib;
	info1->ea_size     = name->dos.ea_size;
	info1->size        = name->st.st_size;
	info1->alloc_size  = name->dos.alloc_size;
	info1->create_time = name->dos.create_time;
	info1->change_time = name->dos.change_time;

	return pvfs_xattr_ndr_save(pvfs, name->full_name, fd, 
				   XATTR_DOSATTRIB_NAME, &attrib, 
				   (ndr_push_flags_fn_t)ndr_push_xattr_DosAttrib);
}


/*
  load the set of DOS EAs
*/
NTSTATUS pvfs_doseas_load(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
			  struct xattr_DosEAs *eas)
{
	NTSTATUS status;
	ZERO_STRUCTP(eas);
	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}
	status = pvfs_xattr_ndr_load(pvfs, eas, name->full_name, fd, XATTR_DOSEAS_NAME,
				     eas, (ndr_pull_flags_fn_t)ndr_pull_xattr_DosEAs);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		return NT_STATUS_OK;
	}
	return status;
}

/*
  save the set of DOS EAs
*/
NTSTATUS pvfs_doseas_save(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
			  struct xattr_DosEAs *eas)
{
	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}
	return pvfs_xattr_ndr_save(pvfs, name->full_name, fd, XATTR_DOSEAS_NAME, eas, 
				   (ndr_push_flags_fn_t)ndr_push_xattr_DosEAs);
}


/*
  load the set of streams from extended attributes
*/
NTSTATUS pvfs_streams_load(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
			   struct xattr_DosStreams *streams)
{
	NTSTATUS status;
	ZERO_STRUCTP(streams);
	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}
	status = pvfs_xattr_ndr_load(pvfs, streams, name->full_name, fd, 
				     XATTR_DOSSTREAMS_NAME,
				     streams, 
				     (ndr_pull_flags_fn_t)ndr_pull_xattr_DosStreams);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		return NT_STATUS_OK;
	}
	return status;
}

/*
  save the set of streams into filesystem xattr
*/
NTSTATUS pvfs_streams_save(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
			   struct xattr_DosStreams *streams)
{
	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}
	return pvfs_xattr_ndr_save(pvfs, name->full_name, fd, 
				   XATTR_DOSSTREAMS_NAME, 
				   streams, 
				   (ndr_push_flags_fn_t)ndr_push_xattr_DosStreams);
}


/*
  load the current ACL from extended attributes
*/
NTSTATUS pvfs_acl_load(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
		       struct xattr_DosAcl *acl)
{
	NTSTATUS status;
	ZERO_STRUCTP(acl);
	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}
	status = pvfs_xattr_ndr_load(pvfs, acl, name->full_name, fd, 
				     XATTR_DOSACL_NAME,
				     acl, 
				     (ndr_pull_flags_fn_t)ndr_pull_xattr_DosAcl);
	return status;
}

/*
  save the acl for a file into filesystem xattr
*/
NTSTATUS pvfs_acl_save(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
		       struct xattr_DosAcl *acl)
{
	NTSTATUS status;
	void *privs;

	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_OK;
	}

	/* this xattr is in the "system" namespace, so we need
	   admin privileges to set it */
	privs = root_privileges();
	status = pvfs_xattr_ndr_save(pvfs, name->full_name, fd, 
				     XATTR_DOSACL_NAME, 
				     acl, 
				     (ndr_push_flags_fn_t)ndr_push_xattr_DosAcl);
	talloc_free(privs);
	return status;
}

/*
  create a zero length xattr with the given name
*/
NTSTATUS pvfs_xattr_create(struct pvfs_state *pvfs, 
			   const char *fname, int fd,
			   const char *attr_prefix,
			   const char *attr_name)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob(NULL, 0);
	char *aname = talloc_asprintf(NULL, "%s%s", attr_prefix, attr_name);
	if (aname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = push_xattr_blob(pvfs, aname, fname, fd, &blob);
	talloc_free(aname);
	return status;
}


/*
  delete a xattr with the given name
*/
NTSTATUS pvfs_xattr_delete(struct pvfs_state *pvfs, 
			   const char *fname, int fd,
			   const char *attr_prefix,
			   const char *attr_name)
{
	NTSTATUS status;
	char *aname = talloc_asprintf(NULL, "%s%s", attr_prefix, attr_name);
	if (aname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = delete_xattr(pvfs, aname, fname, fd);
	talloc_free(aname);
	return status;
}

/*
  load a xattr with the given name
*/
NTSTATUS pvfs_xattr_load(struct pvfs_state *pvfs, 
			 TALLOC_CTX *mem_ctx,
			 const char *fname, int fd,
			 const char *attr_prefix,
			 const char *attr_name,
			 size_t estimated_size,
			 DATA_BLOB *blob)
{
	NTSTATUS status;
	char *aname = talloc_asprintf(mem_ctx, "%s%s", attr_prefix, attr_name);
	if (aname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = pull_xattr_blob(pvfs, mem_ctx, aname, fname, fd, estimated_size, blob);
	talloc_free(aname);
	return status;
}

/*
  save a xattr with the given name
*/
NTSTATUS pvfs_xattr_save(struct pvfs_state *pvfs, 
			 const char *fname, int fd,
			 const char *attr_prefix,
			 const char *attr_name,
			 const DATA_BLOB *blob)
{
	NTSTATUS status;
	char *aname = talloc_asprintf(NULL, "%s%s", attr_prefix, attr_name);
	if (aname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = push_xattr_blob(pvfs, aname, fname, fd, blob);
	talloc_free(aname);
	return status;
}
