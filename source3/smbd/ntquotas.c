/* 
   Unix SMB/CIFS implementation.
   NT QUOTA suppport
   Copyright (C) Stefan (metze) Metzmacher	2003
   
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
#include "smbd/smbd.h"
#include "../lib/util/util_pw.h"
#include "system/passwd.h"
#include "passdb/lookup_sid.h"
#include "libsmb/libsmb.h"
#include "libcli/security/dom_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_QUOTA

static uint64_t limit_nt2unix(uint64_t in, uint64_t bsize)
{
	uint64_t ret = (uint64_t)0;

	ret = 	(uint64_t)(in/bsize);
	if (in>0 && ret==0) {
		/* we have to make sure that a overflow didn't set NO_LIMIT */
		ret = (uint64_t)1;
	}

	if (in == SMB_NTQUOTAS_NO_LIMIT)
		ret = SMB_QUOTAS_NO_LIMIT;
	else if (in == SMB_NTQUOTAS_NO_SPACE)
		ret = SMB_QUOTAS_NO_SPACE;
	else if (in == SMB_NTQUOTAS_NO_ENTRY)
		ret = SMB_QUOTAS_NO_LIMIT;

	return ret;
}

static uint64_t limit_unix2nt(uint64_t in, uint64_t bsize)
{
	uint64_t ret = (uint64_t)0;

	ret = (uint64_t)(in*bsize);
	
	return ret;
}

NTSTATUS vfs_get_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype,
			 struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt)
{
	int ret;
	SMB_DISK_QUOTA D;
	unid_t id;
	struct smb_filename *smb_fname_cwd = NULL;
	int saved_errno = 0;

	ZERO_STRUCT(D);

	if (!fsp || !fsp->conn || !qt) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ZERO_STRUCT(*qt);

	id.uid = -1;

	if (psid && !sid_to_uid(psid, &id.uid)) {
		struct dom_sid_buf buf;
		DEBUG(0,("sid_to_uid: failed, SID[%s]\n",
			 dom_sid_str_buf(psid, &buf)));
		return NT_STATUS_NO_SUCH_USER;
	}

	smb_fname_cwd = synthetic_smb_fname(talloc_tos(),
				".",
				NULL,
				NULL,
				0,
				0);
	if (smb_fname_cwd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_GET_QUOTA(fsp->conn, smb_fname_cwd, qtype, id, &D);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(smb_fname_cwd);
	if (saved_errno != 0) {
		errno = saved_errno;
	}

	if (psid)
		qt->sid    = *psid;

	if (ret!=0) {
		return map_nt_error_from_unix(errno);
	}
		
	qt->usedspace = (uint64_t)D.curblocks*D.bsize;
	qt->softlim = limit_unix2nt(D.softlimit, D.bsize);
	qt->hardlim = limit_unix2nt(D.hardlimit, D.bsize);
	qt->qflags = D.qflags;

	return NT_STATUS_OK;
}

int vfs_set_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt)
{
	int ret;
	SMB_DISK_QUOTA D;
	unid_t id;
	ZERO_STRUCT(D);

	if (!fsp||!fsp->conn||!qt)
		return (-1);

	id.uid = -1;

	D.bsize     = (uint64_t)QUOTABLOCK_SIZE;

	D.softlimit = limit_nt2unix(qt->softlim,D.bsize);
	D.hardlimit = limit_nt2unix(qt->hardlim,D.bsize);
	D.qflags     = qt->qflags;

	if (psid && !sid_to_uid(psid, &id.uid)) {
		struct dom_sid_buf buf;
		DEBUG(0,("sid_to_uid: failed, SID[%s]\n",
			 dom_sid_str_buf(psid, &buf)));
	}

	ret = SMB_VFS_SET_QUOTA(fsp->conn, qtype, id, &D);
	
	return ret;
}

static bool already_in_quota_list(SMB_NTQUOTA_LIST *qt_list, uid_t uid)
{
	SMB_NTQUOTA_LIST *tmp_list = NULL;
	
	if (!qt_list)
		return False;

	for (tmp_list=qt_list;tmp_list!=NULL;tmp_list=tmp_list->next) {
		if (tmp_list->uid == uid) {
			return True;	
		}
	}

	return False;
}

int vfs_get_user_ntquota_list(files_struct *fsp, SMB_NTQUOTA_LIST **qt_list)
{
	struct passwd *usr;
	TALLOC_CTX *mem_ctx = NULL;

	if (!fsp||!fsp->conn||!qt_list)
		return (-1);

	*qt_list = NULL;

	if ((mem_ctx=talloc_init("SMB_USER_QUOTA_LIST"))==NULL) {
		DEBUG(0,("talloc_init() failed\n"));
		return (-1);
	}

	setpwent();
	while ((usr = getpwent()) != NULL) {
		SMB_NTQUOTA_STRUCT tmp_qt;
		SMB_NTQUOTA_LIST *tmp_list_ent;
		struct dom_sid	sid;
		struct dom_sid_buf buf;
		NTSTATUS status;

		ZERO_STRUCT(tmp_qt);

		if (already_in_quota_list((*qt_list),usr->pw_uid)) {
			DEBUG(5,("record for uid[%ld] already in the list\n",(long)usr->pw_uid));
			continue;
		}

		uid_to_sid(&sid, usr->pw_uid);

		status =
		    vfs_get_ntquota(fsp, SMB_USER_QUOTA_TYPE, &sid, &tmp_qt);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("failed getting quota for uid[%ld] - %s\n",
				  (long)usr->pw_uid, nt_errstr(status)));
			continue;
		}
		if (tmp_qt.softlim == 0 && tmp_qt.hardlim == 0) {
			DEBUG(5,("no quota entry for sid[%s] path[%s]\n",
				 dom_sid_str_buf(&sid, &buf),
				 fsp->conn->connectpath));
			continue;
		}

		DEBUG(15,("quota entry for id[%s] path[%s]\n",
			  dom_sid_str_buf(&sid, &buf),
			  fsp->conn->connectpath));

		if ((tmp_list_ent=talloc_zero(mem_ctx,SMB_NTQUOTA_LIST))==NULL) {
			DEBUG(0,("TALLOC_ZERO() failed\n"));
			*qt_list = NULL;
			talloc_destroy(mem_ctx);
			return (-1);
		}

		if ((tmp_list_ent->quotas=talloc_zero(mem_ctx,SMB_NTQUOTA_STRUCT))==NULL) {
			DEBUG(0,("TALLOC_ZERO() failed\n"));
			*qt_list = NULL;
			talloc_destroy(mem_ctx);
			return (-1);
		}

		tmp_list_ent->uid = usr->pw_uid;
		memcpy(tmp_list_ent->quotas,&tmp_qt,sizeof(tmp_qt));
		tmp_list_ent->mem_ctx = mem_ctx;

		DLIST_ADD((*qt_list),tmp_list_ent);
		
	}
	endpwent();

	if (*qt_list == NULL) {
		TALLOC_FREE(mem_ctx);
	}
	return 0;
}

static int quota_handle_destructor(SMB_NTQUOTA_HANDLE *handle)
{
	free_ntquota_list(&handle->quota_list);
	return 0;
}

void *init_quota_handle(TALLOC_CTX *mem_ctx)
{
	SMB_NTQUOTA_HANDLE *qt_handle;

	if (!mem_ctx)
		return NULL;

	qt_handle = talloc_zero(mem_ctx,SMB_NTQUOTA_HANDLE);
	if (qt_handle==NULL) {
		DEBUG(0,("TALLOC_ZERO() failed\n"));
		return NULL;
	}

	talloc_set_destructor(qt_handle, quota_handle_destructor);
	return (void *)qt_handle;
}
