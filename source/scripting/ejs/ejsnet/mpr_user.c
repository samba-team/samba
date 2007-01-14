/* 
   Unix SMB/CIFS implementation.

   provides interfaces to libnet calls from ejs scripts

   Copyright (C) Rafal Szczesniak  2005-2007
   
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
#include "lib/appweb/ejs/ejs.h"
#include "libnet/libnet.h"
#include "scripting/ejs/smbcalls.h"
#include "events/events.h"
#include "auth/credentials/credentials.h"


/*
  Properties:
  UserInfo.AccountName
  UserInfo.FullName
  UserInfo.Description
  UserInfo.HomeDirectory
  UserInfo.HomeDrive
  UserInfo.Comment
  UserInfo.LogonScript
  UserInfo.AcctExpiry
  UserInfo.AllowPasswordChange
  UserInfo.ForcePasswordChange
 */
struct MprVar mprCreateUserInfo(TALLOC_CTX *mem_ctx, struct libnet_UserInfo *info)
{
	const char *name = "UserInfo";
	NTSTATUS status;
	struct MprVar mprUserInfo;
	struct MprVar mprAccountName, mprFullName, mprDescription;
	struct MprVar mprHomeDir, mprHomeDrive, mprComment;
	struct MprVar mprLogonScript;
	struct MprVar mprAcctExpiry, mprAllowPassChange, mprForcePassChange;

	if (info == NULL || mem_ctx == NULL) {
		mprUserInfo = mprCreateNullVar();
		goto done;
	}

	mprUserInfo = mprObject(name);

	mprAccountName = mprString(info->out.account_name);
	mprFullName = mprString(info->out.full_name);
	mprDescription = mprString(info->out.description);
	mprHomeDir = mprString(info->out.home_directory);
	mprHomeDrive = mprString(info->out.home_drive);
	mprComment = mprString(info->out.comment);
	mprLogonScript = mprString(info->out.logon_script);
	mprAcctExpiry = mprString(timestring(mem_ctx, info->out.acct_expiry->tv_sec));
	mprAllowPassChange = mprString(timestring(mem_ctx, info->out.allow_password_change->tv_sec));
	mprForcePassChange = mprString(timestring(mem_ctx, info->out.force_password_change->tv_sec));

	status = mprSetVar(&mprUserInfo, "AccountName", mprAccountName);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "FullName", mprFullName);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "Description", mprDescription);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "HomeDirectory", mprHomeDir);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "HomeDrive", mprHomeDrive);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "Comment", mprComment);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "LogonScript", mprLogonScript);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "AcctExpiry", mprAcctExpiry);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "AllowPasswordChange", mprAllowPassChange);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "ForcePasswordChange", mprForcePassChange);
	if (!NT_STATUS_IS_OK(status)) goto done;

done:
	return mprUserInfo;
}


/*
  Properties:
  UserListCtx.Users[]
  UserListCtx.ResumeIndex
  UserListCtx.Count
 */
struct MprVar mprUserListCtx(TALLOC_CTX *mem_ctx, struct libnet_UserList *list)
{
	const char *name = "UserListCtx";
	NTSTATUS status;
	struct MprVar mprListCtx, mprUserList;
	struct MprVar mprUser, mprSid, mprUsername;
	int i;

	if (list == NULL || mem_ctx == NULL) {
		mprListCtx = mprCreateNullVar();
		goto done;
	}

	mprUserList = mprArray("Users");
	for (i = 0; i < list->out.count; i++) {
		struct userlist u = list->out.users[i];
		
		/* get userlist fields */
		mprSid      = mprString(u.sid);
		mprUsername = mprString(u.username);
		
		/* create userlist object */
		mprUser = mprObject("User");
		mprSetVar(&mprUser, "Username", mprUsername);
		mprSetVar(&mprUser, "SID", mprSid);
		
		/* add the object to the array being constructed */
		mprAddArray(&mprUserList, 0, mprUser);
	}

	mprListCtx = mprObject(name);
	status = mprSetVar(&mprListCtx, "Users", mprUserList);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprListCtx, "Count", mprCreateIntegerVar(list->out.count));
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprListCtx, "ResumeIndex", mprCreateIntegerVar((int)list->out.resume_index));
	if (!NT_STATUS_IS_OK(status)) goto done;

done:
	return mprListCtx;
}


/*
  Returns UserListCtx.ResumeIndex out of passed UserListCtx
 */
unsigned int mprListGetResumeIndex(struct MprVar *listCtx)
{
	NTSTATUS status;
	unsigned int resume = 0;
	struct MprVar *mprResumeIndex;
	if (listCtx == NULL) return 0;
	
	mprResumeIndex = listCtx;
	status = mprGetVar(&mprResumeIndex, "ResumeIndex");
	if (!NT_STATUS_IS_OK(status)) goto done;

	resume = (unsigned int) mprVarToInteger(mprResumeIndex);

done:
	return resume;
}
