/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Volker Lendecke 2010

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

NTSTATUS make_user_info(struct auth_usersupplied_info **user_info,
			const char *smb_name,
			const char *internal_username,
			const char *client_domain,
			const char *domain,
			const char *workstation_name,
			const DATA_BLOB *lm_pwd,
			const DATA_BLOB *nt_pwd,
			const DATA_BLOB *lm_interactive_pwd,
			const DATA_BLOB *nt_interactive_pwd,
			const DATA_BLOB *plaintext,
			bool encrypted)
{

	DEBUG(5,("attempting to make a user_info for %s (%s)\n", internal_username, smb_name));

	*user_info = SMB_MALLOC_P(struct auth_usersupplied_info);
	if (*user_info == NULL) {
		DEBUG(0,("malloc failed for user_info (size %lu)\n", (unsigned long)sizeof(*user_info)));
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*user_info);

	DEBUG(5,("making strings for %s's user_info struct\n", internal_username));

	(*user_info)->client.account_name = SMB_STRDUP(smb_name);
	if ((*user_info)->client.account_name == NULL) {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->mapped.account_name = SMB_STRDUP(internal_username);
	if ((*user_info)->mapped.account_name == NULL) {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->mapped.domain_name = SMB_STRDUP(domain);
	if ((*user_info)->mapped.domain_name == NULL) {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->client.domain_name = SMB_STRDUP(client_domain);
	if ((*user_info)->client.domain_name == NULL) {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	(*user_info)->workstation_name = SMB_STRDUP(workstation_name);
	if ((*user_info)->workstation_name == NULL) {
		free_user_info(user_info);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5,("making blobs for %s's user_info struct\n", internal_username));

	if (lm_pwd)
		(*user_info)->lm_resp = data_blob(lm_pwd->data, lm_pwd->length);
	if (nt_pwd)
		(*user_info)->nt_resp = data_blob(nt_pwd->data, nt_pwd->length);
	if (lm_interactive_pwd)
		(*user_info)->lm_interactive_pwd = data_blob(lm_interactive_pwd->data, lm_interactive_pwd->length);
	if (nt_interactive_pwd)
		(*user_info)->nt_interactive_pwd = data_blob(nt_interactive_pwd->data, nt_interactive_pwd->length);

	if (plaintext)
		(*user_info)->plaintext_password = data_blob(plaintext->data, plaintext->length);

	(*user_info)->encrypted = encrypted;

	(*user_info)->logon_parameters = 0;

	DEBUG(10,("made an %sencrypted user_info for %s (%s)\n", encrypted ? "":"un" , internal_username, smb_name));

	return NT_STATUS_OK;
}

/***************************************************************************
 Free a user_info struct
***************************************************************************/

void free_user_info(struct auth_usersupplied_info **user_info)
{
	DEBUG(5,("attempting to free (and zero) a user_info structure\n"));
	if (*user_info != NULL) {
		if ((*user_info)->client.account_name) {
			DEBUG(10,("structure was created for %s\n",
				  (*user_info)->client.account_name));
		}
		SAFE_FREE((*user_info)->client.account_name);
		SAFE_FREE((*user_info)->mapped.account_name);
		SAFE_FREE((*user_info)->client.domain_name);
		SAFE_FREE((*user_info)->mapped.domain_name);
		SAFE_FREE((*user_info)->workstation_name);
		data_blob_free(&(*user_info)->lm_resp);
		data_blob_free(&(*user_info)->nt_resp);
		data_blob_clear_free(&(*user_info)->lm_interactive_pwd);
		data_blob_clear_free(&(*user_info)->nt_interactive_pwd);
		data_blob_clear_free(&(*user_info)->plaintext_password);
		ZERO_STRUCT(**user_info);
	}
	SAFE_FREE(*user_info);
}
