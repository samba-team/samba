/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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


/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
struct user_struct *get_valid_user_struct(struct smbsrv_connection *smb, uint16_t vuid)
{
	user_struct *usp;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	for (usp=smb->users.validated_users;usp;usp=usp->next,count++) {
		if (vuid == usp->vuid) {
			if (count > 10) {
				DLIST_PROMOTE(smb->users.validated_users, usp);
			}
			return usp;
		}
	}

	return NULL;
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(struct smbsrv_connection *smb, uint16_t vuid)
{
	user_struct *vuser = get_valid_user_struct(smb, vuid);

	if (vuser == NULL)
		return;

	session_yield(vuser);

	free_session_info(&vuser->session_info);

	DLIST_REMOVE(smb->users.validated_users, vuser);

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	/* REWRITE: conn_clear_vuid_cache(smb, vuid); */

	SAFE_FREE(vuser);
	smb->users.num_validated_vuids--;
}

/****************************************************************************
invalidate all vuid entries for this process
****************************************************************************/
void invalidate_all_vuids(struct smbsrv_connection *smb)
{
	user_struct *usp, *next=NULL;

	for (usp=smb->users.validated_users;usp;usp=next) {
		next = usp->next;
		
		invalidate_vuid(smb, usp->vuid);
	}
}

/**
 *  register that a valid login has been performed, establish 'session'.
 *  @param server_info The token returned from the authentication process. 
 *   (now 'owned' by register_vuid)
 *
 *  @param session_key The User session key for the login session (now also 'owned' by register_vuid)
 *
 *  @param smb_name The untranslated name of the user
 *
 *  @return Newly allocated vuid, biased by an offset. (This allows us to
 *   tell random client vuid's (normally zero) from valid vuids.)
 *
 */

int register_vuid(struct smbsrv_connection *smb,
		  struct auth_session_info *session_info,
		  const char *smb_name)
{
	user_struct *vuser = NULL;

	/* Ensure no vuid gets registered in share level security. */
	if(lp_security() == SEC_SHARE)
		return UID_FIELD_INVALID;

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (smb->users.num_validated_vuids >= 0xFFFF-VUID_OFFSET)
		return UID_FIELD_INVALID;

	if((vuser = (user_struct *)malloc( sizeof(user_struct) )) == NULL) {
		DEBUG(0,("Failed to malloc users struct!\n"));
		return UID_FIELD_INVALID;
	}

	ZERO_STRUCTP(vuser);

	/* Allocate a free vuid. Yes this is a linear search... :-) */
	while (get_valid_user_struct(smb, smb->users.next_vuid) != NULL ) {
		smb->users.next_vuid++;
		/* Check for vuid wrap. */
		if (smb->users.next_vuid == UID_FIELD_INVALID)
			smb->users.next_vuid = VUID_OFFSET;
	}

	DEBUG(10,("register_vuid: allocated vuid = %u\n", 
		  (uint_t)smb->users.next_vuid));

	vuser->vuid = smb->users.next_vuid;

	/* use this to keep tabs on all our info from the authentication */
	vuser->session_info = session_info;

	smb->users.next_vuid++;
	smb->users.num_validated_vuids++;

	DLIST_ADD(smb->users.validated_users, vuser);

	if (!session_claim(smb, vuser)) {
		DEBUG(1,("Failed to claim session for vuid=%d\n", vuser->vuid));
		invalidate_vuid(smb, vuser->vuid);
		return UID_FIELD_INVALID;
	}

	return vuser->vuid;
}
