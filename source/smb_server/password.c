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
struct smbsrv_session *smbsrv_session_find(struct smbsrv_connection *smb_conn, uint16_t vuid)
{
	struct smbsrv_session *sess;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	for (sess=smb_conn->sessions.session_list; sess; sess=sess->next,count++) {
		if (vuid == sess->vuid) {
			if (count > 10) {
				DLIST_PROMOTE(smb_conn->sessions.session_list, sess);
			}
			return sess;
		}
	}

	return NULL;
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void smbsrv_invalidate_vuid(struct smbsrv_connection *smb_conn, uint16_t vuid)
{
	struct smbsrv_session *sess = smbsrv_session_find(smb_conn, vuid);

	if (sess == NULL)
		return;

	DLIST_REMOVE(smb_conn->sessions.session_list, sess);

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	/* REWRITE: conn_clear_vuid_cache(smb, vuid); */

	smb_conn->sessions.num_validated_vuids--;
}

/****************************************************************************
invalidate all vuid entries for this process
****************************************************************************/
void smbsrv_invalidate_all_vuids(struct smbsrv_connection *smb_conn)
{
	struct smbsrv_session *sess,*next=NULL;

	for (sess=smb_conn->sessions.session_list; sess; sess=next) {
		next = sess->next;
		
		smbsrv_invalidate_vuid(smb_conn, sess->vuid);
	}
}

/**
 *  register that a valid login has been performed, establish 'session'.
 *  @param session_info The token returned from the authentication process (if the authentication has completed)
 *   (now 'owned' by register_vuid)
 *
 *  @param smb_name The untranslated name of the user
 *
 *  @return Newly allocated vuid, biased by an offset. (This allows us to
 *   tell random client vuid's (normally zero) from valid vuids.)
 *
 */

uint16_t smbsrv_register_session(struct smbsrv_connection *smb_conn,
				 struct auth_session_info *session_info,
				 struct gensec_security *gensec_ctx)
{
	struct smbsrv_session *sess = NULL;

	sess = talloc_p(smb_conn, struct smbsrv_session);
	if(sess == NULL) {
		DEBUG(0,("talloc_p(smb_conn->mem_ctx, struct smbsrv_session) failed\n"));
		return UID_FIELD_INVALID;
	}

	ZERO_STRUCTP(sess);
	sess->vuid = UID_FIELD_INVALID;

	/* Ensure no vuid gets registered in share level security. */
	/* TODO: replace lp_security with a flag in smbsrv_connection */
	if(lp_security() == SEC_SHARE)
		return sess->vuid;

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (smb_conn->sessions.num_validated_vuids >= 0xFFFF-VUID_OFFSET)
		return sess->vuid;

	/* Allocate a free vuid. Yes this is a linear search... :-) */
	while (smbsrv_session_find(smb_conn, smb_conn->sessions.next_vuid) != NULL ) {
		smb_conn->sessions.next_vuid++;
		/* Check for vuid wrap. */
		if (smb_conn->sessions.next_vuid == UID_FIELD_INVALID)
			smb_conn->sessions.next_vuid = VUID_OFFSET;
	}

	DEBUG(10,("register_vuid: allocated vuid = %u\n", 
		  (uint_t)smb_conn->sessions.next_vuid));

	sess->vuid = smb_conn->sessions.next_vuid;
	smb_conn->sessions.next_vuid++;
	smb_conn->sessions.num_validated_vuids++;

	/* use this to keep tabs on all our info from the authentication */
	if (session_info) {
		sess->session_info = talloc_reference(sess, session_info);
	}

	if (gensec_ctx) {
		sess->gensec_ctx = talloc_reference(sess, gensec_ctx);
	}

	sess->smb_conn = smb_conn;
	DLIST_ADD(smb_conn->sessions.session_list, sess);

	return sess->vuid;
}
