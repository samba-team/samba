/* 
 * $Header: /data/src/mirror/cvs/samba/source/pam_ntdom/Attic/support.c,v 1.1.2.1 2000/04/09 02:04:30 lkcl Exp $ 
 */
 
/*
 * Copyright Andrew Morgan, 1996.  All rights reserved.
 * Modified by Alexander O. Yuriev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * $Log: support.c,v $
 * Revision 1.1.2.1  2000/04/09 02:04:30  lkcl
 * added pam_ntdom.  amazingly, it actually works.
 *
 * Revision 1.1  1998/04/17 15:34:25  lkcl
 *
 * adding pam_ntdom to samba source repository.  this version is known as 0.21
 *
 * further work to be done is:
 *
 * - to add the "change machine password" support so that the transmission
 * of the user's password is secure.
 *
 * - the session key needs to be generated from a random number.
 *
 * - the domain server needs to be automatically detected (using a UDP 138
 *   broadcast SAMQUERY packet to \\DOMAIN-NAME\MAILSLOT\NTLOGON)
 *
 * - the code to be changed from SamLogon immediately followed by SamLogoff
 *   to SamLogon when PAM user session starts followed by SamLogoff (or
 *   drop SMB connection) when PAM user session ends.
 *
 *   this will result in the user _really_ joining the domain from the
 *   workstation, will all the benefits thereof (including that of the
 *   administrator being able to disconnect them!)
 *
 * Revision 1.1  1996/11/09 19:44:35  morgan
 * Initial revision
 *
 * Revision 1.1  1996/04/17 01:11:08  alex
 * Initial revision
 *
 */
 
#include <stdlib.h>					/* define NULL */

#ifndef LINUX 

	#include <security/pam_appl.h>

#endif  /* LINUX */

#include <security/pam_modules.h>


#ifndef NDEBUG

	#include <syslog.h>

#endif	/* NDEBUG */


/* Phototype declarations */

int converse(		pam_handle_t *pamh,
			int nargs, 
			struct pam_message **message,
			struct pam_response **response	);

int _set_auth_tok(	pam_handle_t *pamh, 
			int flags, 
			int argc, 
			const char **argv	);

/* Implementation */

int converse(	pam_handle_t *pamh,
		int nargs, 
		struct pam_message **message,
		struct pam_response **response	)

{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(	pamh, PAM_CONV,  (const void **) &conv ) ; 
	if ( retval == PAM_SUCCESS )
		{
	  		retval = conv->conv( 	nargs,  
	  					( const struct pam_message ** ) message, 
	  					response, 
	  					conv->appdata_ptr );
     		}
	return retval;
}

/***************************************************************************/
/* prompt user for a using conversation calls 				   */
/***************************************************************************/

int _set_auth_tok(	pam_handle_t *pamh, 
			int flags, int argc, 
			const char **argv	)
{
	int	retval;
	char	*p;
	
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	/* set up conversation call */

	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = "Password: ";
	resp = NULL;

	if ( ( retval = converse( pamh, 1 , pmsg, &resp ) ) != PAM_SUCCESS ) 
		return retval;

	if ( resp ) 
		{
			if ( ( flags & PAM_DISALLOW_NULL_AUTHTOK ) && 
							resp[0].resp == NULL ) 
		       		{
					free( resp );
					return PAM_AUTH_ERR;
		  		}

			p = resp[ 0 ].resp;
			
			/* This could be a memory leak. If resp[0].resp 
			   is malloc()ed, then it has to be free()ed! 
			   	-- alex 
			*/
			
		  	resp[ 0 ].resp = NULL; 		  				  

	     	} 
	else 
		return PAM_CONV_ERR;

	free( resp );
	pam_set_item( pamh, PAM_AUTHTOK, p );
	return PAM_SUCCESS;
}
