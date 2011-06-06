#ifndef __PAM_SMBPASS_SUPPORT_H__
#define __PAM_SMBPASS_SUPPORT_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* syslogging function for errors and other information */
extern void _log_err(pam_handle_t *, int, const char *, ...);

/* set the control flags for the UNIX module. */
extern int set_ctrl(pam_handle_t *, int, int, const char **);

/* generic function for freeing pam data segments */
extern void _cleanup(pam_handle_t *, void *, int);

/*
 * Safe duplication of character strings. "Paranoid"; don't leave
 * evidence of old token around for later stack analysis.
 */

extern char *smbpXstrDup(pam_handle_t *,const char *);

/* ************************************************************** *
 * Useful non-trivial functions                                   *
 * ************************************************************** */

extern void _cleanup_failures(pam_handle_t *, void *, int);

/* compare 2 strings */
extern bool strequal(const char *, const char *);

extern struct smb_passwd *
_my_get_smbpwnam(FILE *, const char *, bool *, bool *, long *);

extern int _smb_verify_password( pam_handle_t *pamh , struct samu *sampass, 
	const char *p, unsigned int ctrl );

/*
 * this function obtains the name of the current user and ensures
 * that the PAM_USER item is set to this value
 */

extern int _smb_get_user(pam_handle_t *, unsigned int,
			 const char *, const char **);

/* _smb_blankpasswd() is a quick check for a blank password */

extern int _smb_blankpasswd(unsigned int, struct samu *);


/* obtain a password from the user */
extern int _smb_read_password( pam_handle_t *, unsigned int, const char*,
				const char *, const char *, const char *, char **);

extern int _pam_smb_approve_pass(pam_handle_t *, unsigned int, const char *,
				 const char *);

int _pam_get_item(const pam_handle_t *pamh,
		  int item_type,
		  const void *_item);
int _pam_get_data(const pam_handle_t *pamh,
		  const char *module_data_name,
		  const void *_data);
#endif
