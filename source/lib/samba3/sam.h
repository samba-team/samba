/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Jelmer Vernooij			2005.
   
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

#ifndef _SAMBA3_SAM_H /* _SAMBA3_SAM_H */
#define _SAMBA3_SAM_H 

struct samba3_samaccount {
	uint32_t logon_time,
		logoff_time,
		kickoff_time,
		bad_password_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;
	char *username;
	char *domain;
	char *nt_username;
	char *dir_drive;
	char *unknown_str;
	char *munged_dial;
	char *fullname;
	char *homedir;
	char *logon_script;
	char *profile_path;
	char *acct_desc;
	char *workstations;
	uint32_t user_rid, group_rid, hours_len, unknown_6;
	uint16_t acct_ctrl, logon_divs;
	uint16_t bad_password_count, logon_count;
	uint8_t	*lm_pw_ptr, *nt_pw_ptr;
	uint8_t *nt_pw_hist_ptr;
	uint8_t	*hours;
};

#endif /* _SAMBA3_SAM_H */
