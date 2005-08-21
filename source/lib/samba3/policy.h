/* 
   Unix SMB/CIFS implementation.
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

#ifndef _SAMBA3_POLICY_H /* _SAMBA3_POLICY_H */
#define _SAMBA3_POLICY_H 

struct samba3_policy
{
	uint32_t min_password_length;
	uint32_t password_history;
	uint32_t user_must_logon_to_change_password;
	uint32_t maximum_password_age;
	uint32_t minimum_password_age;
	uint32_t lockout_duration;
	uint32_t reset_count_minutes;
	uint32_t bad_lockout_minutes;
	uint32_t disconnect_time;
	uint32_t refuse_machine_password_change;
};

#endif /* _SAMBA3_POLICY_H */
