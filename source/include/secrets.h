#ifndef _SECRETS_H
#define _SECRETS_H
/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   secrets database defines
   Copyright (C) Andrew Tridgell 1994-1998
   
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



#define SECRETS_MACHINE_ACCT_PASS "SECRETS/$MACHINE.ACC"
#define SECRETS_DOMAIN_SID    "SECRETS/SID"
#define SECRETS_SAM_SID       "SAM/SAM_SID"

struct machine_acct_pass {
	uint8 hash[16];
	time_t mod_time;
};

#endif  /* _SECRETS_H */
