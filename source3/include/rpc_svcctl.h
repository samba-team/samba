/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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

#ifndef _RPC_SVCCTL_H /* _RPC_SVCCTL_H */
#define _RPC_SVCCTL_H 


/* svcctl pipe */
#define SVC_OPEN_POLICY    0x0f
#define SVC_CLOSE          0x00


/* SVC_Q_OPEN_POLICY */
typedef struct q_svc_open_pol_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* unicode server name starting with '\\' */

	uint32 unknown;            /* unknown */

} SVC_Q_OPEN_POLICY;

/* SVC_R_OPEN_POLICY */
typedef struct r_svc_open_pol_info
{
	POLICY_HND pol;
	uint32 status;             /* return status */

} SVC_R_OPEN_POLICY;


/* SVC_Q_CLOSE */
typedef struct q_svc_close_info
{
	POLICY_HND pol;

} SVC_Q_CLOSE;



/* SVC_R_CLOSE */
typedef struct r_svc_close_info
{
	POLICY_HND pol;
	uint32 status;             /* return status */

} SVC_R_CLOSE;


#endif /* _RPC_SVCCTL_H */

