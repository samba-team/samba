#ifndef _SMBAUTH_H_
#define _SMBAUTH_H_
/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   Standardised Authentication types
   Copyright (C) Andrew Bartlett 2001
   
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

/* AUTH_STR - string */
typedef struct normal_string
{
	int len;
	char *str;
} AUTH_STR;

/* AUTH_UNISTR - unicode string or buffer */
typedef struct unicode_string
{
	int len;
	uchar *unistr;
} AUTH_UNISTR;

/* AUTH_BUFFER - 8-bit byte buffer */
typedef struct auth_buffer
{
	int len;
	uint8 *buffer;
} AUTH_BUFFER;

typedef struct net_password
{
	AUTH_BUFFER lm_resp;
	AUTH_BUFFER nt_resp;
} auth_net_password;

typedef struct interactive_password
{
	OWF_INFO          lm_owf;              /* LM OWF Password */
	OWF_INFO          nt_owf;              /* NT OWF Password */
} auth_interactive_password;

typedef struct plaintext_password
{
	AUTH_STR password;
} auth_plaintext_password;

typedef struct usersupplied_info
{
	
 	AUTH_BUFFER lm_resp;
	AUTH_BUFFER nt_resp;
	auth_interactive_password * interactive_password;
        AUTH_STR plaintext_password;
	
	uint8 chal[8];

	AUTH_STR           requested_domain;     /* domain name string */
	AUTH_STR           domain;               /* domain name after mapping */
	AUTH_STR           unix_username;        /* username after mapping */
	AUTH_STR           smb_username;         /* username before mapping */
	AUTH_STR           wksta_name;           /* workstation name (netbios calling name) unicode string */
	
} auth_usersupplied_info;

typedef struct serversupplied_info
{
	AUTH_STR full_name;
	AUTH_STR unix_user;
	
	BOOL guest;
	
	uid_t unix_uid;
	gid_t unix_gid;
	
	/* This groups info is needed for when we become_user() for this uid */
	int n_groups;
	gid_t *groups;
	
	uchar session_key[16];
	
} auth_serversupplied_info;

#endif /* _SMBAUTH_H_ */
