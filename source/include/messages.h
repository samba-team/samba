/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   messages.c header
   Copyright (C) Andrew Tridgell 2000
   
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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_

/* general messages */
#define MSG_DEBUG		1
#define MSG_PING		2
#define MSG_PONG		3
#define MSG_PROFILE		4
#define MSG_REQ_DEBUGLEVEL	5
#define MSG_DEBUGLEVEL		6
#define MSG_REQ_PROFILELEVEL	7
#define MSG_PROFILELEVEL	8

/* nmbd messages */
#define MSG_FORCE_ELECTION 1001

/* rpc messages */
#define MSG_PRINTER_NOTIFY 	2001
#define MSG_PRINTER_DRVUPGRADE	2002

/* smbd messages */
#define MSG_SMB_CONF_UPDATED 3001
#define MSG_SMB_FORCE_TDIS   3002
#define MSG_SMB_SAM_SYNC     3003
#define MSG_SMB_SAM_REPL     3004
#define MSG_SMB_UNLOCK	     3005
#endif
