/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Interface header: Scheduler service
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Andrew Tridgell 1992-1999
   
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

#ifndef _RPC_EVENTLOG_H
#define _RPC_EVENTLOG_H

#define EVENTLOG_OPEN 0x07
#define EVENTLOG_CLOSE 0x02
#define EVENTLOG_NUMOFEVENTLOGRECORDS 0x04
#define EVENTLOG_READEVENTLOG	0x0a

#define EVENTLOG_READ_SEQUENTIAL	0x01
#define EVENTLOG_READ_SEEK		0x02
#define EVENTLOG_READ_FORWARD		0x04
#define EVENTLOG_READ_BACKWARD		0x08

#define EVENTLOG_OK			0X00
#define EVENTLOG_ERROR			0x01
#define EVENTLOG_WARNING		0x02
#define EVENTLOG_INFORMATION		0x04
#define EVENTLOG_AUDIT_OK		0x08
#define EVENTLOG_AUDIT_ERROR		0x10

typedef struct eventlogrecord
{
	uint32 size;
	uint32 reserved;
	uint32 recordnumber;
	uint32 creationtime;
	uint32 writetime;
	uint32 eventnumber;
	uint16 eventtype;
	uint16 num_of_strings;
	uint16 category;
	uint16 reserved_flag;
	uint32 closingrecord;
	uint32 stringoffset;
	uint32 sid_length;
	uint32 sid_offset;
	uint32 data_length;
	uint32 data_offset;
	UNISTR sourcename;
	UNISTR computername;
	UNISTR sid;
	UNISTR strings;
	UNISTR data;
	uint32 size2;	
} EVENTLOGRECORD;

typedef struct eventlog_q_open
{
	uint32 ptr0;

	uint16 unk0;
	uint16 unk1;

	UNIHDR  hdr_source;
	UNISTR2 uni_source;
	
	UNIHDR  hdr_unk;
	UNISTR2 uni_unk;
	
	uint32 unk6; /* one of these is an access mask! */
	uint32 unk7; /* one of these is an access mask! */

} EVENTLOG_Q_OPEN;

typedef struct eventlog_r_open
{
        POLICY_HND pol;
        uint32 status;

} EVENTLOG_R_OPEN;

typedef struct eventlog_q_close
{
        POLICY_HND pol;
} EVENTLOG_Q_CLOSE;

typedef struct eventlog_r_close
{
        POLICY_HND pol;
        uint32 status;
} EVENTLOG_R_CLOSE;

typedef struct eventlog_q_numofeventlogrec
{
        POLICY_HND pol;
} EVENTLOG_Q_NUMOFEVENTLOGREC;

typedef struct eventlog_r_numofeventlogrec
{
        uint32 number;
        uint32 status;
} EVENTLOG_R_NUMOFEVENTLOGREC;

typedef struct eventlog_q_readeventlog
{
        POLICY_HND pol;
	uint32 flags;
	uint32 offset;
	uint32 number_of_bytes;
} EVENTLOG_Q_READEVENTLOG;

typedef struct eventlog_r_readeventlog
{
	uint32 number_of_bytes;
	EVENTLOGRECORD *event;
	uint32 sent_size;
	uint32 real_size;
	uint32 status;
} EVENTLOG_R_READEVENTLOG;

#endif /* _RPC_EVENTLOG_H */
