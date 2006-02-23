/* 
   Unix SMB/CIFS implementation.
   ioctl and fsctl definitions
   
   Copyright (C) Andrew Tridgell              2003
   
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


/* ioctl codes */
#define IOCTL_QUERY_JOB_INFO      0x530060


/* filesystem control codes */
#define FSCTL_FILESYSTEM 0x90000
#define FSCTL_SET_SPARSE (FSCTL_FILESYSTEM | (49<<2))
#define FSCTL_REQUEST_BATCH_OPLOCK (FSCTL_FILESYSTEM | (2<<2))

#define FSCTL_NAMED_PIPE 0x110000
#define FSCTL_NAMED_PIPE_READ_WRITE (FSCTL_NAMED_PIPE | 0xc017)
