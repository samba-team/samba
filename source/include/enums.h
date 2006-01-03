/* 
   Unix SMB/CIFS implementation.
   
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

/*
  this header declares basic enumerated types
*/

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets */
enum protocol_types {PROTOCOL_NONE,PROTOCOL_CORE,PROTOCOL_COREPLUS,PROTOCOL_LANMAN1,PROTOCOL_LANMAN2,PROTOCOL_NT1};

/* security levels */
enum security_types {SEC_SHARE,SEC_USER};

/* passed to br lock code */
enum brl_type {READ_LOCK, WRITE_LOCK, PENDING_READ_LOCK, PENDING_WRITE_LOCK};

enum smb_signing_state {SMB_SIGNING_OFF, SMB_SIGNING_SUPPORTED, 
			SMB_SIGNING_REQUIRED, SMB_SIGNING_AUTO};


