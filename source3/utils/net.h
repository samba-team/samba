/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "../utils/net_proto.h"
 
#define NET_FLAGS_MASTER 1
#define NET_FLAGS_DMB 2

/* Would it be insane to set 'localhost' as the default
   remote host for this operation? 

   For example, localhost is insane for a 'join' operation.
*/
#define NET_FLAGS_LOCALHOST_DEFAULT_INSANE 4 

/* We want to find the PDC only */
#define NET_FLAGS_PDC 8 

/* We want an anonymous connection */
#define NET_FLAGS_ANONYMOUS 16 

/* don't open an RPC pipe */
#define NET_FLAGS_NO_PIPE 32

extern int opt_maxusers;
extern const char *opt_comment;
extern const char *opt_container;
extern int opt_flags;

extern const char *opt_comment;

extern const char *opt_target_workgroup;
extern const char *opt_workgroup;
extern int opt_long_list_entries;
extern int opt_verbose;
extern int opt_reboot;
extern int opt_force;
extern int opt_machine_pass;
extern int opt_timeout;
extern const char *opt_host;
extern const char *opt_user_name;
extern const char *opt_password;
extern BOOL opt_user_specified;

extern BOOL opt_localgroup;
extern BOOL opt_domaingroup;
extern const char *opt_newntname;
extern int opt_rid;

extern BOOL opt_have_ip;
extern struct in_addr opt_dest_ip;

extern const char *share_type[];

