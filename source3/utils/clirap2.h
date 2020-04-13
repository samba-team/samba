/*
   Samba Unix/Linux SMB client library
   More client RAP (SMB Remote Procedure Calls) functions
   Copyright (C) 2001 Steve French (sfrench@us.ibm.com)
   Copyright (C) 2001 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2007 Jeremy Allison. jra@samba.org
   Copyright (C) Andrew Tridgell         1994-1998
   Copyright (C) Gerald (Jerry) Carter   2004
   Copyright (C) James Peach		 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __UTILS_CLIRAP2_H__
#define __UTILS_CLIRAP2_H__

#include "../libsmb/clirap.h"

struct rap_group_info_1;
struct rap_user_info_1;
struct rap_share_info_2;

int cli_NetGroupDelete(struct cli_state *cli, const char *group_name);
int cli_NetGroupAdd(struct cli_state *cli, struct rap_group_info_1 *grinfo);
int cli_RNetGroupEnum(struct cli_state *cli, void (*fn)(const char *, const char *, void *), void *state);
int cli_RNetGroupEnum0(struct cli_state *cli,
		       void (*fn)(const char *, void *),
		       void *state);
int cli_NetGroupDelUser(struct cli_state * cli, const char *group_name, const char *user_name);
int cli_NetGroupAddUser(struct cli_state * cli, const char *group_name, const char *user_name);
int cli_NetGroupGetUsers(struct cli_state * cli, const char *group_name, void (*fn)(const char *, void *), void *state );
int cli_NetUserGetGroups(struct cli_state * cli, const char *user_name, void (*fn)(const char *, void *), void *state );
int cli_NetUserDelete(struct cli_state *cli, const char * user_name );
int cli_NetUserAdd(struct cli_state *cli, struct rap_user_info_1 * userinfo );
int cli_RNetUserEnum(struct cli_state *cli, void (*fn)(const char *, const char *, const char *, const char *, void *), void *state);
int cli_RNetUserEnum0(struct cli_state *cli,
		      void (*fn)(const char *, void *),
		      void *state);
int cli_NetFileClose(struct cli_state *cli, uint32_t file_id );
int cli_NetFileGetInfo(struct cli_state *cli, uint32_t file_id, void (*fn)(const char *, const char *, uint16_t, uint16_t, uint32_t));
int cli_NetFileEnum(struct cli_state *cli, const char * user,
		    const char * base_path,
		    void (*fn)(const char *, const char *, uint16_t, uint16_t,
			       uint32_t));
int cli_NetShareAdd(struct cli_state *cli, struct rap_share_info_2 * sinfo );
int cli_NetShareDelete(struct cli_state *cli, const char * share_name );
bool cli_get_pdc_name(struct cli_state *cli, const char *workgroup, char **pdc_name);
bool cli_get_server_name(TALLOC_CTX *mem_ctx, struct cli_state *cli,
			 char **servername);
bool cli_ns_check_server_type(struct cli_state *cli, char *workgroup, uint32_t stype);
bool cli_NetWkstaUserLogoff(struct cli_state *cli, const char *user, const char *workstation);
int cli_NetPrintQEnum(struct cli_state *cli,
		void (*qfn)(const char*,uint16_t,uint16_t,uint16_t,const char*,const char*,const char*,const char*,const char*,uint16_t,uint16_t),
		void (*jfn)(uint16_t,const char*,const char*,const char*,const char*,uint16_t,uint16_t,const char*,unsigned int,unsigned int,const char*));
int cli_NetPrintQGetInfo(struct cli_state *cli, const char *printer,
	void (*qfn)(const char*,uint16_t,uint16_t,uint16_t,const char*,const char*,const char*,const char*,const char*,uint16_t,uint16_t),
	void (*jfn)(uint16_t,const char*,const char*,const char*,const char*,uint16_t,uint16_t,const char*,unsigned int,unsigned int,const char*));
int cli_RNetServiceEnum(struct cli_state *cli, void (*fn)(const char *, const char *, void *), void *state);
int cli_NetSessionEnum(struct cli_state *cli, void (*fn)(char *, char *, uint16_t, uint16_t, uint16_t, unsigned int, unsigned int, unsigned int, char *));
int cli_NetSessionGetInfo(struct cli_state *cli, const char *workstation,
		void (*fn)(const char *, const char *, uint16_t, uint16_t, uint16_t, unsigned int, unsigned int, unsigned int, const char *));
int cli_NetSessionDel(struct cli_state *cli, const char *workstation);
int cli_NetConnectionEnum(struct cli_state *cli, const char *qualifier,
			void (*fn)(uint16_t conid, uint16_t contype,
				uint16_t numopens, uint16_t numusers,
				uint32_t contime, const char *username,
				const char *netname));

#endif /* __UTILS_CLIRAP2_H__ */
