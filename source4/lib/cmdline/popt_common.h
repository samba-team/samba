/* 
   Unix SMB/CIFS implementation.
   Common popt arguments
   Copyright (C) Jelmer Vernooij	2003
   
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

#ifndef _POPT_COMMON_H
#define _POPT_COMMON_H

#include <popt.h>

/* Common popt structures */
extern struct poptOption popt_common_samba4[];
extern struct poptOption popt_common_connection4[];
extern struct poptOption popt_common_version4[];
extern struct poptOption popt_common_credentials4[];

#ifndef POPT_TABLEEND
#define POPT_TABLEEND { NULL, '\0', 0, 0, 0, NULL, NULL }
#endif

#define POPT_COMMON_SAMBA { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_samba4, 0, "Common Samba options:", NULL },
#define POPT_COMMON_CONNECTION { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_connection4, 0, "Connection options:", NULL },
#define POPT_COMMON_VERSION { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_version4, 0, "Version options:", NULL },
#define POPT_COMMON_CREDENTIALS { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_credentials4, 0, "Authentication options:", NULL },

struct cli_credentials;

void popt_set_cmdline_credentials(struct cli_credentials *creds);
struct cli_credentials *popt_get_cmdline_credentials(void);
void popt_free_cmdline_credentials(void);
extern struct loadparm_context *cmdline_lp_ctx;

#endif /* _POPT_COMMON_H */
